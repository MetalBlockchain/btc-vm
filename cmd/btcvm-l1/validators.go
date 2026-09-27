// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

// Adding and removing the L1's validators (proof of authority).
//
// The L1's manager is the BTCVM chain itself (see create), so each change
// is a Warp message from the chain that the L1's current validators sign,
// and each validator signs only a change enough admins approved (M of N:
// "validatorAdmins" and "validatorAdminThreshold" in each validator's chain
// config; vm/validator_manager.go).
//
// A change travels as a proposal file: the first admin makes it, each
// other admin adds an approval on their own machine, and anyone with a
// validator node's rpcPass submits it once it has enough.
//
//	candidate:  btcvm-l1 request -node-uri http://127.0.0.1:9650 -owner P-metal1... > request.json
//	admin 1:    btcvm-l1 approve -request request.json -key admin1-key.json > proposal.json
//	admin 2:    btcvm-l1 approve -proposal proposal.json -key admin2-key.json > proposal2.json
//	            (each approve shows the change and what it does to the
//	            validators' shares, and asks; -yes skips the question. It
//	            needs no validator node: -node-uri only reads the P-Chain.)
//	submitter:  btcvm-l1 submit -proposal proposal2.json -node-uri http://127.0.0.1:9660 \
//	              -rpc-pass-file rpc-password > registration.json
//	candidate:  btcvm-l1 register -registration registration.json -key my-p-chain-key.json -balance 1
//	admin 1:    btcvm-l1 remove -validation-id ... -key admin1-key.json -node-uri ... > proposal.json
//	            (then approve -proposal and submit as above; submit -payer-key pays the P-Chain fee)
//	admin 1:    btcvm-l1 set-weight -validation-id ... -weight 100 -key admin1-key.json -node-uri ... > proposal.json
//	            (a new validator starts at a small weight, since it can't sign until
//	            it's funded and online; raise it once it's active)
//	anyone:     btcvm-l1 top-up -validation-id ... -key p-chain-key.json -balance 1
//	owner:      btcvm-l1 disable -validation-id ... -key owner-key.json   (ends it; the unused balance returns to the owner)
//	anyone:     btcvm-l1 validators -node-uri ...
//
// approve and remove also take -rpc-pass-file, to submit at once when this
// approval is the last one needed.
//
// When a submit fails, submit the same proposal again; don't make a new one.
// Validators that signed a change hold it (they sign nothing else) until
// it's on the P-Chain or can't be: a registration until it expires, a
// weight change until the P-Chain's nonce passes it. Each validator judges
// deadlines by its own clock and the P-Chain by its own view of it, so
// leave margin: a change near its deadline, or moments after another,
// can be refused by some and signed by others.
//
// If validators end up holding different changes, so that none gathers
// 67%, every admin together can start a change with -replace-held: it
// replaces whatever they hold. A held change already signed by enough
// validators can still reach the P-Chain, so check none is waiting first.
//
// A validator keeps the change it holds in <dataDir>/validator-manager/
// held-change.json. Never start one on a restored or copied data directory
// without the admins checking no change is outstanding: it could hold an
// older change than the one it really signed. Each operator's -owner key
// is its own: the owner can disable the validator.
//
// Nothing secret changes hands: a request holds the candidate's NodeID and
// BLS public key and proof of possession; a proposal holds the unsigned
// change and the admins' approvals; a registration holds the signed Warp
// message. Each party's private key stays in its own key file.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MetalBlockchain/metalgo/api/info"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/vms/platformvm"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/payload"
	"github.com/MetalBlockchain/metalgo/vms/secp256k1fx"
	pwallet "github.com/MetalBlockchain/metalgo/wallet/chain/p/wallet"
	"github.com/MetalBlockchain/metalgo/wallet/subnet/primary"

	"github.com/MetalBlockchain/btcvm/vm"
)

// The BTCVM L1 on Metal mainnet (the defaults for every command here).
const (
	mainnetChainID  = "BYogm85qvZxwX4PitKLDPzNDbAgo61nw2NSXx5VVXyZZ8yGUK"
	mainnetSubnetID = "SWJQGgyAvXY1aBczr7WupCGpLmukvP2YdXZJUvqm1td37EcJm"
)

// validatorRequest is what a candidate sends the admin. All public.
type validatorRequest struct {
	NodeID               string `json:"nodeID"`
	BLSPublicKey         string `json:"blsPublicKey"`
	BLSProofOfPossession string `json:"blsProofOfPossession"`
	// The candidate's P-Chain address: it gets back whatever is left of the
	// validator's balance, and may disable the validator itself.
	Owner string `json:"owner"`
}

// registration is what the admin sends back: the signed registration.
type registration struct {
	NodeID               string `json:"nodeID"`
	ValidationID         string `json:"validationID"`
	Weight               uint64 `json:"weight"`
	Expiry               string `json:"expiry"`
	BLSProofOfPossession string `json:"blsProofOfPossession"`
	SignedMessage        string `json:"signedMessage"`
}

type l1Flags struct {
	networkID *uint
	chainID   *string
	subnetID  *string
	nodeURI   *string
}

func addL1Flags(fs *flag.FlagSet) l1Flags {
	return l1Flags{
		networkID: networkIDFlag(fs),
		chainID:   fs.String("chain-id", mainnetChainID, "the BTCVM chain (the L1's manager)"),
		subnetID:  fs.String("subnet-id", mainnetSubnetID, "the BTCVM L1's subnet"),
		nodeURI:   fs.String("node-uri", "http://127.0.0.1:9650", "API of a node: for approve and remove, one of the L1's validators"),
	}
}

func (f l1Flags) ids() (ids.ID, ids.ID, error) {
	chainID, err := ids.FromString(*f.chainID)
	if err != nil {
		return ids.Empty, ids.Empty, fmt.Errorf("-chain-id: %w", err)
	}
	subnetID, err := ids.FromString(*f.subnetID)
	if err != nil {
		return ids.Empty, ids.Empty, fmt.Errorf("-subnet-id: %w", err)
	}
	return chainID, subnetID, nil
}

func hexBytes(b []byte) string { return "0x" + hex.EncodeToString(b) }

func unhex(s, what string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return b, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func pOwner(addr string) (message.PChainOwner, error) {
	id, err := address.ParseToID(addr)
	if err != nil {
		return message.PChainOwner{}, fmt.Errorf("%q is not a P-Chain address: %w", addr, err)
	}
	return message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{id}}, nil
}

// cmdRequest prints the request a candidate sends the admin, from its own
// node's info API.
func cmdRequest(args []string) error {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	nodeURI := fs.String("node-uri", "http://127.0.0.1:9650", "your node's API")
	owner := fs.String("owner", "", "your P-Chain address (gets back what's left of the validator's balance)")
	_ = fs.Parse(args)
	if _, err := pOwner(*owner); err != nil {
		return fmt.Errorf("-owner: %w", err)
	}
	nodeID, pop, err := info.NewClient(*nodeURI).GetNodeID(context.Background())
	if err != nil {
		return fmt.Errorf("reading your node's ID: %w", err)
	}
	if pop == nil {
		return errors.New("your node has no BLS key (staking-signer); it can't validate an L1")
	}
	return printJSON(validatorRequest{
		NodeID:               nodeID.String(),
		BLSPublicKey:         hexBytes(pop.PublicKey[:]),
		BLSProofOfPossession: hexBytes(pop.ProofOfPossession[:]),
		Owner:                *owner,
	})
}

// proposal is a validator change on its way through the admins: the unsigned
// Warp message and the approvals so far. Every field but the message and
// the approvals is a label, recomputed from the message whenever it's read.
type proposal struct {
	Change          string `json:"change"` // "register" or "set-weight"
	Summary         string `json:"summary"`
	UnsignedMessage string `json:"unsignedMessage"`
	// Every approval is of the message until this time (Unix seconds); the
	// validators refuse approvals past it.
	Deadline    uint64 `json:"deadline"`
	DeadlineUTC string `json:"deadlineUTC"`
	// Replaces whatever change the validators hold (every admin must
	// approve): the way out if validators hold different changes.
	ReplaceHeld bool     `json:"replaceHeld,omitempty"`
	Approvals   []string `json:"approvals"`
	ApprovedBy  []string `json:"approvedBy"`
	// For a registration: what the candidate needs to register.
	NodeID               string `json:"nodeID,omitempty"`
	ValidationID         string `json:"validationID,omitempty"`
	Weight               uint64 `json:"weight"`
	Expiry               string `json:"expiry,omitempty"`
	BLSProofOfPossession string `json:"blsProofOfPossession,omitempty"`
}

// change is what an unsigned message asks for.
type change struct {
	unsigned *warp.UnsignedMessage
	reg      *message.RegisterL1Validator
	weight   *message.L1ValidatorWeight
}

func parseChange(networkID uint32, chainID ids.ID, unsignedBytes []byte) (*change, error) {
	unsigned, err := warp.ParseUnsignedMessage(unsignedBytes)
	if err != nil {
		return nil, fmt.Errorf("not an unsigned Warp message: %w", err)
	}
	if unsigned.NetworkID != networkID || unsigned.SourceChainID != chainID {
		return nil, fmt.Errorf("the change is for network %d chain %s, not network %d chain %s", unsigned.NetworkID, unsigned.SourceChainID, networkID, chainID)
	}
	call, err := payload.ParseAddressedCall(unsigned.Payload)
	if err != nil {
		return nil, fmt.Errorf("not an addressed call: %w", err)
	}
	parsed, err := message.Parse(call.Payload)
	if err != nil {
		return nil, err
	}
	c := &change{unsigned: unsigned}
	switch p := parsed.(type) {
	case *message.RegisterL1Validator:
		c.reg = p
	case *message.L1ValidatorWeight:
		c.weight = p
	default:
		return nil, fmt.Errorf("not a validator change: %T", parsed)
	}
	return c, nil
}

// label fills a proposal's labels from its change.
func (c *change) label(p *proposal) error {
	switch {
	case c.reg != nil:
		nodeID, err := ids.ToNodeID(c.reg.NodeID)
		if err != nil {
			return err
		}
		expiry := time.Unix(int64(c.reg.Expiry), 0).UTC()
		p.Change, p.NodeID, p.ValidationID, p.Weight = "register", nodeID.String(), c.reg.ValidationID().String(), c.reg.Weight
		p.Expiry = expiry.Format(time.RFC3339)
		balanceOwner, err := ownerText(c.unsigned.NetworkID, c.reg.RemainingBalanceOwner)
		if err != nil {
			return err
		}
		disableOwner, err := ownerText(c.unsigned.NetworkID, c.reg.DisableOwner)
		if err != nil {
			return err
		}
		p.Summary = fmt.Sprintf("register %s (BLS key %s) on subnet %s with weight %d; what's left of its balance returns to %s; "+
			"it can be disabled by %s; valid until %s",
			nodeID, hexBytes(c.reg.BLSPublicKey[:]), c.reg.SubnetID, c.reg.Weight, balanceOwner, disableOwner, p.Expiry)
	default:
		p.Change, p.ValidationID, p.Weight = "set-weight", c.weight.ValidationID.String(), c.weight.Weight
		p.NodeID, p.Expiry, p.BLSProofOfPossession = "", "", ""
		verb := fmt.Sprintf("set the weight of validation %s to %d", c.weight.ValidationID, c.weight.Weight)
		if c.weight.Weight == 0 {
			verb = fmt.Sprintf("remove validation %s", c.weight.ValidationID)
		}
		p.Summary = fmt.Sprintf("%s (nonce %d)", verb, c.weight.Nonce)
	}
	return nil
}

// ownerText is a P-Chain owner as "N of [addresses]".
func ownerText(networkID uint32, o message.PChainOwner) (string, error) {
	var addrs []string
	for _, a := range o.Addresses {
		addr, err := address.Format("P", constants.GetHRP(networkID), a.Bytes())
		if err != nil {
			return "", err
		}
		addrs = append(addrs, addr)
	}
	return fmt.Sprintf("%d of [%s]", o.Threshold, strings.Join(addrs, ", ")), nil
}

// check refuses a change nobody could still make: a registration past its
// expiry, or approvals past their deadline.
func (c *change) check(p *proposal) error {
	if c.reg != nil && time.Now().Unix() >= int64(c.reg.Expiry) {
		return fmt.Errorf("this registration expired at %s; start a new one", time.Unix(int64(c.reg.Expiry), 0).UTC().Format(time.RFC3339))
	}
	if p.Deadline == 0 || uint64(time.Now().Unix()) >= p.Deadline {
		return fmt.Errorf("this proposal's approvals expired at %s; start a new one", time.Unix(int64(p.Deadline), 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// flags are the approval flags every admin signs with.
func (p *proposal) flags() byte {
	if p.ReplaceHeld {
		return vm.FlagReplaceHeld
	}
	return 0
}

// setDeadline fixes the time every approval of the proposal is good until.
func (p *proposal) setDeadline(t time.Time) {
	p.Deadline = uint64(t.Unix())
	p.DeadlineUTC = t.UTC().Format(time.RFC3339)
}

// approvals decodes a proposal's approvals and who gave each.
func (p *proposal) approvals(unsigned *warp.UnsignedMessage) ([][]byte, []ids.ShortID, error) {
	hash := vm.ApprovalHash(unsigned.Bytes(), p.flags(), p.Deadline)
	var sigs [][]byte
	var who []ids.ShortID
	for i, a := range p.Approvals {
		sig, err := unhex(a, fmt.Sprintf("approval %d", i+1))
		if err != nil {
			return nil, nil, err
		}
		pub, err := secp256k1.RecoverPublicKeyFromHash(hash, sig)
		if err != nil {
			return nil, nil, fmt.Errorf("approval %d doesn't verify: %w", i+1, err)
		}
		sigs, who = append(sigs, sig), append(who, pub.Address())
	}
	return sigs, who, nil
}

// addApproval signs the proposal's change with an admin key.
func (p *proposal) addApproval(unsigned *warp.UnsignedMessage, networkID uint32, keyPath string) error {
	key, err := readKey(keyPath)
	if err != nil {
		return fmt.Errorf("admin key: %w", err)
	}
	_, who, err := p.approvals(unsigned)
	if err != nil {
		return err
	}
	for _, w := range who {
		if w == key.Address() {
			return errors.New("this key has already approved this change")
		}
	}
	sig, err := key.SignHash(vm.ApprovalHash(unsigned.Bytes(), p.flags(), p.Deadline))
	if err != nil {
		return err
	}
	p.Approvals = append(p.Approvals, hexBytes(sig))
	p.ApprovedBy = p.ApprovedBy[:0]
	for _, w := range append(who, key.Address()) {
		addr, err := address.Format("P", constants.GetHRP(networkID), w.Bytes())
		if err != nil {
			return err
		}
		p.ApprovedBy = append(p.ApprovedBy, addr)
	}
	return nil
}

// readProposal reads and checks a proposal: its change, for this chain, and
// its approvals (each must verify; the validators check who gave them).
func readProposal(path string, networkID uint32, chainID ids.ID) (*proposal, *change, error) {
	var p proposal
	if err := readJSON(path, &p); err != nil {
		return nil, nil, fmt.Errorf("-proposal: %w", err)
	}
	raw, err := unhex(p.UnsignedMessage, "unsignedMessage")
	if err != nil {
		return nil, nil, err
	}
	c, err := parseChange(networkID, chainID, raw)
	if err != nil {
		return nil, nil, err
	}
	if err := c.label(&p); err != nil {
		return nil, nil, err
	}
	p.setDeadline(time.Unix(int64(p.Deadline), 0))
	_, who, err := p.approvals(c.unsigned)
	if err != nil {
		return nil, nil, err
	}
	// Who approved is whoever the signatures recover to, never the file's say.
	p.ApprovedBy = nil
	for _, w := range who {
		addr, err := address.Format("P", constants.GetHRP(networkID), w.Bytes())
		if err != nil {
			return nil, nil, err
		}
		p.ApprovedBy = append(p.ApprovedBy, addr)
	}
	return &p, c, nil
}

// collect has the validator node at nodeURI collect the L1 validators'
// signatures on an approved change.
func collect(nodeURI string, chainID ids.ID, rpcUser, rpcPassFile string, unsigned *warp.UnsignedMessage, flags byte, deadline uint64, approvals [][]byte) (*warp.Message, error) {
	pass, err := os.ReadFile(rpcPassFile)
	if err != nil {
		return nil, fmt.Errorf("-rpc-pass-file: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"message": hexBytes(unsigned.Bytes()), "justification": hexBytes(vm.EncodeJustification(flags, deadline, approvals))})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(nodeURI, "/")+"/ext/bc/"+chainID.String()+"/validators", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(rpcUser, strings.TrimSpace(string(pass)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the validators didn't sign: %s", strings.TrimSpace(string(raw)))
	}
	var reply struct{ SignedMessage, SignedWeight, TotalWeight string }
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, err
	}
	signed, err := unhex(reply.SignedMessage, "signed message")
	if err != nil {
		return nil, err
	}
	msg, err := warp.ParseMessage(signed)
	if err != nil {
		return nil, err
	}
	// What came back must be exactly what the admins approved.
	if !bytes.Equal(msg.UnsignedMessage.Bytes(), unsigned.Bytes()) {
		return nil, errors.New("the node returned a signed message that isn't the approved one; not using it")
	}
	fmt.Fprintf(os.Stderr, "signed by weight %s of %s\n", reply.SignedWeight, reply.TotalWeight)
	return msg, nil
}

// submitFlags are how a proposal reaches the validators.
type submitFlags struct {
	rpcUser, rpcPassFile, payerPath *string
}

func addSubmitFlags(fs *flag.FlagSet, optional bool) submitFlags {
	what := "file holding the validator node's BTCVM rpcPass"
	if optional {
		what += " (to submit now: this approval is the last one needed)"
	}
	return submitFlags{
		rpcUser:     fs.String("rpc-user", "btcvm", "the validator node's BTCVM rpcUser"),
		rpcPassFile: fs.String("rpc-pass-file", "", what),
		payerPath:   fs.String("payer-key", "", "for a weight change: the P-Chain key that pays its fee"),
	}
}

// submit has the validators sign an approved proposal. A registration is
// printed for the candidate to register; a weight change is issued on the
// P-Chain at once, paid by -payer-key.
func submit(p *proposal, c *change, nodeURI string, chainID ids.ID, f submitFlags) error {
	if err := c.check(p); err != nil {
		return err
	}
	sigs, _, err := p.approvals(c.unsigned)
	if err != nil {
		return err
	}
	if c.weight != nil && *f.payerPath == "" {
		return errors.New("-payer-key is needed to issue a weight change")
	}
	signed, err := collect(nodeURI, chainID, *f.rpcUser, *f.rpcPassFile, c.unsigned, p.flags(), p.Deadline, sigs)
	if err != nil {
		return err
	}
	if c.reg != nil {
		return printJSON(registration{
			NodeID:               p.NodeID,
			ValidationID:         p.ValidationID,
			Weight:               p.Weight,
			Expiry:               p.Expiry,
			BLSProofOfPossession: p.BLSProofOfPossession,
			SignedMessage:        hexBytes(signed.Bytes()),
		})
	}
	wallet, err := pWallet(nodeURI, *f.payerPath)
	if err != nil {
		return err
	}
	tx, err := wallet.IssueSetL1ValidatorWeightTx(signed.Bytes())
	if err != nil {
		return fmt.Errorf("issuing the weight change: %w", err)
	}
	return printJSON(map[string]string{"validationID": p.ValidationID, "txID": tx.ID().String()})
}

func unsignedFor(networkID uint32, chainID ids.ID, p message.Payload) (*warp.UnsignedMessage, error) {
	// The L1's manager address is empty (see create).
	call, err := payload.NewAddressedCall(nil, p.Bytes())
	if err != nil {
		return nil, err
	}
	return warp.NewUnsignedMessage(networkID, chainID, call.Bytes())
}

// cmdApprove approves a change: a candidate's request (making a new
// proposal), or a proposal another admin started (adding this approval).
func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	l1 := addL1Flags(fs)
	requestPath := fs.String("request", "", "a candidate's request.json: start a registration proposal")
	proposalPath := fs.String("proposal", "", "a proposal another admin started: add this approval")
	keyPath := fs.String("key", "", "an admin key (its P-Chain address is in the validators' validatorAdmins)")
	weight := fs.Uint64("weight", 100, "with -request: the new validator's weight (the first validator has 100)")
	valid := fs.Duration("valid-for", 23*time.Hour, "with -request: how long the admins and the candidate have to finish (at most 24h, which the P-Chain counts from when it is registered)")
	yes := fs.Bool("yes", false, "approve without asking")
	offline := fs.Bool("offline", false, "approve without the share preview (no P-Chain access)")
	replaceHeld := fs.Bool("replace-held", false, "with -request: the change replaces whatever change the validators hold (only if every admin approves; for validators stuck holding different changes)")
	sf := addSubmitFlags(fs, true)
	_ = fs.Parse(args)
	if (*requestPath == "") == (*proposalPath == "") || *keyPath == "" {
		return errors.New("-key and one of -request or -proposal are required")
	}
	if *replaceHeld && *proposalPath != "" {
		return errors.New("-replace-held is set when a proposal starts (with -request), not later")
	}
	chainID, subnetID, err := l1.ids()
	if err != nil {
		return err
	}
	networkID := uint32(*l1.networkID)
	var p *proposal
	var c *change
	if *proposalPath != "" {
		if p, c, err = readProposal(*proposalPath, networkID, chainID); err != nil {
			return err
		}
	} else {
		if *valid <= 0 || *valid > 24*time.Hour {
			return errors.New("-valid-for must be between 0 and 24h")
		}
		reg, pop, err := registrationFor(*requestPath, subnetID, *weight, time.Now().Add(*valid))
		if err != nil {
			return err
		}
		unsigned, err := unsignedFor(networkID, chainID, reg)
		if err != nil {
			return err
		}
		c = &change{unsigned: unsigned, reg: reg}
		p = &proposal{UnsignedMessage: hexBytes(unsigned.Bytes()), BLSProofOfPossession: pop, ReplaceHeld: *replaceHeld}
		if err := c.label(p); err != nil {
			return err
		}
		// A registration's approvals are good as long as the registration.
		p.setDeadline(time.Unix(int64(reg.Expiry), 0))
	}
	if err := c.check(p); err != nil {
		return err
	}
	if err := confirm(p, c, *l1.nodeURI, subnetID, *yes, *offline); err != nil {
		return err
	}
	if err := p.addApproval(c.unsigned, networkID, *keyPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approved by %d admin(s): %s\n", len(p.ApprovedBy), strings.Join(p.ApprovedBy, ", "))
	if *sf.rpcPassFile != "" {
		return submit(p, c, *l1.nodeURI, chainID, sf)
	}
	return printJSON(p)
}

// registrationFor makes the registration a candidate's request asks for,
// after checking the request.
func registrationFor(requestPath string, subnetID ids.ID, weight uint64, expiry time.Time) (*message.RegisterL1Validator, string, error) {
	var req validatorRequest
	if err := readJSON(requestPath, &req); err != nil {
		return nil, "", fmt.Errorf("-request: %w", err)
	}
	nodeID, err := ids.NodeIDFromString(req.NodeID)
	if err != nil {
		return nil, "", fmt.Errorf("request nodeID: %w", err)
	}
	pkBytes, err := unhex(req.BLSPublicKey, "request blsPublicKey")
	if err != nil {
		return nil, "", err
	}
	popBytes, err := unhex(req.BLSProofOfPossession, "request blsProofOfPossession")
	if err != nil {
		return nil, "", err
	}
	// The P-Chain checks the proof of possession at registration; checking
	// it here catches a mistyped request before anyone signs.
	pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		return nil, "", fmt.Errorf("request blsPublicKey: %w", err)
	}
	popSig, err := bls.SignatureFromBytes(popBytes)
	if err != nil {
		return nil, "", fmt.Errorf("request blsProofOfPossession: %w", err)
	}
	if !bls.VerifyProofOfPossession(pk, popSig, pkBytes) {
		return nil, "", errors.New("the request's proof of possession doesn't match its BLS key")
	}
	owner, err := pOwner(req.Owner)
	if err != nil {
		return nil, "", fmt.Errorf("request owner: %w", err)
	}
	var pkArr [bls.PublicKeyLen]byte
	copy(pkArr[:], pkBytes)
	reg, err := message.NewRegisterL1Validator(subnetID, nodeID, pkArr, uint64(expiry.Unix()), owner, owner, weight)
	return reg, req.BLSProofOfPossession, err
}

// confirm shows an admin what they're approving, from the message itself,
// and what it does to the validators' shares; then asks, unless yes.
func confirm(p *proposal, c *change, nodeURI string, subnetID ids.ID, yes, offline bool) error {
	fmt.Fprintf(os.Stderr, "\nThe change:      %s\n", p.Summary)
	fmt.Fprintf(os.Stderr, "Approvals until: %s\n", p.DeadlineUTC)
	if p.ReplaceHeld {
		fmt.Fprint(os.Stderr, "REPLACES whatever change the validators hold, and needs every admin. A held change that was\n"+
			"already signed by enough validators can still reach the P-Chain: check none is waiting to be submitted.\n")
	}
	if len(p.ApprovedBy) > 0 {
		fmt.Fprintf(os.Stderr, "Approved by:     %s (recovered from their signatures)\n", strings.Join(p.ApprovedBy, ", "))
	}
	switch lines, err := shareReport(c, nodeURI, subnetID, offline); {
	case offline:
		fmt.Fprint(os.Stderr, "\nOffline: no share preview. The validators check the shares themselves before they sign.\n")
	case err != nil:
		return fmt.Errorf("reading the L1's validators from %s for the share preview: %w (-offline approves without it)", nodeURI, err)
	default:
		fmt.Fprint(os.Stderr, lines)
	}
	if yes {
		return nil
	}
	fmt.Fprint(os.Stderr, "\nApprove this change? Type yes: ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		return errors.New("not approved")
	}
	return nil
}

// shareReport is the L1's validators before and after the change, as the
// validators will judge it (vm checkChange): every registered weight counts
// in the total, only active validators can sign.
func shareReport(c *change, nodeURI string, subnetID ids.ID, offline bool) (string, error) {
	if offline {
		return "", nil
	}
	vdrs, err := platformvm.NewClient(nodeURI).GetCurrentValidators(context.Background(), subnetID, nil)
	if err != nil {
		return "", err
	}
	type row struct {
		id            string
		before, after *big.Int
		active        bool
	}
	var rows []row
	var subject string
	if c.reg != nil {
		subject = c.reg.ValidationID().String()
	} else {
		subject = c.weight.ValidationID.String()
	}
	found := false
	for _, v := range vdrs {
		if v.ValidationID == nil {
			continue
		}
		r := row{id: v.NodeID.String(), before: new(big.Int).SetUint64(v.Weight), after: new(big.Int).SetUint64(v.Weight),
			active: v.Balance != nil && *v.Balance > 0}
		if c.weight != nil && v.ValidationID.String() == subject {
			found = true
			r.after = new(big.Int).SetUint64(c.weight.Weight)
		}
		if !r.active {
			r.id += " (inactive)"
		}
		rows = append(rows, r)
	}
	if c.reg != nil {
		nodeID, _ := ids.ToNodeID(c.reg.NodeID)
		rows = append(rows, row{id: nodeID.String() + " (new)", before: new(big.Int), after: new(big.Int).SetUint64(c.reg.Weight)})
	} else if !found {
		return "", fmt.Errorf("validation %s is not one of this L1's current validators", subject)
	}
	before, after, signable := new(big.Int), new(big.Int), new(big.Int)
	var weights []*big.Int
	for _, r := range rows {
		before.Add(before, r.before)
		after.Add(after, r.after)
		if r.after.Sign() > 0 {
			weights = append(weights, r.after)
			if r.active {
				signable.Add(signable, r.after)
			}
		}
	}
	pct := func(w, total *big.Int) string {
		if total.Sign() == 0 {
			return "-"
		}
		return vm.Percent(w, total)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-56s %13s %13s\n", "Validator", "share before", "share after")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-56s %13s %13s\n", r.id, pct(r.before, before), pct(r.after, after))
	}
	fmt.Fprintf(&b, "Afterwards the validators able to sign now hold %s of the weight (the P-Chain needs 67%%).\n", pct(signable, after))
	if c.reg != nil {
		rest := new(big.Int).Sub(after, new(big.Int).SetUint64(c.reg.Weight))
		maxW := vm.MaxNewcomerWeight(signable, rest)
		fmt.Fprintf(&b, "A new validator can't sign until it's funded and online: register it at a weight of at most %s, then raise it once it's active.\n", maxW)
	}
	// How many of the validators able to sign could be offline: only they
	// count toward the 67%, of the whole registered weight.
	var activeWeights []*big.Int
	for _, r := range rows {
		if r.active && r.after.Sign() > 0 {
			activeWeights = append(activeWeights, r.after)
		}
	}
	sort.Slice(activeWeights, func(i, j int) bool { return activeWeights[i].Cmp(activeWeights[j]) > 0 })
	tolerate := 0
	left := new(big.Int).Set(signable)
	for _, w := range activeWeights {
		rest := new(big.Int).Sub(left, w)
		if !vm.Quorum(rest, after) {
			break
		}
		tolerate++
		left = rest
	}
	fmt.Fprintf(&b, "%d validator(s) could be offline and the rest still reach 67%%.\n", tolerate)
	if tolerate == 0 {
		b.WriteString("WARNING: with any one validator offline, the L1's validators can't be changed again until it's back.\n")
	}
	for _, w := range weights {
		if vm.Blocks(w, after) {
			b.WriteString("One validator could block the 67% alone: the validators sign this only with every admin's approval.\n")
			break
		}
	}
	return b.String(), nil
}

// cmdSubmit has the validators sign a proposal with enough approvals.
func cmdSubmit(args []string) error {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	l1 := addL1Flags(fs)
	proposalPath := fs.String("proposal", "", "the proposal, with its approvals")
	sf := addSubmitFlags(fs, false)
	_ = fs.Parse(args)
	if *proposalPath == "" || *sf.rpcPassFile == "" {
		return errors.New("-proposal and -rpc-pass-file are required")
	}
	chainID, _, err := l1.ids()
	if err != nil {
		return err
	}
	p, c, err := readProposal(*proposalPath, uint32(*l1.networkID), chainID)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "submitting: %s\n", p.Summary)
	return submit(p, c, *l1.nodeURI, chainID, sf)
}

func pWallet(uri, keyPath string) (pwallet.Wallet, error) {
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	return primary.MakePWallet(context.Background(), uri, secp256k1fx.NewKeychain(key), primary.WalletConfig{})
}

// cmdRegister issues the registration on the P-Chain, paying the new
// validator's starting balance.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	regPath := fs.String("registration", "", "registration.json from the admin")
	keyPath := fs.String("key", "", "the P-Chain key that pays the balance")
	uri := fs.String("uri", "http://127.0.0.1:9650", "a node's API, for the P-Chain")
	balance := fs.Float64("balance", 1, "METAL for the validator's continuous P-Chain fee")
	otherNode := fs.Bool("other-node", false, "register it though it isn't for the node at -uri (then -candidate-uri is the candidate's node)")
	candidateURI := fs.String("candidate-uri", "", "with -other-node: the candidate node's API, to check the registration is for it and it has bootstrapped")
	skipBootstrap := fs.Bool("skip-bootstrap-check", false, "register without checking the candidate has bootstrapped (it counts as a validator at once)")
	lowBalance := fs.Bool("low-balance", false, "allow a starting balance under 1 METAL (under a month of fees)")
	_ = fs.Parse(args)
	if *regPath == "" || *keyPath == "" {
		return errors.New("-registration and -key are required")
	}
	if *balance < 1 && !*lowBalance {
		return errors.New("-balance under 1 METAL runs out in a few weeks, and the validator stops counting; -low-balance allows it")
	}
	var reg registration
	if err := readJSON(*regPath, &reg); err != nil {
		return err
	}
	signed, err := unhex(reg.SignedMessage, "signedMessage")
	if err != nil {
		return err
	}
	// Check what's actually signed, not the file's labels: paying for
	// someone else's validator would hand them the balance.
	inner, err := registrationIn(signed)
	if err != nil {
		return err
	}
	nodeID, err := ids.ToNodeID(inner.NodeID)
	if err != nil {
		return fmt.Errorf("the signed registration's NodeID: %w", err)
	}
	fmt.Fprintf(os.Stderr, "registering %s (weight %d); what's left of the balance goes to %v\n",
		nodeID, inner.Weight, inner.RemainingBalanceOwner.Addresses)
	candidate := *uri
	if *otherNode {
		if *candidateURI == "" {
			return errors.New("-other-node needs -candidate-uri: the candidate's node, to check the registration is for it")
		}
		candidate = *candidateURI
	}
	{
		mine, pop, err := info.NewClient(candidate).GetNodeID(context.Background())
		if err != nil {
			return fmt.Errorf("reading the candidate node at %s (to check the registration is for it): %w", candidate, err)
		}
		if mine != nodeID || pop == nil || pop.PublicKey != inner.BLSPublicKey {
			return fmt.Errorf("this registration is for %s, not the node at %s (%s)", nodeID, candidate, mine)
		}
		// A validator counts from the moment it's registered: it must
		// already be caught up on the P-Chain and the L1, ready to sign.
		msg, err := warp.ParseMessage(signed)
		if err != nil {
			return err
		}
		for _, chain := range []string{"P", msg.UnsignedMessage.SourceChainID.String()} {
			if *skipBootstrap {
				fmt.Fprintln(os.Stderr, "WARNING: not checking the candidate node has bootstrapped; it counts as a validator from the moment it's registered")
				break
			}
			done, err := info.NewClient(candidate).IsBootstrapped(context.Background(), chain)
			if err != nil {
				return fmt.Errorf("asking the candidate node whether it has bootstrapped %s: %w", chain, err)
			}
			if !done {
				return fmt.Errorf("the candidate node hasn't finished bootstrapping %s; register once it has (sudo ./setup.sh --status)", chain)
			}
		}
	}
	popBytes, err := unhex(reg.BLSProofOfPossession, "blsProofOfPossession")
	if err != nil {
		return err
	}
	var pop [bls.SignatureLen]byte
	copy(pop[:], popBytes)
	wallet, err := pWallet(*uri, *keyPath)
	if err != nil {
		return err
	}
	tx, err := wallet.IssueRegisterL1ValidatorTx(uint64(*balance*float64(units.Avax)), pop, signed)
	if err != nil {
		return fmt.Errorf("registering: %w", err)
	}
	return printJSON(map[string]string{"nodeID": reg.NodeID, "validationID": reg.ValidationID, "txID": tx.ID().String()})
}

// registrationIn returns the RegisterL1Validator inside a signed Warp message.
func registrationIn(signed []byte) (*message.RegisterL1Validator, error) {
	msg, err := warp.ParseMessage(signed)
	if err != nil {
		return nil, fmt.Errorf("not a signed Warp message: %w", err)
	}
	call, err := payload.ParseAddressedCall(msg.UnsignedMessage.Payload)
	if err != nil {
		return nil, fmt.Errorf("not an addressed call: %w", err)
	}
	return message.ParseRegisterL1Validator(call.Payload)
}

// cmdRemove starts a proposal to remove a validator (set its weight to 0).
func cmdRemove(args []string) error { return weightProposal("remove", args, false) }

// cmdSetWeight starts a proposal to change a validator's weight: to raise a
// validator added at a small weight once it's active, say.
func cmdSetWeight(args []string) error { return weightProposal("set-weight", args, true) }

func weightProposal(name string, args []string, withWeight bool) error {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	l1 := addL1Flags(fs)
	validationFlag := fs.String("validation-id", "", "the validator's validation ID (btcvm-l1 validators)")
	newWeight := new(uint64)
	if withWeight {
		newWeight = fs.Uint64("weight", 0, "its new weight (above 0; remove sets 0)")
	}
	replaceHeld := fs.Bool("replace-held", false, "the change replaces whatever change the validators hold (only if every admin approves)")
	keyPath := fs.String("key", "", "an admin key")
	valid := fs.Duration("valid-for", 72*time.Hour, "how long the other admins have to approve (at most "+vm.MaxApprovalLife.String()+")")
	yes := fs.Bool("yes", false, "approve without asking")
	sf := addSubmitFlags(fs, true)
	_ = fs.Parse(args)
	if *validationFlag == "" || *keyPath == "" {
		return errors.New("-validation-id and -key are required")
	}
	if withWeight && *newWeight == 0 {
		return errors.New("-weight must be above 0 (to remove a validator: remove)")
	}
	if *valid <= 0 || *valid > vm.MaxApprovalLife {
		return fmt.Errorf("-valid-for must be between 0 and %s", vm.MaxApprovalLife)
	}
	chainID, subnetID, err := l1.ids()
	if err != nil {
		return err
	}
	validationID, err := ids.FromString(*validationFlag)
	if err != nil {
		return err
	}
	current, _, err := platformvm.NewClient(*l1.nodeURI).GetL1Validator(context.Background(), validationID)
	if err != nil {
		return fmt.Errorf("reading the validator: %w", err)
	}
	// At the nonce the P-Chain expects next: the validators sign no other.
	w, err := message.NewL1ValidatorWeight(validationID, current.MinNonce, *newWeight)
	if err != nil {
		return err
	}
	networkID := uint32(*l1.networkID)
	unsigned, err := unsignedFor(networkID, chainID, w)
	if err != nil {
		return err
	}
	c := &change{unsigned: unsigned, weight: w}
	p := &proposal{UnsignedMessage: hexBytes(unsigned.Bytes()), ReplaceHeld: *replaceHeld}
	if err := c.label(p); err != nil {
		return err
	}
	p.setDeadline(time.Now().Add(*valid))
	if err := confirm(p, c, *l1.nodeURI, subnetID, *yes, false); err != nil {
		return err
	}
	if err := p.addApproval(unsigned, networkID, *keyPath); err != nil {
		return err
	}
	if *sf.rpcPassFile != "" {
		if *sf.payerPath == "" {
			*sf.payerPath = *keyPath
		}
		return submit(p, c, *l1.nodeURI, chainID, sf)
	}
	return printJSON(p)
}

// cmdTopUp adds METAL to a validator's balance for the continuous fee.
func cmdTopUp(args []string) error {
	fs := flag.NewFlagSet("top-up", flag.ExitOnError)
	validationFlag := fs.String("validation-id", "", "the validator's validation ID")
	keyPath := fs.String("key", "", "the P-Chain key that pays")
	uri := fs.String("uri", "http://127.0.0.1:9650", "a node's API, for the P-Chain")
	balance := fs.Float64("balance", 1, "METAL to add")
	_ = fs.Parse(args)
	validationID, err := ids.FromString(*validationFlag)
	if err != nil {
		return fmt.Errorf("-validation-id: %w", err)
	}
	wallet, err := pWallet(*uri, *keyPath)
	if err != nil {
		return err
	}
	tx, err := wallet.IssueIncreaseL1ValidatorBalanceTx(validationID, uint64(*balance*float64(units.Avax)))
	if err != nil {
		return err
	}
	return printJSON(map[string]string{"validationID": validationID.String(), "txID": tx.ID().String()})
}

// cmdDisable ends a validator from its owner's side: the P-Chain stops it
// and returns the rest of its balance to the owner. (Its weight stays on the
// L1's books until an admin removes it, but it no longer validates.)
func cmdDisable(args []string) error {
	fs := flag.NewFlagSet("disable", flag.ExitOnError)
	validationFlag := fs.String("validation-id", "", "the validator's validation ID")
	keyPath := fs.String("key", "", "the validator's owner key (the -owner of its request)")
	uri := fs.String("uri", "http://127.0.0.1:9650", "a node's API, for the P-Chain")
	last := fs.Bool("last", false, "disable it even if that stops the L1 or leaves its validators unchangeable")
	_ = fs.Parse(args)
	validationID, err := ids.FromString(*validationFlag)
	if err != nil {
		return fmt.Errorf("-validation-id: %w", err)
	}
	if !*last {
		pc := platformvm.NewClient(*uri)
		v, _, err := pc.GetL1Validator(context.Background(), validationID)
		if err != nil {
			return fmt.Errorf("reading the validator: %w", err)
		}
		vdrs, err := pc.GetCurrentValidators(context.Background(), v.SubnetID, nil)
		if err != nil {
			return fmt.Errorf("reading the L1's validators: %w", err)
		}
		// A disabled validator keeps its weight in the total but can't sign:
		// the rest must still make 67%, or no change could be signed again
		// (not even removing it).
		total, signable := new(big.Int), new(big.Int)
		others := 0
		for _, o := range vdrs {
			if o.ValidationID == nil {
				continue
			}
			w := new(big.Int).SetUint64(o.Weight)
			total.Add(total, w)
			if *o.ValidationID != validationID && o.Balance != nil && *o.Balance > 0 {
				signable.Add(signable, w)
				others++
			}
		}
		if others == 0 {
			return errors.New("this is the L1's last active validator: disabling it stops the L1 (-last does it anyway)")
		}
		if !vm.Quorum(signable, total) {
			return fmt.Errorf("after disabling it the validators able to sign would hold %s of the weight, under the 67%% any change needs: "+
				"the L1's validators could never be changed again. Ask the admins to remove it instead (-last does it anyway)", vm.Percent(signable, total))
		}
	}
	wallet, err := pWallet(*uri, *keyPath)
	if err != nil {
		return err
	}
	tx, err := wallet.IssueDisableL1ValidatorTx(validationID)
	if err != nil {
		return err
	}
	return printJSON(map[string]string{"validationID": validationID.String(), "txID": tx.ID().String()})
}

// cmdValidators lists the L1's validators.
func cmdValidators(args []string) error {
	fs := flag.NewFlagSet("validators", flag.ExitOnError)
	l1 := addL1Flags(fs)
	_ = fs.Parse(args)
	_, subnetID, err := l1.ids()
	if err != nil {
		return err
	}
	vdrs, err := platformvm.NewClient(*l1.nodeURI).GetCurrentValidators(context.Background(), subnetID, nil)
	if err != nil {
		return err
	}
	type row struct {
		NodeID       string  `json:"nodeID"`
		Weight       uint64  `json:"weight"`
		ValidationID string  `json:"validationID,omitempty"`
		BalanceMETAL float64 `json:"balanceMETAL"`
	}
	rows := []row{}
	for _, v := range vdrs {
		r := row{NodeID: v.NodeID.String(), Weight: v.Weight}
		if v.ValidationID != nil {
			r.ValidationID = v.ValidationID.String()
		}
		if v.Balance != nil {
			r.BalanceMETAL = float64(*v.Balance) / float64(units.Avax)
		}
		rows = append(rows, r)
	}
	return printJSON(rows)
}
