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
//	submitter:  btcvm-l1 submit -proposal proposal2.json -node-uri http://127.0.0.1:9660 \
//	              -rpc-pass-file rpc-password > registration.json
//	candidate:  btcvm-l1 register -registration registration.json -key my-p-chain-key.json -balance 1
//	admin 1:    btcvm-l1 remove -validation-id ... -key admin1-key.json -node-uri ... > proposal.json
//	            (then approve -proposal and submit as above; submit -payer-key pays the P-Chain fee)
//	anyone:     btcvm-l1 top-up -validation-id ... -key p-chain-key.json -balance 1
//	owner:      btcvm-l1 disable -validation-id ... -key owner-key.json   (ends it; the unused balance returns to the owner)
//	anyone:     btcvm-l1 validators -node-uri ...
//
// approve and remove also take -rpc-pass-file, to submit at once when this
// approval is the last one needed.
//
// Nothing secret changes hands: a request holds the candidate's NodeID and
// BLS public key and proof of possession; a proposal holds the unsigned
// change and the admins' approvals; a registration holds the signed Warp
// message. Each party's private key stays in its own key file.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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
	Change          string   `json:"change"` // "register" or "set-weight"
	Summary         string   `json:"summary"`
	UnsignedMessage string   `json:"unsignedMessage"`
	Approvals       []string `json:"approvals"`
	ApprovedBy      []string `json:"approvedBy"`
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
		var owners []string
		for _, a := range c.reg.RemainingBalanceOwner.Addresses {
			addr, err := address.Format("P", constants.GetHRP(c.unsigned.NetworkID), a.Bytes())
			if err != nil {
				return err
			}
			owners = append(owners, addr)
		}
		p.Summary = fmt.Sprintf("register %s on subnet %s with weight %d; what's left of its balance returns to %s; valid until %s",
			nodeID, c.reg.SubnetID, c.reg.Weight, strings.Join(owners, ", "), p.Expiry)
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

// check refuses a registration that has expired: nobody could register it.
func (c *change) check() error {
	if c.reg != nil && time.Now().Unix() >= int64(c.reg.Expiry) {
		return fmt.Errorf("this registration expired at %s; start a new one", time.Unix(int64(c.reg.Expiry), 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// approvals decodes a proposal's approvals and who gave each.
func (p *proposal) approvals(unsigned *warp.UnsignedMessage) ([][]byte, []ids.ShortID, error) {
	hash := vm.ApprovalHash(unsigned.Bytes())
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
	sig, err := key.SignHash(vm.ApprovalHash(unsigned.Bytes()))
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
	if _, _, err := p.approvals(c.unsigned); err != nil {
		return nil, nil, err
	}
	return &p, c, nil
}

// collect has the validator node at nodeURI collect the L1 validators'
// signatures on an approved change.
func collect(nodeURI string, chainID ids.ID, rpcUser, rpcPassFile string, unsigned *warp.UnsignedMessage, approvals [][]byte) (*warp.Message, error) {
	pass, err := os.ReadFile(rpcPassFile)
	if err != nil {
		return nil, fmt.Errorf("-rpc-pass-file: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"message": hexBytes(unsigned.Bytes()), "justification": hexBytes(bytes.Join(approvals, nil))})
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
	fmt.Fprintf(os.Stderr, "signed by weight %s of %s\n", reply.SignedWeight, reply.TotalWeight)
	return warp.ParseMessage(signed)
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
	if err := c.check(); err != nil {
		return err
	}
	sigs, _, err := p.approvals(c.unsigned)
	if err != nil {
		return err
	}
	if c.weight != nil && *f.payerPath == "" {
		return errors.New("-payer-key is needed to issue a weight change")
	}
	signed, err := collect(nodeURI, chainID, *f.rpcUser, *f.rpcPassFile, c.unsigned, sigs)
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
	sf := addSubmitFlags(fs, true)
	_ = fs.Parse(args)
	if (*requestPath == "") == (*proposalPath == "") || *keyPath == "" {
		return errors.New("-key and one of -request or -proposal are required")
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
		p = &proposal{UnsignedMessage: hexBytes(unsigned.Bytes()), BLSProofOfPossession: pop}
		if err := c.label(p); err != nil {
			return err
		}
	}
	if err := c.check(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approving: %s\n", p.Summary)
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
	otherNode := fs.Bool("other-node", false, "register it even though it isn't for the node at -uri")
	_ = fs.Parse(args)
	if *regPath == "" || *keyPath == "" {
		return errors.New("-registration and -key are required")
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
	if !*otherNode {
		mine, pop, err := info.NewClient(*uri).GetNodeID(context.Background())
		if err != nil {
			return fmt.Errorf("reading the node at -uri (to check the registration is for it): %w", err)
		}
		if mine != nodeID || pop == nil || pop.PublicKey != inner.BLSPublicKey {
			return fmt.Errorf("this registration is for %s, not the node at -uri (%s); -other-node registers it anyway", nodeID, mine)
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
func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	l1 := addL1Flags(fs)
	validationFlag := fs.String("validation-id", "", "the validator's validation ID (btcvm-l1 validators)")
	keyPath := fs.String("key", "", "an admin key")
	sf := addSubmitFlags(fs, true)
	_ = fs.Parse(args)
	if *validationFlag == "" || *keyPath == "" {
		return errors.New("-validation-id and -key are required")
	}
	chainID, _, err := l1.ids()
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
	w, err := message.NewL1ValidatorWeight(validationID, current.MinNonce, 0)
	if err != nil {
		return err
	}
	networkID := uint32(*l1.networkID)
	unsigned, err := unsignedFor(networkID, chainID, w)
	if err != nil {
		return err
	}
	c := &change{unsigned: unsigned, weight: w}
	p := &proposal{UnsignedMessage: hexBytes(unsigned.Bytes())}
	if err := c.label(p); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approving: %s\n", p.Summary)
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
	_ = fs.Parse(args)
	validationID, err := ids.FromString(*validationFlag)
	if err != nil {
		return fmt.Errorf("-validation-id: %w", err)
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
