// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

// Adding and removing the L1's validators (proof of authority).
//
// The L1's manager is the BTCVM chain itself (see create), so each change
// is a Warp message from the chain that the L1's current validators sign,
// and each validator signs only a change an admin approved (the admins are
// "validatorAdmins" in each validator's chain config; vm/validator_manager.go).
//
//	candidate:  btcvm-l1 request -node-uri http://127.0.0.1:9650 -owner P-metal1... > request.json
//	admin:      btcvm-l1 approve -request request.json -key admin-key.json \
//	              -node-uri http://127.0.0.1:9660 -rpc-pass-file rpc-password > registration.json
//	candidate:  btcvm-l1 register -registration registration.json -key my-p-chain-key.json -balance 1
//	admin:      btcvm-l1 remove -validation-id ... -key admin-key.json -node-uri ... -rpc-pass-file ...
//	anyone:     btcvm-l1 top-up -validation-id ... -key p-chain-key.json -balance 1
//	owner:      btcvm-l1 disable -validation-id ... -key owner-key.json   (ends it; the unused balance returns to the owner)
//	anyone:     btcvm-l1 validators -node-uri ...
//
// Nothing secret changes hands: a request holds the candidate's NodeID and
// BLS public key and proof of possession; a registration holds the signed
// Warp message. Each party's private key stays in its own key file.

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
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
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

// approveAndCollect signs an unsigned message as the admin and has the
// validator node at nodeURI collect the L1 validators' signatures on it.
func approveAndCollect(nodeURI string, chainID ids.ID, adminKeyPath, rpcUser, rpcPassFile string, unsigned *warp.UnsignedMessage) (*warp.Message, error) {
	key, err := readKey(adminKeyPath)
	if err != nil {
		return nil, fmt.Errorf("admin key: %w", err)
	}
	approval, err := key.SignHash(vm.ApprovalHash(unsigned.Bytes()))
	if err != nil {
		return nil, err
	}
	pass, err := os.ReadFile(rpcPassFile)
	if err != nil {
		return nil, fmt.Errorf("-rpc-pass-file: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"message": hexBytes(unsigned.Bytes()), "justification": hexBytes(approval)})
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

func unsignedFor(networkID uint32, chainID ids.ID, p message.Payload) (*warp.UnsignedMessage, error) {
	// The L1's manager address is empty (see create).
	call, err := payload.NewAddressedCall(nil, p.Bytes())
	if err != nil {
		return nil, err
	}
	return warp.NewUnsignedMessage(networkID, chainID, call.Bytes())
}

// cmdApprove approves a candidate's request and prints the registration.
func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	l1 := addL1Flags(fs)
	requestPath := fs.String("request", "", "the candidate's request.json")
	keyPath := fs.String("key", "", "an admin key (its P-Chain address is in the validators' validatorAdmins)")
	rpcUser := fs.String("rpc-user", "btcvm", "the validator node's BTCVM rpcUser")
	rpcPassFile := fs.String("rpc-pass-file", "", "file holding the validator node's BTCVM rpcPass")
	weight := fs.Uint64("weight", 100, "the new validator's weight (the first validator has 100)")
	valid := fs.Duration("valid-for", time.Hour, "how long the candidate has to register (at most 24h)")
	_ = fs.Parse(args)
	if *requestPath == "" || *keyPath == "" || *rpcPassFile == "" {
		return errors.New("-request, -key and -rpc-pass-file are required")
	}
	if *valid <= 0 || *valid > 24*time.Hour {
		return errors.New("-valid-for must be between 0 and 24h")
	}
	chainID, subnetID, err := l1.ids()
	if err != nil {
		return err
	}
	var req validatorRequest
	if err := readJSON(*requestPath, &req); err != nil {
		return fmt.Errorf("-request: %w", err)
	}
	nodeID, err := ids.NodeIDFromString(req.NodeID)
	if err != nil {
		return fmt.Errorf("request nodeID: %w", err)
	}
	pkBytes, err := unhex(req.BLSPublicKey, "request blsPublicKey")
	if err != nil {
		return err
	}
	popBytes, err := unhex(req.BLSProofOfPossession, "request blsProofOfPossession")
	if err != nil {
		return err
	}
	// The P-Chain checks the proof of possession at registration; checking
	// it here catches a mistyped request before anyone signs.
	pk, err := bls.PublicKeyFromCompressedBytes(pkBytes)
	if err != nil {
		return fmt.Errorf("request blsPublicKey: %w", err)
	}
	popSig, err := bls.SignatureFromBytes(popBytes)
	if err != nil {
		return fmt.Errorf("request blsProofOfPossession: %w", err)
	}
	if !bls.VerifyProofOfPossession(pk, popSig, pkBytes) {
		return errors.New("the request's proof of possession doesn't match its BLS key")
	}
	owner, err := pOwner(req.Owner)
	if err != nil {
		return fmt.Errorf("request owner: %w", err)
	}
	var pkArr [bls.PublicKeyLen]byte
	copy(pkArr[:], pkBytes)
	expiry := time.Now().Add(*valid)
	reg, err := message.NewRegisterL1Validator(subnetID, nodeID, pkArr, uint64(expiry.Unix()), owner, owner, *weight)
	if err != nil {
		return err
	}
	unsigned, err := unsignedFor(uint32(*l1.networkID), chainID, reg)
	if err != nil {
		return err
	}
	signed, err := approveAndCollect(*l1.nodeURI, chainID, *keyPath, *rpcUser, *rpcPassFile, unsigned)
	if err != nil {
		return err
	}
	return printJSON(registration{
		NodeID:               nodeID.String(),
		ValidationID:         reg.ValidationID().String(),
		Weight:               *weight,
		Expiry:               expiry.UTC().Format(time.RFC3339),
		BLSProofOfPossession: req.BLSProofOfPossession,
		SignedMessage:        hexBytes(signed.Bytes()),
	})
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

// cmdRemove removes a validator (sets its weight to 0).
func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	l1 := addL1Flags(fs)
	validationFlag := fs.String("validation-id", "", "the validator's validation ID (btcvm-l1 validators)")
	keyPath := fs.String("key", "", "an admin key")
	payerPath := fs.String("payer-key", "", "the P-Chain key that pays the fee (default: -key)")
	rpcUser := fs.String("rpc-user", "btcvm", "the validator node's BTCVM rpcUser")
	rpcPassFile := fs.String("rpc-pass-file", "", "file holding the validator node's BTCVM rpcPass")
	_ = fs.Parse(args)
	if *validationFlag == "" || *keyPath == "" || *rpcPassFile == "" {
		return errors.New("-validation-id, -key and -rpc-pass-file are required")
	}
	chainID, _, err := l1.ids()
	if err != nil {
		return err
	}
	validationID, err := ids.FromString(*validationFlag)
	if err != nil {
		return err
	}
	ctx := context.Background()
	current, _, err := platformvm.NewClient(*l1.nodeURI).GetL1Validator(ctx, validationID)
	if err != nil {
		return fmt.Errorf("reading the validator: %w", err)
	}
	w, err := message.NewL1ValidatorWeight(validationID, current.MinNonce, 0)
	if err != nil {
		return err
	}
	unsigned, err := unsignedFor(uint32(*l1.networkID), chainID, w)
	if err != nil {
		return err
	}
	signed, err := approveAndCollect(*l1.nodeURI, chainID, *keyPath, *rpcUser, *rpcPassFile, unsigned)
	if err != nil {
		return err
	}
	payer := *payerPath
	if payer == "" {
		payer = *keyPath
	}
	wallet, err := pWallet(*l1.nodeURI, payer)
	if err != nil {
		return err
	}
	tx, err := wallet.IssueSetL1ValidatorWeightTx(signed.Bytes())
	if err != nil {
		return fmt.Errorf("removing: %w", err)
	}
	return printJSON(map[string]string{"validationID": validationID.String(), "txID": tx.ID().String()})
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
