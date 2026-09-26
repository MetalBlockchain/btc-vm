// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p"
	"github.com/MetalBlockchain/metalgo/network/p2p/acp118"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/payload"
)

// The L1's validator manager.
//
// The L1 was converted with this chain as its validator manager and an
// empty manager address (cmd/btcvm-l1), so the P-Chain changes the L1's
// validator set only on a Warp message from this chain, with that empty
// source address, signed by at least 67% of the L1's validator weight
// (RegisterL1ValidatorTx, SetL1ValidatorWeightTx).
//
// Each validator signs such a message only when one of the admins in its
// chain config ("validatorAdmins": P-Chain addresses) approved it: proof of
// authority. The approval is the admin key's signature over
// ApprovalHash(message), sent as the ACP-118 justification. Signing is node
// policy, not consensus: blocks and their validity are unchanged, and a node
// with no admins configured signs nothing.

// ApprovalDomain prefixes what an admin signs, so an approval can never be
// mistaken for any other signature made with the same key (a P-Chain
// transaction signs the hash of its own bytes).
const ApprovalDomain = "Metal L1 validator change, approved\x00"

// Signing a request, or answering one, gives up after this long.
const aggregateTimeout = 30 * time.Second

// ApprovalHash is what an admin signs to approve an unsigned Warp message.
func ApprovalHash(unsignedMessage []byte) []byte {
	h := sha256.New()
	h.Write([]byte(ApprovalDomain))
	h.Write(unsignedMessage)
	return h.Sum(nil)
}

// validatorAdminsConfig is the part of the chain config the manager reads.
type validatorAdminsConfig struct {
	ValidatorAdmins []string `json:"validatorAdmins"`
}

// parseValidatorAdmins reads "validatorAdmins" from the chain config.
func parseValidatorAdmins(configBytes []byte) (set.Set[ids.ShortID], error) {
	admins := set.Set[ids.ShortID]{}
	if len(configBytes) == 0 {
		return admins, nil
	}
	var cfg validatorAdminsConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, err
	}
	for _, a := range cfg.ValidatorAdmins {
		id, err := address.ParseToID(a)
		if err != nil {
			return nil, fmt.Errorf("validatorAdmins: %q is not a P-Chain address: %w", a, err)
		}
		admins.Add(id)
	}
	return admins, nil
}

type validatorManager struct {
	vm         *VM
	admins     set.Set[ids.ShortID]
	aggregator *acp118.SignatureAggregator
}

var _ acp118.Verifier = (*validatorManager)(nil)

const (
	errCodeNotManaged = iota + 1
	errCodeNotApproved
)

func appError(code int32, format string, args ...any) *common.AppError {
	return &common.AppError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Verify decides whether this node signs an unsigned Warp message: a
// validator registration for this L1, or a validator weight change (weight
// 0 removes a validator), from this chain as the L1's manager, approved by
// an admin.
func (m *validatorManager) Verify(_ context.Context, msg *warp.UnsignedMessage, justification []byte) *common.AppError {
	ctx := m.vm.ctx
	if msg.NetworkID != ctx.NetworkID || msg.SourceChainID != ctx.ChainID {
		return appError(errCodeNotManaged, "message is for network %d chain %s, not this chain", msg.NetworkID, msg.SourceChainID)
	}
	call, err := payload.ParseAddressedCall(msg.Payload)
	if err != nil {
		return appError(errCodeNotManaged, "not an addressed call: %s", err)
	}
	// The L1 was converted with an empty manager address; any other source
	// address would not be accepted by the P-Chain as the manager.
	if len(call.SourceAddress) != 0 {
		return appError(errCodeNotManaged, "source address must be empty (the L1's manager address)")
	}
	parsed, err := message.Parse(call.Payload)
	if err != nil {
		return appError(errCodeNotManaged, "not a validator message: %s", err)
	}
	switch p := parsed.(type) {
	case *message.RegisterL1Validator:
		if p.SubnetID != ctx.SubnetID {
			return appError(errCodeNotManaged, "registration is for subnet %s, not this L1's %s", p.SubnetID, ctx.SubnetID)
		}
		if p.Weight == 0 {
			return appError(errCodeNotManaged, "a registration needs a weight above 0")
		}
	case *message.L1ValidatorWeight:
		// The P-Chain checks that the validation belongs to this L1 (its
		// manager is this chain) and that the nonce is fresh.
	default:
		return appError(errCodeNotManaged, "this chain signs validator registrations and weight changes only, not %T", parsed)
	}
	if m.admins.Len() == 0 {
		return appError(errCodeNotApproved, "this node has no validatorAdmins in its chain config, so it approves no validator changes")
	}
	if len(justification) != secp256k1.SignatureLen {
		return appError(errCodeNotApproved, "the change carries no admin approval")
	}
	pub, err := secp256k1.RecoverPublicKeyFromHash(ApprovalHash(msg.Bytes()), justification)
	if err != nil {
		return appError(errCodeNotApproved, "bad admin approval: %s", err)
	}
	if !m.admins.Contains(pub.Address()) {
		return appError(errCodeNotApproved, "approved by %s, which is not one of this L1's validatorAdmins", pub.Address())
	}
	return nil
}

// Aggregate signs an approved change with this node's key, collects the
// other validators' signatures, and returns the signed Warp message with
// the weight that signed it.
func (m *validatorManager) Aggregate(parent context.Context, unsignedBytes, justification []byte) (*warp.Message, *big.Int, *big.Int, error) {
	ctx, cancel := context.WithTimeout(parent, aggregateTimeout)
	defer cancel()

	unsigned, err := warp.ParseUnsignedMessage(unsignedBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("not a Warp message: %w", err)
	}
	if appErr := m.Verify(ctx, unsigned, justification); appErr != nil {
		return nil, nil, nil, errors.New(appErr.Message)
	}
	snowCtx := m.vm.ctx
	// The P-Chain checks the signatures against the L1's validators at the
	// P-Chain height its block proposer picks, which lags the tip (the
	// minimum height, as proposervm uses). Signing for the same height means
	// a validator added or removed moments ago counts only once the P-Chain
	// itself would count it; until then, a change needs a retry.
	height, err := snowCtx.ValidatorState.GetMinimumHeight(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the P-Chain height: %w", err)
	}
	vdrs, err := warp.GetCanonicalValidatorSetFromSubnetID(ctx, snowCtx.ValidatorState, height, snowCtx.SubnetID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the L1's validators: %w", err)
	}
	tip, err := snowCtx.ValidatorState.GetCurrentHeight(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the P-Chain height: %w", err)
	}
	if tip != height {
		now, err := warp.GetCanonicalValidatorSetFromSubnetID(ctx, snowCtx.ValidatorState, tip, snowCtx.SubnetID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reading the L1's validators: %w", err)
		}
		if !sameValidators(vdrs, now) {
			return nil, nil, nil, errValidatorSetSettling
		}
	}

	// This node's own signature first; the aggregator asks only the others.
	sig := &warp.BitSetSignature{}
	for i, v := range vdrs.Validators {
		if !containsNode(v.NodeIDs, snowCtx.NodeID) {
			continue
		}
		own, err := snowCtx.WarpSigner.Sign(unsigned)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("signing: %w", err)
		}
		bits := set.NewBits(i)
		sig.Signers = bits.Bytes()
		copy(sig.Signature[:], own)
		break
	}
	msg, err := warp.NewMessage(unsigned, sig)
	if err != nil {
		return nil, nil, nil, err
	}
	return m.aggregator.AggregateSignatures(ctx, msg, justification, vdrs.Validators, 67, 100)
}

// errValidatorSetSettling: signatures made now might be checked against
// either validator set, so none are made.
var errValidatorSetSettling = errors.New("the L1's validators changed moments ago and the P-Chain doesn't count the change yet; try again in a minute or two")

func sameValidators(a, b warp.CanonicalValidatorSet) bool {
	if len(a.Validators) != len(b.Validators) || a.TotalWeight != b.TotalWeight {
		return false
	}
	for i := range a.Validators {
		if a.Validators[i].Weight != b.Validators[i].Weight || !bytes.Equal(a.Validators[i].PublicKeyBytes, b.Validators[i].PublicKeyBytes) {
			return false
		}
	}
	return true
}

func containsNode(nodeIDs []ids.NodeID, want ids.NodeID) bool {
	for _, n := range nodeIDs {
		if n == want {
			return true
		}
	}
	return false
}

// newValidatorManager registers the ACP-118 signature handler on the VM's
// p2p network and a client for collecting signatures.
func newValidatorManager(vm *VM, network *p2p.Network, admins set.Set[ids.ShortID]) (*validatorManager, error) {
	m := &validatorManager{vm: vm, admins: admins}
	if err := network.AddHandler(acp118.HandlerID, acp118.NewHandler(m, vm.ctx.WarpSigner)); err != nil {
		return nil, fmt.Errorf("registering the signature handler: %w", err)
	}
	client := network.NewClient(acp118.HandlerID, vm.p2pValidators)
	m.aggregator = acp118.NewSignatureAggregator(vm.ctx.Log, client)
	return m, nil
}

// --- HTTP: /ext/bc/<chain>/validators ------------------------------------------

type aggregateRequest struct {
	Message       string `json:"message"`       // hex unsigned Warp message
	Justification string `json:"justification"` // hex admin approval
}

type aggregateReply struct {
	SignedMessage string `json:"signedMessage"`
	SignedWeight  string `json:"signedWeight"`
	TotalWeight   string `json:"totalWeight"`
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// ServeHTTP collects the L1 validators' signatures on an approved change.
// It needs the chain config's rpcUser/rpcPass: collecting signatures sends a
// request to every validator. (The approval, not this login, is what makes
// validators sign.)
func (m *validatorManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fail := func(code int, format string, args ...any) {
		http.Error(w, fmt.Sprintf(format, args...), code)
	}
	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "POST a JSON {message, justification}")
		return
	}
	cfg := m.vm.config
	user, pass, ok := r.BasicAuth()
	if cfg.RPCUser == "" || cfg.RPCPass == "" || !ok ||
		subtle.ConstantTimeCompare([]byte(user), []byte(cfg.RPCUser)) != 1 ||
		subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.RPCPass)) != 1 {
		fail(http.StatusUnauthorized, "this needs the chain's rpcUser and rpcPass")
		return
	}
	var req aggregateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "bad request: %s", err)
		return
	}
	unsigned, err := decodeHex(req.Message)
	if err != nil {
		fail(http.StatusBadRequest, "message: %s", err)
		return
	}
	justification, err := decodeHex(req.Justification)
	if err != nil {
		fail(http.StatusBadRequest, "justification: %s", err)
		return
	}
	msg, signed, total, err := m.Aggregate(r.Context(), unsigned, justification)
	if err != nil {
		fail(http.StatusForbidden, "%s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aggregateReply{
		SignedMessage: "0x" + hex.EncodeToString(msg.Bytes()),
		SignedWeight:  signed.String(),
		TotalWeight:   total.String(),
	})
}
