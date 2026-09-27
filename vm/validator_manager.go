// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p"
	"github.com/MetalBlockchain/metalgo/network/p2p/acp118"
	"github.com/MetalBlockchain/metalgo/proto/pb/sdk"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/snow/validators"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/payload"
	"google.golang.org/protobuf/proto"
)

// The L1's validator manager.
//
// The L1 was converted with this chain as its validator manager and an
// empty manager address (cmd/btcvm-l1), so the P-Chain changes the L1's
// validator set only on a Warp message from this chain, with that empty
// source address, signed by at least 67% of the L1's validator weight
// (RegisterL1ValidatorTx, SetL1ValidatorWeightTx).
//
// Each validator signs such a message only when enough of the admins in its
// chain config approved it: proof of authority, M of N. The admins are
// "validatorAdmins" (P-Chain addresses); M is "validatorAdminThreshold",
// by default a majority of them, and never 1 when there are several. An
// approval is an admin key's signature over ApprovalHash(message,
// deadline); the ACP-118 justification (EncodeJustification) carries the
// deadline and M or more approvals, each by a different admin. So no one
// admin key can change the validator set alone, and approvals expire.
//
// A change is also checked against the L1's current validators (see
// checkChange): a weight change must be for one of them; a registration
// can't reuse a registered BLS key; the validators able to sign must still
// reach the P-Chain's 67% of the whole registered weight afterwards (only a
// registration approved by every admin may count on the newcomer); and a
// change after which any one BLS key could block that quorum alone needs
// every admin.
//
// Changes don't add up behind the policy's back: a node signs one change at
// a time. Until the change it last signed is on the P-Chain or can no
// longer be (a registration past its expiry, a weight change whose nonce
// the P-Chain has moved past), it signs only that same change again, or a
// weight change replacing it at the same nonce (only one of the two can
// ever apply). Any 67% of the weight asked to sign a second change includes
// validators still holding the first, so the second never gathers enough.
//
// Signing is node policy, not consensus: blocks and their validity are
// unchanged, and a node with no admins configured signs nothing.

// ApprovalDomain prefixes what an admin signs, so an approval can never be
// mistaken for any other signature made with the same key (a P-Chain
// transaction signs the hash of its own bytes).
const ApprovalDomain = "Metal L1 validator change, approved\x00"

// Signing a request, or answering one, gives up after this long.
const aggregateTimeout = 30 * time.Second

// ApprovalVersion is the format of an approval and of the justification
// that carries approvals.
const ApprovalVersion byte = 1

// MaxApprovalLife bounds how far ahead an approval's deadline can be: long
// enough for admins to sign in turn, short enough that a forgotten
// approval dies.
const MaxApprovalLife = 7 * 24 * time.Hour

// justificationHeader is the version byte and the 8-byte deadline.
const justificationHeader = 1 + 8

// ApprovalHash is what every admin signs to approve an unsigned Warp message
// until deadline (Unix seconds):
//
//	sha256(ApprovalDomain || ApprovalVersion || deadline, 8 bytes big-endian || unsigned message)
func ApprovalHash(unsignedMessage []byte, deadline uint64) []byte {
	h := sha256.New()
	h.Write([]byte(ApprovalDomain))
	h.Write([]byte{ApprovalVersion})
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], deadline)
	h.Write(d[:])
	h.Write(unsignedMessage)
	return h.Sum(nil)
}

// EncodeJustification is the ACP-118 justification for approvals of one
// message, all with the same deadline:
//
//	ApprovalVersion || deadline, 8 bytes big-endian || approval (65 bytes) ...
func EncodeJustification(deadline uint64, approvals [][]byte) []byte {
	out := make([]byte, justificationHeader, justificationHeader+len(approvals)*secp256k1.SignatureLen)
	out[0] = ApprovalVersion
	binary.BigEndian.PutUint64(out[1:], deadline)
	for _, a := range approvals {
		out = append(out, a...)
	}
	return out
}

func decodeJustification(b []byte) (uint64, [][]byte, error) {
	if len(b) < justificationHeader {
		return 0, nil, errors.New("the change carries no admin approvals")
	}
	if b[0] != ApprovalVersion {
		return 0, nil, fmt.Errorf("approval format %d; this node reads format %d", b[0], ApprovalVersion)
	}
	deadline := binary.BigEndian.Uint64(b[1:justificationHeader])
	rest := b[justificationHeader:]
	if len(rest) == 0 || len(rest)%secp256k1.SignatureLen != 0 {
		return 0, nil, errors.New("the change carries no whole admin approvals (each is a 65-byte signature)")
	}
	var sigs [][]byte
	for len(rest) > 0 {
		sigs = append(sigs, rest[:secp256k1.SignatureLen])
		rest = rest[secp256k1.SignatureLen:]
	}
	return deadline, sigs, nil
}

// validatorAdminsConfig is the part of the chain config the manager reads.
type validatorAdminsConfig struct {
	ValidatorAdmins         []string `json:"validatorAdmins"`
	ValidatorAdminThreshold *int     `json:"validatorAdminThreshold"`
}

// adminPolicy is who approves validator changes, and how many of them must.
type adminPolicy struct {
	admins    set.Set[ids.ShortID]
	threshold int
}

// majority is the default threshold: more than half of n admins.
func majority(n int) int { return n/2 + 1 }

// parseValidatorAdmins reads "validatorAdmins" and "validatorAdminThreshold"
// from the chain config. A threshold outside 1..len(admins) is an error, so
// a typo can't leave a chain approving on fewer signatures than intended.
func parseValidatorAdmins(configBytes []byte) (adminPolicy, error) {
	p := adminPolicy{admins: set.Set[ids.ShortID]{}}
	if len(configBytes) == 0 {
		return p, nil
	}
	var cfg validatorAdminsConfig
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return adminPolicy{}, err
	}
	for _, a := range cfg.ValidatorAdmins {
		id, err := address.ParseToID(a)
		if err != nil {
			return adminPolicy{}, fmt.Errorf("validatorAdmins: %q is not a P-Chain address: %w", a, err)
		}
		if p.admins.Contains(id) {
			return adminPolicy{}, fmt.Errorf("validatorAdmins: %q is listed twice", a)
		}
		p.admins.Add(id)
	}
	n := p.admins.Len()
	switch {
	case cfg.ValidatorAdminThreshold == nil:
		p.threshold = majority(n)
	case n == 0:
		return adminPolicy{}, errors.New("validatorAdminThreshold is set but validatorAdmins is empty")
	case *cfg.ValidatorAdminThreshold < 1 || *cfg.ValidatorAdminThreshold > n:
		return adminPolicy{}, fmt.Errorf("validatorAdminThreshold %d must be between 1 and the %d validatorAdmins", *cfg.ValidatorAdminThreshold, n)
	case n > 1 && *cfg.ValidatorAdminThreshold < 2:
		// Several admins with a threshold of 1 is 1-of-N: any one stolen
		// key changes the validator set.
		return adminPolicy{}, fmt.Errorf("validatorAdminThreshold 1 with %d validatorAdmins would let any one of them change the validators alone; use at least 2", n)
	default:
		p.threshold = *cfg.ValidatorAdminThreshold
	}
	if n == 0 {
		p.threshold = 0
	}
	return p, nil
}

type validatorManager struct {
	vm     *VM
	policy adminPolicy
	client *p2p.Client
	db     database.Database // the manager's part of the VM database
	now    func() time.Time

	outstandingMu sync.Mutex
}

// Signature requests from peers are unauthenticated, each costing a
// P-Chain read and signature recoveries. Each peer gets its own budget, and
// all peers together a larger one; this node's own collection (Aggregate)
// isn't limited, so peers can't starve it.
const (
	peerRate    = 2
	peerBurst   = 10
	globalRate  = 20
	globalBurst = 100
	maxPeers    = 10_000 // budgets kept; beyond it they start over
)

// limitedHandler rate-limits peers' signature requests, per peer and in all.
type limitedHandler struct {
	p2p.Handler
	now    func() time.Time
	mu     sync.Mutex
	global *rateLimiter
	peers  map[ids.NodeID]*rateLimiter
}

func newLimitedHandler(h p2p.Handler, now func() time.Time) *limitedHandler {
	return &limitedHandler{Handler: h, now: now, global: newRateLimiter(globalRate, globalBurst), peers: map[ids.NodeID]*rateLimiter{}}
}

func (h *limitedHandler) AppRequest(ctx context.Context, nodeID ids.NodeID, deadline time.Time, request []byte) ([]byte, *common.AppError) {
	now := h.now()
	h.mu.Lock()
	peer := h.peers[nodeID]
	if peer == nil {
		if len(h.peers) >= maxPeers {
			h.peers = map[ids.NodeID]*rateLimiter{}
		}
		peer = newRateLimiter(peerRate, peerBurst)
		h.peers[nodeID] = peer
	}
	h.mu.Unlock()
	if !peer.allow(now) || !h.global.allow(now) {
		return nil, appError(errCodeBusy, "too many signature requests; try again shortly")
	}
	return h.Handler.AppRequest(ctx, nodeID, deadline, request)
}

// rateLimiter is a token bucket.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{tokens: burst, rate: rate, burst: burst}
}

func (l *rateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

var _ acp118.Verifier = (*validatorManager)(nil)

const (
	errCodeNotManaged = iota + 1
	errCodeNotApproved
	errCodeBusy
)

func appError(code int32, format string, args ...any) *common.AppError {
	return &common.AppError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Verify decides whether this node signs an unsigned Warp message: a
// validator registration for this L1, or a validator weight change (weight
// 0 removes a validator), from this chain as the L1's manager, approved by
// at least the threshold of admins.
func (m *validatorManager) Verify(ctx context.Context, msg *warp.UnsignedMessage, justification []byte) *common.AppError {
	snowCtx := m.vm.ctx
	if msg.NetworkID != snowCtx.NetworkID || msg.SourceChainID != snowCtx.ChainID {
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
		if p.SubnetID != snowCtx.SubnetID {
			return appError(errCodeNotManaged, "registration is for subnet %s, not this L1's %s", p.SubnetID, snowCtx.SubnetID)
		}
		if p.Weight == 0 {
			return appError(errCodeNotManaged, "a registration needs a weight above 0")
		}
	case *message.L1ValidatorWeight:
		// checkChange checks the validation is this L1's; the P-Chain checks
		// the nonce is fresh.
	default:
		return appError(errCodeNotManaged, "this chain signs validator registrations and weight changes only, not %T", parsed)
	}
	if m.policy.admins.Len() == 0 {
		return appError(errCodeNotApproved, "this node has no validatorAdmins in its chain config, so it approves no validator changes")
	}
	approvers, err := m.policy.approvers(msg.Bytes(), justification, m.clock())
	if err != nil {
		return appError(errCodeNotApproved, "%s", err)
	}
	if approvers.Len() < m.policy.threshold {
		return appError(errCodeNotApproved, "approved by %d of this L1's admins; it needs %d", approvers.Len(), m.policy.threshold)
	}
	current, _, err := snowCtx.ValidatorState.GetCurrentValidatorSet(ctx, snowCtx.SubnetID)
	if err != nil {
		return appError(errCodeNotManaged, "reading the L1's validators: %s", err)
	}
	m.outstandingMu.Lock()
	defer m.outstandingMu.Unlock()
	if appErr := m.checkOutstanding(msg.Bytes(), parsed, current); appErr != nil {
		return appErr
	}
	if appErr := m.policy.checkChange(parsed, current, approvers.Len()); appErr != nil {
		return appErr
	}
	if err := m.db.Put(outstandingKey, msg.Bytes()); err != nil {
		return appError(errCodeBusy, "recording the change before signing it: %s", err)
	}
	return nil
}

// outstandingKey holds the unsigned message of the change this node signed
// last, in the manager's part of the VM database.
var outstandingKey = []byte("outstanding")

// Past a registration's expiry, the P-Chain (whose clock can trail this
// node's) can't take it: wait this much longer to be sure.
const expirySlack = 10 * time.Minute

// checkOutstanding refuses a change while another this node signed may
// still reach the P-Chain (see the package comment).
func (m *validatorManager) checkOutstanding(msg []byte, change message.Payload, current map[ids.ID]*validators.GetCurrentValidatorOutput) *common.AppError {
	prev, err := m.db.Get(outstandingKey)
	if errors.Is(err, database.ErrNotFound) || (err == nil && bytes.Equal(prev, msg)) {
		return nil
	}
	if err != nil {
		return appError(errCodeBusy, "reading the change signed last: %s", err)
	}
	prevChange, err := parseChange(prev)
	if err != nil {
		// Unreadable (a format this node no longer knows): it can't be told
		// apart from a live change, so it holds until an operator clears it.
		return appError(errCodeNotApproved, "the change this node signed last can't be read (%s); nothing else is signed until it's cleared", err)
	}
	done := false
	var what string
	switch p := prevChange.(type) {
	case *message.RegisterL1Validator:
		_, registered := current[p.ValidationID()]
		expired := m.clock().After(time.Unix(int64(p.Expiry), 0).Add(expirySlack))
		done = registered || expired
		what = fmt.Sprintf("registration %s, until it's registered or expires at %s", p.ValidationID(), time.Unix(int64(p.Expiry), 0).UTC().Format(time.RFC3339))
	case *message.L1ValidatorWeight:
		v, ok := current[p.ValidationID]
		done = !ok || v.MinNonce > p.Nonce
		if w, same := change.(*message.L1ValidatorWeight); !done && same && w.ValidationID == p.ValidationID && w.Nonce == p.Nonce {
			return nil // replaces it: the P-Chain takes only one change per nonce
		}
		what = fmt.Sprintf("weight %d for validation %s at nonce %d, until the P-Chain has it", p.Weight, p.ValidationID, p.Nonce)
	}
	if !done {
		return appError(errCodeNotApproved, "this node signed another validator change that isn't on the P-Chain yet (%s): submit that one first, or replace a weight change at the same nonce", what)
	}
	if err := m.db.Delete(outstandingKey); err != nil {
		return appError(errCodeBusy, "clearing the change signed last: %s", err)
	}
	return nil
}

// parseChange is the validator change in an unsigned Warp message.
func parseChange(unsignedBytes []byte) (message.Payload, error) {
	unsigned, err := warp.ParseUnsignedMessage(unsignedBytes)
	if err != nil {
		return nil, err
	}
	call, err := payload.ParseAddressedCall(unsigned.Payload)
	if err != nil {
		return nil, err
	}
	return message.Parse(call.Payload)
}

func (m *validatorManager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// seat is one validation, as checkChange models it.
type seat struct {
	weight uint64
	active bool   // funded: its BLS key signs for it
	key    string // compressed BLS public key; Warp sums weight per key
}

// checkChange checks what an approved change does to the L1's current
// validators. Warp counts every registered validation's weight in the total
// (inactive ones too, with no key to sign), and sums weight per BLS key.
func (p adminPolicy) checkChange(change message.Payload, current map[ids.ID]*validators.GetCurrentValidatorOutput, approvals int) *common.AppError {
	seats := map[ids.ID]*seat{}
	for id, v := range current {
		s := &seat{weight: v.Weight, active: v.IsActive}
		if v.PublicKey != nil {
			s.key = string(bls.PublicKeyToCompressedBytes(v.PublicKey))
		}
		seats[id] = s
	}
	newcomer := false
	switch c := change.(type) {
	case *message.RegisterL1Validator:
		id := c.ValidationID()
		if _, ok := current[id]; ok {
			return appError(errCodeNotManaged, "validation %s is already registered", id)
		}
		for _, v := range current {
			if bytes.Equal(v.NodeID[:], c.NodeID) {
				return appError(errCodeNotManaged, "%s already validates this L1", v.NodeID)
			}
		}
		key := string(c.BLSPublicKey[:])
		for _, s := range seats {
			if s.key == key {
				return appError(errCodeNotManaged, "that BLS key is already registered for another validation: Warp would add their weight together")
			}
		}
		// Until it's funded and online it can't sign: count it in the
		// total, not in what can sign.
		seats[id] = &seat{weight: c.Weight, key: key}
		newcomer = true
	case *message.L1ValidatorWeight:
		s, ok := seats[c.ValidationID]
		if !ok {
			return appError(errCodeNotManaged, "validation %s is not one of this L1's validators", c.ValidationID)
		}
		if c.Weight == 0 {
			delete(seats, c.ValidationID)
		} else {
			s.weight = c.Weight // a weight change doesn't fund or reactivate it
		}
	}
	total, signable := new(big.Int), new(big.Int)
	byKey := map[string]*big.Int{}
	active := 0
	for id, s := range seats {
		w := new(big.Int).SetUint64(s.weight)
		total.Add(total, w)
		if s.active {
			signable.Add(signable, w)
			active++
		}
		k := s.key
		if k == "" {
			k = "validation:" + id.String()
		}
		if byKey[k] == nil {
			byKey[k] = new(big.Int)
		}
		byKey[k].Add(byKey[k], w)
	}
	all := approvals >= p.admins.Len()
	if active == 0 {
		return appError(errCodeNotManaged, "that would leave the L1 with no active validator")
	}
	// Afterwards the validators that can sign today must still make 67% of
	// the whole weight, or no later change could be signed. Growing from
	// one validator can't meet that (the newcomer must come online first):
	// only every admin together may count on it.
	if !quorumOf(signable, total) && !(newcomer && all) {
		msg := "after this change the validators able to sign hold %s of the L1's weight; the P-Chain needs 67%%, so no later change could be signed"
		if newcomer {
			msg += " until the new validator is funded and online: counting on that needs all %d admins"
			return appError(errCodeNotApproved, msg, percent(signable, total), p.admins.Len())
		}
		return appError(errCodeNotApproved, msg, percent(signable, total))
	}
	// One key that could block the quorum alone: the rest wouldn't make 67%.
	for _, w := range byKey {
		if blocks(w, total) && !all {
			return appError(errCodeNotApproved,
				"after this change one validator holds %s of the L1's weight, enough to block the P-Chain's 67%% alone; that needs all %d admins, and %d approved",
				percent(w, total), p.admins.Len(), approvals)
		}
	}
	return nil
}

// quorumOf is the P-Chain's check: signed*100 >= total*67.
func quorumOf(signed, total *big.Int) bool {
	lhs := new(big.Int).Mul(signed, big.NewInt(100))
	rhs := new(big.Int).Mul(total, big.NewInt(67))
	return lhs.Cmp(rhs) >= 0
}

// blocks: without w, the rest of total can't make the P-Chain's quorum.
func blocks(w, total *big.Int) bool {
	return !quorumOf(new(big.Int).Sub(total, w), total)
}

// Quorum, Blocks and Percent are for the admin tools, so they show exactly
// what the validators will decide.
func Quorum(signed, total *big.Int) bool { return quorumOf(signed, total) }
func Blocks(w, total *big.Int) bool      { return blocks(w, total) }
func Percent(w, total *big.Int) string   { return percent(w, total) }

// percent is w as a percentage of total, e.g. "33.3%".
func percent(w, total *big.Int) string {
	if total.Sign() == 0 {
		return "100%"
	}
	r := new(big.Rat).SetFrac(new(big.Int).Mul(w, big.NewInt(100)), total)
	f, _ := r.Float64()
	return fmt.Sprintf("%.1f%%", f)
}

// approvers checks every approval in a justification and returns the admins
// who gave them. An approval from a key that isn't an admin, a second one
// from the same admin, or a justification that isn't whole approvals
// refuses the lot: a well-formed request never has them.
func (p adminPolicy) approvers(unsignedMessage, justification []byte, now time.Time) (set.Set[ids.ShortID], error) {
	deadline, sigs, err := decodeJustification(justification)
	if err != nil {
		return nil, err
	}
	switch at := time.Unix(int64(deadline), 0); {
	case deadline > uint64(now.Add(MaxApprovalLife).Unix()):
		return nil, fmt.Errorf("the approvals' deadline %s is more than %s away", at.UTC().Format(time.RFC3339), MaxApprovalLife)
	case uint64(now.Unix()) > deadline:
		return nil, fmt.Errorf("the approvals expired at %s", at.UTC().Format(time.RFC3339))
	}
	if len(sigs) > p.admins.Len() {
		return nil, fmt.Errorf("%d approvals, but this L1 has only %d admins", len(sigs), p.admins.Len())
	}
	hash := ApprovalHash(unsignedMessage, deadline)
	approvers := set.NewSet[ids.ShortID](len(sigs))
	for i, sig := range sigs {
		pub, err := secp256k1.RecoverPublicKeyFromHash(hash, sig)
		if err != nil {
			return nil, fmt.Errorf("approval %d: %w", i+1, err)
		}
		who := pub.Address()
		if !p.admins.Contains(who) {
			return nil, fmt.Errorf("approval %d is by %s, which is not one of this L1's validatorAdmins", i+1, who)
		}
		if approvers.Contains(who) {
			return nil, fmt.Errorf("approval %d repeats admin %s", i+1, who)
		}
		approvers.Add(who)
	}
	return approvers, nil
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

	// Only now, when this node will sign and ask the others to: Verify
	// records the change as this node's outstanding one.
	if appErr := m.Verify(ctx, unsigned, justification); appErr != nil {
		return nil, nil, nil, errors.New(appErr.Message)
	}
	need := requiredWeight(vdrs.TotalWeight)
	signed, weight, err := m.collect(ctx, unsigned, justification, vdrs, need)
	if err != nil {
		return nil, nil, nil, err
	}
	total := new(big.Int).SetUint64(vdrs.TotalWeight)
	// The P-Chain's own check, at the same quorum, before anyone gets it: a
	// message it would reject (too little weight, a bad signature) never
	// leaves this node.
	if err := signed.Signature.Verify(unsigned, snowCtx.NetworkID, vdrs, 67, 100); err != nil {
		return nil, nil, nil, fmt.Errorf("only weight %s of %d signed (the P-Chain needs %d): %w", weight, vdrs.TotalWeight, need, err)
	}
	return signed, weight, total, nil
}

type signatureReply struct {
	index int
	sig   *bls.Signature
}

// collect gathers the L1 validators' signatures on an approved message until
// they reach need, every validator has answered, or ctx ends. (metalgo's
// acp118.SignatureAggregator sends replies on an unbuffered channel it
// stops reading once it has enough, so each late reply blocks one of the
// chain's app-message workers for good. Here late replies are dropped.)
func (m *validatorManager) collect(ctx context.Context, unsigned *warp.UnsignedMessage, justification []byte, vdrs warp.CanonicalValidatorSet, need uint64) (*warp.Message, *big.Int, error) {
	snowCtx := m.vm.ctx
	bits := set.NewBits()
	var sigs []*bls.Signature
	weight := new(big.Int)
	add := func(i int, sig *bls.Signature) {
		if bits.Contains(i) {
			return // validators can share a key: count it once
		}
		bits.Add(i)
		sigs = append(sigs, sig)
		weight.Add(weight, new(big.Int).SetUint64(vdrs.Validators[i].Weight))
	}

	// This node's own signature, if it is a validator and its key is the one
	// the P-Chain has for it (a rotated staking key would not be).
	nodeIndex := map[ids.NodeID]int{}
	for i, v := range vdrs.Validators {
		for _, n := range v.NodeIDs {
			nodeIndex[n] = i
		}
	}
	if i, ok := nodeIndex[snowCtx.NodeID]; ok {
		raw, err := snowCtx.WarpSigner.Sign(unsigned)
		if err != nil {
			return nil, nil, fmt.Errorf("signing: %w", err)
		}
		if sig, err := bls.SignatureFromBytes(raw); err == nil && bls.Verify(vdrs.Validators[i].PublicKey, sig, unsigned.Bytes()) {
			add(i, sig)
		} else {
			snowCtx.Log.Warn("this node's signature doesn't match its registered BLS key; not counting it")
		}
	}

	others := set.Set[ids.NodeID]{}
	for n := range nodeIndex {
		if n != snowCtx.NodeID {
			others.Add(n)
		}
	}
	replies := make(chan signatureReply, others.Len()) // never blocks a sender
	if others.Len() > 0 && weight.Cmp(new(big.Int).SetUint64(need)) < 0 {
		request, err := proto.Marshal(&sdk.SignatureRequest{Message: unsigned.Bytes(), Justification: justification})
		if err != nil {
			return nil, nil, err
		}
		onReply := func(_ context.Context, nodeID ids.NodeID, response []byte, err error) {
			i, ok := nodeIndex[nodeID]
			if !ok || err != nil {
				select {
				case replies <- signatureReply{index: -1}:
				default:
				}
				return
			}
			var r sdk.SignatureResponse
			var sig *bls.Signature
			if proto.Unmarshal(response, &r) == nil {
				if s, err := bls.SignatureFromBytes(r.Signature); err == nil && bls.Verify(vdrs.Validators[i].PublicKey, s, unsigned.Bytes()) {
					sig = s
				}
			}
			reply := signatureReply{index: -1}
			if sig != nil {
				reply = signatureReply{index: i, sig: sig}
			}
			select {
			case replies <- reply:
			default: // nobody is waiting any more
			}
		}
		if err := m.client.AppRequest(ctx, others, request, onReply); err != nil {
			return nil, nil, fmt.Errorf("asking the other validators: %w", err)
		}
		for answered := 0; answered < others.Len() && weight.Cmp(new(big.Int).SetUint64(need)) < 0; answered++ {
			select {
			case <-ctx.Done():
				answered = others.Len()
			case r := <-replies:
				if r.sig != nil {
					add(r.index, r.sig)
				}
			}
		}
	}
	if len(sigs) == 0 {
		return nil, nil, errors.New("no validator signed")
	}
	agg, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, nil, err
	}
	sig := &warp.BitSetSignature{Signers: bits.Bytes()}
	copy(sig.Signature[:], bls.SignatureToBytes(agg))
	msg, err := warp.NewMessage(unsigned, sig)
	return msg, weight, err
}

// requiredWeight is the least signing weight the P-Chain accepts out of
// total: signed*100 >= total*67, rounded up.
func requiredWeight(total uint64) uint64 {
	n := new(big.Int).Mul(new(big.Int).SetUint64(total), big.NewInt(67))
	n.Add(n, big.NewInt(99))
	n.Div(n, big.NewInt(100))
	return n.Uint64()
}

// quorum is quorumOf for a uint64 total.
func quorum(signed *big.Int, total uint64) bool {
	return quorumOf(signed, new(big.Int).SetUint64(total))
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
func newValidatorManager(vm *VM, network *p2p.Network, policy adminPolicy, db database.Database) (*validatorManager, error) {
	m := &validatorManager{vm: vm, policy: policy, db: db}
	handler := newLimitedHandler(acp118.NewHandler(m, vm.ctx.WarpSigner), m.clock)
	if err := network.AddHandler(acp118.HandlerID, handler); err != nil {
		return nil, fmt.Errorf("registering the signature handler: %w", err)
	}
	m.client = network.NewClient(acp118.HandlerID, vm.p2pValidators)
	return m, nil
}

// --- HTTP: /ext/bc/<chain>/validators ------------------------------------------

type aggregateRequest struct {
	Message       string `json:"message"`       // hex unsigned Warp message
	Justification string `json:"justification"` // hex admin approvals, one after another
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
	if cfg.RPCPass == "public" || len(cfg.RPCPass) < 16 {
		fail(http.StatusForbidden, "this chain's rpcPass is too weak to guard signature collection (at least 16 characters, not \"public\")")
		return
	}
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
