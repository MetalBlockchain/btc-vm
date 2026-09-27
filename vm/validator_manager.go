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
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	btcd "github.com/MetalBlockchain/btcvm/btcd"
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
// checkChange): a weight change must be for one of them, at the nonce the
// P-Chain expects next; a registration expires within a day and can't reuse
// a registered BLS key; the validators able to sign now must still make the
// P-Chain's 67% of the whole registered weight afterwards (a newcomer can't
// sign until it's funded and online, so an L1 grows by adding a validator
// at a small weight and raising it once it's active); and a change after
// which any one BLS key could block that quorum alone (without the active
// weight it signs for, the rest able to sign wouldn't make 67% of the
// whole) needs every admin.
//
// Changes don't add up behind the policy's back: a node signs one change at
// a time (changeLock). Until the change it holds is on the P-Chain or can no
// longer be (a registration past its expiry, a weight change whose nonce
// the P-Chain has moved past), it signs only that same change again, or a
// weight change replacing it at the same nonce (only one of the two can
// ever apply). Any 67% of the weight asked to sign a second change includes
// validators still holding the first, so the second never gathers enough.
// Holding is judged only on a P-Chain view at least as new as the held
// change's. If validators end up holding different changes (so neither can
// reach 67%), every admin together can approve a change flagged to replace
// whatever they hold (FlagReplaceHeld): every admin can already make any
// change, so this adds no power, only a way out.
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
const ApprovalVersion byte = 3

// Approval flags: part of what every admin signs.
const (
	// FlagReplaceHeld: the change replaces a held change (see the package
	// comment), but only one the approval names: it carries the SHA-256 of
	// each held message it may replace, so it can't be kept and used on a
	// later one. Only with every admin's approval.
	FlagReplaceHeld byte = 1 << 0

	knownFlags = FlagReplaceHeld
)

// MaxReplaced bounds the held changes one replacement names.
const MaxReplaced = 16

// MaxReplaceLife bounds how far ahead a replacement's deadline can be: it
// names the changes held now, and mustn't be kept for later.
const MaxReplaceLife = time.Hour

// MaxApprovalLife bounds how far ahead an approval's deadline can be: long
// enough for admins to sign in turn, short enough that a forgotten
// approval dies.
const MaxApprovalLife = 7 * 24 * time.Hour

// MaxRegistrationLife is the P-Chain's limit on how far ahead a
// registration's expiry can be.
const MaxRegistrationLife = 24 * time.Hour

// Approval says what every admin approves: the unsigned Warp message, with
// flags, until a deadline, and for a replacement the held messages (their
// SHA-256) it may replace.
type Approval struct {
	Flags    byte
	Deadline uint64 // Unix seconds
	Replaces [][32]byte
}

// HeldHash identifies a held change: the SHA-256 of its unsigned message.
func HeldHash(unsignedMessage []byte) [32]byte { return sha256.Sum256(unsignedMessage) }

// header is the approval's fixed part, as signed and as carried:
//
//	ApprovalVersion || flags || deadline (8 bytes, big-endian) || count || count SHA-256 hashes
//
// (count and hashes only with FlagReplaceHeld).
func (a Approval) header() []byte {
	out := []byte{ApprovalVersion, a.Flags}
	out = binary.BigEndian.AppendUint64(out, a.Deadline)
	if a.Flags&FlagReplaceHeld != 0 {
		out = append(out, byte(len(a.Replaces)))
		for _, h := range a.Replaces {
			out = append(out, h[:]...)
		}
	}
	return out
}

// ApprovalHash is what every admin signs to approve an unsigned Warp message:
//
//	sha256(ApprovalDomain || header || unsigned message)
func ApprovalHash(unsignedMessage []byte, a Approval) []byte {
	h := sha256.New()
	h.Write([]byte(ApprovalDomain))
	h.Write(a.header())
	h.Write(unsignedMessage)
	return h.Sum(nil)
}

// EncodeJustification is the ACP-118 justification: the header, then each
// admin's 65-byte approval of the same message and header.
func EncodeJustification(a Approval, approvals [][]byte) []byte {
	out := a.header()
	for _, sig := range approvals {
		out = append(out, sig...)
	}
	return out
}

func decodeJustification(b []byte) (Approval, [][]byte, error) {
	var a Approval
	if len(b) < 10 {
		return a, nil, errors.New("the change carries no admin approvals")
	}
	if b[0] != ApprovalVersion {
		return a, nil, fmt.Errorf("approval format %d; this node reads format %d", b[0], ApprovalVersion)
	}
	a.Flags = b[1]
	if a.Flags&^knownFlags != 0 {
		return a, nil, fmt.Errorf("approval flags %#x include ones this node doesn't know", a.Flags)
	}
	a.Deadline = binary.BigEndian.Uint64(b[2:10])
	rest := b[10:]
	if a.Flags&FlagReplaceHeld != 0 {
		if len(rest) < 1 {
			return a, nil, errors.New("a replacement must name the held changes it replaces")
		}
		n := int(rest[0])
		if n == 0 || n > MaxReplaced || len(rest) < 1+32*n {
			return a, nil, fmt.Errorf("a replacement names 1 to %d held changes", MaxReplaced)
		}
		for i := range n {
			var h [32]byte
			copy(h[:], rest[1+32*i:1+32*(i+1)])
			a.Replaces = append(a.Replaces, h)
		}
		rest = rest[1+32*n:]
	}
	if len(rest) == 0 || len(rest)%secp256k1.SignatureLen != 0 {
		return a, nil, errors.New("the change carries no whole admin approvals (each is a 65-byte signature)")
	}
	var sigs [][]byte
	for len(rest) > 0 {
		sigs = append(sigs, rest[:secp256k1.SignatureLen])
		rest = rest[secp256k1.SignatureLen:]
	}
	return a, sigs, nil
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

// CheckChainConfig reports whether the VM would accept a chain config's
// validator settings (for installers, via the plugin's -check-config).
func CheckChainConfig(configBytes []byte) error {
	if _, err := parseValidatorAdmins(configBytes); err != nil {
		return err
	}
	// The overrides the VM refuses at start (consensus settings, index drops),
	// applied to an empty config: only the refusals matter here.
	return applyChainConfig(&btcd.Config{}, configBytes)
}

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
	lock   changeLock
	now    func() time.Time
	// ready once the chain has bootstrapped: before, its view of the L1 and
	// the P-Chain can be behind, so it signs nothing.
	ready atomic.Bool
	// broken after a failed write of the held change: signs nothing more.
	broken atomic.Bool

	heldMu sync.Mutex
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
	maxPeers    = 10_000 // peers with budgets; beyond it, new non-validators are turned away
)

// limitedHandler rate-limits peers' signature requests: each peer has a
// budget; peers that aren't the L1's validators also share a global one,
// so they can't crowd out the validators, who collect signatures from
// each other. When too many peers are known, unknown non-validators are
// turned away, never the budgets reset.
type limitedHandler struct {
	p2p.Handler
	now         func() time.Time
	isValidator func(context.Context, ids.NodeID) bool
	mu          sync.Mutex
	global      *rateLimiter
	peers       map[ids.NodeID]*rateLimiter
}

func newLimitedHandler(h p2p.Handler, now func() time.Time, isValidator func(context.Context, ids.NodeID) bool) *limitedHandler {
	return &limitedHandler{Handler: h, now: now, isValidator: isValidator,
		global: newRateLimiter(globalRate, globalBurst), peers: map[ids.NodeID]*rateLimiter{}}
}

var errBusy = appError(errCodeBusy, "too many signature requests; try again shortly")

func (h *limitedHandler) AppRequest(ctx context.Context, nodeID ids.NodeID, deadline time.Time, request []byte) ([]byte, *common.AppError) {
	now := h.now()
	validator := h.isValidator != nil && h.isValidator(ctx, nodeID)
	h.mu.Lock()
	peer := h.peers[nodeID]
	if peer == nil {
		if len(h.peers) >= maxPeers && !validator {
			h.mu.Unlock()
			return nil, errBusy
		}
		peer = newRateLimiter(peerRate, peerBurst)
		h.peers[nodeID] = peer
	}
	h.mu.Unlock()
	if !peer.allow(now) || (!validator && !h.global.allow(now)) {
		return nil, errBusy
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
	now := m.clock()
	if !m.ready.Load() {
		return appError(errCodeBusy, "this node is still bootstrapping; it signs nothing yet")
	}
	if m.broken.Load() {
		return appError(errCodeBusy, "this node couldn't record a change it was asked to sign; it signs nothing more until it restarts")
	}
	if msg.NetworkID != snowCtx.NetworkID || msg.SourceChainID != snowCtx.ChainID {
		return appError(errCodeNotManaged, "message is for network %d chain %s, not this chain", msg.NetworkID, msg.SourceChainID)
	}
	parsed, appErr := parseChange(msg.Bytes())
	if appErr != nil {
		return appErr
	}
	switch p := parsed.(type) {
	case *message.RegisterL1Validator:
		if p.SubnetID != snowCtx.SubnetID {
			return appError(errCodeNotManaged, "registration is for subnet %s, not this L1's %s", p.SubnetID, snowCtx.SubnetID)
		}
		if p.Weight == 0 {
			return appError(errCodeNotManaged, "a registration needs a weight above 0")
		}
		// The P-Chain takes a registration only before its expiry, and at
		// most a day ahead: anything else could never be registered, or
		// could be for longer than the lock below expects.
		nowUnix := uint64(now.Unix())
		if p.Expiry <= nowUnix || p.Expiry > nowUnix+uint64(MaxRegistrationLife/time.Second) {
			return appError(errCodeNotManaged, "a registration must expire within the next %s", MaxRegistrationLife)
		}
		if _, err := bls.PublicKeyFromCompressedBytes(p.BLSPublicKey[:]); err != nil {
			return appError(errCodeNotManaged, "the registration's BLS key doesn't parse: %s", err)
		}
	case *message.L1ValidatorWeight:
		// Its validation and nonce are checked against the P-Chain below.
	}
	if m.policy.admins.Len() == 0 {
		return appError(errCodeNotApproved, "this node has no validatorAdmins in its chain config, so it approves no validator changes")
	}
	approvers, approval, err := m.policy.approvers(msg.Bytes(), justification, now)
	if err != nil {
		return appError(errCodeNotApproved, "%s", err)
	}
	if approvers.Len() < m.policy.threshold {
		return appError(errCodeNotApproved, "approved by %d of this L1's admins; it needs %d", approvers.Len(), m.policy.threshold)
	}
	all := approvers.Len() >= m.policy.admins.Len()
	replaceHeld := approval.Flags&FlagReplaceHeld != 0
	if replaceHeld && !all {
		return appError(errCodeNotApproved, "only every admin together may replace a change the validators hold; %d of %d approved", approvers.Len(), m.policy.admins.Len())
	}

	// From reading the P-Chain to recording the change, one change at a time.
	m.heldMu.Lock()
	defer m.heldMu.Unlock()
	current, height, err := snowCtx.ValidatorState.GetCurrentValidatorSet(ctx, snowCtx.SubnetID)
	if err != nil {
		return appError(errCodeNotManaged, "reading the L1's validators: %s", err)
	}
	if w, ok := parsed.(*message.L1ValidatorWeight); ok {
		v, ok := current[w.ValidationID]
		if !ok {
			return appError(errCodeNotManaged, "validation %s is not one of this L1's validators", w.ValidationID)
		}
		if w.Nonce == math.MaxUint64 {
			return appError(errCodeNotManaged, "a weight change at nonce %d could never be followed by another", w.Nonce)
		}
		if w.Nonce != v.MinNonce {
			return appError(errCodeNotManaged, "the weight change has nonce %d; the P-Chain expects %d for this validation", w.Nonce, v.MinNonce)
		}
	}
	held, err := m.lock.read()
	if err != nil {
		return appError(errCodeBusy, "%s", err)
	}
	same := held != nil && bytes.Equal(held.Message, msg.Bytes())
	var dropped [][]byte
	if held != nil {
		dropped = stillDropped(held.Dropped, current, now)
		for _, d := range dropped {
			if bytes.Equal(d, msg.Bytes()) {
				return appError(errCodeNotApproved, "every admin replaced this change; it isn't signed again")
			}
		}
	}
	if held != nil && !same && replaceHeld && !names(approval.Replaces, HeldHash(held.Message)) {
		return appError(errCodeNotApproved, "the replacement doesn't name the change this node holds (%x); approve one that does", HeldHash(held.Message))
	}
	if held != nil && !same && !replaceHeld {
		if height < held.Height {
			return appError(errCodeBusy, "this node's view of the P-Chain (height %d) is older than the change it holds (%d); try again shortly", height, held.Height)
		}
		if appErr := checkHeld(held, parsed, current, now); appErr != nil {
			return appErr
		}
	}
	if appErr := m.policy.checkChange(parsed, current, approvers.Len()); appErr != nil {
		return appErr
	}
	// Written (again, if it's the one held) and synced before each
	// signature: a retry after a failed sync must not sign on a record the
	// disk may not have. A failed write stops all signing until restart.
	record := heldChange{Message: msg.Bytes(), Height: height, Dropped: dropped}
	switch {
	case same:
		record = *held
		record.Dropped = dropped
	case held != nil && replaceHeld:
		// Replaced: remembered, so it's never signed again while it could
		// still land.
		record.Dropped = stillDropped(append(dropped, held.Message), current, now)
	}
	if err := m.lock.write(record); err != nil {
		m.broken.Store(true)
		return appError(errCodeBusy, "recording the change before signing it failed (%s); this node signs nothing more until it restarts", err)
	}
	return nil
}

func names(list [][32]byte, h [32]byte) bool {
	for _, x := range list {
		if x == h {
			return true
		}
	}
	return false
}

// Past a registration's expiry, the P-Chain (whose clock can trail this
// node's) can't take it: wait this much longer to be sure.
const expirySlack = time.Hour

// checkHeld refuses a new change while the one held may still reach the
// P-Chain. It's released only on evidence from a view at least as new as
// the held change's: the registration on the P-Chain or past its expiry,
// the weight change's nonce passed, or its validation gone (it was there
// when the change was held).
func checkHeld(held *heldChange, change message.Payload, current map[ids.ID]*validators.GetCurrentValidatorOutput, now time.Time) *common.AppError {
	prev, appErr := parseChange(held.Message)
	if appErr != nil {
		return appError(errCodeNotApproved, "the change this node holds can't be read (%s); only every admin together can replace it", appErr.Message)
	}
	if settled(prev, current, now) {
		return nil
	}
	var what string
	switch p := prev.(type) {
	case *message.RegisterL1Validator:
		what = fmt.Sprintf("registration %s, until it's registered or expires at %s", p.ValidationID(), time.Unix(int64(min(p.Expiry, math.MaxInt64)), 0).UTC().Format(time.RFC3339))
	case *message.L1ValidatorWeight:
		if w, same := change.(*message.L1ValidatorWeight); same && w.ValidationID == p.ValidationID && w.Nonce == p.Nonce {
			return nil // replaces it: the P-Chain takes only one change per nonce
		}
		what = fmt.Sprintf("weight %d for validation %s at nonce %d, until the P-Chain has it", p.Weight, p.ValidationID, p.Nonce)
	}
	return appError(errCodeNotApproved, "this node signed another validator change that isn't on the P-Chain yet (%s): submit that one first, or replace a weight change at the same nonce", what)
}

// settled: the change is on the P-Chain, or can no longer be: a
// registration registered or past its expiry, a weight change whose nonce
// the P-Chain passed or whose validation is gone.
func settled(change message.Payload, current map[ids.ID]*validators.GetCurrentValidatorOutput, now time.Time) bool {
	switch p := change.(type) {
	case *message.RegisterL1Validator:
		_, registered := current[p.ValidationID()]
		return registered || uint64(now.Unix()) > p.Expiry+uint64(expirySlack/time.Second)
	case *message.L1ValidatorWeight:
		v, ok := current[p.ValidationID]
		return !ok || v.MinNonce > p.Nonce
	}
	return false
}

// maxDropped bounds the replaced changes a node remembers.
const maxDropped = 32

// stillDropped is the replaced changes not yet settled: signed once, then
// replaced by every admin, they're never signed again while they could
// still reach the P-Chain.
func stillDropped(dropped [][]byte, current map[ids.ID]*validators.GetCurrentValidatorOutput, now time.Time) [][]byte {
	var keep [][]byte
	for _, d := range dropped {
		c, appErr := parseChange(d)
		if appErr == nil && settled(c, current, now) {
			continue
		}
		keep = append(keep, d)
	}
	if len(keep) > maxDropped {
		keep = keep[len(keep)-maxDropped:]
	}
	return keep
}

// parseChange is the validator change in an unsigned Warp message from this
// chain's manager (an empty source address), checked as the P-Chain will.
func parseChange(unsignedBytes []byte) (message.Payload, *common.AppError) {
	unsigned, err := warp.ParseUnsignedMessage(unsignedBytes)
	if err != nil {
		return nil, appError(errCodeNotManaged, "not a Warp message: %s", err)
	}
	call, err := payload.ParseAddressedCall(unsigned.Payload)
	if err != nil {
		return nil, appError(errCodeNotManaged, "not an addressed call: %s", err)
	}
	// The L1 was converted with an empty manager address; any other source
	// address would not be accepted by the P-Chain as the manager.
	if len(call.SourceAddress) != 0 {
		return nil, appError(errCodeNotManaged, "source address must be empty (the L1's manager address)")
	}
	parsed, err := message.Parse(call.Payload)
	if err != nil {
		return nil, appError(errCodeNotManaged, "not a validator message: %s", err)
	}
	switch p := parsed.(type) {
	case *message.RegisterL1Validator:
		if err := p.Verify(); err != nil {
			return nil, appError(errCodeNotManaged, "invalid registration: %s", err)
		}
	case *message.L1ValidatorWeight:
		if err := p.Verify(); err != nil {
			return nil, appError(errCodeNotManaged, "invalid weight change: %s", err)
		}
	default:
		return nil, appError(errCodeNotManaged, "this chain signs validator registrations and weight changes only, not %T", parsed)
	}
	return parsed, nil
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
	newcomer, newWeight := false, uint64(0)
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
		newcomer, newWeight = true, c.Weight
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
		// What each key signs for: only an active validation's weight.
		if !s.active {
			continue
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
	if total.Cmp(new(big.Int).SetUint64(math.MaxUint64)) > 0 {
		return appError(errCodeNotManaged, "the L1's total weight would pass the P-Chain's limit")
	}
	// Afterwards the validators that can sign now must still make 67% of the
	// whole weight, or no later change could be signed. A newcomer can't
	// sign until it's funded and online: add it at a weight the others
	// outweigh, and raise it once it's active.
	if !quorumOf(signable, total) {
		msg := fmt.Sprintf("after this change the validators able to sign hold %s of the L1's weight; the P-Chain needs 67%%, so no later change could be signed",
			percent(signable, total))
		if newcomer {
			rest := new(big.Int).Sub(total, new(big.Int).SetUint64(newWeight))
			msg += fmt.Sprintf(". Register it at a weight of at most %s, and raise it once it's active", MaxNewcomerWeight(signable, rest))
		}
		return appError(errCodeNotApproved, "%s", msg)
	}
	// One key that could block the quorum alone: without the weight it signs
	// for (offline, out of balance, disabled), the rest able to sign wouldn't
	// make 67% of the whole.
	for _, w := range byKey {
		if !quorumOf(new(big.Int).Sub(signable, w), total) && !all {
			return appError(errCodeNotApproved,
				"after this change one validator signs for %s of the L1's weight, and without it the rest able to sign (%s) wouldn't make the P-Chain's 67%%; that needs all %d admins, and %d approved",
				percent(w, total), percent(new(big.Int).Sub(signable, w), total), p.admins.Len(), approvals)
		}
	}
	return nil
}

// MaxNewcomerWeight is the largest weight a new validator can be registered
// at while the validators able to sign still make 67% of the whole, given
// what can sign and the registered total without it:
// signable*100 >= (total+w)*67. Zero if they already don't.
func MaxNewcomerWeight(signable, total *big.Int) *big.Int {
	w := new(big.Int).Mul(signable, big.NewInt(100))
	w.Sub(w, new(big.Int).Mul(total, big.NewInt(67)))
	if w.Sign() <= 0 {
		return new(big.Int)
	}
	return w.Div(w, big.NewInt(67))
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
func (p adminPolicy) approvers(unsignedMessage, justification []byte, now time.Time) (set.Set[ids.ShortID], Approval, error) {
	approval, sigs, err := decodeJustification(justification)
	if err != nil {
		return nil, approval, err
	}
	deadline := approval.Deadline
	switch at := time.Unix(int64(deadline), 0); {
	case deadline > uint64(now.Add(MaxApprovalLife).Unix()):
		return nil, approval, fmt.Errorf("the approvals' deadline %s is more than %s away", at.UTC().Format(time.RFC3339), MaxApprovalLife)
	case uint64(now.Unix()) > deadline:
		return nil, approval, fmt.Errorf("the approvals expired at %s", at.UTC().Format(time.RFC3339))
	case approval.Flags&FlagReplaceHeld != 0 && deadline > uint64(now.Add(MaxReplaceLife).Unix()):
		return nil, approval, fmt.Errorf("a replacement's deadline can be at most %s away", MaxReplaceLife)
	}
	if len(sigs) > p.admins.Len() {
		return nil, approval, fmt.Errorf("%d approvals, but this L1 has only %d admins", len(sigs), p.admins.Len())
	}
	hash := ApprovalHash(unsignedMessage, approval)
	approvers := set.NewSet[ids.ShortID](len(sigs))
	for i, sig := range sigs {
		pub, err := secp256k1.RecoverPublicKeyFromHash(hash, sig)
		if err != nil {
			return nil, approval, fmt.Errorf("approval %d: %w", i+1, err)
		}
		who := pub.Address()
		if !p.admins.Contains(who) {
			return nil, approval, fmt.Errorf("approval %d is by %s, which is not one of this L1's validatorAdmins", i+1, who)
		}
		if approvers.Contains(who) {
			return nil, approval, fmt.Errorf("approval %d repeats admin %s", i+1, who)
		}
		approvers.Add(who)
	}
	return approvers, approval, nil
}

// Aggregate signs an approved change with this node's key, collects the
// other validators' signatures, and returns the signed Warp message with
// the weight that signed it.
func (m *validatorManager) Aggregate(parent context.Context, unsignedBytes, justification []byte, required ids.NodeID) (*warp.Message, *big.Int, *big.Int, []ids.NodeID, error) {
	ctx, cancel := context.WithTimeout(parent, aggregateTimeout)
	defer cancel()

	unsigned, err := warp.ParseUnsignedMessage(unsignedBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("not a Warp message: %w", err)
	}
	snowCtx := m.vm.ctx
	// A raise must show the validator being raised signs, whatever the
	// client asked for: otherwise more of the weight could come to depend on
	// a validator that isn't online and signing.
	if change, appErr := parseChange(unsignedBytes); appErr == nil {
		if w, ok := change.(*message.L1ValidatorWeight); ok {
			current, _, err := snowCtx.ValidatorState.GetCurrentValidatorSet(ctx, snowCtx.SubnetID)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("reading the L1's validators: %w", err)
			}
			if v, ok := current[w.ValidationID]; ok && w.Weight > v.Weight {
				required = v.NodeID
			}
		}
	}
	// The P-Chain checks the signatures against the L1's validators at the
	// P-Chain height its block proposer picks, which lags the tip (the
	// minimum height, as proposervm uses). Signing for the same height means
	// a validator added or removed moments ago counts only once the P-Chain
	// itself would count it; until then, a change needs a retry.
	height, err := snowCtx.ValidatorState.GetMinimumHeight(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading the P-Chain height: %w", err)
	}
	vdrs, err := warp.GetCanonicalValidatorSetFromSubnetID(ctx, snowCtx.ValidatorState, height, snowCtx.SubnetID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading the L1's validators: %w", err)
	}
	tip, err := snowCtx.ValidatorState.GetCurrentHeight(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading the P-Chain height: %w", err)
	}
	if tip != height {
		now, err := warp.GetCanonicalValidatorSetFromSubnetID(ctx, snowCtx.ValidatorState, tip, snowCtx.SubnetID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("reading the L1's validators: %w", err)
		}
		if !sameValidators(vdrs, now) {
			return nil, nil, nil, nil, errValidatorSetSettling
		}
	}

	// Only now, when this node will sign and ask the others to: Verify
	// records the change as this node's outstanding one.
	if appErr := m.Verify(ctx, unsigned, justification); appErr != nil {
		return nil, nil, nil, nil, errors.New(appErr.Message)
	}
	need := requiredWeight(vdrs.TotalWeight)
	signed, weight, signers, err := m.collect(ctx, unsigned, justification, vdrs, need, required)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	total := new(big.Int).SetUint64(vdrs.TotalWeight)
	// The P-Chain's own check, at the same quorum, before anyone gets it: a
	// message it would reject (too little weight, a bad signature) never
	// leaves this node.
	if err := signed.Signature.Verify(unsigned, snowCtx.NetworkID, vdrs, 67, 100); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("only weight %s of %d signed (the P-Chain needs %d): %w", weight, vdrs.TotalWeight, need, err)
	}
	return signed, weight, total, signers, nil
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
//
// With required set, it also waits for that validator's own signature: a
// raise must show the validator being raised signs, or the raise could
// leave the L1 short of 67% able to sign.
func (m *validatorManager) collect(ctx context.Context, unsigned *warp.UnsignedMessage, justification []byte, vdrs warp.CanonicalValidatorSet, need uint64, required ids.NodeID) (*warp.Message, *big.Int, []ids.NodeID, error) {
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
			return nil, nil, nil, fmt.Errorf("signing: %w", err)
		}
		if sig, err := bls.SignatureFromBytes(raw); err == nil && bls.Verify(vdrs.Validators[i].PublicKey, sig, unsigned.Bytes()) {
			add(i, sig)
		} else {
			snowCtx.Log.Warn("this node's signature doesn't match its registered BLS key; not counting it")
		}
	}

	requiredIndex := -1
	if required != ids.EmptyNodeID {
		i, ok := nodeIndex[required]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%s isn't among the validators the signatures are checked against yet; try again shortly", required)
		}
		requiredIndex = i
	}
	enough := func() bool {
		return weight.Cmp(new(big.Int).SetUint64(need)) >= 0 && (requiredIndex < 0 || bits.Contains(requiredIndex))
	}

	others := set.Set[ids.NodeID]{}
	for n := range nodeIndex {
		if n != snowCtx.NodeID {
			others.Add(n)
		}
	}
	replies := make(chan signatureReply, others.Len()) // never blocks a sender
	if others.Len() > 0 && !enough() {
		request, err := proto.Marshal(&sdk.SignatureRequest{Message: unsigned.Bytes(), Justification: justification})
		if err != nil {
			return nil, nil, nil, err
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
			return nil, nil, nil, fmt.Errorf("asking the other validators: %w", err)
		}
		for answered := 0; answered < others.Len() && !enough(); answered++ {
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
	if requiredIndex >= 0 && !bits.Contains(requiredIndex) {
		return nil, nil, nil, fmt.Errorf("%s didn't sign (it isn't online, funded and caught up yet): not raising it", required)
	}
	if len(sigs) == 0 {
		return nil, nil, nil, errors.New("no validator signed")
	}
	agg, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, nil, nil, err
	}
	sig := &warp.BitSetSignature{Signers: bits.Bytes()}
	copy(sig.Signature[:], bls.SignatureToBytes(agg))
	msg, err := warp.NewMessage(unsigned, sig)
	var signers []ids.NodeID
	for i := range vdrs.Validators {
		if bits.Contains(i) {
			signers = append(signers, vdrs.Validators[i].NodeIDs...)
		}
	}
	return msg, weight, signers, err
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
func newValidatorManager(vm *VM, network *p2p.Network, policy adminPolicy, lockPath string) (*validatorManager, error) {
	m := &validatorManager{vm: vm, policy: policy, lock: changeLock{path: lockPath}}
	isValidator := func(ctx context.Context, nodeID ids.NodeID) bool {
		return vm.p2pValidators != nil && vm.p2pValidators.Has(ctx, nodeID)
	}
	handler := newLimitedHandler(acp118.NewHandler(m, vm.ctx.WarpSigner), m.clock, isValidator)
	if err := network.AddHandler(acp118.HandlerID, handler); err != nil {
		return nil, fmt.Errorf("registering the signature handler: %w", err)
	}
	m.client = network.NewClient(acp118.HandlerID, vm.p2pValidators)
	return m, nil
}

// --- HTTP: /ext/bc/<chain>/validators ------------------------------------------

type aggregateRequest struct {
	Message       string `json:"message"`       // hex unsigned Warp message
	Justification string `json:"justification"` // hex EncodeJustification
	// A validator whose own signature must be among them (for a raise).
	RequireSigner string `json:"requireSigner,omitempty"`
}

type aggregateReply struct {
	SignedMessage string   `json:"signedMessage"`
	SignedWeight  string   `json:"signedWeight"`
	TotalWeight   string   `json:"totalWeight"`
	Signers       []string `json:"signers"` // NodeIDs whose signatures it holds
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
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		fail(http.StatusMethodNotAllowed, "POST a JSON {message, justification}, or GET the change this node holds")
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
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		// The change this node holds, for admins replacing held changes
		// (a replacement names each by its HeldHash).
		m.heldMu.Lock()
		held, err := m.lock.read()
		m.heldMu.Unlock()
		if err != nil {
			fail(http.StatusInternalServerError, "%s", err)
			return
		}
		reply := map[string]any{"held": nil}
		if held != nil {
			h := HeldHash(held.Message)
			reply = map[string]any{"held": "0x" + hex.EncodeToString(held.Message), "heldHash": "0x" + hex.EncodeToString(h[:]), "height": held.Height}
		}
		_ = json.NewEncoder(w).Encode(reply)
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
	required := ids.EmptyNodeID
	if req.RequireSigner != "" {
		if required, err = ids.NodeIDFromString(req.RequireSigner); err != nil {
			fail(http.StatusBadRequest, "requireSigner: %s", err)
			return
		}
	}
	msg, signed, total, signers, err := m.Aggregate(r.Context(), unsigned, justification, required)
	if err != nil {
		fail(http.StatusForbidden, "%s", err)
		return
	}
	reply := aggregateReply{
		SignedMessage: "0x" + hex.EncodeToString(msg.Bytes()),
		SignedWeight:  signed.String(),
		TotalWeight:   total.String(),
		Signers:       []string{},
	}
	for _, n := range signers {
		reply.Signers = append(reply.Signers, n.String())
	}
	_ = json.NewEncoder(w).Encode(reply)
}
