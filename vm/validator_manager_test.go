// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/MetalBlockchain/metalgo/database/memdb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/snow/validators"
	"github.com/MetalBlockchain/metalgo/snow/validators/validatorstest"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls/signer/localsigner"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/formatting/address"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/payload"
)

type managerFixture struct {
	m        *validatorManager
	admins   []*secp256k1.PrivateKey // three admins, any two approve
	outsider *secp256k1.PrivateKey
	netID    uint32
	chainID  ids.ID
	subnetID ids.ID
	now      time.Time
	current  map[ids.ID]*validators.GetCurrentValidatorOutput // the L1's validators
	deadline uint64
}

func newKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	k, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newManagerFixture: an L1 with `validators` active validators of weight 100.
func newManagerFixture(t *testing.T, withAdmins bool, validatorCount int) *managerFixture {
	t.Helper()
	f := &managerFixture{
		outsider: newKey(t), netID: constants.LocalID, chainID: ids.GenerateTestID(), subnetID: ids.GenerateTestID(),
		now: time.Unix(1_800_000_000, 0), current: map[ids.ID]*validators.GetCurrentValidatorOutput{},
	}
	f.deadline = uint64(f.now.Add(time.Hour).Unix())
	for range validatorCount {
		f.addValidator(t, 100, true)
	}
	policy := adminPolicy{admins: set.Set[ids.ShortID]{}}
	for range 3 {
		f.admins = append(f.admins, newKey(t))
	}
	if withAdmins {
		for _, a := range f.admins {
			policy.admins.Add(a.Address())
		}
		policy.threshold = 2
	}
	state := &validatorstest.State{
		T: t,
		GetCurrentValidatorSetF: func(_ context.Context, subnetID ids.ID) (map[ids.ID]*validators.GetCurrentValidatorOutput, uint64, error) {
			if subnetID != f.subnetID {
				t.Fatalf("read subnet %s's validators", subnetID)
			}
			return f.current, 10, nil
		},
	}
	vm := &VM{ctx: &snow.Context{NetworkID: f.netID, ChainID: f.chainID, SubnetID: f.subnetID, ValidatorState: state}}
	f.m = &validatorManager{vm: vm, policy: policy, db: memdb.New(), now: func() time.Time { return f.now }}
	return f
}

// addValidator adds a validation with its own BLS key to the fixture L1.
func (f *managerFixture) addValidator(t *testing.T, weight uint64, active bool) ids.ID {
	t.Helper()
	sk, err := localsigner.New()
	if err != nil {
		t.Fatal(err)
	}
	id := ids.GenerateTestID()
	f.current[id] = &validators.GetCurrentValidatorOutput{
		ValidationID: id, NodeID: ids.GenerateTestNodeID(), PublicKey: sk.PublicKey(),
		Weight: weight, IsActive: active, IsL1Validator: true,
	}
	return id
}

// fresh forgets the change the manager signed last.
func (f *managerFixture) fresh() { f.m.db = memdb.New() }

// anyValidation is one of the fixture L1's validation IDs.
func (f *managerFixture) anyValidation() ids.ID {
	for id := range f.current {
		return id
	}
	return ids.Empty
}

// unsigned wraps a validator message as this chain's manager would send it.
func (f *managerFixture) unsigned(t *testing.T, chainID ids.ID, sourceAddress []byte, p message.Payload) *warp.UnsignedMessage {
	t.Helper()
	call, err := payload.NewAddressedCall(sourceAddress, p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := warp.NewUnsignedMessage(f.netID, chainID, call.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func (f *managerFixture) registration(t *testing.T, subnetID ids.ID, weight uint64) *message.RegisterL1Validator {
	t.Helper()
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	r, err := message.NewRegisterL1Validator(subnetID, ids.GenerateTestNodeID(), [bls.PublicKeyLen]byte{1}, 1_900_000_000, owner, owner, weight)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *managerFixture) weight(t *testing.T, validationID ids.ID, weight uint64) *message.L1ValidatorWeight {
	t.Helper()
	w, err := message.NewL1ValidatorWeight(validationID, 3, weight)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func sign(t *testing.T, msg *warp.UnsignedMessage, deadline uint64, keys ...*secp256k1.PrivateKey) [][]byte {
	t.Helper()
	var out [][]byte
	for _, key := range keys {
		sig, err := key.SignHash(ApprovalHash(msg.Bytes(), deadline))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig)
	}
	return out
}

// approve is the justification carrying each key's approval of msg, in
// order, with the fixture's deadline.
func (f *managerFixture) approve(t *testing.T, msg *warp.UnsignedMessage, keys ...*secp256k1.PrivateKey) []byte {
	t.Helper()
	return EncodeJustification(f.deadline, sign(t, msg, f.deadline, keys...))
}

func (f *managerFixture) check(t *testing.T, msg *warp.UnsignedMessage, justification []byte, wantErr string) {
	t.Helper()
	appErr := f.m.Verify(context.Background(), msg, justification)
	switch {
	case wantErr == "" && appErr != nil:
		t.Fatalf("refused: %s", appErr.Message)
	case wantErr != "" && appErr == nil:
		t.Fatalf("signed; want refusal %q", wantErr)
	case wantErr != "" && !strings.Contains(appErr.Message, wantErr):
		t.Fatalf("refused with %q; want %q", appErr.Message, wantErr)
	}
}

func TestValidatorManagerVerify(t *testing.T) {
	f := newManagerFixture(t, true, 4)
	a, b, c := f.admins[0], f.admins[1], f.admins[2]
	reg := f.registration(t, f.subnetID, 100)
	good := f.unsigned(t, f.chainID, nil, reg)

	rawHash := sha256.Sum256(good.Bytes())
	undomained, err := a.SignHash(rawHash[:])
	if err != nil {
		t.Fatal(err)
	}
	conversion, err := message.NewSubnetToL1Conversion(ids.GenerateTestID())
	if err != nil {
		t.Fatal(err)
	}
	other := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	by := func(keys ...*secp256k1.PrivateKey) func(*warp.UnsignedMessage) []byte {
		return func(m *warp.UnsignedMessage) []byte { return f.approve(t, m, keys...) }
	}
	withDeadline := func(deadline uint64, keys ...*secp256k1.PrivateKey) func(*warp.UnsignedMessage) []byte {
		return func(m *warp.UnsignedMessage) []byte {
			return EncodeJustification(deadline, sign(t, m, deadline, keys...))
		}
	}
	now := uint64(f.now.Unix())

	for _, tc := range []struct {
		name          string
		msg           *warp.UnsignedMessage
		justification func(*warp.UnsignedMessage) []byte
		wantErr       string // "" = must sign
	}{
		{"registration approved by two admins", good, by(a, b), ""},
		{"approved by all three", good, by(c, a, b), ""},
		{"removing one of four needs all three", f.unsigned(t, f.chainID, nil, f.weight(t, f.anyValidation(), 0)), by(b, c), "needs all 3 admins"},
		{"no approval", good, func(*warp.UnsignedMessage) []byte { return nil }, "no admin approvals"},
		{"a header and no approvals", good, func(*warp.UnsignedMessage) []byte { return EncodeJustification(f.deadline, nil) }, "no whole admin approvals"},
		{"one admin alone", good, by(a), "approved by 1 of this L1's admins; it needs 2"},
		{"one admin twice", good, by(a, a), "repeats admin"},
		{"an admin and an outsider", good, by(a, f.outsider), "not one of this L1's validatorAdmins"},
		{"more approvals than admins", good, by(a, b, c, a), "only 3 admins"},
		{"a partial approval", good, func(m *warp.UnsignedMessage) []byte { return f.approve(t, m, a, b)[:100] }, "each is a 65-byte signature"},
		{"another format", good, func(m *warp.UnsignedMessage) []byte { j := f.approve(t, m, a, b); j[0] = 2; return j }, "approval format 2"},
		{"expired", good, withDeadline(now-1, a, b), "expired"},
		{"deadline too far ahead", good, withDeadline(uint64(f.now.Add(MaxApprovalLife+time.Minute).Unix()), a, b), "more than"},
		{"deadline changed after signing", good, func(m *warp.UnsignedMessage) []byte {
			return EncodeJustification(f.deadline+60, sign(t, m, f.deadline, a, b))
		}, "not one of this L1's validatorAdmins"},
		{"admin signed the bare hash, not the approval", good, func(m *warp.UnsignedMessage) []byte {
			return EncodeJustification(f.deadline, append(sign(t, m, f.deadline, b), undomained))
		}, "not one of this L1's validatorAdmins"},
		{"second approval is of a different message", good, func(m *warp.UnsignedMessage) []byte {
			return EncodeJustification(f.deadline, append(sign(t, m, f.deadline, a), sign(t, other, f.deadline, b)...))
		}, "not one of this L1's validatorAdmins"},
		{"another L1's subnet", f.unsigned(t, f.chainID, nil, f.registration(t, ids.GenerateTestID(), 100)), by(a, b), "registration is for subnet"},
		{"weight 0 registration", f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 0)), by(a, b), "weight above 0"},
		{"non-empty source address", f.unsigned(t, f.chainID, []byte{1, 2, 3}, reg), by(a, b), "source address must be empty"},
		{"from another chain", f.unsigned(t, ids.GenerateTestID(), nil, reg), by(a, b), "not this chain"},
		{"another kind of message", f.unsigned(t, f.chainID, nil, conversion), by(a, b), "registrations and weight changes only"},
		{"weight change for another L1's validator", f.unsigned(t, f.chainID, nil, f.weight(t, ids.GenerateTestID(), 50)), by(a, b, c), "not one of this L1's validators"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.fresh()
			f.check(t, tc.msg, tc.justification(tc.msg), tc.wantErr)
		})
	}
}

// A change that leaves one validator with a third or more of the weight
// needs every admin; the last validator can't be removed.
func TestValidatorManagerWeightShares(t *testing.T) {
	for _, tc := range []struct {
		name       string
		validators int
		change     func(f *managerFixture) message.Payload
		two, all   string // refusal with two admins, with all three ("" = signs)
	}{
		{"second validator (50%)", 1, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "needs all 3 admins", ""},
		{"fourth validator (25%)", 3, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "", ""},
		{"a heavy fifth (weight 400 of 800)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 400) }, "able to sign hold 50.0%", ""},
		// The P-Chain's quorum, exactly: 400 of 597 is 67.0%, of 598 isn't.
		{"a fifth at 197 of 597 (the rest still make 67%)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 197) }, "", ""},
		{"a fifth at 198 of 598 (the rest don't)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 198) }, "needs all 3 admins", ""},
		{"removing one of five (25% each after)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "", ""},
		{"removing one of four (33.3% each after)", 4, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "needs all 3 admins", ""},
		{"removing the last", 1, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "no active validator", "no active validator"},
		{"raising one of five to 300 (300 of 700)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 300) }, "needs all 3 admins", ""},
		{"a node that already validates", 4, func(f *managerFixture) message.Payload {
			r := f.registration(t, f.subnetID, 100)
			node := f.current[f.anyValidation()].NodeID
			owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
			r, err := message.NewRegisterL1Validator(f.subnetID, node, [bls.PublicKeyLen]byte{1}, r.Expiry, owner, owner, 100)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}, "already validates", "already validates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagerFixture(t, true, tc.validators)
			msg := f.unsigned(t, f.chainID, nil, tc.change(f))
			f.check(t, msg, f.approve(t, msg, f.admins[0], f.admins[1]), tc.two)
			f.fresh()
			f.check(t, msg, f.approve(t, msg, f.admins...), tc.all)
		})
	}
}

// Inactive validators (no balance) count in the total, as in Warp, but
// can't sign: a change must leave the active ones at 67% of it.
func TestValidatorManagerInactiveWeight(t *testing.T) {
	two := func(f *managerFixture) []*secp256k1.PrivateKey { return f.admins[:2] }
	for _, tc := range []struct {
		name    string
		setup   func(f *managerFixture) message.Payload
		wantErr string
		admins  func(f *managerFixture) []*secp256k1.PrivateKey
	}{
		{"a fifth into four active and one inactive (400 of 600 can sign)", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.registration(t, f.subnetID, 100)
		}, "able to sign hold 66.7%", two},
		{"...unless every admin counts on the newcomer", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.registration(t, f.subnetID, 100)
		}, "", func(f *managerFixture) []*secp256k1.PrivateKey { return f.admins }},
		{"raising an inactive validator's weight", func(f *managerFixture) message.Payload {
			return f.weight(t, f.addValidator(t, 100, false), 300)
		}, "able to sign hold", func(f *managerFixture) []*secp256k1.PrivateKey { return f.admins }},
		{"removing an inactive validator from a stuck set", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.weight(t, f.addValidator(t, 100, false), 0) // 400 of 600 -> 400 of 500
		}, "", two},
		{"removing an active one while inactive weight is high", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			var active ids.ID
			for id, v := range f.current {
				if v.IsActive {
					active = id
				}
			}
			return f.weight(t, active, 0) // 300 of 400 active... of 400 total with the inactive: 75%
		}, "", two},
		{"a heavy inactive validator counts (a top-up could reactivate it)", func(f *managerFixture) message.Payload {
			f.addValidator(t, 250, false)
			return f.registration(t, f.subnetID, 10)
		}, "able to sign hold", two},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newManagerFixture(t, true, 4)
			msg := f.unsigned(t, f.chainID, nil, tc.setup(f))
			f.check(t, msg, f.approve(t, msg, tc.admins(f)...), tc.wantErr)
		})
	}
}

// Warp sums weight per BLS key: a registration reusing one is refused.
func TestValidatorManagerRefusesReusedBLSKey(t *testing.T) {
	f := newManagerFixture(t, true, 5)
	existing := f.current[f.anyValidation()]
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	var key [bls.PublicKeyLen]byte
	copy(key[:], bls.PublicKeyToCompressedBytes(existing.PublicKey))
	reg, err := message.NewRegisterL1Validator(f.subnetID, ids.GenerateTestNodeID(), key, 1_900_000_000, owner, owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	msg := f.unsigned(t, f.chainID, nil, reg)
	f.check(t, msg, f.approve(t, msg, f.admins...), "BLS key is already registered")
}

// A node signs one change at a time, so separately approved changes can't
// be gathered and submitted together.
func TestValidatorManagerOneChangeAtATime(t *testing.T) {
	f := newManagerFixture(t, true, 6)
	regA := f.registration(t, f.subnetID, 100)
	a := f.unsigned(t, f.chainID, nil, regA)
	b := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, a, f.approve(t, a, f.admins[0], f.admins[1]), "")
	f.check(t, b, f.approve(t, b, f.admins[0], f.admins[1]), "isn't on the P-Chain yet")
	f.check(t, a, f.approve(t, a, f.admins[1], f.admins[2]), "") // the same change again

	// Survives a restart: a new manager on the same database.
	f.m = &validatorManager{vm: f.m.vm, policy: f.m.policy, db: f.m.db, now: f.m.now}
	f.check(t, b, f.approve(t, b, f.admins[0], f.admins[1]), "isn't on the P-Chain yet")

	// Once A is on the P-Chain, B can go.
	nodeA, _ := ids.ToNodeID(regA.NodeID)
	f.current[regA.ValidationID()] = &validators.GetCurrentValidatorOutput{ValidationID: regA.ValidationID(), NodeID: nodeA, Weight: 100, IsL1Validator: true, IsActive: true}
	f.check(t, b, f.approve(t, b, f.admins[0], f.admins[1]), "")

	// A registration that expired no longer holds anything up.
	f.fresh()
	c := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, c, f.approve(t, c, f.admins[0], f.admins[1]), "")
	f.check(t, b, f.approve(t, b, f.admins[0], f.admins[1]), "isn't on the P-Chain yet")
	f.now = time.Unix(1_900_000_000, 0).Add(expirySlack + time.Second) // past the fixture's expiry
	f.deadline = uint64(f.now.Add(time.Hour).Unix())
	f.check(t, b, f.approve(t, b, f.admins[0], f.admins[1]), "")

	// A weight change holds until the P-Chain's nonce passes it; one at the
	// same nonce may replace it, one at another nonce may not.
	f.fresh()
	target := f.anyValidation()
	f.current[target].MinNonce = 3
	w1 := f.unsigned(t, f.chainID, nil, f.weight(t, target, 150)) // nonce 3
	f.check(t, w1, f.approve(t, w1, f.admins[0], f.admins[1]), "")
	replaced, err := message.NewL1ValidatorWeight(target, 3, 120)
	if err != nil {
		t.Fatal(err)
	}
	w2 := f.unsigned(t, f.chainID, nil, replaced)
	f.check(t, w2, f.approve(t, w2, f.admins[0], f.admins[1]), "")
	later, err := message.NewL1ValidatorWeight(target, 4, 110)
	if err != nil {
		t.Fatal(err)
	}
	w3 := f.unsigned(t, f.chainID, nil, later)
	f.check(t, w3, f.approve(t, w3, f.admins[0], f.admins[1]), "isn't on the P-Chain yet")
	f.current[target].MinNonce = 4 // w2 applied
	f.current[target].Weight = 120
	f.check(t, w3, f.approve(t, w3, f.admins[0], f.admins[1]), "")
}

type countingHandler struct{ calls int }

func (*countingHandler) AppGossip(context.Context, ids.NodeID, []byte) {}
func (h *countingHandler) AppRequest(context.Context, ids.NodeID, time.Time, []byte) ([]byte, *common.AppError) {
	h.calls++
	return nil, nil
}

// Each peer has its own budget, so one can't starve the others.
func TestLimitedHandler(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	inner := &countingHandler{}
	h := newLimitedHandler(inner, func() time.Time { return now })
	noisy, quiet := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	refused := 0
	for range 50 {
		if _, err := h.AppRequest(context.Background(), noisy, now, nil); err != nil {
			refused++
		}
	}
	if inner.calls != peerBurst || refused != 50-peerBurst {
		t.Fatalf("noisy peer: %d served, %d refused; want %d served", inner.calls, refused, peerBurst)
	}
	if _, err := h.AppRequest(context.Background(), quiet, now, nil); err != nil {
		t.Fatalf("a quiet peer was refused: %s", err.Message)
	}
	now = now.Add(time.Second)
	if _, err := h.AppRequest(context.Background(), noisy, now, nil); err != nil {
		t.Fatalf("the noisy peer's budget didn't refill: %s", err.Message)
	}
}

func TestValidatorManagerWithoutAdminsSignsNothing(t *testing.T) {
	f := newManagerFixture(t, false, 4)
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, msg, f.approve(t, msg, f.admins...), "no validatorAdmins")
}

// The approval format is shared with the admin tools (metal-l1-admin):
// these bytes must not change.
func TestApprovalHashVector(t *testing.T) {
	msg := []byte("unsigned warp message bytes")
	got := hex.EncodeToString(ApprovalHash(msg, 1_800_000_000))
	const want = "afefcb8bc9f1797ea50a59c04795f36ea691fe95586b6c4f3b242e8c608523b6"
	if got != want {
		t.Fatalf("ApprovalHash vector = %s; want %s", got, want)
	}
	j := EncodeJustification(1_800_000_000, [][]byte{bytes.Repeat([]byte{7}, 65)})
	if hex.EncodeToString(j[:9]) != "01000000006b49d200" || len(j) != 9+65 {
		t.Fatalf("justification header %x", j[:9])
	}
}

func TestParseValidatorAdmins(t *testing.T) {
	var addrs []string
	for range 3 {
		addr, err := address.Format("P", constants.GetHRP(constants.MainnetID), newKey(t).Address().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, `"`+addr+`"`)
	}
	config := func(admins []string, threshold string) []byte {
		s := `{"rpcUser":"x","validatorAdmins":[` + strings.Join(admins, ",") + `]`
		if threshold != "" {
			s += `,"validatorAdminThreshold":` + threshold
		}
		return []byte(s + "}")
	}
	for _, tc := range []struct {
		name      string
		config    []byte
		admins    int
		threshold int // -1 = must be refused
	}{
		{"no config", nil, 0, 0},
		{"no admins", []byte(`{"rpcUser":"x"}`), 0, 0},
		{"one admin, default threshold", config(addrs[:1], ""), 1, 1},
		{"one admin, threshold 1", config(addrs[:1], "1"), 1, 1},
		{"two admins, default is both", config(addrs[:2], ""), 2, 2},
		{"three admins, default is two", config(addrs, ""), 3, 2},
		{"three admins, all three", config(addrs, "3"), 3, 3},
		{"three admins, one: 1-of-N", config(addrs, "1"), 0, -1},
		{"threshold above the admins", config(addrs, "4"), 0, -1},
		{"threshold 0", config(addrs, "0"), 0, -1},
		{"threshold without admins", config(nil, "1"), 0, -1},
		{"an admin twice", config([]string{addrs[0], addrs[0]}, ""), 0, -1},
		{"a bad address", config([]string{`"not-an-address"`}, ""), 0, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseValidatorAdmins(tc.config)
			if tc.threshold < 0 {
				if err == nil {
					t.Fatalf("accepted: %d admins, threshold %d", p.admins.Len(), p.threshold)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.admins.Len() != tc.admins || p.threshold != tc.threshold {
				t.Fatalf("%d admins, threshold %d; want %d, %d", p.admins.Len(), p.threshold, tc.admins, tc.threshold)
			}
		})
	}
}

func TestQuorumMatchesThePChain(t *testing.T) {
	for _, tc := range []struct{ total, need uint64 }{
		{1, 1}, {2, 2}, {3, 3}, {100, 67}, {200, 134}, {300, 201}, {600, 402}, {101, 68},
	} {
		if got := requiredWeight(tc.total); got != tc.need {
			t.Errorf("requiredWeight(%d) = %d, want %d", tc.total, got, tc.need)
		}
		if !quorum(new(big.Int).SetUint64(tc.need), tc.total) {
			t.Errorf("quorum(%d of %d) = false", tc.need, tc.total)
		}
		if tc.need > 0 && quorum(new(big.Int).SetUint64(tc.need-1), tc.total) {
			t.Errorf("quorum(%d of %d) = true; the P-Chain would reject it", tc.need-1, tc.total)
		}
	}
}
