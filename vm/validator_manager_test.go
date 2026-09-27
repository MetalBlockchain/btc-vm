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

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/validators"
	"github.com/MetalBlockchain/metalgo/snow/validators/validatorstest"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
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
		id := ids.GenerateTestID()
		f.current[id] = &validators.GetCurrentValidatorOutput{ValidationID: id, NodeID: ids.GenerateTestNodeID(), Weight: 100, IsActive: true, IsL1Validator: true}
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
	f.m = &validatorManager{vm: vm, policy: policy, now: func() time.Time { return f.now }}
	return f
}

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
		t.Run(tc.name, func(t *testing.T) { f.check(t, tc.msg, tc.justification(tc.msg), tc.wantErr) })
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
		{"a heavy fifth (weight 400 of 800)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 400) }, "holds 50.0%", ""},
		{"a fifth at 199 of 599 (33.2%)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 199) }, "", ""},
		{"a fifth at 200 of 600 (33.3%)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 200) }, "needs all 3 admins", ""},
		{"removing one of five (25% each after)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "", ""},
		{"removing one of four (33.3% each after)", 4, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "needs all 3 admins", ""},
		{"removing the last", 1, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "last active validator", "last active validator"},
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
			f.check(t, msg, f.approve(t, msg, f.admins...), tc.all)
		})
	}
}

// Inactive validators (no balance left) don't count toward the weight.
func TestValidatorManagerIgnoresInactiveWeight(t *testing.T) {
	f := newManagerFixture(t, true, 4)
	for _, v := range f.current {
		v.IsActive = false
		break
	}
	// 3 active at 100 plus a new 100: 25% each, fine with two admins. With
	// the inactive one counted it would be 20%; without it, 100 of 400.
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, msg, f.approve(t, msg, f.admins[0], f.admins[1]), "")
	// 3 active: removing one leaves 2 at 50%.
	var active ids.ID
	for id, v := range f.current {
		if v.IsActive {
			active = id
		}
	}
	msg = f.unsigned(t, f.chainID, nil, f.weight(t, active, 0))
	f.check(t, msg, f.approve(t, msg, f.admins[0], f.admins[1]), "needs all 3 admins")
}

func TestValidatorManagerWithoutAdminsSignsNothing(t *testing.T) {
	f := newManagerFixture(t, false, 4)
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, msg, f.approve(t, msg, f.admins...), "no validatorAdmins")
}

func TestValidatorManagerRateLimit(t *testing.T) {
	f := newManagerFixture(t, true, 4)
	f.m.limiter = newRateLimiter(1, 3)
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	j := f.approve(t, msg, f.admins[0], f.admins[1])
	for i := range 3 {
		if appErr := f.m.Verify(context.Background(), msg, j); appErr != nil {
			t.Fatalf("request %d: %s", i+1, appErr.Message)
		}
	}
	f.check(t, msg, j, "too many signature requests")
	f.now = f.now.Add(1500 * time.Millisecond)
	f.check(t, msg, j, "")
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
