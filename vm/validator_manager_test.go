// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	height   uint64                                           // the P-Chain height the fixture reports
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

func blsKey(t *testing.T) *bls.PublicKey {
	t.Helper()
	sk, err := localsigner.New()
	if err != nil {
		t.Fatal(err)
	}
	return sk.PublicKey()
}

// newManagerFixture: an L1 with validatorCount active validators of weight
// 100, a bootstrapped node, and no change held.
func newManagerFixture(t *testing.T, withAdmins bool, validatorCount int) *managerFixture {
	t.Helper()
	f := &managerFixture{
		outsider: newKey(t), netID: constants.LocalID, chainID: ids.GenerateTestID(), subnetID: ids.GenerateTestID(),
		now: time.Unix(1_800_000_000, 0), height: 10, current: map[ids.ID]*validators.GetCurrentValidatorOutput{},
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
			return f.current, f.height, nil
		},
	}
	vm := &VM{ctx: &snow.Context{NetworkID: f.netID, ChainID: f.chainID, SubnetID: f.subnetID, ValidatorState: state}}
	f.m = &validatorManager{vm: vm, policy: policy, lock: changeLock{path: filepath.Join(t.TempDir(), "held-change.json")}, now: func() time.Time { return f.now }}
	f.m.ready.Store(true)
	return f
}

// addValidator adds a validation with its own BLS key to the fixture L1.
func (f *managerFixture) addValidator(t *testing.T, weight uint64, active bool) ids.ID {
	t.Helper()
	id := ids.GenerateTestID()
	f.current[id] = &validators.GetCurrentValidatorOutput{
		ValidationID: id, NodeID: ids.GenerateTestNodeID(), PublicKey: blsKey(t),
		Weight: weight, IsActive: active, IsL1Validator: true,
	}
	return id
}

// fresh forgets the change the manager holds.
func (f *managerFixture) fresh(t *testing.T) {
	t.Helper()
	if err := os.Remove(f.m.lock.path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// anyOtherThan is an active validation other than id.
func (f *managerFixture) anyOtherThan(id ids.ID) ids.ID {
	for other, v := range f.current {
		if other != id && v.IsActive {
			return other
		}
	}
	return ids.Empty
}

// anyValidation is one of the fixture L1's active validation IDs.
func (f *managerFixture) anyValidation() ids.ID {
	for id, v := range f.current {
		if v.IsActive {
			return id
		}
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

// registrationAt is a registration for a new node, expiring an hour from now.
func (f *managerFixture) registrationAt(t *testing.T, subnetID ids.ID, weight uint64, key *bls.PublicKey, expiry uint64) *message.RegisterL1Validator {
	t.Helper()
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	var pk [bls.PublicKeyLen]byte
	copy(pk[:], bls.PublicKeyToCompressedBytes(key))
	r, err := message.NewRegisterL1Validator(subnetID, ids.GenerateTestNodeID(), pk, expiry, owner, owner, weight)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *managerFixture) registration(t *testing.T, subnetID ids.ID, weight uint64) *message.RegisterL1Validator {
	t.Helper()
	return f.registrationAt(t, subnetID, weight, blsKey(t), uint64(f.now.Add(time.Hour).Unix()))
}

// weight is a weight change at the nonce the P-Chain expects.
func (f *managerFixture) weight(t *testing.T, validationID ids.ID, weight uint64) *message.L1ValidatorWeight {
	t.Helper()
	nonce := uint64(0)
	if v, ok := f.current[validationID]; ok {
		nonce = v.MinNonce
	}
	w, err := message.NewL1ValidatorWeight(validationID, nonce, weight)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func sign(t *testing.T, msg *warp.UnsignedMessage, a Approval, keys ...*secp256k1.PrivateKey) [][]byte {
	t.Helper()
	var out [][]byte
	for _, key := range keys {
		sig, err := key.SignHash(ApprovalHash(msg.Bytes(), a))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig)
	}
	return out
}

// approve is the justification carrying each key's approval of msg, in
// order, with the fixture's deadline and no flags.
func (f *managerFixture) approve(t *testing.T, msg *warp.UnsignedMessage, keys ...*secp256k1.PrivateKey) []byte {
	t.Helper()
	a := Approval{Deadline: f.deadline}
	return EncodeJustification(a, sign(t, msg, a, keys...))
}

// approveReplacing approves msg to replace the held changes named.
func (f *managerFixture) approveReplacing(t *testing.T, msg *warp.UnsignedMessage, replaces [][32]byte, keys ...*secp256k1.PrivateKey) []byte {
	t.Helper()
	a := Approval{Flags: FlagReplaceHeld, Deadline: f.deadline, Replaces: replaces}
	return EncodeJustification(a, sign(t, msg, a, keys...))
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
	// Six validators: adding a seventh at 100 leaves 500 of 700 able to sign
	// without any one of them, so two admins suffice.
	f := newManagerFixture(t, true, 6)
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
			a := Approval{Deadline: deadline}
			return EncodeJustification(a, sign(t, m, a, keys...))
		}
	}
	now := uint64(f.now.Unix())
	target := f.anyValidation()
	f.current[target].MinNonce = 7
	wrongNonce, err := message.NewL1ValidatorWeight(target, 8, 50)
	if err != nil {
		t.Fatal(err)
	}
	hugeNonce, err := message.NewL1ValidatorWeight(target, math.MaxUint64, 50)
	if err != nil {
		t.Fatal(err)
	}
	hugeRemoval, err := message.NewL1ValidatorWeight(target, math.MaxUint64, 0)
	if err != nil {
		t.Fatal(err)
	}
	var badKey [bls.PublicKeyLen]byte
	badKey[0] = 1
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	badKeyReg, err := message.NewRegisterL1Validator(f.subnetID, ids.GenerateTestNodeID(), badKey, now+3600, owner, owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	badOwner, err := message.NewRegisterL1Validator(f.subnetID, ids.GenerateTestNodeID(), [bls.PublicKeyLen]byte{}, now+3600,
		message.PChainOwner{Threshold: 2, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}, owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	copy(badOwner.BLSPublicKey[:], bls.PublicKeyToCompressedBytes(blsKey(t)))
	badOwnerMsg := f.unsigned(t, f.chainID, nil, badOwner)

	for _, tc := range []struct {
		name          string
		msg           *warp.UnsignedMessage
		justification func(*warp.UnsignedMessage) []byte
		wantErr       string // "" = must sign
	}{
		{"registration approved by two admins", good, by(a, b), ""},
		{"approved by all three", good, by(c, a, b), ""},
		{"removal of one of six by two", f.unsigned(t, f.chainID, nil, f.weight(t, target, 0)), by(b, c), ""},
		{"no approval", good, func(*warp.UnsignedMessage) []byte { return nil }, "no admin approvals"},
		{"a header and no approvals", good, func(*warp.UnsignedMessage) []byte { return EncodeJustification(Approval{Deadline: f.deadline}, nil) }, "no whole admin approvals"},
		{"one admin alone", good, by(a), "approved by 1 of this L1's admins; it needs 2"},
		{"one admin twice", good, by(a, a), "repeats admin"},
		{"an admin and an outsider", good, by(a, f.outsider), "not one of this L1's validatorAdmins"},
		{"more approvals than admins", good, by(a, b, c, a), "only 3 admins"},
		{"a partial approval", good, func(m *warp.UnsignedMessage) []byte { return f.approve(t, m, a, b)[:100] }, "each is a 65-byte signature"},
		{"another format", good, func(m *warp.UnsignedMessage) []byte { j := f.approve(t, m, a, b); j[0] = 2; return j }, "approval format 2"},
		{"an unknown flag", good, func(m *warp.UnsignedMessage) []byte { j := f.approve(t, m, a, b); j[1] = 0x80; return j }, "flags"},
		{"a replacement naming no held change", good, func(m *warp.UnsignedMessage) []byte {
			j := f.approveReplacing(t, m, [][32]byte{{1}}, a, b, c)
			j[10] = 0
			return j
		}, "names 1 to"},
		{"a named held change swapped after signing", good, func(m *warp.UnsignedMessage) []byte {
			j := f.approveReplacing(t, m, [][32]byte{{1}}, a, b, c)
			j[11] = 2
			return j
		}, "not one of this L1's validatorAdmins"},
		{"replacing held changes with two admins", good, func(m *warp.UnsignedMessage) []byte { return f.approveReplacing(t, m, [][32]byte{{1}}, a, b) }, "only every admin together"},
		{"expired", good, withDeadline(now-1, a, b), "expired"},
		{"deadline too far ahead", good, withDeadline(uint64(f.now.Add(MaxApprovalLife+time.Minute).Unix()), a, b), "more than"},
		{"deadline changed after signing", good, func(m *warp.UnsignedMessage) []byte {
			return EncodeJustification(Approval{Deadline: f.deadline + 60}, sign(t, m, Approval{Deadline: f.deadline}, a, b))
		}, "not one of this L1's validatorAdmins"},
		{"admin signed the bare hash, not the approval", good, func(m *warp.UnsignedMessage) []byte {
			ap := Approval{Deadline: f.deadline}
			return EncodeJustification(ap, append(sign(t, m, ap, b), undomained))
		}, "not one of this L1's validatorAdmins"},
		{"second approval is of a different message", good, func(m *warp.UnsignedMessage) []byte {
			ap := Approval{Deadline: f.deadline}
			return EncodeJustification(ap, append(sign(t, m, ap, a), sign(t, other, ap, b)...))
		}, "not one of this L1's validatorAdmins"},
		{"a registration already expired", f.unsigned(t, f.chainID, nil, f.registrationAt(t, f.subnetID, 100, blsKey(t), now)), by(a, b), "expire within the next"},
		{"a registration expiring in over a day", f.unsigned(t, f.chainID, nil, f.registrationAt(t, f.subnetID, 100, blsKey(t), now+86401)), by(a, b), "expire within the next"},
		{"a registration expiring past MaxInt64", f.unsigned(t, f.chainID, nil, f.registrationAt(t, f.subnetID, 100, blsKey(t), math.MaxUint64)), by(a, b), "expire within the next"},
		{"a BLS key that doesn't parse", f.unsigned(t, f.chainID, nil, badKeyReg), by(a, b), "BLS key doesn't parse"},
		{"an owner the P-Chain would refuse", badOwnerMsg, by(a, b), "invalid registration"},
		{"a weight change at the wrong nonce", f.unsigned(t, f.chainID, nil, wrongNonce), by(a, b, c), "the P-Chain expects 7"},
		{"a weight change at nonce MaxUint64", f.unsigned(t, f.chainID, nil, hugeNonce), by(a, b, c), "invalid weight change"},
		{"a removal at nonce MaxUint64 (it would hold every signer for good)", f.unsigned(t, f.chainID, nil, hugeRemoval), by(a, b, c), "could never be followed"},
		{"another L1's subnet", f.unsigned(t, f.chainID, nil, f.registration(t, ids.GenerateTestID(), 100)), by(a, b), "registration is for subnet"},
		{"weight 0 registration", f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 0)), by(a, b), "weight"},
		{"non-empty source address", f.unsigned(t, f.chainID, []byte{1, 2, 3}, reg), by(a, b), "source address must be empty"},
		{"from another chain", f.unsigned(t, ids.GenerateTestID(), nil, reg), by(a, b), "not this chain"},
		{"another kind of message", f.unsigned(t, f.chainID, nil, conversion), by(a, b), "registrations and weight changes only"},
		{"weight change for another L1's validator", f.unsigned(t, f.chainID, nil, f.weight(t, ids.GenerateTestID(), 50)), by(a, b, c), "not one of this L1's validators"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.fresh(t)
			f.check(t, tc.msg, tc.justification(tc.msg), tc.wantErr)
		})
	}
}

func TestValidatorManagerWaitsForBootstrap(t *testing.T) {
	f := newManagerFixture(t, true, 5)
	f.m.ready.Store(false)
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, msg, f.approve(t, msg, f.admins...), "still bootstrapping")
	if _, err := os.Stat(f.m.lock.path); !os.IsNotExist(err) {
		t.Fatal("held a change it didn't sign")
	}
}

// A change after which any one validator could block the P-Chain's quorum
// needs every admin; one leaving the validators able to sign under 67% is
// refused outright (a newcomer can't sign until it's active).
func TestValidatorManagerWeightShares(t *testing.T) {
	for _, tc := range []struct {
		name       string
		validators int
		change     func(f *managerFixture) message.Payload
		two, all   string // refusal with two admins, with all three ("" = signs)
	}{
		{"second validator at 100 (only 100 of 200 could sign)", 1, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "at most 49", "at most 49"},
		{"second validator at 49 (the first still blocks alone)", 1, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 49) }, "needs all 3 admins", ""},
		{"second validator at 50", 1, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 50) }, "at most 49", "at most 49"},
		// 300 of 400 can sign, but the newcomer can't yet: without any one of
		// the three, 200 of 400 is under 67%.
		{"fourth validator at 100 (a newcomer can't sign yet)", 3, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "needs all 3 admins", ""},
		{"a sixth at 100 (without one of five, 400 of 600 isn't 67%)", 5, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "needs all 3 admins", ""},
		{"a seventh at 100 (without one of six, 500 of 700 is)", 6, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 100) }, "", ""},
		{"a heavy fifth (weight 400 of 800)", 4, func(f *managerFixture) message.Payload { return f.registration(t, f.subnetID, 400) }, "able to sign hold 50.0%", "able to sign hold 50.0%"},
		// The P-Chain's quorum, exactly: 400 of 597 is 67.0%, of 598 isn't.
		{"raising one of five to 197 (the rest still make 67%)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 197) }, "", ""},
		{"raising one of five to 198 (the rest don't)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 198) }, "needs all 3 admins", ""},
		{"removing one of five (25% each after)", 5, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "", ""},
		{"removing one of four (33.3% each after)", 4, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "needs all 3 admins", ""},
		{"removing the last", 1, func(f *managerFixture) message.Payload { return f.weight(t, f.anyValidation(), 0) }, "no active validator", "no active validator"},
		{"a node that already validates", 4, func(f *managerFixture) message.Payload {
			node := f.current[f.anyValidation()].NodeID
			owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
			var pk [bls.PublicKeyLen]byte
			copy(pk[:], bls.PublicKeyToCompressedBytes(blsKey(t)))
			r, err := message.NewRegisterL1Validator(f.subnetID, node, pk, uint64(f.now.Add(time.Hour).Unix()), owner, owner, 100)
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
			f.fresh(t)
			f.check(t, msg, f.approve(t, msg, f.admins...), tc.all)
		})
	}
}

// Inactive validators (no balance) count in the total, as in Warp, but
// can't sign: a change must leave the active ones at 67% of it.
func TestValidatorManagerInactiveWeight(t *testing.T) {
	two := func(f *managerFixture) []*secp256k1.PrivateKey { return f.admins[:2] }
	all := func(f *managerFixture) []*secp256k1.PrivateKey { return f.admins }
	var active func(f *managerFixture) ids.ID = func(f *managerFixture) ids.ID { return f.anyValidation() }
	for _, tc := range []struct {
		name    string
		setup   func(f *managerFixture) message.Payload
		admins  func(f *managerFixture) []*secp256k1.PrivateKey
		wantErr string
	}{
		{"a fifth into four active and one inactive (400 of 600 can sign)", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.registration(t, f.subnetID, 100)
		}, all, "able to sign hold 66.7%"},
		// 400 of 597 can sign, but without any one active validator 300 can't.
		{"...at a weight the active ones outweigh: every admin", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.registration(t, f.subnetID, 97)
		}, two, "needs all 3 admins"},
		{"...approved by every admin", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.registration(t, f.subnetID, 97)
		}, all, ""},
		{"raising an inactive validator's weight", func(f *managerFixture) message.Payload {
			return f.weight(t, f.addValidator(t, 100, false), 300)
		}, all, "able to sign hold"},
		// 400 of 600 -> 400 of 500: signable again, but one loss (300 of 500)
		// would stop it, so every admin.
		{"removing an inactive validator from a stuck set", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.weight(t, f.addValidator(t, 100, false), 0)
		}, all, ""},
		{"...with two admins", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.weight(t, f.addValidator(t, 100, false), 0)
		}, two, "needs all 3 admins"},
		{"removing an active one while inactive weight is high", func(f *managerFixture) message.Payload {
			f.addValidator(t, 100, false)
			return f.weight(t, active(f), 0) // 300 of 400: any one more loss stops it
		}, two, "needs all 3 admins"},
		// The growth walk's last step: V4 joined at 1 and is active; raising it
		// to 100 leaves 4 x 100, where losing any one still leaves 75%.
		{"raising an active fourth validator from 1 to 100", func(f *managerFixture) message.Payload {
			v4 := f.addValidator(t, 1, true)      // the fixture's four, plus V4 at 1
			delete(f.current, f.anyOtherThan(v4)) // three at 100, and V4
			return f.weight(t, v4, 100)
		}, two, ""},
		{"a heavy inactive validator counts (a top-up could reactivate it)", func(f *managerFixture) message.Payload {
			f.addValidator(t, 250, false)
			return f.registration(t, f.subnetID, 10)
		}, all, "able to sign hold"},
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
	msg := f.unsigned(t, f.chainID, nil, f.registrationAt(t, f.subnetID, 1, existing.PublicKey, uint64(f.now.Add(time.Hour).Unix())))
	f.check(t, msg, f.approve(t, msg, f.admins...), "BLS key is already registered")
}

// A node signs one change at a time, so separately approved changes can't
// be gathered and submitted together.
func TestValidatorManagerOneChangeAtATime(t *testing.T) {
	f := newManagerFixture(t, true, 6)
	two := []*secp256k1.PrivateKey{f.admins[0], f.admins[1]}
	regA := f.registration(t, f.subnetID, 100)
	a := f.unsigned(t, f.chainID, nil, regA)
	b := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, a, f.approve(t, a, two...), "")
	f.check(t, b, f.approve(t, b, two...), "isn't on the P-Chain yet")
	f.check(t, a, f.approve(t, a, f.admins[1], f.admins[2]), "") // the same change again

	// Held on disk: a new manager on the same data directory still holds it.
	restarted := &validatorManager{vm: f.m.vm, policy: f.m.policy, lock: f.m.lock, now: f.m.now}
	restarted.ready.Store(true)
	f.m = restarted
	f.check(t, b, f.approve(t, b, two...), "isn't on the P-Chain yet")

	// A view of the P-Chain older than the held change proves nothing.
	f.height = 9
	f.check(t, b, f.approve(t, b, two...), "older than the change it holds")
	f.height = 10

	// Once A is on the P-Chain, B can go.
	nodeA, _ := ids.ToNodeID(regA.NodeID)
	f.current[regA.ValidationID()] = &validators.GetCurrentValidatorOutput{ValidationID: regA.ValidationID(), NodeID: nodeA, PublicKey: blsKey(t), Weight: 100, IsL1Validator: true, IsActive: true}
	f.height = 11
	f.check(t, b, f.approve(t, b, two...), "")

	// A registration past its expiry no longer holds anything up.
	f.fresh(t)
	regC := f.registration(t, f.subnetID, 100)
	cMsg := f.unsigned(t, f.chainID, nil, regC)
	f.check(t, cMsg, f.approve(t, cMsg, two...), "")
	d := f.unsigned(t, f.chainID, nil, f.weight(t, f.anyValidation(), 90))
	f.check(t, d, f.approve(t, d, two...), "isn't on the P-Chain yet")
	f.now = time.Unix(int64(regC.Expiry), 0).Add(expirySlack + time.Second)
	f.deadline = uint64(f.now.Add(time.Hour).Unix())
	f.check(t, d, f.approve(t, d, two...), "")

	// A weight change holds until the P-Chain's nonce passes it; one at the
	// same nonce may replace it.
	f.fresh(t)
	target := f.anyValidation()
	f.current[target].MinNonce = 3
	w1 := f.unsigned(t, f.chainID, nil, f.weight(t, target, 150))
	f.check(t, w1, f.approve(t, w1, two...), "")
	w2 := f.unsigned(t, f.chainID, nil, f.weight(t, target, 120)) // same nonce 3
	f.check(t, w2, f.approve(t, w2, two...), "")
	other := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, other, f.approve(t, other, two...), "isn't on the P-Chain yet")
	f.current[target].MinNonce, f.current[target].Weight = 4, 120 // w2 applied
	f.height = 12
	f.check(t, other, f.approve(t, other, two...), "")

	// A removal is released once the validation is gone from a view at
	// least as new.
	f.fresh(t)
	gone := f.anyValidation()
	rm := f.unsigned(t, f.chainID, nil, f.weight(t, gone, 0))
	f.check(t, rm, f.approve(t, rm, two...), "")
	next := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, next, f.approve(t, next, two...), "isn't on the P-Chain yet")
	delete(f.current, gone)
	f.height = 13
	f.check(t, next, f.approve(t, next, two...), "")
}

// Validators holding different changes (so neither reaches 67%) can be
// freed by every admin together, never by fewer, and only from the held
// changes the replacement names: a saved one can't reset a later hold.
func TestValidatorManagerReplaceHeld(t *testing.T) {
	f := newManagerFixture(t, true, 6)
	a := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, a, f.approve(t, a, f.admins[0], f.admins[1]), "")
	c := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	heldA := HeldHash(a.Bytes())
	f.check(t, c, f.approve(t, c, f.admins...), "isn't on the P-Chain yet") // unanimity alone isn't enough
	f.check(t, c, f.approveReplacing(t, c, [][32]byte{heldA}, f.admins[0], f.admins[1]), "only every admin together")
	f.check(t, c, f.approveReplacing(t, c, [][32]byte{{9}}, f.admins...), "doesn't name the change this node holds")
	// A split: the replacement names both held changes; any node holding
	// either is freed.
	b := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	replaceBoth := f.approveReplacing(t, c, [][32]byte{HeldHash(b.Bytes()), heldA}, f.admins...)
	f.check(t, c, replaceBoth, "")
	held, err := f.m.lock.read()
	if err != nil || held == nil || !bytes.Equal(held.Message, c.Bytes()) {
		t.Fatalf("held %v, %v; want the replacing change", held, err)
	}
	// Kept and used later, on a new hold, it frees nothing: the new hold
	// isn't among those it names. (Here: a new change d, held after c.)
	f.fresh(t)
	d := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, d, f.approve(t, d, f.admins[0], f.admins[1]), "")
	f.check(t, c, replaceBoth, "doesn't name the change this node holds")
}

// A change every admin replaced is never signed again while it could still
// land; a replacement is good for an hour at most.
func TestValidatorManagerNeverResignsAReplacedChange(t *testing.T) {
	f := newManagerFixture(t, true, 6)
	a := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, a, f.approve(t, a, f.admins[0], f.admins[1]), "")
	regC := f.registration(t, f.subnetID, 100)
	c := f.unsigned(t, f.chainID, nil, regC)
	f.check(t, c, f.approveReplacing(t, c, [][32]byte{HeldHash(a.Bytes())}, f.admins...), "")
	// c lands: the hold on it is settled, but a stays dropped.
	nodeC, _ := ids.ToNodeID(regC.NodeID)
	f.current[regC.ValidationID()] = &validators.GetCurrentValidatorOutput{ValidationID: regC.ValidationID(), NodeID: nodeC, PublicKey: blsKey(t), Weight: 100, IsActive: true, IsL1Validator: true}
	f.height++
	f.check(t, a, f.approve(t, a, f.admins...), "every admin replaced this change")
	// Other changes go ahead.
	e := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, e, f.approve(t, e, f.admins...), "")
	held, err := f.m.lock.read()
	if err != nil || len(held.Dropped) != 1 || !bytes.Equal(held.Dropped[0], a.Bytes()) {
		t.Fatalf("dropped %v, %v; want a, kept across the new hold", held.Dropped, err)
	}

	// A replacement good for more than an hour is refused.
	far := Approval{Flags: FlagReplaceHeld, Deadline: uint64(f.now.Add(2 * time.Hour).Unix()), Replaces: [][32]byte{HeldHash(e.Bytes())}}
	g := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	f.check(t, g, EncodeJustification(far, sign(t, g, far, f.admins...)), "at most 1h0m0s away")
}

// A failed write of the held change stops all signing, and a retry of the
// same change rewrites it (so a record the disk may not have isn't trusted).
func TestValidatorManagerStopsAfterAFailedRecord(t *testing.T) {
	f := newManagerFixture(t, true, 6)
	a := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	j := f.approve(t, a, f.admins[0], f.admins[1])
	f.check(t, a, j, "")
	dir := filepath.Dir(f.m.lock.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)                               //nolint:errcheck // cleanup
	f.check(t, a, j, "signs nothing more until it restarts") // the same change: rewritten, and that fails
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.check(t, a, j, "signs nothing more until it restarts") // latched
}

func TestChangeLockIsDurableAndStrict(t *testing.T) {
	dir := t.TempDir()
	l := changeLock{path: filepath.Join(dir, "sub", "held-change.json")}
	if h, err := l.read(); h != nil || err != nil {
		t.Fatalf("empty lock read %v, %v", h, err)
	}
	if err := l.write(heldChange{Message: []byte{1, 2, 3}, Height: 42}); err != nil {
		t.Fatal(err)
	}
	h, err := l.read()
	if err != nil || h.Height != 42 || !bytes.Equal(h.Message, []byte{1, 2, 3}) {
		t.Fatalf("read back %+v, %v", h, err)
	}
	if err := os.WriteFile(l.path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.read(); err == nil {
		t.Fatal("a corrupt lock read as empty")
	}
}

type countingHandler struct{ calls int }

func (*countingHandler) AppGossip(context.Context, ids.NodeID, []byte) {}
func (h *countingHandler) AppRequest(context.Context, ids.NodeID, time.Time, []byte) ([]byte, *common.AppError) {
	h.calls++
	return nil, nil
}

// Each peer has its own budget; non-validators share a global one too, so
// they can't starve the validators.
func TestLimitedHandler(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	inner := &countingHandler{}
	validator := ids.GenerateTestNodeID()
	h := newLimitedHandler(inner, func() time.Time { return now }, func(_ context.Context, n ids.NodeID) bool { return n == validator })
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
	// Many strangers drain the global budget; a validator still gets through.
	for range globalBurst + 50 {
		_, _ = h.AppRequest(context.Background(), ids.GenerateTestNodeID(), now, nil)
	}
	if _, err := h.AppRequest(context.Background(), ids.GenerateTestNodeID(), now, nil); err == nil {
		t.Fatal("a stranger got through with the global budget spent")
	}
	if _, err := h.AppRequest(context.Background(), validator, now, nil); err != nil {
		t.Fatalf("a validator was starved: %s", err.Message)
	}
	// With the peer table full, new strangers are turned away; the table
	// isn't reset (known peers keep their spent budgets).
	h.peers = map[ids.NodeID]*rateLimiter{noisy: h.peers[noisy]}
	for len(h.peers) < maxPeers {
		h.peers[ids.GenerateTestNodeID()] = newRateLimiter(peerRate, peerBurst)
	}
	now = now.Add(time.Hour)
	if _, err := h.AppRequest(context.Background(), ids.GenerateTestNodeID(), now, nil); err == nil {
		t.Fatal("a new stranger was admitted to a full table")
	}
	if _, ok := h.peers[noisy]; !ok {
		t.Fatal("the peer table was reset")
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
	var named [32]byte
	for i := range named {
		named[i] = 0xab
	}
	for _, tc := range []struct {
		a    Approval
		want string
	}{
		{Approval{Deadline: 1_800_000_000}, "51dd794736aa128ac3063b1f3ec5124006e12a2951b187aaed0d94b8e107e4d8"},
		{Approval{Flags: FlagReplaceHeld, Deadline: 1_800_000_000, Replaces: [][32]byte{named}}, "21bb593acd992e4d3e0d0260889b1ec0c344f17b567a42f27ea0ff3c88778ab4"},
	} {
		if got := hex.EncodeToString(ApprovalHash(msg, tc.a)); got != tc.want {
			t.Fatalf("ApprovalHash vector (flags %d) = %s; want %s", tc.a.Flags, got, tc.want)
		}
	}
	a := Approval{Flags: FlagReplaceHeld, Deadline: 1_800_000_000, Replaces: [][32]byte{named}}
	j := EncodeJustification(a, [][]byte{bytes.Repeat([]byte{7}, 65)})
	if hex.EncodeToString(j[:11]) != "0301000000006b49d20001" || len(j) != 11+32+65 {
		t.Fatalf("justification header %x", j[:11])
	}
	back, sigs, err := decodeJustification(j)
	if err != nil || len(sigs) != 1 || len(back.Replaces) != 1 || back.Replaces[0] != named || back.Deadline != a.Deadline {
		t.Fatalf("decoded %+v, %d sigs, %v", back, len(sigs), err)
	}
}

func TestMaxNewcomerWeight(t *testing.T) {
	for _, tc := range []struct{ signable, total, want int64 }{
		{100, 100, 49}, {200, 200, 98}, {300, 300, 147}, {400, 500, 97}, {60, 100, 0},
	} {
		got := MaxNewcomerWeight(big.NewInt(tc.signable), big.NewInt(tc.total))
		if got.Int64() != tc.want {
			t.Fatalf("MaxNewcomerWeight(%d, %d) = %s; want %d", tc.signable, tc.total, got, tc.want)
		}
		// And it's exact: one more wouldn't make 67%.
		w := new(big.Int).Add(got, big.NewInt(1))
		if quorumOf(big.NewInt(tc.signable), new(big.Int).Add(big.NewInt(tc.total), w)) {
			t.Fatalf("%d, %d: %s more would still make 67%%", tc.signable, tc.total, w)
		}
	}
}

// -check-config refuses what the VM would refuse at start.
func TestCheckChainConfig(t *testing.T) {
	addr, err := address.Format("P", constants.GetHRP(constants.MainnetID), newKey(t).Address().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for cfg, ok := range map[string]bool{
		`{"rpcUser":"x","validatorAdmins":["` + addr + `"]}`: true,
		`{}`:                                true,
		`{"validatorAdminThreshold":false}`: false,
		`{"MAINNET":true}`:                  false,
		`{"dropTxIndex":true}`:              false,
		`{"validatorAdmins":["` + addr + `"],"testNet":true}`: false,
	} {
		if err := CheckChainConfig([]byte(cfg)); (err == nil) != ok {
			t.Errorf("%s: %v; want ok=%v", cfg, err, ok)
		}
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
