// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
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
}

func newKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	k, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newManagerFixture(t *testing.T, withAdmins bool) *managerFixture {
	t.Helper()
	f := &managerFixture{outsider: newKey(t), netID: constants.LocalID, chainID: ids.GenerateTestID(), subnetID: ids.GenerateTestID()}
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
	vm := &VM{ctx: &snow.Context{NetworkID: f.netID, ChainID: f.chainID, SubnetID: f.subnetID}}
	f.m = &validatorManager{vm: vm, policy: policy}
	return f
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

// approve is the justification carrying each key's approval of msg, in order.
func approve(t *testing.T, msg *warp.UnsignedMessage, keys ...*secp256k1.PrivateKey) []byte {
	t.Helper()
	var out []byte
	for _, key := range keys {
		sig, err := key.SignHash(ApprovalHash(msg.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig...)
	}
	return out
}

func TestValidatorManagerVerify(t *testing.T) {
	f := newManagerFixture(t, true)
	a, b, c := f.admins[0], f.admins[1], f.admins[2]
	weight, err := message.NewL1ValidatorWeight(ids.GenerateTestID(), 3, 0)
	if err != nil {
		t.Fatal(err)
	}
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
		return func(m *warp.UnsignedMessage) []byte { return approve(t, m, keys...) }
	}

	for _, tc := range []struct {
		name          string
		msg           *warp.UnsignedMessage
		justification func(*warp.UnsignedMessage) []byte
		wantErr       string // "" = must sign
	}{
		{"registration approved by two admins", good, by(a, b), ""},
		{"approved by all three", good, by(c, a, b), ""},
		{"removal (weight 0) approved by two", f.unsigned(t, f.chainID, nil, weight), by(b, c), ""},
		{"no approval", good, func(*warp.UnsignedMessage) []byte { return nil }, "no admin approvals"},
		{"one admin alone", good, by(a), "approved by 1 of this L1's admins; it needs 2"},
		{"one admin twice", good, by(a, a), "repeats admin"},
		{"an admin and an outsider", good, by(a, f.outsider), "not one of this L1's validatorAdmins"},
		{"more approvals than admins", good, by(a, b, c, a), "only 3 admins"},
		{"a partial approval", good, func(m *warp.UnsignedMessage) []byte { return approve(t, m, a, b)[:100] }, "each is a 65-byte signature"},
		{"admin signed the bare hash, not the approval", good, func(m *warp.UnsignedMessage) []byte {
			return append(approve(t, m, b), undomained...)
		}, "not one of this L1's validatorAdmins"},
		{"second approval is of a different message", good, func(m *warp.UnsignedMessage) []byte {
			return append(approve(t, m, a), approve(t, other, b)...)
		}, "not one of this L1's validatorAdmins"},
		{"another L1's subnet", f.unsigned(t, f.chainID, nil, f.registration(t, ids.GenerateTestID(), 100)), by(a, b), "registration is for subnet"},
		{"weight 0 registration", f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 0)), by(a, b), "weight above 0"},
		{"non-empty source address", f.unsigned(t, f.chainID, []byte{1, 2, 3}, reg), by(a, b), "source address must be empty"},
		{"from another chain", f.unsigned(t, ids.GenerateTestID(), nil, reg), by(a, b), "not this chain"},
		{"another kind of message", f.unsigned(t, f.chainID, nil, conversion), by(a, b), "registrations and weight changes only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appErr := f.m.Verify(context.Background(), tc.msg, tc.justification(tc.msg))
			switch {
			case tc.wantErr == "" && appErr != nil:
				t.Fatalf("refused: %s", appErr.Message)
			case tc.wantErr != "" && appErr == nil:
				t.Fatalf("signed; want refusal %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(appErr.Message, tc.wantErr):
				t.Fatalf("refused with %q; want %q", appErr.Message, tc.wantErr)
			}
		})
	}
}

func TestValidatorManagerWithoutAdminsSignsNothing(t *testing.T) {
	f := newManagerFixture(t, false)
	msg := f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100))
	appErr := f.m.Verify(context.Background(), msg, approve(t, msg, f.admins...))
	if appErr == nil || !strings.Contains(appErr.Message, "no validatorAdmins") {
		t.Fatalf("got %v; want a refusal for no validatorAdmins", appErr)
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
		{"two admins, default is both", config(addrs[:2], ""), 2, 2},
		{"three admins, default is two", config(addrs, ""), 3, 2},
		{"three admins, all three", config(addrs, "3"), 3, 3},
		{"three admins, one (explicit)", config(addrs, "1"), 3, 1},
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
