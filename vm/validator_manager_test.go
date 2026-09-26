// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vm

import (
	"context"
	"crypto/sha256"
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
	admin    *secp256k1.PrivateKey
	outsider *secp256k1.PrivateKey
	netID    uint32
	chainID  ids.ID
	subnetID ids.ID
}

func newManagerFixture(t *testing.T, withAdmin bool) *managerFixture {
	t.Helper()
	admin, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &managerFixture{admin: admin, outsider: outsider, netID: constants.LocalID, chainID: ids.GenerateTestID(), subnetID: ids.GenerateTestID()}
	admins := set.Set[ids.ShortID]{}
	if withAdmin {
		admins.Add(admin.Address())
	}
	vm := &VM{ctx: &snow.Context{NetworkID: f.netID, ChainID: f.chainID, SubnetID: f.subnetID}}
	f.m = &validatorManager{vm: vm, admins: admins}
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

func approve(t *testing.T, key *secp256k1.PrivateKey, msg *warp.UnsignedMessage) []byte {
	t.Helper()
	sig, err := key.SignHash(ApprovalHash(msg.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestValidatorManagerVerify(t *testing.T) {
	f := newManagerFixture(t, true)
	weight, err := message.NewL1ValidatorWeight(ids.GenerateTestID(), 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	reg := f.registration(t, f.subnetID, 100)
	good := f.unsigned(t, f.chainID, nil, reg)

	rawHash := sha256.Sum256(good.Bytes())
	undomained, err := f.admin.SignHash(rawHash[:])
	if err != nil {
		t.Fatal(err)
	}
	conversion, err := message.NewSubnetToL1Conversion(ids.GenerateTestID())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		msg           *warp.UnsignedMessage
		justification func(*warp.UnsignedMessage) []byte
		wantErr       string // "" = must sign
	}{
		{"admin-approved registration", good, func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, ""},
		{"admin-approved removal (weight 0)", f.unsigned(t, f.chainID, nil, weight), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, ""},
		{"no approval", good, func(*warp.UnsignedMessage) []byte { return nil }, "no admin approval"},
		{"approved by a key that isn't an admin", good, func(m *warp.UnsignedMessage) []byte { return approve(t, f.outsider, m) }, "not one of this L1's validatorAdmins"},
		{"admin signed the bare hash, not the approval", good, func(*warp.UnsignedMessage) []byte { return undomained }, "not one of this L1's validatorAdmins"},
		{"approval of a different message", good, func(*warp.UnsignedMessage) []byte {
			return approve(t, f.admin, f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 100)))
		}, "not one of this L1's validatorAdmins"},
		{"another L1's subnet", f.unsigned(t, f.chainID, nil, f.registration(t, ids.GenerateTestID(), 100)), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, "registration is for subnet"},
		{"weight 0 registration", f.unsigned(t, f.chainID, nil, f.registration(t, f.subnetID, 0)), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, "weight above 0"},
		{"non-empty source address", f.unsigned(t, f.chainID, []byte{1, 2, 3}, reg), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, "source address must be empty"},
		{"from another chain", f.unsigned(t, ids.GenerateTestID(), nil, reg), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, "not this chain"},
		{"another kind of message", f.unsigned(t, f.chainID, nil, conversion), func(m *warp.UnsignedMessage) []byte { return approve(t, f.admin, m) }, "registrations and weight changes only"},
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
	appErr := f.m.Verify(context.Background(), msg, approve(t, f.admin, msg))
	if appErr == nil || !strings.Contains(appErr.Message, "no validatorAdmins") {
		t.Fatalf("got %v; want a refusal for no validatorAdmins", appErr)
	}
}

func TestParseValidatorAdmins(t *testing.T) {
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := address.Format("P", constants.GetHRP(constants.MainnetID), key.Address().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	admins, err := parseValidatorAdmins([]byte(`{"rpcUser":"x","validatorAdmins":["` + addr + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !admins.Contains(key.Address()) || admins.Len() != 1 {
		t.Fatalf("admins %v; want %s", admins, addr)
	}
	if a, err := parseValidatorAdmins(nil); err != nil || a.Len() != 0 {
		t.Fatalf("empty config: %v, %v", a, err)
	}
	if _, err := parseValidatorAdmins([]byte(`{"validatorAdmins":["not-an-address"]}`)); err == nil {
		t.Fatal("accepted a bad address")
	}
}
