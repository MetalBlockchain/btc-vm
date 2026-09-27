// Copyright (C) 2024-2025, Metallicus, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/constants"
	"github.com/MetalBlockchain/metalgo/utils/crypto/bls"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/vms/platformvm/warp/message"
)

func writeKey(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(keyFile{PrivateKey: key.String()})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeProposal(t *testing.T, dir string, p *proposal) string {
	t.Helper()
	raw, _ := json.Marshal(p)
	path := filepath.Join(dir, "proposal.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProposalApprovals(t *testing.T) {
	dir := t.TempDir()
	netID, chainID, subnetID := constants.LocalID, ids.GenerateTestID(), ids.GenerateTestID()
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	nodeID := ids.GenerateTestNodeID()
	reg, err := message.NewRegisterL1Validator(subnetID, nodeID, [bls.PublicKeyLen]byte{1}, uint64(time.Now().Add(time.Hour).Unix()), owner, owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := unsignedFor(netID, chainID, reg)
	if err != nil {
		t.Fatal(err)
	}
	c := &change{unsigned: unsigned, reg: reg}
	p := &proposal{UnsignedMessage: hexBytes(unsigned.Bytes())}
	if err := c.label(p); err != nil {
		t.Fatal(err)
	}
	p.setDeadline(time.Now().Add(time.Hour))
	if err := c.check(p); err != nil {
		t.Fatal(err)
	}
	admin1, admin2 := writeKey(t, dir, "a1.json"), writeKey(t, dir, "a2.json")
	if err := p.addApproval(unsigned, netID, admin1); err != nil {
		t.Fatal(err)
	}
	if err := p.addApproval(unsigned, netID, admin1); err == nil || !strings.Contains(err.Error(), "already approved") {
		t.Fatalf("a second approval by the same admin: %v", err)
	}

	// The next admin reads the file; its labels don't count, only the message
	// and whoever the signatures recover to.
	p.NodeID, p.Weight, p.Summary = ids.GenerateTestNodeID().String(), 1_000_000, "something harmless"
	p.ApprovedBy = []string{"P-local1fakefakefake", "P-local1another"}
	read, rc, err := readProposal(writeProposal(t, dir, p), netID, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if read.NodeID != nodeID.String() || read.Weight != 100 || !strings.Contains(read.Summary, nodeID.String()) {
		t.Fatalf("labels not recomputed from the message: %+v", read)
	}
	if len(read.ApprovedBy) != 1 || strings.Contains(read.ApprovedBy[0], "fake") {
		t.Fatalf("ApprovedBy taken from the file, not the signatures: %v", read.ApprovedBy)
	}
	if !strings.Contains(read.Summary, "can be disabled by 1 of [") || !strings.Contains(read.Summary, "BLS key 0x") {
		t.Fatalf("summary leaves out the disable owner or BLS key: %s", read.Summary)
	}
	if err := read.addApproval(rc.unsigned, netID, admin2); err != nil {
		t.Fatal(err)
	}
	sigs, who, err := read.approvals(rc.unsigned)
	if err != nil || len(sigs) != 2 || len(who) != 2 || who[0] == who[1] || len(read.ApprovedBy) != 2 {
		t.Fatalf("approvals %d by %v (%v), %v", len(sigs), who, read.ApprovedBy, err)
	}

	// Another chain's tool refuses the file.
	if _, _, err := readProposal(writeProposal(t, dir, read), netID, ids.GenerateTestID()); err == nil {
		t.Fatal("read a proposal for another chain")
	}
	// A deadline moved after approving invalidates the approvals.
	moved := *read
	moved.Deadline += 60
	if _, _, err := readProposal(writeProposal(t, dir, &moved), netID, chainID); err != nil {
		t.Fatal(err) // they still recover to some key...
	}
	_, movedWho, _ := moved.approvals(rc.unsigned)
	if movedWho[0] == who[0] || movedWho[1] == who[1] {
		t.Fatal("approvals still verify as the admins' after the deadline moved")
	}
	// So does the replace flag, turned on or off after approving: it's part
	// of what each admin signed.
	flipped := *read
	flipped.ReplaceHeld = !flipped.ReplaceHeld
	_, flippedWho, _ := flipped.approvals(rc.unsigned)
	if flippedWho[0] == who[0] || flippedWho[1] == who[1] {
		t.Fatal("approvals still verify as the admins' after the replace flag changed")
	}
	// A corrupted approval is refused.
	read.Approvals[1] = read.Approvals[1][:len(read.Approvals[1])-2] + "zz"
	if _, _, err := readProposal(writeProposal(t, dir, read), netID, chainID); err == nil {
		t.Fatal("read a proposal with a corrupted approval")
	}
}

func TestExpiredRegistrationRefused(t *testing.T) {
	owner := message.PChainOwner{Threshold: 1, Addresses: []ids.ShortID{ids.GenerateTestShortID()}}
	reg, err := message.NewRegisterL1Validator(ids.GenerateTestID(), ids.GenerateTestNodeID(), [bls.PublicKeyLen]byte{1}, uint64(time.Now().Add(-time.Minute).Unix()), owner, owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	future := &proposal{}
	future.setDeadline(time.Now().Add(time.Hour))
	if err := (&change{reg: reg}).check(future); err == nil || !strings.Contains(err.Error(), "registration expired") {
		t.Fatalf("expired registration: %v", err)
	}
	past := &proposal{}
	past.setDeadline(time.Now().Add(-time.Second))
	if err := (&change{}).check(past); err == nil || !strings.Contains(err.Error(), "approvals expired") {
		t.Fatalf("expired approvals: %v", err)
	}
}
