package main

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// rotation is a cosign harness moved from its first set to a new one: the
// coordinator runs with the new set, which names the old set as previous;
// the old set's three signers stay up, retired; three new signers join.
type rotation struct {
	*cosignHarness
	old, next *signerSet // public copies
	retired   []*cosigner
	fresh     []*cosigner
}

func (h *cosignHarness) rotate(t *testing.T) *rotation {
	t.Helper()
	full, err := newSignerSet(2, 3)
	require.NoError(t, err)
	old := h.b.signers
	next := &signerSet{Required: full.Required, PublicKeys: full.PublicKeys,
		Previous: []priorSet{{Required: old.Required, PublicKeys: old.PublicKeys}}}
	require.NoError(t, next.load())
	require.NotEqual(t, old.fingerprint(), next.fingerprint())

	r := &rotation{cosignHarness: h, old: old, next: next, retired: h.signers}
	h.b.signers = next
	// The retired signers keep their keys, logs and registries, and run
	// with the new set, which names theirs as previous.
	for _, c := range h.signers {
		c.b.signers = next
	}
	for i, key := range full.privKeys {
		dir := t.TempDir()
		own := *h.b
		own.signers = next
		own.cosigners = nil
		own.registry = &depositRegistry{path: filepath.Join(dir, "deposits.json")}
		log, err := openSigningLog(filepath.Join(dir, "signing-log.json"))
		require.NoError(t, err)
		c := &cosigner{b: &own, key: key, log: log, token: "token-new-" + string(rune('a'+i))}
		srv := httptest.NewServer(c.handler())
		t.Cleanup(srv.Close)
		r.fresh = append(r.fresh, c)
		h.b.cosigners = append(h.b.cosigners, &remoteSigner{URL: srv.URL, Token: c.token})
	}
	return r
}

// TestRotation moves a peg with history to a new set: the reserve and
// every Bitcoin coin move, a deposit credited under the old set is not
// credited again, one not yet credited is credited once under the new set,
// a late deposit to an old address is moved and credited, and the new set
// pays withdrawals. The peg stays solvent throughout.
func TestRotation(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 50
	}
	h.b.minFeeRate, h.b.maxFeeRate = 1, 50
	h.b.feeRate = func() (int64, error) { return 5, nil }
	alice, bob, dave, erin, carol := h.user(1), h.user(2), h.user(4), h.user(5), h.user(3)
	for _, d := range []destination{alice, bob, dave, erin} {
		_, err := registerDeposit(h.b, d)
		require.NoError(err)
	}

	// History under the old set.
	h.personalDeposit(10*btc, alice, 6)
	h.deposit(1*btc, nil, 6) // untagged: surplus that pays for the moves
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(10*btc-h.b.vmFee, creditedTo(h.vm, alice))
	h.pegOut(2*btc, carol)
	require.Contains(h.step(), "paid")
	h.btc.mine()
	// Bob's deposit is credited and its coin is still at his old deposit
	// address when the set changes: it must not be credited again.
	h.personalDeposit(4*btc, bob, 6)
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(4*btc-h.b.vmFee, creditedTo(h.vm, bob))
	h.personalDeposit(5*btc, dave, 1) // confirmed, not yet credited
	require.Empty(h.step())
	before := h.audit()
	require.True(before.solvent(), "%+v", before)

	r := h.rotate(t)

	// The reserve moves first.
	did := h.step()
	require.Contains(did, "reserve")
	h.vm.mine()
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Equal(before.Circulating+h.b.vmFee, a.Circulating, "the move's BTCVM fee is all that leaves the reserve")

	// Then Bitcoin: everything the old set holds, in one move.
	did = h.step()
	require.Contains(did, "Bitcoin")
	move := h.lastBTC()
	require.True(isMigrate(move))
	h.btc.mine()
	a = h.audit()
	require.True(a.solvent(), "%+v", a)
	s, err := h.b.load()
	require.NoError(err)
	require.Empty(s.legacyUTXOs, "the old set holds nothing on Bitcoin")
	require.Empty(s.legacyReserve, "nor on BTCVM")

	// Dave's deposit, uncredited, moved to his new deposit address; alice's,
	// credited, moved to the new peg address and is not credited again.
	daveScript := p2wshScript(r.next.depositRedeemScript(dave))
	bobScript := p2wshScript(r.next.depositRedeemScript(bob))
	var toDave, toBob int64
	for _, out := range move.TxOut {
		switch {
		case string(out.PkScript) == string(daveScript):
			toDave += out.Value
		case string(out.PkScript) == string(bobScript):
			toBob += out.Value
		}
	}
	require.Equal(int64(5*btc), toDave)
	require.Zero(toBob, "a credited deposit moves to the peg address, not a deposit address")

	for i := 0; i < 6; i++ {
		h.btc.mine()
	}
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(5*btc-h.b.vmFee, creditedTo(h.vm, dave), "credited once, under the new set")
	require.Equal(10*btc-h.b.vmFee, creditedTo(h.vm, alice), "not credited again")
	require.Equal(4*btc-h.b.vmFee, creditedTo(h.vm, bob), "not credited again")

	// A late deposit to erin's old address moves, then is credited.
	old := r.old.depositRedeemScript(erin)
	late := wire.NewMsgTx(1)
	late.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
	late.AddTxOut(wire.NewTxOut(3*btc, p2wshScript(old)))
	h.btc.add(late, 6)
	require.Contains(h.step(), "Bitcoin")
	sweep := h.lastBTC()
	sweepFee := h.feeOf(sweep) // a late deposit pays for its own move
	for i := 0; i < 6; i++ {
		h.btc.mine()
	}
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(3*btc-sweepFee-h.b.vmFee, creditedTo(h.vm, erin), "credited once, less the fee for moving it")
	require.Positive(sweepFee)

	// The new set pays withdrawals, from its own coins.
	h.pegOut(3*btc, carol)
	did, err = h.b.step()
	require.NoError(err)
	require.Contains(did, "paid")
	payout := h.lastBTC()
	for _, in := range payout.TxIn {
		_, ok := r.next.pegWitness(in.Witness[len(in.Witness)-1])
		require.True(ok, "paid from the new set's coins")
	}
	h.btc.mine()
	a = h.audit()
	require.True(a.solvent(), "%+v", a)
}

// TestRotationRefusals: each signer signs only its part. A retired signer
// signs nothing but moves, and only moves to where its own view says; a new
// signer never signs a move.
func TestRotationRefusals(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 50
	}
	h.b.minFeeRate, h.b.maxFeeRate = 1, 50
	alice := h.user(1)
	_, err := registerDeposit(h.b, alice)
	require.NoError(err)
	h.personalDeposit(10*btc, alice, 6)
	h.deposit(1*btc, nil, 6)
	for h.step() != "" {
		h.vm.mine()
	}
	r := h.rotate(t)
	s, err := h.b.load()
	require.NoError(err)
	sets, by := h.b.legacyBySet(s, s.legacyUTXOs)
	require.Len(sets, 1)
	coins := by[sets[0]]
	prev, _, err := s.pegSpends(coins)
	require.NoError(err)
	build := func(successors [][]byte) signRequest {
		tx, err := h.b.buildMigrate(chainBitcoin, sets[0], coins, prev, successors, 5)
		require.NoError(err)
		return signRequest{Chain: chainBitcoin, FeeRate: 5, Tx: encodeTx(tx),
			Action: action{Kind: actionMigrate, Deposit: coins[0].outPoint.String()}}
	}
	honest := make([][]byte, len(coins))
	for i, u := range coins {
		honest[i] = h.b.successor(s, chainBitcoin, u)
	}
	_, _, _, err = r.retired[0].check(build(honest))
	require.NoError(err, "the honest move passes")

	// Anywhere else: refused.
	thief := make([][]byte, len(coins))
	for i := range thief {
		thief[i] = h.user(9).pkScript()
	}
	_, _, _, err = r.retired[0].check(build(thief))
	require.ErrorContains(err, "not the transaction this signer would build")

	// Alice's credited deposit to her new deposit address, to be credited
	// again: refused.
	again := make([][]byte, len(coins))
	for i := range again {
		again[i] = p2wshScript(r.next.depositRedeemScript(alice))
	}
	_, _, _, err = r.retired[0].check(build(again))
	require.ErrorContains(err, "not the transaction this signer would build")

	// A new signer never signs a move; a retired one signs nothing else.
	_, _, _, err = r.fresh[0].check(build(honest))
	require.ErrorContains(err, "takes that set's signers")
	pegOut := h.pegOut(2*btc, h.user(3))
	req := signRequest{Chain: chainBitcoin, FeeRate: 5, Tx: build(honest).Tx,
		Action: action{Kind: actionPayout, PegOut: pegOut.TxHash().String()}}
	_, _, _, err = r.retired[0].check(req)
	require.ErrorContains(err, "only moves its coins to the new set")

}

// TestRotationNeedsSurplus: a move pays a network fee out of the peg, so
// neither coordinator nor signers move anything until the surplus covers
// it; the audit never dips below what is owed.
func TestRotationNeedsSurplus(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 50
	}
	h.b.minFeeRate, h.b.maxFeeRate = 1, 50
	h.b.feeRate = func() (int64, error) { return 5, nil }
	alice := h.user(1)
	_, err := registerDeposit(h.b, alice)
	require.NoError(err)
	h.personalDeposit(10*btc, alice, 6)
	for h.step() != "" {
		h.vm.mine()
	}
	require.Zero(h.audit().Surplus)
	r := h.rotate(t)

	_, err = h.b.step()
	require.ErrorContains(err, "surplus")
	require.True(h.audit().solvent())

	s, err := h.b.load()
	require.NoError(err)
	sets, by := h.b.legacyBySet(s, s.legacyReserve)
	require.Len(sets, 1)
	coins := by[sets[0]]
	var prev []spent
	for _, u := range coins {
		prev = append(prev, spent{script: sets[0].redeemScript, value: u.value})
	}
	successors := make([][]byte, len(coins))
	for i, u := range coins {
		successors[i] = h.b.successor(s, chainBTCVM, u)
	}
	tx, err := h.b.buildMigrate(chainBTCVM, sets[0], coins, prev, successors, 0)
	require.NoError(err)
	_, _, _, err = r.retired[0].check(signRequest{Chain: chainBTCVM, Tx: encodeTx(tx),
		Action: action{Kind: actionMigrate, Deposit: coins[0].outPoint.String()}})
	require.ErrorContains(err, "surplus")

	// Topped up, it moves.
	h.deposit(1*btc, nil, 6)
	require.Contains(h.step(), "reserve")
}

// creditedTo is everything every transaction on c pays dest: a deposit
// credited twice would show twice.
func creditedTo(c *fakeChain, dest destination) int64 {
	var total int64
	for _, t := range c.txs {
		for _, o := range t.tx.TxOut {
			if string(o.PkScript) == string(dest.pkScript()) {
				total += o.Value
			}
		}
	}
	return total
}
