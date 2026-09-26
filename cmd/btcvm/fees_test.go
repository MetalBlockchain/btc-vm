package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// TestPayoutToEveryAddressType pays peg-outs to legacy, SegWit and Taproot
// addresses; the destination survives the BVMO tag and the payout pays it.
func TestPayoutToEveryAddressType(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	for i, kind := range []byte{destP2PKH, destP2SH, destP2WPKH, destP2WSH, destP2TR} {
		program := make([]byte, programSize(kind))
		program[0] = byte(i + 1)
		dest, err := newDestination(kind, program)
		require.NoError(err)

		addr, err := dest.address(&chaincfg.MainNetParams)
		require.NoError(err)
		back, err := btcutil.DecodeAddress(addr.EncodeAddress(), &chaincfg.MainNetParams)
		require.NoError(err)
		fromAddr, err := destinationOf(back)
		require.NoError(err)
		require.Equal(dest, fromAddr, addr.EncodeAddress())
		fromScript, err := destinationOfScript(dest.pkScript())
		require.NoError(err)
		require.Equal(dest, fromScript)

		h.pegOut(5*btc, dest)
		require.NotEmpty(h.step(), addr.EncodeAddress())
		require.Equal(5*btc-h.feeOf(h.lastBTC()), paidTo(h.btc, dest), addr.EncodeAddress())
		h.btc.mine()
	}
	require.True(h.audit().solvent())
}

// TestPegAddressIsTheSameOnBothChains checks the peg on Bitcoin and the
// reserve on BTCVM are one P2WSH address.
func TestPegAddressIsTheSameOnBothChains(t *testing.T) {
	h := newHarness(t)
	h.b.btcParams = &chaincfg.MainNetParams
	vmParams, err := btcvmParams("mainnet")
	require.NoError(t, err)
	h.b.vmParams = vmParams
	peg, err := h.b.btcPegAddress()
	require.NoError(t, err)
	reserve, err := h.b.vmReserveAddress()
	require.NoError(t, err)
	require.Equal(t, peg.EncodeAddress(), reserve.EncodeAddress())
	require.Regexp(t, "^bc1q[a-z0-9]{58}$", peg.EncodeAddress())
}

func TestFeeRateStaysWithinPolicy(t *testing.T) {
	h := newHarness(t)
	h.b.minFeeRate, h.b.maxFeeRate = 2, 50
	for estimate, want := range map[int64]int64{1: 2, 7: 7, 500: 50} {
		h.b.feeRate = func() (int64, error) { return estimate, nil }
		require.Equal(t, want, h.b.currentFeeRate(), "estimate %d", estimate)
	}
}

// TestStuckPayoutIsReplaced checks a payout left unconfirmed is replaced by
// one spending the same outputs at a higher fee rate, so only one can
// confirm, and the peg-out is still paid once.
func TestStuckPayoutIsReplaced(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	h.b.minFeeRate, h.b.maxFeeRate = 1, 100
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 100
	}
	rate := int64(5)
	h.b.feeRate = func() (int64, error) { return rate, nil }
	h.b.bumpAfter = time.Nanosecond

	alice, aliceOnBTC := h.user(1), h.user(2)
	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()
	h.pegOut(40*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	first := h.lastBTC()

	// The rate has not risen enough: nothing to do.
	rate = 6
	require.Empty(h.step())

	// Fees jump: the payout is replaced.
	rate = 20
	did := h.step()
	require.Contains(did, "replaced "+first.TxHash().String())
	second := h.lastBTC()
	require.NotEqual(first.TxHash(), second.TxHash())
	require.Len(second.TxIn, len(first.TxIn))
	for i := range first.TxIn {
		require.Equal(first.TxIn[i].PreviousOutPoint, second.TxIn[i].PreviousOutPoint, "same inputs")
	}
	require.Equal(int64(20), h.b.feeRateOf(second, h.spends(second)))
	require.Equal(40*btc-h.feeOf(second), paidTo(h.btc, aliceOnBTC), "paid once")

	// Once it confirms, nothing more happens.
	h.btc.mine()
	rate = 90
	require.Empty(h.step())
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegOuts)
}

// TestSignerRefusesBadReplacements checks the rules a signer applies to a
// second transaction for a payout that is already unconfirmed on Bitcoin.
func TestSignerRefusesBadReplacements(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range append([]*cosigner{{b: h.b}}, h.signers...) {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 100
	}
	h.b.feeRate = func() (int64, error) { return 5, nil }
	c := h.signers[0]

	alice, aliceOnBTC := h.user(1), h.user(2)
	h.deposit(100*btc, &alice, 6)
	h.deposit(100*btc, &alice, 6) // a second peg output to try instead
	require.NotEmpty(h.step())
	h.vm.mine()
	require.NotEmpty(h.step())
	h.vm.mine()
	req := h.pegOut(40*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	first := h.lastBTC()

	s, err := h.b.load()
	require.NoError(err)
	p, ok := findPegOut(s.pegOuts, req.TxHash())
	require.True(ok)
	why := action{Kind: actionPayout, PegOut: req.TxHash().String()}
	request := func(inputs []utxo, rate int64) signRequest {
		prev, _, err := s.pegSpends(inputs)
		require.NoError(err)
		tx, err := h.b.buildPayout(inputs, prev, p.value, p.dest, encodePayment(p.txid), rate)
		require.NoError(err)
		return signRequest{Chain: chainBitcoin, Action: why, Tx: encodeTx(tx), FeeRate: rate}
	}
	r, err := h.b.replaceable(s, first.TxHash())
	require.NoError(err)

	_, _, _, err = c.check(request(r.inputs, 5))
	require.ErrorContains(err, "must pay more", "no higher fee")

	var other []utxo
	for _, u := range s.lockedUTXOs {
		if u.outPoint != r.inputs[0].outPoint && u.confirmations > 0 {
			other = append(other, u)
		}
	}
	require.NotEmpty(other)
	_, _, _, err = c.check(request(other[:1], 30))
	// Different inputs could confirm alongside the first payment.
	require.ErrorContains(err, "not a confirmed peg output")

	_, _, _, err = c.check(request(r.inputs, 101))
	require.ErrorContains(err, "outside")

	_, _, _, err = c.check(request(r.inputs, 30))
	require.NoError(err, "same inputs, higher fee")

	// Once the first payment is in a block, nothing replaces it.
	h.btc.mine()
	s, err = h.b.load()
	require.NoError(err)
	_, _, _, err = c.check(request(r.inputs, 40))
	require.ErrorContains(err, "already done")
}

// TestSignerRefusesNeedlessInputs checks a coordinator can't spend a
// payout on fees by adding peg outputs it doesn't need.
func TestSignerRefusesNeedlessInputs(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 50
	}
	alice, aliceOnBTC := h.user(1), h.user(2)
	for i := 0; i < 3; i++ {
		h.deposit(10*btc, &alice, 6)
		require.NotEmpty(h.step())
		h.vm.mine()
	}
	req := h.pegOut(5*btc, aliceOnBTC)
	s, err := h.b.load()
	require.NoError(err)
	p, ok := findPegOut(s.pegOuts, req.TxHash())
	require.True(ok)
	build := func(inputs []utxo) signRequest {
		prev, _, err := s.pegSpends(inputs)
		require.NoError(err)
		tx := wire.NewMsgTx(2)
		for _, u := range inputs {
			in := wire.NewTxIn(&u.outPoint, nil, nil)
			in.Sequence = wire.MaxTxInSequenceNum - 2
			tx.AddTxIn(in)
		}
		// What buildPayout would make, were it not to refuse.
		var total int64
		for _, pr := range prev {
			total += pr.value
		}
		tx.AddTxOut(wire.NewTxOut(p.value-50*400, p.dest.pkScript()))
		tx.AddTxOut(wire.NewTxOut(total-p.value, h.b.signers.pkScript()))
		tx.AddTxOut(nullData(encodePayment(p.txid)))
		return signRequest{Chain: chainBitcoin, Action: action{Kind: actionPayout, PegOut: p.txid.String()}, Tx: encodeTx(tx), FeeRate: 50}
	}
	var confirmed []utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 {
			confirmed = append(confirmed, u)
		}
	}
	require.Len(confirmed, 3)
	// The anchor goes first, as every payout's first input must be.
	sort.SliceStable(confirmed, func(i, j int) bool { return confirmed[i].outPoint == s.pegAnchor.outPoint })
	_, _, _, err = h.signers[0].check(build(confirmed))
	require.ErrorContains(err, "does not need")

	// The honest payout at the same rate is signed.
	_, err = h.b.buildPayout(confirmed[:1], mustSpends(t, s, confirmed[:1]), p.value, p.dest, encodePayment(p.txid), 50)
	require.NoError(err)
}

func mustSpends(t *testing.T, s *pegState, inputs []utxo) []spent {
	prev, _, err := s.pegSpends(inputs)
	require.NoError(t, err)
	return prev
}

// TestSignerNeverRefundsACreditedDeposit: after a policy change makes a
// credited deposit look held (here, a higher minimum), a refund of it is
// still refused.
func TestSignerNeverRefundsACreditedDeposit(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	alice := h.user(1)
	dep := h.deposit(3*btc, &alice, 6)
	h.deposit(50*btc, &alice, 6) // something to pay a refund from
	require.NotEmpty(h.step())
	h.vm.mine()
	require.NotEmpty(h.step())
	h.vm.mine()

	op := wire.OutPoint{Hash: dep.TxHash()}
	c := h.signers[0]
	c.b.minDeposit = 5 * btc
	s, err := c.b.load()
	require.NoError(err)
	_, held := findDeposit(s.held, op)
	require.True(held, "the credited deposit now looks held")

	back := h.user(9)
	req := signRequest{Chain: chainBitcoin, FeeRate: 10, Action: refundAction(op, back)}
	var confirmed []utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 && u.value >= 3*btc {
			confirmed = append(confirmed, u)
			break
		}
	}
	prev, _, err := s.pegSpends(confirmed)
	require.NoError(err)
	tx, err := h.b.buildPayout(confirmed, prev, 3*btc, back, encodeRefund(op), 10)
	require.NoError(err)
	req.Tx = encodeTx(tx)
	_, _, _, err = c.check(req)
	require.ErrorContains(err, "was credited")
}

// TestPayoutToADepositAddressIsCredited: a withdrawal paid to a personal
// deposit address is a deposit to it, credited again, not stranded.
func TestPayoutToADepositAddressIsCredited(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)
	_, err := h.b.registry.add(alice)
	require.NoError(err)
	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	depositAddr, err := h.b.signers.depositAddress(alice, h.b.btcParams)
	require.NoError(err)
	back, err := destinationOf(depositAddr)
	require.NoError(err)
	h.pegOut(40*btc, back)
	require.NotEmpty(h.step())
	for i := 0; i < 6; i++ {
		h.btc.mine()
	}
	require.NotEmpty(h.step(), "the payout is credited as a deposit")
	h.vm.mine()
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegIns)
	// The latest credit to Alice is the withdrawal, less the network fee
	// and the bridge fee.
	payout := h.btc.txs[len(h.btc.txs)-1].tx
	require.Equal(40*btc-h.feeOf(payout)-h.b.vmFee, paidTo(h.vm, alice))
	require.Equal(int64(100*btc-h.feeOf(payout)), a.Circulating)
}

// TestPegOutToThePegAddressIsRefused: it would look like change.
func TestPegOutToThePegAddressIsRefused(t *testing.T) {
	h := newHarness(t)
	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(t, h.step())
	h.vm.mine()
	h.pegOut(40*btc, h.b.signers.destination())
	require.Empty(t, h.step())
	require.Equal(t, int64(40*btc), h.audit().UnclaimedOnVM)
}

// TestOneStuckPayoutDoesNotBlockTheRest: a peg-out whose fee is too high
// to pay now waits, and the next one is still paid.
func TestOneStuckPayoutDoesNotBlockTheRest(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	h.b.minPegOut = 1000
	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	h.pegOut(2000, h.user(2)) // at 10 sat/vB the fee is more than half
	h.pegOut(btc, h.user(3))
	did, err := h.b.step()
	require.NoError(err)
	require.Contains(did, "paid")
	require.Equal(btc-h.feeOf(h.lastBTC()), paidTo(h.btc, h.user(3)))

	h.btc.mine()
	_, err = h.b.step()
	require.ErrorContains(err, "more than half", "the small one waits, and says why")
}

// TestUnconfirmedDepositIsNotRefunded: a held deposit is refunded only
// once it has the confirmations a credit of it would need.
func TestUnconfirmedDepositIsNotRefunded(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)
	h.deposit(50*btc, &alice, 6) // something to pay from
	require.NotEmpty(h.step())
	h.vm.mine()
	held := h.deposit(30*btc, nil, 0) // no destination: held
	op := wire.OutPoint{Hash: held.TxHash()}

	_, err := h.b.refund(op, h.user(9), false)
	require.ErrorContains(err, "0 of 6 confirmations")
	for i := 0; i < 6; i++ {
		h.btc.mine()
	}
	_, err = h.b.refund(op, h.user(9), false)
	require.NoError(err)
}

// TestEveryPayoutPaysThePeg: a payout whose inputs leave no change still
// pays pegDust back to the peg address, so every signer's wallet lists it.
func TestEveryPayoutPaysThePeg(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	h.b.maxDeposit = 50 * btc
	alice := h.user(1)
	// Over the cap: held. One block older than the other deposit, so it is
	// the peg's anchor, the coin a refund must spend first, and it covers
	// the refund exactly, leaving no change.
	held := h.deposit(60*btc, &alice, 7)
	h.deposit(10*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()
	_, err := h.b.refund(wire.OutPoint{Hash: held.TxHash()}, h.user(9), false)
	require.NoError(err)
	refund := h.lastBTC()
	require.Equal(int64(pegDust), h.toPeg(refund))
	require.Equal(60*btc-h.feeOf(refund)-pegDust, paidTo(h.btc, h.user(9)))
}

// TestPegSpendKnownByWitness: a signer that never saw a deposit still knows
// a payout spending it as a peg spend, from its witness script, and so
// knows the peg-out is paid.
func TestPegSpendKnownByWitness(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err := h.b.registry.add(alice)
	require.NoError(err)
	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()
	req := h.pegOut(40*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	payout := h.lastBTC()
	h.btc.mine()

	// A signer that never registered Alice's address: its registry is
	// empty, so it doesn't know the deposit output the payout spends.
	late := *h.b
	late.registry = &depositRegistry{path: t.TempDir() + "/deposits.json"}
	s, err := late.load()
	require.NoError(err)
	require.Equal(payout.TxHash(), s.paid[req.TxHash()], "the payout is known by its witness")
	require.True(late.signers.spendsPeg(payout))
	d, ok := late.signers.pegWitness(payout.TxIn[0].Witness[len(payout.TxIn[0].Witness)-1])
	require.True(ok)
	require.Equal(alice, *d)
}

// TestRefundWaitsForTheBridge: a refund can't take the lock the running
// bridge holds, so the two can't credit and refund one deposit.
func TestRefundWaitsForTheBridge(t *testing.T) {
	signersPath := t.TempDir() + "/signers.json"
	running, err := lockBridge(signersPath)
	require.NoError(t, err)
	_, err = lockBridge(signersPath)
	require.ErrorIs(t, err, errBridgeRunning)
	require.NoError(t, running.Close())
	again, err := lockBridge(signersPath)
	require.NoError(t, err, "free once the bridge stops")
	again.Close()
}

// TestSigningLogRefusesAfterAConfirmedSignature: once a transaction this
// signer signed for an action is in a block, it refuses to sign another,
// even when its view says the old inputs are gone (spent, so "dead").
func TestSigningLogRefusesAfterAConfirmedSignature(t *testing.T) {
	require := require.New(t)
	l, err := openSigningLog(t.TempDir() + "/signing-log.json")
	require.NoError(err)
	first := wire.NewMsgTx(3)
	first.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 1}, nil, nil))
	require.NoError(l.record("payout:x", first, 100))

	second := wire.NewMsgTx(3)
	second.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 2}, nil, nil))
	noneUnspent := map[wire.OutPoint]bool{}
	require.NoError(l.permit("payout:x", second, noneUnspent, func(string) bool { return false }),
		"the old payment's inputs are gone and it isn't confirmed: it can't confirm")
	require.ErrorContains(l.permit("payout:x", second, noneUnspent, func(txid string) bool { return txid == first.TxHash().String() }),
		"in a block")
}

// TestSignersCheckKeyFiles checks separate signers' keys one file at a time
// against the public set, as a restore check does: each must be in the set,
// and no two the same.
func TestSignersCheckKeyFiles(t *testing.T) {
	require := require.New(t)
	full, err := newSignerSet(2, 3)
	require.NoError(err)
	dir := t.TempDir()
	setPath := filepath.Join(dir, "signers.json")
	require.NoError(full.publicCopy().write(setPath))
	keyFile := func(name, hexKey string) string {
		path := filepath.Join(dir, name)
		require.NoError(os.WriteFile(path, []byte(hexKey+"\n"), 0o600))
		return path
	}
	a := keyFile("a.key", full.PrivateKeys[0])
	b := keyFile("b.key", full.PrivateKeys[1])
	again := keyFile("again.key", full.PrivateKeys[0])
	stranger, err := newSignerSet(1, 1)
	require.NoError(err)
	other := keyFile("other.key", stranger.PrivateKeys[0])

	check := func(files ...string) error {
		args := []string{"-signers", setPath}
		for _, f := range files {
			args = append(args, "-key-file", f)
		}
		return cmdSignersCheck(args)
	}
	require.NoError(check(a, b))
	require.ErrorContains(check(a, again), "same key")
	require.ErrorContains(check(a, other), "not one of the set's public keys")
}

// TestPayoutPrefersCoinLeavingPegChange: a payout exactly the size of a
// peg coin would leave no change, and the 330 sats every payout returns to
// the peg would come out of the user's payout. A larger coin that leaves
// that change is preferred; the exact one is used only if none does.
func TestPayoutPrefersCoinLeavingPegChange(t *testing.T) {
	require := require.New(t)
	coin := func(v int64, n byte) utxo {
		return utxo{outPoint: wire.OutPoint{Hash: [32]byte{n}}, value: v}
	}
	exact, larger, huge := coin(10_000, 1), coin(23_828, 2), coin(1_000_000, 3)

	picked, err := selectForPayout([]utxo{exact, larger, huge}, 10_000)
	require.NoError(err)
	require.Equal([]utxo{larger}, picked, "the smallest coin leaving at least pegDust of change")

	picked, err = selectForPayout([]utxo{exact}, 10_000)
	require.NoError(err)
	require.Equal([]utxo{exact}, picked, "the exact coin when nothing else covers it")

	picked, err = selectForPayout([]utxo{coin(10_200, 4), exact}, 10_000)
	require.NoError(err)
	require.Equal(int64(10_000), picked[0].value, "no coin leaves pegDust: the smallest that covers it")
}
