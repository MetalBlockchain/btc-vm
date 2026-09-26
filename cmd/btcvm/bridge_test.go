package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
	"github.com/MetalBlockchain/btcvm/btcd/txscript"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// fakeChain is an in-memory ledger: it checks that inputs exist and are
// unspent, but not signatures.
type fakeChain struct {
	txs []*chainTx
}

func (c *fakeChain) output(op wire.OutPoint) (*wire.TxOut, bool) {
	for _, t := range c.txs {
		if t.tx.TxHash() == op.Hash && int(op.Index) < len(t.tx.TxOut) {
			return t.tx.TxOut[op.Index], true
		}
	}
	return nil, false
}

func (c *fakeChain) spent(op wire.OutPoint) bool {
	for _, t := range c.txs {
		for _, in := range t.tx.TxIn {
			if in.PreviousOutPoint == op {
				return true
			}
		}
	}
	return false
}

func (c *fakeChain) txsFor(addresses []btcutil.Address) ([]chainTx, error) {
	scripts := scriptSet(addresses)
	var out []chainTx
	for _, t := range c.txs {
		match := false
		for _, o := range t.tx.TxOut {
			match = match || scripts[string(o.PkScript)]
		}
		for _, in := range t.tx.TxIn {
			if prev, ok := c.output(in.PreviousOutPoint); ok && scripts[string(prev.PkScript)] {
				match = true
			}
		}
		if match {
			out = append(out, *t)
		}
	}
	return out, nil
}

func (c *fakeChain) unspent(addresses []btcutil.Address, minConf int64) ([]utxo, error) {
	scripts := scriptSet(addresses)
	var out []utxo
	for _, t := range c.txs {
		if t.confirmations < minConf {
			continue
		}
		hash := t.tx.TxHash()
		for i, o := range t.tx.TxOut {
			op := wire.OutPoint{Hash: hash, Index: uint32(i)}
			if scripts[string(o.PkScript)] && !c.spent(op) {
				out = append(out, utxo{outPoint: op, value: o.Value, pkScript: o.PkScript, confirmations: t.confirmations})
			}
		}
	}
	return out, nil
}

// prevOut is prevOutSource for the fake chain.
func (c *fakeChain) prevOut(op wire.OutPoint) (*wire.TxOut, bool, error) {
	out, ok := c.output(op)
	if !ok {
		return nil, false, fmt.Errorf("no output %v", op)
	}
	confirmed := false
	for _, t := range c.txs {
		if t.tx.TxHash() == op.Hash {
			confirmed = t.confirmations > 0
		}
		for _, in := range t.tx.TxIn {
			if in.PreviousOutPoint == op && t.confirmations > 0 {
				return out, false, nil // spent in a block
			}
		}
	}
	return out, confirmed, nil
}

// replace drops unconfirmed transactions that spend any of tx's inputs, as
// a node does when a replacement (BIP125) is accepted.
func (c *fakeChain) replace(tx *wire.MsgTx) {
	kept := c.txs[:0]
	for _, t := range c.txs {
		conflicts := false
		for _, in := range t.tx.TxIn {
			for _, mine := range tx.TxIn {
				conflicts = conflicts || in.PreviousOutPoint == mine.PreviousOutPoint
			}
		}
		if !conflicts || t.confirmations > 0 {
			kept = append(kept, t)
		}
	}
	c.txs = kept
}

func (c *fakeChain) send(tx *wire.MsgTx) (chainhash.Hash, error) {
	c.replace(tx)
	var in, out int64
	for i, txIn := range tx.TxIn {
		prev, ok := c.output(txIn.PreviousOutPoint)
		if !ok || c.spent(txIn.PreviousOutPoint) {
			return chainhash.Hash{}, fmt.Errorf("input %v missing or spent", txIn.PreviousOutPoint)
		}
		in += prev.Value
		// Run the real script engine, so signing bugs fail the tests.
		vm, err := txscript.NewEngine(prev.PkScript, tx, i, txscript.StandardVerifyFlags,
			nil, nil, prev.Value, txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value))
		if err != nil {
			return chainhash.Hash{}, err
		}
		if err := vm.Execute(); err != nil {
			return chainhash.Hash{}, fmt.Errorf("input %d does not verify: %w", i, err)
		}
	}
	for _, o := range tx.TxOut {
		out += o.Value
	}
	if out > in {
		return chainhash.Hash{}, errors.New("outputs exceed inputs")
	}
	c.txs = append(c.txs, &chainTx{tx: tx, time: time.Now().Unix()})
	return tx.TxHash(), nil
}

// confirmed is confirmer for the fake chain.
func (c *fakeChain) confirmed(txid chainhash.Hash) (bool, error) {
	for _, t := range c.txs {
		if t.tx.TxHash() == txid {
			return t.confirmations > 0, nil
		}
	}
	return false, nil
}

// add puts tx on the chain with the given confirmations, without checks.
func (c *fakeChain) add(tx *wire.MsgTx, confirmations int64) {
	c.txs = append(c.txs, &chainTx{tx: tx, confirmations: confirmations})
}

func (c *fakeChain) mine() {
	for _, t := range c.txs {
		t.confirmations++
	}
}

type harness struct {
	t        *testing.T
	b        *bridge
	vm, btc  *fakeChain
	nextCoin uint32
}

const btc = satPerBTC

func newHarness(t *testing.T) *harness {
	signers, err := newSignerSet(2, 3)
	require.NoError(t, err)
	h := &harness{t: t, vm: &fakeChain{}, btc: &fakeChain{}}
	h.b = &bridge{
		signers: signers, vm: h.vm, btc: h.btc,
		vmParams: &chaincfg.TestNet3Params, btcParams: &chaincfg.RegressionNetParams,
		depositConfirmations: 6,
		vmFee:                btc / 100,
		minFeeRate:           10,
		maxFeeRate:           10,
		minDeposit:           btc,
		minPegOut:            2 * btc,
		logf:                 t.Logf,
	}
	h.b.registry = &depositRegistry{path: t.TempDir() + "/deposits.json"}
	var err2 error
	h.b.vmParams, err2 = btcvmParams("testnet")
	require.NoError(t, err2)

	// The consensus-created reserve.
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{1}, nil))
	coinbase.AddTxOut(wire.NewTxOut(20_999_000*btc, signers.pkScript()))
	h.vm.add(coinbase, 1)
	return h
}

// coin returns a fresh funding outpoint from nowhere, for user payments the
// fake chain does not check.
func (h *harness) coin() *wire.OutPoint {
	h.nextCoin++
	return wire.NewOutPoint(&chainhash.Hash{0xff, byte(h.nextCoin)}, 0)
}

func (h *harness) user(b byte) destination {
	var d destination
	d.hash[0] = b
	return d
}

// deposit makes a Bitcoin deposit to the peg, tagged for dest if non-nil.
func (h *harness) deposit(value int64, dest *destination, confirmations int64) *wire.MsgTx {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
	tx.AddTxOut(wire.NewTxOut(value, h.b.signers.pkScript()))
	if dest != nil {
		tx.AddTxOut(nullData(encodeDestination(tagDeposit, *dest)))
	}
	h.btc.add(tx, confirmations)
	return tx
}

// pegOut makes a BTCVM payment to the reserve asking for dest.
func (h *harness) pegOut(value int64, dest destination) *wire.MsgTx {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
	tx.AddTxOut(wire.NewTxOut(value, h.b.signers.pkScript()))
	tx.AddTxOut(nullData(encodeDestination(tagPegOut, dest)))
	h.vm.add(tx, 1)
	return tx
}

// toPeg is what tx pays back to the peg address: change, topped up to
// pegDust when the payout would otherwise leave none.
func (h *harness) toPeg(tx *wire.MsgTx) int64 {
	var v int64
	for _, out := range tx.TxOut {
		if bytes.Equal(out.PkScript, h.b.signers.pkScript()) {
			v += out.Value
		}
	}
	return v
}

// lastBTC is the latest transaction on Bitcoin.
func (h *harness) lastBTC() *wire.MsgTx { return h.btc.txs[len(h.btc.txs)-1].tx }

// feeOf is the network fee tx pays, from the outputs it spends.
func (h *harness) feeOf(tx *wire.MsgTx) int64 {
	var fee int64
	for _, in := range tx.TxIn {
		prev, ok := h.btc.output(in.PreviousOutPoint)
		require.True(h.t, ok)
		fee += prev.Value
	}
	for _, out := range tx.TxOut {
		fee -= out.Value
	}
	return fee
}

// spends describes the peg outputs tx spends.
func (h *harness) spends(tx *wire.MsgTx) []spent {
	s, err := h.b.load()
	require.NoError(h.t, err)
	var prev []spent
	for _, in := range tx.TxIn {
		out, ok := h.btc.output(in.PreviousOutPoint)
		require.True(h.t, ok)
		prev = append(prev, spent{script: s.redeemFor[string(out.PkScript)], value: out.Value})
	}
	return prev
}

func (h *harness) step() string {
	h.t.Helper()
	did, err := h.b.step()
	require.NoError(h.t, err)
	return did
}

func (h *harness) audit() audit {
	s, err := h.b.load()
	require.NoError(h.t, err)
	return h.b.audit(s)
}

// paidTo returns what the last transaction on c pays to dest.
func paidTo(c *fakeChain, dest destination) int64 {
	var total int64
	for _, o := range c.txs[len(c.txs)-1].tx.TxOut {
		if bytes.Equal(o.PkScript, dest.pkScript()) {
			total += o.Value
		}
	}
	return total
}

func TestPegInCreditsOnceAfterConfirmations(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)

	h.deposit(100*btc, &alice, 5)
	require.Empty(h.step(), "credited before 6 confirmations")

	h.btc.mine()
	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))

	// While the release is in the mempool, and after it is accepted,
	// the deposit is not credited again.
	require.Empty(h.step())
	h.vm.mine()
	require.Empty(h.step())

	a := h.audit()
	require.True(a.solvent())
	require.Equal(int64(100*btc), a.Circulating)
	require.Equal(int64(100*btc), a.Locked)
	require.Zero(a.PendingPegIns)
	require.Zero(a.Surplus)
}

func TestSpoofedReleaseTagIsIgnored(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)
	dep := h.deposit(100*btc, &alice, 6)

	// Anyone can pay the reserve with a release tag; it must not count as
	// crediting the deposit.
	spoof := wire.NewMsgTx(1)
	spoof.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
	spoof.AddTxOut(wire.NewTxOut(btc, h.b.signers.pkScript()))
	spoof.AddTxOut(nullData(encodeRelease(wire.OutPoint{Hash: dep.TxHash(), Index: 0})))
	h.vm.add(spoof, 1)

	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))
}

func TestRoundTrip(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice, aliceOnBTC := h.user(1), h.user(2)

	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	req := h.pegOut(40*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	payment := h.btc.txs[len(h.btc.txs)-1].tx
	require.Equal(40*btc-h.feeOf(payment), paidTo(h.btc, aliceOnBTC), "40 BTC less the network fee")
	require.Equal(int64(10), h.b.feeRateOf(payment, h.spends(payment)), "at the policy's fee rate")
	paidFor, ok := parsePayment(payment)
	require.True(ok)
	require.Equal(req.TxHash(), paidFor)

	// Paid once, even before the payment confirms.
	require.Empty(h.step())
	h.btc.mine()
	require.Empty(h.step())

	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Equal(int64(60*btc), a.Circulating)
	require.Equal(int64(60*btc), a.Locked)
	require.Zero(a.Surplus)
}

func TestUntaggedDepositsAreNotCredited(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice := h.user(1)

	h.deposit(100*btc, nil, 6)  // no destination
	h.deposit(btc/2, &alice, 6) // below the minimum
	require.Empty(h.step())

	a := h.audit()
	require.True(a.solvent())
	require.Zero(a.Circulating)
	require.Equal(int64(100*btc+btc/2), a.UnclaimedOnBTC)
	require.Equal(a.UnclaimedOnBTC, a.Surplus)
}

func TestBridgeHaltsWhenInsolvent(t *testing.T) {
	h := newHarness(t)
	alice := h.user(1)

	// Reserve released with nothing locked on Bitcoin, as if a signer key
	// were compromised.
	reserve, err := h.vm.unspent([]btcutil.Address{mustAddr(h.b.vmReserveAddress())}, 1)
	require.NoError(t, err)
	theft := wire.NewMsgTx(1)
	theft.AddTxIn(wire.NewTxIn(&reserve[0].outPoint, nil, nil))
	theft.AddTxOut(wire.NewTxOut(50*btc, alice.pkScript()))
	theft.AddTxOut(wire.NewTxOut(reserve[0].value-50*btc, h.b.signers.pkScript()))
	h.vm.add(theft, 1)
	h.deposit(10*btc, &alice, 6)

	_, err = h.b.step()
	require.ErrorIs(t, err, errInsolvent)

	// An unconfirmed payment into the peg, which its sender could still
	// double-spend, does not make the bridge solvent again.
	h.deposit(60*btc, nil, 0)
	_, err = h.b.step()
	require.ErrorIs(t, err, errInsolvent)
}

func mustAddr(a btcutil.Address, err error) btcutil.Address {
	if err != nil {
		panic(err)
	}
	return a
}

func TestTagsRoundTrip(t *testing.T) {
	require := require.New(t)
	d := destination{kind: destP2SH}
	d.hash[19] = 9

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(nullData(encodeDestination(tagPegOut, d)))
	got, ok := parseDestinationTag(tx, tagPegOut)
	require.True(ok)
	require.Equal(d, got)
	_, ok = parseDestinationTag(tx, tagDeposit)
	require.False(ok, "wrong tag")

	// Two OP_RETURNs are ambiguous and ignored.
	tx.AddTxOut(nullData(encodeDestination(tagPegOut, d)))
	_, ok = parseDestinationTag(tx, tagPegOut)
	require.False(ok)
}

func TestParseBTC(t *testing.T) {
	for in, want := range map[string]int64{
		"1": btc, "0.00000001": 1, "123.45": 12345 * btc / 100, "21000000": 21_000_000 * btc,
	} {
		got, err := parseBTC(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
		require.Equal(t, in, trimZeros(formatBTC(got)), in)
	}
	for _, bad := range []string{"", "1.2.3", "-1", "abc", "21000001"} {
		_, err := parseBTC(bad)
		require.Error(t, err, bad)
	}
}

func trimZeros(s string) string {
	s = string(bytes.TrimRight([]byte(s), "0"))
	return string(bytes.TrimSuffix([]byte(s), []byte(".")))
}

// personalDeposit pays value to dest's personal deposit address, with no
// OP_RETURN, as any Bitcoin wallet would.
func (h *harness) personalDeposit(value int64, dest destination, confirmations int64) *wire.MsgTx {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
	tx.AddTxOut(wire.NewTxOut(value, p2wshScript(h.b.signers.depositRedeemScript(dest))))
	h.btc.add(tx, confirmations)
	return tx
}

func TestPersonalDepositAddress(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice, bob := h.user(1), h.user(2)

	// Each destination gets its own address, distinct from the peg address.
	aliceAddr, err := h.b.signers.depositAddress(alice, h.b.btcParams)
	require.NoError(err)
	bobAddr, err := h.b.signers.depositAddress(bob, h.b.btcParams)
	require.NoError(err)
	pegAddr, _ := h.b.btcPegAddress()
	require.NotEqual(aliceAddr.EncodeAddress(), bobAddr.EncodeAddress())
	require.NotEqual(pegAddr.EncodeAddress(), aliceAddr.EncodeAddress())

	// Unregistered, the bridge does not watch it.
	h.personalDeposit(100*btc, alice, 6)
	require.Empty(h.step())

	added, err := h.b.registry.add(alice)
	require.NoError(err)
	require.True(added)
	added, err = h.b.registry.add(alice)
	require.NoError(err)
	require.False(added, "registering twice is a no-op")

	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))
	h.vm.mine()
	require.Empty(h.step())
}

// TestPegOutSpendsPersonalDeposit checks that the signers can spend a
// personal deposit output: fakeChain runs the script engine on it.
func TestPegOutSpendsPersonalDeposit(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err := h.b.registry.add(alice)
	require.NoError(err)

	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	h.pegOut(60*btc, aliceOnBTC)
	did, err := h.b.step()
	require.NoError(err)
	require.NotEmpty(did)
	require.Equal(60*btc-h.feeOf(h.btc.txs[len(h.btc.txs)-1].tx), paidTo(h.btc, aliceOnBTC))

	h.btc.mine()
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Equal(int64(40*btc), a.Circulating)
	require.Equal(int64(40*btc), a.Locked)
}

func TestDepositCaps(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	h.b.maxDeposit = 100 * btc
	h.b.maxCirculating = 150 * btc
	alice := h.user(1)

	// Over the per-deposit cap: never credited, held on Bitcoin.
	h.deposit(101*btc, &alice, 6)
	require.Empty(h.step())
	a := h.audit()
	require.Equal(int64(101*btc), a.UnclaimedOnBTC)

	// Within both caps: credited.
	h.deposit(100*btc, &alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()

	// Would take circulating to 180 BTC, past the 150 cap: waits.
	h.deposit(80*btc, &alice, 6)
	require.Empty(h.step())
	a = h.audit()
	require.Equal(int64(100*btc), a.Circulating)
	require.Equal(int64(80*btc), a.PendingPegIns)
	require.True(a.solvent())

	// Raising the cap releases it.
	h.b.maxCirculating = 200 * btc
	require.NotEmpty(h.step())
}

func TestRefundHeldDeposit(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	h.b.maxDeposit = 100 * btc
	alice, aliceOnBTC := h.user(1), h.user(2)

	// Two deposits so the peg has a confirmed output to pay from, one of
	// them over the cap. The first is a block older, so it is the peg's
	// anchor, which the refund spends first.
	h.deposit(50*btc, &alice, 7)
	require.NotEmpty(h.step())
	h.vm.mine()
	over := h.deposit(150*btc, &alice, 6)
	op := wire.OutPoint{Hash: over.TxHash(), Index: 0}
	require.Empty(h.step())
	require.Equal(int64(150*btc), h.audit().UnclaimedOnBTC)

	_, err := h.b.refund(op, aliceOnBTC, false)
	require.NoError(err)
	refundTx := h.btc.txs[len(h.btc.txs)-1].tx
	// It spends the 50 BTC anchor and the 150 BTC deposit: 150 BTC less the
	// network fee, and 50 BTC change back to the peg.
	require.Equal(150*btc-h.feeOf(refundTx), paidTo(h.btc, aliceOnBTC))
	require.Equal(int64(50*btc), h.toPeg(refundTx))
	refunded, ok := parseRefund(refundTx)
	require.True(ok)
	require.Equal(op, refunded)

	// Settled: no longer held, never credited, and cannot be refunded again.
	h.btc.mine()
	a := h.audit()
	require.Zero(a.UnclaimedOnBTC)
	require.True(a.solvent(), "%+v", a)
	require.Equal(int64(50*btc), a.Circulating)
	require.Equal(int64(50*btc), a.Locked, "the refund's change stays in the peg")
	_, err = h.b.refund(op, aliceOnBTC, false)
	require.ErrorContains(err, "already refunded")

	h.b.maxDeposit = 0 // even with the cap lifted, it stays refunded
	require.Empty(h.step())
}

func TestRefundCreditableDepositNeedsForce(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	alice, aliceOnBTC := h.user(1), h.user(2)

	// Waiting for confirmations: the bridge would credit it later.
	dep := h.deposit(40*btc, &alice, 1)
	h.btc.add(func() *wire.MsgTx { // a confirmed peg output to pay from
		tx := wire.NewMsgTx(1)
		tx.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
		tx.AddTxOut(wire.NewTxOut(100*btc, h.b.signers.pkScript()))
		return tx
	}(), 6)
	op := wire.OutPoint{Hash: dep.TxHash(), Index: 0}

	_, err := h.b.refund(op, aliceOnBTC, false)
	require.ErrorIs(err, errCreditable)

	_, err = h.b.refund(op, aliceOnBTC, true)
	require.NoError(err)
	for i := 0; i < 6; i++ {
		h.btc.mine()
	}
	require.Empty(h.step(), "a refunded deposit is never credited")

	_, err = h.b.refund(wire.OutPoint{Index: 9}, aliceOnBTC, false)
	require.ErrorIs(err, errNotRefundable)
}
