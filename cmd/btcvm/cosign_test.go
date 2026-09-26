package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// cosignHarness is a keyless coordinator and three separate signers, each
// with its own key, registry and log, reading the same fake chains.
type cosignHarness struct {
	*harness
	signers []*cosigner
	servers []*httptest.Server
}

func publicOnly(t *testing.T, s *signerSet) *signerSet {
	pub := &signerSet{Required: s.Required, PublicKeys: s.PublicKeys}
	require.NoError(t, pub.load())
	return pub
}

func newCosignHarness(t *testing.T) *cosignHarness {
	h := &cosignHarness{harness: newHarness(t)}
	full := h.b.signers
	h.b.signers = publicOnly(t, full)
	for i, key := range full.privKeys {
		dir := t.TempDir()
		own := *h.b // same policy and chains
		own.signers = publicOnly(t, full)
		own.cosigners = nil
		own.registry = &depositRegistry{path: filepath.Join(dir, "deposits.json")}
		log, err := createSigningLog(filepath.Join(dir, "signing-log.json"))
		require.NoError(t, err)
		c := &cosigner{b: &own, key: key, log: log, token: "token-" + string(rune('a'+i))}
		srv := httptest.NewServer(c.handler())
		t.Cleanup(srv.Close)
		h.signers = append(h.signers, c)
		h.servers = append(h.servers, srv)
		h.b.cosigners = append(h.b.cosigners, &remoteSigner{URL: srv.URL, Token: c.token})
	}
	return h
}

func TestActionKeyIsCanonical(t *testing.T) {
	require := require.New(t)
	op := wire.OutPoint{Hash: chainhash.Hash{0xab}, Index: 0}

	releaseKey, err := (action{Kind: actionRelease, Deposit: op.String()}).key()
	require.NoError(err)
	aliasKey, err := (action{Kind: actionRelease, Deposit: op.Hash.String() + ":00"}).key()
	require.NoError(err)
	require.Equal(releaseKey, aliasKey)

	payoutKey, err := (action{Kind: actionPayout, PegOut: op.Hash.String()}).key()
	require.NoError(err)
	aliasKey, err = (action{Kind: actionPayout, PegOut: strings.ToUpper(op.Hash.String())}).key()
	require.NoError(err)
	require.Equal(payoutKey, aliasKey)
}

func TestSigningLogMergesLegacyActionAliases(t *testing.T) {
	require := require.New(t)
	op := wire.OutPoint{Hash: chainhash.Hash{0xab}, Index: 0}
	canonical, err := (action{Kind: actionRelease, Deposit: op.String()}).key()
	require.NoError(err)
	legacyAlias := actionRelease + ":" + op.Hash.String() + ":00"
	path := filepath.Join(t.TempDir(), "signing-log.json")
	l := &signingLog{Actions: map[string]*loggedAction{
		canonical:   {Value: 100, First: 20, Txs: []loggedTx{{Txid: "first"}}},
		legacyAlias: {Value: 100, First: 10, Txs: []loggedTx{{Txid: "second"}}},
	}}
	raw, err := json.Marshal(l)
	require.NoError(err)
	require.NoError(os.WriteFile(path, raw, 0o600))

	reopened, err := openSigningLog(path)
	require.NoError(err)
	require.Len(reopened.Actions, 1)
	require.Equal(int64(10), reopened.Actions[canonical].First)
	require.Len(reopened.Actions[canonical].Txs, 2)
}

// releaseRequest is the proposal the coordinator would send to credit the
// first creditable deposit, spending inputs.
func (h *cosignHarness) releaseRequest(inputs []utxo) (signRequest, deposit) {
	h.t.Helper()
	s, err := h.b.load()
	require.NoError(h.t, err)
	require.NotEmpty(h.t, s.deposits)
	d := s.deposits[0]
	var total int64
	for _, u := range inputs {
		total += u.value
	}
	tx := h.b.buildRelease(inputs, total, d)
	return signRequest{
		Chain: chainBTCVM, Tx: encodeTx(tx),
		Action:   action{Kind: actionRelease, Deposit: d.outPoint.String()},
		Register: []string{encodeDest(d.dest)},
	}, d
}

func (h *cosignHarness) reserveUTXOs() []utxo {
	s, err := h.b.load()
	require.NoError(h.t, err)
	return s.reserveUTXOs
}

func TestSeparateSignersRoundTrip(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	require.Empty(h.b.signers.privKeys, "the coordinator holds no keys")
	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err := registerDeposit(h.b, alice)
	require.NoError(err)

	// fakeChain.send runs the script engine, so this proves the signers'
	// signatures satisfy the multisig.
	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))
	h.vm.mine()

	h.pegOut(60*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	require.Equal(60*btc-h.feeOf(h.lastBTC()), paidTo(h.btc, aliceOnBTC))
	h.btc.mine()
	require.Empty(h.step())

	a := h.audit()
	require.True(a.solvent(), "%+v", a)
}

func TestOneSignerDownStillSigns(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	h.servers[0].Close()
	alice := h.user(1)
	h.personalDeposit(100*btc, alice, 6)
	_, err := registerDeposit(h.b, alice)
	require.NoError(err)
	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))

	// With two down, nothing moves.
	h.vm.mine()
	h.servers[1].Close()
	h.pegOut(60*btc, h.user(2))
	_, err = h.b.step()
	require.ErrorContains(err, "1 of 2 signatures")
	require.Zero(paidTo(h.btc, h.user(2)))
}

func TestSignerRefusesBadProposals(t *testing.T) {
	h := newCosignHarness(t)
	c := h.signers[0]
	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	good, _ := h.releaseRequest(h.reserveUTXOs())

	_, _, _, err := c.check(good)
	require.NoError(t, err, "the honest proposal passes")

	tamper := func(edit func(tx *wire.MsgTx)) signRequest {
		tx, err := decodeTx(good.Tx)
		require.NoError(t, err)
		edit(tx)
		r := good
		r.Tx = encodeTx(tx)
		return r
	}
	for name, tc := range map[string]struct {
		req  signRequest
		want string
	}{
		"credit to someone else": {tamper(func(tx *wire.MsgTx) {
			tx.TxOut[0].PkScript = h.user(9).pkScript()
		}), "not the transaction this signer would build"},
		"credit more than the deposit": {tamper(func(tx *wire.MsgTx) {
			tx.TxOut[0].Value += 50 * btc
			tx.TxOut[1].Value -= 50 * btc
		}), "not the transaction this signer would build"},
		"extra output": {tamper(func(tx *wire.MsgTx) {
			tx.AddTxOut(wire.NewTxOut(btc, h.user(9).pkScript()))
		}), "not the transaction this signer would build"},
		"signed input": {tamper(func(tx *wire.MsgTx) {
			tx.TxIn[0].SignatureScript = []byte{1}
		}), "unsigned"},
		"spends a non-reserve output": {tamper(func(tx *wire.MsgTx) {
			tx.AddTxIn(wire.NewTxIn(h.coin(), nil, nil))
		}), "not a confirmed peg output"},
		"doesn't spend the anchor first": {tamper(func(tx *wire.MsgTx) {
			tx.TxIn[0].PreviousOutPoint = *h.coin()
		}), "the oldest confirmed coin"},
		"unknown deposit": {func() signRequest {
			r := good
			r.Action.Deposit = wire.OutPoint{Hash: chainhash.Hash{7}}.String()
			return r
		}(), "no creditable deposit"},
		"wrong chain": {func() signRequest {
			r := good
			r.Chain = chainBitcoin
			return r
		}(), "BTCVM transaction"},
		"unknown peg-out": {signRequest{
			Chain: chainBitcoin, Tx: good.Tx, FeeRate: 10,
			Action: action{Kind: actionPayout, PegOut: chainhash.Hash{8}.String()},
		}, "no final peg-out"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := c.check(tc.req)
			require.ErrorContains(t, err, tc.want)
		})
	}

	// Too few confirmations.
	bob := h.user(2)
	young := h.deposit(100*btc, &bob, 2)
	req, _ := h.releaseRequest(h.reserveUTXOs())
	req.Action.Deposit = wire.OutPoint{Hash: young.TxHash()}.String()
	_, _, _, err = c.check(req)
	require.ErrorContains(t, err, "2 of 6 confirmations")
}

func TestSignerWontDoubleSign(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	// A second reserve output, so two different releases are possible.
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{1}, wire.MaxPrevOutIndex), []byte{2}, nil))
	coinbase.AddTxOut(wire.NewTxOut(9_000_000_000*btc, h.b.signers.pkScript()))
	h.vm.add(coinbase, 1)

	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	reserve := h.reserveUTXOs()
	require.Len(reserve, 2)
	// The anchor (the oldest coin) first, as every release must spend it.
	loaded, err := h.b.load()
	require.NoError(err)
	if reserve[0].outPoint != loaded.reserveAnchor.outPoint {
		reserve[0], reserve[1] = reserve[1], reserve[0]
	}
	first, _ := h.releaseRequest(reserve[:1])
	second, _ := h.releaseRequest(reserve[1:])
	r := h.b.cosigners[0]

	sign := func(req signRequest) error {
		return r.post("/v1/sign", req, &signResponse{})
	}
	require.NoError(sign(first))
	// Could confirm alongside the first: refused. Every release must spend
	// the reserve's oldest coin first, so a release from other coins is
	// refused before the signing log is even consulted.
	require.ErrorContains(sign(second), "the oldest confirmed coin")
	// A different textual encoding of the same deposit is the same action.
	// The deposit output is vout 0, so appending a zero changes :0 to :00.
	aliased := second
	aliased.Action.Deposit += "0"
	require.ErrorContains(sign(aliased), "the oldest confirmed coin")
	// The same transaction again is fine.
	require.NoError(sign(first))

	// Once the first can no longer confirm (its input is spent by
	// something else), a replacement may be signed.
	spend := wire.NewMsgTx(1)
	spend.AddTxIn(wire.NewTxIn(&reserve[0].outPoint, nil, nil))
	spend.AddTxOut(wire.NewTxOut(reserve[0].value, h.b.signers.pkScript()))
	h.vm.add(spend, 1)
	loaded, err = h.b.load()
	require.NoError(err)
	second, _ = h.releaseRequest([]utxo{*loaded.reserveAnchor})
	require.NoError(sign(second))

	// The log survives a restart.
	reopened, err := openSigningLog(h.signers[0].log.path)
	require.NoError(err)
	require.Len(reopened.Actions, 1)
	for _, a := range reopened.Actions {
		require.Len(a.Txs, 3)
	}
}

func TestSignerRefundNeedsApproval(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	held := h.deposit(100*btc, nil, 6) // no destination: held for a refund
	op := wire.OutPoint{Hash: held.TxHash()}
	back := h.user(9)

	_, err := h.b.refund(op, back, false)
	require.ErrorContains(err, "approves no refunds")

	backAddr, err := back.address(h.b.btcParams)
	require.NoError(err)
	for _, c := range h.signers[:2] {
		path := filepath.Join(t.TempDir(), "approvals")
		require.NoError(os.WriteFile(path, []byte("# approved by the operator\n"+op.String()+" "+backAddr.EncodeAddress()+"\n"), 0o600))
		c.refundApprovals = path
	}
	// Approved to a different address: refused.
	_, err = h.b.refund(op, h.user(8), false)
	require.ErrorContains(err, "different address")

	_, err = h.b.refund(op, back, false)
	require.NoError(err)
	require.Equal(100*btc-h.feeOf(h.lastBTC())-h.toPeg(h.lastBTC()), paidTo(h.btc, back))
}

func TestSignerAuthAndDailyLimit(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	alice := h.user(1)
	h.deposit(100*btc, &alice, 6)
	req, _ := h.releaseRequest(h.reserveUTXOs())

	wrong := &remoteSigner{URL: h.servers[0].URL, Token: "nope"}
	require.ErrorContains(wrong.post("/v1/sign", req, nil), "unauthorized")

	for _, c := range h.signers {
		c.maxDaily = 50 * btc
	}
	_, err := h.b.step()
	require.ErrorContains(err, "daily limit")
	require.Zero(paidTo(h.vm, alice))

	for _, c := range h.signers {
		c.maxDaily = 500 * btc
	}
	require.NotEmpty(h.step())
	var status map[string]any
	require.NoError(h.b.cosigners[0].status(&status))
	require.Equal(hex.EncodeToString(h.signers[0].key.PubKey().SerializeCompressed()), status["publicKey"])
	require.Equal("100.00000000", status["signedToday"])
}

// TestColludingSignerCantDoublePay: the attack the anchor stops. A
// dishonest coordinator and one dishonest signer (B) have A and B sign a
// payout and keep it back, then ask C to sign the same payout again from a
// different coin, perhaps after a new deposit makes another coin the natural
// choice, or after showing C's node a decoy transaction spending the first
// coin. Neither honest signer would sign twice, so without the anchor both
// payouts could confirm. C must refuse anything that doesn't spend the
// oldest confirmed coin, which the kept-back payout already spends.
func TestColludingSignerCantDoublePay(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	for _, c := range h.signers {
		c.b.minFeeRate, c.b.maxFeeRate = 1, 50
	}
	alice := h.user(1)
	h.deposit(10*btc, &alice, 9) // the oldest: the peg's anchor
	h.deposit(10*btc, &alice, 8)
	for h.step() != "" {
		h.vm.mine()
	}
	req := h.pegOut(5*btc, h.user(2))

	s, err := h.b.load()
	require.NoError(err)
	p, ok := findPegOut(s.pegOuts, req.TxHash())
	require.True(ok)
	require.NotNil(s.pegAnchor)
	var other utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 && u.outPoint != s.pegAnchor.outPoint && u.value >= p.value {
			other = u
		}
	}
	require.NotZero(other.value)
	build := func(inputs []utxo) signRequest {
		prev, _, err := s.pegSpends(inputs)
		require.NoError(err)
		tx, err := h.b.buildPayout(inputs, prev, p.value, p.dest, encodePayment(p.txid), 10)
		require.NoError(err)
		return signRequest{Chain: chainBitcoin, Action: action{Kind: actionPayout, PegOut: p.txid.String()}, Tx: encodeTx(tx), FeeRate: 10}
	}
	sign := func(i int, r signRequest) error {
		return h.b.cosigners[i].post("/v1/sign", r, &signResponse{})
	}

	// A and B sign the payout from the anchor; it is kept back.
	kept := build([]utxo{*s.pegAnchor})
	require.NoError(sign(0, kept))
	require.NoError(sign(1, kept))

	// C is asked for the same payout from another coin: refused.
	require.ErrorContains(sign(2, build([]utxo{other})), "the oldest confirmed coin")

	// A new deposit arrives. The anchor is still the oldest coin, so C
	// still refuses.
	h.deposit(20*btc, &alice, 1)
	require.ErrorContains(sign(2, build([]utxo{other})), "the oldest confirmed coin")

	// C's node is shown a decoy spending the anchor, never mined. The
	// anchor comes from blocks alone, so C still refuses.
	decoy := wire.NewMsgTx(2)
	decoy.AddTxIn(wire.NewTxIn(&s.pegAnchor.outPoint, nil, nil))
	decoy.AddTxOut(wire.NewTxOut(s.pegAnchor.value-1000, h.b.signers.pkScript()))
	h.btc.add(decoy, 0)
	require.ErrorContains(sign(2, build([]utxo{other})), "the oldest confirmed coin")
}
