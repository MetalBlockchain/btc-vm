package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
)

// regtestNode is a private Bitcoin Core on regtest, for tests only. It
// enforces mainnet's relay policy (-acceptnonstdtxn=0), so what it accepts
// mainnet nodes relay too, and runs pruned without -txindex, as the
// bridge's node does.
type regtestNode struct {
	t        *testing.T
	bitcoind string
	args     []string
	cmd      *exec.Cmd
	settings settings
	funder   *rpcClient // a wallet holding mined coins
	node     *rpcClient
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startRegtest(t *testing.T, extra ...string) *regtestNode {
	bitcoind, err := exec.LookPath("bitcoind")
	if err != nil {
		t.Skip("bitcoind is not installed")
	}
	dir := t.TempDir()
	var secret [16]byte
	_, _ = rand.Read(secret[:])
	pass := hex.EncodeToString(secret[:])
	rpcPort := freePort(t)
	args := append([]string{"-regtest", "-datadir=" + dir, "-prune=550", "-acceptnonstdtxn=0",
		"-listen=0", fmt.Sprintf("-rpcport=%d", rpcPort), "-rpcuser=test", "-rpcpassword=" + pass,
		"-fallbackfee=0.0002", "-printtoconsole=0"}, extra...)
	n := &regtestNode{t: t, bitcoind: bitcoind, args: args}
	n.start()
	t.Cleanup(func() {
		_ = n.cmd.Process.Kill()
		_ = n.cmd.Wait()
	})

	n.settings = settings{
		btcRPC: fmt.Sprintf("http://127.0.0.1:%d", rpcPort), btcUser: "test", btcPass: pass,
		btcNet: "regtest", btcWallet: "btcvm", btcParams: &chaincfg.RegressionNetParams,
	}
	n.node = n.settings.btcWalletClient("")
	n.waitReady()
	require.NoError(t, n.node.callNamed(nil, "createwallet", map[string]any{"wallet_name": "funder"}))
	n.funder = n.settings.btcWalletClient("funder")
	n.mine(101) // mature coinbases to spend
	return n
}

func (n *regtestNode) start(extra ...string) {
	n.cmd = exec.Command(n.bitcoind, append(append([]string{}, n.args...), extra...)...)
	require.NoError(n.t, n.cmd.Start())
}

func (n *regtestNode) waitReady() {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := n.node.call(nil, "getblockchaininfo"); err == nil {
			return
		}
		require.True(n.t, time.Now().Before(deadline), "bitcoind did not start")
		time.Sleep(200 * time.Millisecond)
	}
}

// restart stops the node and starts it again with extra arguments,
// reloading the named wallets.
func (n *regtestNode) restart(wallets []string, extra ...string) {
	require.NoError(n.t, n.node.call(nil, "stop"))
	_ = n.cmd.Wait()
	n.start(extra...)
	n.waitReady()
	for _, w := range wallets {
		require.NoError(n.t, n.node.call(nil, "loadwallet", w))
	}
}

func (n *regtestNode) mine(blocks int) {
	var addr string
	require.NoError(n.t, n.funder.call(&addr, "getnewaddress"))
	require.NoError(n.t, n.node.call(nil, "generatetoaddress", blocks, addr))
}

func (n *regtestNode) newAddress() destination {
	var s string
	require.NoError(n.t, n.funder.call(&s, "getnewaddress"))
	addr, err := btcutil.DecodeAddress(s, &chaincfg.RegressionNetParams)
	require.NoError(n.t, err)
	d, err := destinationOf(addr)
	require.NoError(n.t, err)
	return d
}

func (n *regtestNode) inMempool(txid chainhash.Hash) bool {
	var ids []string
	require.NoError(n.t, n.node.call(&ids, "getrawmempool"))
	for _, id := range ids {
		if id == txid.String() {
			return true
		}
	}
	return false
}

// TestBridgeWithBitcoinCore runs a round trip against a real Bitcoin Core:
// a deposit to a personal P2WSH address is credited, a withdrawal is paid
// on Bitcoin, the stalled payout is replaced at a higher fee rate under
// Core's BIP125 rules, and the peg stays solvent. BTCVM is the in-memory
// fake; Bitcoin is real.
func TestBridgeWithBitcoinCore(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)

	h := newHarness(t)
	btcChain := &btcChain{rpc: n.settings.btcRPCClient()}
	require.NoError(btcChain.ensureWallet())
	require.NoError(btcChain.ensureWallet(), "loading an existing wallet")
	h.b.btc = btcChain
	h.b.btcParams = &chaincfg.RegressionNetParams
	h.b.minFeeRate, h.b.maxFeeRate = 1, 100
	rate := int64(2)
	h.b.feeRate = func() (int64, error) { return rate, nil }
	h.b.minDeposit, h.b.minPegOut = 10_000, 30_000
	require.NoError(watchPeg(h.b, false))

	// A deposit from an ordinary wallet to Alice's personal address.
	alice := h.user(1)
	depositAddr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	require.Regexp("^bcrt1q", depositAddr.EncodeAddress())
	var depositTxid string
	require.NoError(n.funder.call(&depositTxid, "sendtoaddress", depositAddr.EncodeAddress(), 0.5))
	require.Empty(h.step(), "unconfirmed: not credited")
	n.mine(6)
	require.NotEmpty(h.step())
	require.Equal(btc/2-h.b.vmFee, paidTo(h.vm, alice))
	h.vm.mine()

	// Withdraw to an address in the funder wallet.
	aliceOnBTC := n.newAddress()
	h.pegOut(btc/5, aliceOnBTC)
	did, err := h.b.step()
	require.NoError(err)
	require.Contains(did, "paid")
	s, err := h.b.load()
	require.NoError(err)
	require.Len(s.unconfirmed, 1)
	var first chainhash.Hash
	for id := range s.unconfirmed {
		first = id
	}
	require.True(n.inMempool(first), "Bitcoin Core accepted the payout")

	// Fees rise and the payout has waited: it is replaced.
	h.b.bumpAfter = time.Nanosecond
	rate = 12
	did, err = h.b.step()
	require.NoError(err)
	require.Contains(did, "replaced "+first.String())
	require.False(n.inMempool(first), "the first payout left the mempool")
	s, err = h.b.load()
	require.NoError(err)
	require.Len(s.unconfirmed, 1, "the replaced payout no longer counts: %v", s.unconfirmed)
	var second chainhash.Hash
	for id := range s.unconfirmed {
		second = id
	}
	require.NotEqual(first, second)
	require.True(n.inMempool(second))

	// Nothing more to do: paid once, and not bumped again at the same rate.
	require.Empty(h.step())
	n.mine(1)
	require.Empty(h.step())

	var received float64
	addr, err := aliceOnBTC.address(&chaincfg.RegressionNetParams)
	require.NoError(err)
	require.NoError(n.funder.call(&received, "getreceivedbyaddress", addr.EncodeAddress(), 1))
	s, err = h.b.load()
	require.NoError(err)
	require.InDelta(float64(s.paidAmount[h.vm.txs[len(h.vm.txs)-1].tx.TxHash()])/btc, received, 1e-9)
	require.Less(received, 0.2)
	require.Greater(received, 0.199)

	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegOuts)
	require.Equal(int64(btc/2-btc/5), a.Circulating)
}

// TestSeparateSignersWithBitcoinCore has three signers, each with its own
// Bitcoin Core wallet, sign a round trip for a coordinator holding no keys.
// The signers are not told of the deposit address until the release that
// needs it, so each must import the deposit it missed (importprunedfunds)
// from its own node.
func TestSeparateSignersWithBitcoinCore(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)

	h := newCosignHarness(t)
	wallet := func(name string) *btcChain {
		s := n.settings
		s.btcWallet = name
		c := &btcChain{rpc: s.btcRPCClient()}
		require.NoError(c.ensureWallet())
		return c
	}
	setup := func(b *bridge, c *btcChain) {
		b.btc, b.btcParams = c, &chaincfg.RegressionNetParams
		b.minFeeRate, b.maxFeeRate = 1, 100
		b.minDeposit, b.minPegOut = 10_000, 30_000
	}
	setup(h.b, wallet("btcvm"))
	h.b.feeRate = func() (int64, error) { return 3, nil }
	for i, c := range h.signers {
		setup(c.b, wallet(fmt.Sprintf("signer%d", i)))
		require.NoError(watchPeg(c.b, false))
	}
	require.NoError(watchPeg(h.b, false))

	// The coordinator registers Alice's address without telling the
	// signers, as if they were offline.
	cosigners := h.b.cosigners
	h.b.cosigners = nil
	alice := h.user(1)
	depositAddr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	h.b.cosigners = cosigners

	require.NoError(n.funder.call(nil, "sendtoaddress", depositAddr.EncodeAddress(), 0.25))
	n.mine(6)
	require.NotEmpty(h.step(), "signers caught up on the deposit and signed")
	require.Equal(btc/4-h.b.vmFee, paidTo(h.vm, alice))
	h.vm.mine()

	aliceOnBTC := n.newAddress()
	h.pegOut(btc/10, aliceOnBTC)
	did, err := h.b.step()
	require.NoError(err)
	require.Contains(did, "paid")
	n.mine(1)
	require.Empty(h.step())

	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegOuts)
	for _, c := range h.signers {
		s, err := c.b.load()
		require.NoError(err)
		require.Equal(int64(btc/4-btc/10), c.b.audit(s).Locked, "each signer sees the peg on its own node")
	}
}

// TestScanFindsOldCoins scans Bitcoin Core's UTXO set for addresses, as a
// wallet importing a wallet.dat does, and finds a coin paid to one before
// anything watched it.
func TestScanFindsOldCoins(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newHarness(t)
	h.b.btcParams = &chaincfg.RegressionNetParams
	srv := &server{b: h.b, scan: newScanner(n.settings.btcWalletClient(""))}

	var addr, txid string
	require.NoError(n.funder.call(&addr, "getnewaddress"))
	require.NoError(n.funder.call(&txid, "sendtoaddress", addr, 0.123))
	n.mine(1)

	req := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		return r
	}
	_, err := srv.btcScan(req("POST", "/api/btc/scan", `{"addresses":["not-an-address"]}`))
	require.Error(err)

	started, err := srv.btcScan(req("POST", "/api/btc/scan", fmt.Sprintf(`{"addresses":[%q]}`, addr)))
	require.NoError(err)
	id := started.(map[string]any)["id"].(string)

	var result map[string]any
	require.Eventually(func() bool {
		r := req("GET", "/api/btc/scan/"+id, "")
		r.SetPathValue("id", id)
		res, err := srv.btcScanStatus(r)
		require.NoError(err)
		result = res.(map[string]any)
		return result["status"] != "running"
	}, 30*time.Second, 100*time.Millisecond)
	require.Equal("done", result["status"], "%v", result)
	utxos := result["utxos"].([]map[string]any)
	var found bool
	for _, u := range utxos {
		if u["txid"] == txid {
			found = true
			require.Equal("12300000", u["value"])
		}
	}
	require.True(found, "%v", utxos)
}

// TestWalletLoadsOnceWhenStartedTogether: the bridge and web server start
// at the same moment, and both must come up with the wallet loaded.
func TestWalletLoadsOnceWhenStartedTogether(t *testing.T) {
	n := startRegtest(t)
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		go func() { errs <- (&btcChain{rpc: n.settings.btcRPCClient()}).ensureWallet() }()
	}
	for i := 0; i < 6; i++ {
		require.NoError(t, <-errs)
	}
}

// TestEvictedPayoutKeepsThePegSolvent: a payout that falls out of Bitcoin
// Core's mempool (here, a restart that drops the mempool and raises the
// minimum relay fee) must not make the audit report the peg insolvent,
// which would stop the bridge and signers bumping it; the bump then gets
// it paid.
func TestEvictedPayoutKeepsThePegSolvent(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newHarness(t)
	c := &btcChain{rpc: n.settings.btcRPCClient()}
	require.NoError(c.ensureWallet())
	h.b.btc, h.b.btcParams = c, &chaincfg.RegressionNetParams
	h.b.minFeeRate, h.b.maxFeeRate = 1, 100
	rate := int64(2)
	h.b.feeRate = func() (int64, error) { return rate, nil }
	h.b.minDeposit, h.b.minPegOut = 10_000, 30_000
	require.NoError(watchPeg(h.b, false))

	alice := h.user(1)
	depositAddr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	require.NoError(n.funder.call(nil, "sendtoaddress", depositAddr.EncodeAddress(), 0.3))
	n.mine(6)
	require.NotEmpty(h.step())
	h.vm.mine()
	h.pegOut(btc/10, n.newAddress())
	require.NotEmpty(h.step())
	before := h.audit()
	require.True(before.solvent(), "%+v", before)

	// The payout leaves the mempool.
	n.restart([]string{"btcvm", "funder"}, "-persistmempool=0", "-minrelaytxfee=0.00005")
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Equal(before.Locked, a.Locked)
	require.Equal(int64(btc/10), a.PendingPegOuts, "the evicted payout is still owed")

	// Fees rise and it has waited: the bridge bumps it, the node takes it,
	// and once it confirms nothing is owed.
	h.b.bumpAfter = time.Nanosecond
	rate = 20
	did, err := h.b.step()
	require.NoError(err)
	require.Contains(did, "replaced")
	n.mine(1)
	a = h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegOuts)
	require.Empty(h.step())
}

// TestLateSignerKnowsPayoutByWitness: a signer that was offline when a
// deposit address was registered, and never saw the deposit or took part in
// crediting and paying it, still refuses to pay the peg-out again once the
// payout is in a block: it knows the payout by its witness script, on a
// pruned node that can't look the deposit up.
func TestLateSignerKnowsPayoutByWitness(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newCosignHarness(t)
	wallet := func(name string) *btcChain {
		s := n.settings
		s.btcWallet = name
		c := &btcChain{rpc: s.btcRPCClient()}
		require.NoError(c.ensureWallet())
		return c
	}
	setup := func(b *bridge, c *btcChain) {
		b.btc, b.btcParams = c, &chaincfg.RegressionNetParams
		b.minFeeRate, b.maxFeeRate = 1, 100
		b.minDeposit, b.minPegOut = 10_000, 30_000
	}
	setup(h.b, wallet("btcvm"))
	h.b.feeRate = func() (int64, error) { return 3, nil }
	for i, c := range h.signers {
		setup(c.b, wallet(fmt.Sprintf("signer%d", i)))
		require.NoError(watchPeg(c.b, false))
	}
	require.NoError(watchPeg(h.b, false))

	// Signer 2 is offline throughout.
	all := h.b.cosigners
	h.b.cosigners = all[:2]
	alice := h.user(1)
	depositAddr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	require.NoError(n.funder.call(nil, "sendtoaddress", depositAddr.EncodeAddress(), 0.25))
	n.mine(6)
	require.NotEmpty(h.step())
	h.vm.mine()
	req := h.pegOut(btc/10, n.newAddress())
	require.NotEmpty(h.step())
	n.mine(1)

	// Signer 2 comes back and is asked to pay the same peg-out again, from
	// a different peg output (the change of the first payout).
	late := h.signers[2]
	s, err := late.b.load()
	require.NoError(err)
	payment, paid := s.paid[req.TxHash()]
	require.True(paid, "the late signer sees the payout")
	var other []utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 {
			other = append(other, u)
		}
	}
	require.NotEmpty(other)
	prev, _, err := s.pegSpends(other[:1])
	require.NoError(err)
	p, _ := findPegOut(s.pegOuts, req.TxHash())
	tx, err := h.b.buildPayout(other[:1], prev, p.value, p.dest, encodePayment(p.txid), 3)
	if err == nil {
		_, _, _, err = late.check(signRequest{Chain: chainBitcoin, FeeRate: 3, Tx: encodeTx(tx),
			Action: action{Kind: actionPayout, PegOut: req.TxHash().String()}})
	}
	require.ErrorContains(err, "already done in "+payment.String())
}

// TestSignerToldAboutEarlierDeposits reproduces the first mainnet deposits:
// with 2 of 3 signing, the third signer is never asked about the first
// deposit, so never watches its address. When a second deposit comes, it
// must still see the first one locked, or it counts less locked than
// circulating and refuses everything as insolvent.
func TestSignerToldAboutEarlierDeposits(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newCosignHarness(t)
	wallet := func(name string) *btcChain {
		s := n.settings
		s.btcWallet = name
		c := &btcChain{rpc: s.btcRPCClient()}
		require.NoError(c.ensureWallet())
		return c
	}
	setup := func(b *bridge, c *btcChain) {
		b.btc, b.btcParams = c, &chaincfg.RegressionNetParams
		b.minFeeRate, b.maxFeeRate = 1, 100
		b.minDeposit, b.minPegOut = 10_000, 30_000
	}
	setup(h.b, wallet("btcvm"))
	h.b.feeRate = func() (int64, error) { return 3, nil }
	for i, c := range h.signers {
		setup(c.b, wallet(fmt.Sprintf("signer%d", i)))
		require.NoError(watchPeg(c.b, false))
	}
	require.NoError(watchPeg(h.b, false))

	// The web server registers Alice's address; it can't reach the
	// signers. Signer 2 is not asked about her deposit.
	all := h.b.cosigners
	h.b.cosigners = nil
	alice := h.user(1)
	first, err := registerDeposit(h.b, alice)
	require.NoError(err)
	h.b.cosigners = all[:2]
	require.NoError(n.funder.call(nil, "sendtoaddress", first.EncodeAddress(), 0.25))
	n.mine(6)
	require.NotEmpty(h.step())
	h.vm.mine()

	// Bob deposits; now every signer is reachable.
	h.b.cosigners = nil
	bob := h.user(2)
	second, err := registerDeposit(h.b, bob)
	require.NoError(err)
	h.b.cosigners = all
	require.NoError(n.funder.call(nil, "sendtoaddress", second.EncodeAddress(), 0.1))
	n.mine(6)
	require.NotEmpty(h.step(), "Bob's deposit is credited")
	h.vm.mine()

	for i, c := range h.signers {
		s, err := c.b.load()
		require.NoError(err)
		a := c.b.audit(s)
		require.True(a.solvent(), "signer %d: %+v", i, a)
		require.Equal(int64(btc/4+btc/10), a.Locked, "signer %d sees both deposits locked", i)
	}
}

// TestFailedImportIsRetried: when the wallet can't import a new deposit
// address, the registration is recorded but the next request imports it,
// rather than leaving it recorded and unwatched.
func TestFailedImportIsRetried(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newHarness(t)
	c := &btcChain{rpc: n.settings.btcRPCClient()}
	require.NoError(c.ensureWallet())
	h.b.btc, h.b.btcParams = c, &chaincfg.RegressionNetParams

	require.NoError(n.node.call(nil, "unloadwallet", "btcvm"))
	alice := h.user(1)
	_, err := registerDeposit(h.b, alice)
	require.Error(err, "the wallet isn't loaded")
	known, err := h.b.registry.has(alice)
	require.NoError(err)
	require.True(known, "the registration itself was recorded")

	require.NoError(n.node.call(nil, "loadwallet", "btcvm"))
	addr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	var info struct {
		IsWatchOnly bool `json:"iswatchonly"`
		IsMine      bool `json:"ismine"`
	}
	require.NoError(c.rpc.call(&info, "getaddressinfo", addr.EncodeAddress()))
	require.True(info.IsMine || info.IsWatchOnly, "the retry imported it")
}

// TestRotationWithBitcoinCore rotates a peg with history to a new set of
// signers against a real Bitcoin Core: the move is a valid transaction that
// confirms, each signer sees the old set's addresses and the new set's from
// its own wallet, a deposit not yet credited at the change is credited once
// by the new set, and the new set pays withdrawals.
func TestRotationWithBitcoinCore(t *testing.T) {
	require := require.New(t)
	n := startRegtest(t)
	h := newCosignHarness(t)
	wallet := func(name string) *btcChain {
		s := n.settings
		s.btcWallet = name
		c := &btcChain{rpc: s.btcRPCClient()}
		require.NoError(c.ensureWallet())
		return c
	}
	setup := func(b *bridge, c *btcChain) {
		b.btc, b.btcParams = c, &chaincfg.RegressionNetParams
		b.minFeeRate, b.maxFeeRate = 1, 100
		b.minDeposit, b.minPegOut = 10_000, 30_000
	}
	setup(h.b, wallet("btcvm"))
	h.b.feeRate = func() (int64, error) { return 3, nil }
	for i, c := range h.signers {
		setup(c.b, wallet(fmt.Sprintf("signer%d", i)))
		require.NoError(watchPeg(c.b, false))
	}
	require.NoError(watchPeg(h.b, false))

	// History under the first set: alice credited, bob not yet, and a
	// little untagged BTC at the peg to pay for the moves.
	alice, bob := h.user(1), h.user(2)
	aliceAddr, err := registerDeposit(h.b, alice)
	require.NoError(err)
	bobAddr, err := registerDeposit(h.b, bob)
	require.NoError(err)
	pegAddr, err := h.b.btcPegAddress()
	require.NoError(err)
	require.NoError(n.funder.call(nil, "sendtoaddress", aliceAddr.EncodeAddress(), 0.25))
	require.NoError(n.funder.call(nil, "sendtoaddress", pegAddr.EncodeAddress(), 0.02))
	n.mine(6)
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(btc/4-h.b.vmFee, creditedTo(h.vm, alice))
	require.NoError(n.funder.call(nil, "sendtoaddress", bobAddr.EncodeAddress(), 0.1))
	n.mine(1)
	require.Empty(h.step(), "bob's deposit waits for confirmations")

	r := h.rotate(t)
	for i, c := range r.fresh {
		setup(c.b, wallet(fmt.Sprintf("new%d", i)))
		require.NoError(watchPeg(c.b, false))
	}
	for _, c := range r.retired {
		require.NoError(watchPeg(c.b, false))
	}
	require.NoError(watchPeg(h.b, false))

	require.Contains(h.step(), "reserve")
	h.vm.mine()
	require.Contains(h.step(), "Bitcoin")
	n.mine(1)
	a := h.audit()
	require.True(a.solvent(), "%+v", a)
	s, err := h.b.load()
	require.NoError(err)
	require.Empty(s.legacyUTXOs, "the old set holds nothing on Bitcoin")

	// Bob's deposit is credited once, by the new set.
	n.mine(6)
	for h.step() != "" {
		h.vm.mine()
	}
	require.Equal(btc/10-h.b.vmFee, creditedTo(h.vm, bob))
	require.Equal(btc/4-h.b.vmFee, creditedTo(h.vm, alice))

	// The new set pays a withdrawal from its own coins, on Bitcoin.
	aliceOnBTC := n.newAddress()
	h.pegOut(btc/20, aliceOnBTC)
	did, err := h.b.step()
	require.NoError(err)
	require.Contains(did, "paid")
	n.mine(1)
	require.Empty(h.step())
	a = h.audit()
	require.True(a.solvent(), "%+v", a)
	require.Zero(a.PendingPegOuts)
	for _, c := range r.fresh {
		s, err := c.b.load()
		require.NoError(err)
		require.True(c.b.audit(s).solvent(), "each new signer sees a solvent peg on its own node")
	}
}
