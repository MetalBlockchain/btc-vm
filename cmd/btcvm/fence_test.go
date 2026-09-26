package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

func TestMissingSigningLogQuarantines(t *testing.T) {
	require := require.New(t)
	path := filepath.Join(t.TempDir(), "signing-log.json")
	_, err := openSigningLog(path)
	require.ErrorIs(err, errQuarantined, "a missing log is a lost one, never an empty one")

	_, err = createSigningLog(path)
	require.NoError(err)
	_, err = createSigningLog(path)
	require.Error(err, "starting a log never replaces one")
	l, err := openSigningLog(path)
	require.NoError(err)
	require.Empty(l.Actions)
}

// restoreLog puts raw back as c's log, as restoring a backup would, and
// reopens it.
func restoreLog(t *testing.T, c *cosigner, raw []byte) {
	require.NoError(t, os.WriteFile(c.log.path, raw, 0o600))
	l, err := openSigningLog(c.log.path)
	require.NoError(t, err)
	c.log, c.mine = l, nil
}

func TestStaleSigningLogQuarantines(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	signer, idle := h.signers[0], h.signers[2] // 2 of 3: the first two sign
	empty, err := os.ReadFile(signer.log.path)
	require.NoError(err)

	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err = registerDeposit(h.b, alice)
	require.NoError(err)
	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step()) // a release, signed on BTCVM
	h.vm.mine()
	afterRelease, err := os.ReadFile(signer.log.path)
	require.NoError(err)
	h.pegOut(60*btc, aliceOnBTC)
	require.NotEmpty(h.step()) // a payout, signed on Bitcoin
	h.btc.mine()
	current, err := os.ReadFile(signer.log.path)
	require.NoError(err)

	s, err := h.b.load()
	require.NoError(err)
	require.NoError(signer.fence(s), "a log holding everything signed")
	require.NoError(idle.fence(s), "a signer that signed nothing, with an empty log")

	// A backup from before the payout: the chains show the payout it signed.
	restoreLog(t, signer, afterRelease)
	require.ErrorIs(signer.fence(s), errQuarantined)
	// And one from before anything: the release shows too.
	require.NoError(os.Remove(quarantinePath(signer.log.path)))
	restoreLog(t, signer, empty)
	require.ErrorIs(signer.fence(s), errQuarantined)

	// Quarantined, it signs nothing, whatever it is asked.
	h.personalDeposit(5*btc, alice, 6)
	req, _ := h.releaseRequest(h.reserveUTXOs())
	_, _, _, err = signer.check(req)
	require.ErrorIs(err, errQuarantined)
	status, err := signer.handleStatus(nil)
	require.NoError(err)
	require.NotEmpty(status.(map[string]any)["quarantined"])

	// A restart stays quarantined even with the right log back, until the
	// operator removes the marker.
	restoreLog(t, signer, current)
	restarted := &cosigner{b: signer.b, key: signer.key, log: signer.log}
	s, err = h.b.load()
	require.NoError(err)
	require.ErrorIs(restarted.fence(s), errQuarantined)
	require.NoError(os.Remove(quarantinePath(signer.log.path)))
	require.NoError(restarted.fence(s))
}

// TestAdoptRebuildsALogFromTheChains: a key that signed before signers kept
// logs gets its confirmed signatures logged under the actions they did; an
// unconfirmed one is never adopted.
func TestAdoptRebuildsALogFromTheChains(t *testing.T) {
	require := require.New(t)
	h := newCosignHarness(t)
	signer := h.signers[0]
	empty, err := os.ReadFile(signer.log.path)
	require.NoError(err)
	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err = registerDeposit(h.b, alice)
	require.NoError(err)
	d := h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	h.vm.mine()
	h.pegOut(60*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	current, err := os.ReadFile(signer.log.path)
	require.NoError(err)

	// The payout isn't in a block yet: nothing is adopted.
	restoreLog(t, signer, empty)
	s, err := h.b.load()
	require.NoError(err)
	_, err = signer.adopt(s)
	require.ErrorContains(err, "not in a block")
	reread, err := openSigningLog(signer.log.path)
	require.NoError(err)
	require.Empty(reread.Actions, "nothing written")

	// Once it is, both are adopted, under the actions the signer logged.
	h.btc.mine()
	s, err = h.b.load()
	require.NoError(err)
	adopted, err := signer.adopt(s)
	require.NoError(err)
	require.Len(adopted, 2)
	require.NoError(signer.fence(s))
	var want signingLog
	require.NoError(json.Unmarshal(current, &want))
	reread, err = openSigningLog(signer.log.path)
	require.NoError(err)
	for key, a := range want.Actions {
		require.Contains(reread.Actions, key)
		require.Equal(a.Txs[0].Txid, reread.Actions[key].Txs[0].Txid)
	}
	releaseKey, err := (action{Kind: actionRelease, Deposit: wire.OutPoint{Hash: d.TxHash()}.String()}).key()
	require.NoError(err)
	require.True(reread.has(releaseKey))
}
