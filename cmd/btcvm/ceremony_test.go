package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2/ecdsa"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
)

func ecdsaSign(key *btcec.PrivateKey, hash []byte) []byte {
	return ecdsa.Sign(key, hash).Serialize()
}

// answering makes signer-setup read its answers from input, as if typed at
// a terminal.
func answering(t *testing.T, input string) {
	t.Helper()
	orig := newPrompter
	newPrompter = func(yes bool) *prompter {
		return &prompter{in: bufio.NewReader(strings.NewReader(input)), out: io.Discard, interactive: !yes}
	}
	t.Cleanup(func() { newPrompter = orig })
}

// ceremony runs signer-setup for the harness's three keys: the first
// imported interactively by pasting it, the others from files, one as a
// WIF. It returns the coordinator key file, the set and each signer's dir.
func ceremony(t *testing.T, h *harness) (coordKey string, set *signerSet, dirs []string) {
	require := require.New(t)
	root := t.TempDir()
	var cards []string
	for i, key := range h.b.signers.privKeys {
		dir := filepath.Join(root, "signer"+strconv.Itoa(i))
		dirs = append(dirs, dir)
		url := "https://signer" + strconv.Itoa(i) + ".example:9700"
		switch i {
		case 0:
			// Interactive: name, URL, "import", the pasted key, "y".
			answering(t, strings.Join([]string{"Signer Zero", url, "import", hex.EncodeToString(key.Serialize()), "y", ""}, "\n"))
			require.NoError(setupInit([]string{"-dir", dir}))
		default:
			keyFile := filepath.Join(root, "import"+strconv.Itoa(i))
			secret := hex.EncodeToString(key.Serialize())
			if i == 2 {
				wif, err := btcutil.NewWIF(key, &chaincfg.MainNetParams, true)
				require.NoError(err)
				secret = wif.String()
			}
			require.NoError(os.WriteFile(keyFile, []byte(secret), 0o600))
			answering(t, "")
			require.NoError(setupInit([]string{"-yes", "-dir", dir, "-name", "Signer " + strconv.Itoa(i), "-url", url, "-import-key-file", keyFile}))
		}
		cards = append(cards, filepath.Join(dir, cardFileName))
		imported, err := readKeyFile(filepath.Join(dir, keyFileName))
		require.NoError(err)
		require.True(imported.PubKey().IsEqual(key.PubKey()))
	}

	answering(t, "")
	coordDir := filepath.Join(root, "coordinator")
	require.NoError(setupCoordinator([]string{"-yes", "-dir", coordDir}))
	coordKey = filepath.Join(coordDir, coordKeyName)
	coord, err := readKeyFile(coordKey)
	require.NoError(err)

	setPath := filepath.Join(root, "signers.json")
	assembleArgs := []string{"-yes", "-required", "2", "-btc-network", "regtest", "-vm-network", "testnet",
		"-confirmations", "6", "-confirmation-tiers", "1:1",
		"-coordinator-key", hex.EncodeToString(coord.PubKey().SerializeCompressed()),
		"-out", setPath, "-cosigners-out", filepath.Join(root, "cosigners.json")}
	// The signers are reached over https, so the set needs the coordinator's
	// transport key.
	require.ErrorContains(setupAssemble(append(append([]string{}, assembleArgs...), cards...)), "-coordinator-tls")
	assembleArgs = append(assembleArgs, "-coordinator-tls", coordinatorPin(t, coordKey))
	require.NoError(setupAssemble(append(assembleArgs, cards...)))
	set, err = readSignerSet(setPath)
	require.NoError(err)
	require.Empty(set.PrivateKeys)
	require.Equal(h.b.signers.PublicKeys, set.PublicKeys, "same keys, same order: the same peg address")
	require.Equal([]confirmationTier{{UpTo: satPerBTC, Confirmations: 1}}, set.Policy.ConfirmationTiers,
		"the confirmation tiers are part of the agreed policy")

	for i, dir := range dirs {
		if i == 0 {
			// Interactive: confirm the fingerprint, then a 500 BTC daily limit.
			answering(t, "y\n500\n")
			require.NoError(setupJoin([]string{"-dir", dir, "-signers", setPath}))
		} else {
			answering(t, "")
			require.NoError(setupJoin([]string{"-yes", "-dir", dir, "-signers", setPath, "-fingerprint", set.fingerprint()}))
		}
		env, err := os.Stat(filepath.Join(dir, envFileName))
		require.NoError(err)
		require.Equal(os.FileMode(0o600), env.Mode().Perm())
		unit, err := os.ReadFile(filepath.Join(dir, unitFileName))
		require.NoError(err)
		require.Contains(string(unit), "-key-file "+filepath.Join(dir, keyFileName))
		if i == 0 {
			require.Contains(string(unit), "-max-daily 50000000000")
		}
	}
	return coordKey, set, dirs
}

func TestSignerCeremony(t *testing.T) {
	require := require.New(t)
	h := &cosignHarness{harness: newHarness(t)}
	coordKeyPath, set, dirs := ceremony(t, h.harness)

	// The coordinator: the agreed set, no keys, requests signed.
	coord, err := readKeyFile(coordKeyPath)
	require.NoError(err)
	h.b.signers = set
	require.NoError(h.b.applyPolicy(set.Policy))
	for _, dir := range dirs {
		own := *h.b
		own.signers, err = readSignerSet(filepath.Join(dir, setFileName))
		require.NoError(err)
		own.registry = &depositRegistry{path: filepath.Join(dir, "deposits.json")}
		key, err := readKeyFile(filepath.Join(dir, keyFileName))
		require.NoError(err)
		log, err := openSigningLog(filepath.Join(dir, signingLogKey))
		require.NoError(err)
		c := &cosigner{b: &own, key: key, log: log}
		srv := httptest.NewServer(c.handler())
		t.Cleanup(srv.Close)
		h.signers = append(h.signers, c)
		h.servers = append(h.servers, srv)
		h.b.cosigners = append(h.b.cosigners, &remoteSigner{URL: srv.URL, auth: coord,
			PublicKey: hex.EncodeToString(key.PubKey().SerializeCompressed())})
	}

	alice, aliceOnBTC := h.user(1), h.user(2)
	_, err = registerDeposit(h.b, alice)
	require.NoError(err)
	h.personalDeposit(100*btc, alice, 6)
	require.NotEmpty(h.step())
	require.Equal(100*btc-h.b.vmFee, paidTo(h.vm, alice))
	h.vm.mine()
	h.pegOut(60*btc, aliceOnBTC)
	require.NotEmpty(h.step())
	require.Equal(60*btc-h.feeOf(h.lastBTC()), paidTo(h.btc, aliceOnBTC))

	// Requests not signed by the coordinator key are refused.
	var status map[string]any
	unsigned := &remoteSigner{URL: h.servers[0].URL}
	require.ErrorContains(unsigned.status(&status), "not signed by the coordinator")
	impostor := &remoteSigner{URL: h.servers[0].URL, auth: h.signers[1].key, PublicKey: h.b.cosigners[0].PublicKey}
	require.ErrorContains(impostor.status(&status), "not signed by the coordinator")
	require.NoError(h.b.cosigners[0].status(&status))

	// signed returns the status request the coordinator would send signer
	// for, at time unix, with nonce.
	signed := func(to int, unix int64, nonce string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, h.servers[0].URL+"/v1/status", nil)
		req.Header.Set("X-Btcvm-Time", strconv.FormatInt(unix, 10))
		req.Header.Set("X-Btcvm-Nonce", nonce)
		digest := requestDigest("GET", "/v1/status", unix, nonce, h.b.cosigners[to].PublicKey, nil)
		req.Header.Set("X-Btcvm-Signature", hex.EncodeToString(ecdsaSign(coord, digest)))
		return req
	}
	code := func(req *http.Request) int {
		resp, err := http.DefaultClient.Do(req)
		require.NoError(err)
		resp.Body.Close()
		return resp.StatusCode
	}
	now := time.Now().Unix()
	// So are stale ones.
	require.Equal(http.StatusUnauthorized, code(signed(0, time.Now().Add(-time.Hour).Unix(), newNonce())))
	// And ones made for another signer: signer 0 is sent signer 1's.
	require.Equal(http.StatusUnauthorized, code(signed(1, now, newNonce())))
	// A request is accepted once; a replay of it is refused.
	nonce := newNonce()
	require.Equal(http.StatusOK, code(signed(0, now, nonce)))
	require.Equal(http.StatusUnauthorized, code(signed(0, now, nonce)))
	// A request with no nonce, as a coordinator before nonces sent, is refused.
	legacy := signed(0, now, newNonce())
	legacy.Header.Del("X-Btcvm-Nonce")
	require.Equal(http.StatusUnauthorized, code(legacy))
}

func TestCeremonyRefusesMistakes(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	_, set, dirs := ceremony(t, h)
	setPath := filepath.Join(filepath.Dir(dirs[0]), "signers.json")
	answering(t, "")

	// A fingerprint that doesn't match.
	err := setupJoin([]string{"-yes", "-dir", dirs[1], "-signers", setPath, "-fingerprint", "0000-0000-0000-0000-0000"})
	require.ErrorContains(err, "do not join")
	// No fingerprint at all, without a terminal.
	err = setupJoin([]string{"-yes", "-dir", dirs[1], "-signers", setPath})
	require.ErrorContains(err, "-fingerprint is required")

	// Interactively declining the fingerprint writes nothing new.
	answering(t, "n\n")
	err = setupJoin([]string{"-dir", dirs[1], "-signers", setPath})
	require.ErrorContains(err, "not confirmed")

	// A card whose name was changed after it was signed.
	answering(t, "")
	card, err := readCard(filepath.Join(dirs[0], cardFileName))
	require.NoError(err)
	card.Name = "Someone Else"
	require.ErrorContains(card.verify(), "does not match")

	// A second init on the same machine.
	err = setupInit([]string{"-yes", "-dir", dirs[0], "-name", "x", "-url", "https://x.example"})
	require.ErrorContains(err, "already has a signer key")

	// Keys the peg can't use.
	_, err = parsePrivateKey("5HueCGU8rMjxEXxiPuD5" + "BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ") // the textbook uncompressed WIF, split for key scanners
	require.ErrorContains(err, "uncompressed")
	_, err = parsePrivateKey("abcd")
	require.Error(err)

	// The agreed policy wins; a flag that disagrees with it is an error.
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	b := bridgeFlags(fs)
	require.NoError(fs.Parse([]string{"-vm-fee", "7"}))
	require.ErrorContains(b.applyPolicy(set.Policy), "-vm-fee=7 disagrees")
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	b = bridgeFlags(fs)
	require.NoError(fs.Parse(nil))
	require.NoError(b.applyPolicy(set.Policy))
	require.Equal(set.Policy.VMFee, b.vmFee)

	// Interactive init that makes a new key, with the defaults.
	dir := filepath.Join(t.TempDir(), "fresh")
	answering(t, strings.Join([]string{"Fresh Signer", "https://fresh.example:9700", "new", ""}, "\n"))
	require.NoError(setupInit([]string{"-dir", dir}))
	_, err = readKeyFile(filepath.Join(dir, keyFileName))
	require.NoError(err)
}

// TestRotationCeremony runs signer-setup for a key rotation: three new
// signers make fresh keys and cards, the coordinator assembles a set that
// names the old one, the new signers join it, and the old signers join it
// too, retired, keeping a copy of the set they ran with. A new set reusing
// an old key is refused.
func TestRotationCeremony(t *testing.T) {
	require := require.New(t)
	h := newHarness(t)
	coordKeyPath, old, oldDirs := ceremony(t, h)
	coord, err := readKeyFile(coordKeyPath)
	require.NoError(err)
	root := t.TempDir()
	oldPath := filepath.Join(oldDirs[0], setFileName)

	var cards, newDirs []string
	for i := 0; i < 3; i++ {
		dir := filepath.Join(root, "new"+strconv.Itoa(i))
		answering(t, "")
		require.NoError(setupInit([]string{"-yes", "-dir", dir, "-name", "New " + strconv.Itoa(i),
			"-url", "https://new" + strconv.Itoa(i) + ".example:9700"}))
		cards = append(cards, filepath.Join(dir, cardFileName))
		newDirs = append(newDirs, dir)
	}
	setPath := filepath.Join(root, "signers.json")
	cosignersPath := filepath.Join(root, "cosigners.json")
	args := []string{"-yes", "-required", "2", "-btc-network", "regtest", "-vm-network", "testnet",
		"-confirmations", "6", "-coordinator-key", hex.EncodeToString(coord.PubKey().SerializeCompressed()),
		"-previous", oldPath, "-out", setPath, "-cosigners-out", cosignersPath,
		"-coordinator-tls", coordinatorPin(t, coordKeyPath)}
	answering(t, "")
	require.NoError(setupAssemble(append(args, cards...)))
	next, err := readSignerSet(setPath)
	require.NoError(err)
	require.Equal([]priorSet{{Required: old.Required, PublicKeys: old.PublicKeys}}, next.Previous)
	require.NotEqual(old.fingerprint(), next.fingerprint())
	cosigners, err := os.ReadFile(cosignersPath)
	require.NoError(err)
	require.Contains(string(cosigners), "new0.example", "the coordinator reaches the new signers")
	require.Contains(string(cosigners), "signer0.example", "and the retired ones, to move the old set's coins")

	for _, dir := range newDirs {
		answering(t, "")
		require.NoError(setupJoin([]string{"-yes", "-dir", dir, "-signers", setPath, "-fingerprint", next.fingerprint()}))
	}
	for _, dir := range oldDirs {
		answering(t, "")
		require.NoError(setupJoin([]string{"-yes", "-dir", dir, "-signers", setPath, "-fingerprint", next.fingerprint()}))
		installed, err := readSignerSet(filepath.Join(dir, setFileName))
		require.NoError(err)
		require.Equal(next.fingerprint(), installed.fingerprint(), "the retired signer runs with the new set")
		kept, err := readSignerSet(filepath.Join(dir, "signers."+old.fingerprint()+".json"))
		require.NoError(err, "and keeps the set it ran with")
		require.Equal(old.fingerprint(), kept.fingerprint())
		unit, err := os.ReadFile(filepath.Join(dir, unitFileName))
		require.NoError(err)
		require.Contains(string(unit), "retired signer")
	}

	// Reusing an old key in the new set: refused.
	reuse := filepath.Join(oldDirs[1], cardFileName)
	answering(t, "")
	err = setupAssemble(append(append([]string{}, args...), cards[0], cards[1], reuse))
	require.ErrorContains(err, "rotation needs new keys")
}

// coordinatorPin is the pin of the transport key signer-setup coordinator
// made next to the coordinator key.
func coordinatorPin(t *testing.T, coordKeyPath string) string {
	cert, key, ok := transportFiles(coordKeyPath)
	require.True(t, ok, "signer-setup coordinator makes a transport key")
	_, pin, err := loadTransportKey(cert, key)
	require.NoError(t, err)
	return pin
}
