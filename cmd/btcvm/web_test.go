package main

import (
	"encoding/hex"
	"encoding/json"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MetalBlockchain/btcvm/btcd/blockchain"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/txscript"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// TestWebChainMatchesGo runs the web wallet's chain.js under Node and checks
// it agrees with the Go implementation: addresses, WIF keys, personal
// deposit addresses, and that a transaction it signs verifies in btcd's
// script engine.
func TestWebChainMatchesGo(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	require := require.New(t)

	vmParams, _ := btcvmParams("testnet")
	btcParams := &chaincfg.TestNet3Params
	signers, err := newSignerSet(2, 3)
	require.NoError(err)

	key, _ := btcec.PrivKeyFromBytes([]byte("0123456789abcdef0123456789abcdef"))
	report, err := describeKey(key, vmParams, btcParams)
	require.NoError(err)
	vmAddr, err := keyAddress(key, vmParams)
	require.NoError(err)
	dest, err := destinationOf(vmAddr)
	require.NoError(err)
	wantDeposit, err := signers.depositAddress(dest, btcParams)
	require.NoError(err)

	// A UTXO of 500 BTC the key owns, paid on to the peg reserve with a
	// BVMO tag, as the Withdraw tab does.
	fromScript := destinationScript(vmAddr)
	btcDest := destination{kind: destP2PKH, hash: [32]byte{9}}

	// The transaction that created the UTXO; the page fetches it to check
	// the UTXO's value.
	prev := wire.NewMsgTx(1)
	prev.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 7}, []byte{0x51}, nil))
	for i := 0; i < 3; i++ {
		prev.AddTxOut(wire.NewTxOut(satPerBTC, []byte{0x51}))
	}
	prev.AddTxOut(wire.NewTxOut(500*satPerBTC, fromScript))
	other := wire.NewMsgTx(1)
	other.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 8}, []byte{0x51}, nil))
	for i := 0; i < 4; i++ {
		other.AddTxOut(wire.NewTxOut(5000*satPerBTC, fromScript))
	}
	uncompressed, err := btcutil.NewWIF(key, btcParams, false)
	require.NoError(err)
	input := map[string]any{
		"keyHex":      hex.EncodeToString(key.Serialize()),
		"vmVersions":  addressVersions(vmParams),
		"btcVersions": addressVersions(btcParams),
		"signers":     map[string]any{"required": signers.Required, "publicKeys": signers.PublicKeys},
		"utxo": map[string]any{
			"txid": prev.TxHash().String(), "vout": 3,
			"value": strconv.FormatInt(500*satPerBTC, 10), "script": hex.EncodeToString(fromScript), "confirmations": 1,
		},
		"rawTxs":          map[string]string{prev.TxHash().String(): encodeTx(prev)},
		"otherTx":         encodeTx(other),
		"uncompressedWIF": uncompressed.String(),
		"toScript":        hex.EncodeToString(signers.pkScript()),
		"amount":          120 * satPerBTC,
		"data":            hex.EncodeToString(encodeDestination(tagPegOut, btcDest)),
	}
	raw, err := json.Marshal(input)
	require.NoError(err)
	inputPath := filepath.Join(t.TempDir(), "input.json")
	require.NoError(os.WriteFile(inputPath, raw, 0o600))

	out, err := exec.Command(node, "testdata/chain_vectors.mjs", inputPath).CombinedOutput()
	require.NoError(err, "%s", out)
	var got struct {
		VMAddress, BTCAddress, VMWIF, BTCWIF, KeyFromWIF, DepositAddress, TxHex string
		TxID, InflatedHex, Refused, Uncompressed                                string
	}
	require.NoError(json.Unmarshal(out, &got), "%s", out)

	require.Equal(report.BTCVMAddr, got.VMAddress)
	require.Equal(report.BitcoinAddr, got.BTCAddress)
	require.Equal(report.BTCVMWIF, got.VMWIF)
	require.Equal(report.BitcoinWIF, got.BTCWIF)
	require.Equal(report.PrivateKeyHex, got.KeyFromWIF)
	require.Equal(wantDeposit.EncodeAddress(), got.DepositAddress)

	// The browser-signed transaction pays the reserve, carries the tag, and
	// its input verifies.
	tx, err := decodeTx(got.TxHex)
	require.NoError(err)
	require.Equal(int64(120*satPerBTC), tx.TxOut[0].Value)
	require.Equal(signers.pkScript(), tx.TxOut[0].PkScript)
	parsed, ok := parseDestinationTag(tx, tagPegOut)
	require.True(ok)
	require.Equal(btcDest, parsed)

	vm, err := txscript.NewEngine(fromScript, tx, 0, txscript.StandardVerifyFlags, nil, nil,
		500*satPerBTC, txscript.NewCannedPrevOutputFetcher(fromScript, 500*satPerBTC))
	require.NoError(err)
	require.NoError(vm.Execute())

	// Change returns to the sender, and the fee is BTCVM's relay minimum:
	// a satoshi.
	require.Len(tx.TxOut, 3)
	require.Equal(fromScript, tx.TxOut[2].PkScript)
	fee := int64(500*satPerBTC) - tx.TxOut[0].Value - tx.TxOut[2].Value
	vsize := (blockchain.GetTransactionWeight(btcutil.NewTx(tx)) + 3) / 4
	require.Less(vsize, int64(1000))
	require.Equal(int64(1), fee)

	require.Equal(tx.TxHash().String(), got.TxID)
	require.Equal(got.TxHex, got.InflatedHex, "an overstated UTXO value changed the transaction")
	require.Contains(got.Refused, "wrong transaction")
	require.Contains(got.Uncompressed, "uncompressed")
}

// TestEmbeddedImportsResolve checks that every relative module import in the
// embedded web files is itself embedded. go:embed skips files starting with
// _ unless the pattern uses all:, which once shipped a page that could not
// load its crypto.
func TestEmbeddedImportsResolve(t *testing.T) {
	importRE := regexp.MustCompile(`(?:from\s+|import\()\s*['"](\./[^'"]+|\.\./[^'"]+)['"]`)
	checked := 0
	err := fs.WalkDir(webFiles, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs")) {
			return err
		}
		src, err := fs.ReadFile(webFiles, p)
		if err != nil {
			return err
		}
		for _, m := range importRE.FindAllStringSubmatch(string(src), -1) {
			target := path.Join(path.Dir(p), m[1])
			if _, err := fs.Stat(webFiles, target); err != nil {
				t.Errorf("%s imports %s, which is not embedded", p, m[1])
			}
			checked++
		}
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, checked, 5)
}

// TestPageIDsUnique checks no two elements of a page share an id: the pages
// find elements by id, and a duplicate once hid the wallet's unlock button
// behind an unrelated figure. It also checks each page marks itself, and
// only itself, as the current one in the menu.
func TestPageIDsUnique(t *testing.T) {
	pages, err := renderPages()
	require.NoError(t, err)
	require.Len(t, pages, len(sitePages))
	for path, page := range pages {
		seen := map[string]bool{}
		for _, m := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllStringSubmatch(string(page), -1) {
			require.False(t, seen[m[1]], "id %q is used twice on %s", m[1], path)
			seen[m[1]] = true
		}
		current := regexp.MustCompile(`href="([^"]+)" aria-current="page"`).FindAllStringSubmatch(string(page), -1)
		require.Len(t, current, 1, path)
		require.Equal(t, path, current[0][1])
	}
	require.Greater(t, len(regexp.MustCompile(`\sid="`).FindAll(pages["/"], -1)), 50)
}

// TestWebReview runs the web wallet's review-before-signing checks.
func TestWebReview(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/review_check.mjs").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Equal(t, "ok\n", string(out))
}

// TestWebUnits runs the web wallet's amount-unit checks: BTC, sats and USD
// convert to exact satoshis, and USD is refused without a fresh price.
func TestWebUnits(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/units_check.mjs").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Equal(t, "ok\n", string(out))
}

// TestWebAddressBook runs the web wallet's address-book checks: only valid
// addresses are saved, names and the book are capped, stored entries are
// re-checked on load, and lookups match an address for its network.
func TestWebAddressBook(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/addressbook_check.mjs").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Equal(t, "ok\n", string(out))
}

// TestWebPasskey runs the web wallet's passkey checks: a PIN or biometric
// is required and checked, and backups made before still open.
func TestWebPasskey(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/passkey_check.mjs").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Equal(t, "ok\n", string(out))
}
