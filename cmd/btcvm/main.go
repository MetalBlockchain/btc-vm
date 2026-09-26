// Command btcvm is a wallet and two-way peg bridge for BTCVM.
//
// Connection settings come from flags or environment variables:
//
//	BTCVM_RPC        BTCVM JSON-RPC URL, e.g. http://127.0.0.1:9650/ext/bc/btcvm/rpc
//	BTCVM_RPC_USER   BTCVM RPC user
//	BTCVM_RPC_PASS   BTCVM RPC password
//	BTCVM_NETWORK    BTCVM network: testnet (default) or mainnet
//	BITCOIN_RPC      Bitcoin Core JSON-RPC URL, e.g. http://127.0.0.1:18332
//	BITCOIN_RPC_USER Bitcoin Core RPC user
//	BITCOIN_RPC_PASS Bitcoin Core RPC password
//	BITCOIN_NETWORK  Bitcoin network: regtest, testnet (default) or mainnet
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

const usage = `btcvm: BTCVM wallet and two-way peg bridge

Wallet (BTCVM):
  btcvm keygen                               new key, shown for both chains
  btcvm balance -address ADDR                BTCVM balance
  btcvm send -key KEY -to ADDR -amount BTC  send BTC on BTCVM

Peg (users):
  btcvm deposit-address -signers FILE -to VMADDR
      personal Bitcoin address that credits VMADDR; send to it from any wallet
  btcvm peg-in -signers FILE -to VMADDR -amount BTC
      deposit from the Bitcoin Core wallet at BITCOIN_RPC to the peg,
      credited to VMADDR on BTCVM
  btcvm peg-out -signers FILE -key KEY -to BTCADDR -amount BTC
      send BTC from BTCVM back to BTCADDR on Bitcoin

Bridge (peg signers):
  btcvm signers -required M -total N -out FILE
      create a signer set, and print the peg addresses and genesis config
  btcvm signers-check -signers FILE          check a signer set's private keys match it; print its peg addresses
  btcvm bridge -signers FILE [-once]         run the bridge
  btcvm audit -signers FILE                  check the peg is fully backed
  btcvm refund -signers FILE -list           deposits that are held or not yet credited
  btcvm refund -signers FILE -deposit TXID:VOUT [-to BTCADDR]
  btcvm import-deposit -signers FILE -txid TXID [-block HASH]
      add a deposit paid before its address was registered
      return a held deposit, less the Bitcoin fee, to its sender (or -to)
  btcvm monitor -signers FILE [-webhook URL]  alert when a health check fails
  btcvm pause -signers FILE -reason TEXT     emergency stop: sign and pay nothing (a signer: -dir DIR)
  btcvm resume -signers FILE                 end a pause
  btcvm serve -signers FILE                  web wallet and bridge API
  btcvm signer-setup STEP                    set up separate signers: init, coordinator, assemble, join, check
  btcvm signer-key -out FILE                 new key for one separate signer; prints its public key
  btcvm signer -signers FILE -key-file FILE  run one separate signer (see docs/SIGNERS.md)
  btcvm signer-log check|init|adopt -signers FILE -key-file FILE
                                             check a signer's log against the chains, or start the
                                             log of a key that has never signed

Personal deposit addresses are recorded in -deposits (default deposits.json
next to the signers file) so the bridge knows to watch them.

Run "btcvm COMMAND -h" for a command's flags. Connection settings come from
the BTCVM_* and BITCOIN_* environment variables; see the package docs.
`

// settings holds the connection flags shared by every command.
type settings struct {
	vmRPC, vmUser, vmPass, vmNetwork string
	btcRPC, btcUser, btcPass, btcNet string
	btcWallet                        string
	vmParams, btcParams              *chaincfg.Params
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func (s *settings) register(fs *flag.FlagSet) {
	fs.StringVar(&s.vmRPC, "vm-rpc", envOr("BTCVM_RPC", "http://127.0.0.1:9650/ext/bc/btcvm/rpc"), "BTCVM JSON-RPC URL")
	fs.StringVar(&s.vmUser, "vm-user", os.Getenv("BTCVM_RPC_USER"), "BTCVM RPC user")
	fs.StringVar(&s.vmPass, "vm-pass", os.Getenv("BTCVM_RPC_PASS"), "BTCVM RPC password")
	fs.StringVar(&s.vmNetwork, "vm-network", envOr("BTCVM_NETWORK", "testnet"), "BTCVM network: testnet or mainnet")
	fs.StringVar(&s.btcRPC, "btc-rpc", envOr("BITCOIN_RPC", "http://127.0.0.1:8332"), "Bitcoin Core JSON-RPC URL")
	fs.StringVar(&s.btcWallet, "btc-wallet", envOr("BITCOIN_WALLET", "btcvm"), "Bitcoin Core wallet the bridge watches addresses with; created, watch-only, if missing")
	fs.StringVar(&s.btcUser, "btc-user", os.Getenv("BITCOIN_RPC_USER"), "Bitcoin Core RPC user")
	fs.StringVar(&s.btcPass, "btc-pass", os.Getenv("BITCOIN_RPC_PASS"), "Bitcoin Core RPC password")
	fs.StringVar(&s.btcNet, "btc-network", envOr("BITCOIN_NETWORK", "testnet"), "Bitcoin network: regtest, testnet or mainnet")
}

func (s *settings) resolve() error {
	var err error
	if s.vmParams, err = btcvmParams(s.vmNetwork); err != nil {
		return err
	}
	s.btcParams, err = bitcoinParams(s.btcNet)
	return err
}

func (s *settings) vmChain() *vmChain {
	return &vmChain{rpc: newRPCClient(s.vmRPC, s.vmUser, s.vmPass)}
}

// btcRPCClient is the bridge's wallet endpoint on Bitcoin Core. Calls that
// are not wallet calls work there too.
func (s *settings) btcRPCClient() *rpcClient {
	return s.btcWalletClient(s.btcWallet)
}

// btcWalletClient is the endpoint of Bitcoin Core wallet name ("" for the
// node's default wallet).
func (s *settings) btcWalletClient(name string) *rpcClient {
	url := strings.TrimRight(s.btcRPC, "/")
	if name != "" {
		url += "/wallet/" + name
	}
	return newRPCClient(url, s.btcUser, s.btcPass)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	commands := map[string]func([]string) error{
		"keygen":          cmdKeygen,
		"balance":         cmdBalance,
		"send":            cmdSend,
		"peg-in":          cmdPegIn,
		"deposit-address": cmdDepositAddress,
		"serve":           cmdServe,
		"peg-out":         cmdPegOut,
		"signers":         cmdSigners,
		"bridge":          cmdBridge,
		"audit":           cmdAudit,
		"refund":          cmdRefund,
		"import-deposit":  cmdImportDeposit,
		"monitor":         cmdMonitor,
		"signer":          cmdSigner,
		"signer-key":      cmdSignerKey,
		"signer-log":      cmdSignerLog,
		"signer-setup":    cmdSignerSetup,
		"signers-check":   cmdSignersCheck,
		"pause":           cmdPause,
		"resume":          cmdResume,
	}
	run, ok := commands[cmd]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "btcvm "+cmd+":", err)
		os.Exit(1)
	}
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func parseFlags(fs *flag.FlagSet, s *settings, args []string) error {
	s.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return s.resolve()
}

func required(values map[string]string) error {
	for name, v := range values {
		if v == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}
	return nil
}

func cmdKeygen(args []string) error {
	var s settings
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	key, err := newKey()
	if err != nil {
		return err
	}
	report, err := describeKey(key, s.vmParams, s.btcParams)
	if err != nil {
		return err
	}
	printJSON(report)
	return nil
}

func cmdBalance(args []string) error {
	var s settings
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	address := fs.String("address", "", "BTCVM address")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"address": *address}); err != nil {
		return err
	}
	addr, err := btcutil.DecodeAddress(*address, s.vmParams)
	if err != nil {
		return err
	}
	confirmed, pending, err := balance(s.vmChain(), addr)
	if err != nil {
		return err
	}
	printJSON(map[string]string{
		"address":   addr.EncodeAddress(),
		"confirmed": formatBTC(confirmed),
		"pending":   formatBTC(pending),
	})
	return nil
}

func cmdSend(args []string) error {
	var s settings
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	keyFlag := fs.String("key", "", "sender private key (WIF or hex)")
	to := fs.String("to", "", "BTCVM destination address")
	amountFlag := fs.String("amount", "", "amount in BTC")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"key": *keyFlag, "to": *to, "amount": *amountFlag}); err != nil {
		return err
	}
	key, err := parseKey(*keyFlag)
	if err != nil {
		return err
	}
	dest, err := btcutil.DecodeAddress(*to, s.vmParams)
	if err != nil {
		return err
	}
	amount, err := parseBTC(*amountFlag)
	if err != nil {
		return err
	}
	txid, err := payFromKey(s.vmChain(), s.vmParams, key, destinationScript(dest), amount, nil)
	if err != nil {
		return err
	}
	printJSON(map[string]string{"txid": txid.String()})
	return nil
}

func cmdPegIn(args []string) error {
	var s settings
	fs := flag.NewFlagSet("peg-in", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file")
	to := fs.String("to", "", "BTCVM address to credit")
	amountFlag := fs.String("amount", "", "amount in BTC")
	fromWallet := fs.String("from-wallet", "", "Bitcoin Core wallet holding the BTC to deposit (default: the node's default wallet)")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath, "to": *to, "amount": *amountFlag}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	destAddr, err := btcutil.DecodeAddress(*to, s.vmParams)
	if err != nil {
		return fmt.Errorf("-to must be a BTCVM %s address: %w", s.vmNetwork, err)
	}
	dest, err := destinationOf(destAddr)
	if err != nil {
		return err
	}
	amount, err := parseBTC(*amountFlag)
	if err != nil {
		return err
	}
	pegAddr, err := signers.address(s.btcParams)
	if err != nil {
		return err
	}
	txid, err := depositFromBitcoinCore(s.btcWalletClient(*fromWallet), pegAddr, dest, amount)
	if err != nil {
		return err
	}
	printJSON(map[string]string{
		"bitcoinTxid": txid,
		"pegAddress":  pegAddr.EncodeAddress(),
		"creditTo":    destAddr.EncodeAddress(),
	})
	return nil
}

func cmdPegOut(args []string) error {
	var s settings
	fs := flag.NewFlagSet("peg-out", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file")
	keyFlag := fs.String("key", "", "sender private key on BTCVM (WIF or hex)")
	to := fs.String("to", "", "Bitcoin address to pay")
	amountFlag := fs.String("amount", "", "amount in BTC")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath, "key": *keyFlag, "to": *to, "amount": *amountFlag}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	key, err := parseKey(*keyFlag)
	if err != nil {
		return err
	}
	destAddr, err := btcutil.DecodeAddress(*to, s.btcParams)
	if err != nil {
		return fmt.Errorf("-to must be a Bitcoin %s address: %w", s.btcNet, err)
	}
	dest, err := destinationOf(destAddr)
	if err != nil {
		return err
	}
	amount, err := parseBTC(*amountFlag)
	if err != nil {
		return err
	}
	txid, err := payFromKey(s.vmChain(), s.vmParams, key, signers.pkScript(), amount,
		nullData(encodeDestination(tagPegOut, dest)))
	if err != nil {
		return err
	}
	printJSON(map[string]string{"btcvmTxid": txid.String(), "payTo": destAddr.EncodeAddress()})
	return nil
}

func cmdSigners(args []string) error {
	var s settings
	fs := flag.NewFlagSet("signers", flag.ExitOnError)
	req := fs.Int("required", 2, "signatures required")
	total := fs.Int("total", 3, "number of signers")
	out := fs.String("out", "", "file to write the signer set to (contains private keys, unless -public-keys)")
	publicKeys := fs.String("public-keys", "", "comma-separated signer public keys (from btcvm signer-key); the set then holds no private keys")
	blocks := fs.Int("reserve-blocks", 1, "pegReserveBlocks for the genesis config (20,999,000 BTC each)")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"out": *out}); err != nil {
		return err
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite a signer set", *out)
	}
	var signers *signerSet
	var err error
	if *publicKeys != "" {
		signers = &signerSet{Required: *req, PublicKeys: strings.Split(*publicKeys, ",")}
		err = signers.load()
	} else {
		signers, err = newSignerSet(*req, *total)
	}
	if err != nil {
		return err
	}
	if err := signers.write(*out); err != nil {
		return err
	}
	vmAddr, _ := signers.address(s.vmParams)
	btcAddr, _ := signers.address(s.btcParams)
	printJSON(map[string]any{
		"file":                 *out,
		"btcvmReserve":         vmAddr.EncodeAddress(),
		"bitcoinPegAddress":    btcAddr.EncodeAddress(),
		"genesisConfigSnippet": map[string]any{"pegReserveAddress": vmAddr.EncodeAddress(), "pegReserveBlocks": *blocks},
	})
	return nil
}

// cmdSignersCheck checks every private key in a signer set belongs to it, and
// prints the peg addresses the set controls. Restoring a backup uses it to
// show the restored keys are the ones holding the peg.
func cmdSignersCheck(args []string) error {
	var s settings
	fs := flag.NewFlagSet("signers-check", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file")
	var keyFiles []string
	fs.Func("key-file", "a separate signer's key file, to check it's in the set (repeatable)", func(v string) error {
		keyFiles = append(keyFiles, v)
		return nil
	})
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	for i, key := range signers.privKeys {
		if signers.indexOf(key.PubKey()) < 0 {
			return fmt.Errorf("private key %d is not one of the set's public keys", i)
		}
	}
	// Separate signers' keys are checked one file at a time; they are
	// never put together.
	seen := map[int]bool{}
	for _, path := range keyFiles {
		key, err := readKeyFile(path)
		if err != nil {
			return err
		}
		i := signers.indexOf(key.PubKey())
		if i < 0 {
			return fmt.Errorf("%s is not one of the set's public keys", path)
		}
		if seen[i] {
			return fmt.Errorf("%s holds the same key as another key file", path)
		}
		seen[i] = true
	}
	vmAddr, _ := signers.address(s.vmParams)
	btcAddr, _ := signers.address(s.btcParams)
	printJSON(map[string]any{
		"required":          signers.Required,
		"publicKeys":        len(signers.PublicKeys),
		"privateKeys":       len(signers.privKeys),
		"keyFiles":          len(seen),
		"bitcoinPegAddress": btcAddr.EncodeAddress(),
		"btcvmReserve":      vmAddr.EncodeAddress(),
		"fingerprint":       signers.fingerprint(),
	})
	return nil
}

// bridgeFlags registers the bridge's policy flags on fs.
func bridgeFlags(fs *flag.FlagSet) *bridge {
	b := &bridge{
		logf: func(format string, args ...any) {
			fmt.Printf("%s "+format+"\n", append([]any{time.Now().Format(time.RFC3339)}, args...)...)
		},
	}
	fs.Int64Var(&b.depositConfirmations, "confirmations", 6, "Bitcoin confirmations before a deposit is credited")
	fs.StringVar(&b.tiersFlag, "confirmation-tiers", "", `fewer confirmations for smaller deposits, as BTC:CONFIRMATIONS pairs, e.g. "0.001:1,0.01:3"; larger deposits need -confirmations`)
	fs.Int64Var(&b.vmFee, "vm-fee", 10, "satoshis deducted from each credit for the BTCVM fee")
	fs.Int64Var(&b.minFeeRate, "min-fee-rate", 1, "lowest fee rate a Bitcoin payout pays, in sat/vB")
	fs.Int64Var(&b.maxFeeRate, "max-fee-rate", 50, "highest fee rate a Bitcoin payout pays, in sat/vB; the fee comes out of the payout")
	fs.DurationVar(&b.bumpAfter, "bump-after", 30*time.Minute, "replace a payout still unconfirmed after this long with one paying the current fee rate (0: never)")
	fs.Int64Var(&b.minDeposit, "min-deposit", 10_000, "smallest deposit credited, in satoshis")
	fs.Int64Var(&b.minPegOut, "min-peg-out", 10_000, "smallest peg-out paid, in satoshis; the network fee must be under half of it")
	fs.Int64Var(&b.maxDeposit, "max-deposit", 0, "largest deposit credited, in satoshis; larger ones are held for refund (0: no cap)")
	fs.Int64Var(&b.maxCirculating, "max-circulating", 0, "most BTC, in satoshis, the bridge lets circulate on BTCVM (0: no cap)")
	fs.StringVar(&b.cosignersPath, "cosigners", "", "JSON list of remote signers, [{\"url\": ...}] (from btcvm signer-setup assemble)")
	fs.StringVar(&b.coordinatorKeyPath, "coordinator-key-file", "", "the coordinator key, to sign requests to the signers (from btcvm signer-setup coordinator)")
	fs.StringVar(&b.coordinatorTLSCert, "coordinator-tls-cert", "", "the coordinator's transport certificate, for signers over TLS (default: tls.crt next to -coordinator-key-file)")
	fs.StringVar(&b.coordinatorTLSKey, "coordinator-tls-key", "", "the coordinator's transport key (default: tls.key next to -coordinator-key-file)")
	b.flags = fs
	return b
}

// registryFor returns the deposit registry at path, or next to the signers
// file if path is empty.
func registryFor(path, signersPath string) *depositRegistry {
	if path == "" {
		path = filepath.Join(filepath.Dir(signersPath), "deposits.json")
	}
	return &depositRegistry{path: path}
}

// connect points b at the chains, the signer set and any remote signers.
func (b *bridge) connect(s *settings, signers *signerSet) error {
	b.signers = signers
	b.vm = s.vmChain()
	btc := &btcChain{rpc: s.btcRPCClient()}
	if err := btc.ensureWallet(); err != nil {
		return fmt.Errorf("Bitcoin Core wallet %q: %w", s.btcWallet, err)
	}
	b.btc = btc
	b.feeRate = btc.estimateFeeRate
	b.vmParams, b.btcParams = s.vmParams, s.btcParams
	if n := signers.Networks; n != nil && (n.Bitcoin != s.btcNet || n.BTCVM != s.vmNetwork) {
		return fmt.Errorf("the signer set is for Bitcoin %s and BTCVM %s, not %s and %s",
			n.Bitcoin, n.BTCVM, s.btcNet, s.vmNetwork)
	}
	tiers, err := parseConfirmationTiers(b.tiersFlag, b.depositConfirmations)
	if err != nil {
		return fmt.Errorf("-confirmation-tiers: %w", err)
	}
	b.confirmationTiers = tiers
	if err := b.applyPolicy(signers.Policy); err != nil {
		return err
	}
	if err := b.checkFeeRates(); err != nil {
		return err
	}
	if b.cosignersPath != "" {
		var err error
		if b.cosigners, err = readCosigners(b.cosignersPath); err != nil {
			return err
		}
		if err := signers.identifyCosigners(b.cosigners); err != nil {
			return fmt.Errorf("%s: %w", b.cosignersPath, err)
		}
	}
	if b.coordinatorKeyPath != "" {
		key, err := readKeyFile(b.coordinatorKeyPath)
		if err != nil {
			return err
		}
		if signers.coordKey == nil || !signers.coordKey.IsEqual(key.PubKey()) {
			return errors.New("-coordinator-key-file is not the coordinator key the signer set names")
		}
		for _, r := range b.cosigners {
			r.auth = key
		}
		if b.coordinatorTLSCert == "" && b.coordinatorTLSKey == "" {
			if cert, key, ok := transportFiles(b.coordinatorKeyPath); ok {
				b.coordinatorTLSCert, b.coordinatorTLSKey = cert, key
			}
		}
	}
	return b.secureCosigners(b.coordinatorTLSCert, b.coordinatorTLSKey)
}

// applyPolicy adopts the policy the signers agreed to. A policy flag given
// explicitly must agree with it.
func (b *bridge) applyPolicy(p *pegPolicy) error {
	if p == nil {
		return nil
	}
	fields := map[string]*int64{
		"confirmations": &b.depositConfirmations, "vm-fee": &b.vmFee,
		"min-fee-rate": &b.minFeeRate, "max-fee-rate": &b.maxFeeRate,
		"min-deposit": &b.minDeposit, "min-peg-out": &b.minPegOut,
		"max-deposit": &b.maxDeposit, "max-circulating": &b.maxCirculating,
	}
	agreed := map[string]int64{
		"confirmations": p.Confirmations, "vm-fee": p.VMFee,
		"min-fee-rate": p.MinFeeRate, "max-fee-rate": p.MaxFeeRate,
		"min-deposit": p.MinDeposit, "min-peg-out": p.MinPegOut,
		"max-deposit": p.MaxDeposit, "max-circulating": p.MaxCirculating,
	}
	var err error
	if b.flags != nil {
		b.flags.Visit(func(f *flag.Flag) {
			if want, ok := agreed[f.Name]; ok && *fields[f.Name] != want && err == nil {
				err = fmt.Errorf("-%s=%d disagrees with the signer set's policy (%d)", f.Name, *fields[f.Name], want)
			}
		})
	}
	for name, v := range agreed {
		*fields[name] = v
	}
	if err == nil && b.flags != nil {
		b.flags.Visit(func(f *flag.Flag) {
			if f.Name == "confirmation-tiers" && !sameTiers(b.confirmationTiers, p.ConfirmationTiers) {
				err = fmt.Errorf("-confirmation-tiers=%s disagrees with the signer set's policy (%s)",
					formatConfirmationTiers(b.confirmationTiers), formatConfirmationTiers(p.ConfirmationTiers))
			}
		})
	}
	b.confirmationTiers = p.ConfirmationTiers
	return err
}

// watchPeg makes Bitcoin Core track the peg address and every registered
// deposit address.
func watchPeg(b *bridge, rescan bool) error {
	addrs, _, err := b.btcWatchSet(&pegState{})
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := b.btc.(*btcChain).watch(addr, rescan); err != nil {
			return err
		}
	}
	return nil
}

// registerDeposit records dest's personal deposit address and has Bitcoin
// Core watch it.
func registerDeposit(b *bridge, dest destination) (btcutil.Address, error) {
	addr, err := b.signers.depositAddress(dest, b.btcParams)
	if err != nil {
		return nil, err
	}
	added, err := b.registry.add(dest)
	if err != nil {
		return nil, err
	}
	// Watch it unless this process already has: a registration whose
	// import failed is retried on the next request, rather than left
	// recorded but unwatched. Nothing can have been sent to a new address,
	// so no rescan.
	if dc, ok := b.btc.(*btcChain); ok {
		if err := dc.watchOnce(addr); err != nil {
			return nil, err
		}
	}
	if added {
		// Tell the remote signers now, so their nodes watch the address
		// before anything arrives at it. A signer that misses this learns
		// of the address from the first proposal that involves it.
		var wg sync.WaitGroup
		for _, r := range b.cosigners {
			wg.Add(1)
			go func(r *remoteSigner) {
				defer wg.Done()
				if err := r.register(dest, nil); err != nil {
					b.logf("telling signer %s about deposit address %s: %v", r.URL, addr.EncodeAddress(), err)
				}
			}(r)
		}
		wg.Wait()
	}
	return addr, nil
}

func cmdDepositAddress(args []string) error {
	var s settings
	fs := flag.NewFlagSet("deposit-address", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file (public keys are enough)")
	depositsPath := fs.String("deposits", "", "deposit address registry (default: deposits.json next to -signers)")
	to := fs.String("to", "", "BTCVM address to credit")
	b := bridgeFlags(fs) // for -cosigners, to tell the signers
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath, "to": *to}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	b.registry = registryFor(*depositsPath, *signersPath)
	if err := b.connect(&s, signers); err != nil {
		return err
	}
	destAddr, err := btcutil.DecodeAddress(*to, s.vmParams)
	if err != nil {
		return fmt.Errorf("-to must be a BTCVM %s address: %w", s.vmNetwork, err)
	}
	dest, err := destinationOf(destAddr)
	if err != nil {
		return err
	}
	addr, err := registerDeposit(b, dest)
	if err != nil {
		return err
	}
	printJSON(map[string]string{
		"depositAddress": addr.EncodeAddress(),
		"creditTo":       destAddr.EncodeAddress(),
		"redeemScript":   hex.EncodeToString(signers.depositRedeemScript(dest)),
	})
	return nil
}

func cmdBridge(args []string) error {
	var s settings
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	depositsPath := fs.String("deposits", "", "deposit address registry (default: deposits.json next to -signers)")
	signersPath := fs.String("signers", "", "peg signer set file")
	once := fs.Bool("once", false, "process what is pending, then exit")
	interval := fs.Duration("interval", 10*time.Second, "longest wait between polls; a new block on either chain starts the next one at once")
	rescan := fs.Bool("rescan", false, "rescan Bitcoin for past deposits when importing the peg address")
	s.register(fs)
	b := bridgeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := s.resolve(); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	lock, err := lockBridge(*signersPath)
	if err != nil {
		return fmt.Errorf("another bridge is using this signer set: %w", err)
	}
	defer lock.Close()
	if err := b.connect(&s, signers); err != nil {
		return err
	}
	b.registry = registryFor(*depositsPath, *signersPath)
	if err := watchPeg(b, *rescan); err != nil {
		return fmt.Errorf("importing the peg address into Bitcoin Core: %w", err)
	}

	lastErr := ""
	for {
		for {
			done, err := b.step()
			if err != nil {
				if !*once {
					// Log a standing condition, such as a pause, once.
					if err.Error() != lastErr {
						b.logf("error: %v", err)
						lastErr = err.Error()
					}
					break
				}
				return err
			}
			if lastErr != "" {
				b.logf("running again")
				lastErr = ""
			}
			if done == "" {
				break
			}
			b.logf("%s", done)
		}
		if *once {
			return nil
		}
		b.waitForBlock(*interval)
	}
}

func cmdAudit(args []string) error {
	var s settings
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	depositsPath := fs.String("deposits", "", "deposit address registry (default: deposits.json next to -signers)")
	signersPath := fs.String("signers", "", "peg signer set file (public keys are enough)")
	s.register(fs)
	b := bridgeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := s.resolve(); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	if err := b.connect(&s, signers); err != nil {
		return err
	}
	b.registry = registryFor(*depositsPath, *signersPath)
	if err := watchPeg(b, false); err != nil {
		return err
	}
	state, err := b.load()
	if err != nil {
		return err
	}
	a := b.audit(state)
	report := map[string]any{"solvent": a.solvent()}
	for name, v := range map[string]int64{
		"circulating": a.Circulating, "pendingPegIns": a.PendingPegIns,
		"pendingPegOuts": a.PendingPegOuts, "locked": a.Locked, "required": a.Required,
		"surplus": a.Surplus, "unclaimedOnBitcoin": a.UnclaimedOnBTC,
		"unclaimedOnBTCVM": a.UnclaimedOnVM,
	} {
		report[name] = formatBTC(v)
	}
	printJSON(report)
	if !a.solvent() {
		return errInsolvent
	}
	return nil
}

func parseOutPoint(s string) (wire.OutPoint, error) {
	var op wire.OutPoint
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return op, fmt.Errorf("deposit must be TXID:VOUT, got %q", s)
	}
	hash, err := chainhash.NewHashFromStr(s[:i])
	if err != nil {
		return op, err
	}
	vout, err := strconv.ParseUint(s[i+1:], 10, 32)
	if err != nil {
		return op, err
	}
	return wire.OutPoint{Hash: *hash, Index: uint32(vout)}, nil
}

// holdReason explains why the bridge has not credited a deposit.
func (b *bridge) holdReason(d deposit) string {
	switch {
	case d.valid && d.confirmations < b.confirmationsFor(d.value):
		return fmt.Sprintf("waiting for confirmations (%d of %d)", d.confirmations, b.confirmationsFor(d.value))
	case d.valid:
		return "waiting for room under -max-circulating"
	case d.value < b.minDeposit:
		return "below the minimum deposit"
	case b.maxDeposit > 0 && d.value > b.maxDeposit:
		return "above the maximum deposit"
	default:
		return "no BTCVM destination"
	}
}

func cmdRefund(args []string) error {
	var s settings
	fs := flag.NewFlagSet("refund", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file")
	depositsPath := fs.String("deposits", "", "deposit address registry (default: deposits.json next to -signers)")
	list := fs.Bool("list", false, "list deposits that are held or not yet credited")
	depositFlag := fs.String("deposit", "", "deposit to refund, as TXID:VOUT")
	to := fs.String("to", "", "Bitcoin address to refund to (default: the deposit's sender)")
	force := fs.Bool("force", false, "refund a deposit the bridge may still credit (stop the bridge first)")
	s.register(fs)
	b := bridgeFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := s.resolve(); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath}); err != nil {
		return err
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	if err := b.connect(&s, signers); err != nil {
		return err
	}
	b.registry = registryFor(*depositsPath, *signersPath)

	if *list {
		state, err := b.load()
		if err != nil {
			return err
		}
		rows := []map[string]string{}
		for _, d := range append(append([]deposit{}, state.held...), state.deposits...) {
			if _, done := state.released[d.outPoint]; done {
				continue
			}
			rows = append(rows, map[string]string{
				"deposit": d.outPoint.String(),
				"amount":  formatBTC(d.value),
				"status":  b.holdReason(d),
			})
		}
		printJSON(rows)
		return nil
	}

	if err := required(map[string]string{"deposit": *depositFlag}); err != nil {
		return err
	}
	op, err := parseOutPoint(*depositFlag)
	if err != nil {
		return err
	}
	var dest destination
	if *to != "" {
		addr, err := btcutil.DecodeAddress(*to, s.btcParams)
		if err != nil {
			return fmt.Errorf("-to must be a Bitcoin %s address: %w", s.btcNet, err)
		}
		if dest, err = destinationOf(addr); err != nil {
			return err
		}
	} else if dest, err = b.btc.(*btcChain).sender(op.Hash); err != nil {
		return fmt.Errorf("finding the deposit's sender (pass -to): %w", err)
	}
	// A refund and the running bridge must not act at once.
	lock, err := lockBridge(*signersPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	txid, err := b.refund(op, dest, *force)
	if err != nil {
		return err
	}
	destAddr, _ := dest.address(s.btcParams)
	printJSON(map[string]string{"refundTxid": txid.String(), "to": destAddr.EncodeAddress()})
	return nil
}

// cmdImportDeposit adds to the bridge's wallet a deposit paid to a personal
// deposit address before the address was registered: the wallet watches an
// address only from registration on, and a pruned node can't rescan far
// back. This node proves the transaction is in the chain (gettxoutproof);
// a pruned node needs -block, the hash of the block holding it, and must
// still have that block.
func cmdImportDeposit(args []string) error {
	var s settings
	fs := flag.NewFlagSet("import-deposit", flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file (public keys are enough)")
	txidFlag := fs.String("txid", "", "the deposit transaction")
	block := fs.String("block", "", "hash of the block holding it (needed on a pruned node without -txindex)")
	if err := parseFlags(fs, &s, args); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath, "txid": *txidFlag}); err != nil {
		return err
	}
	txid, err := chainhash.NewHashFromStr(*txidFlag)
	if err != nil {
		return fmt.Errorf("-txid: %w", err)
	}
	c := &btcChain{rpc: s.btcRPCClient()}
	if err := c.ensureWallet(); err != nil {
		return err
	}
	if err := c.importTx(*txid, *block); err != nil {
		return err
	}
	fmt.Printf("imported %v; the bridge sees it on its next pass if it pays a registered deposit address\n", txid)
	return nil
}
