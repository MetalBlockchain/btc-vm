package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2/ecdsa"
	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"github.com/MetalBlockchain/btcvm/btcd/txscript"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// signerSet is the m-of-n multisig that holds the peg: BTC locked on
// Bitcoin and the reserve on BTCVM are both locked to the same witness
// script, so they share one P2WSH address (bc1q...) on both chains.
//
// A signers file holds public keys and, for development, the private keys
// too. In production each signer keeps its own key and signs separately.
type signerSet struct {
	Required   int      `json:"required"`
	PublicKeys []string `json:"publicKeys"`
	// PrivateKeys holds hex private keys this process may sign with.
	PrivateKeys []string `json:"privateKeys,omitempty"`

	// Set by a signer ceremony (btcvm signer-setup); absent in older sets.
	// Networks, Operators, CoordinatorKey and Policy are what every signer
	// agrees to, and the fingerprint covers them.
	Networks       *setNetworks   `json:"networks,omitempty"`
	Operators      []operatorCard `json:"operators,omitempty"`
	CoordinatorKey string         `json:"coordinatorKey,omitempty"` // hex; signs every request to the signers
	Policy         *pegPolicy     `json:"policy,omitempty"`
	// Previous are the sets this one replaced, newest first. Coins still
	// held by them are the peg's too: their signers, now retired, sign only
	// transactions moving those coins to this set (see rotate.go).
	Previous []priorSet `json:"previous,omitempty"`

	path         string // the file it was read from, if any
	prior        []*signerSet
	redeemScript []byte
	pubKeys      []*btcec.PublicKey
	privKeys     []*btcec.PrivateKey
	coordKey     *btcec.PublicKey
}

// priorSet is a signer set a later one replaced: its keys and threshold,
// which fix its scripts and addresses.
type priorSet struct {
	Required   int      `json:"required"`
	PublicKeys []string `json:"publicKeys"`
}

// lineage is the set and the sets it replaced, newest first.
func (s *signerSet) lineage() []*signerSet {
	return append([]*signerSet{s}, s.prior...)
}

// retired is the prior set pub belongs to, or nil if it belongs to none.
func (s *signerSet) retired(pub *btcec.PublicKey) *signerSet {
	for _, p := range s.prior {
		if p.indexOf(pub) >= 0 {
			return p
		}
	}
	return nil
}

type setNetworks struct {
	Bitcoin string `json:"bitcoin"`
	BTCVM   string `json:"btcvm"`
}

// pegPolicy is the bridge's policy, in satoshis. Signers rebuild transactions
// with it, so coordinator and signers must agree on it exactly.
type pegPolicy struct {
	Confirmations int64 `json:"confirmations"`
	VMFee         int64 `json:"vmFee"`
	// Bitcoin payouts pay a fee rate within these bounds, in sat/vB,
	// out of the payout.
	MinFeeRate     int64 `json:"minFeeRate"`
	MaxFeeRate     int64 `json:"maxFeeRate"`
	MinDeposit     int64 `json:"minDeposit"`
	MinPegOut      int64 `json:"minPegOut"`
	MaxDeposit     int64 `json:"maxDeposit"`
	MaxCirculating int64 `json:"maxCirculating"`
	// Fewer confirmations for smaller deposits; omitted when there are
	// none, so sets made before tiers keep their fingerprint.
	ConfirmationTiers []confirmationTier `json:"confirmationTiers,omitempty"`
}

// fingerprint identifies everything the signers agree to. Each signer reads
// it out to the others over a separate channel before joining.
func (s *signerSet) fingerprint() string {
	agreed, _ := json.Marshal(struct {
		Required       int            `json:"required"`
		PublicKeys     []string       `json:"publicKeys"`
		Networks       *setNetworks   `json:"networks"`
		Operators      []operatorCard `json:"operators"`
		CoordinatorKey string         `json:"coordinatorKey"`
		Policy         *pegPolicy     `json:"policy"`
		// Omitted when empty, so sets made before rotation keep their
		// fingerprint.
		Previous []priorSet `json:"previous,omitempty"`
	}{s.Required, s.PublicKeys, s.Networks, s.Operators, s.CoordinatorKey, s.Policy, s.Previous})
	sum := sha256.Sum256(agreed)
	h := hex.EncodeToString(sum[:10])
	return strings.Join([]string{h[0:4], h[4:8], h[8:12], h[12:16], h[16:20]}, "-")
}

// refuseKeys fails if the set holds private keys, for processes that
// never sign: the web server and the monitor face the internet or run
// unattended, and holding keys there would put the peg behind them.
func (s *signerSet) refuseKeys(process string, allowed bool) error {
	if len(s.PrivateKeys) > 0 && !allowed {
		return fmt.Errorf("%s never signs, so its signer set must hold no private keys: give it a public copy "+
			"(jq 'del(.privateKeys)' signers.json > signers.public.json), or -allow-signing-keys for local development", process)
	}
	return nil
}

// publicCopy is the set without private keys.
func (s *signerSet) publicCopy() *signerSet {
	c := *s
	c.PrivateKeys, c.privKeys = nil, nil
	return &c
}

func newSignerSet(required, total int) (*signerSet, error) {
	if required < 1 || required > total || total > 15 {
		return nil, fmt.Errorf("need 1 <= required (%d) <= total (%d) <= 15", required, total)
	}
	s := &signerSet{Required: required}
	for i := 0; i < total; i++ {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return nil, err
		}
		key, _ := btcec.PrivKeyFromBytes(secret[:])
		s.PublicKeys = append(s.PublicKeys, hex.EncodeToString(key.PubKey().SerializeCompressed()))
		s.PrivateKeys = append(s.PrivateKeys, hex.EncodeToString(secret[:]))
	}
	return s, s.load()
}

func readSignerSet(path string) (*signerSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s signerSet
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.path = path
	return &s, s.load()
}

func (s *signerSet) write(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// load parses the keys and builds the redeem script.
func (s *signerSet) load() error {
	var addrs []*btcutil.AddressPubKey
	for _, h := range s.PublicKeys {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("public key %s: %w", h, err)
		}
		pub, err := btcec.ParsePubKey(raw)
		if err != nil {
			return fmt.Errorf("public key %s: %w", h, err)
		}
		s.pubKeys = append(s.pubKeys, pub)
		// The network only affects encoding, which the script does not use.
		addr, err := btcutil.NewAddressPubKey(pub.SerializeCompressed(), &chaincfg.MainNetParams)
		if err != nil {
			return err
		}
		addrs = append(addrs, addr)
	}
	for _, h := range s.PrivateKeys {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return errors.New("private keys must be 32-byte hex")
		}
		key, _ := btcec.PrivKeyFromBytes(raw)
		s.privKeys = append(s.privKeys, key)
	}
	if s.CoordinatorKey != "" {
		raw, err := hex.DecodeString(s.CoordinatorKey)
		if err != nil {
			return fmt.Errorf("coordinator key: %w", err)
		}
		if s.coordKey, err = btcec.ParsePubKey(raw); err != nil {
			return fmt.Errorf("coordinator key: %w", err)
		}
	}
	if s.Required < 1 || s.Required > len(addrs) {
		return fmt.Errorf("required signatures %d out of range for %d keys", s.Required, len(addrs))
	}

	var err error
	if s.redeemScript, err = txscript.MultiSigScript(addrs, s.Required); err != nil {
		return err
	}
	s.prior = nil
	seen := map[string]bool{string(s.redeemScript): true}
	for i, p := range s.Previous {
		prior := &signerSet{Required: p.Required, PublicKeys: p.PublicKeys}
		if err := prior.load(); err != nil {
			return fmt.Errorf("previous set %d: %w", i+1, err)
		}
		if seen[string(prior.redeemScript)] {
			return fmt.Errorf("previous set %d repeats an earlier set", i+1)
		}
		seen[string(prior.redeemScript)] = true
		s.prior = append(s.prior, prior)
	}
	return nil
}

// address returns the peg P2WSH address on the network params encode.
func (s *signerSet) address(params *chaincfg.Params) (btcutil.Address, error) {
	return s.destination().address(params)
}

func (s *signerSet) pkScript() []byte {
	return p2wshScript(s.redeemScript)
}

func (s *signerSet) destination() destination {
	return p2wshDestination(s.redeemScript)
}

// depositRedeemScript is the witness script of dest's personal deposit
// address: <kind || program> OP_DROP followed by the peg multisig. Only the
// signers can spend it, exactly as with the peg address, but each BTCVM
// address gets its own Bitcoin address, so deposits need no OP_RETURN and
// any wallet can make them.
func (s *signerSet) depositRedeemScript(dest destination) []byte {
	prefix, _ := txscript.NewScriptBuilder().AddData(dest.bytes()).AddOp(txscript.OP_DROP).Script()
	return append(prefix, s.redeemScript...)
}

func (s *signerSet) depositAddress(dest destination, params *chaincfg.Params) (btcutil.Address, error) {
	return p2wshDestination(s.depositRedeemScript(dest)).address(params)
}

func p2wshDestination(witnessScript []byte) destination {
	sum := sha256.Sum256(witnessScript)
	d, _ := newDestination(destP2WSH, sum[:])
	return d
}

func p2wshScript(witnessScript []byte) []byte {
	return p2wshDestination(witnessScript).pkScript()
}

// spent is what signing an input needs to know about the output it spends:
// its witness script and value, both committed to by a BIP143 signature.
type spent struct {
	script []byte
	value  int64
}

// sigHashes precomputes tx's BIP143 hashes.
func sigHashes(tx *wire.MsgTx, prev []spent) *txscript.TxSigHashes {
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, in := range tx.TxIn {
		fetcher.AddPrevOut(in.PreviousOutPoint, wire.NewTxOut(prev[i].value, p2wshScript(prev[i].script)))
	}
	return txscript.NewTxSigHashes(tx, fetcher)
}

// sign signs every input of tx with the private keys this process holds.
// prev[i] is the peg output input i spends.
func (s *signerSet) sign(tx *wire.MsgTx, prev []spent) error {
	sigs := map[int][][]byte{}
	for i, pub := range s.pubKeys {
		for _, key := range s.privKeys {
			if key.PubKey().IsEqual(pub) {
				inputSigs, err := signInputs(tx, prev, key)
				if err != nil {
					return err
				}
				sigs[i] = inputSigs
				break
			}
		}
	}
	return s.assemble(tx, prev, sigs)
}

// spendsPeg reports whether tx spends a peg output: the peg address or a
// personal deposit address. It reads the witness scripts, which consensus
// has checked against the outputs spent, so it needs no record of those
// outputs: a signer that never saw a deposit still knows a payout that
// spends it for what it is.
func (s *signerSet) spendsPeg(tx *wire.MsgTx) bool {
	for _, in := range tx.TxIn {
		if len(in.Witness) == 0 {
			continue
		}
		for _, set := range s.lineage() {
			if _, ok := set.pegWitness(in.Witness[len(in.Witness)-1]); ok {
				return true
			}
		}
	}
	return false
}

// pegWitness reports whether script is the peg's witness script, or a
// personal deposit address's; for a deposit address it also returns the
// destination it credits.
func (s *signerSet) pegWitness(script []byte) (*destination, bool) {
	if bytes.Equal(script, s.redeemScript) {
		return nil, true
	}
	if len(script) < 2 || !bytes.HasSuffix(script, s.redeemScript) {
		return nil, false
	}
	prefix := script[:len(script)-len(s.redeemScript)]
	n := int(prefix[0])
	if len(prefix) != 1+n+1 || prefix[len(prefix)-1] != txscript.OP_DROP {
		return nil, false
	}
	d, err := decodeDestination(prefix[1 : 1+n])
	if err != nil {
		return nil, false
	}
	return &d, true
}

// indexOf returns the position of pub in the set, or -1.
func (s *signerSet) indexOf(pub *btcec.PublicKey) int {
	for i, p := range s.pubKeys {
		if p.IsEqual(pub) {
			return i
		}
	}
	return -1
}

// signInputs returns key's signature, with its sighash byte, for each input
// of tx. prev[i] is the output input i spends.
func signInputs(tx *wire.MsgTx, prev []spent, key *btcec.PrivateKey) ([][]byte, error) {
	if len(prev) != len(tx.TxIn) {
		return nil, fmt.Errorf("have %d spent outputs for %d inputs", len(prev), len(tx.TxIn))
	}
	hashes := sigHashes(tx, prev)
	sigs := make([][]byte, len(tx.TxIn))
	for i, p := range prev {
		sig, err := txscript.RawTxInWitnessSignature(tx, hashes, i, p.value, p.script, txscript.SigHashAll, key)
		if err != nil {
			return nil, fmt.Errorf("signing input %d: %w", i, err)
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// verifyInputs checks sigs are the signer at index's signatures of every
// input of tx.
func (s *signerSet) verifyInputs(tx *wire.MsgTx, prev []spent, index int, sigs [][]byte) error {
	if index < 0 || index >= len(s.pubKeys) {
		return fmt.Errorf("no signer %d", index)
	}
	if len(sigs) != len(tx.TxIn) || len(prev) != len(tx.TxIn) {
		return fmt.Errorf("have %d signatures for %d inputs", len(sigs), len(tx.TxIn))
	}
	hashes := sigHashes(tx, prev)
	for i, sig := range sigs {
		if len(sig) < 2 || txscript.SigHashType(sig[len(sig)-1]) != txscript.SigHashAll {
			return fmt.Errorf("input %d: not a SIGHASH_ALL signature", i)
		}
		parsed, err := ecdsa.ParseDERSignature(sig[:len(sig)-1])
		if err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
		hash, err := txscript.CalcWitnessSigHash(prev[i].script, hashes, txscript.SigHashAll, tx, i, prev[i].value)
		if err != nil {
			return err
		}
		if !parsed.Verify(hash, s.pubKeys[index]) {
			return fmt.Errorf("input %d: signature does not verify", i)
		}
	}
	return nil
}

// assemble completes tx's witnesses from the signatures of at least
// Required signers, keyed by their position in the set.
func (s *signerSet) assemble(tx *wire.MsgTx, prev []spent, sigs map[int][][]byte) error {
	if len(prev) != len(tx.TxIn) {
		return fmt.Errorf("have %d spent outputs for %d inputs", len(prev), len(tx.TxIn))
	}
	// CHECKMULTISIG needs signatures in public key order.
	var signers []int
	for i := range s.pubKeys {
		if _, ok := sigs[i]; ok && len(signers) < s.Required {
			signers = append(signers, i)
		}
	}
	if len(signers) < s.Required {
		return fmt.Errorf("have signatures from %d signers, need %d", len(signers), s.Required)
	}
	for i, p := range prev {
		witness := wire.TxWitness{nil} // CHECKMULTISIG's extra pop
		for _, signer := range signers {
			witness = append(witness, sigs[signer][i])
		}
		tx.TxIn[i].Witness = append(witness, p.script)
		tx.TxIn[i].SignatureScript = nil
	}
	return nil
}

// witnessVSize is a transaction's virtual size once its inputs, each
// spending a peg output with a witness script of the given size, carry
// Required signatures. Signatures are taken at their largest, so the size
// is never under the real one, and it depends only on the unsigned
// transaction: coordinator and signers compute the same fee from it.
func (s *signerSet) witnessVSize(tx *wire.MsgTx, scriptSizes []int) int64 {
	base := int64(tx.SerializeSizeStripped())
	weight := base * 4
	weight += 2 // segwit marker and flag
	for _, n := range scriptSizes {
		w := wire.VarIntSerializeSize(uint64(s.Required + 2)) // item count
		w++                                                   // empty dummy
		w += s.Required * (1 + 73)                            // signatures, 73 bytes at most
		w += wire.VarIntSerializeSize(uint64(n)) + n          // witness script
		weight += int64(w)
	}
	return (weight + 3) / 4
}
