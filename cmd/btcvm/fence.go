package main

// Fencing against a stale signing log. The log is what stops a signer
// signing two transactions for one action that could both confirm, so a
// signer must never run on a log older than what it has signed: one restored
// from a backup, copied to a clone, or lost and started empty. Its own chain
// nodes are the witness outside the log: every transaction it signed that
// reached either chain carries its signature. A missing log, or one that
// lacks a transaction the chains show it signed, quarantines the signer: it
// signs nothing until its operator restores the log and removes the marker.
//
// This catches a stale log once anything signed after it reaches a chain. A
// signature the coordinator holds back is not visible to it; the anchor rule
// (every transaction on a chain spends its oldest coin) is what keeps that
// from confirming alongside another.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2"
	"github.com/MetalBlockchain/btcvm/btcd/btcec/v2/ecdsa"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
	"github.com/MetalBlockchain/btcvm/btcd/txscript"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

var errQuarantined = errors.New("this signer is quarantined")

// unsignedHash is a transaction's txid with its signatures stripped: what
// the signing log records, whatever signatures the coordinator assembled.
func unsignedHash(tx *wire.MsgTx) chainhash.Hash {
	c := tx.Copy()
	for _, in := range c.TxIn {
		in.SignatureScript = nil
		in.Witness = nil
	}
	return c.TxHash()
}

// signedBy reports whether any input of tx carries a signature by pub over
// a peg witness script of set's lineage. value gives the value of the output
// an input spends; an input whose value is unknown can't be checked.
func signedBy(tx *wire.MsgTx, set *signerSet, pub *btcec.PublicKey, value func(wire.OutPoint) (int64, bool)) bool {
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for _, in := range tx.TxIn {
		fetcher.AddPrevOut(in.PreviousOutPoint, wire.NewTxOut(0, nil))
	}
	var hashes *txscript.TxSigHashes
	for i, in := range tx.TxIn {
		if len(in.Witness) < 2 {
			continue
		}
		script := in.Witness[len(in.Witness)-1]
		peg := false
		for _, s := range set.lineage() {
			if _, ok := s.pegWitness(script); ok && s.indexOf(pub) >= 0 {
				peg = true
			}
		}
		if !peg {
			continue
		}
		v, ok := value(in.PreviousOutPoint)
		if !ok {
			continue
		}
		if hashes == nil {
			hashes = txscript.NewTxSigHashes(tx, fetcher)
		}
		hash, err := txscript.CalcWitnessSigHash(script, hashes, txscript.SigHashAll, tx, i, v)
		if err != nil {
			continue
		}
		for _, item := range in.Witness[1 : len(in.Witness)-1] {
			if len(item) < 2 || txscript.SigHashType(item[len(item)-1]) != txscript.SigHashAll {
				continue
			}
			sig, err := ecdsa.ParseDERSignature(item[:len(item)-1])
			if err == nil && sig.Verify(hash, pub) {
				return true
			}
		}
	}
	return false
}

// unlogged returns the transactions on either chain, as s read them, that
// carry this signer's signature but are not in its signing log. Checked
// transactions are remembered: their bytes, and so their signatures, never
// change.
func (c *cosigner) unlogged(s *pegState) []string {
	values := map[wire.OutPoint]int64{}
	all := append(append([]chainTx{}, s.vmTxs...), s.btcTxs...)
	for _, t := range all {
		hash := t.tx.TxHash()
		for i, out := range t.tx.TxOut {
			values[wire.OutPoint{Hash: hash, Index: uint32(i)}] = out.Value
		}
	}
	value := func(op wire.OutPoint) (int64, bool) {
		v, ok := values[op]
		return v, ok
	}
	logged := c.log.txids()
	if c.mine == nil {
		c.mine = map[chainhash.Hash]bool{}
	}
	pub := c.key.PubKey()
	var missing []string
	for _, t := range all {
		txid := t.tx.TxHash()
		signed, known := c.mine[txid]
		if !known {
			signed = signedBy(t.tx, c.b.signers, pub, value)
			// An input whose spent output isn't listed yet may be checkable
			// later, so only a transaction found signed is remembered.
			if signed {
				c.mine[txid] = true
			}
		}
		if signed && !logged[unsignedHash(t.tx).String()] {
			missing = append(missing, txid.String())
		}
	}
	return missing
}

// adoptedKey is the log key of a transaction's action, read from its tags.
func adoptedKey(tx *wire.MsgTx) (string, bool) {
	var a action
	if op, ok := parseRelease(tx); ok {
		a = action{Kind: actionRelease, Deposit: op.String()}
	} else if id, ok := parsePayment(tx); ok {
		a = action{Kind: actionPayout, PegOut: id.String()}
	} else if op, ok := parseRefund(tx); ok {
		a = action{Kind: actionRefund, Deposit: op.String()}
	} else if isMigrate(tx) {
		return migrateKey(tx), true
	} else {
		return "", false
	}
	key, err := a.key()
	return key, err == nil
}

// adopt adds to c's log each transaction the chains show this key signed and
// the log lacks, under the action it did: for a key that signed before
// signers kept logs (the bridge once signed with every key itself). Only
// transactions in a block are adopted, dated when they were; one that isn't,
// or whose action its tags don't say, is left to investigate, and then
// nothing is written.
func (c *cosigner) adopt(s *pegState) ([]string, error) {
	missing := c.unlogged(s)
	if len(missing) == 0 {
		return nil, nil
	}
	byID := map[string]chainTx{}
	for _, t := range append(append([]chainTx{}, s.vmTxs...), s.btcTxs...) {
		byID[t.tx.TxHash().String()] = t
	}
	keys := make([]string, len(missing))
	for i, id := range missing {
		t := byID[id]
		if t.confirmations <= 0 {
			return nil, fmt.Errorf("%s is not in a block: an unlogged signature that may still confirm is never adopted; find out who signed it", id)
		}
		key, ok := adoptedKey(t.tx)
		if !ok {
			return nil, fmt.Errorf("%s: its tags don't say which action it did", id)
		}
		keys[i] = key
	}
	for i, id := range missing {
		t := byID[id]
		a := c.log.Actions[keys[i]]
		if a == nil {
			a = &loggedAction{First: t.time}
			c.log.Actions[keys[i]] = a
		}
		entry := loggedTx{Txid: unsignedHash(t.tx).String()}
		for _, in := range t.tx.TxIn {
			entry.Inputs = append(entry.Inputs, in.PreviousOutPoint.String())
		}
		a.Txs = append(a.Txs, entry)
	}
	return missing, c.log.write()
}

// txids is every transaction in the log, by its unsigned txid.
func (l *signingLog) txids() map[string]bool {
	ids := map[string]bool{}
	for _, a := range l.Actions {
		for _, t := range a.Txs {
			ids[t.Txid] = true
		}
	}
	return ids
}

// quarantinePath is the marker that keeps a signer from signing until its
// operator has restored the signing log.
func quarantinePath(logPath string) string { return logPath + ".quarantine" }

// quarantined returns the reason the signer is quarantined, or "".
func (c *cosigner) quarantined() string {
	raw, err := os.ReadFile(quarantinePath(c.log.path))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("the quarantine marker can't be read: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// quarantine writes the marker, so a restart stays quarantined too, and
// returns the error the signer refuses with.
func (c *cosigner) quarantine(reason string) error {
	path := quarantinePath(c.log.path)
	if err := os.WriteFile(path, []byte(reason+"\n"), 0o600); err != nil {
		c.b.logf("writing %s: %v", path, err)
	} else {
		_ = syncDir(filepath.Dir(path))
	}
	c.b.logf("QUARANTINED: %s", reason)
	return fmt.Errorf("%w: %s", errQuarantined, reason)
}

// fence quarantines the signer if the chains show it signed a transaction
// its log doesn't hold.
func (c *cosigner) fence(s *pegState) error {
	if reason := c.quarantined(); reason != "" {
		return fmt.Errorf("%w: %s (restore the signing log, then remove %s)", errQuarantined, reason, quarantinePath(c.log.path))
	}
	if missing := c.unlogged(s); len(missing) > 0 {
		return c.quarantine(fmt.Sprintf("the chains show this signer signed %s, which its signing log %s does not hold: "+
			"the log is older than what this key has signed (a restored backup or a copy)", strings.Join(missing, ", "), c.log.path))
	}
	return nil
}

// syncDir makes a rename or a new file in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// cmdSignerLog checks a signer's log against the chains, or starts one.
//
// check lists every transaction on either chain carrying the key's
// signature that the log lacks, and changes nothing: run it before
// upgrading a signer to a version that quarantines on them.
//
// adopt adds to the log (starting it if need be) what the key signed before
// signers kept logs: every transaction in a block that carries its signature
// and the log lacks, under the action its tags name. It adopts nothing if
// any such transaction isn't in a block, or doesn't say its action.
//
// init starts a log for a key that has none: a key made before signer keys
// came with a log, that has never signed. It refuses if the chains show a
// transaction the key signed: that key's log was lost, and must be restored
// from a backup instead.
func cmdSignerLog(args []string) error {
	const usage = "usage: btcvm signer-log check|init|adopt -signers FILE -key-file FILE [-log FILE]"
	if len(args) == 0 || (args[0] != "init" && args[0] != "check" && args[0] != "adopt") {
		return errors.New(usage)
	}
	step := args[0]
	var s settings
	fs := flag.NewFlagSet("signer-log "+step, flag.ExitOnError)
	signersPath := fs.String("signers", "", "peg signer set file, with public keys only")
	keyFile := fs.String("key-file", "", "this signer's private key")
	depositsPath := fs.String("deposits", "", "this signer's deposit address registry (default: deposits.json next to -signers)")
	logPath := fs.String("log", "", "signing log (default: signing-log.json next to -key-file)")
	s.register(fs)
	b := bridgeFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if err := s.resolve(); err != nil {
		return err
	}
	if err := required(map[string]string{"signers": *signersPath, "key-file": *keyFile}); err != nil {
		return err
	}
	if *logPath == "" {
		*logPath = filepath.Join(filepath.Dir(*keyFile), "signing-log.json")
	}
	log := &signingLog{path: *logPath, Actions: map[string]*loggedAction{}}
	if step == "init" {
		if _, err := os.Lstat(*logPath); err == nil {
			return fmt.Errorf("%s already exists", *logPath)
		}
	} else if _, err := os.Lstat(*logPath); err == nil {
		// check: a missing log reads as empty, to show what init would find.
		if log, err = openSigningLog(*logPath); err != nil {
			return err
		}
	}
	signers, err := readSignerSet(*signersPath)
	if err != nil {
		return err
	}
	key, err := readKeyFile(*keyFile)
	if err != nil {
		return err
	}
	if signers.indexOf(key.PubKey()) < 0 && signers.retired(key.PubKey()) == nil {
		return errors.New("this key is not in the signer set")
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
	c := &cosigner{b: b, key: key, log: log}
	missing := c.unlogged(state)
	if step == "adopt" {
		adopted, err := c.adopt(state)
		if err != nil {
			return err
		}
		printJSON(map[string]any{"signingLog": *logPath, "adopted": adopted})
		return nil
	}
	if step == "check" {
		_, statErr := os.Lstat(*logPath)
		printJSON(map[string]any{"signingLog": *logPath, "exists": statErr == nil, "quarantined": c.quarantined(), "unlogged": missing})
		if len(missing) > 0 {
			return fmt.Errorf("the log lacks %d transaction(s) the chains show this key signed", len(missing))
		}
		return nil
	}
	if len(missing) > 0 {
		return fmt.Errorf("the chains show this key signed %s: its signing log was lost; restore it from a backup",
			strings.Join(missing, ", "))
	}
	if _, err := createSigningLog(*logPath); err != nil {
		return err
	}
	printJSON(map[string]string{"signingLog": *logPath})
	return nil
}
