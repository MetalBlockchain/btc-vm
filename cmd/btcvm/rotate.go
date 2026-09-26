package main

// Key rotation. A new signer set names the sets it replaces (Previous), so
// the bridge sees the whole peg: coins still held by an earlier set on
// Bitcoin, and its reserve on BTCVM. Once the coordinator runs with the new
// set, each pass moves any coin an earlier set still holds to the new set,
// and only there:
//
//   - the reserve on BTCVM, to the new reserve;
//   - on Bitcoin, a deposit to an earlier set's address that was never
//     credited, to the new set's personal deposit address for the same
//     destination, where the new set credits it once;
//   - every other Bitcoin coin (backing for BTC already credited, change),
//     to the new peg address.
//
// A coin already credited must never land at a personal deposit address:
// the new set would credit it again. Each retired signer checks where every
// coin goes against its own record of what was credited, and signs nothing
// else. Moving costs a network fee; signers sign only if the peg's surplus
// covers it, so the audit stays solvent. The same pass later moves deposits
// that arrive at the old addresses, for as long as the retired signers run.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

const actionMigrate = "migrate" // move an earlier set's coins to the current set

// tagMigrate marks a move, with the hash of the witness script it moves to.
var tagMigrate = []byte("BVMM")

// maxMigrateInputs bounds one move, so it stays a standard transaction.
const maxMigrateInputs = 100

func encodeMigrate(to []byte) []byte {
	sum := sha256.Sum256(to)
	return append(append([]byte{}, tagMigrate...), sum[:]...)
}

// setOfScript is the set in b's lineage whose peg script is script (the
// reserve on BTCVM, the peg address on Bitcoin), or nil.
func (b *bridge) setOfScript(script []byte) *signerSet {
	for _, set := range b.signers.lineage() {
		if bytes.Equal(set.pkScript(), script) {
			return set
		}
	}
	return nil
}

// successor is the current set's script a coin of an earlier set moves to:
// an uncredited deposit to its destination's personal deposit address, and
// anything else to the peg address (the reserve, on BTCVM).
func (b *bridge) successor(s *pegState, chain string, u utxo) []byte {
	if chain == chainBitcoin {
		for _, d := range s.legacyDeposits {
			if d.outPoint == u.outPoint && d.hasDest {
				return p2wshScript(b.signers.depositRedeemScript(d.dest))
			}
		}
	}
	return b.signers.pkScript()
}

// buildMigrate is the unsigned move of inputs, all held by set, to the
// scripts successors name, one output per script (sorted) with the fee
// taken from the largest, tagged with the current set's script. Signers
// rebuild it to check a proposal, so it depends only on its arguments.
func (b *bridge) buildMigrate(chain string, set *signerSet, inputs []utxo, prev []spent, successors [][]byte, feeRate int64) (*wire.MsgTx, error) {
	if len(inputs) == 0 || len(inputs) != len(prev) || len(inputs) != len(successors) {
		return nil, errors.New("nothing to move")
	}
	tx := wire.NewMsgTx(2)
	scriptSizes := make([]int, len(inputs))
	totals := map[string]int64{}
	for i, u := range inputs {
		in := wire.NewTxIn(&u.outPoint, nil, nil)
		in.Sequence = wire.MaxTxInSequenceNum - 2 // BIP125: replaceable
		tx.AddTxIn(in)
		scriptSizes[i] = len(prev[i].script)
		totals[string(successors[i])] += prev[i].value
	}
	scripts := make([]string, 0, len(totals))
	for script := range totals {
		scripts = append(scripts, script)
	}
	sort.Strings(scripts)
	largest := 0
	for i, script := range scripts {
		tx.AddTxOut(wire.NewTxOut(totals[script], []byte(script)))
		if totals[script] > totals[scripts[largest]] {
			largest = i
		}
	}
	tx.AddTxOut(nullData(encodeMigrate(b.signers.redeemScript)))

	fee, dust := b.vmFee, int64(1)
	if chain == chainBitcoin {
		fee, dust = feeRate*set.witnessVSize(tx, scriptSizes), pegDust
	}
	tx.TxOut[largest].Value -= fee
	for _, out := range tx.TxOut[:len(scripts)] {
		if out.Value < dust {
			return nil, fmt.Errorf("the %s BTC fee would leave an output below %s BTC", formatBTC(fee), formatBTC(dust))
		}
	}
	return tx, nil
}

// solventAfterMove reports whether the peg stays solvent once tx, a move of
// coins that prev describes, confirms. The fee leaves the peg, so it needs
// the surplus, unless it comes out of a creditable deposit's own output:
// then what is owed drops with it. (On BTCVM the fee leaves the reserve and
// circulates, so it always needs the surplus.)
func (b *bridge) solventAfterMove(s *pegState, chain string, tx *wire.MsgTx, prev []spent) error {
	fee := migrateFee(tx, prev)
	a := b.audit(s)
	need := fee
	if chain == chainBitcoin {
		owedTo := map[string]int64{} // new deposit script -> creditable value moved there
		for _, d := range s.legacyDeposits {
			if d.valid && d.hasDest {
				owedTo[string(p2wshScript(b.signers.depositRedeemScript(d.dest)))] += d.value
			}
		}
		for _, out := range tx.TxOut {
			if moved, ok := owedTo[string(out.PkScript)]; ok && out.Value < moved {
				// This output paid the fee: what is owed shrinks by as much,
				// if it stays creditable.
				if b.depositInRange(out.Value) {
					need = 0
				}
			}
		}
	}
	if need > a.Surplus {
		return fmt.Errorf("the %s BTC fee is more than the peg's surplus of %s BTC; top up the surplus first (docs/ROTATION.md)",
			formatBTC(fee), formatBTC(a.Surplus))
	}
	return nil
}

// migrateFee is what tx pays in fees, given the values it spends.
func migrateFee(tx *wire.MsgTx, prev []spent) int64 {
	var fee int64
	for _, p := range prev {
		fee += p.value
	}
	for _, out := range tx.TxOut {
		fee -= out.Value
	}
	return fee
}

// legacyBySet groups an earlier set's coins by the set holding them, oldest
// first, and returns the sets in lineage order.
func (b *bridge) legacyBySet(s *pegState, coins []utxo) ([]*signerSet, map[*signerSet][]utxo) {
	by := map[*signerSet][]utxo{}
	for _, u := range coins {
		set := s.setFor[string(u.pkScript)]
		if set == nil {
			set = b.setOfScript(u.pkScript)
		}
		if set == nil || set == b.signers {
			continue
		}
		by[set] = append(by[set], u)
	}
	var sets []*signerSet
	for _, set := range b.signers.prior {
		coins := by[set]
		if len(coins) == 0 {
			continue
		}
		sort.Slice(coins, func(i, j int) bool {
			if coins[i].confirmations != coins[j].confirmations {
				return coins[i].confirmations > coins[j].confirmations
			}
			return outPointLess(coins[i].outPoint, coins[j].outPoint)
		})
		if len(coins) > maxMigrateInputs {
			coins = coins[:maxMigrateInputs]
		}
		by[set] = coins
		sets = append(sets, set)
	}
	return sets, by
}

// migrate moves what earlier sets still hold to the current set: the
// reserve on BTCVM, then the coins on Bitcoin. It returns what it did.
func (b *bridge) migrate(s *pegState) ([]string, error) {
	if len(b.signers.prior) == 0 {
		return nil, nil
	}
	var did []string
	// Whether a deposit was credited decides where its coin goes, so
	// nothing moves while a release could still be pending.
	if s.vmPending {
		return nil, nil
	}
	sets, by := b.legacyBySet(s, s.legacyReserve)
	for _, set := range sets {
		txid, err := b.proposeMigrate(s, chainBTCVM, set, by[set], 0)
		if err != nil {
			return did, fmt.Errorf("moving the reserve of set %s: %w", set.fingerprint(), err)
		}
		did = append(did, fmt.Sprintf("moved %d reserve outputs to the new set in %v", len(by[set]), txid))
	}
	if len(did) > 0 {
		return did, nil // the Bitcoin side waits for the reserve to settle
	}
	sets, by = b.legacyBySet(s, s.legacyUTXOs)
	for _, set := range sets {
		if b.moving(s, set) {
			continue // one move at a time per set
		}
		rate := b.currentFeeRate()
		txid, err := b.proposeMigrate(s, chainBitcoin, set, by[set], rate)
		if err != nil {
			return did, fmt.Errorf("moving Bitcoin held by set %s: %w", set.fingerprint(), err)
		}
		did = append(did, fmt.Sprintf("moved %d Bitcoin outputs to the new set in %v", len(by[set]), txid))
	}
	return did, nil
}

// moving reports whether a move of set's Bitcoin is still unconfirmed.
func (b *bridge) moving(s *pegState, set *signerSet) bool {
	for _, t := range s.unconfirmed {
		if !isMigrate(t.tx) {
			continue
		}
		for _, in := range t.tx.TxIn {
			if len(in.Witness) > 0 {
				w := in.Witness[len(in.Witness)-1]
				if _, ok := set.pegWitness(w); ok {
					return true
				}
			}
		}
	}
	return false
}

func isMigrate(tx *wire.MsgTx) bool {
	tag, _, ok := opReturnData(tx)
	return ok && bytes.Equal(tag, tagMigrate)
}

func (b *bridge) proposeMigrate(s *pegState, chain string, set *signerSet, coins []utxo, rate int64) (string, error) {
	var prev []spent
	var register []destination
	if chain == chainBitcoin {
		var err error
		if prev, register, err = s.pegSpends(coins); err != nil {
			return "", err
		}
	} else {
		for _, u := range coins {
			prev = append(prev, spent{script: set.redeemScript, value: u.value})
		}
	}
	successors := make([][]byte, len(coins))
	for i, u := range coins {
		successors[i] = b.successor(s, chain, u)
	}
	tx, err := b.buildMigrate(chain, set, coins, prev, successors, rate)
	if err != nil {
		return "", err
	}
	if err := b.solventAfterMove(s, chain, tx, prev); err != nil {
		return "", err
	}
	p := &proposal{Chain: chain, tx: tx, prev: prev, Register: register, FeeRate: rate, set: set,
		Action: action{Kind: actionMigrate, Deposit: coins[0].outPoint.String()}}
	if err := b.authorize(p); err != nil {
		return "", err
	}
	send := b.vm.send
	if chain == chainBitcoin {
		send = b.btc.send
	}
	txid, err := send(tx)
	return txid.String(), err
}

// checkMigrate is a retired signer's check of a proposed move: every input
// is a confirmed coin its own set holds, each goes where successor says, the
// fee is within policy, and the peg's surplus covers it.
func (c *cosigner) checkMigrate(s *pegState, req signRequest, tx *wire.MsgTx, pick func([]utxo) ([]utxo, int64, error)) (*wire.MsgTx, []spent, map[wire.OutPoint]bool, error) {
	b := c.b
	set := b.signers.retired(c.key.PubKey())
	if set == nil {
		return nil, nil, nil, errors.New("only a signer of a replaced set moves its coins")
	}
	if s.vmPending {
		return nil, nil, nil, errors.New("a release is pending on BTCVM; moving waits until it is final")
	}
	coins := s.legacyUTXOs
	rate := req.FeeRate
	if req.Chain == chainBTCVM {
		coins, rate = s.legacyReserve, 0
	} else if rate < b.minFeeRate || rate > b.maxFeeRate {
		return nil, nil, nil, fmt.Errorf("fee rate %d sat/vB is outside %d-%d", rate, b.minFeeRate, b.maxFeeRate)
	}
	var mine []utxo
	unspent := map[wire.OutPoint]bool{}
	for _, u := range coins {
		unspent[u.outPoint] = true
		if s.setFor[string(u.pkScript)] == set || b.setOfScript(u.pkScript) == set {
			mine = append(mine, u)
		}
	}
	inputs, _, err := pick(mine)
	if err != nil {
		return nil, nil, nil, err
	}
	var prev []spent
	if req.Chain == chainBitcoin {
		if prev, _, err = s.pegSpends(inputs); err != nil {
			return nil, nil, nil, err
		}
	} else {
		for _, u := range inputs {
			prev = append(prev, spent{script: set.redeemScript, value: u.value})
		}
	}
	successors := make([][]byte, len(inputs))
	for i, u := range inputs {
		successors[i] = b.successor(s, req.Chain, u)
	}
	want, err := b.buildMigrate(req.Chain, set, inputs, prev, successors, rate)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := b.solventAfterMove(s, req.Chain, want, prev); err != nil {
		return nil, nil, nil, err
	}
	return want, prev, unspent, nil
}
