package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MetalBlockchain/btcvm/btcd/btcutil"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg"
	"github.com/MetalBlockchain/btcvm/btcd/chaincfg/chainhash"
	"github.com/MetalBlockchain/btcvm/btcd/wire"
)

// bridge moves BTC between Bitcoin and BTCVM.
//
// Peg-in: a Bitcoin deposit to the peg address carrying a BVMD tag is, once
// it has depositConfirmations, credited on BTCVM from the peg reserve
// by a release tagged BVMI. Peg-out: a BTCVM payment to the reserve
// carrying a BVMO tag is paid out on Bitcoin from the peg address by a
// payment tagged BVMR. BTCVM transactions are final once in a block.
//
// All state is read back from the two chains, so a restarted bridge picks up
// where it left off, and nothing is ever credited or paid twice. Release and
// payment tags are only trusted on transactions that spend peg outputs,
// which only the signers can create.
type bridge struct {
	signers *signerSet
	// cosigners are remote signers, each holding one key, asked to sign
	// what this process cannot sign with the keys in signers.
	cosigners     []*remoteSigner
	cosignersPath string
	// told records, per signer URL, the deposit destinations that signer
	// has confirmed it watches (see syncSigners).
	told               map[string]map[string]bool
	coordinatorKeyPath string
	flags              *flag.FlagSet    // the policy flags, if from bridgeFlags
	registry           *depositRegistry // personal deposit addresses; may be nil
	vm, btc            chain
	vmParams           *chaincfg.Params
	btcParams          *chaincfg.Params

	depositConfirmations int64
	confirmationTiers    []confirmationTier // smaller deposits need fewer; see tiers.go
	tiersFlag            string
	vmFee                int64 // deducted from each credit to pay the VM fee
	// Payouts on Bitcoin pay a fee rate, in sat/vB, from the fee source,
	// kept within these bounds; the fee comes out of the payment.
	minFeeRate, maxFeeRate int64
	feeRate                func() (int64, error) // current rate; nil: minFeeRate
	// bumpAfter is how long a payout may wait unconfirmed before the bridge
	// replaces it with one paying a higher fee (BIP125).
	bumpAfter  time.Duration
	minDeposit int64
	minPegOut  int64
	// maxDeposit and maxCirculating cap what the bridge will credit, so a
	// bug or a compromised signer can only lose so much. Deposits above
	// maxDeposit are never credited; a deposit that would take circulating
	// BTC past maxCirculating waits. Either stays locked on Bitcoin for a
	// manual refund. Zero means no cap.
	maxDeposit     int64
	maxCirculating int64

	logf func(format string, args ...any)
}

type deposit struct {
	time          int64
	outPoint      wire.OutPoint
	value         int64
	dest          destination
	valid         bool // has a destination and meets the minimum
	confirmations int64
	// hasDest: the destination is known (a personal deposit address, or a
	// BVMD tag), whether or not the deposit is valid.
	hasDest bool
	// legacy: paid to an address of a set this one replaced.
	legacy bool
}

type pegOut struct {
	time          int64
	txid          chainhash.Hash
	value         int64
	dest          destination
	valid         bool
	confirmations int64
}

// pegState is everything the bridge knows, read from both chains.
type pegState struct {
	redeemFor   map[string][]byte      // Bitcoin peg output script -> redeem script
	depositDest map[string]destination // personal deposit script -> its destination
	setFor      map[string]*signerSet  // Bitcoin peg output script -> the set holding it
	// legacyDeposits are deposits to an earlier set's addresses not
	// credited or refunded: they are moved to this set's address for the
	// same destination, and credited there (rotate.go).
	legacyDeposits []deposit
	reserveCreated int64 // reserve paid in by consensus (coinbases)
	reserveUnspent int64 // reserve still held
	reserveUTXOs   []utxo
	// legacyReserve and legacyUTXOs are confirmed coins still held by a
	// set this one replaced, on BTCVM and on Bitcoin. They back the peg
	// like any other, but only their own set's signers can move them, and
	// only to this set (rotate.go).
	legacyReserve []utxo
	legacyUTXOs   []utxo
	// reserveAnchor and pegAnchor are the oldest confirmed coins of the
	// reserve and the peg, whether or not a transaction in a mempool spends
	// them. Every release spends reserveAnchor, and every payout and refund
	// spends pegAnchor, so any two transactions the signers sign on one chain
	// conflict and at most one confirms (see oldestCoin).
	reserveAnchor *utxo
	pegAnchor     *utxo
	vmPending     bool                             // a release is still in the VM mempool
	released      map[wire.OutPoint]chainhash.Hash // deposit -> release txid
	pegOuts       []pegOut
	deposits      []deposit
	paid          map[chainhash.Hash]chainhash.Hash // peg-out -> payment txid
	refunded      map[wire.OutPoint]chainhash.Hash  // deposit -> refund txid
	// unconfirmed are Bitcoin payments and refunds not yet in a block, by
	// txid: they can still be replaced by one paying a higher fee.
	unconfirmed map[chainhash.Hash]chainTx
	// paidAmount is what each payment gave its peg-out's destination.
	paidAmount     map[chainhash.Hash]int64
	held           []deposit // deposits not credited: no destination, or outside the limits
	settled        []deposit // deposits refunded instead of credited
	locked         int64     // BTC held at the peg address on Bitcoin
	lockedUTXOs    []utxo
	unclaimedOnBTC int64 // deposits without a usable destination
	unclaimedOnVM  int64 // untagged or too-small payments into the reserve
}

// audit is the peg's solvency check.
type audit struct {
	Circulating    int64 `json:"circulating"`    // BTC released onto BTCVM
	PendingPegIns  int64 `json:"pendingPegIns"`  // deposits not yet credited
	PendingPegOuts int64 `json:"pendingPegOuts"` // peg-outs not yet paid
	Locked         int64 `json:"locked"`         // BTC held on Bitcoin
	Required       int64 `json:"required"`       // circulating + pending
	Surplus        int64 `json:"surplus"`        // locked - required
	UnclaimedOnBTC int64 `json:"unclaimedOnBTC"` // part of surplus
	UnclaimedOnVM  int64 `json:"unclaimedOnVM"`
}

func (a audit) solvent() bool { return a.Surplus >= 0 }

func (b *bridge) vmReserveAddress() (btcutil.Address, error) {
	return b.signers.address(b.vmParams)
}

func (b *bridge) btcPegAddress() (btcutil.Address, error) {
	return b.signers.address(b.btcParams)
}

// btcWatchSet returns the Bitcoin addresses holding the peg: the peg
// address and each registered personal deposit address. It fills
// s.redeemFor and returns the destination of each deposit script.
func (b *bridge) btcWatchSet(s *pegState) ([]btcutil.Address, map[string]destination, error) {
	dests, err := b.registry.list()
	if err != nil {
		return nil, nil, err
	}
	var addrs []btcutil.Address
	s.redeemFor = map[string][]byte{}
	s.setFor = map[string]*signerSet{}
	depositDest := map[string]destination{}
	// Every set's addresses: the current set's, and the earlier sets',
	// whose coins are moved to this set and where late deposits may arrive.
	for _, set := range b.signers.lineage() {
		pegAddr, err := set.address(b.btcParams)
		if err != nil {
			return nil, nil, err
		}
		addrs = append(addrs, pegAddr)
		s.redeemFor[string(set.pkScript())] = set.redeemScript
		s.setFor[string(set.pkScript())] = set
		for _, d := range dests {
			redeem := set.depositRedeemScript(d)
			addr, err := set.depositAddress(d, b.btcParams)
			if err != nil {
				return nil, nil, err
			}
			addrs = append(addrs, addr)
			s.redeemFor[string(p2wshScript(redeem))] = redeem
			s.setFor[string(p2wshScript(redeem))] = set
			depositDest[string(p2wshScript(redeem))] = d
		}
	}
	return addrs, depositDest, nil
}

// depositInRange reports whether a deposit of value is credited at all.
func (b *bridge) depositInRange(value int64) bool {
	return value >= b.minDeposit && (b.maxDeposit == 0 || value <= b.maxDeposit)
}

// spendsAny reports whether tx spends one of outs.
func spendsAny(tx *wire.MsgTx, outs map[wire.OutPoint]bool) bool {
	for _, in := range tx.TxIn {
		if outs[in.PreviousOutPoint] {
			return true
		}
	}
	return false
}

// outputsTo returns the outpoints and total value tx pays to script.
func outputsTo(tx *wire.MsgTx, script []byte) (map[wire.OutPoint]bool, int64) {
	hash := tx.TxHash()
	outs := map[wire.OutPoint]bool{}
	var total int64
	for i, out := range tx.TxOut {
		if bytes.Equal(out.PkScript, script) {
			outs[wire.OutPoint{Hash: hash, Index: uint32(i)}] = true
			total += out.Value
		}
	}
	return outs, total
}

func (b *bridge) load() (*pegState, error) {
	script := b.signers.pkScript()
	// Every set's peg script holds the reserve on BTCVM: the current set's,
	// and those of the sets it replaced until their coins have moved.
	lineageScripts := map[string]bool{}
	var reserveAddrs []btcutil.Address
	for _, set := range b.signers.lineage() {
		lineageScripts[string(set.pkScript())] = true
		addr, err := set.address(b.vmParams)
		if err != nil {
			return nil, err
		}
		reserveAddrs = append(reserveAddrs, addr)
	}
	paidToReserve := func(tx *wire.MsgTx) (map[wire.OutPoint]bool, int64) {
		hash := tx.TxHash()
		outs := map[wire.OutPoint]bool{}
		var total int64
		for i, out := range tx.TxOut {
			if lineageScripts[string(out.PkScript)] {
				outs[wire.OutPoint{Hash: hash, Index: uint32(i)}] = true
				total += out.Value
			}
		}
		return outs, total
	}
	s := &pegState{
		released: map[wire.OutPoint]chainhash.Hash{},
		paid:     map[chainhash.Hash]chainhash.Hash{},
		refunded: map[wire.OutPoint]chainhash.Hash{},

		unconfirmed: map[chainhash.Hash]chainTx{},
		paidAmount:  map[chainhash.Hash]int64{},
	}

	// BTCVM side.
	vmTxs, err := b.vm.txsFor(reserveAddrs)
	if err != nil {
		return nil, fmt.Errorf("reading BTCVM reserve: %w", err)
	}
	reserveOuts := map[wire.OutPoint]bool{}
	for _, t := range vmTxs {
		outs, _ := paidToReserve(t.tx)
		for op := range outs {
			reserveOuts[op] = true
		}
	}
	for _, t := range vmTxs {
		_, paidIn := paidToReserve(t.tx)
		switch {
		case isCoinbase(t.tx):
			if t.confirmations > 0 {
				s.reserveCreated += paidIn
			}
		case spendsAny(t.tx, reserveOuts):
			// Only the signers can spend the reserve.
			if deposit, ok := parseRelease(t.tx); ok {
				s.released[deposit] = t.tx.TxHash()
			}
			if t.confirmations == 0 {
				s.vmPending = true
			}
		default:
			if t.confirmations == 0 {
				continue // not final yet
			}
			dest, ok := parseDestinationTag(t.tx, tagPegOut)
			// A payout to the peg address itself would look like change on
			// Bitcoin, so it is never made. Nor to an earlier set's: that
			// would give the retired signers new coins to move.
			ok = ok && !lineageScripts[string(dest.pkScript())]
			p := pegOut{time: t.time, txid: t.tx.TxHash(), value: paidIn, dest: dest,
				valid: ok && paidIn >= b.minPegOut, confirmations: t.confirmations}
			if p.valid {
				s.pegOuts = append(s.pegOuts, p)
			} else {
				s.unclaimedOnVM += paidIn
			}
		}
	}
	// The reserve still held includes the change of releases waiting in the
	// mempool, whose reserve inputs already count as spent. Other
	// unconfirmed payments into the reserve are not final yet.
	signerSpends := map[chainhash.Hash]bool{}
	for _, t := range vmTxs {
		if !isCoinbase(t.tx) && spendsAny(t.tx, reserveOuts) {
			signerSpends[t.tx.TxHash()] = true
		}
	}
	held, err := b.vm.unspent(reserveAddrs, 0)
	if err != nil {
		return nil, fmt.Errorf("reading BTCVM reserve: %w", err)
	}
	// btcd reports a reserve output as unspent while a transaction in its
	// mempool spends it, so the outputs known transactions spend are left
	// out here: otherwise a release in flight counts both its input and its
	// change, and the reserve looks larger than it is.
	spentByKnown := map[wire.OutPoint]bool{}
	for _, t := range vmTxs {
		for _, in := range t.tx.TxIn {
			spentByKnown[in.PreviousOutPoint] = true
		}
	}
	// Only the current set's coins pay releases, and so only they can be
	// the anchor; an earlier set's coins only move to this set.
	current := func(u utxo) bool { return bytes.Equal(u.pkScript, script) }
	var reserveCoins []utxo
	for _, u := range held {
		if u.confirmations > 0 && current(u) {
			reserveCoins = append(reserveCoins, u)
		}
	}
	s.reserveAnchor = oldestCoin(reserveCoins)
	for _, u := range held {
		if spentByKnown[u.outPoint] {
			continue
		}
		if u.confirmations == 0 && !signerSpends[u.outPoint.Hash] {
			continue
		}
		s.reserveUnspent += u.value
		switch {
		case u.confirmations == 0:
		case current(u):
			s.reserveUTXOs = append(s.reserveUTXOs, u)
		default:
			s.legacyReserve = append(s.legacyReserve, u)
		}
	}

	// Bitcoin side: the peg address and every personal deposit address.
	btcAddrs, depositDest, err := b.btcWatchSet(s)
	if err != nil {
		return nil, err
	}
	s.depositDest = depositDest
	btcTxs, err := b.btc.txsFor(btcAddrs)
	if err != nil {
		return nil, fmt.Errorf("reading Bitcoin peg addresses: %w", err)
	}
	pegOuts := map[wire.OutPoint]bool{}
	for _, t := range btcTxs {
		hash := t.tx.TxHash()
		for i, out := range t.tx.TxOut {
			if s.redeemFor[string(out.PkScript)] != nil {
				pegOuts[wire.OutPoint{Hash: hash, Index: uint32(i)}] = true
			}
		}
	}
	var all []deposit
	for _, t := range btcTxs {
		if spendsAny(t.tx, pegOuts) || b.signers.spendsPeg(t.tx) {
			// Only the signers can spend peg outputs; outputs back to the
			// peg are change, not deposits.
			hash := t.tx.TxHash()
			if t.confirmations == 0 {
				s.unconfirmed[hash] = t
			}
			// If an action has two transactions listed, one replacing the
			// other, the one in a block is the one that counts.
			counts := func(prev chainhash.Hash, listed bool) bool {
				_, prevPending := s.unconfirmed[prev]
				return !listed || (prevPending && t.confirmations > 0)
			}
			if request, ok := parsePayment(t.tx); ok {
				if prev, listed := s.paid[request]; counts(prev, listed) {
					s.paid[request] = hash
					s.paidAmount[request] = t.tx.TxOut[0].Value
				}
			}
			if deposit, ok := parseRefund(t.tx); ok {
				if prev, listed := s.refunded[deposit]; counts(prev, listed) {
					s.refunded[deposit] = hash
				}
			}
			// A payout to a personal deposit address is a deposit to it; so
			// is a retired set's move of a deposit to this set's address.
			for i, out := range t.tx.TxOut {
				if dest, personal := depositDest[string(out.PkScript)]; personal {
					all = append(all, deposit{time: t.time, outPoint: wire.OutPoint{Hash: hash, Index: uint32(i)},
						value: out.Value, dest: dest, valid: b.depositInRange(out.Value), confirmations: t.confirmations,
						hasDest: true, legacy: s.setFor[string(out.PkScript)] != b.signers})
				}
			}
			continue
		}
		tagDest, hasTag := parseDestinationTag(t.tx, tagDeposit)
		hash := t.tx.TxHash()
		for i, out := range t.tx.TxOut {
			d := deposit{
				time:          t.time,
				outPoint:      wire.OutPoint{Hash: hash, Index: uint32(i)},
				value:         out.Value,
				confirmations: t.confirmations,
			}
			owner := s.setFor[string(out.PkScript)]
			switch dest, personal := depositDest[string(out.PkScript)]; {
			case personal:
				// A personal deposit address names its destination.
				d.dest, d.valid, d.hasDest = dest, b.depositInRange(out.Value), true
			case owner != nil:
				// The shared peg address needs a BVMD tag.
				d.dest, d.valid, d.hasDest = tagDest, hasTag && b.depositInRange(out.Value), hasTag
			default:
				continue
			}
			d.legacy = owner != b.signers
			all = append(all, d)
		}
	}
	// A refunded deposit is settled: never credited, no longer owed.
	for _, d := range all {
		switch {
		case s.refunded[d.outPoint] != (chainhash.Hash{}):
			s.settled = append(s.settled, d)
		case d.legacy:
			// Only this set credits, and only at its own addresses: a
			// deposit to an earlier set's address is moved here first. One
			// already credited is simply part of the peg. Which are still
			// to move is settled below, once the coins are read.
			if _, credited := s.released[d.outPoint]; !credited {
				s.legacyDeposits = append(s.legacyDeposits, d)
			}
		case d.valid:
			s.deposits = append(s.deposits, d)
		default:
			s.held = append(s.held, d)
			if d.confirmations > 0 {
				s.unclaimedOnBTC += d.value
			}
		}
	}
	s.lockedUTXOs, err = b.btc.unspent(btcAddrs, 0)
	if err != nil {
		return nil, fmt.Errorf("reading Bitcoin peg addresses: %w", err)
	}
	// The audit reads only what's in blocks, so nothing in the mempool
	// (a deposit that may be double-spent, a payout that is evicted or
	// replaced) moves it. Locked BTC is the peg's confirmed outputs,
	// including those the signers' unconfirmed payments spend, which the
	// wallet no longer lists as unspent; such a payment's peg-out stays
	// owed until it confirms.
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 {
			s.locked += u.value
		}
	}
	confirmedOut := map[wire.OutPoint]int64{}
	confirmedCoin := map[wire.OutPoint]utxo{}
	for _, t := range btcTxs {
		if t.confirmations > 0 {
			hash := t.tx.TxHash()
			for i, out := range t.tx.TxOut {
				if s.redeemFor[string(out.PkScript)] != nil {
					op := wire.OutPoint{Hash: hash, Index: uint32(i)}
					confirmedOut[op] = out.Value
					confirmedCoin[op] = utxo{outPoint: op, value: out.Value, pkScript: out.PkScript, confirmations: t.confirmations}
				}
			}
		}
	}
	pendingSpent := map[wire.OutPoint]bool{}
	for _, t := range s.unconfirmed {
		for _, in := range t.tx.TxIn {
			if v, ok := confirmedOut[in.PreviousOutPoint]; ok && !pendingSpent[in.PreviousOutPoint] {
				pendingSpent[in.PreviousOutPoint] = true
				s.locked += v
			}
		}
	}
	// The anchor is chosen from what is in blocks alone: the wallet stops
	// listing an output a mempool transaction spends, so those are added
	// back, and a transaction someone shows this node without mining it
	// can't move the anchor.
	var pegCoins []utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 {
			pegCoins = append(pegCoins, u)
		}
	}
	for op := range pendingSpent {
		pegCoins = append(pegCoins, confirmedCoin[op])
	}

	// The current set pays only from its own coins; an earlier set's coins
	// only move here (rotate.go). Anchor and payouts use the current set's.
	var mine []utxo
	for _, u := range s.lockedUTXOs {
		if s.setFor[string(u.pkScript)] == b.signers {
			mine = append(mine, u)
		} else if u.confirmations > 0 {
			s.legacyUTXOs = append(s.legacyUTXOs, u)
		}
	}
	s.lockedUTXOs = mine
	var currentCoins []utxo
	for _, u := range pegCoins {
		if s.setFor[string(u.pkScript)] == b.signers {
			currentCoins = append(currentCoins, u)
		}
	}
	s.pegAnchor = oldestCoin(currentCoins)
	// A deposit to an earlier set's address waits to move while its coin is
	// in a block and not spent by one (a move still in the mempool hasn't
	// happened yet); until it is credited here it backs nothing owed.
	open := map[wire.OutPoint]bool{}
	for _, u := range s.legacyUTXOs {
		open[u.outPoint] = true
	}
	for op := range pendingSpent {
		open[op] = true
	}
	var waiting []deposit
	for _, d := range s.legacyDeposits {
		if open[d.outPoint] {
			waiting = append(waiting, d)
			if !d.valid || !d.hasDest {
				s.unclaimedOnBTC += d.value // owed to no one yet
			}
		}
	}
	s.legacyDeposits = waiting

	// Oldest first, so the bridge works through them in order.
	sort.Slice(s.deposits, func(i, j int) bool {
		return s.deposits[i].confirmations > s.deposits[j].confirmations
	})
	sort.Slice(s.pegOuts, func(i, j int) bool {
		return s.pegOuts[i].confirmations > s.pegOuts[j].confirmations
	})
	return s, nil
}

func (b *bridge) audit(s *pegState) audit {
	a := audit{
		Circulating:    s.reserveCreated - s.reserveUnspent,
		Locked:         s.locked,
		UnclaimedOnBTC: s.unclaimedOnBTC,
		UnclaimedOnVM:  s.unclaimedOnVM,
	}
	for _, d := range s.deposits {
		if _, done := s.released[d.outPoint]; !done && d.confirmations > 0 {
			a.PendingPegIns += d.value
		}
	}
	// A creditable deposit to an earlier set's address is owed as much as
	// one to this set's: it moves here and is credited (rotate.go).
	for _, d := range s.legacyDeposits {
		if d.valid && d.hasDest {
			a.PendingPegIns += d.value
		}
	}
	for _, p := range s.pegOuts {
		payment, paid := s.paid[p.txid]
		if _, pending := s.unconfirmed[payment]; !paid || pending {
			a.PendingPegOuts += p.value
		}
	}
	a.Required = a.Circulating + a.PendingPegIns + a.PendingPegOuts
	a.Surplus = a.Locked - a.Required
	return a
}

var errInsolvent = errors.New("peg is insolvent: BTC locked on Bitcoin is less than what BTCVM owes; refusing to act")

// step performs at most one release or payment. It returns what it did, or
// "" if there was nothing to do.
func (b *bridge) step() (string, error) {
	if p := b.paused(); p != nil {
		return "", p.err()
	}
	s, err := b.load()
	if err != nil {
		return "", err
	}
	if a := b.audit(s); !a.solvent() {
		return "", fmt.Errorf("%w (%+v)", errInsolvent, a)
	}
	b.syncSigners()

	var failed error
	// Coins an earlier set still holds move to this one first (rotate.go).
	moved, err := b.migrate(s)
	if len(moved) > 0 {
		return strings.Join(moved, "; "), err
	}
	failed = err
	// Releases chain off each other's reserve change, so wait for the
	// previous one to be accepted.
	if !s.vmPending {
		for _, d := range s.deposits {
			if _, done := s.released[d.outPoint]; done || d.confirmations < b.confirmationsFor(d.value) {
				continue
			}
			if b.maxCirculating > 0 && s.reserveCreated-s.reserveUnspent+d.value > b.maxCirculating {
				b.logf("holding deposit %v: crediting %s BTC would exceed the %s BTC cap",
					d.outPoint, formatBTC(d.value), formatBTC(b.maxCirculating))
				continue
			}
			txid, err := b.release(s, d)
			if err != nil {
				// Go on to the next: one that can't be credited mustn't
				// hold up the rest.
				failed = errors.Join(failed, fmt.Errorf("releasing deposit %v: %w", d.outPoint, err))
				continue
			}
			b.logWaiting(failed)
			return fmt.Sprintf("credited %s BTC for deposit %v in %v",
				formatBTC(d.value-b.vmFee), d.outPoint, txid), nil
		}
	}

	for _, p := range s.pegOuts {
		if _, done := s.paid[p.txid]; done {
			continue
		}
		txid, pays, err := b.pay(s, p)
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("paying peg-out %v: %w", p.txid, err))
			continue
		}
		b.logWaiting(failed)
		return fmt.Sprintf("paid %s BTC for peg-out %v in %v",
			formatBTC(pays), p.txid, txid), nil
	}
	did, err := b.bumpStuck(s)
	if did != "" {
		b.logWaiting(failed)
		return did, nil
	}
	return "", errors.Join(failed, err)
}

// logWaiting logs what couldn't be done in a step that did something else.
func (b *bridge) logWaiting(failed error) {
	if failed != nil {
		b.logf("waiting: %v", failed)
	}
}

// payoutInputs is what a payout or refund of value spends: the peg's
// anchor, and if it doesn't cover the payout, what selectForPayout picks
// from the other confirmed coins. While a transaction in the mempool spends
// the anchor, nothing else can be paid: it would conflict.
func (s *pegState) payoutInputs(confirmed []utxo, value int64) ([]utxo, error) {
	if s.pegAnchor == nil {
		return nil, errors.New("the peg holds no confirmed BTC")
	}
	if !containsOutPoint(confirmed, s.pegAnchor.outPoint) {
		return nil, fmt.Errorf("waiting for the payment spending %v to confirm", s.pegAnchor.outPoint)
	}
	return anchoredSelection(*s.pegAnchor, confirmed, value, func(rest []utxo, need int64) ([]utxo, error) {
		return selectForPayout(rest, need)
	})
}

// releaseInputs is what a release of value spends: the reserve's anchor,
// and more of the reserve if it doesn't cover the release.
func (s *pegState) releaseInputs(value int64) ([]utxo, int64, error) {
	if s.reserveAnchor == nil || !containsOutPoint(s.reserveUTXOs, s.reserveAnchor.outPoint) {
		return nil, 0, errors.New("waiting for the reserve's oldest coin to be free")
	}
	inputs, err := anchoredSelection(*s.reserveAnchor, s.reserveUTXOs, value, func(rest []utxo, need int64) ([]utxo, error) {
		picked, _, err := selectUTXOs(rest, need)
		return picked, err
	})
	if err != nil {
		return nil, 0, err
	}
	var total int64
	for _, u := range inputs {
		total += u.value
	}
	return inputs, total, nil
}

func containsOutPoint(coins []utxo, op wire.OutPoint) bool {
	for _, u := range coins {
		if u.outPoint == op {
			return true
		}
	}
	return false
}

// oldestCoin returns the coin in the oldest block, ties broken by outpoint,
// or nil. It is the anchor every signed transaction on a chain must spend
// first.
//
// Why: each signer's log stops it signing two transactions for one action
// that could both confirm, but that is per signer. With 2 of 3, a dishonest
// coordinator and one dishonest signer B could have A and B sign a payout
// from some coins and B and C sign the same payout again from other coins;
// neither honest signer signs twice, and both payouts confirm. If every
// transaction must spend the oldest coin, any two of them conflict. The
// oldest coin can't change until a transaction spending it is in a block,
// since new coins are always newer, so a withheld transaction can't be
// dodged by waiting for new deposits.
func oldestCoin(coins []utxo) *utxo {
	var best *utxo
	for i := range coins {
		u := &coins[i]
		if best == nil || u.confirmations > best.confirmations ||
			u.confirmations == best.confirmations && outPointLess(u.outPoint, best.outPoint) {
			best = u
		}
	}
	if best == nil {
		return nil
	}
	c := *best
	return &c
}

func outPointLess(a, b wire.OutPoint) bool {
	if c := bytes.Compare(a.Hash[:], b.Hash[:]); c != 0 {
		return c < 0
	}
	return a.Index < b.Index
}

// anchoredSelection is the inputs a signed transaction spends: the anchor
// first, then, if it doesn't cover need, what select picks from the rest.
func anchoredSelection(anchor utxo, available []utxo, need int64, pick func([]utxo, int64) ([]utxo, error)) ([]utxo, error) {
	if anchor.value >= need {
		return []utxo{anchor}, nil
	}
	var rest []utxo
	for _, u := range available {
		if u.outPoint != anchor.outPoint {
			rest = append(rest, u)
		}
	}
	more, err := pick(rest, need-anchor.value)
	if err != nil {
		return nil, err
	}
	return append([]utxo{anchor}, more...), nil
}

// selectForPayout picks the peg outputs a payout spends: the smallest one
// that covers value, so a payout that stalls ties up as little of the peg as
// it can; or, if none does alone, the fewest, largest first.
func selectForPayout(utxos []utxo, value int64) ([]utxo, error) {
	// smallest is the smallest output of at least need.
	smallest := func(need int64) *utxo {
		var best *utxo
		for i := range utxos {
			if u := &utxos[i]; u.value >= need && (best == nil || u.value < best.value) {
				best = u
			}
		}
		return best
	}
	// Prefer one that leaves the peg its change of at least pegDust, so
	// nothing is topped up from the payout; else one that just covers it.
	if best := smallest(value + pegDust); best != nil {
		return []utxo{*best}, nil
	}
	if best := smallest(value); best != nil {
		return []utxo{*best}, nil
	}
	inputs, _, err := selectUTXOs(utxos, value)
	return inputs, err
}

// selectUTXOs picks outputs, largest first, until they cover amount.
func selectUTXOs(utxos []utxo, amount int64) ([]utxo, int64, error) {
	sorted := append([]utxo(nil), utxos...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].value > sorted[j].value })
	var picked []utxo
	var total int64
	for _, u := range sorted {
		if total >= amount {
			break
		}
		picked = append(picked, u)
		total += u.value
	}
	if total < amount {
		return nil, 0, fmt.Errorf("only %s BTC available, need %s", formatBTC(total), formatBTC(amount))
	}
	return picked, total, nil
}

// release credits d on BTCVM from the reserve. The reserve gives up the
// full deposit; the VM fee comes out of the credit.
func (b *bridge) release(s *pegState, d deposit) (chainhash.Hash, error) {
	inputs, total, err := s.releaseInputs(d.value)
	if err != nil {
		return chainhash.Hash{}, err
	}
	tx := b.buildRelease(inputs, total, d)
	p := &proposal{
		Chain: chainBTCVM, tx: tx, prev: b.reserveSpends(inputs),
		Action:   action{Kind: actionRelease, Deposit: d.outPoint.String()},
		Register: []destination{d.dest},
	}
	if err := b.authorize(p); err != nil {
		return chainhash.Hash{}, err
	}
	return b.vm.send(tx)
}

// buildRelease is the unsigned transaction crediting d from inputs, which
// hold total. Signers rebuild it to check a proposal, so it must depend
// only on its arguments.
func (b *bridge) buildRelease(inputs []utxo, total int64, d deposit) *wire.MsgTx {
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, u := range inputs {
		tx.AddTxIn(wire.NewTxIn(&u.outPoint, nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(d.value-b.vmFee, d.dest.pkScript()))
	// Change below the dust threshold would make the release unrelayable,
	// so it goes to the fee.
	if change := total - d.value; change >= pegDust {
		tx.AddTxOut(wire.NewTxOut(change, b.signers.pkScript()))
	}
	tx.AddTxOut(nullData(encodeRelease(d.outPoint)))
	return tx
}

// pays is what peg-out p pays, or will at feeRate sat/vB.
func (s *pegState) pays(b *bridge, p pegOut, feeRate int64) int64 {
	if v, ok := s.paidAmount[p.txid]; ok {
		return v
	}
	return max(p.value-b.payoutFee(feeRate), 0)
}

// reserveSpends describes reserve outputs for signing.
func (b *bridge) reserveSpends(inputs []utxo) []spent {
	prev := make([]spent, len(inputs))
	for i, u := range inputs {
		prev[i] = spent{script: b.signers.redeemScript, value: u.value}
	}
	return prev
}

// pay pays peg-out p on Bitcoin from the peg address. The peg gives up the
// full peg-out; the Bitcoin fee comes out of the payment. It returns the
// payment's txid and what it pays.
func (b *bridge) pay(s *pegState, p pegOut) (chainhash.Hash, int64, error) {
	return b.payFromPeg(s, p.value, p.dest, encodePayment(p.txid),
		action{Kind: actionPayout, PegOut: p.txid.String()})
}

// checkFeeRates checks the fee rate bounds make sense.
func (b *bridge) checkFeeRates() error {
	if b.minFeeRate < 1 || b.maxFeeRate < b.minFeeRate {
		return fmt.Errorf("fee rates must satisfy 1 <= -min-fee-rate (%d) <= -max-fee-rate (%d)", b.minFeeRate, b.maxFeeRate)
	}
	return nil
}

// currentFeeRate is the rate a payout pays now, within the bounds.
func (b *bridge) currentFeeRate() int64 {
	rate := b.minFeeRate
	if b.feeRate != nil {
		if r, err := b.feeRate(); err == nil {
			rate = r
		} else {
			b.logf("fee estimate: %v; paying %d sat/vB", err, b.minFeeRate)
		}
	}
	return min(max(rate, b.minFeeRate), b.maxFeeRate)
}

// payFromPeg pays value, less the Bitcoin fee, to dest from confirmed peg
// outputs on Bitcoin, tagged with data. Change returns to the peg address.
// It returns the payment's txid and what it pays dest.
func (b *bridge) payFromPeg(s *pegState, value int64, dest destination, data []byte, why action) (chainhash.Hash, int64, error) {
	var confirmed []utxo
	for _, u := range s.lockedUTXOs {
		if u.confirmations > 0 {
			confirmed = append(confirmed, u)
		}
	}
	inputs, err := s.payoutInputs(confirmed, value)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}
	prev, register, err := s.pegSpends(inputs)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}
	rate := b.currentFeeRate()
	tx, err := b.buildPayout(inputs, prev, value, dest, data, rate)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}
	p := &proposal{Chain: chainBitcoin, Action: why, tx: tx, prev: prev, Register: register, FeeRate: rate}
	if err := b.authorize(p); err != nil {
		return chainhash.Hash{}, 0, err
	}
	txid, err := b.btc.send(tx)
	return txid, tx.TxOut[0].Value, err
}

// pegSpends describes peg outputs on Bitcoin for signing, and lists the
// personal deposit destinations among them.
func (s *pegState) pegSpends(inputs []utxo) ([]spent, []destination, error) {
	prev := make([]spent, len(inputs))
	var register []destination
	for i, u := range inputs {
		redeem := s.redeemFor[string(u.pkScript)]
		if redeem == nil {
			return nil, nil, fmt.Errorf("no witness script for peg output %v", u.outPoint)
		}
		prev[i] = spent{script: redeem, value: u.value}
		if d, ok := s.depositDest[string(u.pkScript)]; ok {
			register = append(register, d)
		}
	}
	return prev, register, nil
}

// bitcoinDust is the smallest output the bridge pays out: Bitcoin Core's
// dust threshold for a P2PKH output, the largest of the standard ones.
const bitcoinDust = 546

// pegDust is the smallest change a payout returns to the peg: Bitcoin
// Core's dust threshold for a P2WSH output.
const pegDust = 330

// buildPayout is the unsigned Bitcoin transaction paying value, less the
// fee at feeRate sat/vB, to dest from inputs, which spend prev. Like
// buildRelease, signers rebuild it, so it depends only on its arguments.
// Its inputs signal replaceability, so a payout that stalls can be bumped.
func (b *bridge) buildPayout(inputs []utxo, prev []spent, value int64, dest destination, data []byte, feeRate int64) (*wire.MsgTx, error) {
	if len(prev) != len(inputs) {
		return nil, errors.New("inputs and spent outputs differ")
	}
	var total int64
	// Version 3 (TRUC, BIP431): any child spending an output of the payout
	// before it confirms is limited to 1,000 vB, so nobody can pin it with
	// a large low-fee child that makes it too costly to replace.
	tx := wire.NewMsgTx(3)
	scriptSizes := make([]int, len(inputs))
	for i, u := range inputs {
		in := wire.NewTxIn(&u.outPoint, nil, nil)
		in.Sequence = wire.MaxTxInSequenceNum - 2 // BIP125: replaceable
		tx.AddTxIn(in)
		total += prev[i].value
		scriptSizes[i] = len(prev[i].script)
	}
	if total < value {
		return nil, fmt.Errorf("inputs hold %s BTC, need %s", formatBTC(total), formatBTC(value))
	}
	// Every input must be needed: each one adds to the fee, which comes
	// out of the payout, so extra inputs would spend the user's BTC on fees.
	// The first is the anchor (oldestCoin), which every payout spends.
	for i := 1; i < len(prev); i++ {
		if total-prev[i].value >= value {
			return nil, fmt.Errorf("spends %v, which the payout does not need", inputs[i].outPoint)
		}
	}
	tx.AddTxOut(wire.NewTxOut(0, dest.pkScript())) // value set below
	// Every payout pays something back to the shared peg address, which
	// every signer watches from the start, so every signer's wallet lists
	// it and knows the peg-out is paid. Change below pegDust is topped up
	// from the payout.
	change, topUp := total-value, int64(0)
	if change < pegDust {
		change, topUp = pegDust, pegDust-change
	}
	tx.AddTxOut(wire.NewTxOut(change, b.signers.pkScript()))
	tx.AddTxOut(nullData(data))
	fee := feeRate * b.signers.witnessVSize(tx, scriptSizes)
	pays := value - fee - topUp
	if pays < bitcoinDust || fee > value/2 {
		return nil, fmt.Errorf("the %s BTC network fee at %d sat/vB would take more than half of %s BTC; waiting for lower fees",
			formatBTC(fee), feeRate, formatBTC(value))
	}
	tx.TxOut[0].Value = pays
	return tx, nil
}

// payoutFee is what a payout at feeRate from one personal deposit output
// costs: an estimate to show users before they withdraw.
func (b *bridge) payoutFee(feeRate int64) int64 {
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(wire.NewTxOut(0, destination{kind: destP2TR}.pkScript()))
	tx.AddTxOut(wire.NewTxOut(0, b.signers.pkScript()))
	tx.AddTxOut(nullData(encodePayment(chainhash.Hash{})))
	// A deposit script is the peg's with a 34-byte destination push and
	// OP_DROP in front.
	return feeRate * b.signers.witnessVSize(tx, []int{len(b.signers.redeemScript) + 35})
}

// feeRateOf is the fee rate, in sat/vB, tx pays spending prev.
func (b *bridge) feeRateOf(tx *wire.MsgTx, prev []spent) int64 {
	var in, out int64
	sizes := make([]int, len(prev))
	for i, p := range prev {
		in += p.value
		sizes[i] = len(p.script)
	}
	for _, o := range tx.TxOut {
		out += o.Value
	}
	return (in - out) / b.signers.witnessVSize(tx, sizes)
}

// prevOutSource looks up the output an input spends, and whether it is in a
// block and unspent there.
type prevOutSource interface {
	prevOut(op wire.OutPoint) (out *wire.TxOut, confirmed bool, err error)
}

// replacement is an unconfirmed payment or refund, and the peg outputs it
// spends, which a new transaction paying a higher fee can spend instead.
type replacement struct {
	tx       *wire.MsgTx
	inputs   []utxo
	prev     []spent
	register []destination // personal deposit destinations among the inputs
}

// replaceable returns the unconfirmed transaction txid. It fails if the
// transaction is in a block, or spends anything but peg outputs that are in
// a block and unspent there.
func (b *bridge) replaceable(s *pegState, txid chainhash.Hash) (*replacement, error) {
	t, ok := s.unconfirmed[txid]
	if !ok {
		return nil, fmt.Errorf("%v is not an unconfirmed peg payment", txid)
	}
	src, ok := b.btc.(prevOutSource)
	if !ok {
		return nil, errors.New("this Bitcoin connection cannot look up spent outputs")
	}
	r := &replacement{tx: t.tx}
	for _, in := range t.tx.TxIn {
		out, confirmed, err := src.prevOut(in.PreviousOutPoint)
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return nil, fmt.Errorf("%v spends %v, which is not in a block", txid, in.PreviousOutPoint)
		}
		r.inputs = append(r.inputs, utxo{outPoint: in.PreviousOutPoint, value: out.Value, pkScript: out.PkScript, confirmations: 1})
	}
	var err error
	if r.prev, r.register, err = s.pegSpends(r.inputs); err != nil {
		return nil, err
	}
	return r, nil
}

// replacementFor returns what a transaction for action replaces: nil if
// the action has no unconfirmed transaction, an error if it has one in a
// block.
func (b *bridge) replacementFor(s *pegState, a action) (*replacement, error) {
	var done chainhash.Hash
	var ok bool
	switch a.Kind {
	case actionPayout:
		txid, err := chainhash.NewHashFromStr(a.PegOut)
		if err != nil {
			return nil, err
		}
		done, ok = s.paid[*txid]
	case actionRefund:
		op, err := parseOutPoint(a.Deposit)
		if err != nil {
			return nil, err
		}
		done, ok = s.refunded[op]
	}
	if !ok {
		return nil, nil
	}
	if _, pending := s.unconfirmed[done]; !pending {
		return nil, fmt.Errorf("%s was already done in %v", a.Kind, done)
	}
	return b.replaceable(s, done)
}

// bumpStuck replaces one payout or refund that has waited unconfirmed for
// bumpAfter, if the fee rate now is higher than the one it pays. The
// replacement spends the same outputs, so only one of them can confirm.
func (b *bridge) bumpStuck(s *pegState) (string, error) {
	if b.bumpAfter <= 0 {
		return "", nil
	}
	now := time.Now().Unix()
	var failed error
	for txid, t := range s.unconfirmed {
		if t.time == 0 || now-t.time < int64(b.bumpAfter/time.Second) {
			continue
		}
		r, err := b.replaceable(s, txid)
		if err != nil {
			b.logf("not bumping %v: %v", txid, err)
			continue
		}
		old, rate := b.feeRateOf(t.tx, r.prev), b.currentFeeRate()
		if rate < old+2 { // BIP125: the new fee must also pay for its own relay
			continue
		}
		why, value, dest, data, ok := s.actionOf(t.tx)
		if !ok || s.doneBy(why) != txid {
			continue // not what the action currently counts as done by
		}
		tx, err := b.buildPayout(r.inputs, r.prev, value, dest, data, rate)
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("bumping %v: %w", txid, err))
			continue
		}
		p := &proposal{Chain: chainBitcoin, Action: why, tx: tx, prev: r.prev, Register: r.register, FeeRate: rate}
		if err := b.authorize(p); err != nil {
			failed = errors.Join(failed, fmt.Errorf("bumping %v: %w", txid, err))
			continue
		}
		newID, err := b.btc.send(tx)
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("bumping %v: %w", txid, err))
			continue
		}
		b.logWaiting(failed)
		return fmt.Sprintf("replaced %v (%d sat/vB) with %v (%d sat/vB)", txid, old, newID, rate), nil
	}
	return "", failed
}

// doneBy is the transaction a payout or refund is done by, if any.
func (s *pegState) doneBy(a action) chainhash.Hash {
	switch a.Kind {
	case actionPayout:
		if txid, err := chainhash.NewHashFromStr(a.PegOut); err == nil {
			return s.paid[*txid]
		}
	case actionRefund:
		if op, err := parseOutPoint(a.Deposit); err == nil {
			return s.refunded[op]
		}
	}
	return chainhash.Hash{}
}

// actionOf reads what a peg payment or refund on Bitcoin was for: its
// action, the value it gave up, where it paid and its tag.
func (s *pegState) actionOf(tx *wire.MsgTx) (why action, value int64, dest destination, data []byte, ok bool) {
	if request, found := parsePayment(tx); found {
		p, found := findPegOut(s.pegOuts, request)
		if !found {
			return
		}
		return action{Kind: actionPayout, PegOut: request.String()}, p.value, p.dest, encodePayment(request), true
	}
	if op, found := parseRefund(tx); found {
		d, found := findDeposit(append(append([]deposit{}, s.held...), s.deposits...), op)
		if !found {
			d, found = findDeposit(s.settled, op)
		}
		to, err := destinationOfScript(tx.TxOut[0].PkScript)
		if !found || err != nil {
			return
		}
		return refundAction(op, to), d.value, to, encodeRefund(op), true
	}
	return
}

// refundable checks a deposit has the confirmations a credit of it would
// need: a refund of one that is not settled in a block could be paid while
// its sender double-spends it.
func (b *bridge) refundable(d deposit) error {
	if need := b.confirmationsFor(d.value); d.confirmations < need {
		return fmt.Errorf("deposit %v has %d of %d confirmations; it can be refunded once it has them", d.outPoint, d.confirmations, need)
	}
	return nil
}

var (
	errNotRefundable = errors.New("not a deposit the bridge holds")
	errCreditable    = errors.New("the bridge may still credit this deposit; stop the bridge and pass -force to refund it")
)

// refund returns deposit op, less the Bitcoin fee, to dest. Deposits the
// bridge will never credit (no destination, outside the limits) can always
// be refunded. One it may still credit (it is waiting for confirmations or
// for room under maxCirculating) needs force, and the bridge must be
// stopped first so the two cannot race.
func (b *bridge) refund(op wire.OutPoint, dest destination, force bool) (chainhash.Hash, error) {
	if p := b.paused(); p != nil {
		return chainhash.Hash{}, p.err()
	}
	s, err := b.load()
	if err != nil {
		return chainhash.Hash{}, err
	}
	if txid, done := s.refunded[op]; done {
		return chainhash.Hash{}, fmt.Errorf("already refunded in %v", txid)
	}
	if txid, done := s.released[op]; done {
		return chainhash.Hash{}, fmt.Errorf("already credited in %v", txid)
	}
	for _, d := range s.held {
		if d.outPoint == op {
			if err := b.refundable(d); err != nil {
				return chainhash.Hash{}, err
			}
			txid, _, err := b.payFromPeg(s, d.value, dest, encodeRefund(op), refundAction(op, dest))
			return txid, err
		}
	}
	for _, d := range s.deposits {
		if d.outPoint == op {
			if !force {
				return chainhash.Hash{}, errCreditable
			}
			txid, _, err := b.payFromPeg(s, d.value, dest, encodeRefund(op), refundAction(op, dest))
			return txid, err
		}
	}
	return chainhash.Hash{}, errNotRefundable
}

func isCoinbase(tx *wire.MsgTx) bool {
	return len(tx.TxIn) == 1 && tx.TxIn[0].PreviousOutPoint.Index == wire.MaxPrevOutIndex &&
		tx.TxIn[0].PreviousOutPoint.Hash == chainhash.Hash{}
}
