# BTCVM two-way peg

BTCVM never issues BTC. Every BTC on BTCVM is backed by BTC locked on Bitcoin, and moves between the chains through a two-way peg run by a set of signers.

## Pieces

| Piece | Where | What it does |
|---|---|---|
| Peg reserve | BTCVM consensus ([`btcd/params.go`](../btcd/params.go), [`btcd/blockchain/validate.go`](../btcd/blockchain/validate.go)) | Blocks 1..`pegReserveBlocks` must each pay 20,999,000 BTC to `pegReserveAddress`. This is the only way coins come into existence. |
| Signer set | [`cmd/btcvm/signers.go`](../cmd/btcvm/signers.go) | An m-of-n multisig. The reserve on BTCVM and the peg address on Bitcoin both use its witness script, so they share one P2WSH (`bc1q…`) address. |
| Bridge | [`cmd/btcvm/bridge.go`](../cmd/btcvm/bridge.go) | Watches both chains. It credits deposits from the reserve, pays peg-outs from the locked BTC, and refuses to act if the peg is not fully backed. |

The reserve is not circulating supply. It is locked to the signers and leaves the reserve only when BTC of equal value is locked on Bitcoin. A single output can hold at most 21 million BTC, Bitcoin's whole supply, so one reserve block (`pegReserveBlocks: 1`) is enough.

## Flows

**Peg-in (Bitcoin → BTCVM)**
1. Each BTCVM address has its own Bitcoin deposit address: a P2WSH (`bc1q…`) address whose witness script names the BTCVM address and then the peg multisig, so only the signers can spend it (`btcvm deposit-address` prints it). The user sends BTC there from any wallet. Alternatively, a payment to the peg address can carry an `OP_RETURN` tagged `BVMD` naming the BTCVM address (`btcvm peg-in` builds it).
2. Once the deposit has enough Bitcoin confirmations for its size (`-confirmations`, default 6, about an hour; `-confirmation-tiers` lets smaller deposits need fewer), the bridge spends the reserve. It pays the deposit amount, minus `-vm-fee` (default 10 sats), to that address, and tags the transaction `BVMI` with the deposit's outpoint.
3. BTCVM finalizes the release in its next block.

**Peg-out (BTCVM → Bitcoin)**
1. The user pays BTC on BTCVM to the reserve address. The transaction carries an `OP_RETURN` tagged `BVMO` naming any Bitcoin address (`btcvm peg-out` builds it).
2. Once it is in a block (final), the bridge pays the amount from the locked BTC on Bitcoin, tagged `BVMR` with the peg-out's txid. The Bitcoin network fee comes out of the payout, at Bitcoin Core's current two-block fee estimate, kept between `-min-fee-rate` and `-max-fee-rate` (default 1 to 50 sat/vB).
3. Payouts are replaceable (BIP125). If one is still unconfirmed after `-bump-after` (default 30 minutes) and the fee rate has risen, the bridge replaces it with one paying the current rate, spending the same coins, so only one of them can confirm.

## Tags

Each is the whole data of the transaction's single `OP_RETURN` output. Transactions with more than one `OP_RETURN` are ignored. A destination is a kind (0 = P2PKH, 1 = P2SH, 2 = P2WPKH, 3 = P2WSH, 4 = P2TR) followed by its 20- or 32-byte hash or key.

| Tag | Chain | Payload | Bytes |
|---|---|---|---|
| `BVMD` | Bitcoin | destination | 25 or 37 |
| `BVMI` | BTCVM | deposit txid (internal byte order), vout (little endian) | 40 |
| `BVMO` | BTCVM | destination | 25 or 37 |
| `BVMR` | Bitcoin | peg-out txid | 36 |
| `BVMF` | Bitcoin | refunded deposit's txid, vout | 40 |

## Safety properties

- **Exactly once.** The bridge reads its state back from both chains every time. A deposit counts as credited only if a release carrying its outpoint exists, and a peg-out as paid only if a payment carrying its txid exists. After a crash, the bridge picks up where it left off. A replacement payout spends the same coins as the payout it replaces, so at most one confirms.
- **Every signed transaction spends the oldest coin first.** Each payout and refund on Bitcoin must spend the peg's oldest confirmed coin, and each release on BTCVM the reserve's oldest coin, as its first input. Any two transactions the signers sign on one chain therefore conflict, and at most one can confirm. A signer's log only stops that signer signing twice; without this rule, a dishonest coordinator and one dishonest signer could have the other two signers each sign once, for the same withdrawal, from different coins, and both would confirm. The oldest coin is read from blocks only, so a transaction someone shows a node without mining it can't change it, and new deposits are always newer. The cost: while one payout is unconfirmed, the next waits for it, so Bitcoin payouts go one per block.
- **Spoofed tags are ignored.** Anyone can write `BVMI` or `BVMR` into a transaction. The bridge only trusts them on transactions that spend reserve or peg outputs, which only the signers can do. Otherwise, a forged `BVMI` could mark someone's deposit as already credited.
- **Solvency check.** Before every action the bridge checks that `locked on Bitcoin ≥ circulating on BTCVM + pending peg-ins + pending peg-outs`, and halts if it does not hold. `btcvm audit` prints the same numbers for anyone to check.
- **Deposits without a usable destination** (none, malformed, or below `-min-deposit`, default 0.0001 BTC) are not credited. They show up in the audit as `unclaimedOnBitcoin`. The same goes for untagged payments into the reserve (`unclaimedOnBTCVM`). Peg-outs below `-min-peg-out` (default 0.0001 BTC, 10,000 sats; 5,000 sats on mainnet) are not paid.
- **Caps.** `-max-deposit` and `-max-circulating` limit what's at risk: a larger deposit is held for a refund, and one that would take the total past the cap waits.
- **Consensus pins the reserve.** Block builders cannot redirect the reserve coinbase or mint more than it (`ErrBadPegReserve`, `ErrBadCoinbaseValue`).

## Trust model and limits

This is a federated peg: **the signers can move the locked BTC.** m of the n signers could release reserve coins with no deposit behind them, or spend BTC locked on Bitcoin. The audit would detect either, but it cannot prevent them. This is the same trust model as other federated pegs; making deposits trustless needs a Bitcoin light client inside BTCVM (Bitcoin header and proof-of-work validation) and is not built.

The bridge can run as a single process holding all signer keys, which suits development only. Production needs:
- Each signer running its own process with its own key (ideally an HSM), co-signing releases and payments that it has verified independently. This is built: see [SIGNERS.md](SIGNERS.md).
- A deposit confirmation depth sized to what's at stake: 6 by default, fewer only for small deposits.
- A peg-out delay and rate limits, so a compromised signer set is caught by the audit before everything moves.
- Monitoring and alerting on the audit.

Other limits:
- Releases are sent one at a time, waiting for each to be accepted, because each spends the previous release's reserve change.
- `btcvm`'s Bitcoin side uses Bitcoin Core's wallet RPC: the bridge creates its own watch-only descriptor wallet (`btcvm` by default) and imports the peg and deposit addresses into it. It needs no `-txindex`, and the node can be pruned: a signer that missed a deposit imports it from the block the coordinator names (which its node checks), as long as its node still has that block. A refund of a deposit whose sender the node can no longer look up needs the refund address given with `-to`.
