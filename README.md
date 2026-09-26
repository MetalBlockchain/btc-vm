<p align="center"><img src="cmd/btcvm/web/bitcoin.svg" alt="Bitcoin logo" width="120" height="120"></p>

# BTCVM

A Bitcoin virtual machine for [Metal Blockchain](https://github.com/MetalBlockchain/metalgo): a UTXO ledger with Bitcoin's addresses, keys, script and consensus rules, run under Snowman consensus instead of proof of work.

BTCVM embeds [btcd](https://github.com/btcsuite/btcd) as the ledger and script engine. It is a second ledger for existing BTC, not a new coin:

- **No premine and no block reward.** The genesis block pays nothing, and the coinbase can only claim transaction fees. BTC enters the ledger only through a two-way peg with Bitcoin ([docs/BRIDGE.md](docs/BRIDGE.md)).
- **Same addresses and keys as Bitcoin.** A `1…`, `3…`, `bc1q…` or `bc1p…` address, a `K…`/`L…` WIF key or an `xprv`/`xpub` extended key is the same on both chains.
- **Today's Bitcoin rules from the first block.** SegWit and Taproot are active from block 1.
- **No change to Bitcoin itself.** Bitcoin keeps running exactly as it does today.

> **Status: beta.** The code has not had an outside security review, and nothing has crossed the bridge on mainnet yet. Keep amounts small.

**Site:** **https://metalbtc.com** will serve the web wallet, explorer and roadmap, with JSON-RPC at `/rpc`, once BTCVM launches on mainnet. [docs/TESTING.md](docs/TESTING.md) covers running the whole stack locally.

## Networks

| | Mainnet | Testnet (default) |
|---|---|---|
| Select with | `--mainnet` / `"mainNet": true` | `--testnet` / `"testNet": true` |
| P2PKH / P2SH / WIF version | 0 / 5 / 128 | 111 / 196 / 239 |
| SegWit address prefix | `bc` | `tb` |
| Extended keys | `xprv` / `xpub` | `tprv` / `tpub` |
| BIP44 coin type | 0 | 1 |
| Max single output | 21,000,000 BTC (Bitcoin's `MAX_MONEY`) | same |

The parameters live in [`btcd/params.go`](btcd/params.go). The encodings match Bitcoin Core's `chainparams.cpp`.

## Fees and policy

Relay policy is Bitcoin Core's standard policy, as btcd implements it ([`btcd/mempool/policy.go`](btcd/mempool/policy.go)), with two exceptions: BTCVM has no miners to pay, so fees are a thousandth of Bitcoin's and there is no dust limit.

| Rule | Value |
|---|---|
| Minimum relay fee | 0.001 sat/vB (`minRelayTxFee`), and never less than 1 sat: a payment costs 1 sat. Required on every transaction (no free or priority relay) |
| Dust | none (`dustRelayFee` 0): any output of 1 sat or more; an empty output is refused |
| OP_RETURN | never dust; at most one per transaction |
| Replace-by-fee | BIP125 |

The wallets pay the minimum: 1 sat for a typical payment, whatever the amount. Fees go to the validator that built the block. Both settings are node policy, not consensus: a node can set its own in the chain config.

## How it works

Metal's Snowman consensus orders blocks, and btcd validates and stores them. The adapter in [`vm/block_adapter.go`](vm/block_adapter.go) keeps one rule: **btcd only ever holds accepted blocks.**

- `ParseBlock` decodes a block without storing it, and rejects any encoding other than the block's canonical one.
- `Verify` runs full consensus validation against the last accepted block, read-only, via btcd's `CheckConnectBlockTemplate`.
- `Accept` is the only place a block is written to btcd.
- `Reject` has nothing to undo.

As a result, btcd's chain tip is always the last accepted block, and a transaction is final once it is in a block, typically within a couple of seconds. Blocks propagate through Snowman, not gossip; only transactions are gossiped. Proof-of-work checks are disabled, since Snowman provides the security.

## Two-way peg

A peg reserve, created by consensus in the chain's first block and locked to an m-of-n signer multisig, backs every BTC on BTCVM. The `btcvm` CLI ([`cmd/btcvm`](cmd/btcvm)) is a wallet and the bridge:

- **Peg-in:** each BTCVM address gets its own Bitcoin deposit address (P2WSH, `bc1q…`). BTC sent there is credited 1:1 from the reserve once it has enough Bitcoin confirmations for its size, less a small bridge fee.
- **Peg-out:** BTC paid back into the reserve, naming a Bitcoin address, is paid out on Bitcoin once it is final on BTCVM, less the Bitcoin network fee.
- **Audit:** `btcvm audit` checks that BTC locked on Bitcoin covers everything circulating on BTCVM plus what is pending.

The peg is federated: the signers are trusted. See [docs/BRIDGE.md](docs/BRIDGE.md) for the design, message format and trust model.

The signers can run separately, each with one key on its own machine, checking every transaction against its own view of both chains before signing. A compromised bridge process can then delay transfers but can't move locked BTC. See [docs/SIGNERS.md](docs/SIGNERS.md). A key rotation moves the peg to a new set of signers ([docs/ROTATION.md](docs/ROTATION.md)).

## Status and roadmap

The chain, the bridge (SegWit deposit addresses, live fee rates, replaceable payouts) and the web wallet are built for Bitcoin and tested against btcd's script engine. BTCVM has not yet made a round trip on mainnet.

Next is hosting the bridge's Bitcoin node and, once it has synced, a first small mainnet round trip: a deposit, then a withdrawal ([docs/FIRST-ROUND-TRIP.md](docs/FIRST-ROUND-TRIP.md)). Then independent signers, and an outside security review before larger amounts. The full roadmap is at [metalbtc.com/roadmap](https://metalbtc.com/roadmap).

## Building and testing

Requires Go 1.24+.

```bash
go build ./...
go test ./vm/ ./cmd/... ./btcd/ ./btcd/mempool/
```

The VM targets metalgo v1.13.5 (rpcchainvm protocol 43). Its VM ID is `kMtihm7W3KssmcJb9mzwZfC6gkiPrJhWaa5KMLHdEB9R8Q4pp` (from the name `btcvm`). The Metal plugin is built from [`cmd/btcvm-plugin`](cmd/btcvm-plugin).

Some vendored btcd tests fail because proof of work is disabled. Examples are `TestFullBlocks` and `TestUtxoCacheFlush`.

See [`docs/README.md`](docs/README.md) for the Makefile targets that build the plugin and run a local five-node network with `metal-network-runner`.

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE). The vendored btcd is under its own ISC license in [`btcd/LICENSE`](btcd/LICENSE).

## Credits

Developed by Paul Grey @ [metallicus.com](https://metallicus.com), built on [btcvm](https://github.com/MetalBlockchain/btcvm) by Deep V @ [metallicus.com](https://metallicus.com), which runs [btcd](https://github.com/btcsuite/btcd) as a virtual machine on [metalgo](https://github.com/MetalBlockchain/metalgo).
