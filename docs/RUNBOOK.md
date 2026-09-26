# Runbook

What to do when something goes wrong with the mainnet bridge. The commands
assume the host set up by `deploy/mainnet.sh`: state in `/var/lib/metal-main`,
secrets in `/var/lib/metal-main/secrets`, Bitcoin Core's data in
`/var/lib/bitcoin-main`, services run as the `btcvm` user.

```sh
S=/var/lib/metal-main/secrets
SET=$S/separate-signers/signers.json   # the public signer set the bridge runs with
REG="-deposits $S/deposits.json"         # the deposit address registry
COORD="-cosigners $S/separate-signers/cosigners.json -coordinator-key-file $S/separate-signers/coordinator/coordinator.key"
bv() { sudo -u btcvm env HOME=/opt/btcvm $(cat $S/bridge.env | xargs) /opt/btcvm/bin/btcvm "$@"; }
```

The pause, the bridge lock and (unless `-deposits` says otherwise) the
registry sit next to the signer set file, so always name the one in the
bridge's `ExecStart`. The host holds no signer keys: each signer runs as its
own user from `/var/lib/btcvm-signer-N`, and can be paused on its own with
`btcvm pause -dir /var/lib/btcvm-signer-N`.

## First: pause

In any incident where funds might be at risk, pause first and investigate
second. A pause is safe: nothing is lost, and deposits and withdrawals made
while paused are processed after it ends.

```sh
bv pause -signers $SET -reason "Investigating an alert. Funds are safe."
```

Within seconds:
- the bridge stops proposing and paying anything, and refunds are refused;
- metalbtc.com shows a red banner with the reason, and `/api/status` has
  `paused`;
- the monitor sends a Telegram alert, and repeats it every 6 hours while
  paused.

To resume, once the cause is understood and fixed:

```sh
bv resume -signers $SET
```

With separate signers, each operator can also pause their own signer:
`btcvm pause -dir /var/lib/btcvm-signer -reason "..."`. Once fewer than
the required number of signers are available, nothing moves. A pause is the
one power every operator has on their own.

**What a pause does not do.** It stops the software. It does not stop
someone who has stolen the keys. While all three signer keys are on one
server, a compromise of that server exposes them all, and the beta caps
(per deposit and in total, at `/api/info`) bound the loss. Separate signers
([SIGNERS.md](SIGNERS.md)) are the real fix.

## Alerts

The monitor checks every minute and alerts on Telegram when a check changes.
`curl -s https://metalbtc.com/api/health` shows the same checks.

| Check | Failing means | Do |
| --- | --- | --- |
| `peg` | Locked BTC no longer covers circulating BTC plus pending transfers. The bridge has already stopped itself. | Pause. Run `bv audit -signers $SET $REG`, and compare proof of reserves on the site with a public Bitcoin explorer. Don't resume until the difference is explained. |
| `pause` | The bridge is paused. | Expected during an incident. Confirm who paused it and why (`cat $S/paused.json`). |
| `bridge` | A deposit or withdrawal is well past due. | `journalctl -u btcvm-bridge-main -n 50`. Common causes: a node behind, the circulating cap reached (the deposit waits), or signers unreachable. A payout waiting on a slow Bitcoin block is not stuck: the bridge replaces it with a higher fee after 30 minutes if fees have risen. |
| `bitcoin` | Bitcoin Core is down, still syncing, or its latest block is over 90 minutes old. | `systemctl status bitcoind-main`; restart it if stopped. Bitcoin blocks come about every 10 minutes at random, so an old block alone can be a slow block. While it syncs, deposits wait and nothing is lost. |
| `btcvm` | The BTCVM node isn't answering. | `systemctl status metal-mainnet`, and its logs. |
| `validator` | The validator's P-Chain balance is low; at zero the validator stops and the chain halts. | Top up the validator balance on the P-Chain. This isn't scripted yet, so do it before the balance runs out; the alert gives the days left. |

## A deposit that hasn't arrived

```sh
bv refund -signers $SET $REG $COORD -list     # held or not yet credited, and why
```

- **Waiting for confirmations** (2 for up to 0.001 BTC, 3 up to 0.005, 6 above; about 10 minutes each): nothing to do.
- **Waiting for room under the circulating cap:** it's credited when there is room, or refund it.
- **Above the maximum deposit, below the minimum, or no destination:** refund it.

```sh
bv refund -signers $SET $REG $COORD -deposit TXID:VOUT            # back to the sender
bv refund -signers $SET $REG $COORD -deposit TXID:VOUT -to BTCADDR
```

- **Not listed at all:** the deposit was probably paid to a personal deposit
  address before the address was registered (anyone can work the address out
  from the signers' keys, but the bridge watches it only from registration
  on). Register it, if it isn't, then import the payment. The node is pruned,
  so name the block holding it (from a public explorer); it must be recent
  enough that the node still has the block:

  ```sh
  bv import-deposit -signers $SET -txid TXID -block BLOCKHASH
  ```

  It's then credited, or held for a refund, on the bridge's next pass.

With separate signers, each operator first adds `TXID:VOUT BTCADDR` to their
`-refund-approvals` file.

## Blocks lost after a restart

**Sign:** after the Metal node restarts, BTCVM's height is lower than
before, and the peg alert fires (`locked` below `circulating`), because a
withdrawal that was paid on Bitcoin is no longer on BTCVM. The chain log shows
`Detected unclean shutdown` and `repairing accepted chain by height
{"outerHeight": N, "innerHeight": M}`.

**Cause:** the BTCVM plugin died without shutting down, and btcd lost the
blocks still in its caches. It happened once, on 26 September 2026 (blocks
11-13), before three fixes: each accepted block is now written to disk before
it is accepted, the plugin waits for metalgo to shut it down, and the node's
unit has `KillMode=mixed`. Check the unit has it after any change.

**Recover** (nothing is lost: metalgo's proposervm keeps its own copy of each
block, and only moves its pointer back):

1. Pause the bridge (above). Then `systemctl stop metal-mainnet` at once, so
   no new block overwrites the lost heights.
2. Copy the node's database, and work on the copy:
   `cp -a /var/lib/metal-main/node/db /root/incident-DATE/node-db`.
3. Read the lost blocks' transactions from the copy (build it from this
   repo: `go build ./cmd/btcvm-blocks`):
   `btcvm-blocks /root/incident-DATE/node-db/mainnet/v1.4.5 CHAIN-ID M+1 N`.
4. Start the node, and send each block's non-coinbase transactions with
   `sendrawtransaction`, in block order, waiting for each to be in a block.
5. Check the height is back to N, the peg audit matches, and each signer's
   own `btcvm audit` agrees; then resume.

## Suspected compromise of the server

1. Pause.
2. Cut public access if needed: `systemctl stop btcvm-web-main`. The bridge
   and nodes keep running, paused.
3. Check what moved: proof of reserves on the site, and the peg address on a
   public Bitcoin explorer.
4. Take a fresh backup (`btcvm-backup run`), and keep the server as it is
   for investigation.
5. Rebuild on a new server from backup (below). Treat every key that was on
   the old server as exposed: move the funds to new keys as soon as key
   rotation exists.

## Restore from backup

Backups are made daily at 03:17 UTC to `/var/backups/btcvm`, encrypted to an
age key that only the operators hold. `scripts/pull-backups.sh` keeps a copy
off the server.

Prove a backup restores, on a machine with the age key:

```sh
scripts/restore-check.sh ~/BTCVM-backups/btcvm-YYYYMMDDTHHMMSSZ.tar.age
```

Rebuild a host from one:

1. Provision a new Ubuntu 24.04 server. Run the install parts of
   `deploy/provision.sh` (Go, metalgo, BTCVM, Bitcoin Core), and the
   node setup in `deploy/mainnet.sh`.
2. Copy the backup over and unpack it at the filesystem root. It holds its
   files at their original paths:

   ```sh
   age -d -i identity.txt btcvm-….tar.age | tar -xzf - -C /tmp && cp -a /tmp/btcvm/. / && rm -rf /tmp/btcvm
   chown -R btcvm:btcvm /var/lib/metal-main /var/lib/bitcoin-main
   ```

3. Start Bitcoin Core and the Metal node, and let both sync (Bitcoin Core's
   first sync downloads and checks the whole chain, about a day; pruned, it
   keeps about 100 GB). The restored
   staking files keep the same NodeID, so the validator carries on.
4. Start the bridge, web wallet and monitor, **paused** until everything
   checks out: `bv pause …`, then start the services, `bv audit`, and resume.
5. Point DNS at the new server.

Only the restored secrets can move funds, so wipe the unpacked copy and
anything else holding them once the host is running.
