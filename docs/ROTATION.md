# Key rotation

A rotation replaces the peg's signer set with a new one: new keys, made on
each new signer's own machine, and usually new operators. It is how the peg
moves off the beta's keys, how an operator leaves or joins, and what to do
if a key may be compromised.

Every peg address is built from the signer set's keys, so a new set means a
new peg address, new personal deposit addresses and a new reserve address on
BTCVM. Rotation moves everything the old set holds to the new set's
addresses. Nothing is re-issued and nothing is credited twice.

## How it works

The new signer set names the set it replaces (`previous`, part of its
fingerprint). From then on the bridge reads the whole peg: coins still held
by the old set count as locked, and the old reserve still counts on BTCVM.
Only the new set credits deposits and pays withdrawals, and only from its own
coins.

On each pass, the coordinator moves whatever the old set still holds to the
new set:

1. **The reserve on BTCVM** moves to the new reserve address.
2. **Bitcoin**, once the reserve has moved:
   - a deposit not yet credited moves to its destination's **new personal
     deposit address**, where the new set credits it once;
   - everything else (the backing for BTC already credited, change) moves
     to the **new peg address**.

The old set's signers keep running, **retired**. A retired signer signs only
these moves, and only the move its own view of both chains builds:
- every input is a confirmed coin its own set holds, and the first is the
  oldest such coin on that chain (the anchor), so any two moves conflict
  and at most one confirms;
- each coin goes where the rule above says, checked against its own record
  of what was credited;
- the fee rate is within policy and its own estimate;
- nothing moves while a release is pending;
- the peg is still solvent after the move.

Its signing log records a move by the coins it spends, read from the
transaction, not by the label the coordinator gives it. The coordinator
can't redirect a move. A signer of the new set never signs
a move, and a retired signer signs nothing else.

Each move is tagged `BVMM` with the hash of the new set's script.

**Late deposits.** People will keep paying the old addresses: saved
addresses, exchanges that cached one. The bridge keeps watching them. A
payment that arrives later is moved to the new set's address for the same
destination and credited there. It pays the Bitcoin fee for its own move, a
few hundred satoshis. This works for as long as the retired signers run.

## Before you start

- **Nothing in flight.** Wait until `/api/health` shows nothing pending in
  either direction. A deposit waiting for confirmations is fine: it moves
  with the rest and is credited under the new set.
- **The surplus covers the fees.** Moving the reserve pays the BTCVM fee
  (the policy's `vmFee`), and moving Bitcoin pays a network fee, roughly
  100 vB per coin at the current rate. Both come out of the peg, so the
  bridge moves nothing until its surplus covers them. To top up, send a
  little BTC to the old peg address without a tag: it counts as surplus.
  About 0.0002 BTC covers a small peg at a few sat/vB.
- **Backups.** Every old signer backs up its directory (`btcvm-backup run`,
  or bridge-operator's `backup.sh run`), and the coordinator backs up its
  secrets.

## Step by step

In the commands below, `btcvm` runs as the service's user with the node
settings in its environment. Write the fingerprint down when it's printed.

### 1. The new signers make keys and cards

Each new operator, on their own server (bridge-operator's installer sets it
up), runs:

```sh
sudo -u btcvm-signer btcvm signer-setup init
```

It makes the key on that machine and writes `card.json`, which holds public
information only. Each operator sends their card to the coordinator.

### 2. The coordinator assembles the new set

```sh
btcvm signer-setup assemble -previous /var/lib/metal-main/secrets/separate-signers/signers.json \
  -required 2 -coordinator-key COORDINATOR-PUBKEY \
  -btc-network mainnet -vm-network mainnet \
  -confirmations 6 -confirmation-tiers 0.001:2,0.005:3 \
  -max-deposit 1000000 -max-circulating 10000000 -min-fee-rate 1 -max-fee-rate 50 \
  -min-peg-out 5000 -vm-fee 10 \
  -out signers.json -cosigners-out cosigners.json \
  new1/card.json new2/card.json new3/card.json
```

Keep the policy flags the same as the live set's, unless the rotation is
also meant to change them. It prints the new fingerprint, the new peg
address, and the set it replaces. `assemble` refuses a new set that reuses
any old key. `cosigners.json` lists the new signers and the retired ones.

### 3. Everyone confirms the fingerprint

The coordinator sends `signers.json` to every signer, old and new, and reads
the fingerprint out on a call. Each signer checks the one `join` shows
against it. **Confirming the fingerprint is the consent**: the old signers
are agreeing to move the peg's coins to exactly this set.

### 4. Pause the bridge

```sh
bv pause -signers $SET -reason "Rotating the signer keys. Funds are safe."
```

### 5. The new signers join and start

```sh
sudo -u btcvm-signer btcvm signer-setup join -signers signers.json -fingerprint FINGERPRINT
```

Then install and start the service, and run `btcvm signer-setup check`
(bridge-operator's `install.sh` and `check.sh` do both).

### 6. The old signers join, retired

Each old signer runs the same `join`, in its existing directory, with the
**new** `signers.json`:

```sh
sudo -u btcvm-signer btcvm signer-setup join -dir /var/lib/btcvm-signer \
  -signers signers.json -fingerprint FINGERPRINT
```

`join` recognises the old key, says the signer is joining **retired**, and
keeps a copy of the set it ran with (`signers.OLD-FINGERPRINT.json`). Then
restart its service. `signer-setup check` then reports:
`retired: this signer's key is in a set this one replaced`.

### 7. The coordinator switches to the new set

Install the new `signers.json` and `cosigners.json` where the bridge, web
server and monitor read them. Keep the deposit registry (`-deposits`)
where it is. Then restart them and resume:

```sh
systemctl restart btcvm-web-main btcvm-monitor-main btcvm-bridge-main
bv resume -signers $SET
```

### 8. Watch the move

The bridge logs `moved N reserve outputs to the new set`, then, once that is
final, `moved N Bitcoin outputs to the new set`. The health check
`rotation` shows what the old set still holds. The move needs 6 Bitcoin
confirmations to settle, like any deposit. Then:

- `btcvm audit` shows the peg solvent, with the old set holding nothing.
- Every signer's own `btcvm audit` agrees.
- The site shows the new peg and deposit addresses. Wallets pick them up
  from `/api/info`.

Then do a small round trip on the new set: a deposit and a withdrawal.

## After the rotation

- **Keep the retired signers running**, so late deposits to old addresses are
  moved and credited. The `rotation` check fails if a coin waits too long,
  which usually means a retired signer is down or the surplus can't cover
  the fee.
- **Retiring for good.** Once nothing has arrived at the old addresses for
  a period you announce beforehand (say three months), the retired signers
  may stop. After that, a payment to an old address can only be recovered
  by a manual ceremony with the old keys, so **keep the old keys' backups**.
- **The old keys stay dangerous** while the old set's addresses can receive
  payments: whoever holds enough of them can move what arrives there. Store
  their backups as carefully as live keys.

## If something goes wrong

- **The move doesn't start.** Read the bridge log.
  - "fee is more than the peg's surplus": top up, as above.
  - "0 of 2 signatures": check the retired signers are up and have joined
    the new set.
  - "a release is pending": wait for it to finish.
- **A move is stuck unconfirmed.** It pays the rate estimated when it was
  made. Moves aren't bumped automatically yet: wait for fees to fall, or
  ask the maintainers.
- **Undoing a rotation.** Before any move is broadcast, nothing has
  happened: put the old set back on the coordinator and every signer, and
  resume. After that, going back is another rotation, from the new set back
  to fresh keys.
- **A crash mid-rotation.** The bridge rebuilds its state from both chains
  on every pass, so a restarted coordinator carries on where it stopped.

## Limits

- Each rotation changes the peg address. A threshold-signature scheme (FROST)
  could change keys without changing the address; that is future work.
- Moves are made one per old set at a time, up to 100 coins each.
- DogecoinVM doesn't have rotation yet.
