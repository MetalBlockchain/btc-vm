# Validators of the BTCVM L1: runbook

The BTCVM L1's validators are managed by proof of authority. Its admins
approve each change; the L1's validators sign it; the P-Chain applies it.
The code is `vm/validator_manager.go`; the tool is `btcvm-l1` (`cmd/btcvm-l1`).
This page covers operating it: growing the set, day-to-day changes, and
recovering when something goes wrong.

## The rules the validators enforce

- **M of N admins.** `validatorAdmins` (P-Chain addresses) and
  `validatorAdminThreshold` (default: a majority) in every validator's chain
  config. Three admins, two of whom must approve.
- **Every admin, while one validator could block.** A change after which
  losing any one validator (one BLS key: offline, out of balance or
  disabled) would leave the rest able to sign under 67% of the whole weight
  needs every admin. With equal weights that is any set of three validators
  or fewer, and any change that adds a newcomer to one of up to five (it
  can't sign yet).
- **What can sign must still make 67%.** Only active (funded) validators
  sign, but every registered weight counts in the total. A change that would
  leave the validators able to sign now under 67% of the total is refused,
  whoever approves it. A newcomer can't sign until it's funded and online, so
  it joins at a small weight and is raised later.
- **A raise needs the raised validator's signature.** A weight change that
  raises a validator is collected only with that validator's own signature
  among the signers (the collecting node insists, whatever the client asks):
  proof it's online and signing.
- **One change at a time.** Each validator holds the last change it signed
  (`held-change.json`, below) and signs no other until that one is on the
  P-Chain or can't be: a registration until it's registered or expires (a day
  at most), a weight change until the P-Chain's nonce passes it.
- **Approvals expire.** Each approval carries a deadline, at most 7 days
  ahead (an hour for a replacement). The tool sets a registration's to its
  expiry (at most a day).

## Growing from one validator to four

Start: one validator at weight 100. Each step waits for the P-Chain to
settle (a minute or two) before the next. The first five steps need all
three admins; the last needs two.

1. **Register V2 at weight 1.** `approve -request request.json -weight 1`,
   the other admins approve, `submit`, then the operator runs `register` with
   at least 1 METAL.
2. **Check V2 is active and caught up** (`btcvm-l1 validators`; the operator's
   `setup.sh --status`), then **raise it to 100**: `set-weight -validation-id
   V2 -weight 100`, approved by all three. The validators sign it only with
   V2's own signature among them.
3. **Register V3 at weight 1** (all three).
4. **Raise V3 to 100** once it's active (all three; V3 must sign).
5. **Register V4 at weight 1** (all three: until it signs, losing any one of
   the three would leave 200 of 301).
6. **Raise V4 to 100** once it's active (two admins: 4 x 100, and without any
   one validator the rest hold 75%). The L1 now tolerates one validator
   offline.

An unfunded or silent newcomer at weight 1 can be removed (`remove`, all
three admins) without freezing anything, as long as the existing
validators stay up. Growing further: a newcomer at 100 needs every admin
until the L1 has six validators; at weight 1, raised later, two suffice
from four.

## Day to day

- **Approving.** The first admin makes the proposal (`approve -request` or
  `set-weight`/`remove`); each other admin runs `approve -proposal` on their
  own machine (`-offline` works with no node); whoever has a validator's
  `rpcPass` runs `submit`. Each `approve` shows the change from the message
  itself (NodeID, BLS key, both owners, weight) and the shares before and
  after.
- **Retrying.** If `submit` fails, submit the same proposal again. Don't make
  a new one: validators that signed hold that exact change.
- **Clocks.** Each validator judges deadlines by its own clock and the
  P-Chain by its own view of it: leave margin, and retry a change refused
  moments after another.

## Held changes and replacing them

`btcvm-l1 held -node-uri … -rpc-pass-file …` shows the change a validator
holds and its hash. If validators hold different changes and none can reach
67% (a split), every admin together approves a change that replaces them:

```sh
btcvm-l1 held …                                  # on each stuck validator: note heldHash
btcvm-l1 remove … -replace-held HASH1,HASH2 …    # or approve -request / set-weight
```

The replacement names the held changes it may replace (their hashes, part of
what every admin signs) and is good for an hour, so it can't be kept for
later. A held change already signed by enough validators can still reach the
P-Chain: check none is waiting to be submitted before replacing it.

## A lost admin key

While the set needs every admin (three validators or fewer), a lost key
blocks growth and replacements. There is no way around it inside the
protocol. The recovery is to change `validatorAdmins` in the chain config of
validators holding at least 67% of the weight, and restart them. Keep every
admin key backed up offline, and grow past three validators quickly.

## Disabling a validator

An owner can disable its validator (`disable`) without the admins. A
disabled validator's weight stays in the total but can't sign, so `disable`
refuses when the rest would fall under 67%. Coordinate disables with the
admins and prefer removal. Two disables at once are the dangerous case: with
four validators of 100, disabling two leaves 200 of 400 able to sign, so no
change can be signed: not a removal, not a raise (either needs 268 of the 400
to sign). The only repair is to make the disabled validators active again:
anyone can `top-up` their balances, and their nodes must be online and
signing. Then the admins remove them properly.

## The held change on disk, and restores

Each validator keeps its held change in
`<dataDir>/<network>/validator-manager/held-change.json`, where `dataDir` is
the chain config's and the network is the btcd one (`btcvm` on mainnet): for
example `/var/lib/metalgo/l1/btcvm/data/btcvm/validator-manager/held-change.json`
on a node metalgo-setup installed. Without a `dataDir` in the chain config it
sits under the btcd home instead: set one. It's written with fsync before every signature. If a write fails, the
validator stops signing until it restarts.

- **Back it up together with the node's signing identity** (the staking and
  BLS keys).
- **Never start a validator on a restored, copied, wiped or resynced data
  directory** without the admins confirming no change is outstanding: it may
  hold an older change than the one it really signed last (or none), and then
  sign a second.
- **Never copy a held-change.json between nodes.**
- A corrupt file stops signing until an operator looks at it.

## Owner keys

Each operator's request names its own P-Chain address as owner. The owner gets
back what's left of the balance and can disable the validator, so owner keys
are never shared between operators.
