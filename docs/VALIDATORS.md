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
- **Every admin, while one validator could block.** A change after which any
  one validator (one BLS key) holds enough weight to stop the P-Chain's 67%
  quorum on its own needs every admin. With equal weights that is any set of
  three validators or fewer.
- **What can sign must still make 67%.** Only active (funded) validators
  sign, but every registered weight counts in the total. A change that would
  leave the validators able to sign now under 67% of the total is refused,
  whoever approves it. A newcomer can't sign until it's funded and online, so
  it joins at a small weight and is raised later.
- **A raise needs the raised validator's signature.** `set-weight` to a
  higher weight is collected only with the raised validator's own signature
  among the signers: proof it's online and signing.
- **One change at a time.** Each validator holds the last change it signed
  (`held-change.json`, below) and signs no other until that one is on the
  P-Chain or can't be: a registration until it's registered or expires (a day
  at most), a weight change until the P-Chain's nonce passes it.
- **Approvals expire.** Each approval carries a deadline: at most 7 days, a
  registration's expiry, or an hour for a replacement.

## Growing from one validator to four

Start: one validator at weight 100. Each step waits for the P-Chain to
settle (a minute or two) before the next. The first four steps need all
three admins; the last needs two.

1. **Register V2 at weight 1.** `approve -request request.json -weight 1`,
   the other admins approve, `submit`, then the operator runs `register` with
   at least 1 METAL.
2. **Check V2 is active and caught up** (`btcvm-l1 validators`; the operator's
   `setup.sh --status`), then **raise it to 100**: `set-weight -validation-id
   V2 -weight 100`, approved by all three. The submit fails unless V2 itself
   signs.
3. **Register V3 at weight 1** (all three).
4. **Raise V3 to 100** once it's active (all three; V3 must sign).
5. **Register V4 at 100** (two admins): 300 of 400 can sign, 25% each. The
   L1 now tolerates one validator offline.

An unfunded or silent newcomer at weight 1 can be removed (`remove`, all
three admins) without freezing anything, as long as the existing
validators stay up.

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
the chain config's (the btcd data directory: the network name is added to
it). It's written with fsync before every signature. If a write fails, the
validator stops signing until it restarts.

- **Back it up together with the node's signing identity** (the staking and
  BLS keys).
- **Never start a validator on a restored or copied data directory** without
  the admins confirming no change is outstanding: it may hold an older change
  than the one it really signed last, and then sign a second.
- **Never copy a held-change.json between nodes.**
- A corrupt file stops signing until an operator looks at it.

## Owner keys

Each operator's request names its own P-Chain address as owner. The owner gets
back what's left of the balance and can disable the validator, so owner keys
are never shared between operators.
