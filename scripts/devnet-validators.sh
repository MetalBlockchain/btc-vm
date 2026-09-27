#!/usr/bin/env bash
# Tests adding and removing BTCVM L1 validators (proof of authority) on a
# local 5-node Metal network, end to end:
#
#   METALGO=/path/to/metalgo METALGO_SRC=/path/to/metalgo/source scripts/devnet-validators.sh
#
# 1. Starts five local-network nodes with metalgo's public local staking keys
#    (METALGO_SRC/staking/local), sybil protection on.
# 2. Creates a BTCVM L1 validated by node 1 alone (btcvm-l1 create), every
#    node tracking it, each with its own miningAddrs and the same
#    validatorAdmins: three admin keys made here, any two of which approve
#    (validatorAdminThreshold 2).
# 3. Adds nodes 2, 3 and 4: request -> approve (admin 1 starts the
#    proposal) -> approve (the next admins; the last submits via node 1) ->
#    register (paid by the local network's public ewoq key). Nodes 2 and 3
#    each leave a validator with a third or more of the weight, so they need
#    all three admins; node 4 (25% each) needs two.
# 4. Sends payments until each of the four validators has built blocks and
#    been paid their fees; node 5, not a validator, builds none.
# 5. Removes node 3: two admins are refused (it leaves 33.3% each), all
#    three succeed; it builds no more blocks.
# 6. Checks refusals: one admin alone, an admin with an outsider, an admin
#    twice, two admins adding a heavy validator (50%), and the signing
#    endpoint without the RPC login.
#
# Development only: the keys are public. State in DEVNET_DIR (default
# ~/.btcvm-validators-devnet), deleted at the start of each run. KEEP=1 leaves
# the nodes running at the end.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIR=${DEVNET_DIR:-$HOME/.btcvm-validators-devnet}
: "${METALGO:?set METALGO to a metalgo v1.13.5 binary}"
: "${METALGO_SRC:?set METALGO_SRC to a metalgo v1.13.5 source tree (for staking/local)}"
STAKING=$METALGO_SRC/staking/local
N=5
NETWORK_ID=12345
RPC_USER=btcvm

log() { printf '\n==> %s\n' "$*" >&2; }
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}
ok() { printf '    ok  %s\n' "$*" >&2; }
http_port() { echo $((9650 + 10 * ($1 - 1))); }
uri() { echo "http://127.0.0.1:$(http_port "$1")"; }

stop_all() {
  local i
  for i in $(seq $N); do
    [[ -f $DIR/n$i/pid ]] && kill "$(cat "$DIR/n$i/pid")" 2>/dev/null || true
  done
  for i in $(seq $N); do
    while [[ -f $DIR/n$i/pid ]] && kill -0 "$(cat "$DIR/n$i/pid")" 2>/dev/null; do sleep 0.3; done
    rm -f "$DIR/n$i/pid"
  done
}
[[ ${KEEP:-0} == 1 ]] || trap stop_all EXIT

call() { # call NODE ENDPOINT METHOD [PARAMS]
  local params=${4:-'{}'}
  curl -s -m 20 -X POST -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$3\",\"params\":$params}" "$(uri "$1")/ext/$2"
}
btc() { # btc NODE METHOD [PARAMS]: the BTCVM JSON-RPC on a node
  local params=${3:-'[]'}
  curl -s -m 20 -u "$RPC_USER:$(cat "$DIR/rpc-password")" -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"$2\",\"params\":$params}" "$(uri "$1")/ext/bc/$CHAIN_ID/rpc"
}
wait_for() { # wait_for SECONDS DESCRIPTION COMMAND...
  local secs=$1 what=$2
  shift 2
  for _ in $(seq "$secs"); do
    "$@" >/dev/null 2>"$DIR/wait.err" && return 0
    sleep 1
  done
  fail "timed out waiting for $what${DIR:+: $(tail -1 "$DIR/wait.err" 2>/dev/null)}"
}
bootstrapped() { call "$1" info info.isBootstrapped "{\"chain\":\"$2\"}" | grep -q '"isBootstrapped":true'; }

start_node() {
  local i=$1 flags
  flags=(
    --network-id=local
    --data-dir="$DIR/n$i" --log-dir="$DIR/n$i/logs"
    --staking-tls-key-file="$STAKING/staker$i.key" --staking-tls-cert-file="$STAKING/staker$i.crt"
    --staking-signer-key-file="$STAKING/signer$i.key"
    --http-host=127.0.0.1 --http-port="$(http_port "$i")" --staking-port=$(($(http_port "$i") + 1))
    --public-ip=127.0.0.1 --plugin-dir="$DIR/plugins" --chain-config-dir="$DIR/n$i/chain-configs"
    --log-level=info
  )
  if ((i == 1)); then
    flags+=(--bootstrap-ips= --bootstrap-ids=)
  else
    flags+=(--bootstrap-ips=127.0.0.1:9651 --bootstrap-ids="$NODE1_ID")
  fi
  [[ -n ${SUBNET_ID:-} ]] && flags+=(--track-subnets="$SUBNET_ID")
  nohup "$METALGO" "${flags[@]}" >"$DIR/n$i/out.log" 2>&1 &
  echo $! >"$DIR/n$i/pid"
}

start_all() {
  local i
  for i in $(seq $N); do start_node "$i"; done
  for i in $(seq $N); do wait_for 180 "node $i to sync the P-Chain" bootstrapped "$i" P; done
}

# --- 1. The network -------------------------------------------------------------
log "Five-node local network"
stop_all 2>/dev/null || true
rm -rf "$DIR"
mkdir -p "$DIR/plugins" "$DIR/bin"
for i in $(seq $N); do mkdir -p "$DIR/n$i/chain-configs"; done
(
  cd "$ROOT"
  VMID=$(go run ./scripts/vm-id-generator.go)
  go build -o "$DIR/plugins/$VMID" ./cmd/btcvm-plugin
  go build -o "$DIR/bin/btcvm" ./cmd/btcvm
  go build -o "$DIR/bin/btcvm-l1" ./cmd/btcvm-l1
  go build -o "$DIR/bin/btcvm-devnet" ./cmd/btcvm-devnet
)
BIN=$DIR/bin
NODE1_ID=$("$BIN/btcvm-l1" node-id -cert "$STAKING/staker1.crt")
start_all
ok "5 nodes up, P-Chain synced"

# --- 2. A BTCVM L1 validated by node 1 -------------------------------------------
log "BTCVM L1 validated by node 1"
"$BIN/btcvm-devnet" -ewoq-key-out "$DIR/ewoq.json"
EWOQ_P=$(jq -r .pChainAddress "$DIR/ewoq.json")
for a in 1 2 3; do "$BIN/btcvm-l1" key -out "$DIR/admin$a.json" -network-id $NETWORK_ID >/dev/null; done
ADMINS=$(jq -s 'map(.pChainAddress)' "$DIR"/admin{1,2,3}.json)
"$BIN/btcvm-l1" key -out "$DIR/outsider.json" -network-id $NETWORK_ID >/dev/null
"$BIN/btcvm" keygen -vm-network testnet >"$DIR/reserve.json"
for i in $(seq $N); do "$BIN/btcvm" keygen -vm-network testnet >"$DIR/builder$i.json"; done
openssl rand -hex 16 >"$DIR/rpc-password"
jq -n --arg r "$(jq -r .btcvmAddress "$DIR/reserve.json")" \
  '{config: {testNet: true, pegReserveAddress: $r, pegReserveBlocks: 1}}' >"$DIR/genesis.json"
"$BIN/btcvm-l1" create -key "$DIR/ewoq.json" -genesis "$DIR/genesis.json" -node-uri "$(uri 1)" \
  -network-id $NETWORK_ID -validator-balance 5 >"$DIR/chain.json"
CHAIN_ID=$(jq -r .chainID "$DIR/chain.json")
SUBNET_ID=$(jq -r .subnetID "$DIR/chain.json")
for i in $(seq $N); do
  mkdir -p "$DIR/n$i/chain-configs/$CHAIN_ID"
  jq -n --arg pass "$(cat "$DIR/rpc-password")" --arg builder "$(jq -r .btcvmAddress "$DIR/builder$i.json")" \
    --argjson admins "$ADMINS" --arg d "$DIR/n$i/chaindata" --arg l "$DIR/n$i/chainlogs" \
    '{rpcUser: "btcvm", rpcPass: $pass, txIndex: true, addrIndex: true,
      miningAddrs: [$builder], validatorAdmins: $admins, validatorAdminThreshold: 2, dataDir: $d, logDir: $l}' \
    >"$DIR/n$i/chain-configs/$CHAIN_ID/config.json"
done
stop_all
start_all
for i in $(seq $N); do wait_for 180 "node $i to bootstrap the L1" bootstrapped "$i" "$CHAIN_ID"; done
ok "chain $CHAIN_ID (subnet $SUBNET_ID) on all nodes"

L1=(-network-id "$NETWORK_ID" -chain-id "$CHAIN_ID" -subnet-id "$SUBNET_ID")
validators() { "$BIN/btcvm-l1" validators "${L1[@]}" -node-uri "$(uri 1)"; }
validator_count() { validators | jq length; }
has_validator() { validators | jq -e --arg n "$1" 'map(.nodeID) | index($n)' >/dev/null; }
[[ $(validator_count) == 1 ]] || fail "expected 1 validator, got $(validator_count)"
ok "1 validator: node 1"

# --- 3. Add nodes 2 and 3 ----------------------------------------------------------
# settling ATTEMPT CMD...: runs CMD until it succeeds; while the L1's
# validator set is still settling from the last change, waits and retries.
settling() {
  local attempt err=$DIR/settling.err
  for attempt in $(seq 12); do
    if "$@" 2>"$err"; then return 0; fi
    if grep -qE "changed moments ago|failed verifying warp" "$err"; then
      printf '    (validator set still settling: retry %d)\n' "$attempt" >&2
      sleep 15
      continue
    fi
    cat "$err" >&2
    return 1
  done
  fail "the validator set never settled"
}
# approvals PROPOSAL ADMIN...: each admin adds an approval to PROPOSAL (the
# first admin's is already in it).
approvals() {
  local proposal=$1 a
  shift
  for a in "$@"; do
    "$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -proposal "$proposal" -key "$DIR/admin$a.json" -yes \
      >"$proposal.next" && mv "$proposal.next" "$proposal" || return 1
  done
}
# submit PROPOSAL OUT: node 1 collects the validators' signatures; a
# registration comes back for the candidate, a weight change is issued.
# Retry this, never a new proposal: validators that signed hold that exact
# change until it's on the P-Chain or expires.
submit() {
  "$BIN/btcvm-l1" submit "${L1[@]}" -node-uri "$(uri 1)" -proposal "$1" -payer-key "$DIR/ewoq.json" \
    -rpc-pass-file "$DIR/rpc-password" >"$2"
}
submit_and_register() { # NODE
  submit "$DIR/proposal$1.json" "$DIR/registration$1.json" || return 1
  "$BIN/btcvm-l1" register -registration "$DIR/registration$1.json" -key "$DIR/ewoq.json" \
    -uri "$(uri "$1")" -balance 1 >"$DIR/registered$1.json"
}
add_validator() { # NODE ADMIN...: admin 1 starts the proposal, the others follow
  local i=$1 id
  shift
  "$BIN/btcvm-l1" request -node-uri "$(uri "$i")" -owner "$EWOQ_P" >"$DIR/request$i.json"
  id=$(jq -r .nodeID "$DIR/request$i.json")
  "$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -request "$DIR/request$i.json" -key "$DIR/admin1.json" -yes \
    >"$DIR/proposal$i.json"
  approvals "$DIR/proposal$i.json" "$@"
  settling submit_and_register "$i"
  wait_for 60 "node $i on the validator list" has_validator "$id"
  ok "node $i ($id) is a validator: $(jq -r .txID "$DIR/registered$i.json")"
}
log "Add validators"
# 1 -> 2 validators (50% each) and 2 -> 3 (33.3%): every admin.
"$BIN/btcvm-l1" request -node-uri "$(uri 2)" -owner "$EWOQ_P" >"$DIR/request2.json"
"$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -request "$DIR/request2.json" -key "$DIR/admin1.json" -yes \
  >"$DIR/proposal2-two.json"
approvals "$DIR/proposal2-two.json" 2
if submit "$DIR/proposal2-two.json" "$DIR/out2.json" 2>"$DIR/err2.txt"; then
  fail "two admins added a second validator (50% of the weight)"
fi
grep -q "needs all 3 admins" "$DIR/err2.txt" || fail "unexpected refusal: $(cat "$DIR/err2.txt")"
ok "two admins can't add a validator that would hold 50%: $(grep -o 'after this change[^;:]*' "$DIR/err2.txt" | head -1)"
add_validator 2 2 3
add_validator 3 2 3
# 3 -> 4 (25% each): two admins are enough.
add_validator 4 2
[[ $(validator_count) == 4 ]] || fail "expected 4 validators, got $(validator_count)"

# --- 4. Blocks and fees ---------------------------------------------------------------
log "Payments: each validator builds blocks and is paid their fees"
export BTCVM_RPC BTCVM_RPC_USER=$RPC_USER BTCVM_RPC_PASS BTCVM_NETWORK=testnet
BTCVM_RPC="$(uri 1)/ext/bc/$CHAIN_ID/rpc"
BTCVM_RPC_PASS=$(cat "$DIR/rpc-password")
height() { btc 1 getblockcount | jq -r '.result // 0'; }
height_above() { [[ $(height) -gt $1 ]]; }
wait_for 60 "the peg reserve block" height_above 0
DEST=$(jq -r .btcvmAddress "$DIR/builder5.json")
PAY_AMOUNT=0.001
builder_of() { # the node whose miningAddrs block H's coinbase pays; 6: no fees to pay
  local block addr i
  block=$(btc 1 getblock "[\"$(btc 1 getblockhash "[$1]" | jq -r .result)\", 2]")
  addr=$(jq -r '.result.rawtx[0].vout[] | select(.value > 0) | (.scriptPubKey.address // .scriptPubKey.addresses[0])' <<<"$block" | head -1)
  if [[ -z $addr ]]; then
    # A block with no fees (only its coinbase) has nothing to pay.
    [[ $(jq '.result.rawtx | length' <<<"$block") == 1 ]] && { echo 6; return; }
    echo 0
    return
  fi
  for i in $(seq $N); do
    [[ $addr == "$(jq -r .btcvmAddress "$DIR/builder$i.json")" ]] && { echo "$i"; return; }
  done
  echo 0 # nobody's
}
pay() { # pay COUNT: one payment per block
  local h
  for _ in $(seq "$1"); do
    h=$(height)
    # The address index can lag the newest block by a moment.
    wait_for 30 "the reserve's coins to be spendable" \
      "$BIN/btcvm" send -key "$(jq -r .btcvmWIF "$DIR/reserve.json")" -to "$DEST" -amount "$PAY_AMOUNT"
    wait_for 60 "block $((h + 1))" height_above "$h"
  done
}
# A new validator proposes once the P-Chain height the L1 uses (which lags
# the tip) includes it, so pay in rounds until all four have built blocks.
FIRST=$(($(height) + 1))
BUILT=(0 0 0 0 0 0 0) # 0: paid to nobody's address; 6: no fees
counted=$((FIRST - 1))
for round in $(seq 12); do
  pay 10
  LAST=$(height)
  for h in $(seq $((counted + 1)) "$LAST"); do
    b=$(builder_of "$h")
    BUILT[b]=$((BUILT[b] + 1))
  done
  counted=$LAST
  ((BUILT[1] > 0 && BUILT[2] > 0 && BUILT[3] > 0 && BUILT[4] > 0)) && break
  printf '    (round %d: not every validator has built yet)\n' "$round" >&2
done
printf '    blocks %d-%d paid to node 1: %d, 2: %d, 3: %d, 4: %d, 5: %d; empty: %d; paid elsewhere: %d\n' "$FIRST" "$LAST" \
  "${BUILT[1]}" "${BUILT[2]}" "${BUILT[3]}" "${BUILT[4]}" "${BUILT[5]}" "${BUILT[6]}" "${BUILT[0]}" >&2
for i in 1 2 3 4; do ((BUILT[i] > 0)) || fail "validator $i built none of blocks $FIRST-$LAST"; done
for i in 5 0; do ((BUILT[i] == 0)) || fail "blocks paid to node '$i', which is not a validator"; done
for i in 1 2 3 4; do
  paid=$("$BIN/btcvm" balance -address "$(jq -r .btcvmAddress "$DIR/builder$i.json")" 2>/dev/null | jq -r '.balance // .confirmed // empty' || true)
  ok "validator $i built ${BUILT[$i]} blocks${paid:+, its fee address holds $paid BTC}"
done

# --- 5. Remove node 3 -------------------------------------------------------------------
log "Remove node 3"
N3=$(jq -r .validationID "$DIR/registration3.json")
remove_node3() { # ADMIN...: admin 1 starts, the others follow
  "$BIN/btcvm-l1" remove "${L1[@]}" -node-uri "$(uri 1)" -validation-id "$N3" -key "$DIR/admin1.json" -yes \
    >"$DIR/remove3.json" || return 1
  approvals "$DIR/remove3.json" "$@" || return 1
  settling submit "$DIR/remove3.json" "$DIR/removed3.json"
}
# 4 -> 3 leaves 33.3% each: two admins aren't enough.
if remove_node3 2 2>"$DIR/err3.txt"; then
  fail "two admins removed a validator, leaving 33.3% each"
fi
grep -q "needs all 3 admins" "$DIR/err3.txt" || fail "unexpected refusal: $(cat "$DIR/err3.txt")"
ok "two admins can't leave a validator with a third of the weight"
remove_node3 2 3
N3_ID=$(jq -r .nodeID "$DIR/registration3.json")
not_validator() { ! has_validator "$1"; }
wait_for 60 "node 3 off the validator list" not_validator "$N3_ID"
ok "3 validators left"
# Block proposers come from a lagged P-Chain height (as the validator
# signatures do), so a removed validator can still propose for a minute or
# two. Let that pass, then check.
pay 3
sleep 120
FIRST=$(($(height) + 1))
pay 12
for h in $(seq $FIRST "$(height)"); do
  [[ $(builder_of "$h") != 3 ]] || fail "removed node 3 built block $h"
done
ok "node 3 built none of the next $(($(height) - FIRST + 1)) blocks"

# --- 6. Refusals ---------------------------------------------------------------------------
log "Changes without enough admins' approval are refused"
"$BIN/btcvm-l1" request -node-uri "$(uri 5)" -owner "$EWOQ_P" >"$DIR/request5.json"
if "$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -request "$DIR/request5.json" -yes \
  -key "$DIR/admin1.json" -rpc-pass-file "$DIR/rpc-password" >"$DIR/out4.json" 2>"$DIR/err4.txt"; then
  fail "one admin alone got a registration signed"
fi
grep -q "approved by 1 of this L1's admins; it needs 2" "$DIR/err4.txt" || fail "unexpected refusal: $(cat "$DIR/err4.txt")"
ok "one admin alone refused: $(tail -1 "$DIR/err4.txt" | cut -c1-110)"
"$BIN/btcvm-l1" approve "${L1[@]}" -request "$DIR/request5.json" -key "$DIR/admin1.json" -yes >"$DIR/proposal5.json"
if "$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -proposal "$DIR/proposal5.json" -yes \
  -key "$DIR/outsider.json" -rpc-pass-file "$DIR/rpc-password" >"$DIR/out4.json" 2>"$DIR/err4.txt"; then
  fail "an admin plus a non-admin key got a registration signed"
fi
grep -q "not one of this L1's validatorAdmins" "$DIR/err4.txt" || fail "unexpected refusal: $(cat "$DIR/err4.txt")"
ok "an admin plus an outsider refused: $(tail -1 "$DIR/err4.txt" | cut -c1-110)"
if "$BIN/btcvm-l1" approve "${L1[@]}" -proposal "$DIR/proposal5.json" -key "$DIR/admin1.json" -yes >/dev/null 2>"$DIR/err4.txt"; then
  fail "one admin approved the same change twice"
fi
ok "an admin can't approve twice"
# 3 validators at 100 plus one at 300: 50%. Two admins aren't enough.
"$BIN/btcvm-l1" approve "${L1[@]}" -request "$DIR/request5.json" -key "$DIR/admin1.json" -weight 300 -yes >"$DIR/heavy5.json"
approvals "$DIR/heavy5.json" 2
if submit "$DIR/heavy5.json" "$DIR/out5.json" 2>"$DIR/err6.txt"; then
  fail "two admins added a validator with 50% of the weight"
fi
grep -q "needs all 3 admins" "$DIR/err6.txt" || fail "unexpected refusal: $(cat "$DIR/err6.txt")"
ok "a heavy validator needs every admin: $(grep -o 'after this change[^;:]*' "$DIR/err6.txt" | head -1)"
echo wrong >"$DIR/wrong-password"
if "$BIN/btcvm-l1" approve "${L1[@]}" -node-uri "$(uri 1)" -proposal "$DIR/proposal5.json" -yes \
  -key "$DIR/admin2.json" -rpc-pass-file "$DIR/wrong-password" >/dev/null 2>"$DIR/err5.txt"; then
  fail "the signing endpoint answered without the chain's RPC login"
fi
ok "signing endpoint needs the RPC login"
[[ $(validator_count) == 3 ]] || fail "validator count changed"

# --- 7. One change at a time ------------------------------------------------------------
log "Validators sign one change at a time"
# Node 5's registration, approved and signed but not submitted: until it's on
# the P-Chain or expires, the validators sign no other change, so changes
# approved one by one can't be gathered and submitted together.
"$BIN/btcvm-l1" approve "${L1[@]}" -request "$DIR/request5.json" -key "$DIR/admin1.json" -yes -offline >"$DIR/pending5.json"
approvals "$DIR/pending5.json" 2
submit "$DIR/pending5.json" "$DIR/signed5.json" || fail "node 5's registration wasn't signed"
N4=$(jq -r .validationID "$DIR/registration4.json")
"$BIN/btcvm-l1" remove "${L1[@]}" -node-uri "$(uri 1)" -validation-id "$N4" -key "$DIR/admin1.json" -yes >"$DIR/remove4.json"
approvals "$DIR/remove4.json" 2 3
if submit "$DIR/remove4.json" "$DIR/removed4.json" 2>"$DIR/err7.txt"; then
  fail "a second change was signed while node 5's registration was outstanding"
fi
grep -q "isn't on the P-Chain yet" "$DIR/err7.txt" || fail "unexpected refusal: $(cat "$DIR/err7.txt")"
ok "a second change waits for the first: $(grep -o "this node signed another validator change[^(]*" "$DIR/err7.txt" | head -1)"
submit "$DIR/pending5.json" "$DIR/signed5-again.json" || fail "the same change wasn't signed again"
ok "the outstanding change itself can be signed again"

log "PASS: validators added, took turns building blocks, were paid their fees, and one was removed"
