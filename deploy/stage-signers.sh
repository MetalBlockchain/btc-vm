#!/usr/bin/env bash
# Stages separate signer services on this host from the live signer set, as
# a rehearsal for Phase 2: one directory per key, a keyless coordinator, and
# a service file for each signer. It starts nothing and doesn't touch the
# running bridge. docs/SIGNERS.md ("Moving an existing deployment") and
# docs/FIRST-ROUND-TRIP.md cover the switch itself.
#
# Keys go from the live set to each signer through a pipe: never on a command
# line, in the environment or on screen. The script checks the staged set has
# the same keys in the same order, so the peg address can't change.
#
#   sudo deploy/stage-signers.sh
#
# Settings, from the environment:
#   SOURCE      the live signer set (with private keys)
#   STAGE       where to stage; must not exist yet. The default is inside the
#               secrets folder, so the daily backup includes it
#   BTCVM      the btcvm binary
#   BRIDGE_ENV  node settings to give each signer
#   REGISTRY    the bridge's deposit address registry, copied to each signer
#   RUN_AS      the user the signers run as; empty for the current user
#   MAX_DAILY   most BTC each signer approves moving in 24 hours
#   NETWORK     Bitcoin and BTCVM network
#   POLICY      the bridge's policy flags; must match its service
set -euo pipefail

SOURCE=${SOURCE-/var/lib/metal-main/secrets/signers.json}
STAGE=${STAGE-/var/lib/metal-main/secrets/separate-signers}
BTCVM=${BTCVM-/opt/btcvm/bin/btcvm}
BRIDGE_ENV=${BRIDGE_ENV-/var/lib/metal-main/secrets/bridge.env}
REGISTRY=${REGISTRY-/var/lib/metal-main/secrets/deposits.json}
RUN_AS=${RUN_AS-btcvm}
MAX_DAILY=${MAX_DAILY-0.1}
NETWORK=${NETWORK-mainnet}
POLICY=${POLICY--confirmations 6 -confirmation-tiers 0.001:2,0.005:3 -max-deposit 1000000 -max-circulating 10000000 -min-fee-rate 1 -max-fee-rate 50}

die() { echo "stage-signers: $*" >&2; exit 1; }
as() { if [ -n "$RUN_AS" ]; then sudo -u "$RUN_AS" "$@"; else "$@"; fi; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

[ -e "$STAGE" ] && die "$STAGE already exists; remove it to stage again"
[ -r "$SOURCE" ] || die "can't read $SOURCE"
[ -x "$BTCVM" ] || die "can't run $BTCVM"
[ -r "$BRIDGE_ENV" ] || die "can't read $BRIDGE_ENV"
command -v python3 >/dev/null || die "needs python3"

total=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["privateKeys"]))' "$SOURCE")
required=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["required"])' "$SOURCE")
[ "$total" -ge 1 ] || die "$SOURCE holds no private keys"
echo "Staging $required of $total signers in $STAGE"

mkdir -m 700 "$STAGE"
[ -n "$RUN_AS" ] && chown "$RUN_AS" "$STAGE"

# 1. One signer per key, in the live set's order. The keys come from a
#    plaintext set file, so they stay plaintext here; keys born on
#    operators' own machines (signer-setup init) are encrypted.
cards=()
for ((i = 0; i < total; i++)); do
  n=$((i + 1))
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["privateKeys"][int(sys.argv[2])])' "$SOURCE" "$i" |
    as "$BTCVM" signer-setup init -yes -dir "$STAGE/signer$n" -name "Signer $n" \
      -url "http://127.0.0.1:970$n" -import-key-stdin -plaintext-key 2>/dev/null >/dev/null
  cards+=("$STAGE/signer$n/card.json")
done

# 2. The coordinator's key, and the signer set.
coord=$(as "$BTCVM" signer-setup coordinator -yes -dir "$STAGE/coordinator" 2>/dev/null | json '["coordinatorKey"]')
# shellcheck disable=SC2086 # POLICY is a list of flags
summary=$(as "$BTCVM" signer-setup assemble -yes -required "$required" -coordinator-key "$coord" \
  -btc-network "$NETWORK" -vm-network "$NETWORK" $POLICY \
  -out "$STAGE/signers.json" -cosigners-out "$STAGE/cosigners.json" "${cards[@]}" 2>/dev/null)
fingerprint=$(echo "$summary" | json '["fingerprint"]')
peg=$(echo "$summary" | json '["bitcoinPegAddress"]')

# 3. The same keys in the same order, so the same peg address.
python3 - "$SOURCE" "$STAGE/signers.json" <<'EOF' || die "the staged set's keys differ from the live set's; stopped"
import json, sys
live, staged = (json.load(open(p)) for p in sys.argv[1:3])
assert live["required"] == staged["required"], "required"
assert live["publicKeys"] == staged["publicKeys"], "publicKeys"
assert "privateKeys" not in staged, "the staged set holds private keys"
EOF

# 4. Each signer joins, with this host's nodes and the bridge's registry.
for ((i = 0; i < total; i++)); do
  n=$((i + 1))
  dir="$STAGE/signer$n"
  as "$BTCVM" signer-setup join -yes -dir "$dir" -signers "$STAGE/signers.json" -fingerprint "$fingerprint" \
    -listen "127.0.0.1:970$n" -max-daily "$MAX_DAILY" -bin "$BTCVM" -user "${RUN_AS:-$(id -un)}" 2>/dev/null >/dev/null
  grep -E '^(BTCVM|BITCOIN)_' "$BRIDGE_ENV" | as tee "$dir/signer.env" >/dev/null
  as chmod 600 "$dir/signer.env"
  [ -r "$REGISTRY" ] && as cp "$REGISTRY" "$dir/deposits.json" && as chmod 600 "$dir/deposits.json"
  as mv "$dir/btcvm-signer.service" "$dir/btcvm-signer-$n.service"
done

cat <<EOF

Staged, nothing started. Fingerprint $fingerprint
Peg address $peg (unchanged from the live set)

  $STAGE/signer1..$total        one key each, with its service file and node settings
  $STAGE/coordinator            the coordinator key (signs requests to the signers)
  $STAGE/signers.json           the set, public keys only
  $STAGE/cosigners.json         where the coordinator reaches the signers

Next, as root: deploy/install-signers.sh (one user per signer), then the
switch in docs/FIRST-ROUND-TRIP.md. To undo staging: rm -r $STAGE
EOF
