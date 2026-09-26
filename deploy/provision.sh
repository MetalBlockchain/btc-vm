#!/usr/bin/env bash
# Prepares a fresh Ubuntu 24.04 x86_64 host to run BTCVM on Metal mainnet,
# pegged to Bitcoin mainnet. Run as root:
#
#   deploy/provision.sh
#
# It installs Go, metalgo v1.13.5, BTCVM (built from source) and Bitcoin
# Core 31.1 (checked against the release's SHA-256, whose SHA256SUMS file is
# signed by Bitcoin Core's builders), and creates and starts two services:
#
#   bitcoind-main   Bitcoin Core on mainnet, pruned: it downloads and checks
#                   every block, but keeps only the latest PRUNE_MB (default
#                   60 GB) of them, so it needs about 100 GB of disk in all.
#                   The first sync takes a day or more.
#   metal-mainnet   a Metal mainnet node, syncing only the P-Chain until the
#                   BTCVM L1 exists.
#
# Nothing else starts: deploy/mainnet.sh launch creates the L1 and starts the
# bridge, web wallet and monitor, once the P-Chain has synced and its key is
# funded. The peg signer set goes in /var/lib/metal-main/secrets; see
# docs/RUNBOOK.md. Safe to re-run: it updates BTCVM and keeps all state.
set -euo pipefail

REPO=${REPO:-https://github.com/MetalBlockchain/btc-vm}
BRANCH=${BRANCH:-main}
GO_VERSION=1.24.11
GO_SHA256=bceca00afaac856bc48b4cc33db7cd9eb383c81811379faed3bdbc80edb0af65
METALGO_VERSION=v1.13.5
BITCOIN_VERSION=31.1
# From https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS, whose
# signatures (SHA256SUMS.asc) verified against the builder keys in
# github.com/bitcoin-core/guix.sigs.
BITCOIN_SHA256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e

HOME_DIR=/opt/btcvm
STATE=/var/lib/metal-main
BTC_DATA=/var/lib/bitcoin-main
PRUNE_MB=${PRUNE_MB:-60000}
IP=$(curl -s4 https://ifconfig.me)

log() { echo "provision: $*"; }

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq git jq curl build-essential caddy ufw openssl age rsync

if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VERSION "; then
  log "Go $GO_VERSION"
  curl -sSLo /tmp/go.tgz "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz"
  echo "$GO_SHA256  /tmp/go.tgz" | sha256sum -c -
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local

id btcvm >/dev/null 2>&1 || useradd --system --create-home --home-dir "$HOME_DIR" --shell /usr/sbin/nologin btcvm
install -d -o btcvm -g btcvm "$STATE" "$STATE/plugins" "$STATE/chain-configs" "$BTC_DATA"
install -d -o btcvm -g btcvm -m 700 "$STATE/secrets"
as_btcvm() { sudo -u btcvm env PATH="$PATH" GOTOOLCHAIN=local HOME="$HOME_DIR" "$@"; }

log "metalgo $METALGO_VERSION"
if [[ ! -x "$HOME_DIR/metalgo/build/metalgo" ]]; then
  as_btcvm git clone -q --depth 1 --branch "$METALGO_VERSION" https://github.com/MetalBlockchain/metalgo "$HOME_DIR/metalgo"
  (cd "$HOME_DIR/metalgo" && as_btcvm ./scripts/build.sh)
fi

log "BTCVM from $REPO@$BRANCH"
if [[ -d "$HOME_DIR/src/.git" ]]; then
  (cd "$HOME_DIR/src" && as_btcvm git fetch -q origin "$BRANCH" && as_btcvm git reset -q --hard "origin/$BRANCH")
else
  as_btcvm git clone -q --branch "$BRANCH" "$REPO" "$HOME_DIR/src"
fi
(
  cd "$HOME_DIR/src"
  as_btcvm go build -o "$HOME_DIR/bin/btcvm" ./cmd/btcvm
  as_btcvm go build -o "$HOME_DIR/bin/btcvm-l1" ./cmd/btcvm-l1
  VMID=$(as_btcvm go run ./scripts/vm-id-generator.go)
  as_btcvm go build -o "$STATE/plugins/$VMID" ./cmd/btcvm-plugin
)
ln -sf "$HOME_DIR/bin/btcvm" /usr/local/bin/btcvm
# Separate signers (deploy/install-signers.sh) run a root-owned copy, which
# the btcvm user can't replace. Update it too, and restart them.
if [[ -d /usr/local/lib/btcvm ]]; then
  install -o root -g root -m 755 "$HOME_DIR/bin/btcvm" /usr/local/lib/btcvm/btcvm
  systemctl try-restart 'btcvm-signer-*.service'
fi

log "Bitcoin Core $BITCOIN_VERSION"
if ! /opt/bitcoin/bin/bitcoind -version 2>/dev/null | grep -q "v$BITCOIN_VERSION"; then
  curl -sSLo /tmp/bitcoin.tgz "https://bitcoincore.org/bin/bitcoin-core-$BITCOIN_VERSION/bitcoin-$BITCOIN_VERSION-x86_64-linux-gnu.tar.gz"
  echo "$BITCOIN_SHA256  /tmp/bitcoin.tgz" | sha256sum -c -
  tar -C /tmp -xzf /tmp/bitcoin.tgz
  rm -rf /opt/bitcoin && mv "/tmp/bitcoin-$BITCOIN_VERSION" /opt/bitcoin
fi
if [[ ! -f "$BTC_DATA/bitcoin.conf" ]]; then
  # The bridge keeps a watch-only descriptor wallet here ("btcvm"); it holds
  # addresses, never keys. Pruning keeps weeks of recent blocks, enough for
  # a signer to rescan for a deposit it missed. dbcache speeds the first
  # sync; lower it after.
  cat >"$BTC_DATA/bitcoin.conf" <<EOF
server=1
prune=$PRUNE_MB
dbcache=8000
maxconnections=40
maxuploadtarget=20000
rpcbind=127.0.0.1
# Load the bridge's wallet on every start, not only when the bridge asks.
wallet=btcvm
rpcallowip=127.0.0.1
rpcuser=btcvm
rpcpassword=$(openssl rand -hex 24)
EOF
  chown btcvm:btcvm "$BTC_DATA/bitcoin.conf" && chmod 600 "$BTC_DATA/bitcoin.conf"
fi

cat >/etc/systemd/system/bitcoind-main.service <<EOF
[Unit]
Description=Bitcoin Core (mainnet)
After=network-online.target

[Service]
User=btcvm
ExecStart=/opt/bitcoin/bin/bitcoind -datadir=$BTC_DATA -printtoconsole
Restart=on-failure
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
EOF

# The node syncs only the P-Chain; deploy/mainnet.sh adds --track-subnets
# once the L1 exists, and a re-run here keeps it: without it the node stops
# running the L1, which then has no validator. Its APIs listen on
# localhost only.
TRACK=""
if [[ -f $STATE/chain.json ]]; then
  TRACK="--track-subnets=$(jq -r .subnetID "$STATE/chain.json") "
fi
cat >/etc/systemd/system/metal-mainnet.service <<EOF
[Unit]
Description=Metal Blockchain mainnet node (BTCVM L1 validator)
After=network-online.target

[Service]
User=btcvm
Environment=HOME=$HOME_DIR
WorkingDirectory=$HOME_DIR
ExecStart=$HOME_DIR/metalgo/build/metalgo --network-id=mainnet --partial-sync-primary-network=true --data-dir=$STATE/node --log-dir=$STATE/logs --plugin-dir=$STATE/plugins --chain-config-dir=$STATE/chain-configs --http-host=127.0.0.1 --http-port=9660 --staking-port=9661 ${TRACK}--public-ip=$IP
Restart=on-failure
# SIGTERM to metalgo only: it shuts each chain down in order, and the
# BTCVM plugin closes its database. Sent to the whole unit, the signal
# killed the plugin first and lost accepted blocks.
KillMode=mixed
TimeoutStopSec=120
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

log "firewall"
ufw allow OpenSSH >/dev/null
ufw allow 80,443/tcp >/dev/null
ufw allow 9661/tcp >/dev/null   # Metal staking (peer) port
ufw allow 8333/tcp >/dev/null   # Bitcoin peers
ufw --force enable >/dev/null

systemctl daemon-reload
systemctl enable --now metal-mainnet >/dev/null
systemctl restart metal-mainnet
systemctl enable --now bitcoind-main >/dev/null

log "done"
cat <<EOF

Bitcoin Core is syncing mainnet:  sudo -u btcvm /opt/bitcoin/bin/bitcoin-cli -datadir=$BTC_DATA getblockchaininfo
The Metal node is syncing the P-Chain.

Next:
  1. Put the peg signer set in $STATE/secrets (docs/SIGNERS.md) and a funded
     P-Chain key in $STATE/secrets/p-chain-key.json.
  2. deploy/mainnet.sh status
  3. deploy/mainnet.sh launch
EOF
