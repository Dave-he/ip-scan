#!/usr/bin/env bash
# One-shot deploy + restart for both ip-scan production servers.
#
# Cross-compiles a static-pie musl binary, packages web/ (unified
# distributed console) + config.toml, scp's the archive to each host,
# pkill's the running instance, and restarts under screen.
#
# Default mode (MODE=pure) ships the scanner nodes as a pure backend
# (--api-only) - the distributed console connects and starts scans
# remotely via POST /api/v1/scan/start. This is the production
# "frontend / backend separated" deployment: every node is just an API,
# scan work is initiated by the operator from the console.
#
# MODE=full restores the original combined scanner+API behaviour for
# unattended long-running sweeps (--api --loop-mode --preset fullpublic).
#
# Usage:
#   ./deploy.sh                       # MODE=pure, deploy to BOTH nodes
#   ./deploy.sh sshali                # MODE=pure, one host
#   MODE=full ./deploy.sh sshali      # combined scanner+API on one host

set -euo pipefail

TARGET_TRIPLE="x86_64-unknown-linux-musl"
ARTIFACT="/tmp/ip-scan-deploy.tar.gz"
MODE="${MODE:-pure}"

# Per-host config: ssh port + scan target range + screen dir mode
HOST_SSHALI_HOST="39.103.188.33"
HOST_SSHALI_SCREEN_MODE="777"
# Pure-backend mode is API-only, so the scan target range is provided by
# whoever initiates the scan (the unified web console). We pre-populate
# the start_ip/end_ip displayed by /api/v1/system with a sensible default
# so the "node status" view in the console always shows a target.
HOST_SSHALI_TARGET_ARGS="-s 1.0.0.0 -e 223.255.255.255"
# Distributed / cluster identity for the ali node. Surfaced via
# /api/v1/system so the console can label each server.
HOST_SSHALI_NODE_ARGS="--node-id node-ali --node-label ali-shanghai --node-provider Aliyun --node-latitude 31.2304 --node-longitude 121.4737"

HOST_SSHTX_HOST="43.133.224.11"
HOST_SSHTX_SCREEN_MODE="775"
HOST_SSHTX_TARGET_ARGS="-s 1.0.0.0 -e 223.255.255.255"
HOST_SSHTX_NODE_ARGS="--node-id node-tx --node-label tx-beijing --node-provider Tencent --node-latitude 39.9042 --node-longitude 116.4074"

# Common flags shared by every host in pure mode.
PURE_FLAGS=(
  --api-only
  --max-rate 5000
)

# Common flags shared by every host in full mode (legacy scanner+API).
#
# --max-rate 5000 keeps each scanner well below the Linux SYN-cookie
# threshold (the OS activates syncookies once the embryonic-queue / listen
# backlog saturates, which previously caused TX to miss open ports). The
# earlier default (unlimited) was hitting 1.5M+ SyncookiesRecv on TX.
#
# --probe-service turns on the background enrichment worker so newly
# discovered open ports get Banner/HTTP/TLS metadata within the same run
# instead of sitting in service_probe_state untouched. --probe-concurrency
# is intentionally lower than --concurrency because each probe opens an
# extra application-layer connection.
FULL_FLAGS=(
  --preset fullpublic
  --api
  --loop-mode
  --round-delay-ms 2000
  --max-rounds 4
  --max-rate 5000
  --probe-service
  --probe-concurrency 16
)

case "$MODE" in
  pure) COMMON_FLAGS=("${PURE_FLAGS[@]}") ;;
  full) COMMON_FLAGS=("${FULL_FLAGS[@]}") ;;
  *) echo "unknown MODE=$MODE (expected pure|full)" >&2; exit 64 ;;
esac

deploy_one() {
  local label="$1"; shift
  local host="$1"; shift
  local target_args="$1"; shift
  local screen_mode="$1"; shift
  local node_args="$1"; shift

  echo "================================================================"
  echo "  Deploy -> $label   $host   mode=$MODE   screen-mode=$screen_mode"
  echo "================================================================"

  scp -P 2222 -o ServerAliveInterval=10 "$ARTIFACT" "root@${host}:/tmp/"

  ssh -p 2222 -o ServerAliveInterval=10 "root@${host}" 'bash -s' <<DEPLOY_EOF
set +e
pkill -f ip-scan || true; sleep 2
chmod ${screen_mode} /run/screen 2>/dev/null || true
mkdir -p /root/ip-scan
cd /root/ip-scan && tar xzf /tmp/ip-scan-deploy.tar.gz
screen -dmS scan bash -lc 'cd /root/ip-scan && ulimit -n 65535 && exec ./ip-scan ${target_args} ${node_args} ${COMMON_FLAGS[*]} > /tmp/scan.log 2>&1'
sleep 5
PID=\$(pgrep -x ip-scan)
echo "  pid=\$PID rss=\$(awk '/VmRSS/{print \$2\$3}' /proc/\$PID/status) fd=\$(ls /proc/\$PID/fd 2>/dev/null | wc -l)"
curl -s -o /dev/null -w "  healthz=%{http_code}\n" --max-time 5 http://127.0.0.1:9090/api/v1/healthz
curl -s --max-time 5 http://127.0.0.1:9090/api/v1/system | head -c 200; echo
grep -cE 'ERROR|WARN|EMFILE|panic' /tmp/scan.log | xargs echo "  errors+warns+emfile+panic lines:"
DEPLOY_EOF
}

# Always rebuild locally so the deploy matches the worktree.
echo "Building ${TARGET_TRIPLE}..."
cargo build --release --target "${TARGET_TRIPLE}"
echo "Packaging..."
# web/ now ships the unified distributed console (HTML + CSS + ES modules
# under web/src/) - the legacy frontend/ directory was merged into web/,
# so the tarball only needs web/ + config.toml.
tar czf "$ARTIFACT" \
  -C "target/${TARGET_TRIPLE}/release" ip-scan \
  -C "$(pwd)" web config.toml
md5sum "$ARTIFACT"

case "${1:-both}" in
  sshali) deploy_one "ALIYUN" "$HOST_SSHALI_HOST" "$HOST_SSHALI_TARGET_ARGS" "$HOST_SSHALI_SCREEN_MODE" "$HOST_SSHALI_NODE_ARGS" ;;
  sshtx)  deploy_one "TENCENT" "$HOST_SSHTX_HOST" "$HOST_SSHTX_TARGET_ARGS" "$HOST_SSHTX_SCREEN_MODE" "$HOST_SSHTX_NODE_ARGS" ;;
  both|"")
    deploy_one "ALIYUN" "$HOST_SSHALI_HOST" "$HOST_SSHALI_TARGET_ARGS" "$HOST_SSHALI_SCREEN_MODE" "$HOST_SSHALI_NODE_ARGS"
    deploy_one "TENCENT" "$HOST_SSHTX_HOST" "$HOST_SSHTX_TARGET_ARGS" "$HOST_SSHTX_SCREEN_MODE" "$HOST_SSHTX_NODE_ARGS"
    ;;
  *) echo "unknown target: $1" >&2; exit 64 ;;
esac

echo "Done."
