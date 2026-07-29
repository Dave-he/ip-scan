#!/usr/bin/env bash
# One-shot deploy + restart for both ip-scan production servers.
#
# Cross-compiles static-pie musl binary, packages web/ + config.toml,
# scp's the archive to each host, pkill's the running instance, and
# restarts under screen with the agreed production flags
# (--preset fullpublic for /0 sweep).
#
# Usage:
#   ./deploy.sh                # deploy to BOTH sshali + sshtx
#   ./deploy.sh sshali         # deploy to one host only
#   ./deploy.sh sshtx          # deploy to one host only
set -euo pipefail

TARGET_TRIPLE="x86_64-unknown-linux-musl"
ARTIFACT="/tmp/ip-scan-deploy.tar.gz"

# Per-host config: ssh port + ip range + screen dir mode
HOST_SSHALI_HOST="39.103.188.33"
HOST_SSHALI_TARGET_ARGS="-s 1.0.0.0 -e 223.255.255.255"
HOST_SSHALI_SCREEN_MODE="777"
# Distributed / cluster identity for the ali node. Surfaced via
# /api/v1/system so the standalone frontend can group results by source.
HOST_SSHALI_NODE_ARGS="--node-id node-ali --node-label ali-shanghai --node-provider Aliyun --node-latitude 31.2304 --node-longitude 121.4737"

HOST_SSHTX_HOST="43.133.224.11"
HOST_SSHTX_TARGET_ARGS="-s 1.0.0.0 -e 223.255.255.255"
HOST_SSHTX_SCREEN_MODE="775"
# Distributed / cluster identity for the tx node.
HOST_SSHTX_NODE_ARGS="--node-id node-tx --node-label tx-beijing --node-provider Tencent --node-latitude 39.9042 --node-longitude 116.4074"

# Common production flags (preserved across hosts).
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
COMMON_FLAGS=(
  --preset fullpublic
  --api
  --loop-mode
  --round-delay-ms 2000
  --max-rounds 4
  --max-rate 5000
  --probe-service
  --probe-concurrency 16
)

deploy_one() {
  local label="$1"; shift
  local host="$1"; shift
  local target_args="$1"; shift
  local screen_mode="$1"; shift
  local node_args="$1"; shift

  echo "═══════════════════════════════════════════════════════════════"
  echo "  Deploy → $label   $host   screen-mode=$screen_mode"
  echo "═══════════════════════════════════════════════════════════════"

  scp -P 2222 -o ServerAliveInterval=10 "$ARTIFACT" "root@${host}:/tmp/"

  ssh -p 2222 -o ServerAliveInterval=10 "root@${host}" 'bash -s' <<EOF
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
curl -s --max-time 5 http://127.0.0.1:9090/api/v1/stats; echo
grep -cE 'ERROR|WARN|EMFILE|panic' /tmp/scan.log | xargs echo "  errors+warns+emfile+panic lines:"
EOF
}

# Always rebuild locally so the deploy matches the worktree.
echo "Building ${TARGET_TRIPLE}…"
cargo build --release --target "${TARGET_TRIPLE}"
echo "Packaging…"
tar czf "$ARTIFACT" \
  -C "target/${TARGET_TRIPLE}/release" ip-scan \
  -C "$(pwd)" web frontend config.toml
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
