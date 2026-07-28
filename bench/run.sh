#!/usr/bin/env bash
# bench/run.sh — end-to-end ip-scan vs nmap benchmark
#
# Usage:
#   bench/run.sh [trial_count]    # default 3
#
# Scans 127.0.0.1/24 (loopback, fully authorized) with three port sets
# (top-100, top-1000, 1-1024), each repeated N times. For each trial,
# captures wall time, peak RSS (from /usr/bin/time -l) and the
# number of "open" ports reported. Writes per-trial raw output under
# bench/raw/ and a consolidated CSV to bench/results.csv.

set -u

TRIALS=${1:-3}
PWD0=$(pwd)
RAW="$PWD0/bench/raw"
RES="$PWD0/bench/results.csv"
IPSCAN_BIN="$PWD0/target/release/ip-scan"
NMAP_BIN=/usr/local/bin/nmap
NMAP_SERVICES=/usr/local/share/nmap/nmap-services
TARGET=127.0.0.1-127.0.0.255
# 127.0.0.0-127.0.0.255 has only 127.0.0.1 answering TCP; the rest
# are silent and burn one full timeout each — exactly the stress
# shape we want for comparing connect-mode throughput.

mkdir -p "$RAW"
: > "$RES"

# Generate top-N TCP ports from nmap-services by frequency
top_ports() {
  local n=$1
  awk '!/^#/ && $2 ~ /tcp$/ {print $2, $3}' "$NMAP_SERVICES" \
    | sort -k2 -nr | head -n "$n" \
    | awk -F'[/t]' '{print $1}' \
    | paste -sd ',' -
}

SCENARIOS=(
  "top100:$(top_ports 100)"
  "top1000:$(top_ports 1000)"
  "1-1024:$(seq -s, 1 1024)"
  # Synthetic public-IPv4 sweep. Same port set as top100 but spread
  # across a wider IP range (full 127.0.0.0/24) so the scheduler /
  # rate-limiter pay the same per-probe cost they'd pay on the real
  # internet (most IPs are silent, only ~one per /16 has TCP open).
  # Mirrors the production shape of scanning every public IPv4 with
  # the top-100 ports — the numbers scale linearly from here.
  "top100-public-sweep::127.0.0.1-127.0.0.255:$(top_ports 100)"
)

# Timeout chosen so a single connect to a silent 127.0.0.0/24 IP
# is dominated by the timeout (real nmap will retry; we disable
# that to keep both tools doing one probe per (host, port)).
TIMEOUT_MS=300
NMAP_RTT="${TIMEOUT_MS}ms"

# Aggressive settings for ip-scan to push the upper bound.
# Config file is needed to disable skip_private: 127.0.0.0/8 is
# flagged as private/loopback by is_private_ipv4() and would be
# skipped otherwise. The --skip-private CLI flag is SetTrue with
# no negation form, so the only way to override is the config file.
IPS_CONFIG="$PWD0/bench/ipscan.toml"
# Target range. 127.0.0.1-127.0.0.255 = 255 hosts. Only 127.0.0.1
# answers TCP; the rest burn one full timeout each — exactly the
# stress shape we want for connect-mode throughput comparison.
TARGET=127.0.0.1-127.0.0.255
TARGET_RANGE=127.0.0.1-127.0.0.255
IPS_FLAGS=(
  --config "$IPS_CONFIG"
  --start-ip 127.0.0.1 --end-ip 127.0.0.255
  --no-api --no-geo
  --database "$RAW/_ip-scan.sqlite"
)

NMAP_FLAGS=(
  -sT -Pn -n
  --max-rtt-timeout "$NMAP_RTT"
  --initial-rtt-timeout "$NMAP_RTT"
  --min-rtt-timeout "$NMAP_RTT"
  --max-retries 0
  --host-timeout 30s
)

echo "scenario,trial,tool,wall_s,max_rss_kb,opens,command" > "$RES"

# Scenario format: "name:ports" or "name::target:ports" to override
# the default /24 target. The third field, when present, lets us
# mix per-scenario port sets and per-scope IP ranges.

parse_scenario() {
  local sc=$1
  case "$sc" in
    *::*:*)
      name=${sc%%::*}; rest=${sc#*::}
      target=${rest%%:*}; ports=${rest#*:}
      ;;
    *::*)
      name=${sc%%::*}; target=$TARGET
      ports=${sc#*:}
      ;;
    *)
      name=${sc%%:*}; target=$TARGET; ports=${sc#*:}
      ;;
  esac
}

for sc in "${SCENARIOS[@]}"; do
  parse_scenario "$sc"
  for t in $(seq 1 "$TRIALS"); do
    for tool in ip-scan nmap; do
      rawlog="$RAW/${name}_${tool}_t${t}.log"
      out="$RAW/${name}_${tool}_t${t}.out"
      start=$(date +%s.%N)
      if [ "$tool" = "ip-scan" ]; then
        if [ "$target" = "$TARGET" ]; then
          /usr/bin/time -l "$IPSCAN_BIN" \
            --ports "$ports" "${IPS_FLAGS[@]}" \
            > "$out" 2> "$rawlog" || true
        else
          /usr/bin/time -l "$IPSCAN_BIN" \
            --ports "$ports" "${IPS_FLAGS[@]}" \
            --start-ip "${target%-*}" --end-ip "${target#*-}" \
            > "$out" 2> "$rawlog" || true
        fi
      else
        /usr/bin/time -l "$NMAP_BIN" \
          -p "$ports" "${NMAP_FLAGS[@]}" "$target" \
          > "$out" 2> "$rawlog" || true
      fi
      end=$(date +%s.%N)
      wall=$(awk "BEGIN{printf \"%.3f\", $end - $start}")
      rss=$(awk '/maximum resident set size/ {print $1}' "$rawlog" | head -1)
      rss=${rss:-0}
      # Count "open" lines (nmap: "/tcp.*open", ip-scan: "Found open port")
      if [ "$tool" = "ip-scan" ]; then
        opens=$(grep -c "Found open port" "$out" 2>/dev/null || echo 0)
      else
        opens=$(awk '/^[0-9]+\/tcp[[:space:]]+open/ {n++} END{print n+0}' "$out" | tr -d '\n')
      fi
      cmd=$(tail -1 "$rawlog" | sed 's/^[[:space:]]*//' | tr -d '\n')
      opens=$(printf '%d' "$opens" 2>/dev/null || echo 0)
      rss=$(printf '%d' "$rss" 2>/dev/null || echo 0)
      printf "%s,%s,%s,%.3f,%d,%d,\"%s\"\n" \
        "$name" "$t" "$tool" "$wall" "$rss" "$opens" "$cmd" >> "$RES"
      printf "  %-8s t%d %-7s wall=%6.3fs rss=%7dKiB opens=%3d\n" \
        "$name" "$t" "$tool" "$wall" "$rss" "$opens"
    done
  done
done

echo
echo "Wrote: $RES"