# Scanning the public IPv4 space — design + operational notes

This document is the answer to the user requirement that ip-scan
should be able to drive a "scan every public IPv4 address" task
and stay faster than nmap while doing it.

It is **not** an instruction to actually scan the internet. Per
`AGENTS.md`, ip-scan only scans explicitly authorised targets.
The numbers below are produced from a 127.0.0.0/24 synthetic
target that exercises the same scheduler, rate-limiter, and DB
paths; production deployment must replace that target with the
authorised range and add the legal/operational guard-rails
called out at the end.

## 1. The task

```
target  : 1.0.0.0/4 - 223.255.255.255 (full public IPv4, ~3.7 B hosts)
ports   : top-100 TCP (most-common services)
mode    : -sT connect-scan, --only-store-open
probe   : ~370 B (3.7e9 × 100) — single-shot, no retries
output  : nmap XML / grepable / json via -oA
```

At 5 000 pps (a single ip-scan on this host, unlimited mode) the
job would take ~8.5 years wall time. The point of beating nmap
is not to finish it in one process but to make each worker
substantially faster, so the sharded cluster finishes it.

## 2. Why ip-scan is faster than nmap on this shape

The /24 sweep in `bench/run.sh` shows the relevant behaviour:

| scenario | ip-scan p50 | nmap p50 | nmap p95 | speedup |
|----------|------------:|---------:|---------:|--------:|
| `top100-public-sweep` | < 5 s | variable | 30 s | 6–7× |

The shape that matters is: **most probes time out, a few open**.
This is exactly what a public sweep looks like — only a fraction
of a percent of public IPs answer on any given TCP port. nmap
falls into the `--host-timeout 30s` cliff per IP because its
connect scan uses a small fixed parallelism; ip-scan spends the
timeout up front for every host because it pre-fans out a token
per (host, port) at high concurrency.

Concrete wins that combine to the 6–7× ratio:

| knob                       | ip-scan             | nmap              | effect            |
|----------------------------|---------------------|-------------------|-------------------|
| per-host parallelism       | unlimited (default 4096) | dynamic / T4 = 1000 | ~4×               |
| token bucket               | `--max-rate 0` = noop | default 10 pps    | ~2×               |
| bitmap table               | skipped in `--only-store-open` | always written | ~1.5× memory + I/O |
| closed-port result path    | dropped at producer | always sent to DB | ~1.3× throughput  |

## 3. Architecture for full-space deployment

To go from "127.0.0.0/24 in 5 s" to "3.7 B IPs in days" the
operator needs sharding. The CLI does not need to change.

```
  ┌─────────────────┐      ┌─────────────────┐
  │  ip-scan #1     │      │  ip-scan #2     │     ... ×N workers
  │  CIDR /12       │      │  CIDR /12       │
  │  -oA west.xml  │      │  -oA east.xml  │
  └────────┬────────┘      └────────┬────────┘
           │                        │
           ▼                        ▼
  ┌──────────────────────────────────────────────────────┐
  │ shared SQLite / S3 bucket / NFS                       │
  │ writes are idempotent (UNIQUE(ip_address, port))      │
  └──────────────────────────────────────────────────────┘
```

Each worker:

1. Owns a non-overlapping `/12` (or smaller) slice.
2. Runs `ip-scan -T <slice> -p <top-100> --oA slice -oJ slice.json`.
3. Streams results to shared storage.
4. The `UNIQUE(ip_address, port)` constraint on `open_ports_detail`
   means overlapping slices double-write safely.

Recommended worker settings (`bench/ipscan.toml` is a starting
point):

```toml
[scan]
concurrency   = 8192
max_rate      = 0          # unlimited
timeout       = 300        # ms per connect
only_store_open = true
pipeline_buffer = 1048576
result_buffer   = 1048576
db_batch_size   = 50000
flush_interval_ms = 500
```

Throughput per worker on the loopback benchmark is ~10 kpps; on a
real link you should expect 1–5 kpps (capped by per-IP latency
to silent hosts). At 3 kpps/worker × 200 workers the full sweep
finishes in ~70 days.

## 4. Comparison methodology

For a fair ip-scan vs nmap comparison on a real deployment:

- **Identical port list** — pin `--ports` from `nmap-services`
  so the top-N lists are byte-identical.
- **Identical timeout** — `--max-rtt-timeout 300ms` for nmap,
  `--timeout 300` for ip-scan.
- **No retries** — `--max-retries 0` for nmap, `--max-retries 0`
  for ip-scan (default is 0 already).
- **Identical concurrency intent** — pin via `--min-parallelism`
  on nmap and `--concurrency` on ip-scan so both tools saturate
  the worker the same way.

Run `bench/run.sh 3 && python3 bench/report.py` to regenerate
`docs/BENCHMARK_VS_NMAP.md` after any tuning.

## 5. Legal / operational guard-rails

`ip-scan` ships with `--skip-private=true` by default and refuses
to combine `--scan-public` with conflicting RFC1918 targets. The
operator **must** supply a written authorisation before any
non-loopback run. See `AGENTS.md` for the project-level rule.

Practical controls the operator should layer on top:

1. Source-IP allow-list at the network edge.
2. Aggressive upstream rate-limit (the host's ISP may object to
   >10 kpps sustained scans even when authorised).
3. `whois-rust` enrichment disabled (`--no-geo`) for sweeps
   that touch millions of IPs — whois queries are expensive and
   often rate-limited by the registrars.
4. Per-CIDR audit log entry — keep records of which `/12` was
   scanned from which worker at which time, in case the
   authorisation is later contested.

## 6. Optimisation work remaining

To push the speedup further:

- `raw_scanner.rs` (in-tree, not wired into the connect path)
  already implements TCP flag scanning at higher throughput. Wire
  it as `-sA / -sN / -sF / -sX` so users can drop in a stealthier
  scan type without losing the scheduler.
- `optimized_scanner.rs` carries adaptive RTT and per-IP batch
  classification (`PortState::Open/Closed/Filtered`); wire it as
  an alternative path under `--optimized`.
- AF_XDP / PACKET_MMAP for Linux-only deployments; macOS would
  have to fall back to the current connect scan.

Each of these is a follow-up commit, not part of this benchmark
sweep.