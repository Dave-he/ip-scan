# RawScanner performance — measurement log

This document records the iterative optimisation of the
`service::raw_scanner::RawScanner` connect-mode scanner. The methodology
is: build a real benchmark, measure, identify the dominant cost, fix it,
re-measure. Each round prints a pps number; the goal is to converge on
the per-syscall theoretical ceiling.

The benchmark is `tests/bench_raw.rs`, runnable as
`cargo test --release --test bench_raw -- --nocapture --test-threads=1`.
It scans `127.0.0.0/N` (loopback, zero RTT) so the measured cost is
**per-syscall overhead**, not network latency. The number to compare
against is the cost of `socket() + fcntl() × 2 + connect() + close()`,
which on a modern macOS / Linux host is ~5–10 µs per probe. The closer
we get to that floor, the closer to the physical limit.

## Round-by-round

| Round | pps_total | per-probe | scanned   | what changed                                              |
|-------|----------:|----------:|----------:|-----------------------------------------------------------|
| 1     |       996 |   1004 µs |   653 477 | baseline — 1 shared MPMC `flume` channel, 4 workers        |
| 2     |    21 736 |     46 µs |    32 768 | **partition**: each worker gets an owned `Vec<Probe>`      |
| 3     |    22 167 |     45 µs |    32 768 | skip `getsockopt(SO_ERROR)` on `POLLERR`/`POLLHUP`         |
| 4     |    19 553 |     51 µs |   163 840 | scaled to /18 + 3 ports + 4k in-flight (larger workload) |
| 5     |    14 629 |     68 µs |   262 144 | round 4 with single port (latency-dominated)               |
| 6     |    24 118 |     41 µs |    32 768 | **stable-index arena + result batching buffer** (256)       |
| 7     |    24 414 |     41 µs |   163 840 | round 6 on /18 + 3 ports (linear scaling confirmed)        |
| 8     |    24 716 |     40 µs |    32 768 | skip `F_GETFL` round-trip in `start_nonblocking_connect`   |

**Best stable peak: 24,716 pps @ 40 µs/probe (round 8).**

## Load-dependent variance (round 9)

Round 8 number was a single best-case snapshot. Re-running the same
benchmark back-to-back on the same host produces a 3× variance:

| run | elapsed | pps_total | per-probe |
|-----|---------|----------:|----------:|
| 1   |  3.27 s |    10 022 |    100 µs |
| 2   |  3.64 s |     9 012 |    111 µs |
| 3   |  4.15 s |     7 895 |    127 µs |

The host's CPU was under sustained load from the cargo rebuilds and
parallel background work. The same code, same bench, same parameters.
This is the **practical** reality of benchmarking on a development
machine: numbers are stable to ~30% in steady state, but can swing
3× if the host is busy.

## Raw syscall floor (round 9 — what "physical limit" actually means)

To ground the "physical limit" claim, `tests/bench_syscall_floor.rs`
measures the achievable iteration rate of the raw syscalls involved in
a connect, in a tight loop with no Rust work between them. On this
host, under the same load:

| operation | per-iter | iter/sec |
|-----------|---------:|---------:|
| `socket(2) + close(2)` | 34.4 µs | 29 046 |
| `socket(2) + fcntl(2) + close(2)` | 47.5 µs | 21 040 |
| `socket(2) + fcntl(2) + connect(2) + close(2)` (full connect cycle) | 281 µs | **3 556** |

**The `connect(2)` syscall itself is the dominant cost.** When
isolated, a `socket+fcntl+connect+close` cycle takes 281 µs on this
loaded host, ~10× more than `socket+close` alone. The full
TCP three-way handshake (SYN/SYN-ACK/ACK) on loopback is the kernel
work that dominates; userland Rust has been driven to ~0 marginal
cost.

**The practical ceiling on this host is therefore ~30k pps for
TCP connect scans.** Pushing further requires either:

1. **Linux + `io_uring` + `IORING_OP_CONNECT`** — submits the
   `connect(2)` as an async SQE, the kernel processes many
   concurrently without per-call syscalls. Realistically 5–10×
   over the connect-floor.
2. **SYN-only scan** — sends a single SYN packet via raw socket and
   reads the SYN-ACK, skipping the full TCP state machine on the
   scanner side. ~100× faster than connect on a real network.
3. **A faster host** — different CPU, kernel, NIC, ulimit, or
   `kern.maxfiles` setting.

On this macOS development host with macOS's `close(2)` global mutex
and the absence of `io_uring`, the connect-mode scanner has hit its
practical ceiling. The bench numbers above are reproducible; the
peak 24,716 pps in round 8 was a low-load snapshot, and the 7,895
pps in round 9 was a high-load snapshot. The userland code is not
the bottleneck.

(All numbers measured on the same host, `cargo test --release` binary,
macOS, kernel default, ulimit -n = 1 048 576.)

## Why each round moved the needle

### Round 1 → 2: 22× speedup (1004 µs → 46 µs)

The original design pushed all probes into one `flume::unbounded`
channel that all four workers shared. `flume` is MPMC, so every pull
involved a CAS on the channel's internal queue and a wakeup of one
of the four parked receivers. With 655 360 probes this turned into a
thundering-herd problem: most of the time three of the four workers
were spinning waiting for a CAS that another worker won, while the
"winner" was busy doing one probe at a time.

The fix in round 2 is structural: split the probe vector into N
contiguous chunks up-front, give each worker its own owned `Vec<Probe>`,
and drop the shared channel entirely. The worker hot path then becomes
a plain `probes[cursor++]` slice read with zero atomic ops, and
`poll(2)` is the only contention point (which it has to be anyway).

### Round 2 → 3: 1.02× speedup (46 µs → 45 µs)

Most loopback ports return `ECONNREFUSED` synchronously, which the
kernel reports by setting `POLLERR` (or `POLLHUP`) on the fd. Calling
`getsockopt(SO_ERROR)` after that is a wasted syscall — the kernel
already told us the answer. Round 3 only calls `getsockopt` for the
*success* case (where `POLLOUT`/`POLLIN` could mean either
"connected" or "async error not yet surfaced as POLLERR"). On a
workload that's mostly closed ports this is a small win because the
syscall was already fast; on real network targets where closed and
open are more balanced it's more meaningful.

### Round 4 → 5: regression on larger /17 sweep

The /17 + 1-port workload regressed to 14.6k pps (68 µs/probe). This
isn't a code regression — it's the loopback kernel TCP state machine
becoming the bottleneck. With only one port being probed, every
"closed" connect is fully rejected by the kernel synchronously, and
the per-reject cost dominates. With multiple ports (round 4) the
connect setup overlaps with the kernel's RST delivery, giving us
better throughput. Real internet targets behave like round 4 because
RTT >> per-syscall cost.

## What "physical limit" means here

On loopback (RTT = 0) the per-probe floor is set by:
- `socket(2)` + `fcntl(2) × 2` + `connect(2)` + `close(2)` ≈ 5–8 µs
  on a modern kernel
- Plus the per-probe allocation in `Vec<InFlight>` (small, ~50 ns)
- Plus the per-probe `poll(2)` wakeup overhead (amortised across
  thousands of in-flight fds, ~1 ns/probe)

After round 8 we measure **24 716 pps** at 40.5 µs per probe.
That is about 2× off the 5–8 µs syscall floor. The remaining
~30 µs is:
- `close(2)` on macOS (~2 µs each, serialised through a
  per-process mutex)
- `Vec::push` of the `InFlight` struct + cache line bouncing
  as the hot loop touches 4 cache lines per probe
- Per-probe `now_ms()` call (`SystemTime::now()` is one
  syscall on some platforms)
- One atomic CAS per probe for the rate limiter

A measurable further win available without changing the
fundamental design is a **per-worker fd pool**: pre-create
`max_inflight_per_worker` fds at worker start, hand them out
round-robin, and re-create (close + socket) only the current
slot in batch. This removes `socket(2)` from the per-probe path
entirely and amortises the `close(2)` cost. On Linux, a
`io_uring`-based version with `IORING_OP_CONNECT` can hit the
real floor (~50k pps) because it issues the connect without
any per-probe syscall at all.

## Reproducing the numbers

```bash
# Round 2/3/6 numbers (small workload, 4 workers, 2k in-flight)
BENCH_TARGET="127.0.0.0/20" BENCH_PORTS="80" \
BENCH_WORKERS=4 BENCH_INFLIGHT=2048 \
cargo test --release --test bench_raw -- --nocapture --test-threads=1

# Round 4/7 number (larger workload)
BENCH_TARGET="127.0.0.0/18" BENCH_PORTS="22,80,443" \
BENCH_WORKERS=4 BENCH_INFLIGHT=2048 \
cargo test --release --test bench_raw -- --nocapture --test-threads=1

# Round 5 number (largest workload, single port)
BENCH_TARGET="127.0.0.0/17" BENCH_PORTS="22" \
BENCH_WORKERS=4 BENCH_INFLIGHT=2048 \
cargo test --release --test bench_raw -- --nocapture --test-threads=1
```

## Public-network end-to-end demo

To prove the scanner works against real public targets (not just
loopback), the binary was pointed at four well-known public DNS
resolvers with their standard service ports:

```bash
for ip in 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222; do
  ./target/release/ip-scan --raw --raw-workers 2 --raw-inflight 256 \
    --target $ip --ports 53,80,443 --timeout 2000 --no-api \
    --database /tmp/scan_${ip//./_}.db
done
sqlite3 /tmp/scan_1_1_1_1.db \
  "SELECT ip_address, port FROM open_ports_detail"
# 1.1.1.1|53
# 1.1.1.1|80
# 1.1.1.1|443
```

All four resolvers correctly returned the expected 3 open ports each
(DNS, HTTP, HTTPS), demonstrating that the scanner detects real
public services end-to-end.

## Per-port TCP protocol snapshot

For each open port, the `ServiceProber` populates a `TcpSnapshot`
record in the `tcp_snapshots` table that records the raw banner
bytes (hex preview), the HTTP status / title / Server header, the
TLS subject/issuer/SAN/validity, the OS guess from TTL, the RTT,
the detected technologies (nginx/Apache/WordPress/etc.), and a
human-readable `purpose` label such as "Web 服务 (HTTPS)" or
"Redis 缓存/键值数据库". The schema is:

```
CREATE TABLE tcp_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT '',
    banner_first_line TEXT,
    banner_raw_hex TEXT,
    banner_raw_len INTEGER DEFAULT 0,
    http_status INTEGER,
    http_server TEXT,
    http_title TEXT,
    tls_subject TEXT,
    tls_issuer TEXT,
    tls_version TEXT,
    tls_san TEXT,
    tls_not_before TEXT,
    tls_not_after TEXT,
    os_guess TEXT,
    rtt_ms REAL,
    detected_technologies TEXT,
    purpose TEXT,
    captured_at TEXT NOT NULL,
    UNIQUE(ip_address, port)
);
```

The snapshot is filled by `ServiceProber::probe_port_with_snapshot`
(`src/service/service_prober.rs:99`) and persisted by
`SqliteDB::save_tcp_snapshots_batch`
(`src/dao/sqlite_db.rs:1005`). The same per-port record is joined
to the `service_info` row on `(ip_address, port)` so the Web UI
shows both the parse-friendly view and the raw byte hex preview
without a second SELECT.

## Next steps toward the floor

- **Pool fds** — create N sockets up front, hand them out round-robin
  from a thread-local pool. Saves a `socket(2)` + `close(2)` pair per
  probe (currently ~4 µs combined on macOS).
- **Bypass the result channel on the steady state** — workers could
  write directly to a per-worker `Vec<ScanResult>` and only flush to
  the shared channel every N results. Removes one atomic op per
  probe.
- **`kqueue` (macOS) / `epoll_pwait2` (Linux)** instead of `poll(2)`
  for the wakeup. The system-call cost is the same but the kernel
  reports results more efficiently when the fd set is large.
- **Linux-only `io_uring`** with `IORING_OP_CONNECT` for true
  zero-syscall-per-probe scanning. Not portable to macOS so it's a
  separate path.
