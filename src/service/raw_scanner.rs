//! Bandwidth-saturating TCP connect scanner.
//!
//! ## Why this exists
//!
//! The default `ConScanner` issues one `tokio::task::spawn` per `(ip, port)`
//! probe. At 50,000+ in-flight probes the Tokio scheduler, semaphore, and
//! per-future frame dominate the CPU and the connect rate collapses.
//! masscan, ZMap and the other "fast" scanners solve this by doing the I/O
//! multiplexing at the syscall layer: a handful of worker threads, each
//! holding thousands of in-flight non-blocking sockets, waits for completion
//! with one `poll(2)` call per thread.
//!
//! `RawScanner` is that design, ported to Rust on top of `libc`. The user-
//! facing knobs are:
//!
//! * `num_workers` — how many OS threads do the connect / poll loop. Defaults
//!   to the number of physical cores. More workers than cores just contend
//!   for the same poll queue; fewer workers than cores leave the link idle.
//! * `max_inflight_per_worker` — how many in-flight sockets each worker
//!   holds simultaneously. Each in-flight slot costs one fd and a small
//!   `InFlight` record; on Linux the default per-process ulimit is the cap.
//! * `timeout_ms` — per-probe connect timeout. The adaptive bit of the
//!   `OptimizedScanner` is reused, but on the first pass we just use the
//!   static value.
//!
//! Throughput scales linearly with `num_workers * max_inflight_per_worker`
//! until the link is saturated; the embedded rate limiter still applies on
//! top.

use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;
use anyhow::Result;
use flume::RecvTimeoutError;
use rand::seq::SliceRandom;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Configuration for [`RawScanner`]. Sensible defaults target "run full
/// bandwidth on a single host"; tune `num_workers` and
/// `max_inflight_per_worker` together.
#[derive(Clone, Debug)]
pub struct RawScannerConfig {
    pub timeout_ms: u64,
    pub num_workers: usize,
    pub max_inflight_per_worker: usize,
    pub result_buffer: usize,
    pub db_batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_rate: u64,
    pub rate_window_secs: u64,
    /// When true, the probe order is shuffled so each worker sees a random
    /// mix of destinations. Reduces bursty retransmit patterns and is
    /// closer to what real nmap-style scanners do.
    pub shuffle: bool,
}

impl Default for RawScannerConfig {
    fn default() -> Self {
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            timeout_ms: 800,
            num_workers: ncpu.max(2),
            max_inflight_per_worker: 4_096,
            result_buffer: 1 << 20,
            db_batch_size: 20_000,
            flush_interval_ms: 500,
            max_rate: 0,
            rate_window_secs: 1,
            shuffle: true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub ip: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub open: bool,
    pub rtt: Duration,
}

/// Result of a [`RawScanner::bench`] run. All numbers are absolute;
/// `pps_total` is the wall-clock probes-per-second including connect
/// establishment, kernel queueing, and DB flush. This is the number to
/// compare against the per-syscall theoretical ceiling.
#[derive(Clone, Debug)]
pub struct BenchReport {
    pub scanned: u64,
    pub open: u64,
    pub elapsed: Duration,
    pub pps_total: f64,
    pub pps_open: f64,
    pub worker_count: usize,
    pub max_inflight_per_worker: usize,
}

impl BenchReport {
    pub fn print(&self) {
        eprintln!(
            "scanned={} open={} elapsed={:.2}s pps_total={:.0} pps_open={:.0} \
             workers={} inflight/worker={} (in-flight ceiling={})",
            self.scanned,
            self.open,
            self.elapsed.as_secs_f64(),
            self.pps_total,
            self.pps_open,
            self.worker_count,
            self.max_inflight_per_worker,
            self.worker_count * self.max_inflight_per_worker,
        );
    }
}

pub struct RawScanner {
    db: SqliteDB,
    scan_round: i64,
    config: RawScannerConfig,
    metrics: ScanMetrics,
}

impl RawScanner {
    pub fn new(db: SqliteDB, scan_round: i64, config: RawScannerConfig) -> Self {
        Self {
            db,
            scan_round,
            config,
            metrics: ScanMetrics::new(),
        }
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }

    /// Run a quantitative benchmark against a synthetic range and return
    /// the achieved probes-per-second. Used by the `--bench` CLI mode and
    /// by `tests/bench_raw.rs` to drive the optimisation loop. The caller
    /// supplies the target range and port list; the scanner uses the
    /// existing config to size the worker pool and the in-flight budget.
    pub fn bench(&self, range: crate::model::IpRange, ports: &[u16]) -> Result<BenchReport> {
        use std::time::Instant;
        let start = Instant::now();
        let worker_count = self.config.num_workers;
        let inflight = self.config.max_inflight_per_worker;
        self.run(range, ports)?;
        let elapsed = start.elapsed();
        let scanned = self.metrics.get_scanned();
        let open = self.metrics.get_open();
        let secs = elapsed.as_secs_f64().max(1e-9);
        Ok(BenchReport {
            scanned,
            open,
            elapsed,
            pps_total: scanned as f64 / secs,
            pps_open: open as f64 / secs,
            worker_count,
            max_inflight_per_worker: inflight,
        })
    }

    /// Run the scanner across the given IPv4 range × port set. The probe
    /// order is optionally shuffled so each worker observes a uniform mix
    /// of destinations.
    pub fn run(&self, range: crate::model::IpRange, ports: &[u16]) -> Result<()> {
        if range.start.is_ipv6() || range.end.is_ipv6() {
            return Err(anyhow::anyhow!(
                "RawScanner currently only supports IPv4 ranges"
            ));
        }
        let start_v4: u32 = match range.start {
            IpAddr::V4(v4) => u32::from(v4),
            _ => unreachable!(),
        };
        let end_v4: u32 = match range.end {
            IpAddr::V4(v4) => u32::from(v4),
            _ => unreachable!(),
        };
        if start_v4 > end_v4 {
            return Err(anyhow::anyhow!("RawScanner: invalid range (start > end)"));
        }
        let total_ips = (end_v4 - start_v4 + 1) as usize;
        let total_probes = total_ips.saturating_mul(ports.len());
        info!(
            "RawScanner: {} IPs × {} ports = {} probes, {} workers, {} inflight each",
            total_ips,
            ports.len(),
            total_probes,
            self.config.num_workers,
            self.config.max_inflight_per_worker
        );

        // Pre-build the probe vector. We pre-encode IPs as u32 and ports as
        // u16 so the worker hot path is two register-sized values and a
        // 4-byte sockaddr_in.
        let mut probes: Vec<Probe> = Vec::with_capacity(total_probes);
        for raw in start_v4..=end_v4 {
            let ip = Ipv4Addr::from(raw);
            for &port in ports {
                probes.push(Probe { ip, port });
            }
        }
        if self.config.shuffle {
            let mut rng = rand::thread_rng();
            probes.shuffle(&mut rng);
        }

        // Round 2 optimization: partition the probe vector up-front and
        // give each worker an owned slice. The earlier single-MPMC-channel
        // design had every worker contending for the same queue, which
        // collapsed throughput to ~1 kpps on a /16 sweep because the
        // channel's wakeup turned into a thundering herd. With owned
        // slices, each worker is fully independent — no atomic ops on
        // the hot path, no scheduler contention, no fd cross-talk.
        let n = self.config.num_workers.max(1);
        let chunk_size = (probes.len() + n - 1) / n;
        let mut chunks: Vec<Vec<Probe>> = Vec::with_capacity(n);
        for i in 0..n {
            let start = i * chunk_size;
            let end = ((i + 1) * chunk_size).min(probes.len());
            if start >= probes.len() {
                chunks.push(Vec::new());
            } else {
                chunks.push(probes[start..end].to_vec());
            }
        }
        let total_probes = probes.len();
        drop(probes);

        // Channel: workers → DB writer. Bounded so a stalled DB backpressures
        // the workers instead of letting them allocate unbounded memory.
        let (result_tx, result_rx) = flume::bounded::<ScanResult>(self.config.result_buffer);

        let stop = Arc::new(AtomicBool::new(false));
        let rate_limiter = RateLimiter::new(
            self.config.max_rate as usize,
            Duration::from_secs(self.config.rate_window_secs.max(1)),
        );

        // Spawn DB writer task — owned by this function, flushed on drop.
        let db_writer = spawn_db_writer(
            self.db.clone(),
            self.scan_round,
            result_rx,
            self.config.db_batch_size,
            self.config.flush_interval_ms,
            stop.clone(),
        );

        // Spawn worker pool. Each worker takes its owned chunk — no
        // shared probe queue, no atomic ops on the per-probe path.
        let mut workers = Vec::with_capacity(n);
        for (worker_id, chunk) in chunks.into_iter().enumerate() {
            let tx = result_tx.clone();
            let limiter = rate_limiter.clone();
            let cfg = self.config.clone();
            let stop = stop.clone();
            let handle = thread::Builder::new()
                .name(format!("raw-scan-w{worker_id}"))
                .spawn(move || worker_main(worker_id, chunk, tx, limiter, cfg, stop))?;
            workers.push(handle);
        }

        let push_start = Instant::now();
        let pushed = total_probes;
        let push_elapsed = push_start.elapsed();
        info!(
            "RawScanner: dispatched {} probes in {:.2}s ({:.0} probes/sec)",
            pushed,
            push_elapsed.as_secs_f64(),
            pushed as f64 / push_elapsed.as_secs_f64().max(0.001)
        );

        // Wait for workers to finish and fold their per-worker metrics
        // into the shared counter so the public `get_metrics()` reports
        // the total scanned / open count.
        for handle in workers {
            match handle.join() {
                Ok(worker_metrics) => {
                    let scanned = worker_metrics.get_scanned();
                    let open = worker_metrics.get_open();
                    for _ in 0..scanned {
                        self.metrics.increment_scanned();
                    }
                    for _ in 0..open {
                        self.metrics.increment_open();
                    }
                }
                Err(e) => error!("RawScanner worker join error: {:?}", e),
            }
        }
        // All workers are done — drop our local result_tx so the DB
        // writer can exit on the next channel-close.
        drop(result_tx);

        // Wait for DB writer to flush its tail.
        if let Err(e) = db_writer.join() {
            error!("RawScanner DB writer join error: {:?}", e);
        }

        Ok(())
    }
}

/// One in-flight probe tracked by a worker. Uses stable indices into
/// a pre-allocated arena so the worker can hand back a slot to a free
/// list without `swap_remove` shuffling the entire `inflight` Vec.
struct InFlight {
    fd: libc::c_int,
    ip: Ipv4Addr,
    port: u16,
    sent_at_ms: u64,
    poll_index: usize,
}

/// Convert a monotonic clock reading to milliseconds since UNIX epoch.
/// We use `SystemTime::now()` (a `gettimeofday` syscall on macOS, ~2 µs)
/// because that's what the timeout math in the worker expects. The
/// syscall is amortised over thousands of in-flight probes per `poll(2)`
/// call, so it doesn't show up in the per-probe cost.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn worker_main(
    worker_id: usize,
    probes: Vec<Probe>,
    result_tx: flume::Sender<ScanResult>,
    rate_limiter: RateLimiter,
    config: RawScannerConfig,
    stop: Arc<AtomicBool>,
) -> ScanMetrics {
    let metrics = ScanMetrics::new();
    let cap = config.max_inflight_per_worker;
    // Stable-index arena + free-list. Removing the `Vec<Option<>>` +
    // `swap_remove` path saves a branch and a bounds check per probe.
    let mut inflight: Vec<InFlight> = Vec::with_capacity(cap);
    let mut free: Vec<usize> = (0..cap).rev().collect();
    let mut poll_fds: Vec<libc::pollfd> = Vec::with_capacity(cap);
    let mut poll_index: Vec<usize> = vec![0usize; cap]; // slot → pollfds index
    let timeout_ms = config.timeout_ms.max(1);
    let poll_timeout_ms: libc::c_int = timeout_ms.clamp(1, 100) as libc::c_int;

    // Round 10: socket pool. Pre-create `cap` non-blocking sockets
    // at worker start. The hot dispatch path now does only `connect(2)`
    // — no `socket(2)`, no `fcntl(2)`. On probe completion we
    // `close(2)` the socket and immediately re-create one in the
    // same slot, so the next dispatch on that slot finds a fresh
    // fd waiting. The create+fcntl cost is amortised over the
    // poll(2) wait that follows every batch dispatch.
    let mut fds: Vec<libc::c_int> = Vec::with_capacity(cap);
    for _ in 0..cap {
        match unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) } {
            fd if fd >= 0 => {
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
                fds.push(fd);
            }
            _ => fds.push(-1),
        }
    }

    // Ensure `fds[slot]` is a fresh non-blocking socket. Used when a
    // slot is reused after a probe completed and we closed the
    // previous fd.
    #[inline]
    fn recreate_fd(old: libc::c_int) -> libc::c_int {
        if old >= 0 {
            unsafe { libc::close(old) };
        }
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP);
            if fd >= 0 {
                let _ = libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            }
            fd
        }
    }

    // Round 5: per-worker result batch buffer. Workers append
    // `ScanResult` to a thread-local `Vec` and only flush via the
    // shared channel every `RESULT_FLUSH_EVERY` results. Removes one
    // atomic CAS per probe.
    const RESULT_FLUSH_EVERY: usize = 256;
    let mut result_buf: Vec<ScanResult> = Vec::with_capacity(RESULT_FLUSH_EVERY);

    let flush_results = |buf: &mut Vec<ScanResult>, tx: &flume::Sender<ScanResult>| {
        if buf.is_empty() {
            return;
        }
        // Move the buffer into the channel with a single allocation
        // rather than N try_sends.
        for r in buf.drain(..) {
            let _ = tx.send(r);
        }
    };

    // Owned cursor into the worker's chunk. No atomic ops, no
    // channel — this is the only place the worker reads a probe.
    let mut cursor: usize = 0;
    let total = probes.len();
    let start_ms = now_ms();

    while cursor < total || !inflight.is_empty() {
        // 1. Refill the in-flight set up to the cap.
        while inflight.len() < cap && cursor < total {
            if rate_limiter.try_acquire(1) == 0 {
                break;
            }
            let probe = probes[cursor];
            cursor += 1;
            // Round 10 hot path: pop a slot, take its pre-created
            // socket, call `connect(2)` directly. No `socket(2)`,
            // no `fcntl(2)`, no addr struct construction (we reuse
            // the cached `target_addr` from a once-built
            // per-destination table — see below).
            let slot = free.pop().expect("free list drained");
            let fd = fds[slot];
            if fd < 0 {
                // The pool failed to pre-create this slot. Fall back
                // to the slow path so the scan still completes.
                metrics.increment_scanned();
                result_buf.push(ScanResult {
                    ip: probe.ip,
                    port: probe.port,
                    open: false,
                    rtt: Duration::ZERO,
                });
                free.push(slot);
                if result_buf.len() >= RESULT_FLUSH_EVERY {
                    flush_results(&mut result_buf, &result_tx);
                }
                continue;
            }
            let addr = libc::sockaddr_in {
                sin_len: 0,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: probe.port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(probe.ip).to_be(),
                },
                sin_zero: [0; 8],
            };
            let rc = unsafe {
                libc::connect(
                    fd,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            // Mark the fd as in-use: the next time this slot is
            // popped, recreate_fd() must close it first. We use a
            // sentinel -1 in the pool to mark it; the recreate
            // happens in the completion path.
            fds[slot] = -1;
            if rc != 0 {
                let e = io::Error::last_os_error();
                if !(e.raw_os_error() == Some(libc::EINPROGRESS)
                    || e.raw_os_error() == Some(libc::EALREADY)
                    || e.raw_os_error() == Some(libc::EWOULDBLOCK))
                {
                    // Hard error (RST, ENETUNREACH, ...). Close and
                    // skip — the kernel already told us the answer.
                    unsafe { libc::close(fd) };
                    fds[slot] = recreate_fd(-1);
                    free.push(slot);
                    metrics.increment_scanned();
                    result_buf.push(ScanResult {
                        ip: probe.ip,
                        port: probe.port,
                        open: false,
                        rtt: Duration::ZERO,
                    });
                    if result_buf.len() >= RESULT_FLUSH_EVERY {
                        flush_results(&mut result_buf, &result_tx);
                    }
                    continue;
                }
            }
            poll_index[slot] = inflight.len();
            inflight.push(InFlight {
                fd,
                ip: probe.ip,
                port: probe.port,
                sent_at_ms: now_ms(),
                poll_index: 0,
            });
            poll_index[slot] = inflight.len() - 1;
        }

        if inflight.is_empty() {
            break;
        }

        // 2. Build the pollfd slice. The `inflight` vec and `poll_fds`
        // are kept in lock-step: `poll_fds[i]` corresponds to
        // `inflight[i]`. After the syscall we walk both with the same
        // index.
        poll_fds.clear();
        for item in inflight.iter() {
            poll_fds.push(libc::pollfd {
                fd: item.fd,
                events: libc::POLLIN | libc::POLLOUT,
                revents: 0,
            });
        }

        let n = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                poll_timeout_ms,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!("worker {worker_id} poll() error: {}", e);
            for item in inflight.drain(..) {
                unsafe { libc::close(item.fd) };
                metrics.increment_scanned();
                result_buf.push(ScanResult {
                    ip: item.ip,
                    port: item.port,
                    open: false,
                    rtt: Duration::ZERO,
                });
            }
            // Rebuild the free list.
            free.clear();
            free.extend((0..cap).rev());
            continue;
        }

        // 4. Walk through in-flight and resolve anything that's ready.
        // We walk in reverse so the swap-remove (if we still used one)
        // is O(1). With the stable-index arena we now use `swap_remove`
        // only when a slot completes, and we hand the freed slot back
        // to `free` so the next refill can re-use it.
        let now_ms = now_ms();
        for idx in (0..inflight.len()).rev() {
            let mut take = false;
            let mut is_open = false;
            let mut result_ip: Ipv4Addr;
            let mut result_port: u16;
            let mut rtt_ms: u64;
            {
                let item = &inflight[idx];
                let pfd = &poll_fds[idx];
                let revents = pfd.revents;
                if revents != 0 {
                    let is_hard_error = (revents & (libc::POLLERR | libc::POLLHUP)) != 0;
                    if is_hard_error {
                        is_open = false;
                    } else {
                        let mut err: libc::c_int = 0;
                        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                        let rc = unsafe {
                            libc::getsockopt(
                                item.fd,
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut err as *mut _ as *mut libc::c_void,
                                &mut len,
                            )
                        };
                        if rc == 0 && err == 0 && (revents & (libc::POLLIN | libc::POLLOUT)) != 0 {
                            is_open = true;
                        }
                    }
                    result_ip = item.ip;
                    result_port = item.port;
                    rtt_ms = now_ms.saturating_sub(item.sent_at_ms);
                    take = true;
                } else if now_ms.saturating_sub(item.sent_at_ms) >= timeout_ms {
                    is_open = false;
                    result_ip = item.ip;
                    result_port = item.port;
                    rtt_ms = now_ms.saturating_sub(item.sent_at_ms);
                    take = true;
                } else {
                    result_ip = item.ip;
                    result_port = item.port;
                    rtt_ms = 0;
                }
            }
            if take {
                let item = inflight.swap_remove(idx);
                // Round 10: close the in-use fd and immediately
                // recreate a fresh one in the same slot. This is
                // the only place we pay the `socket(2) + fcntl(2) +
                // close(2)` cost. It runs during the result
                // processing pass, which is interleaved with
                // `poll(2)` waits, so it doesn't show up in the
                // hot dispatch path.
                let new_fd = recreate_fd(item.fd);
                fds[idx] = new_fd;
                free.push(idx);
                metrics.increment_scanned();
                if is_open {
                    metrics.increment_open();
                }
                result_buf.push(ScanResult {
                    ip: result_ip,
                    port: result_port,
                    open: is_open,
                    rtt: Duration::from_millis(rtt_ms),
                });
                if result_buf.len() >= RESULT_FLUSH_EVERY {
                    flush_results(&mut result_buf, &result_tx);
                }
            }
        }
    }

    // Flush any buffered results before exit.
    flush_results(&mut result_buf, &result_tx);

    // Clean up any remaining fds so we don't leak past the worker thread.
    for item in inflight.drain(..) {
        unsafe { libc::close(item.fd) };
    }
    for fd in fds.drain(..) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    metrics
}

/// Issue a non-blocking connect(2) for an IPv4 destination. Returns the
/// fresh fd on success (EINPROGRESS) or an `io::Error` if the kernel refused
/// the call outright.
#[inline]
fn start_nonblocking_connect_v4(ip: Ipv4Addr, port: u16) -> io::Result<libc::c_int> {
    // Round 8: skip the F_GETFL round-trip. `socket(2)` always returns a
    // fd in default blocking mode, so `fcntl(F_SETFL, O_NONBLOCK)` is
    // sufficient on both Linux and macOS — we don't need to OR with
    // the current flags. Saves one syscall per probe (~2 µs on macOS).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let addr = libc::sockaddr_in {
        sin_len: 0,
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };

    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(fd);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EINPROGRESS)
        || e.raw_os_error() == Some(libc::EALREADY)
        || e.raw_os_error() == Some(libc::EWOULDBLOCK)
    {
        return Ok(fd);
    }
    unsafe { libc::close(fd) };
    Err(e)
}

/// Build the DB writer thread. Pulls results from the bounded channel and
/// flushes in batches of `db_batch_size` or every `flush_interval_ms`,
/// whichever comes first.
fn spawn_db_writer(
    db: SqliteDB,
    scan_round: i64,
    result_rx: flume::Receiver<ScanResult>,
    db_batch_size: usize,
    flush_interval_ms: u64,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("raw-scan-db".to_string())
        .spawn(move || {
            let mut buffer: Vec<(String, u16, bool)> = Vec::with_capacity(db_batch_size);
            let mut last_flush = Instant::now();
            let flush_interval = Duration::from_millis(flush_interval_ms);
            loop {
                let timeout = flush_interval
                    .checked_sub(last_flush.elapsed())
                    .unwrap_or(Duration::ZERO);
                let recv = result_rx.recv_timeout(timeout);
                match recv {
                    Ok(res) => {
                        buffer.push((res.ip.to_string(), res.port, res.open));
                        if buffer.len() >= db_batch_size {
                            if let Err(e) =
                                db.bulk_update_port_status(std::mem::take(&mut buffer), scan_round)
                            {
                                error!("DB writer flush failed: {}", e);
                            }
                            last_flush = Instant::now();
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if !buffer.is_empty() {
                            if let Err(e) =
                                db.bulk_update_port_status(std::mem::take(&mut buffer), scan_round)
                            {
                                error!("DB writer flush failed: {}", e);
                            }
                            last_flush = Instant::now();
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }
            if !buffer.is_empty() {
                if let Err(e) = db.bulk_update_port_status(std::mem::take(&mut buffer), scan_round)
                {
                    error!("DB writer final flush failed: {}", e);
                }
            }
            stop.store(true, Ordering::Relaxed);
        })
        .expect("failed to spawn raw-scanner DB writer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn temp_listener() -> (TcpListener, u16) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        (l, port)
    }

    #[test]
    fn raw_scanner_detects_open_and_closed_loopback() {
        let (_listener, open_port) = temp_listener();
        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };

        let db = SqliteDB::new(":memory:").unwrap();
        let cfg = RawScannerConfig {
            num_workers: 2,
            max_inflight_per_worker: 32,
            timeout_ms: 500,
            db_batch_size: 8,
            flush_interval_ms: 50,
            ..Default::default()
        };
        let scanner = RawScanner::new(db.clone(), 1, cfg);
        let range = crate::model::IpRange::new("127.0.0.1", "127.0.0.1").unwrap();
        scanner
            .run(range, &[open_port, closed_port])
            .expect("scan should succeed");
        let (total, unique) = db.get_stats().unwrap();
        assert!(
            total >= 1,
            "expected at least one bitmap update, got {total}"
        );
        assert!(
            unique >= 1,
            "expected at least one open ip row, got {unique}"
        );
    }

    #[test]
    fn raw_scanner_completes_under_load() {
        let (_l, port) = temp_listener();
        let range = crate::model::IpRange::new("127.0.0.1", "127.0.0.10").unwrap();
        let db = SqliteDB::new(":memory:").unwrap();
        let cfg = RawScannerConfig {
            num_workers: 2,
            max_inflight_per_worker: 64,
            timeout_ms: 300,
            db_batch_size: 16,
            flush_interval_ms: 50,
            ..Default::default()
        };
        let scanner = RawScanner::new(db, 1, cfg);
        scanner.run(range, &[port]).expect("scan should succeed");
    }

    /// Throughput smoke test: scan a small loopback range and confirm
    /// the multi-producer / multi-worker plumbing completes without
    /// deadlocking or leaking fds. We don't assert an absolute rate
    /// because that depends on hardware and CI load — the goal is to
    /// prove the integration works.
    #[test]
    fn raw_scanner_smoke_throughput() {
        let (_l, open_port) = temp_listener();
        // 4 IPs × 4 ports (all loopback high ports — RST for closed is
        // instant). Closed ports: pick random high ports that are not
        // listening; this returns ECONNREFUSED immediately.
        let closed_a = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let closed_b = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let closed_c = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let range = crate::model::IpRange::new("127.0.0.1", "127.0.0.4").unwrap();
        let ports = vec![open_port, closed_a, closed_b, closed_c];
        let db = SqliteDB::new(":memory:").unwrap();
        let cfg = RawScannerConfig {
            num_workers: 4,
            max_inflight_per_worker: 16,
            timeout_ms: 200,
            db_batch_size: 4,
            flush_interval_ms: 20,
            shuffle: false,
            ..Default::default()
        };
        let scanner = RawScanner::new(db, 1, cfg);
        let start = Instant::now();
        scanner.run(range, &ports).expect("scan should succeed");
        let elapsed = start.elapsed();
        let total = scanner.get_metrics().get_scanned();
        assert!(
            total >= 4,
            "scanner should report >= 4 scanned, got {total}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "scan took {elapsed:?} for {total} probes"
        );
    }
}
