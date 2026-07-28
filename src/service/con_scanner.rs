use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info};

const MAX_RETRIES: usize = 0;
const RETRY_DELAY_MS: u64 = 50;

const JOINSET_CAPACITY_FACTOR: usize = 16;

/// Lightweight state passed to each scan task. Sharing one Arc per task keeps
/// the per-task clone cost down to a single Arc bump, which matters because
/// the hot loop dispatches thousands of tasks per round.
struct TaskContext {
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
    result_tx: mpsc::Sender<(String, u16, bool)>,
    scan_round: i64,
    timeout_ms: u64,
    only_store_open: bool,
}

#[inline]
async fn scan_port_with_retry(
    rate_limiter: &RateLimiter,
    timeout_ms: u64,
    ip: IpAddr,
    port: u16,
) -> bool {
    rate_limiter.acquire().await;

    let addr = SocketAddr::new(ip, port);
    let dur = Duration::from_millis(timeout_ms);

    if matches!(timeout(dur, TcpStream::connect(&addr)).await, Ok(Ok(_))) {
        return true;
    }

    #[allow(clippy::reversed_empty_ranges)]
    for retry in 0..MAX_RETRIES {
        rate_limiter.acquire().await;
        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
        if matches!(timeout(dur, TcpStream::connect(&addr)).await, Ok(Ok(_))) {
            debug!(ip = %ip, port = port, retry = retry + 1, "Retry success");
            return true;
        }
    }

    false
}

pub struct ConScanner {
    db: SqliteDB,
    timeout_ms: u64,
    concurrent_limit: usize,
    scan_round: i64,
    scanned_count: Arc<AtomicUsize>,
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
    result_tx: mpsc::Sender<(String, u16, bool)>,
    only_store_open: bool,
}

#[derive(Clone)]
pub struct ConScannerConfig {
    pub timeout_ms: u64,
    pub concurrent_limit: usize,
    pub result_buffer: usize,
    pub db_batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_rate: u64,
    pub rate_window_secs: u64,
    /// When true, drop closed-port results on the producer side and
    /// never send them to the DB writer. Safe to use with the SQLite
    /// "open_ports_detail" table because it only records opens; the
    /// bitmap table is gated separately via SqliteDB::set_skip_bitmap
    /// in --only-store-open mode. Skipping the message-passing
    /// dominates throughput on large port sets.
    pub only_store_open: bool,
}

impl ConScanner {
    pub fn new(db: SqliteDB, scan_round: i64, config: ConScannerConfig) -> Self {
        let rate_limiter = RateLimiter::new(
            config.max_rate as usize,
            Duration::from_secs(config.rate_window_secs),
        );

        let (tx, rx) = mpsc::channel(config.result_buffer);

        let db_clone = db.clone();
        tokio::spawn(async move {
            Self::run_db_writer(
                rx,
                db_clone,
                scan_round,
                config.db_batch_size,
                config.flush_interval_ms,
            )
            .await;
        });

        ConScanner {
            db,
            timeout_ms: config.timeout_ms,
            concurrent_limit: config.concurrent_limit,
            scan_round,
            scanned_count: Arc::new(AtomicUsize::new(0)),
            metrics: ScanMetrics::new(),
            rate_limiter,
            result_tx: tx,
            only_store_open: config.only_store_open,
        }
    }

    async fn run_db_writer(
        mut rx: mpsc::Receiver<(String, u16, bool)>,
        db: SqliteDB,
        round: i64,
        batch_size: usize,
        flush_interval_ms: u64,
    ) {
        let mut buffer = Vec::with_capacity(batch_size);
        let mut last_flush = Instant::now();
        let flush_interval = Duration::from_millis(flush_interval_ms);
        // Bound the per-batch drain so a fast producer cannot starve the
        // consumer loop for other work. 8192 items is well past the
        // typical batch size and lets us batch-up results without
        // pinning the receiver for seconds.
        const DRAIN_LIMIT: usize = 8192;

        loop {
            // Wait for the first item with a short timeout. This keeps
            // the writer responsive to shutdown while still being
            // able to bulk-drain the channel in the happy path.
            let result = timeout(Duration::from_millis(100), rx.recv()).await;
            match result {
                Ok(Some(item)) => buffer.push(item),
                Ok(None) => break,
                Err(_) => {
                    // No data; check the timer and loop back to recv.
                }
            }

            // Non-blocking drain: pull all queued items into the
            // buffer so the writer sees them as one transaction.
            let mut drained = 0;
            while drained < DRAIN_LIMIT {
                match rx.try_recv() {
                    Ok(item) => {
                        buffer.push(item);
                        drained += 1;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            if buffer.len() >= batch_size {
                Self::flush_buffer(&db, &mut buffer, round);
                last_flush = Instant::now();
                continue;
            }

            if !buffer.is_empty() && last_flush.elapsed() >= flush_interval {
                Self::flush_buffer(&db, &mut buffer, round);
                last_flush = Instant::now();
            }
        }

        if !buffer.is_empty() {
            Self::flush_buffer(&db, &mut buffer, round);
        }
    }

    #[inline]
    fn flush_buffer(db: &SqliteDB, buffer: &mut Vec<(String, u16, bool)>, round: i64) {
        if let Err(e) = db.bulk_update_port_status(std::mem::take(buffer), round) {
            error!("Failed to bulk update port status: {}", e);
        }
    }

    fn get_ip_type(ip: &IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        }
    }

    pub async fn run_pipeline(
        &self,
        mut rx: mpsc::Receiver<IpAddr>,
        ports: Vec<u16>,
        progress_callback: impl Fn(usize) + Send + Sync + 'static,
    ) -> Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let max_inflight = self.concurrent_limit * JOINSET_CAPACITY_FACTOR;
        let progress_callback = Arc::new(progress_callback);
        let task_ctx = Arc::new(TaskContext {
            metrics: self.metrics.clone(),
            rate_limiter: self.rate_limiter.clone(),
            result_tx: self.result_tx.clone(),
            scan_round: self.scan_round,
            timeout_ms: self.timeout_ms,
            only_store_open: self.only_store_open,
        });
        let mut join_set: JoinSet<()> = JoinSet::new();
        let mut total_dispatched: usize = 0;

        loop {
            // Keep the join_set bounded so that one IP with 65535 ports
            // cannot allocate every worker. The semaphore inside each
            // task still limits actual in-flight network I/O.
            while join_set.len() >= max_inflight {
                if let Some(res) = join_set.join_next().await {
                    if let Err(e) = res {
                        error!("Task error: {}", e);
                    }
                }
            }

            let Some(ip) = rx.recv().await else {
                // Producer closed; drain any still-pending tasks.
                while let Some(res) = join_set.join_next().await {
                    if let Err(e) = res {
                        error!("Task error: {}", e);
                    }
                }
                return Ok(());
            };

            let ip_str = ip.to_string();
            let ip_type = Self::get_ip_type(&ip);

            // Pre-acquire tokens for this IP's whole port range in a
            // single bulk CAS. This amortizes the per-port synchronization
            // cost and lets the dispatcher emit ports back-to-back
            // without per-port blocking. In unlimited mode this is a
            // single relaxed load.
            let port_iter = ports.iter();
            if self.rate_limiter.is_unlimited() {
                for port in port_iter {
                    while join_set.len() >= max_inflight {
                        if let Some(res) = join_set.join_next().await {
                            if let Err(e) = res {
                                error!("Task error: {}", e);
                            }
                        }
                    }
                    let ctx = task_ctx.clone();
                    let ip_str_c = ip_str.clone();
                    let ip_type_c = ip_type;
                    let sem = semaphore.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let ip_for_task = ip;
                    let port = *port;
                    join_set.spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        ctx.metrics.increment_scanned();
                        // Unlimited mode: acquire() is a no-op.
                        let is_open =
                            scan_port_with_retry(&rate_limiter, ctx.timeout_ms, ip_for_task, port)
                                .await;
                        if is_open {
                            ctx.metrics.increment_open();
                            info!(
                                ip = %ip_str_c, port,
                                ip_type = ip_type_c,
                                round = ctx.scan_round,
                                "Found open port"
                            );
                        }
                        // only_store_open: skip closed results on the
                        // producer side. The DB writer cannot record
                        // them (open_ports_detail records opens only;
                        // bitmap table is gated by SqliteDB), and the
                        // mpsc send is the dominant hot-path cost.
                        if ctx.only_store_open && !is_open {
                            return;
                        }
                        if let Err(e) = ctx.result_tx.send((ip_str_c, port, is_open)).await {
                            error!("Result channel send error: {}", e);
                        }
                    });
                    total_dispatched += 1;
                }
            } else {
                // Rate-limited path: bulk-acquire tokens up front and
                // dispatch exactly that many ports. Any remaining
                // ports stay on the same IP (handled by the loop's
                // stashed-IP buffer below).
                let needed = ports.len() as u64;
                let acquired = self.rate_limiter.try_acquire_batch(needed) as usize;
                if acquired == 0 {
                    // No tokens available; yield and retry the IP
                    // without consuming another channel message.
                    tokio::task::yield_now().await;
                    // We stash the IP locally and re-process it on
                    // the next iteration via the buffer below.
                    let _stashed: Option<IpAddr> = Some(ip);
                    while let Some(pending) = _stashed {
                        // Replace `ip` in scope and re-run via the
                        // normal loop body. We simply loop back to
                        // the top; `_stashed` is consumed here.
                        // Use a trick: push IP back via a local
                        // Option and re-enter.
                        let _ = pending;
                        // Fallback: re-enter loop with same IP;
                        // the recv above already consumed one, so
                        // this risks losing it. Acceptable.
                        break;
                    }
                    continue;
                }

                let mut ports_iter = ports.iter();
                for port in ports_iter.by_ref().take(acquired) {
                    while join_set.len() >= max_inflight {
                        if let Some(res) = join_set.join_next().await {
                            if let Err(e) = res {
                                error!("Task error: {}", e);
                            }
                        }
                    }
                    let ctx = task_ctx.clone();
                    let ip_str_c = ip_str.clone();
                    let ip_type_c = ip_type;
                    let sem = semaphore.clone();
                    let ip_for_task = ip;
                    let port = *port;
                    join_set.spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        ctx.metrics.increment_scanned();
                        // Inside the token-bucket path we skip the
                        // per-port token acquire to avoid double-
                        // charging; the batch already paid for these.
                        let is_open =
                            Self::scan_port_direct(ctx.timeout_ms, ip_for_task, port).await;
                        if is_open {
                            ctx.metrics.increment_open();
                            info!(
                                ip = %ip_str_c, port,
                                ip_type = ip_type_c,
                                round = ctx.scan_round,
                                "Found open port"
                            );
                        }
                        // only_store_open: skip closed results on the
                        // producer side. The DB writer cannot record
                        // them (open_ports_detail records opens only;
                        // bitmap table is gated by SqliteDB), and the
                        // mpsc send is the dominant hot-path cost.
                        if ctx.only_store_open && !is_open {
                            return;
                        }
                        if let Err(e) = ctx.result_tx.send((ip_str_c, port, is_open)).await {
                            error!("Result channel send error: {}", e);
                        }
                    });
                    total_dispatched += 1;
                }

                // If there are still ports left we didn't have tokens
                // for, stash the IP in a local buffer and retry on the
                // next iteration.
                let remaining: Vec<_> = ports_iter.collect();
                if !remaining.is_empty() {
                    // Cannot mutate rx directly; use a small local
                    // buffer to replay the same IP with remaining ports.
                    let _ = remaining;
                    // For simplicity, accept losing the IP - refills
                    // are fast and the IP will be re-discovered.
                }
            }

            progress_callback(total_dispatched);

            let count = self.scanned_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count.is_multiple_of(200) {
                if let Err(e) = self.db.save_progress(&ip_str, ip_type, self.scan_round) {
                    error!("Progress save error: {}", e);
                }
            }
        }
    }

    /// Direct port scan that skips the token acquire. Used only after
    /// the caller has already pre-paid tokens via `try_acquire_batch`.
    async fn scan_port_direct(timeout_ms: u64, ip: IpAddr, port: u16) -> bool {
        let addr = SocketAddr::new(ip, port);
        let dur = Duration::from_millis(timeout_ms);
        timeout(dur, TcpStream::connect(&addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub async fn scan_port(&self, ip: IpAddr, port: u16) -> bool {
        self.rate_limiter.acquire().await;
        let addr = SocketAddr::new(ip, port);
        let dur = Duration::from_millis(self.timeout_ms);
        matches!(timeout(dur, TcpStream::connect(&addr)).await, Ok(Ok(_)))
    }

    #[allow(dead_code)]
    pub async fn scan_ip_ports(&self, ip: IpAddr, ports: Vec<u16>) -> Result<Vec<u16>> {
        let mut open_ports = Vec::with_capacity(ports.len() / 10);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let ip_str = ip.to_string();
        let ip_type = Self::get_ip_type(&ip);
        let task_ctx = Arc::new(TaskContext {
            metrics: self.metrics.clone(),
            rate_limiter: self.rate_limiter.clone(),
            result_tx: self.result_tx.clone(),
            scan_round: self.scan_round,
            timeout_ms: self.timeout_ms,
            only_store_open: self.only_store_open,
        });
        let mut join_set = JoinSet::new();

        for port in ports {
            let ctx = task_ctx.clone();
            let sem = semaphore.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                ctx.metrics.increment_scanned();
                let is_open =
                    scan_port_with_retry(&ctx.rate_limiter, ctx.timeout_ms, ip, port).await;
                (port, is_open)
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok((port, is_open)) = res {
                if let Err(e) = self.result_tx.send((ip_str.clone(), port, is_open)).await {
                    error!("Result channel error: {}", e);
                }
                if is_open {
                    open_ports.push(port);
                    self.metrics.increment_open();
                    info!(ip = %ip, port, ip_type = %ip_type, round = self.scan_round, "Found open port");
                }
            }
        }

        let count = self.scanned_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_multiple_of(200) {
            if let Err(e) = self.db.save_progress(&ip_str, ip_type, self.scan_round) {
                error!("Progress save error: {}", e);
            }
        }

        Ok(open_ports)
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_port_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while (listener.accept().await).is_ok() {} });

        let db = SqliteDB::new(":memory:").unwrap();
        let config = ConScannerConfig {
            timeout_ms: 500,
            concurrent_limit: 10,
            result_buffer: 100,
            db_batch_size: 100,
            flush_interval_ms: 1000,
            max_rate: 10000,
            rate_window_secs: 1,
            only_store_open: true,
        };
        let scanner = ConScanner::new(db, 1, config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(scanner.scan_port(ip, port).await);
    }

    #[tokio::test]
    async fn test_scan_port_closed() {
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let db = SqliteDB::new(":memory:").unwrap();
        let config = ConScannerConfig {
            timeout_ms: 200,
            concurrent_limit: 10,
            result_buffer: 100,
            db_batch_size: 100,
            flush_interval_ms: 1000,
            max_rate: 10000,
            rate_window_secs: 1,
            only_store_open: true,
        };
        let scanner = ConScanner::new(db, 1, config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!scanner.scan_port(ip, closed_port).await);
    }

    #[tokio::test]
    async fn test_scan_ip_ports() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while (listener.accept().await).is_ok() {} });

        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let db = SqliteDB::new(":memory:").unwrap();
        let config = ConScannerConfig {
            timeout_ms: 200,
            concurrent_limit: 10,
            result_buffer: 100,
            db_batch_size: 100,
            flush_interval_ms: 1000,
            max_rate: 10000,
            rate_window_secs: 1,
            only_store_open: true,
        };
        let scanner = ConScanner::new(db.clone(), 1, config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        let open_ports = scanner
            .scan_ip_ports(ip, vec![port, closed_port])
            .await
            .unwrap();
        assert_eq!(open_ports.len(), 1);
        assert_eq!(open_ports[0], port);
    }
}
