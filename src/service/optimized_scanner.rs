use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{error, info};

#[allow(dead_code)]
const DEFAULT_BATCH_SIZE: usize = 1000;
#[allow(dead_code)]
const DEFAULT_CONCURRENCY: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[allow(dead_code)]
pub struct OptimizedScanner {
    db: SqliteDB,
    timeout_ms: u64,
    concurrent_limit: usize,
    scan_round: i64,
    scanned_count: Arc<AtomicUsize>,
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
    result_tx: mpsc::Sender<(String, u16, bool)>,
    batch_size: usize,
    adaptive_timeout: bool,
    avg_rtt_micros: Arc<AtomicU64>,
    min_timeout_ms: u64,
    max_timeout_ms: u64,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OptimizedScannerConfig {
    pub timeout_ms: u64,
    pub concurrent_limit: usize,
    pub result_buffer: usize,
    pub db_batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_rate: u64,
    pub rate_window_secs: u64,
    pub batch_size: usize,
    pub adaptive_timeout: bool,
}

impl Default for OptimizedScannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 500,
            concurrent_limit: DEFAULT_CONCURRENCY,
            result_buffer: 10000,
            db_batch_size: 500,
            flush_interval_ms: 500,
            max_rate: 50000,
            rate_window_secs: 1,
            batch_size: DEFAULT_BATCH_SIZE,
            adaptive_timeout: true,
        }
    }
}

#[allow(dead_code)]
impl OptimizedScanner {
    pub fn new(db: SqliteDB, scan_round: i64, config: OptimizedScannerConfig) -> Self {
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

        let min_timeout = (config.timeout_ms as f64 * 0.3) as u64;
        let max_timeout = config.timeout_ms * 3;

        OptimizedScanner {
            db,
            timeout_ms: config.timeout_ms,
            concurrent_limit: config.concurrent_limit,
            scan_round,
            scanned_count: Arc::new(AtomicUsize::new(0)),
            metrics: ScanMetrics::new(),
            rate_limiter,
            result_tx: tx,
            batch_size: config.batch_size,
            adaptive_timeout: config.adaptive_timeout,
            avg_rtt_micros: Arc::new(AtomicU64::new(config.timeout_ms as u64 * 1000)),
            min_timeout_ms: min_timeout.max(50),
            max_timeout_ms: max_timeout,
        }
    }

    fn get_adaptive_timeout(&self) -> Duration {
        if !self.adaptive_timeout {
            return Duration::from_millis(self.timeout_ms);
        }
        let avg_rtt = self.avg_rtt_micros.load(Ordering::Relaxed);
        let adaptive_ms = (avg_rtt as f64 / 1000.0 * 3.0) as u64;
        let clamped = adaptive_ms.clamp(self.min_timeout_ms, self.max_timeout_ms);
        Duration::from_millis(clamped)
    }

    fn update_rtt(&self, rtt_micros: u64) {
        if !self.adaptive_timeout {
            return;
        }
        let old = self.avg_rtt_micros.load(Ordering::Relaxed);
        let new_avg = if old == 0 { rtt_micros } else { (old * 7 + rtt_micros) / 8 };
        self.avg_rtt_micros.store(new_avg, Ordering::Relaxed);
    }

    async fn run_db_writer(
        mut rx: mpsc::Receiver<(String, u16, bool)>,
        db: SqliteDB,
        round: i64,
        batch_size: usize,
        flush_interval_ms: u64,
    ) {
        let mut buffer = Vec::with_capacity(batch_size);
        let mut _last_flush = Instant::now();
        let flush_interval = Duration::from_millis(flush_interval_ms);

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Some(item) => {
                            buffer.push(item);
                            if buffer.len() >= batch_size {
                                Self::flush_buffer(&db, &mut buffer, round);
                                _last_flush = Instant::now();
                            }
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(flush_interval) => {
                    if !buffer.is_empty() {
                        Self::flush_buffer(&db, &mut buffer, round);
                        _last_flush = Instant::now();
                    }
                }
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

    #[inline]
    async fn scan_port_classified(&self, ip: IpAddr, port: u16) -> PortState {
        self.rate_limiter.acquire().await;
        let addr = SocketAddr::new(ip, port);
        let timeout_duration = self.get_adaptive_timeout();
        let start = Instant::now();

        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                let rtt = start.elapsed().as_micros() as u64;
                self.update_rtt(rtt);
                PortState::Open
            }
            Ok(Err(e)) => {
                let rtt = start.elapsed().as_micros() as u64;
                if rtt < timeout_duration.as_micros() as u64 / 2 {
                    self.update_rtt(rtt);
                }
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                    std::io::ErrorKind::AddrInUse
                    | std::io::ErrorKind::AddrNotAvailable => PortState::Closed,
                    _ => PortState::Closed,
                }
            }
            Err(_) => PortState::Filtered,
        }
    }

    pub async fn scan_batch_ports(
        &self,
        ip: IpAddr,
        ports: &[u16],
    ) -> Result<Vec<u16>> {
        let mut open_ports = Vec::with_capacity(ports.len() / 20);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let ip_str = ip.to_string();
        let ip_type = Self::get_ip_type(&ip);

        let mut join_set = JoinSet::new();

        for &port in ports {
            let sem = semaphore.clone();
            let scanner = self.clone_scanner();
            let ip_clone = ip;

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.metrics.increment_scanned();
                let state = scanner.scan_port_classified(ip_clone, port).await;
                (port, state)
            });
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((port, state)) => {
                    let is_open = state == PortState::Open;
                    if is_open {
                        open_ports.push(port);
                        self.metrics.increment_open();
                        info!(ip = %ip, port = port, ip_type = ip_type, round = self.scan_round, "Found open port");
                    }
                    let _ = self.result_tx.try_send((ip_str.clone(), port, is_open));
                }
                Err(e) => {
                    error!(ip = %ip, error = %e, "Task panicked");
                    self.metrics.increment_errors();
                }
            }
        }

        Ok(open_ports)
    }

    pub async fn scan_batch_ports_classified(
        &self,
        ip: IpAddr,
        ports: &[u16],
    ) -> Result<Vec<(u16, PortState)>> {
        let mut results = Vec::with_capacity(ports.len());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let ip_str = ip.to_string();
        let ip_type = Self::get_ip_type(&ip);

        let mut join_set = JoinSet::new();

        for &port in ports {
            let sem = semaphore.clone();
            let scanner = self.clone_scanner();
            let ip_clone = ip;

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.metrics.increment_scanned();
                let state = scanner.scan_port_classified(ip_clone, port).await;
                (port, state)
            });
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((port, state)) => {
                    let is_open = state == PortState::Open;
                    if is_open {
                        self.metrics.increment_open();
                        info!(ip = %ip, port = port, ip_type = ip_type, round = self.scan_round, "Found open port");
                    }
                    let _ = self.result_tx.try_send((ip_str.clone(), port, is_open));
                    results.push((port, state));
                }
                Err(e) => {
                    error!(ip = %ip, error = %e, "Task panicked");
                    self.metrics.increment_errors();
                }
            }
        }

        results.sort_by_key(|(p, _)| *p);
        Ok(results)
    }

    pub async fn run_high_performance(
        &self,
        mut rx: mpsc::Receiver<IpAddr>,
        ports: Vec<u16>,
        progress_callback: impl Fn(usize) + Send + Sync + 'static,
    ) -> Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let progress_callback = Arc::new(progress_callback);
        let mut join_set = JoinSet::new();
        let mut total_dispatched = 0;

        loop {
            tokio::select! {
                Some(ip) = rx.recv() => {
                    let sem = semaphore.clone();
                    let ports_clone = ports.clone();
                    let scanner = self.clone_scanner();
                    let callback = progress_callback.clone();

                    let permit = sem.acquire_owned().await.unwrap();

                    join_set.spawn(async move {
                        if let Err(e) = scanner.scan_batch_ports(ip, &ports_clone).await {
                            error!(ip = %ip, error = %e, "Failed to scan IP");
                        }
                        drop(permit);
                    });

                    total_dispatched += 1;
                    callback(total_dispatched);
                }

                Some(res) = join_set.join_next() => {
                    if let Err(e) = res {
                        error!("Task join error: {}", e);
                    }
                }

                else => {
                    if join_set.is_empty() {
                        break;
                    }
                }
            }
        }

        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                error!("Task join error: {}", e);
            }
        }

        Ok(())
    }

    fn clone_scanner(&self) -> Self {
        OptimizedScanner {
            db: self.db.clone(),
            timeout_ms: self.timeout_ms,
            concurrent_limit: self.concurrent_limit,
            scan_round: self.scan_round,
            scanned_count: self.scanned_count.clone(),
            metrics: self.metrics.clone(),
            rate_limiter: self.rate_limiter.clone(),
            result_tx: self.result_tx.clone(),
            batch_size: self.batch_size,
            adaptive_timeout: self.adaptive_timeout,
            avg_rtt_micros: self.avg_rtt_micros.clone(),
            min_timeout_ms: self.min_timeout_ms,
            max_timeout_ms: self.max_timeout_ms,
        }
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}

#[allow(dead_code)]
pub async fn quick_scan(
    target: &str,
    ports: &[u16],
    concurrency: Option<usize>,
    timeout_ms: Option<u64>,
) -> Result<Vec<(IpAddr, Vec<u16>)>> {
    let db = SqliteDB::new(":memory:")?;
    let config = OptimizedScannerConfig {
        timeout_ms: timeout_ms.unwrap_or(500),
        concurrent_limit: concurrency.unwrap_or(100),
        ..Default::default()
    };

    let scanner = OptimizedScanner::new(db, 1, config);
    let ip: IpAddr = target.parse()?;

    let open_ports = scanner.scan_batch_ports(ip, ports).await?;

    Ok(vec![(ip, open_ports)])
}

#[allow(dead_code)]
pub async fn range_scan(
    start_ip: &str,
    end_ip: &str,
    ports: &[u16],
    concurrency: Option<usize>,
    timeout_ms: Option<u64>,
) -> Result<Vec<(IpAddr, Vec<u16>)>> {
    use crate::model::IpRange;

    let db = SqliteDB::new(":memory:")?;
    let config = OptimizedScannerConfig {
        timeout_ms: timeout_ms.unwrap_or(500),
        concurrent_limit: concurrency.unwrap_or(500),
        ..Default::default()
    };

    let scanner = OptimizedScanner::new(db, 1, config);
    let ip_range = IpRange::new(start_ip, end_ip).map_err(|e| anyhow::anyhow!(e))?;

    let (tx, rx) = mpsc::channel(1000);
    let mut results = Vec::new();
    let _results_arc = Arc::new(tokio::sync::Mutex::new(&mut results));

    tokio::spawn(async move {
        for ip in ip_range.iter() {
            let _ = tx.send(ip).await;
        }
    });

    let progress = |count| {
        if count % 100 == 0 {
            info!("Scanned {} IPs", count);
        }
    };

    scanner.run_high_performance(rx, ports.to_vec(), progress).await?;

    Ok(results)
}
