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

const JOINSET_CAPACITY_FACTOR: usize = 4;

pub struct ConScanner {
    db: SqliteDB,
    timeout_ms: u64,
    concurrent_limit: usize,
    scan_round: i64,
    scanned_count: Arc<AtomicUsize>,
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
    result_tx: mpsc::Sender<(String, u16, bool)>,
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

        loop {
            let result = timeout(Duration::from_millis(100), rx.recv()).await;

            match result {
                Ok(Some(item)) => {
                    buffer.push(item);
                    if buffer.len() >= batch_size {
                        Self::flush_buffer(&db, &mut buffer, round);
                        last_flush = Instant::now();
                    }
                }
                Ok(None) => break,
                Err(_) => {}
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

    fn clone_for_task(&self) -> Self {
        ConScanner {
            db: self.db.clone(),
            timeout_ms: self.timeout_ms,
            concurrent_limit: self.concurrent_limit,
            scan_round: self.scan_round,
            scanned_count: self.scanned_count.clone(),
            metrics: self.metrics.clone(),
            rate_limiter: self.rate_limiter.clone(),
            result_tx: self.result_tx.clone(),
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
        let mut join_set: JoinSet<()> = JoinSet::new();
        let mut total_dispatched: usize = 0;

        loop {
            let inflight = join_set.len();

            if inflight >= max_inflight {
                if let Some(Err(e)) = join_set.join_next().await {
                    error!("Task error: {}", e);
                }
                continue;
            }

            tokio::select! {
                biased;

                Some(res) = join_set.join_next(), if !join_set.is_empty() => {
                    if let Err(e) = res {
                        error!("Task error: {}", e);
                    }
                }

                ip = rx.recv() => {
                    match ip {
                        Some(ip) => {
                            let ip_str = ip.to_string();
                            let ip_type = Self::get_ip_type(&ip).to_string();

                            for &port in &ports {
                                let scanner = self.clone_for_task();
                                let ip_str_c = ip_str.clone();
                                let ip_type_c = ip_type.clone();
                                let sem = semaphore.clone();

                                join_set.spawn(async move {
                                    let _permit = sem.acquire().await.unwrap();

                                    scanner.metrics.increment_scanned();

                                    let is_open = scanner.scan_port_with_retry(ip, port).await;

                                    if is_open {
                                        scanner.metrics.increment_open();
                                        info!(
                                            ip = %ip_str_c, port,
                                            ip_type = ip_type_c,
                                            round = scanner.scan_round,
                                            "Found open port"
                                        );
                                    }

                                    if let Err(e) = scanner.result_tx.send((ip_str_c, port, is_open)).await {
                                        error!("Result channel send error: {}", e);
                                    }
                                });
                            }

                            total_dispatched += 1;
                            progress_callback(total_dispatched);

                            let count = self.scanned_count.fetch_add(1, Ordering::Relaxed) + 1;
                            if count.is_multiple_of(200) {
                                if let Err(e) = self.db.save_progress(&ip_str, &ip_type, self.scan_round) {
                                    error!("Progress save error: {}", e);
                                }
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }

        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                error!("Task error: {}", e);
            }
        }

        Ok(())
    }

    #[inline]
    async fn scan_port_with_retry(&self, ip: IpAddr, port: u16) -> bool {
        self.rate_limiter.acquire().await;

        let addr = SocketAddr::new(ip, port);
        let dur = Duration::from_millis(self.timeout_ms);

        if matches!(timeout(dur, TcpStream::connect(&addr)).await, Ok(Ok(_))) {
            return true;
        }

        #[allow(clippy::reversed_empty_ranges)]
        for retry in 0..MAX_RETRIES {
            self.metrics.increment_retries();
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            self.rate_limiter.acquire().await;
            if matches!(timeout(dur, TcpStream::connect(&addr)).await, Ok(Ok(_))) {
                debug!(ip = %ip, port = port, retry = retry + 1, "Retry success");
                return true;
            }
        }

        false
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
        let mut join_set = JoinSet::new();

        for port in ports {
            let scanner = self.clone_for_task();
            let sem = semaphore.clone();
            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.metrics.increment_scanned();
                let is_open = scanner.scan_port_with_retry(ip, port).await;
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
                    info!(ip = %ip, port, ip_type = ip_type, round = self.scan_round, "Found open port");
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
