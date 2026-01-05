use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;
use tracing::{debug, info, error};
use crate::bitmap_db::BitmapDatabase;
use crate::metrics::ScanMetrics;
use crate::rate_limiter::RateLimiter;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const MAX_RETRIES: usize = 3;

pub struct BitmapScanner {
    db: BitmapDatabase,
    timeout_ms: u64,
    concurrent_limit: usize,
    scan_round: i64,
    scanned_count: Arc<AtomicUsize>,
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
    result_tx: mpsc::Sender<(String, u16, bool)>,
}

impl BitmapScanner {
    pub fn new(db: BitmapDatabase, timeout_ms: u64, concurrent_limit: usize, scan_round: i64) -> Self {
        // Rate limiter: max 1000 requests per second
        let rate_limiter = RateLimiter::new(1000, Duration::from_secs(1));
        
        // Channel for batch database writing
        let (tx, rx) = mpsc::channel(10000);

        // Spawn background writer task
        let db_clone = db.clone();
        tokio::spawn(async move {
            Self::run_db_writer(rx, db_clone, scan_round).await;
        });

        BitmapScanner {
            db,
            timeout_ms,
            concurrent_limit,
            scan_round,
            scanned_count: Arc::new(AtomicUsize::new(0)),
            metrics: ScanMetrics::new(),
            rate_limiter,
            result_tx: tx,
        }
    }

    async fn run_db_writer(mut rx: mpsc::Receiver<(String, u16, bool)>, db: BitmapDatabase, round: i64) {
        let mut buffer = Vec::with_capacity(5000);
        let mut last_flush = Instant::now();
        const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
        const BATCH_SIZE: usize = 2000;

        loop {
            // Use timeout to ensure we flush periodically even if data comes in slowly
            let result = timeout(Duration::from_millis(100), rx.recv()).await;

            match result {
                Ok(Some(item)) => {
                    buffer.push(item);
                    if buffer.len() >= BATCH_SIZE {
                        if let Err(e) = db.bulk_update_port_status(buffer.drain(..).collect(), round) {
                            error!("Failed to bulk update port status: {}", e);
                        }
                        last_flush = Instant::now();
                    }
                }
                Ok(None) => break, // Channel closed
                Err(_) => {
                    // Timeout
                }
            }

            // Check if we need to flush based on time
            if !buffer.is_empty() && last_flush.elapsed() >= FLUSH_INTERVAL {
                if let Err(e) = db.bulk_update_port_status(buffer.drain(..).collect(), round) {
                    error!("Failed to bulk update port status (timer): {}", e);
                }
                last_flush = Instant::now();
            }
        }

        // Final flush
        if !buffer.is_empty() {
            if let Err(e) = db.bulk_update_port_status(buffer, round) {
                error!("Failed to final bulk update port status: {}", e);
            }
        }
    }

    fn get_ip_type(ip: &IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        }
    }

    pub async fn scan_port(&self, ip: IpAddr, port: u16) -> bool {
        // Apply rate limiting
        self.rate_limiter.acquire().await;
        
        let addr = SocketAddr::new(ip, port);
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!(ip = %ip, port = port, "Port is open");
                true
            }
            Ok(Err(_)) | Err(_) => false,
        }
    }

    async fn scan_port_with_retry(&self, ip: IpAddr, port: u16) -> bool {
        for retry in 0..=MAX_RETRIES {
            if self.scan_port(ip, port).await {
                return true;
            }
            if retry < MAX_RETRIES {
                self.metrics.increment_retries();
                debug!(ip = %ip, port = port, retry = retry + 1, "Retrying port scan");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        false
    }

    pub async fn scan_ip_ports(&self, ip: IpAddr, ports: Vec<u16>) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        let ip_str = ip.to_string();
        let ip_type = Self::get_ip_type(&ip);
        
        let mut join_set = JoinSet::new();
        
        for port in ports {
            let sem = semaphore.clone();
            let scanner = self.clone_scanner();
            
            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.metrics.increment_scanned();
                let is_open = scanner.scan_port_with_retry(ip, port).await;
                (port, is_open)
            });
        }

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((port, is_open)) => {
                    // Send to writer channel instead of direct DB write
                    if let Err(e) = self.result_tx.send((ip_str.clone(), port, is_open)).await {
                         error!("Failed to send result to writer: {}", e);
                    }
                    
                    if is_open {
                        open_ports.push(port);
                        self.metrics.increment_open();
                        info!(ip = %ip, port = port, ip_type = ip_type, round = self.scan_round, "Found open port");
                    }
                }
                Err(e) => {
                    error!(ip = %ip, error = %e, "Task panicked");
                    self.metrics.increment_errors();
                }
            }
        }

        // Batch progress saving: only save every 100 IPs
        let count = self.scanned_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count % 100 == 0 {
            if let Err(e) = self.db.save_progress(&ip_str, ip_type, self.scan_round) {
                error!(error = %e, "Failed to save progress");
            }
        }

        Ok(open_ports)
    }

    fn clone_scanner(&self) -> Self {
        BitmapScanner {
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
        let progress_callback = Arc::new(progress_callback);
        let mut join_set = JoinSet::new();
        let mut total_dispatched = 0;

        // Consumer loop
        loop {
            // Wait for next IP or free slot
            tokio::select! {
                // Receive new IP
                Some(ip) = rx.recv() => {
                    let sem = semaphore.clone();
                    let ports_clone = ports.clone();
                    let scanner = self.clone_scanner();
                    let callback = progress_callback.clone();
                    
                    // Acquire permit before spawning to control concurrency
                    // Note: acquire_owned allows moving the permit into the task
                    let permit = sem.acquire_owned().await.unwrap();
                    
                    join_set.spawn(async move {
                        // permit is held until task completes
                        if let Err(e) = scanner.scan_ip_ports(ip, ports_clone).await {
                            error!(ip = %ip, error = %e, "Failed to scan IP");
                        }
                        drop(permit);
                    });
                    
                    total_dispatched += 1;
                    callback(total_dispatched);
                }
                
                // Reap completed tasks
                Some(res) = join_set.join_next() => {
                    if let Err(e) = res {
                        error!("Task join error: {}", e);
                    }
                }
                
                else => {
                    // Channel closed and join_set empty?
                    if join_set.is_empty() {
                        break;
                    }
                    // If channel closed but tasks running, just wait for tasks
                     if let Some(res) = join_set.join_next().await {
                         if let Err(e) = res {
                            error!("Task join error: {}", e);
                        }
                     }
                }
            }
        }
        
        // Wait for remaining tasks
        while let Some(res) = join_set.join_next().await {
            if let Err(e) = res {
                error!("Task join error: {}", e);
            }
        }

        Ok(())
    }

    // Deprecated: Kept for compatibility if needed, but run_pipeline is preferred
    pub async fn scan_range(
        &self,
        ips: Vec<IpAddr>,
        ports: Vec<u16>,
        progress_callback: impl Fn(usize, usize) + Send + Sync + 'static,
    ) -> Result<()> {
        let (tx, rx) = mpsc::channel(ips.len() + 1);
        for ip in ips {
            tx.send(ip).await?;
        }
        drop(tx); // Close sender so pipeline knows when to stop
        
        // Adapt callback
        let cb = move |current| progress_callback(current, 0); // Total unknown in pipeline
        self.run_pipeline(rx, ports, cb).await
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_port() {
        // Start a local server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        
        // Create scanner
        let db = BitmapDatabase::new(":memory:").unwrap();
        let scanner = BitmapScanner::new(db, 500, 10, 1);
        
        // Spawn server accept loop
        tokio::spawn(async move {
            while let Ok(_) = listener.accept().await {}
        });
        
        // Test open port
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.scan_port(ip, port).await;
        assert!(result);
        
        // Test closed port
        // Get a free port and ensure it's closed by binding and dropping
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);
        
        let result = scanner.scan_port(ip, closed_port).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_scan_ip_ports() {
        // Start a local server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        
        tokio::spawn(async move {
            while let Ok(_) = listener.accept().await {}
        });

        // Get a free port and ensure it's closed by binding and dropping
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let db = BitmapDatabase::new(":memory:").unwrap();
        let scanner = BitmapScanner::new(db.clone(), 500, 10, 1);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        
        let ports = vec![port, closed_port];
        let open_ports = scanner.scan_ip_ports(ip, ports).await.unwrap();
        
        assert_eq!(open_ports.len(), 1, "Expected 1 open port, found {:?}", open_ports);
        assert_eq!(open_ports[0], port);
        
        // Verify metrics
        assert_eq!(scanner.get_metrics().get_scanned(), 2);
        assert_eq!(scanner.get_metrics().get_open(), 1);
    }
}
