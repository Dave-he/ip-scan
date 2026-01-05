use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use anyhow::Result;
use tracing::{debug, info, error};
use crate::bitmap_db::BitmapDatabase;
use crate::metrics::ScanMetrics;
use crate::rate_limiter::RateLimiter;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const MAX_RETRIES: usize = 3;

pub struct BitmapScanner {
    db: BitmapDatabase,
    timeout_ms: u64,
    concurrent_limit: usize,
    scan_round: i64,
    scanned_count: Arc<AtomicUsize>,
    metrics: ScanMetrics,
    rate_limiter: RateLimiter,
}

impl BitmapScanner {
    pub fn new(db: BitmapDatabase, timeout_ms: u64, concurrent_limit: usize, scan_round: i64) -> Self {
        // Rate limiter: max 1000 requests per second
        let rate_limiter = RateLimiter::new(1000, Duration::from_secs(1));
        
        BitmapScanner {
            db,
            timeout_ms,
            concurrent_limit,
            scan_round,
            scanned_count: Arc::new(AtomicUsize::new(0)),
            metrics: ScanMetrics::new(),
            rate_limiter,
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
        
        let mut tasks = Vec::new();
        
        for port in ports {
            let sem = semaphore.clone();
            let scanner = self.clone_scanner();
            
            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                scanner.metrics.increment_scanned();
                let is_open = scanner.scan_port_with_retry(ip, port).await;
                (port, is_open)
            });
            
            tasks.push(task);
        }

        for task in tasks {
            match task.await {
                Ok((port, is_open)) => {
                    if let Err(e) = self.db.set_port_status(&ip_str, port, is_open, self.scan_round) {
                        error!(ip = %ip, port = port, error = %e, "Failed to save port status");
                        self.metrics.increment_errors();
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
        }
    }

    pub async fn scan_range(
        &self,
        ips: Vec<IpAddr>,
        ports: Vec<u16>,
        progress_callback: impl Fn(usize, usize) + Send + Sync + 'static,
    ) -> Result<()> {
        let total = ips.len();
        let last_ip = ips.last().cloned();
        let progress_callback = Arc::new(progress_callback);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrent_limit));
        
        let mut tasks = Vec::new();
        
        for (idx, ip) in ips.into_iter().enumerate() {
            let sem = semaphore.clone();
            let ports_clone = ports.clone();
            let scanner = self.clone_scanner();
            let callback = progress_callback.clone();
            
            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                if let Err(e) = scanner.scan_ip_ports(ip, ports_clone).await {
                    error!(ip = %ip, error = %e, "Failed to scan IP");
                }
                callback(idx + 1, total);
            });
            
            tasks.push(task);
        }

        for task in tasks {
            if let Err(e) = task.await {
                error!(error = %e, "Task join error");
            }
        }

        // Save final progress
        if let Some(ip) = last_ip {
            let ip_str = ip.to_string();
            let ip_type = Self::get_ip_type(&ip);
            if let Err(e) = self.db.save_progress(&ip_str, ip_type, self.scan_round) {
                error!(error = %e, "Failed to save final progress");
            }
        }

        Ok(())
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
