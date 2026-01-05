use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct ScanMetrics {
    total_scanned: Arc<AtomicU64>,
    total_open: Arc<AtomicU64>,
    total_errors: Arc<AtomicU64>,
    total_retries: Arc<AtomicU64>,
    start_time: Arc<Instant>,
}

impl ScanMetrics {
    pub fn new() -> Self {
        ScanMetrics {
            total_scanned: Arc::new(AtomicU64::new(0)),
            total_open: Arc::new(AtomicU64::new(0)),
            total_errors: Arc::new(AtomicU64::new(0)),
            total_retries: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(Instant::now()),
        }
    }

    pub fn increment_scanned(&self) {
        self.total_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_open(&self) {
        self.total_open.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_retries(&self) {
        self.total_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_scanned(&self) -> u64 {
        self.total_scanned.load(Ordering::Relaxed)
    }

    pub fn get_open(&self) -> u64 {
        self.total_open.load(Ordering::Relaxed)
    }

    pub fn get_errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }

    pub fn get_retries(&self) -> u64 {
        self.total_retries.load(Ordering::Relaxed)
    }

    pub fn get_scan_rate(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.get_scanned() as f64 / elapsed
        } else {
            0.0
        }
    }

    pub fn get_success_rate(&self) -> f64 {
        let scanned = self.get_scanned();
        if scanned > 0 {
            (scanned - self.get_errors()) as f64 / scanned as f64 * 100.0
        } else {
            100.0
        }
    }

    pub fn get_open_rate(&self) -> f64 {
        let scanned = self.get_scanned();
        if scanned > 0 {
            self.get_open() as f64 / scanned as f64 * 100.0
        } else {
            0.0
        }
    }

    pub fn print_summary(&self) {
        tracing::info!("=== Scan Metrics Summary ===");
        tracing::info!("  Total scanned: {}", self.get_scanned());
        tracing::info!("  Total open ports: {}", self.get_open());
        tracing::info!("  Total errors: {}", self.get_errors());
        tracing::info!("  Total retries: {}", self.get_retries());
        tracing::info!("  Scan rate: {:.2} IPs/sec", self.get_scan_rate());
        tracing::info!("  Success rate: {:.2}%", self.get_success_rate());
        tracing::info!("  Open port rate: {:.4}%", self.get_open_rate());
        tracing::info!("  Elapsed time: {:.2}s", self.start_time.elapsed().as_secs_f64());
    }
}

impl Default for ScanMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_counters() {
        let metrics = ScanMetrics::new();
        
        metrics.increment_scanned();
        metrics.increment_scanned();
        assert_eq!(metrics.get_scanned(), 2);
        
        metrics.increment_open();
        assert_eq!(metrics.get_open(), 1);
        
        metrics.increment_errors();
        assert_eq!(metrics.get_errors(), 1);
        
        metrics.increment_retries();
        assert_eq!(metrics.get_retries(), 1);
    }

    #[test]
    fn test_metrics_rates() {
        let metrics = ScanMetrics::new();
        
        // 10 scanned, 8 success, 2 errors, 5 open
        for _ in 0..10 { metrics.increment_scanned(); }
        for _ in 0..2 { metrics.increment_errors(); }
        for _ in 0..5 { metrics.increment_open(); }
        
        assert_eq!(metrics.get_success_rate(), 80.0);
        assert_eq!(metrics.get_open_rate(), 50.0);
    }
}
