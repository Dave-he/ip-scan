//! Scan controller for managing scan lifecycle
//!
//! This module provides functionality to control scan operations
//! including start, stop, and status management.

use crate::api::models::{StartScanRequest, ScanStatus};
use crate::cli::Args;
use crate::dao::SqliteDB;
use crate::service::ConScanner;
use crate::service::syn_scanner::SynScanner;
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{error, info};

/// Scan controller for managing scan operations
pub struct ScanController {
    db: SqliteDB,
    scan_status: Arc<Mutex<ScanStatus>>,
    scan_running: Arc<AtomicBool>,
    scan_handle: Arc<Mutex<Option<tokio::task::JoinHandle<Result<()>>>>>,
    scan_id: Arc<Mutex<Option<String>>>,
}

impl ScanController {
    /// Create a new scan controller
    pub fn new(db: SqliteDB) -> Self {
        Self {
            db,
            scan_status: Arc::new(Mutex::new(ScanStatus::Idle)),
            scan_running: Arc::new(AtomicBool::new(false)),
            scan_handle: Arc::new(Mutex::new(None)),
            scan_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Start a new scan
    pub async fn start_scan(
        &self,
        request: StartScanRequest,
        base_args: &Args,
    ) -> Result<String> {
        // Check if scan is already running
        {
            let status = self.scan_status.lock().unwrap();
            match *status {
                ScanStatus::Running | ScanStatus::Starting => {
                    return Err(anyhow!("Scan is already running"));
                }
                _ => {}
            }
        }

        // Update status to starting
        {
            let mut status = self.scan_status.lock().unwrap();
            *status = ScanStatus::Starting;
        }

        // Generate scan ID
        let scan_id = format!("scan_{}", Utc::now().timestamp());
        {
            let mut id = self.scan_id.lock().unwrap();
            *id = Some(scan_id.clone());
        }

        // Update database metadata
        self.db.save_metadata("scan_status", "starting")?;
        self.db.save_metadata("last_scan_id", &scan_id)?;
        self.db.save_metadata("last_scan_start_time", &Utc::now().to_rfc3339())?;

        // Create scan arguments from request
        let scan_args = self.create_scan_args(request, base_args)?;

        // Start scan in background task
        let db_clone = self.db.clone();
        let scan_running = self.scan_running.clone();
        let scan_status = self.scan_status.clone();
        let scan_id_clone = scan_id.clone();

        let handle = tokio::spawn(async move {
            let result = Self::run_scan_task(db_clone, scan_args, scan_running, scan_status.clone()).await;
            
            // Update final status
            match result {
                Ok(_) => {
                    info!("Scan {} completed successfully", scan_id_clone);
                }
                Err(ref e) => {
                    error!("Scan {} failed: {}", scan_id_clone, e);
                    let mut status = scan_status.lock().unwrap();
                    *status = ScanStatus::Error(e.to_string());
                }
            }
            
            result
        });

        // Store handle
        {
            let mut handle_guard = self.scan_handle.lock().unwrap();
            *handle_guard = Some(handle);
        }

        // Update status to running
        {
            let mut status = self.scan_status.lock().unwrap();
            *status = ScanStatus::Running;
        }
        self.db.save_metadata("scan_status", "running")?;

        self.scan_running.store(true, Ordering::SeqCst);

        Ok(scan_id)
    }

    /// Stop the current scan
    pub async fn stop_scan(&self) -> Result<()> {
        // Check if scan is running
        {
            let status = self.scan_status.lock().unwrap();
            match *status {
                ScanStatus::Running | ScanStatus::Starting => {}
                ScanStatus::Idle => return Err(anyhow!("No scan is currently running")),
                ScanStatus::Stopping => return Err(anyhow!("Scan is already stopping")),
                ScanStatus::Stopped => return Err(anyhow!("Scan is already stopped")),
                ScanStatus::Error(_) => return Err(anyhow!("Scan is in error state")),
            }
        }

        // Update status to stopping
        {
            let mut status = self.scan_status.lock().unwrap();
            *status = ScanStatus::Stopping;
        }
        self.db.save_metadata("scan_status", "stopping")?;

        // Stop scan
        self.scan_running.store(false, Ordering::SeqCst);

        // Wait for scan to stop
        let handle = {
            let mut handle_guard = self.scan_handle.lock().unwrap();
            handle_guard.take()
        };

        if let Some(handle) = handle {
            match tokio::time::timeout(tokio::time::Duration::from_secs(30), handle).await {
                Ok(result) => {
                    match result {
                        Ok(_) => {
                            info!("Scan stopped successfully");
                        }
                        Err(e) => {
                            error!("Scan task failed: {}", e);
                        }
                    }
                }
                Err(_) => {
                    error!("Scan did not stop within 30 seconds, forcing stop");
                }
            }
        }

        // Update final status
        {
            let mut status = self.scan_status.lock().unwrap();
            *status = ScanStatus::Stopped;
        }
        self.db.save_metadata("scan_status", "stopped")?;
        self.db.save_metadata("last_scan_stop_time", &Utc::now().to_rfc3339())?;

        Ok(())
    }

    /// Get current scan status
    pub fn get_status(&self) -> ScanStatus {
        let status = self.scan_status.lock().unwrap();
        status.clone()
    }

    /// Get current scan ID
    pub fn get_scan_id(&self) -> Option<String> {
        let id = self.scan_id.lock().unwrap();
        id.clone()
    }

    /// Check if scan is running
    pub fn is_running(&self) -> bool {
        self.scan_running.load(Ordering::SeqCst)
    }

    /// Create scan arguments from request
    fn create_scan_args(&self, request: StartScanRequest, base_args: &Args) -> Result<Args> {
        let mut args = base_args.clone();

        // Override with request parameters
        if let Some(start_ip) = request.start_ip {
            args.start_ip = Some(start_ip);
        }
        if let Some(end_ip) = request.end_ip {
            args.end_ip = Some(end_ip);
        }
        if let Some(ports) = request.ports {
            args.ports = ports;
        }
        
        args.timeout = request.timeout;
        args.concurrency = request.concurrency;
        args.syn = request.syn;
        args.skip_private = request.skip_private;

        // Validate arguments
        args.validate()?;

        Ok(args)
    }

    /// Run scan task
    async fn run_scan_task(
        db: SqliteDB,
        args: Args,
        scan_running: Arc<AtomicBool>,
        _scan_status: Arc<Mutex<ScanStatus>>,
    ) -> Result<()> {
        use crate::model::parse_port_range;

        // Parse port range
        let ports = parse_port_range(&args.ports).map_err(|e| anyhow!(e))?;
        info!("Scanning {} ports: {:?}", ports.len(), ports);

        // Get current round
        let current_round = db.get_current_round()?;

        // Initialize scanner
        let (tx, rx) = tokio::sync::mpsc::channel(args.pipeline_buffer);

        // Producer task
        let producer_handle = {
            let args_clone = args.clone();
            let scan_running_clone = scan_running.clone();
            tokio::spawn(async move {
                let (start_ip, end_ip) = args_clone
                    .start_ip
                    .as_ref()
                    .zip(args_clone.end_ip.as_ref())
                    .map(|(s, e)| (s.clone(), e.clone()))
                    .unwrap_or_else(Args::get_default_ipv4_range);

                info!("Scanning IPv4: {} - {}", start_ip, end_ip);

                match crate::model::IpRange::new(&start_ip, &end_ip) {
                    Ok(ip_range) => {
                        for ip in ip_range.iter() {
                            if !scan_running_clone.load(Ordering::SeqCst) {
                                break;
                            }
                            
                            if args_clone.skip_private && Args::is_private_ipv4(&ip.to_string()) {
                                continue;
                            }

                            // Skip 0.0.0.0/8 range
                            if let std::net::IpAddr::V4(ipv4) = ip {
                                if ipv4.octets()[0] == 0 {
                                    continue;
                                }
                            }

                            if tx.send(ip).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to create IP range: {}", e);
                    }
                }
            })
        };

        // Consumer (Scanner)
        let scanner_result = if args.syn {
            // SYN Scan Mode
            match SynScanner::new(
                db.clone(),
                current_round,
                args.result_buffer,
                args.db_batch_size,
                args.flush_interval_ms,
                args.max_rate,
                args.rate_window_secs,
            ) {
                Ok(scanner) => {
                    scanner
                        .run_pipeline(rx, ports.clone(), |_total_scanned| {})
                        .await
                }
                Err(e) => {
                    error!("Failed to initialize SYN scanner: {}", e);
                    Err(e)
                }
            }
        } else {
            // Connect Scan Mode
            let config = crate::service::ConScannerConfig {
                timeout_ms: args.timeout,
                concurrent_limit: args.concurrency,
                result_buffer: args.result_buffer,
                db_batch_size: args.db_batch_size,
                flush_interval_ms: args.flush_interval_ms,
                max_rate: args.max_rate,
                rate_window_secs: args.rate_window_secs,
            };
            let scanner = ConScanner::new(db.clone(), current_round, config);
            scanner.run_pipeline(rx, ports.clone(), |_total_scanned| {}).await
        };

        // Wait for producer
        let _ = producer_handle.await;

        // Update round if scan completed successfully
        if scanner_result.is_ok() {
            let _ = db.increment_round()?;
        }

        scanner_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_scan_controller() {
        let temp_file = NamedTempFile::new().unwrap();
        let db = SqliteDB::new(temp_file.path().to_str().unwrap()).unwrap();
        let controller = ScanController::new(db);

        // Test initial state
        assert_eq!(controller.get_status(), ScanStatus::Idle);
        assert!(!controller.is_running());

        // Test starting scan
        let request = StartScanRequest {
            start_ip: Some("192.168.1.1".to_string()),
            end_ip: Some("192.168.1.10".to_string()),
            ports: Some("80,443".to_string()),
            timeout: 500,
            concurrency: 10,
            syn: false,
            skip_private: false,
        };

        let base_args = Args {
            config_flag: None,
            config_pos: None,
            start_ip: None,
            end_ip: None,
            ports: "80".to_string(),
            timeout: 500,
            concurrency: 100,
            database: "test.db".to_string(),
            verbose: false,
            loop_mode: false,
            ipv4: true,
            ipv6: false,
            only_store_open: true,
            skip_private: true,
            syn: false,
            geoip_db: None,
            no_geo: false,
            worker_threads: None,
            pipeline_buffer: 2000,
            result_buffer: 10000,
            db_batch_size: 2000,
            flush_interval_ms: 1000,
            max_rate: 100000,
            rate_window_secs: 1,
            api: false,
            api_only: false,
            no_api: false,
            api_host: "127.0.0.1".to_string(),
            api_port: 8080,
            swagger_ui: false,
        };

        // This will fail because we don't have proper network setup in test,
        // but it should at least validate the controller logic
        let result = controller.start_scan(request, &base_args).await;
        assert!(result.is_ok());

        // Clean up
        let _ = controller.stop_scan().await;
    }
}