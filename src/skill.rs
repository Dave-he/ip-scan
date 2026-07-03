use crate::dao::SqliteDB;
use crate::model::IpRange;
use crate::service::optimized_scanner::{OptimizedScanner, OptimizedScannerConfig, PortState};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    pub ip: String,
    pub ip_type: String,
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub port_details: Vec<PortResult>,
    pub scan_time_ms: u64,
    pub total_ports_scanned: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeScanResult {
    pub target: String,
    pub total_hosts: usize,
    pub hosts_with_open_ports: usize,
    pub total_open_ports: usize,
    pub scan_time_ms: u64,
    pub scan_rate: f64,
    pub hosts: Vec<HostScanResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub max_rate: u64,
    pub adaptive_timeout: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 500,
            concurrency: 500,
            max_rate: 50000,
            adaptive_timeout: true,
        }
    }
}

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200, 27017,
];

pub struct IpScanSkill {
    config: ScanConfig,
}

impl IpScanSkill {
    pub fn new() -> Result<Self> {
        Ok(Self {
            config: ScanConfig::default(),
        })
    }

    pub fn with_config(config: ScanConfig) -> Result<Self> {
        Ok(Self { config })
    }

    fn make_scanner_config(&self) -> OptimizedScannerConfig {
        OptimizedScannerConfig {
            timeout_ms: self.config.timeout_ms,
            concurrent_limit: self.config.concurrency,
            max_rate: self.config.max_rate,
            adaptive_timeout: self.config.adaptive_timeout,
            ..Default::default()
        }
    }

    fn ip_type(ip: &IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        }
    }

    fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
        crate::model::parse_port_range(ports_str).map_err(|e| anyhow!(e))
    }

    pub async fn scan_single(&self, target: &str, ports: &str) -> Result<HostScanResult> {
        let start = Instant::now();
        let ip: IpAddr = target.parse()?;
        let ports_vec = Self::parse_ports(ports)?;
        let db = SqliteDB::new(":memory:")?;

        let scanner = OptimizedScanner::new(db, 1, self.make_scanner_config());
        let results = scanner.scan_batch_ports_classified(ip, &ports_vec).await?;

        let mut open_ports = Vec::new();
        let mut closed_ports = Vec::new();
        let mut filtered_ports = Vec::new();
        let mut port_details = Vec::new();

        for (port, state) in &results {
            let state_str = match state {
                PortState::Open => {
                    open_ports.push(*port);
                    "open"
                }
                PortState::Closed => {
                    closed_ports.push(*port);
                    "closed"
                }
                PortState::Filtered => {
                    filtered_ports.push(*port);
                    "filtered"
                }
            };
            port_details.push(PortResult {
                port: *port,
                state: state_str.to_string(),
                latency_ms: 0.0,
            });
        }

        Ok(HostScanResult {
            ip: target.to_string(),
            ip_type: Self::ip_type(&ip).to_string(),
            open_ports,
            closed_ports,
            filtered_ports,
            port_details,
            scan_time_ms: start.elapsed().as_millis() as u64,
            total_ports_scanned: ports_vec.len(),
        })
    }

    pub async fn scan_cidr(&self, cidr: &str, ports: &str) -> Result<RangeScanResult> {
        let start = Instant::now();
        let ip_range = IpRange::parse_target(cidr).map_err(|e| anyhow!(e))?;
        let total_hosts = ip_range.count();
        let ports_vec = Self::parse_ports(ports)?;
        let db = SqliteDB::new(":memory:")?;

        let scanner = OptimizedScanner::new(db.clone(), 1, self.make_scanner_config());

        let (tx, rx) = tokio::sync::mpsc::channel(self.config.concurrency * 2);

        let ip_iter_range = ip_range;
        tokio::spawn(async move {
            for ip in ip_iter_range.iter() {
                if tx.send(ip).await.is_err() {
                    break;
                }
            }
        });

        let total_for_cb = total_hosts;
        let progress_callback = move |count: usize| {
            if count.is_multiple_of(100) {
                tracing::info!("Scanned {} / {} IPs", count, total_for_cb);
            }
        };

        scanner
            .run_high_performance(rx, ports_vec, progress_callback)
            .await?;

        let scan_results = db
            .get_results_by_round(1)
            .map_err(|e| anyhow!("Failed to query scan results: {}", e))?;

        let mut host_map: std::collections::HashMap<String, HostScanResult> =
            std::collections::HashMap::new();

        for detail in &scan_results {
            let entry = host_map
                .entry(detail.ip_address.clone())
                .or_insert_with(|| HostScanResult {
                    ip: detail.ip_address.clone(),
                    ip_type: detail.ip_type.clone(),
                    open_ports: Vec::new(),
                    closed_ports: Vec::new(),
                    filtered_ports: Vec::new(),
                    port_details: Vec::new(),
                    scan_time_ms: 0,
                    total_ports_scanned: 0,
                });
            entry.open_ports.push(detail.port);
            entry.port_details.push(PortResult {
                port: detail.port,
                state: "open".to_string(),
                latency_ms: 0.0,
            });
        }

        let hosts: Vec<HostScanResult> = host_map.into_values().collect();
        let hosts_with_open_ports = hosts.iter().filter(|h| !h.open_ports.is_empty()).count();
        let total_open_ports: usize = hosts.iter().map(|h| h.open_ports.len()).sum();

        let scan_time_ms = start.elapsed().as_millis() as u64;
        let scan_rate = if scan_time_ms > 0 {
            total_hosts as f64 / (scan_time_ms as f64 / 1000.0)
        } else {
            0.0
        };

        Ok(RangeScanResult {
            target: cidr.to_string(),
            total_hosts,
            hosts_with_open_ports,
            total_open_ports,
            scan_time_ms,
            scan_rate,
            hosts,
        })
    }

    pub async fn scan_common_ports(&self, target: &str) -> Result<HostScanResult> {
        let ports_str = COMMON_PORTS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.scan_single(target, &ports_str).await
    }

    pub async fn scan_full(&self, target: &str) -> Result<HostScanResult> {
        self.scan_single(target, "1-65535").await
    }

    pub async fn quick_check(&self, target: &str) -> Result<HostScanResult> {
        let quick_config = ScanConfig {
            timeout_ms: 200,
            concurrency: 1000,
            max_rate: 200000,
            adaptive_timeout: true,
        };
        let skill = Self::with_config(quick_config)?;
        let ports_str = COMMON_PORTS
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        skill.scan_single(target, &ports_str).await
    }
}

impl Default for IpScanSkill {
    fn default() -> Self {
        Self::new().expect("Failed to create IpScanSkill")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        let ports = IpScanSkill::parse_ports("1-10,22,80,443").unwrap();
        assert_eq!(ports.len(), 13);
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[tokio::test]
    async fn test_scan_localhost() {
        let skill = IpScanSkill::new().unwrap();
        let result = skill.scan_single("127.0.0.1", "1-100").await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.ip, "127.0.0.1");
        assert_eq!(r.total_ports_scanned, 100);
    }

    #[tokio::test]
    async fn test_quick_check() {
        let skill = IpScanSkill::new().unwrap();
        let result = skill.quick_check("127.0.0.1").await;
        assert!(result.is_ok());
    }
}
