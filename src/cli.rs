use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ip-scan")]
#[command(author = "IP Scanner")]
#[command(version = "0.1.0")]
#[command(about = "High-performance IPv4/IPv6 port scanner", long_about = None)]
pub struct Args {
    /// Configuration file path (TOML format)
    #[arg(long, env = "SCAN_CONFIG")]
    pub config: Option<PathBuf>,

    /// Start IP address (optional, defaults to full IPv4 range)
    #[arg(short = 's', long, env = "SCAN_START_IP")]
    pub start_ip: Option<String>,

    /// End IP address (optional, defaults to full IPv4 range)
    #[arg(short = 'e', long, env = "SCAN_END_IP")]
    pub end_ip: Option<String>,

    /// Port range (e.g., "80", "1-1000", "22,80,443")
    #[arg(short = 'p', long, env = "SCAN_PORTS", default_value = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017")]
    pub ports: String,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long, env = "SCAN_TIMEOUT", default_value = "500")]
    pub timeout: u64,

    /// Number of concurrent connections (defaults to 100)
    #[arg(short = 'c', long, env = "SCAN_CONCURRENCY", default_value = "100")]
    pub concurrency: usize,

    /// Database file path
    #[arg(short = 'd', long, env = "SCAN_DATABASE", default_value = "scan_results.db")]
    pub database: String,

    /// Verbose output
    #[arg(short = 'v', long, env = "SCAN_VERBOSE")]
    pub verbose: bool,

    /// Enable infinite loop scanning mode
    #[arg(short = 'l', long, env = "SCAN_LOOP_MODE", default_value = "true")]
    pub loop_mode: bool,

    /// Scan IPv4 addresses
    #[arg(long, env = "SCAN_IPV4", default_value = "true")]
    pub ipv4: bool,

    /// Scan IPv6 addresses
    #[arg(long, env = "SCAN_IPV6", default_value = "false")]
    pub ipv6: bool,

    /// Only store open ports (save storage space)
    #[arg(long, env = "SCAN_ONLY_OPEN", default_value = "true")]
    pub only_store_open: bool,

    /// Skip private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    #[arg(long, env = "SCAN_SKIP_PRIVATE", default_value = "true")]
    pub skip_private: bool,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Deserialize)]
pub struct ScanConfig {
    pub start_ip: Option<String>,
    pub end_ip: Option<String>,
    #[serde(default = "default_ports")]
    pub ports: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_database")]
    pub database: String,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default = "default_loop_mode")]
    pub loop_mode: bool,
    #[serde(default = "default_ipv4")]
    pub ipv4: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default = "default_only_store_open")]
    pub only_store_open: bool,
    #[serde(default = "default_skip_private")]
    pub skip_private: bool,
}

#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_max_rate")]
    #[allow(dead_code)]
    pub max_rate: u64,
    #[serde(default = "default_window_duration")]
    #[allow(dead_code)]
    pub window_duration: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            start_ip: None,
            end_ip: None,
            ports: default_ports(),
            timeout: default_timeout(),
            concurrency: default_concurrency(),
            database: default_database(),
            verbose: false,
            loop_mode: default_loop_mode(),
            ipv4: default_ipv4(),
            ipv6: false,
            only_store_open: default_only_store_open(),
            skip_private: default_skip_private(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_rate: default_max_rate(),
            window_duration: default_window_duration(),
        }
    }
}

fn default_ports() -> String {
    "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017".to_string()
}

fn default_timeout() -> u64 {
    500
}

fn default_concurrency() -> usize {
    100
}

fn default_database() -> String {
    "scan_results.db".to_string()
}

fn default_loop_mode() -> bool {
    true
}

fn default_ipv4() -> bool {
    true
}

fn default_only_store_open() -> bool {
    true
}

fn default_skip_private() -> bool {
    true
}

fn default_max_rate() -> u64 {
    100000
}

fn default_window_duration() -> u64 {
    1
}

impl Args {
    /// Merge configuration from file with command line arguments
    /// Command line arguments take precedence over config file
    pub fn merge_with_config(mut self) -> anyhow::Result<Self> {
        if let Some(config_path) = &self.config {
            let config_content = std::fs::read_to_string(config_path)?;
            let config: Config = toml::from_str(&config_content)?;

            // Only use config file values if CLI args are not provided
            if self.start_ip.is_none() {
                self.start_ip = config.scan.start_ip;
            }
            if self.end_ip.is_none() {
                self.end_ip = config.scan.end_ip;
            }
            // For ports, check if it's the default value
            if self.ports == default_ports() {
                self.ports = config.scan.ports;
            }
            if self.timeout == default_timeout() {
                self.timeout = config.scan.timeout;
            }
            if self.concurrency == default_concurrency() {
                self.concurrency = config.scan.concurrency;
            }
            if self.database == default_database() {
                self.database = config.scan.database;
            }
            // For boolean flags, config file takes precedence only if not explicitly set
            if !self.verbose {
                self.verbose = config.scan.verbose;
            }
            // For loop_mode, use config if it's different from default
            if self.loop_mode == default_loop_mode() {
                self.loop_mode = config.scan.loop_mode;
            }
            if self.ipv4 == default_ipv4() {
                self.ipv4 = config.scan.ipv4;
            }
            if !self.ipv6 {
                self.ipv6 = config.scan.ipv6;
            }
            if self.only_store_open == default_only_store_open() {
                self.only_store_open = config.scan.only_store_open;
            }
            if self.skip_private == default_skip_private() {
                self.skip_private = config.scan.skip_private;
            }
        }
        Ok(self)
    }

    pub fn get_default_ipv4_range() -> (String, String) {
        ("0.0.0.0".to_string(), "255.255.255.255".to_string())
    }

    pub fn is_private_ipv4(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            let octets = addr.octets();
            matches!(
                octets,
                [10, _, _, _] |                          // 10.0.0.0/8
                [172, 16..=31, _, _] |                   // 172.16.0.0/12
                [192, 168, _, _] |                       // 192.168.0.0/16
                [127, _, _, _] |                         // 127.0.0.0/8 (loopback)
                [169, 254, _, _] |                       // 169.254.0.0/16 (link-local)
                [224..=239, _, _, _] |                   // 224.0.0.0/4 (multicast)
                [240..=255, _, _, _]                     // 240.0.0.0/4 (reserved)
            )
        } else {
            false
        }
    }
}
