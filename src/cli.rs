use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ip-scan")]
#[command(author = "IP Scanner")]
#[command(version = "0.1.0")]
#[command(about = "High-performance IPv4/IPv6 port scanner", long_about = None)]
pub struct Args {
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

impl Args {
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
