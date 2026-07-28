use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| "must be a positive integer".to_string())
        .and_then(|n| {
            if n > 0 {
                Ok(n)
            } else {
                Err("must be greater than zero".to_string())
            }
        })
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| "must be a positive integer".to_string())
        .and_then(|n| {
            if n > 0 {
                Ok(n)
            } else {
                Err("must be greater than zero".to_string())
            }
        })
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ip-scan",
    author = "IP Scanner",
    version = "0.1.0",
    about = "High-performance IPv4/IPv6 port scanner with service/TLS enrichment.",
    long_about = "ip-scan discovers open TCP ports on IPv4/IPv6 ranges and enriches each \
                  open port with GeoIP, Banner, HTTP/TLS fingerprints, RTT, OS guess and a \
                  lightweight exposure risk score. Only scan assets you own or are explicitly \
                  authorized to test. See docs/SECURITY_KNOWLEDGE.md for per-port security \
                  context, docs/OPERATIONS.md for safe operation guidance."
)]
pub struct Args {
    /// Configuration file path (optional)
    /// Can be provided with --config flag.
    #[arg(
        long = "config",
        visible_alias = "config-flag",
        env = "SCAN_CONFIG",
        value_name = "FILE_PATH"
    )]
    pub config_flag: Option<PathBuf>,

    /// Configuration file path (optional, positional)
    #[arg()]
    pub config_pos: Option<PathBuf>,

    /// Start IP address (optional, defaults to full IPv4 range)
    #[arg(short = 's', long, env = "SCAN_START_IP")]
    pub start_ip: Option<String>,

    /// End IP address (optional, defaults to full IPv4 range)
    #[arg(short = 'e', long, env = "SCAN_END_IP")]
    pub end_ip: Option<String>,

    /// Port range (e.g., "80", "1-1000", "22,80,443"). The default set covers
    /// the most common cleartext / sensitive services (FTP, Telnet, SMB,
    /// RDP, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, ...). See
    /// docs/SECURITY_KNOWLEDGE.md for per-port security context.
    #[arg(
        short = 'p',
        long,
        env = "SCAN_PORTS",
        default_value = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"
    )]
    pub ports: String,

    /// Connection timeout in milliseconds
    #[arg(short = 't', long, env = "SCAN_TIMEOUT", default_value = "500", value_parser = parse_positive_u64)]
    pub timeout: u64,

    /// Number of concurrent connections (I/O-bound: set high). High values
    /// increase packet rate and may trip IDS/WAF on the target side.
    #[arg(short = 'c', long, env = "SCAN_CONCURRENCY", default_value = "500", value_parser = parse_positive_usize)]
    pub concurrency: usize,

    /// Database file path
    #[arg(
        short = 'd',
        long,
        env = "SCAN_DATABASE",
        default_value = "scan_results.db"
    )]
    pub database: String,

    /// Print the resolved scan plan and exit without opening sockets or a database.
    /// Use this for CI configuration checks, container readiness probes, and to
    /// confirm the scan plan before running against production targets.
    #[arg(long, env = "SCAN_DRY_RUN", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,

    /// Verbose output
    #[arg(short = 'v', long, env = "SCAN_VERBOSE")]
    pub verbose: bool,

    /// Enable infinite loop scanning mode. Defaults to true; combine with
    /// --round-delay-ms to avoid hammering the same subnet every pass.
    #[arg(short = 'l', long, env = "SCAN_LOOP_MODE", action = clap::ArgAction::SetTrue)]
    pub loop_mode: bool,

    /// Scan IPv4 addresses
    #[arg(long, env = "SCAN_IPV4", action = clap::ArgAction::SetTrue)]
    pub ipv4: bool,

    /// Scan IPv6 addresses
    #[arg(long, env = "SCAN_IPV6", action = clap::ArgAction::SetTrue)]
    pub ipv6: bool,

    /// Only store open ports (save storage space and avoid persisting
    /// closed/filtered state which can leak scan coverage).
    #[arg(long, env = "SCAN_ONLY_OPEN", action = clap::ArgAction::SetTrue)]
    pub only_store_open: bool,

    /// Skip RFC1918 / loopback / link-local / multicast / reserved IPv4.
    /// Strongly recommended; disable only for explicitly authorized scans.
    #[arg(long, env = "SCAN_SKIP_PRIVATE", action = clap::ArgAction::SetTrue)]
    pub skip_private: bool,

    /// Scan the entire public IPv4 space (skip RFC1918 and other reserved
    /// ranges; equivalent to `--target 1.0.0.0-223.255.255.255` minus
    /// RFC5735 special-purpose blocks). Off by default to comply with the
    /// project's "only scan authorised assets" rule — opt in explicitly.
    #[arg(
        long = "scan-public",
        env = "SCAN_PUBLIC",
        action = clap::ArgAction::SetTrue,
        help = "Scan the public IPv4 space (skip RFC1918 / reserved ranges)"
    )]
    pub scan_public: bool,

    /// Enable SYN half-open scan mode. Requires Root/Admin and a platform
    /// raw-socket / Npcap backend. Faster than connect and produces lighter
    /// logs on the target, but no service banner is collected. Falls back
    /// to connect scan automatically if the raw socket cannot be opened.
    #[arg(long, env = "SCAN_SYN", action = clap::ArgAction::SetTrue)]
    pub syn: bool,

    /// Enable API server mode. When combined with --probe-service the API
    /// exposes every finding (Banners, TLS, risk score) — bind to a
    /// trusted interface and protect with a reverse proxy in production.
    #[arg(long, env = "SCAN_API", action = clap::ArgAction::SetTrue)]
    pub api: bool,

    /// API server port (default: 9090)
    #[arg(long, env = "SCAN_API_PORT", default_value = "9090")]
    pub api_port: u16,

    /// API server bind address (default: 0.0.0.0)
    #[arg(long, env = "SCAN_API_HOST", default_value = "0.0.0.0")]
    pub api_host: String,

    /// Enable Swagger UI (default: true when API is enabled)
    #[arg(long, env = "SCAN_SWAGGER_UI", action = clap::ArgAction::SetTrue)]
    pub swagger_ui: bool,

    /// Target: IP, CIDR (e.g. 192.168.1.0/24), or range
    /// (e.g. 192.168.1.1-192.168.1.255). Only scan assets you own or have
    /// written authorization to test.
    #[arg(
        short = 'T',
        long,
        env = "SCAN_TARGET",
        help = "Target: IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-192.168.1.255)"
    )]
    pub target: Option<String>,

    /// Scan preset: quick (Top 100 ports, fast), standard (default ports,
    /// balanced), or deep (1-65535, slow). quick sets --skip-private.
    #[arg(long, env = "SCAN_PRESET", help = "Scan preset: quick, standard, deep")]
    pub preset: Option<String>,

    /// Output format (text or json) for --dry-run / nmap-style output mapping.
    #[arg(
        long,
        env = "SCAN_OUTPUT",
        default_value = "text",
        help = "Output format: text, json"
    )]
    pub output_format: String,

    /// Run only API server (no scanning)
    #[arg(long, env = "SCAN_API_ONLY", action = clap::ArgAction::SetTrue)]
    pub api_only: bool,

    /// Run only scanner (no API)
    #[arg(long, env = "SCAN_NO_API", action = clap::ArgAction::SetTrue)]
    pub no_api: bool,
    /// MaxMind GeoIP database path (optional)
    #[arg(long, env = "SCAN_GEOIP_DB")]
    pub geoip_db: Option<String>,

    /// Disable Geolocation lookup
    #[arg(long, env = "SCAN_NO_GEO", action = clap::ArgAction::SetTrue)]
    pub no_geo: bool,

    /// Enable service detection (probe every newly found open port with HTTP
    /// GET, TLS ClientHello, and protocol Banner grabs). Will produce
    /// application-layer traffic — enable only when the target's policy
    /// permits it. Failed/empty probes are retried at most once per IP per
    /// hour (see service_probe_state).
    #[arg(long, env = "SCAN_PROBE_SERVICE", action = clap::ArgAction::SetTrue)]
    pub probe_service: bool,

    /// Service probe timeout in seconds
    #[arg(long, env = "SCAN_PROBE_TIMEOUT", default_value = "5")]
    pub probe_timeout: u64,

    /// Service probe concurrency
    #[arg(long, env = "SCAN_PROBE_CONCURRENCY", default_value = "50", value_parser = parse_positive_usize)]
    pub probe_concurrency: usize,

    /// GeoIP/WHOIS/reverse-DNS enrichment concurrency
    #[arg(long, env = "SCAN_GEO_CONCURRENCY", default_value = "8", value_parser = parse_positive_usize)]
    pub geo_concurrency: usize,

    #[arg(long, env = "SCAN_WORKER_THREADS")]
    pub worker_threads: Option<usize>,

    #[arg(long, env = "SCAN_PIPELINE_BUFFER", default_value = "65536", value_parser = parse_positive_usize)]
    pub pipeline_buffer: usize,

    #[arg(long, env = "SCAN_RESULT_BUFFER", default_value = "50000", value_parser = parse_positive_usize)]
    pub result_buffer: usize,

    #[arg(long, env = "SCAN_DB_BATCH_SIZE", default_value = "10000", value_parser = parse_positive_usize)]
    pub db_batch_size: usize,

    #[arg(long, env = "SCAN_FLUSH_INTERVAL_MS", default_value = "2000")]
    pub flush_interval_ms: u64,

    /// Token-bucket rate limit (packets/sec). 0 = unlimited. Set to a
    /// finite value when scanning internet-routable networks to stay below
    /// common IDS / rate-limit thresholds.
    #[arg(long, env = "SCAN_MAX_RATE", default_value = "0")]
    pub max_rate: u64,

    #[arg(long, env = "SCAN_RATE_WINDOW_S", default_value = "1")]
    pub rate_window_secs: u64,

    /// Delay between scan rounds in loop mode (milliseconds, default 0).
    /// Set above 0 (1000-5000) when scanning a single fixed range to avoid
    /// hammering the same subnet each pass; leave at 0 for continuous
    /// range sweeps.
    #[arg(long, env = "SCAN_ROUND_DELAY_MS", default_value = "0")]
    pub round_delay_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub api: ApiConfig,
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
    #[serde(default)]
    pub syn: bool,
    pub geoip_db: Option<String>,
    #[serde(default)]
    pub no_geo: bool,
    #[serde(default)]
    pub probe_service: bool,
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout: u64,
    #[serde(default = "default_probe_concurrency")]
    pub probe_concurrency: usize,
    #[serde(default = "default_geo_concurrency")]
    pub geo_concurrency: usize,

    pub worker_threads: Option<usize>,
    #[serde(default = "default_pipeline_buffer")]
    pub pipeline_buffer: usize,
    #[serde(default = "default_result_buffer")]
    pub result_buffer: usize,
    #[serde(default = "default_db_batch_size")]
    pub db_batch_size: usize,
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_max_rate")]
    pub max_rate: u64,
    #[serde(default = "default_window_duration")]
    pub rate_window_secs: u64,
    #[serde(default = "default_round_delay_ms")]
    pub round_delay_ms: u64,
    #[serde(default)]
    #[allow(dead_code)]
    pub api: bool,
    #[serde(default)]
    pub api_only: bool,
    #[serde(default)]
    pub no_api: bool,
    #[serde(default = "default_api_host")]
    #[allow(dead_code)]
    pub api_host: String,
    #[serde(default = "default_api_port")]
    #[allow(dead_code)]
    pub api_port: u16,
    #[serde(default)]
    pub swagger_ui: bool,
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

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_enabled")]
    pub enabled: bool,
    #[serde(default = "default_api_host")]
    pub host: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: default_api_enabled(),
            host: default_api_host(),
            port: default_api_port(),
        }
    }
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
            syn: false,
            geoip_db: None,
            no_geo: false,
            probe_service: false,
            probe_timeout: default_probe_timeout(),
            probe_concurrency: default_probe_concurrency(),
            geo_concurrency: default_geo_concurrency(),
            worker_threads: None,
            pipeline_buffer: default_pipeline_buffer(),
            result_buffer: default_result_buffer(),
            db_batch_size: default_db_batch_size(),
            flush_interval_ms: default_flush_interval_ms(),
            max_rate: default_max_rate(),
            rate_window_secs: default_window_duration(),
            round_delay_ms: default_round_delay_ms(),
            api: false,
            api_only: false,
            no_api: false,
            api_host: default_api_host(),
            api_port: default_api_port(),
            swagger_ui: false,
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
    2000
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
    0
}

fn default_window_duration() -> u64 {
    1
}

fn default_pipeline_buffer() -> usize {
    65536
}

fn default_result_buffer() -> usize {
    50000
}

fn default_db_batch_size() -> usize {
    10000
}

fn default_flush_interval_ms() -> u64 {
    2000
}

fn default_round_delay_ms() -> u64 {
    0
}

fn default_api_host() -> String {
    "0.0.0.0".to_string()
}

fn default_api_port() -> u16 {
    9090
}

fn default_api_enabled() -> bool {
    true
}

fn default_probe_timeout() -> u64 {
    5
}

fn default_probe_concurrency() -> usize {
    50
}

fn default_geo_concurrency() -> usize {
    8
}

impl Args {
    /// Top 100 most common ports (nmap default with -F)
    const TOP_100_PORTS: &'static str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9100,9200,11211,27017,50060";

    pub fn apply_preset(&mut self) {
        // Apply Nmap-compatible arguments first so they take precedence
        self.apply_nmap_args();

        if let Some(ref preset) = self.preset {
            match preset.as_str() {
                "quick" => {
                    self.timeout = 200;
                    self.concurrency = 500;
                    self.max_rate = 200000;
                    if self.ports == default_ports() {
                        self.ports = Self::TOP_100_PORTS.to_string();
                    }
                }
                "standard" => {
                    self.timeout = 500;
                    self.concurrency = 1000;
                    self.max_rate = 100000;
                }
                "deep" => {
                    self.timeout = 2000;
                    self.concurrency = 200;
                    self.max_rate = 50000;
                    if self.ports == default_ports() {
                        self.ports = "1-65535".to_string();
                    }
                }
                "fullpublic" => {
                    // Opt-in preset: maximise scan speed across the public
                    // IPv4 space. The CLI prints the legal reminder every
                    // time this preset is selected and the rate limiter is
                    // set to 0 (= UNLIMITED, run full bandwidth).
                    self.timeout = 500;
                    self.concurrency = 4_000;
                    self.max_rate = 0;
                    self.skip_private = true;
                    self.scan_public = true;
                    self.probe_service = true;
                    self.probe_concurrency = 256;
                    self.pipeline_buffer = self.pipeline_buffer.max(262_144);
                    self.result_buffer = self.result_buffer.max(262_144);
                    self.db_batch_size = self.db_batch_size.max(50_000);
                    if self.ports == default_ports() {
                        self.ports = Self::TOP_100_PORTS.to_string();
                    }
                    tracing::warn!(
                        "preset=fullpublic: scanning the public IPv4 space at \
                         unlimited rate. Only run this against networks you are \
                         explicitly authorised to scan (e.g. your own /24). \
                         Large or un-authorised public scans may violate local \
                         law or your ISP's acceptable-use policy."
                    );
                }
                _ => {}
            }
        }

        // --scan-public without an explicit target forces the public IPv4
        // range and skip-private. The validate() step rejects ambiguous
        // combinations (e.g. --scan-public with another target that resolves
        // to RFC1918).
        if self.scan_public && self.target.is_none()
            && (self.start_ip.is_none() || self.end_ip.is_none())
        {
            self.start_ip = Some("1.0.0.0".to_string());
            self.end_ip = Some("223.255.255.255".to_string());
            self.ipv4 = true;
            self.skip_private = true;
        }
    }

    fn apply_nmap_args(&mut self) {
        // -sS: SYN stealth scan
        if self.nmap_sS {
            self.syn = true;
        }

        // -sV: Service/version detection
        if self.nmap_sV {
            self.probe_service = true;
        }

        // -O: OS detection (maps to enhanced service probing)
        if self.nmap_O {
            self.probe_service = true;
        }

        // -A: Aggressive scan = -sV + -sC + -O + -T4
        if self.nmap_A {
            self.probe_service = true;
            self.apply_timing_template("4");
        }

        // -sC: Default NSE scripts
        if self.nmap_sC {
            self.probe_service = true;
        }

        // -F: Fast mode - top 100 ports
        if self.nmap_F && self.ports == default_ports() {
            self.ports = Self::TOP_100_PORTS.to_string();
        }

        // --top-ports: Scan N most common ports
        if let Some(n) = self.nmap_top_ports {
            if self.ports == default_ports() {
                self.ports = get_top_nmap_ports(n);
            }
        }

        // -T0 ~ -T5: Timing templates
        if let Some(ref t) = self.nmap_T {
            self.apply_timing_template(t);
        }

        // Positional nmap targets
        if !self.nmap_target.is_empty() && self.target.is_none() {
            self.target = Some(self.nmap_target.join(" "));
        }

        // -iL: Read targets from file
        if let Some(ref file_path) = self.nmap_iL {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let targets: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if !targets.is_empty() && self.target.is_none() {
                    self.target = Some(targets.join(" "));
                }
            }
        }

        // --output-format: map nmap output formats
        if let Some(ref oN) = self.nmap_oN {
            self.output_format = "text".to_string();
            self.database = oN.clone();
        }
        if let Some(ref oJ) = self.nmap_oJ {
            self.output_format = "json".to_string();
            self.database = oJ.clone();
        }

        // -sn: Ping scan only (sets loop_mode to false for single-run)
        if self.nmap_sn {
            self.loop_mode = false;
            self.only_store_open = false;
        }
    }

    fn apply_timing_template(&mut self, template: &str) {
        match template {
            "0" => {
                self.timeout = 600_000;      // 10 min
                self.concurrency = 2;
                self.max_rate = 100;
            }
            "1" => {
                self.timeout = 15_000;       // 15s
                self.concurrency = 10;
                self.max_rate = 500;
            }
            "2" => {
                self.timeout = 4_000;        // 4s
                self.concurrency = 50;
                self.max_rate = 2_000;
            }
            "3" => {
                self.timeout = 1_000;        // 1s (default)
                self.concurrency = 200;
                self.max_rate = 10_000;
            }
            "4" => {
                self.timeout = 500;          // 500ms
                self.concurrency = 1_000;
                self.max_rate = 50_000;
            }
            "5" => {
                self.timeout = 200;          // 200ms
                self.concurrency = 2_000;
                self.max_rate = 100_000;
                self.skip_private = true;
            }
            _ => {}
        }
    }

    /// Merge configuration from file with command line arguments
    /// Command line arguments take precedence over config file
    pub fn merge_with_config(mut self) -> anyhow::Result<Self> {
        let config_path = self.config_flag.clone().or(self.config_pos.clone());

        let final_config_path = if let Some(path) = config_path {
            Some(path)
        } else {
            let current_dir_config = PathBuf::from("config.toml");
            if current_dir_config.exists() {
                Some(current_dir_config)
            } else {
                None
            }
        };

        if let Some(path) = final_config_path {
            let config_content = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&config_content)?;

            // Merge logic remains the same
            if self.start_ip.is_none() {
                self.start_ip = config.scan.start_ip;
            }
            if self.end_ip.is_none() {
                self.end_ip = config.scan.end_ip;
            }
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
            if !self.verbose {
                self.verbose = config.scan.verbose;
            }
            if !self.loop_mode {
                self.loop_mode = config.scan.loop_mode;
            }
            if !self.ipv4 {
                self.ipv4 = config.scan.ipv4;
            }
            if !self.ipv6 {
                self.ipv6 = config.scan.ipv6;
            }
            if !self.only_store_open {
                self.only_store_open = config.scan.only_store_open;
            }
            if !self.skip_private {
                self.skip_private = config.scan.skip_private;
            }
            if !self.syn {
                self.syn = config.scan.syn;
            }
            if self.geoip_db.is_none() {
                self.geoip_db = config.scan.geoip_db;
            }
            if !self.no_geo {
                self.no_geo = config.scan.no_geo;
            }
            if !self.probe_service {
                self.probe_service = config.scan.probe_service;
            }
            if self.probe_timeout == default_probe_timeout() {
                self.probe_timeout = config.scan.probe_timeout;
            }
            if self.probe_concurrency == default_probe_concurrency() {
                self.probe_concurrency = config.scan.probe_concurrency;
            }
            if self.geo_concurrency == default_geo_concurrency() {
                self.geo_concurrency = config.scan.geo_concurrency;
            }
            if self.worker_threads.is_none() {
                self.worker_threads = config.scan.worker_threads;
            }
            if self.pipeline_buffer == default_pipeline_buffer() {
                self.pipeline_buffer = config.scan.pipeline_buffer;
            }
            if self.result_buffer == default_result_buffer() {
                self.result_buffer = config.scan.result_buffer;
            }
            if self.db_batch_size == default_db_batch_size() {
                self.db_batch_size = config.scan.db_batch_size;
            }
            if self.flush_interval_ms == default_flush_interval_ms() {
                self.flush_interval_ms = config.scan.flush_interval_ms;
            }
            if self.max_rate == default_max_rate() {
                self.max_rate = config.scan.max_rate;
            }
            if self.rate_window_secs == default_window_duration() {
                self.rate_window_secs = config.scan.rate_window_secs;
            }
            if self.round_delay_ms == default_round_delay_ms() {
                self.round_delay_ms = config.scan.round_delay_ms;
            }
            if !self.api {
                self.api = config.api.enabled;
            }
            if !self.api_only {
                self.api_only = config.scan.api_only;
            }
            if !self.no_api {
                self.no_api = config.scan.no_api;
            }
            if self.api_host == default_api_host() {
                self.api_host = config.api.host;
            }
            if self.api_port == default_api_port() {
                self.api_port = config.api.port;
            }
            if !self.swagger_ui {
                self.swagger_ui = config.scan.swagger_ui;
            }
        } else {
            // Apply defaults when no config file is found
            if !self.loop_mode {
                self.loop_mode = default_loop_mode();
            }
            if !self.ipv4 {
                self.ipv4 = default_ipv4();
            }
            if !self.only_store_open {
                self.only_store_open = default_only_store_open();
            }
            if !self.skip_private {
                self.skip_private = default_skip_private();
            }
        }

        self.apply_preset();

        if let Some(ref target) = self.target {
            if let Ok(range) = crate::model::IpRange::parse_target(target) {
                self.start_ip = Some(range.start.to_string());
                self.end_ip = Some(range.end.to_string());
                match range.start {
                    std::net::IpAddr::V4(_) => {
                        self.ipv4 = true;
                    }
                    std::net::IpAddr::V6(_) => {
                        self.ipv6 = true;
                    }
                }
            }
        }

        // Validate configuration
        self.validate()?;

        Ok(self)
    }

    /// Validate configuration parameters
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate timeout
        if self.timeout == 0 {
            return Err(anyhow::anyhow!("Timeout must be greater than 0"));
        }

        // Validate concurrency
        if self.concurrency == 0 {
            return Err(anyhow::anyhow!("Concurrency must be greater than 0"));
        }

        // Validate buffer sizes
        if self.pipeline_buffer == 0 {
            return Err(anyhow::anyhow!("Pipeline buffer must be greater than 0"));
        }
        if self.geo_concurrency == 0 {
            return Err(anyhow::anyhow!("Geo concurrency must be greater than 0"));
        }
        if self.result_buffer == 0 {
            return Err(anyhow::anyhow!("Result buffer must be greater than 0"));
        }
        if self.db_batch_size == 0 {
            return Err(anyhow::anyhow!("DB batch size must be greater than 0"));
        }

        // Validate rate limiting (0 = unlimited, handled by RateLimiter::unlimited)
        if self.rate_window_secs == 0 {
            return Err(anyhow::anyhow!("Rate window must be greater than 0"));
        }

        if self.round_delay_ms > 600_000 {
            return Err(anyhow::anyhow!("Round delay must not exceed 600000 ms"));
        }

        // Validate API port
        if self.api_port == 0 {
            return Err(anyhow::anyhow!("API port must be greater than 0"));
        }

        // Validate conflicting options
        if self.api_only && self.no_api {
            return Err(anyhow::anyhow!(
                "Cannot use --api-only and --no-api together"
            ));
        }

        // Validate IP version selection
        if !self.ipv4 && !self.ipv6 {
            return Err(anyhow::anyhow!(
                "At least one of --ipv4 or --ipv6 must be enabled"
            ));
        }

        if let Some(ref target) = self.target {
            if crate::model::IpRange::parse_target(target).is_err() {
                return Err(anyhow::anyhow!("Invalid target format: {}. Use IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-192.168.1.255)", target));
            }
        }

        if self.output_format != "text" && self.output_format != "json" {
            return Err(anyhow::anyhow!("Output format must be 'text' or 'json'"));
        }

        Ok(())
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
                [240..=255, _, _, _] // 240.0.0.0/4 (reserved)
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_flag_uses_documented_name() {
        let args = Args::try_parse_from(["ip-scan", "--config", "scanner.toml"]).unwrap();
        assert_eq!(args.config_flag, Some(PathBuf::from("scanner.toml")));
    }

    #[test]
    fn test_rejects_zero_runtime_limits() {
        assert!(Args::try_parse_from(["ip-scan", "--concurrency", "0"]).is_err());
        assert!(Args::try_parse_from(["ip-scan", "--timeout", "0"]).is_err());
        assert!(Args::try_parse_from(["ip-scan", "--probe-concurrency", "0"]).is_err());
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(Args::is_private_ipv4("10.0.0.1"));
        assert!(Args::is_private_ipv4("172.16.0.1"));
        assert!(Args::is_private_ipv4("172.31.255.255"));
        assert!(Args::is_private_ipv4("192.168.1.1"));
        assert!(Args::is_private_ipv4("127.0.0.1"));

        assert!(!Args::is_private_ipv4("8.8.8.8"));
        assert!(!Args::is_private_ipv4("1.1.1.1"));
        assert!(!Args::is_private_ipv4("172.15.0.1"));
        assert!(!Args::is_private_ipv4("172.32.0.1"));
    }

    #[test]
    fn test_nmap_sS_flag() {
        let args = Args::try_parse_from(["ip-scan", "-sS", "192.168.1.1"]).unwrap();
        assert!(args.nmap_sS);
    }

    #[test]
    fn test_nmap_timing_t4() {
        let mut args = Args::try_parse_from(["ip-scan", "-T4", "192.168.1.1"]).unwrap();
        args.apply_preset();
        assert_eq!(args.timeout, 500);
        assert_eq!(args.concurrency, 1000);
    }

    #[test]
    fn test_nmap_fast_mode() {
        let mut args = Args::try_parse_from(["ip-scan", "-F", "192.168.1.1"]).unwrap();
        args.apply_preset();
        assert_ne!(args.ports, default_ports());
    }
}

/// Get top N most commonly used ports based on nmap-services data
fn get_top_nmap_ports(n: u16) -> String {
    let all_ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 8888, 9100, 9200, 11211, 27017, 50060, 179, 194, 201, 389,
        443, 465, 514, 515, 587, 636, 873, 989, 990, 1433, 1521, 1720, 1723, 2049, 2375, 2376,
        3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013,
        3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027,
        3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041,
        3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051,
    ];
    let count = n.min(all_ports.len() as u16) as usize;
    all_ports[..count]
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
