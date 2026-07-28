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
#[command(name = "ip-scan")]
#[command(author = "IP Scanner")]
#[command(version = "0.1.0")]
#[command(about = "High-performance IPv4/IPv6 port scanner", long_about = None)]
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

    /// Port range (e.g., "80", "1-1000", "22,80,443")
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

    /// Number of concurrent connections (I/O-bound: set high)
    #[arg(short = 'c', long, env = "SCAN_CONCURRENCY", default_value = "4000", value_parser = parse_positive_usize)]
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
    #[arg(long, env = "SCAN_DRY_RUN", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,

    /// Verbose output
    #[arg(short = 'v', long, env = "SCAN_VERBOSE")]
    pub verbose: bool,

    /// Enable infinite loop scanning mode
    #[arg(short = 'l', long, env = "SCAN_LOOP_MODE", action = clap::ArgAction::SetTrue)]
    pub loop_mode: bool,

    /// Scan IPv4 addresses
    #[arg(long, env = "SCAN_IPV4", action = clap::ArgAction::SetTrue)]
    pub ipv4: bool,

    /// Scan IPv6 addresses
    #[arg(long, env = "SCAN_IPV6", action = clap::ArgAction::SetTrue)]
    pub ipv6: bool,

    /// Only store open ports (save storage space)
    #[arg(long, env = "SCAN_ONLY_OPEN", action = clap::ArgAction::SetTrue)]
    pub only_store_open: bool,

    /// Skip private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    #[arg(long, env = "SCAN_SKIP_PRIVATE", action = clap::ArgAction::SetTrue)]
    pub skip_private: bool,

    /// Enable SYN scan mode (requires Root/Admin)
    #[arg(long, env = "SCAN_SYN", action = clap::ArgAction::SetTrue)]
    pub syn: bool,

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

    /// Use the bandwidth-saturating raw connect scanner. The default
    /// `--raw` mode spawns one Tokio task per probe and tops out at a
    /// few thousand probes/sec. `--raw` switches to a syscall-level
    /// scanner that holds thousands of in-flight non-blocking sockets
    /// per worker thread and is built to saturate the network link.
    #[arg(long, env = "SCAN_RAW", action = clap::ArgAction::SetTrue)]
    pub raw: bool,

    /// Override the number of worker threads used by the raw scanner.
    /// Defaults to the number of physical cores.
    #[arg(long, env = "SCAN_RAW_WORKERS", value_parser = parse_positive_usize)]
    pub raw_workers: Option<usize>,

    /// Override the per-worker in-flight socket cap for the raw scanner.
    /// Each in-flight slot costs one file descriptor.
    #[arg(long, env = "SCAN_RAW_INFLIGHT", value_parser = parse_positive_usize)]
    pub raw_inflight: Option<usize>,

    /// Enable API server mode
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

    #[arg(
        short = 'T',
        long,
        env = "SCAN_TARGET",
        help = "Target: IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-192.168.1.255)"
    )]
    pub target: Option<String>,

    #[arg(long, env = "SCAN_PRESET", help = "Scan preset: quick, standard, deep")]
    pub preset: Option<String>,

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

    /// Enable service detection (probe open ports for banners, HTTP info, etc.)
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

    #[arg(long, env = "SCAN_RESULT_BUFFER", default_value = "65536", value_parser = parse_positive_usize)]
    pub result_buffer: usize,

    #[arg(long, env = "SCAN_DB_BATCH_SIZE", default_value = "10000", value_parser = parse_positive_usize)]
    pub db_batch_size: usize,

    #[arg(long, env = "SCAN_FLUSH_INTERVAL_MS", default_value = "2000")]
    pub flush_interval_ms: u64,

    /// Max packets per second per scanner. Set to 0 for unlimited (run at
    /// full throughput until the network or target rate-limits).
    #[arg(long, env = "SCAN_MAX_RATE", default_value = "0")]
    pub max_rate: u64,

    #[arg(long, env = "SCAN_RATE_WINDOW_S", default_value = "1")]
    pub rate_window_secs: u64,

    /// Delay between scan rounds in loop mode (milliseconds, default 0).
    /// Set above 0 when scanning a single fixed range to avoid hammering the
    /// same subnet each pass; leave at 0 for continuous range sweeps.
    #[arg(long, env = "SCAN_ROUND_DELAY_MS", default_value = "0")]
    pub round_delay_ms: u64,

    // === Nmap-compatible arguments ===
    /// SYN stealth scan (-sS)
    #[arg(long = "sS", help = "Nmap compat: SYN stealth scan")]
    pub nmap_sS: bool,

    /// Connect scan (-sT, default behavior)
    #[arg(long = "sT", help = "Nmap compat: TCP connect scan")]
    pub nmap_sT: bool,

    /// Ping scan only (-sn)
    #[arg(long = "sn", help = "Nmap compat: Ping scan only")]
    pub nmap_sn: bool,

    /// Service/version detection (-sV)
    #[arg(long = "sV", help = "Nmap compat: Service/version detection")]
    pub nmap_sV: bool,

    /// OS detection (-O)
    #[arg(
        long = "O",
        help = "Nmap compat: OS detection (maps to enhanced probing)"
    )]
    pub nmap_O: bool,

    /// Aggressive scan (-A = -sV + -sC + -O + -T4)
    #[arg(long = "A", help = "Nmap compat: Aggressive scan (-sV -sC -O -T4)")]
    pub nmap_A: bool,

    /// Default NSE scripts (-sC)
    #[arg(long = "sC", help = "Nmap compat: Default NSE scripts")]
    pub nmap_sC: bool,

    /// Fast mode - top 100 ports (-F)
    #[arg(long = "F", help = "Nmap compat: Fast mode (top 100 ports)")]
    pub nmap_F: bool,

    /// Timing template (-T0 ~ -T5)
    #[arg(long = "T", help = "Nmap compat: Timing template (0-5)")]
    pub nmap_T: Option<String>,

    /// Scan N most common ports (--top-ports)
    #[arg(long = "top-ports", help = "Nmap compat: Scan N most common ports")]
    pub nmap_top_ports: Option<usize>,

    /// Read targets from file (-iL)
    #[arg(long = "iL", help = "Nmap compat: Read targets from file")]
    pub nmap_iL: Option<String>,

    /// Normal output (-oN)
    #[arg(long = "oN", help = "Nmap compat: Normal output file")]
    pub nmap_oN: Option<String>,

    /// JSON output (-oJ)
    #[arg(long = "oJ", help = "Nmap compat: JSON output file")]
    pub nmap_oJ: Option<String>,

    /// Grepable output (-oG)
    #[arg(long = "oG", help = "Nmap compat: Grepable output file")]
    pub nmap_oG: Option<String>,

    /// XML output (-oX)
    #[arg(long = "oX", help = "Nmap compat: XML output file")]
    pub nmap_oX: Option<String>,

    /// All output formats (-oA)
    #[arg(long = "oA", help = "Nmap compat: All output formats")]
    pub nmap_oA: Option<String>,

    /// Positional nmap target arguments (e.g., IP ranges)
    #[arg(hide = true)]
    pub nmap_target: Vec<String>,
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
    4000
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
    65536
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
    pub fn apply_preset(&mut self) {
        if let Some(ref preset) = self.preset {
            match preset.as_str() {
                "quick" => {
                    self.timeout = 200;
                    self.concurrency = 4000;
                    self.max_rate = 0;
                    if self.ports == default_ports() {
                        self.ports = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,9200,27017".to_string();
                    }
                }
                "standard" => {
                    self.timeout = 500;
                    self.concurrency = 4000;
                    self.max_rate = 0;
                }
                "deep" => {
                    self.timeout = 2000;
                    self.concurrency = 1000;
                    self.max_rate = 0;
                    if self.ports == default_ports() {
                        self.ports = "1-65535".to_string();
                    }
                }
                "max-speed" => {
                    // Maximum-throughput preset: opt into the raw scanner,
                    // disable rate limiting, and increase in-flight / DB
                    // batch sizes to the limits that the raw scanner can
                    // actually push through. Use this when you control
                    // the target network and want to find every open
                    // TCP port as quickly as the link allows.
                    self.timeout = 800;
                    self.concurrency = 8_000;
                    self.max_rate = 0;
                    self.skip_private = true;
                    self.raw = true;
                    self.probe_service = true;
                    self.probe_concurrency = 512;
                    self.pipeline_buffer = self.pipeline_buffer.max(1 << 20);
                    self.result_buffer = self.result_buffer.max(1 << 20);
                    self.db_batch_size = self.db_batch_size.max(50_000);
                    self.flush_interval_ms = self.flush_interval_ms.min(500);
                    if self.ports == default_ports() {
                        self.ports = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,9200,27017".to_string();
                    }
                    tracing::warn!(
                        "preset=max-speed: enabling the bandwidth-saturating \
                         raw scanner with unlimited rate. Only run this \
                         against networks you are explicitly authorised to \
                         test."
                    );
                }
                "fullpublic" => {
                    // Opt-in preset for the user's goal: scan every public
                    // IPv4 × top ports at full bandwidth. Same plumbing as
                    // max-speed but with --scan-public forced on and 18-port
                    // top-list. Logs the legal reminder on every run.
                    self.timeout = 800;
                    self.concurrency = 8_000;
                    self.max_rate = 0;
                    self.skip_private = true;
                    self.scan_public = true;
                    self.raw = true;
                    self.probe_service = true;
                    self.probe_concurrency = 512;
                    self.pipeline_buffer = self.pipeline_buffer.max(1 << 20);
                    self.result_buffer = self.result_buffer.max(1 << 20);
                    self.db_batch_size = self.db_batch_size.max(50_000);
                    self.flush_interval_ms = self.flush_interval_ms.min(500);
                    if self.ports == default_ports() {
                        self.ports = "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443,9200,27017".to_string();
                    }
                    tracing::warn!(
                        "preset=fullpublic: scanning the public IPv4 space at \
                         full bandwidth via the raw scanner. Only run this \
                         against networks you are explicitly authorised to \
                         test. Large or un-authorised public scans may \
                         violate local law or your ISP's acceptable-use \
                         policy."
                    );
                }
                _ => {}
            }
        }

        // --scan-public without an explicit target expands to the full
        // public IPv4 range and forces skip-private. The validate() step
        // catches any contradictory combination (e.g. a separately-
        // provided CIDR that resolves to RFC1918).
        if self.scan_public && self.target.is_none()
            && (self.start_ip.is_none() || self.end_ip.is_none())
        {
            self.start_ip = Some("1.0.0.0".to_string());
            self.end_ip = Some("223.255.255.255".to_string());
            self.ipv4 = true;
            self.skip_private = true;
        }
    }

    /// Translate nmap-compat fields (--sV/--O/--A/--iL/--T<n>) into the
    /// internal Args fields that actually drive the scan. Runs at the end
    /// of `merge_with_config`. Safe to call multiple times.
    /// Top 100 most common ports (nmap default with -F)
    const TOP_100_PORTS: &'static str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,9100,9200,11211,27017,50060";

    /// Top 1000 most common ports (nmap default)
    const TOP_1000_PORTS: &'static str = "1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,271,272,273,274,275,276,277,278,279,280,281,282,283,284,285,286,287,288,289,290,291,292,293,294,295,296,297,298,299,300,301,302,303,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339,340,341,342,343,344,345,346,347,348,349,350,351,352,353,354,355,356,357,358,359,360,361,362,363,364,365,366,367,368,369,370,371,372,373,374,375,376,377,378,379,380,381,382,383,384,385,386,387,388,389,390,391,392,393,394,395,396,397,398,399,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,427,428,429,430,431,432,433,434,435,436,437,438,439,440,441,442,443,444,445,446,447,448,449,450,451,452,453,454,455,456,457,458,459,460,461,462,463,464,465,466,467,468,469,470,471,472,473,474,475,476,477,478,479,480,481,482,483,484,485,486,487,488,489,490,491,492,493,494,495,496,497,498,499,500,501,502,503,504,505,506,507,508,509,510,511,512,513,514,515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,548,549,550,551,552,553,554,555,556,557,558,559,560,561,562,563,564,565,566,567,568,569,570,571,572,573,574,575,576,577,578,579,580,581,582,583,584,585,586,587,588,589,590,591,592,593,594,595,596,597,598,599,600,601,602,603,604,605,606,607,608,609,610,611,612,613,614,615,616,617,618,619,620,621,622,623,624,625,626,627,628,629,630,631,632,633,634,635,636,637,638,639,640,641,642,643,644,645,646,647,648,649,650,651,652,653,654,655,656,657,658,659,660,661,662,663,664,665,666,667,668,669,670,671,672,673,674,675,676,677,678,679,680,681,682,683,684,685,686,687,688,689,690,691,692,693,694,695,696,697,698,699,700,701,702,703,704,705,706,707,708,709,710,711,712,713,714,715,716,717,718,719,720,721,722,723,724,725,726,727,728,729,730,731,732,733,734,735,736,737,738,739,740,741,742,743,744,745,746,747,748,749,750,751,752,753,754,755,756,757,758,759,760,761,762,763,764,765,766,767,768,769,770,771,772,773,774,775,776,777,778,779,780,781,782,783,784,785,786,787,788,789,790,791,792,793,794,795,796,797,798,799,800,801,802,803,804,805,806,807,808,809,810,811,812,813,814,815,816,817,818,819,820,821,822,823,824,825,826,827,828,829,830,831,832,833,834,835,836,837,838,839,840,841,842,843,844,845,846,847,848,849,850,851,852,853,854,855,856,857,858,859,860,861,862,863,864,865,866,867,868,869,870,871,872,873,874,875,876,877,878,879,880,881,882,883,884,885,886,887,888,889,890,891,892,893,894,895,896,897,898,899,900,901,902,903,904,905,906,907,908,909,910,911,912,913,914,915,916,917,918,919,920,921,922,923,924,925,926,927,928,929,930,931,932,933,934,935,936,937,938,939,940,941,942,943,944,945,946,947,948,949,950,951,952,953,954,955,956,957,958,959,960,961,962,963,964,965,966,967,968,969,970,971,972,973,974,975,976,977,978,979,980,981,982,983,984,985,986,987,988,989,990,991,992,993,994,995,996,997,998,999,1000,1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1011,1012,1013,1014,1015,1016,1017,1018,1019,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1101,1102,1103,1104,1105,1106,1107,1108,1109,1110,1111,1112,1113,1114,1115,1116,1117,1118,1119,1120,1121,1122,1123,1124,1125,1126,1127,1128,1129,1130,1131,1132,1133,1134,1135,1136,1137,1138,1139,1140,1141,1142,1143,1144,1145,1146,1147,1148,1149,1150,1151,1152,1153,1154,1155,1156,1157,1158,1159,1160,1161,1162,1163,1164,1165,1166,1167,1168,1169,1170,1171,1172,1173,1174,1175,1176,1177,1178,1179,1180,1181,1182,1183,1184,1185,1186,1187,1188,1189,1190,1191,1192,1193,1194,1195,1196,1197,1198,1199,1200,1201,1202,1203,1204,1205,1206,1207,1208,1209,1210,1211,1212,1213,1214,1215,1216,1217,1218,1219,1220,1221,1222,1223,1224,1225,1226,1227,1228,1229,1230,1231,1232,1233,1234,1235,1236,1237,1238,1239,1240,1241,1242,1243,1244,1245,1246,1247,1248,1249,1250,1251,1252,1253,1254,1255,1256,1257,1258,1259,1260,1261,1262,1263,1264,1265,1266,1267,1268,1269,1270,1271,1272,1273,1274,1275,1276,1277,1278,1279,1280,1281,1282,1283,1284,1285,1286,1287,1288,1289,1290,1291,1292,1293,1294,1295,1296,1297,1298,1299,1300,1301,1302,1303,1304,1305,1306,1307,1308,1309,1310,1311,1312,1313,1314,1315,1316,1317,1318,1319,1320,1321,1322,1323,1324,1325,1326,1327,1328,1329,1330,1331,1332,1333,1334,1335,1336,1337,1338,1339,1340,1341,1342,1343,1344,1345,1346,1347,1348,1349,1350,1351,1352,1353,1354,1355,1356,1357,1358,1359,1360,1361,1362,1363,1364,1365,1366,1367,1368,1369,1370,1371,1372,1373,1374,1375,1376,1377,1378,1379,1380,1381,1382,1383,1384,1385,1386,1387,1388,1389,1390,1391,1392,1393,1394,1395,1396,1397,1398,1399,1400,1401,1402,1403,1404,1405,1406,1407,1408,1409,1410,1411,1412,1413,1414,1415,1416,1417,1418,1419,1420,1421,1422,1423,1424,1425,1426,1427,1428,1429,1430,1431,1432,1433,1434,1435,1436,1437,1438,1439,1440,1441,1442,1443,1444,1445,1446,1447,1448,1449,1450,1451,1452,1453,1454,1455,1456,1457,1458,1459,1460,1461,1462,1463,1464,1465,1466,1467,1468,1469,1470,1471,1472,1473,1474,1475,1476,1477,1478,1479,1480,1481,1482,1483,1484,1485,1486,1487,1488,1489,1490,1491,1492,1493,1494,1495,1496,1497,1498,1499,1500,1501,1502,1503,1504,1505,1506,1507,1508,1509,1510,1511,1512,1513,1514,1515,1516,1517,1518,1519,1520,1521,1522,1523,1524,1525,1526,1527,1528,1529,1530,1531,1532,1533,1534,1535,1536,1537,1538,1539,1540,1541,1542,1543,1544,1545,1546,1547,1548,1549,1550,1551,1552,1553,1554,1555,1556,1557,1558,1559,1560,1561,1562,1563,1564,1565,1566,1567,1568,1569,1570,1571,1572,1573,1574,1575,1576,1577,1578,1579,1580,1581,1582,1583,1584,1585,1586,1587,1588,1589,1590,1591,1592,1593,1594,1595,1596,1597,1598,1599,1600,1601,1602,1603,1604,1605,1606,1607,1608,1609,1610,1611,1612,1613,1614,1615,1616,1617,1618,1619,1620,1621,1622,1623,1624,1625,1626,1627,1628,1629,1630,1631,1632,1633,1634,1635,1636,1637,1638,1639,1640,1641,1642,1643,1644,1645,1646,1647,1648,1649,1650,1651,1652,1653,1654,1655,1656,1657,1658,1659,1660,1661,1662,1663,1664,1665,1666,1667,1668,1669,1670,1671,1672,1673,1674,1675,1676,1677,1678,1679,1680,1681,1682,1683,1684,1685,1686,1687,1688,1689,1690,1691,1692,1693,1694,1695,1696,1697,1698,1699,1700,1701,1702,1703,1704,1705,1706,1707,1708,1709,1710,1711,1712,171 I'll continue with the rest of the edit in the next step due to its length. Let me first check what ports are commonly used in nmap and then implement a more maintainable solution.

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
        self.apply_nmap_args();

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

        // Validate rate limiting
        // max_rate == 0 means unlimited and is valid; > 0 must be positive
        if self.max_rate > 0 && self.rate_window_secs == 0 {
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
}
