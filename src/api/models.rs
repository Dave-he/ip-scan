//! API data models
//!
//! This module defines the data structures used in API requests and responses.

use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Helper function to deserialize numbers from strings
fn deserialize_number_from_string<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<usize>().map_err(serde::de::Error::custom)
}

/// Helper function to deserialize optional u16 from strings
fn deserialize_optional_u16_from_string<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => s.parse::<u16>().map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Helper function to deserialize optional i64 from strings
fn deserialize_optional_i64_from_string<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => s.parse::<i64>().map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

/// Scan result for a specific IP and port
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct ScanResult {
    /// IP address
    pub ip_address: String,

    /// IP type (IPv4 or IPv6)
    pub ip_type: String,

    /// Port number
    pub port: u16,

    /// Scan round when this port was found open
    pub scan_round: i64,

    /// First time this port was seen open
    pub first_seen: String,

    /// Last time this port was seen open
    pub last_seen: String,

    /// Country (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// Region / subdivision (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// City (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,

    /// ISP / organization (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,

    /// ASN (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,

    /// Reverse DNS hostname (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<String>,

    /// Top-level service name detected on this port (from service_info).
    /// Empty when --probe-service wasn't enabled for this round.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    /// Banner or HTTP title for this port (truncated, safe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,

    /// Asset category derived from services on this IP
    /// (`web-server`, `database-server`, `mail-server`, `linux-server`,
    /// `remote-desktop`, `file-server`, `server`, `unknown`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Risk score for this (ip, port) pair, 0-100. `None` if no probe ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,

    /// Latitude (optional, used by map view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,

    /// Longitude (optional, used by map view).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
}

/// Paginated response for scan results
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PaginatedResults {
    /// List of scan results
    pub results: Vec<ScanResult>,

    /// Total number of results available
    pub total: usize,

    /// Current page number (1-indexed)
    pub page: usize,

    /// Number of results per page
    pub page_size: usize,

    /// Total number of pages
    pub total_pages: usize,
}

/// Versioned protocol metadata used by independent frontends to discover a compatible backend.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SystemInfoResponse {
    pub protocol: String,
    pub api_version: String,
    pub service: String,
    pub version: String,
    pub status: String,
    pub database: String,
    pub server_time: String,
    pub capabilities: Vec<String>,
    pub endpoints: Vec<String>,
    /// Stable cluster node id (so a distributed frontend can group results
    /// by source). Falls back to the listen host:port if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Human-readable node label (e.g. "ali-shanghai").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_label: Option<String>,
    /// Cloud / hosting provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_provider: Option<String>,
    /// Approximate node latitude (decimal degrees) for the map view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_latitude: Option<f64>,
    /// Approximate node longitude (decimal degrees) for the map view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_longitude: Option<f64>,
    /// Currently configured scan target range (start_ip..end_ip) when a
    /// CLI-managed scan is running. Useful for the distributed frontend to
    /// label which node is sweeping what range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_target_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_target_end: Option<String>,
}

/// Statistics response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StatsResponse {
    /// Total number of open port records
    pub total_open_records: usize,

    /// Number of unique IPs with open ports
    pub unique_ips: usize,

    /// Memory usage in MB
    pub memory_usage_mb: f64,

    /// Current scan round
    pub current_round: i64,

    /// Last scan timestamp
    pub last_scan_time: Option<String>,
}

/// Port statistics
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PortStats {
    /// Port number
    pub port: u16,

    /// Number of IPs with this port open
    pub open_count: usize,

    /// Percentage of total open ports
    pub percentage: f64,
}

/// Top ports response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TopPortsResponse {
    /// List of port statistics
    pub ports: Vec<PortStats>,

    /// Total number of open ports across all IPs
    pub total_open_ports: usize,
}

/// Error response
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,

    /// Error code (optional)
    pub code: Option<String>,
}

/// Query parameters for pagination
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct PaginationQuery {
    /// Page number (1-indexed, default: 1)
    #[serde(
        default = "default_page",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub page: usize,

    /// Page size (default: 50, max: 500)
    #[serde(
        default = "default_page_size",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub page_size: usize,
}

/// Query parameters for filtering scan results
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct FilterQuery {
    /// Filter by IP address (partial match)
    #[serde(default)]
    pub ip: Option<String>,

    /// Filter by port number
    #[serde(default, deserialize_with = "deserialize_optional_u16_from_string")]
    pub port: Option<u16>,

    /// Filter by scan round
    #[serde(default, deserialize_with = "deserialize_optional_i64_from_string")]
    pub round: Option<i64>,

    /// Filter by IP type (IPv4 or IPv6)
    #[serde(default)]
    pub ip_type: Option<String>,
}

/// Combined query parameters
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct ResultsQuery {
    #[serde(flatten)]
    pub pagination: PaginationQuery,

    #[serde(flatten)]
    pub filter: FilterQuery,
}

/// Query parameters for top ports
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct TopPortsQuery {
    /// Number of top ports to return (default: 10, max: 100)
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Start scan request
#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)]
pub struct StartScanRequest {
    /// Start IP address
    pub start_ip: Option<String>,

    /// End IP address
    pub end_ip: Option<String>,

    /// Ports to scan (comma-separated or range)
    pub ports: Option<String>,

    /// Timeout in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Concurrency level
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// Enable SYN scan mode
    #[serde(default)]
    pub syn: bool,

    /// Skip private IP ranges
    #[serde(default)]
    pub skip_private: bool,

    /// Enable service-probe enrichment (Banner / HTTP / TLS metadata) for
    /// newly discovered open ports. Mirrors the CLI --probe-service flag
    /// and the unified web console's "启用服务探测" toggle. Defaults to false
    /// so a request without the field behaves like before.
    #[serde(default)]
    pub probe_service: bool,
}

/// Export format
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    NdJson,
}

/// Scan status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum ScanStatus {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
    Error(String),
}

// Default values
fn default_page() -> usize {
    1
}
fn default_page_size() -> usize {
    50
}
fn default_timeout() -> u64 {
    500
}
fn default_concurrency() -> usize {
    100
}

impl PaginationQuery {
    /// Validate pagination parameters
    pub fn validate(&self) -> Result<(), String> {
        if self.page < 1 {
            return Err("Page must be at least 1".to_string());
        }
        if self.page_size < 1 || self.page_size > 500 {
            return Err("Page size must be between 1 and 500".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceInfoResponse {
    pub ip: String,
    pub port: u16,
    pub service_name: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_body_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_body_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_security_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_guess: Option<String>,
    pub detected_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IpServiceSummaryResponse {
    pub ip: String,
    pub services: Vec<ServiceInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_type: Option<String>,
    pub category: String,
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceSummaryListResponse {
    pub summaries: Vec<IpServiceSummaryResponse>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

/// Aggregate stats grouped by IP family. The distributed frontend uses this
/// to render the IPv4 vs IPv6 split view.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IpFamilyStatsResponse {
    pub ipv4_unique_ips: usize,
    pub ipv6_unique_ips: usize,
    pub ipv4_open_ports: usize,
    pub ipv6_open_ports: usize,
}

/// Aggregate stats grouped by detected service_name (e.g. ssh, http, redis).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceStatsEntry {
    pub service_name: String,
    pub unique_ips: usize,
    pub open_ports: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceStatsResponse {
    pub services: Vec<ServiceStatsEntry>,
    pub total_unique_ips: usize,
}

/// Aggregate stats grouped by asset category (web-server, database-server, …).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CategoryStatsEntry {
    pub category: String,
    pub unique_ips: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CategoryStatsResponse {
    pub categories: Vec<CategoryStatsEntry>,
    pub total_unique_ips: usize,
}

/// Compact geo-located IP for the map view. Lightly trimmed to keep
/// individual responses small even when paginating thousands of markers.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IpLocationResponse {
    pub ip: String,
    pub ip_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub open_ports: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_service: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IpLocationsResponse {
    pub locations: Vec<IpLocationResponse>,
    pub total: usize,
    pub limit: usize,
}

/// Per-IP aggregate returned by `GET /api/v1/ip/{ip}`. Combines geo,
/// open-port list, detected services and risk assessment so a single
/// request drives the IP detail panel in the distributed frontend.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IpDetailResponse {
    pub ip: String,
    pub ip_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_source: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub open_ports: Vec<ScanResult>,
    pub category: String,
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
    /// Number of distinct IPs that share the same ASN as this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_peer_count: Option<usize>,
    /// Number of distinct IPs hosted by the same ISP / organization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp_peer_count: Option<usize>,
}

/// Aggregate stats grouped by ASN (e.g. `AS4134` -> unique IP count).
/// Drives the ASN chart in the IP-family / map view.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AsnStatsEntry {
    pub asn: String,
    pub unique_ips: usize,
    pub open_ports: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AsnStatsResponse {
    pub asns: Vec<AsnStatsEntry>,
    pub total_unique_ips: usize,
}

/// Aggregate stats grouped by ISP / organization.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrgStatsEntry {
    pub isp: String,
    pub unique_ips: usize,
    pub open_ports: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OrgStatsResponse {
    pub organizations: Vec<OrgStatsEntry>,
    pub total_unique_ips: usize,
}

/// Compact preview of an asset (single IP) for the IP-family / map views.
/// Derived from the open_ports_detail + ip_details join.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AssetSummary {
    pub ip: String,
    pub ip_type: String,
    pub open_ports: usize,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AssetSummaryListResponse {
    pub assets: Vec<AssetSummary>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
}

/// Raw TCP snapshot for a single IP (truncated to a safe size). The
/// frontend uses this to render banner previews, raw byte hex dumps and
/// HTTP body previews for the IP detail panel.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpSnapshotResponse {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_first_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_raw_hex: Option<String>,
    pub banner_raw_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_san: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_guess: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_technologies: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub captured_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpSnapshotListResponse {
    pub ip: String,
    pub snapshots: Vec<TcpSnapshotResponse>,
}
/// Query parameters for the /assets endpoint.
#[derive(Debug, serde::Deserialize, ToSchema, IntoParams)]
pub struct AssetsQuery {
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub page_size: Option<usize>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub min_risk: Option<u8>,
}
