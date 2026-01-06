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
#[derive(Debug, Serialize, Deserialize, ToSchema)]
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
}

/// Export format
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    NdJson,
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
