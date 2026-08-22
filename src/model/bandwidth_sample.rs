//! One row of end-to-end bandwidth measurement.
//!
//! Each `BandwidthSample` captures the full breakdown of a single HTTP
//! GET against a target domain: DNS, TCP, TTFB, transfer, total
//! wall-clock, negotiated bytes, throughput in Mbps, the relevant
//! response headers and a one-word error category (`dns_err`,
//! `tcp_timeout`, `http_err`, `waf_challenge`, ...).
//!
//! Mirrored as the `bandwidth_samples` SQLite table. Serialized as
//! JSONL and CSV by `service::bandwidth_prober::report`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthSample {
    pub ts: String,
    pub round: u32,
    pub attempt: u32,
    pub target: String,
    pub ip: Option<String>,
    pub port: u16,
    pub dns_ms: Option<f64>,
    pub tcp_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub transfer_ms: Option<f64>,
    pub total_ms: f64,
    pub bytes: u64,
    pub throughput_mbps: f64,
    pub http_status: Option<u16>,
    pub server: Option<String>,
    pub via: Option<String>,
    pub content_encoding: Option<String>,
    pub accept_ranges: Option<String>,
    pub range_ok: bool,
    /// `None` for a healthy, ranged response. One of: `dns_err`,
    /// `tcp_timeout`, `tcp_err`, `http_err`, `http_timeout`,
    /// `waf_challenge`, `captcha`, `spa`, `too_small`,
    /// `rate_limited`, `empty_body`.
    pub error: Option<String>,
}

impl BandwidthSample {
    /// True only when the sample carried a real ranged response with
    /// non-zero throughput. Used by the stability rule so WAF blocks,
    /// SPA shells and other short-body fallbacks do not pollute the
    /// median.
    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.range_ok && self.throughput_mbps > 0.0
    }

    /// Sum of the three pre-TTFB timing phases. Returns `None` if
    /// any phase is missing (DNS or TCP timed out).
    pub fn rtt_ms(&self) -> Option<f64> {
        Some(self.dns_ms? + self.tcp_ms? + self.ttfb_ms?)
    }
}
