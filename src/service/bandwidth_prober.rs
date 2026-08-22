//! Bandwidth benchmarking prober.
//!
//! Performs end-to-end HTTP GET measurements against a list of target
//! domains. For each target it captures DNS, TCP, TTFB and transfer
//! timing, plus the negotiated `Content-Range`, `Server`, `Via` and
//! `Content-Encoding` headers. Throughput is reported as the wire-speed
//! estimate over the *transfer* phase (excluding TTFB), in megabits per
//! second.
//!
//! Used by `ip-scan --bench-bandwidth` against the bundled
//! `data/cn_top_1000.csv` domain list. The prober runs multiple rounds
//! and stops when the per-round medians of throughput and RTT stay
//! within a configurable coefficient of variation for three
//! consecutive rounds (see [`BenchConfig::stop_cv_throughput`] and
//! [`BenchConfig::stop_cv_rtt`]).

pub use crate::model::BandwidthSample;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) \
     Version/17.0 Safari/605.1.15";

const DEFAULT_BENCH_TIMEOUT_SECS: u64 = 10;
const DEFAULT_DNS_TIMEOUT_SECS: u64 = 5;
const DEFAULT_TCP_TIMEOUT_SECS: u64 = 5;

/// One target the prober will measure. The prober always prefers the
/// supplied port (typically 443); the [`BandwidthProber`] never falls
/// back to a different port on its own — that's a domain-list decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchTarget {
    pub domain: String,
    pub port: u16,
    /// Optional category string from the source CSV ("search", "video",
    /// ...). Carried through to reports so per-category rollups are
    /// trivial. Empty string when unknown.
    #[serde(default)]
    pub category: String,
}

/// Static configuration. CLI flags + `config.toml [bench]` block
/// hydrate this before construction.
#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub concurrency: usize,
    pub bytes_per_target: u64,
    pub rounds: u32,
    pub min_rounds: u32,
    pub stop_cv_throughput: f64,
    pub stop_cv_rtt: f64,
    pub timeout_secs: u64,
    pub output_dir: PathBuf,
    pub node_id: String,
    pub attempts_per_target: u32,
}

impl BenchConfig {
    /// Sensible defaults for a 2026-era home broadband link.
    pub fn default_for_home_link() -> Self {
        Self {
            concurrency: 100,
            bytes_per_target: 1024 * 1024,
            rounds: 5,
            min_rounds: 3,
            stop_cv_throughput: 0.10,
            stop_cv_rtt: 0.15,
            timeout_secs: DEFAULT_BENCH_TIMEOUT_SECS,
            output_dir: PathBuf::from("results/bandwidth"),
            node_id: "local".into(),
            attempts_per_target: 1,
        }
    }
}

/// One row of measurement. The struct itself lives in
/// [`crate::model::BandwidthSample`]; this module imports it as
/// `BandwidthSample` so the local probe code reads naturally.

/// Run-level aggregate returned by `run_until_stable`.
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    pub rounds_run: u32,
    pub stopped_reason: String,
    pub total_targets: usize,
    pub final_median_throughput_mbps: f64,
    pub final_median_rtt_ms: f64,
    pub success_rate: f64,
    pub cv_throughput: f64,
    pub cv_rtt: f64,
    pub node_id: String,
}

#[derive(Clone)]
pub struct BandwidthProber {
    cfg: BenchConfig,
    http_client: reqwest::Client,
}

impl BandwidthProber {
    pub fn new(cfg: BenchConfig) -> Result<Self> {
        let timeout_secs = cfg.timeout_secs.max(1);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs))
            .read_timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .http1_only()
            .user_agent(DEFAULT_USER_AGENT)
            .build()?;
        Ok(Self {
            cfg,
            http_client: client,
        })
    }

    /// Probe every target once. Concurrency is bounded by
    /// `BenchConfig::concurrency`. Order of returned samples is not
    /// preserved — caller should sort if it matters.
    pub async fn run_round(&self, targets: &[BenchTarget], round: u32) -> Vec<BandwidthSample> {
        let sem = Arc::new(tokio::sync::Semaphore::new(self.cfg.concurrency.max(1)));
        let mut tasks = tokio::task::JoinSet::new();
        for (idx, target) in targets.iter().enumerate() {
            for attempt in 0..self.cfg.attempts_per_target.max(1) {
                let permit = sem.clone().acquire_owned().await.unwrap();
                let prober = self.clone();
                let target = target.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    prober.probe_one(&target, round, attempt, idx).await
                });
            }
        }

        let mut samples = Vec::with_capacity(targets.len());
        while let Some(res) = tasks.join_next().await {
            if let Ok(s) = res {
                samples.push(s);
            }
        }
        samples
    }

    /// Run rounds until the stop rule fires or `cfg.rounds` is hit.
    /// `on_round` is invoked after each round completes (with the round
    /// number and the samples just collected) so the caller can persist
    /// per-round JSONL files and refresh the live dashboard.
    pub async fn run_until_stable<F>(
        &self,
        targets: &[BenchTarget],
        mut on_round: F,
    ) -> RunSummary
    where
        F: FnMut(u32, &[BandwidthSample]),
    {
        let mut all_rounds: Vec<Vec<BandwidthSample>> = Vec::new();
        let mut stopped_reason = String::new();

        for round in 1..=self.cfg.rounds.max(1) {
            info!(
                "bench round {}/{} starting ({} targets, concurrency={})",
                round,
                self.cfg.rounds,
                targets.len(),
                self.cfg.concurrency
            );
            let samples = self.run_round(targets, round).await;
            on_round(round, &samples);
            all_rounds.push(samples);

            let stats = compute_round_stats(&all_rounds);
            info!(
                "bench round {}/{} done: med-rtt={:.1}ms med-bw={:.2}Mbps ok={}/{} \
                 CV(bw,{}r)={:.3} CV(rtt,{}r)={:.3} ok%={:.1}%",
                round,
                self.cfg.rounds,
                stats.median_rtt_ms,
                stats.median_throughput_mbps,
                stats.ok_count,
                stats.total_count,
                stats.cv_window,
                stats.cv_throughput,
                stats.cv_window,
                stats.cv_rtt,
                stats.success_rate * 100.0
            );

            if round >= self.cfg.min_rounds
                && stats.cv_window >= 3
                && stats.cv_throughput <= self.cfg.stop_cv_throughput
                && stats.cv_rtt <= self.cfg.stop_cv_rtt
                && stats.success_rate >= 0.60
            {
                stopped_reason = format!(
                    "stable: CV(bw)={:.3} ≤ {}, CV(rtt)={:.3} ≤ {}, ok%={:.1}% ≥ 60%",
                    stats.cv_throughput, self.cfg.stop_cv_throughput, stats.cv_rtt, self.cfg.stop_cv_rtt,
                    stats.success_rate * 100.0
                );
                info!("bench stopping: {}", stopped_reason);
                break;
            }

            if round >= self.cfg.rounds {
                stopped_reason = format!("reached max rounds = {}", self.cfg.rounds);
                warn!("bench stopping: {}", stopped_reason);
            }
        }

        let final_stats = compute_round_stats(&all_rounds);
        RunSummary {
            rounds_run: all_rounds.len() as u32,
            stopped_reason: if stopped_reason.is_empty() {
                "no rounds completed".into()
            } else {
                stopped_reason
            },
            total_targets: targets.len(),
            final_median_throughput_mbps: final_stats.median_throughput_mbps,
            final_median_rtt_ms: final_stats.median_rtt_ms,
            success_rate: final_stats.success_rate,
            cv_throughput: final_stats.cv_throughput,
            cv_rtt: final_stats.cv_rtt,
            node_id: self.cfg.node_id.clone(),
        }
    }

    async fn probe_one(
        &self,
        target: &BenchTarget,
        round: u32,
        attempt: u32,
        _idx: usize,
    ) -> BandwidthSample {
        let started = Instant::now();
        let ts = Utc::now().to_rfc3339();
        let target_str = format!("{}:{}", target.domain, target.port);

        // 1. DNS
        let dns_start = Instant::now();
        let dns_result = timeout(
            Duration::from_secs(DEFAULT_DNS_TIMEOUT_SECS),
            tokio::net::lookup_host((target.domain.clone(), target.port)),
        )
        .await;
        let dns_ms = dns_result
            .as_ref()
            .ok()
            .and_then(|r| r.as_ref().ok())
            .map(|_| dns_start.elapsed().as_secs_f64() * 1000.0);
        let resolved = match dns_result {
            Ok(Ok(mut addrs)) => addrs.next(),
            Ok(Err(e)) => {
                debug!("dns error for {}: {}", target_str, e);
                None
            }
            Err(_) => None,
        };
        let ip_str = resolved.as_ref().map(|a| a.ip().to_string());

        let Some(addr) = resolved else {
            return BandwidthSample {
                ts,
                round,
                attempt,
                target: target.domain.clone(),
                ip: None,
                port: target.port,
                dns_ms,
                tcp_ms: None,
                ttfb_ms: None,
                transfer_ms: None,
                total_ms: started.elapsed().as_secs_f64() * 1000.0,
                bytes: 0,
                throughput_mbps: 0.0,
                http_status: None,
                server: None,
                via: None,
                content_encoding: None,
                accept_ranges: None,
                range_ok: false,
                error: Some("dns_err".into()),
            };
        };

        // 2. TCP
        let tcp_start = Instant::now();
        let tcp_result = timeout(
            Duration::from_secs(DEFAULT_TCP_TIMEOUT_SECS),
            TcpStream::connect(addr),
        )
        .await;
        let tcp_ms = tcp_result
            .as_ref()
            .ok()
            .and_then(|r| r.as_ref().ok())
            .map(|_| tcp_start.elapsed().as_secs_f64() * 1000.0);
        if tcp_result.is_err() || tcp_result.as_ref().ok().map(|r| r.is_err()).unwrap_or(true) {
            return BandwidthSample {
                ts,
                round,
                attempt,
                target: target.domain.clone(),
                ip: ip_str,
                port: target.port,
                dns_ms,
                tcp_ms,
                ttfb_ms: None,
                transfer_ms: None,
                total_ms: started.elapsed().as_secs_f64() * 1000.0,
                bytes: 0,
                throughput_mbps: 0.0,
                http_status: None,
                server: None,
                via: None,
                content_encoding: None,
                accept_ranges: None,
                range_ok: false,
                error: Some(if tcp_result.is_err() { "tcp_timeout".into() } else { "tcp_err".into() }),
            };
        }

        // 3. HTTP GET with Range header
        let scheme = if target.port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, target.domain, target.port);
        let req = self
            .http_client
            .get(&url)
            .header(reqwest::header::RANGE, format!("bytes=0-{}", self.cfg.bytes_per_target.saturating_sub(1)));
        let req_start = Instant::now();
        let resp = match timeout(Duration::from_secs(self.cfg.timeout_secs.max(1)), req.send()).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("http error for {}: {}", target_str, e);
                let cat = classify_reqwest_error(&e);
                return BandwidthSample {
                    ts,
                    round,
                    attempt,
                    target: target.domain.clone(),
                    ip: ip_str,
                    port: target.port,
                    dns_ms,
                    tcp_ms,
                    ttfb_ms: None,
                    transfer_ms: None,
                    total_ms: started.elapsed().as_secs_f64() * 1000.0,
                    bytes: 0,
                    throughput_mbps: 0.0,
                    http_status: None,
                    server: None,
                    via: None,
                    content_encoding: None,
                    accept_ranges: None,
                    range_ok: false,
                    error: Some(cat),
                };
            }
            Err(_) => {
                return BandwidthSample {
                    ts,
                    round,
                    attempt,
                    target: target.domain.clone(),
                    ip: ip_str,
                    port: target.port,
                    dns_ms,
                    tcp_ms,
                    ttfb_ms: None,
                    transfer_ms: None,
                    total_ms: started.elapsed().as_secs_f64() * 1000.0,
                    bytes: 0,
                    throughput_mbps: 0.0,
                    http_status: None,
                    server: None,
                    via: None,
                    content_encoding: None,
                    accept_ranges: None,
                    range_ok: false,
                    error: Some("http_err".into()),
                };
            }
        };
        let ttfb_ms = req_start.elapsed().as_secs_f64() * 1000.0;

        let http_status = resp.status().as_u16();
        let server = header_str(resp.headers().get(reqwest::header::SERVER));
        let via = header_str(resp.headers().get(reqwest::header::VIA));
        let content_encoding = header_str(resp.headers().get(reqwest::header::CONTENT_ENCODING));
        let accept_ranges = header_str(resp.headers().get(reqwest::header::ACCEPT_RANGES));
        let content_range = header_str(resp.headers().get(reqwest::header::CONTENT_RANGE));
        let content_length = header_u64(resp.headers().get(reqwest::header::CONTENT_LENGTH));
        // A real ranged response: 206 Partial Content OR a `Content-Range`
        // header echoed back by the server. We also accept a 200 OK with
        // a sizeable body (≥ 64 KiB) — most CDNs ignore `Range:` and return
        // the full page; that body is still long enough for a meaningful
        // throughput number, just measured over a smaller-than-requested
        // window. Below that, we mark `small_body` so it never counts
        // toward the stability rule.
        let mut range_ok = http_status == 206 || content_range.is_some();

        // 4. Stream body chunks; measure transfer time and accumulate bytes.
        let mut bytes: u64 = 0;
        let transfer_start = Instant::now();
        let mut resp = resp;
        let mut body_class: Option<String> = None;
        loop {
            match timeout(
                Duration::from_secs(self.cfg.timeout_secs.max(1)),
                resp.chunk(),
            )
            .await
            {
                Ok(Ok(Some(chunk))) => {
                    bytes = bytes.saturating_add(chunk.len() as u64);
                    if bytes >= self.cfg.bytes_per_target {
                        break;
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    debug!("body read error for {}: {}", target_str, e);
                    break;
                }
                Err(_) => break,
            }
        }
        let transfer_ms = transfer_start.elapsed().as_secs_f64() * 1000.0;

        // Honour Content-Length if the server told us the actual size
        // (the chunked transfer may have stopped early).
        if bytes == 0 {
            if let Some(cl) = content_length {
                bytes = cl;
            }
        }

        let throughput_mbps = if transfer_ms > 0.0 {
            (bytes as f64) * 8.0 / transfer_ms / 1000.0
        } else {
            0.0
        };

        // Promote range_ok once we know the actual body size: 200 OK with
        // ≥ 64 KiB is acceptable even without 206.
        if !range_ok && http_status == 200 && bytes >= 64 * 1024 {
            range_ok = true;
        }

        // Classify samples that did not yield a usable bandwidth number.
        if bytes < 64 * 1024 {
            if http_status == 403 || http_status == 401 {
                body_class = Some("blocked".into());
            } else if http_status == 429 || http_status == 503 {
                body_class = Some("rate_limited".into());
            } else if !range_ok {
                body_class = Some("small_body".into());
            }
        }

        let error = body_class.or_else(|| {
            if http_status == 429 || http_status == 503 {
                Some("rate_limited".into())
            } else {
                None
            }
        });

        BandwidthSample {
            ts,
            round,
            attempt,
            target: target.domain.clone(),
            ip: ip_str,
            port: target.port,
            dns_ms,
            tcp_ms,
            ttfb_ms: Some(ttfb_ms),
            transfer_ms: Some(transfer_ms),
            total_ms: started.elapsed().as_secs_f64() * 1000.0,
            bytes,
            throughput_mbps,
            http_status: Some(http_status),
            server,
            via,
            content_encoding,
            accept_ranges,
            range_ok,
            error,
        }
    }
}

fn header_str(h: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    h.and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn header_u64(h: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    h.and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn classify_reqwest_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "http_timeout".into()
    } else if e.is_connect() {
        "tcp_err".into()
    } else if e.is_request() {
        "http_err".into()
    } else {
        "http_err".into()
    }
}

/// Per-round rollups used by the stability rule.
#[derive(Debug, Clone, Default)]
pub struct RoundStats {
    pub median_throughput_mbps: f64,
    pub median_rtt_ms: f64,
    pub success_rate: f64,
    pub ok_count: usize,
    pub total_count: usize,
    pub cv_throughput: f64,
    pub cv_rtt: f64,
    pub cv_window: usize,
}

/// Compute aggregate stats across the most recent rounds. The CVs use
/// the per-round medians as their sample points (so they answer
/// "did the network settle round-over-round?", not "did individual
/// targets vary?").
pub fn compute_round_stats(all_rounds: &[Vec<BandwidthSample>]) -> RoundStats {
    if all_rounds.is_empty() {
        return RoundStats::default();
    }

    let window = all_rounds.len().min(3);
    let recent = &all_rounds[all_rounds.len() - window..];

    // Per-round median throughput / RTT, computed from `is_ok` samples only.
    let mut per_round_throughput: Vec<f64> = Vec::with_capacity(recent.len());
    let mut per_round_rtt: Vec<f64> = Vec::with_capacity(recent.len());
    let mut ok_total = 0usize;
    let mut total = 0usize;
    for round in recent {
        let mut tps = Vec::new();
        let mut rtts = Vec::new();
        for s in round {
            total += 1;
            if s.is_ok() {
                ok_total += 1;
                tps.push(s.throughput_mbps);
                if let Some(r) = s.rtt_ms() {
                    rtts.push(r);
                }
            }
        }
        per_round_throughput.push(median(&mut tps));
        per_round_rtt.push(median(&mut rtts));
    }

    let last = recent.last().unwrap();
    let ok_in_last = last.iter().filter(|s| s.is_ok()).count();
    let total_in_last = last.len().max(1);

    RoundStats {
        median_throughput_mbps: per_round_throughput.last().copied().unwrap_or(0.0),
        median_rtt_ms: per_round_rtt.last().copied().unwrap_or(0.0),
        success_rate: ok_in_last as f64 / total_in_last as f64,
        ok_count: ok_total,
        total_count: total,
        cv_throughput: coefficient_of_variation(&per_round_throughput),
        cv_rtt: coefficient_of_variation(&per_round_rtt),
        cv_window: window,
    }
}

fn median(xs: &mut Vec<f64>) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = xs.len() / 2;
    if xs.len() % 2 == 0 {
        (xs[mid - 1] + xs[mid]) / 2.0
    } else {
        xs[mid]
    }
}

fn coefficient_of_variation(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let mean = xs.iter().sum::<f64>() / xs.len() as f64;
    if mean.abs() < 1e-9 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len() as f64;
    (var.sqrt() / mean).abs()
}

/// Per-domain rollup used by the Markdown summary writer. Aggregates
/// samples grouped by target.
#[derive(Debug, Clone, Serialize)]
pub struct DomainSummary {
    pub target: String,
    pub category: String,
    pub n: usize,
    pub ok_pct: f64,
    pub dns_p50_ms: f64,
    pub tcp_p50_ms: f64,
    pub ttfb_p50_ms: f64,
    pub transfer_p50_ms: f64,
    pub throughput_mean_mbps: f64,
    pub throughput_p50_mbps: f64,
    pub throughput_p95_mbps: f64,
    pub status: String,
}

pub fn summarize_per_domain(samples: &[BandwidthSample]) -> Vec<DomainSummary> {
    let mut groups: HashMap<String, Vec<&BandwidthSample>> = HashMap::new();
    for s in samples {
        groups.entry(s.target.clone()).or_default().push(s);
    }
    let mut out: Vec<DomainSummary> = groups
        .into_iter()
        .map(|(target, list)| {
            let n = list.len();
            let ok = list.iter().filter(|s| s.is_ok()).count();
            let mut dns = collect_field(&list, |s| s.dns_ms);
            let mut tcp = collect_field(&list, |s| s.tcp_ms);
            let mut ttfb = collect_field(&list, |s| s.ttfb_ms);
            let mut xfer = collect_field(&list, |s| s.transfer_ms);
            let mut tps: Vec<f64> = list
                .iter()
                .filter(|s| s.is_ok())
                .map(|s| s.throughput_mbps)
                .collect();
            let status = if n > 0 && ok * 100 / n == 100 {
                "ok".into()
            } else if ok == 0 {
                list.first()
                    .and_then(|s| s.error.clone())
                    .unwrap_or_else(|| "fail".into())
            } else {
                "partial".into()
            };
            DomainSummary {
                target,
                category: String::new(),
                n,
                ok_pct: if n == 0 { 0.0 } else { ok as f64 * 100.0 / n as f64 },
                dns_p50_ms: median(&mut dns),
                tcp_p50_ms: median(&mut tcp),
                ttfb_p50_ms: median(&mut ttfb),
                transfer_p50_ms: median(&mut xfer),
                throughput_mean_mbps: if tps.is_empty() {
                    0.0
                } else {
                    tps.iter().sum::<f64>() / tps.len() as f64
                },
                throughput_p50_mbps: median(&mut tps),
                throughput_p95_mbps: percentile(&mut tps, 0.95),
                status,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.throughput_mean_mbps
            .partial_cmp(&a.throughput_mean_mbps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn collect_field<F>(list: &[&BandwidthSample], f: F) -> Vec<f64>
where
    F: Fn(&BandwidthSample) -> Option<f64>,
{
    list.iter().filter_map(|s| f(s)).collect()
}

fn percentile(xs: &mut Vec<f64>, p: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((xs.len() as f64 - 1.0) * p).round() as usize;
    xs[idx.min(xs.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(target: &str, tp: f64, ok: bool) -> BandwidthSample {
        BandwidthSample {
            ts: "2026-08-22T00:00:00Z".into(),
            round: 1,
            attempt: 0,
            target: target.into(),
            ip: None,
            port: 443,
            dns_ms: Some(2.0),
            tcp_ms: Some(8.0),
            ttfb_ms: Some(40.0),
            transfer_ms: Some(100.0),
            total_ms: 150.0,
            bytes: if ok { 1024 * 1024 } else { 0 },
            throughput_mbps: tp,
            http_status: if ok { Some(206) } else { Some(403) },
            server: None,
            via: None,
            content_encoding: None,
            accept_ranges: Some("bytes".into()),
            range_ok: ok,
            error: if ok { None } else { Some("waf_challenge".into()) },
        }
    }

    #[test]
    fn coefficient_of_variation_zero_for_identical() {
        let v = vec![100.0, 100.0, 100.0];
        assert!(coefficient_of_variation(&v) < 1e-9);
    }

    #[test]
    fn coefficient_of_variation_matches_formula() {
        let v = vec![10.0_f64, 12.0_f64, 14.0_f64];
        let mean: f64 = 12.0_f64;
        let diffs: [f64; 3] = [10.0_f64 - 12.0_f64, 12.0_f64 - 12.0_f64, 14.0_f64 - 12.0_f64];
        let var: f64 = diffs.iter().map(|d| d.powi(2)).sum::<f64>() / 3.0_f64;
        let expected = var.sqrt() / mean;
        let got = coefficient_of_variation(&v);
        assert!((got - expected).abs() < 1e-9);
    }

    #[test]
    fn median_even_and_odd() {
        let mut odd = vec![3.0, 1.0, 2.0];
        assert_eq!(median(&mut odd), 2.0);
        let mut even = vec![4.0, 1.0, 3.0, 2.0];
        assert_eq!(median(&mut even), 2.5);
    }

    #[test]
    fn is_ok_requires_range_ok_and_throughput() {
        let good = sample("a", 50.0, true);
        assert!(good.is_ok());
        let bad = sample("a", 0.0, false);
        assert!(!bad.is_ok());
    }

    #[test]
    fn round_stats_aggregates_recent_rounds() {
        let r1 = vec![sample("a", 50.0, true), sample("b", 60.0, true)];
        let r2 = vec![sample("a", 51.0, true), sample("b", 59.0, true)];
        let r3 = vec![sample("a", 50.5, true), sample("b", 60.5, true)];
        let stats = compute_round_stats(&[r1, r2, r3]);
        assert_eq!(stats.cv_window, 3);
        assert!(stats.success_rate > 0.99);
        assert!(stats.cv_throughput < 0.05);
    }

    #[test]
    fn summarize_groups_by_target() {
        let v = vec![
            sample("a", 50.0, true),
            sample("a", 60.0, true),
            sample("b", 10.0, false),
        ];
        let s = summarize_per_domain(&v);
        assert_eq!(s.len(), 2);
        let a = s.iter().find(|x| x.target == "a").unwrap();
        assert_eq!(a.n, 2);
        assert_eq!(a.ok_pct, 100.0);
        let b = s.iter().find(|x| x.target == "b").unwrap();
        assert_eq!(b.ok_pct, 0.0);
        assert_eq!(b.status, "waf_challenge");
    }

}
