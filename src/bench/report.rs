//! Concrete report writers for `--bench-bandwidth`.

use crate::model::BandwidthSample;
use crate::service::summarize_per_domain;
use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// CSV column order — keep in lock-step with the JSONL serialised
/// shape (`BandwidthSample` `serde_derive`). Stable for downstream
/// tools; **do not reorder**.
const CSV_COLUMNS: &[&str] = &[
    "ts",
    "round",
    "attempt",
    "target",
    "ip",
    "port",
    "dns_ms",
    "tcp_ms",
    "ttfb_ms",
    "transfer_ms",
    "total_ms",
    "bytes",
    "throughput_mbps",
    "http_status",
    "server",
    "via",
    "content_encoding",
    "accept_ranges",
    "range_ok",
    "error",
    "node_id",
];

/// Append-mode writer for one round's samples. Compresses with gzip
/// (`bench-r{N}.jsonl.gz`) so a 1000-site round takes ~200 KB
/// instead of ~5 MB.
pub fn write_bandwidth_jsonl(
    path: &Path,
    samples: &[BandwidthSample],
    node_id: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = GzEncoder::new(BufWriter::new(file), Compression::default());
    for s in samples {
        let mut v = serde_json::to_value(s)?;
        if let Some(obj) = v.as_object_mut() {
            obj.insert("node_id".into(), serde_json::Value::String(node_id.into()));
        }
        serde_json::to_writer(&mut writer, &v)?;
        writer.write_all(b"\n")?;
    }
    writer.finish()?;
    Ok(())
}

/// Write the combined CSV (header line + one row per sample).
/// Used as the canonical artefact for downstream consumers.
pub fn write_bandwidth_csv(
    path: &Path,
    samples: &[BandwidthSample],
    node_id: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = BufWriter::new(File::create(path)?);
    writeln!(f, "{}", CSV_COLUMNS.join(","))?;
    for s in samples {
        write_csv_row(&mut f, s, node_id)?;
    }
    Ok(())
}

/// Load back the per-round JSONL.gz files we previously wrote. Used
/// by tests and the summary writer. Errors on missing file or
/// malformed rows.
pub fn load_bandwidth_samples_for_domain(path: &Path) -> Result<Vec<BandwidthSample>> {
    use std::io::BufRead;
    let file = File::open(path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let reader = std::io::BufReader::new(decoder);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let s: BandwidthSample = serde_json::from_str(&line)?;
        out.push(s);
    }
    Ok(out)
}

/// Write the Markdown per-domain rollup. Sorted by mean throughput
/// descending.
pub fn write_bandwidth_markdown_summary(
    path: &Path,
    samples: &[BandwidthSample],
    title: &str,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let summaries = summarize_per_domain(samples);
    let mut f = BufWriter::new(File::create(path)?);
    writeln!(f, "# {}\n", title)?;
    writeln!(f, "Total samples: {}\n", samples.len())?;
    writeln!(
        f,
        "| target | n | ok% | dns p50 | tcp p50 | ttfb p50 | xfer p50 | tp mean | tp p50 | tp p95 | status |"
    )?;
    writeln!(
        f,
        "|--------|---|-----|---------|---------|----------|----------|---------|--------|--------|--------|"
    )?;
    for s in &summaries {
        writeln!(
            f,
            "| {} | {} | {:.0}% | {:.1} | {:.1} | {:.1} | {:.1} | {:.2} | {:.2} | {:.2} | {} |",
            escape_md(&s.target),
            s.n,
            s.ok_pct,
            s.dns_p50_ms,
            s.tcp_p50_ms,
            s.ttfb_p50_ms,
            s.transfer_p50_ms,
            s.throughput_mean_mbps,
            s.throughput_p50_mbps,
            s.throughput_p95_mbps,
            s.status,
        )?;
    }
    Ok(())
}

fn write_csv_row<W: Write>(f: &mut W, s: &BandwidthSample, node_id: &str) -> Result<()> {
    let cells: [String; CSV_COLUMNS.len()] = [
        s.ts.clone(),
        s.round.to_string(),
        s.attempt.to_string(),
        csv_field(&s.target),
        s.ip.clone().unwrap_or_default(),
        s.port.to_string(),
        fmt_opt(s.dns_ms),
        fmt_opt(s.tcp_ms),
        fmt_opt(s.ttfb_ms),
        fmt_opt(s.transfer_ms),
        format!("{:.3}", s.total_ms),
        s.bytes.to_string(),
        format!("{:.4}", s.throughput_mbps),
        s.http_status.map(|v| v.to_string()).unwrap_or_default(),
        csv_field(s.server.as_deref().unwrap_or("")),
        csv_field(s.via.as_deref().unwrap_or("")),
        csv_field(s.content_encoding.as_deref().unwrap_or("")),
        csv_field(s.accept_ranges.as_deref().unwrap_or("")),
        if s.range_ok { "1" } else { "0" }.into(),
        csv_field(s.error.as_deref().unwrap_or("")),
        csv_field(node_id),
    ];
    writeln!(f, "{}", cells.join(","))?;
    Ok(())
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map(|x| format!("{:.3}", x)).unwrap_or_default()
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BandwidthSample;

    fn sample(target: &str, tp: f64, ok: bool) -> BandwidthSample {
        BandwidthSample {
            ts: "2026-08-22T00:00:00Z".into(),
            round: 1,
            attempt: 0,
            target: target.into(),
            ip: Some("1.2.3.4".into()),
            port: 443,
            dns_ms: Some(2.0),
            tcp_ms: Some(8.0),
            ttfb_ms: Some(40.0),
            transfer_ms: Some(100.0),
            total_ms: 150.0,
            bytes: if ok { 1024 * 1024 } else { 0 },
            throughput_mbps: tp,
            http_status: if ok { Some(206) } else { Some(403) },
            server: Some("Tengine".into()),
            via: None,
            content_encoding: None,
            accept_ranges: Some("bytes".into()),
            range_ok: ok,
            error: if ok { None } else { Some("waf_challenge".into()) },
        }
    }

    #[test]
    fn csv_field_handles_special_chars() {
        assert_eq!(csv_field("hello"), "hello");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_round_trip_via_jsonl() {
        let tmp = std::env::temp_dir().join("ip_scan_bench_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let samples = vec![sample("a.com", 50.0, true), sample("b.com", 60.0, true)];
        let jsonl = tmp.join("round.jsonl.gz");
        write_bandwidth_jsonl(&jsonl, &samples, "node-x").unwrap();
        let loaded = load_bandwidth_samples_for_domain(&jsonl).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].target, "a.com");
        assert!((loaded[0].throughput_mbps - 50.0).abs() < 1e-9);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn markdown_summary_writes_table() {
        let tmp = std::env::temp_dir().join("ip_scan_bench_md_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let samples = vec![sample("a.com", 50.0, true), sample("b.com", 0.0, false)];
        let md = tmp.join("summary.md");
        write_bandwidth_markdown_summary(&md, &samples, "Test Run").unwrap();
        let content = std::fs::read_to_string(&md).unwrap();
        assert!(content.contains("a.com"));
        assert!(content.contains("b.com"));
        assert!(content.contains("Test Run"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
