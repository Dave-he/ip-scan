//! Throughput benchmark for the bandwidth-saturating RawScanner.
//!
//! Run with: `cargo test --release --test bench_raw -- --nocapture`
//!
//! This is the loop the `/goal` optimisation uses to drive the scanner
//! toward the physical ceiling. The test prints a pps number; you then
//! read the source, find the dominant cost, fix it, and re-run. Each
//! round of this loop is a measurable step on the way to the limit.
//!
//! The benchmark intentionally scans the loopback /16 (65 024 IPs) so
//! the syscall overhead — not network latency — is the bottleneck. On
//! a modern CPU that lets us measure the *per-connect* floor of the
//! scanner, which is the upper bound for any real network where
//! RTT > 0 adds to (not replaces) this cost.
//!
//! To measure against a real network, override the target via the
//! `BENCH_TARGET` and `BENCH_PORTS` env vars.

use std::net::TcpListener;
use std::time::Duration;

use ip_scan::dao::SqliteDB;
use ip_scan::model::IpRange;
use ip_scan::service::{RawScanner, RawScannerConfig};

fn parse_env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn temp_listener() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    // Keep the listener alive for the test by leaking it; the OS
    // reaps the socket when the test process exits.
    Box::leak(Box::new(l));
    p
}

fn parse_port_list(s: &str) -> Vec<u16> {
    s.split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .collect()
}

fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[test]
fn bench_loopback_full() {
    let target = parse_env("BENCH_TARGET", "127.0.0.0/16");
    let ports_str = parse_env("BENCH_PORTS", "22,80,443");
    let workers: usize = parse_env("BENCH_WORKERS", "4").parse().unwrap_or(4);
    let inflight: usize = parse_env("BENCH_INFLIGHT", "4096").parse().unwrap_or(4096);
    let timeout_ms: u64 = parse_env("BENCH_TIMEOUT_MS", "200").parse().unwrap_or(200);

    // Pick one open port + several closed ports so the open-pps is
    // a real signal, not just "everything was ECONNREFUSED".
    let open = temp_listener();
    let closed: Vec<u16> = (0..6).map(|_| closed_port()).collect();
    let mut ports = vec![open];
    ports.extend(closed);
    ports.extend(parse_port_list(&ports_str));
    ports.sort();
    ports.dedup();

    let range = IpRange::parse_target(&target).expect("valid target");
    let total_ips = range.count();
    let total_probes = total_ips * ports.len();

    eprintln!(
        "[bench] target={} ips={} ports={} probes={} workers={} inflight/worker={}",
        target,
        total_ips,
        ports.len(),
        total_probes,
        workers,
        inflight,
    );

    let db = SqliteDB::new(":memory:").expect("in-mem db");
    let cfg = RawScannerConfig {
        timeout_ms,
        num_workers: workers,
        max_inflight_per_worker: inflight,
        result_buffer: 1 << 18,
        db_batch_size: 32_768,
        flush_interval_ms: 200,
        max_rate: 0, // unlimited
        rate_window_secs: 1,
        shuffle: true,
    };
    let scanner = RawScanner::new(db, 1, cfg);
    let report = scanner.bench(range, &ports).expect("bench should succeed");

    report.print();
    eprintln!(
        "[bench] per-syscall cost = {:.2} µs (lower = closer to physical limit)",
        report.elapsed.as_micros() as f64 / report.scanned as f64
    );

    // Always assert: at least one probe ran and the result is plausible.
    assert!(report.scanned > 0, "scanner reported 0 probes");
    // Sanity: the run should not be unreasonably slow. A full /16 sweep
    // on loopback should finish in well under 60 s on any reasonable
    // machine. If it takes longer, something is broken.
    assert!(
        report.elapsed < Duration::from_secs(120),
        "bench took {} — scanner is too slow",
        report.elapsed.as_secs_f64()
    );
}
