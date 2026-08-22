//! Report writers for `ip-scan --bench-bandwidth`.
//!
//! Three output formats, all driven from the same
//! `Vec<BandwidthSample>` collected across rounds:
//!
//! - **JSONL** (gzip-compressed per round, plus one combined CSV)
//!   — append-only, downstream pipelines.
//! - **CSV** — flat table matching the JSONL column order.
//! - **Markdown** — per-domain rollup (mean/p50/p95, ok%), the
//!   human-readable summary the user reads after a run.
//!
//! The writers are pure functions: callers decide where to put the
//! files and when to call them.

pub mod report;

pub use report::{
    load_bandwidth_samples_for_domain, write_bandwidth_csv, write_bandwidth_jsonl,
    write_bandwidth_markdown_summary,
};
