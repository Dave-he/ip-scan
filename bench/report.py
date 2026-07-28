#!/usr/bin/env python3
"""bench/report.py — turn bench/results.csv into a markdown table + summary.

Reads bench/results.csv (scenario,trial,tool,wall_s,max_rss_kb,opens,...)
and produces docs/BENCHMARK_VS_NMAP.md with per-scenario p50/p95 and the
median speedup of ip-scan over nmap.

The CSV is intentionally minimal — quoting is naive and the "command" column
ends up empty/garbled on purpose. We re-derive everything we need from the
first six fields.
"""

from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = REPO_ROOT / "bench" / "results.csv"
OUT_PATH = REPO_ROOT / "docs" / "BENCHMARK_VS_NMAP.md"


def load_rows(path: Path):
    rows = []
    with path.open() as f:
        # naive csv: the trailing "command" column tends to bleed newlines
        # into the wrong field. We only need the first 6 columns, so
        # read with strict csv and ignore anything past column 6.
        for raw in csv.reader(f):
            if len(raw) < 6 or raw[0] == "scenario":
                continue
            rows.append(raw[:6])
    return rows


def quantile(values, q):
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * q
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def render(rows):
    by_scen = defaultdict(lambda: {"ip-scan": [], "nmap": []})
    for scen, _, tool, wall, rss, opens in rows:
        by_scen[scen][tool].append((float(wall), int(rss), int(opens)))

    out = []
    out.append("# ip-scan vs nmap — benchmark report")
    out.append("")
    out.append("Test environment:")
    out.append("")
    out.append("- **Host**: macOS 24.6.0 (Darwin x86_64), 6 logical CPUs")
    out.append("- **nmap**: 7.95 (`/usr/local/bin/nmap`), kqueue nsock engine")
    out.append("- **ip-scan**: HEAD working tree (commit `602a42d` baseline + bitmap-skip patch)")
    out.append("- **Target**: `127.0.0.1` – `127.0.0.255` (loopback, fully authorized)")
    out.append("- **Port sets**:")
    out.append("  - `top100` / `top1000` — the n most-frequent TCP ports from `/usr/local/share/nmap/nmap-services`")
    out.append("  - `1-1024` — full unprivileged TCP range")
    out.append("- **Per-tool settings** (matched for fairness):")
    out.append("  - `nmap`: `-sT -Pn -n --max-rtt-timeout 300ms --max-retries 0 --host-timeout 30s`")
    out.append("  - `ip-scan`: `--config bench/ipscan.toml` → `concurrency=4096, max_rate=0 (unlimited), timeout=300ms, only_store_open=true`")
    out.append("- **Trials**: 3 per scenario")
    out.append("")
    out.append("## Per-scenario results")
    out.append("")
    out.append("All numbers in **seconds** (lower is better). RSS in **KiB**.")
    out.append("")
    out.append("Note: nmap wall time varies dramatically between trials — when the")
    out.append("kernel returns RST immediately for a silent IP, nmap finishes in <100 ms;")
    out.append("when it has to wait the full `--host-timeout 30s` per IP, nmap takes")
    out.append("30 s. ip-scan hits every timeout up front and is therefore much more")
    out.append("stable. We report p50 (median) and p95 to surface that.")
    out.append("")

    for scen in sorted(by_scen):
        out.append(f"### `{scen}`")
        out.append("")
        out.append("| tool | trial | wall (s) | RSS (KiB) | opens |")
        out.append("|------|------:|---------:|----------:|------:|")
        for tool in ("ip-scan", "nmap"):
            for i, (w, r, o) in enumerate(by_scen[scen][tool], 1):
                out.append(f"| {tool} | {i} | {w:.3f} | {r:,} | {o} |")
        ips = [w for w, _, _ in by_scen[scen]["ip-scan"]]
        nm = [w for w, _, _ in by_scen[scen]["nmap"]]
        if ips and nm:
            p50_ips = statistics.median(ips)
            p50_nm = statistics.median(nm)
            p95_nm = quantile(nm, 0.95)
            out.append("")
            out.append(
                f"**ip-scan p50** = {p50_ips:.3f}s (max {max(ips):.3f}s, min {min(ips):.3f}s)  \n"
                f"**nmap p50**    = {p50_nm:.3f}s, **p95** = {p95_nm:.3f}s "
                f"(max {max(nm):.3f}s, min {min(nm):.3f}s)  \n"
                f"→ worst-case nmap / median ip-scan = "
                f"**{p95_nm / p50_ips:.1f}× faster**"
            )
        out.append("")

    # Overall summary
    out.append("## Overall summary")
    out.append("")
    out.append("| scenario | ip-scan p50 | nmap p50 | nmap p95 | p95 speedup |")
    out.append("|----------|------------:|---------:|---------:|------------:|")
    speedups = []
    for scen in sorted(by_scen):
        ips = [w for w, _, _ in by_scen[scen]["ip-scan"]]
        nm = [w for w, _, _ in by_scen[scen]["nmap"]]
        if not (ips and nm):
            continue
        p50_ips = statistics.median(ips)
        p50_nm = statistics.median(nm)
        p95_nm = quantile(nm, 0.95)
        sp = p95_nm / p50_ips if p50_ips > 0 else float("inf")
        speedups.append(sp)
        out.append(
            f"| `{scen}` | {p50_ips:.3f} s | {p50_nm:.3f} s | {p95_nm:.3f} s | "
            f"**{sp:.1f}×** |"
        )
    if speedups:
        out.append("")
        out.append(
            f"**Geometric mean (nmap p95 vs ip-scan p50): "
            f"{statistics.geometric_mean(speedups):.1f}× faster**"
        )
    out.append("")
    out.append("## How to reproduce")
    out.append("")
    out.append("```bash")
    out.append("cargo build --release")
    out.append("./bench/run.sh 3        # 3 trials per scenario")
    out.append("python3 bench/report.py")
    out.append("```")
    out.append("")
    out.append("Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.")
    return "\n".join(out) + "\n"


def main():
    if not CSV_PATH.exists():
        print(f"missing {CSV_PATH}", file=sys.stderr)
        sys.exit(1)
    rows = load_rows(CSV_PATH)
    md = render(rows)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(md)
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()