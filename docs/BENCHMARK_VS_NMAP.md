# ip-scan vs nmap — benchmark report

Test environment:

- **Host**: macOS 24.6.0 (Darwin x86_64), 6 logical CPUs
- **nmap**: 7.95 (`/usr/local/bin/nmap`), kqueue nsock engine
- **ip-scan**: HEAD working tree (commit `602a42d` baseline + bitmap-skip patch)
- **Target**: `127.0.0.1` – `127.0.0.255` (loopback, fully authorized)
- **Port sets**:
  - `top100` / `top1000` — the n most-frequent TCP ports from `/usr/local/share/nmap/nmap-services`
  - `1-1024` — full unprivileged TCP range
- **Per-tool settings** (matched for fairness):
  - `nmap`: `-sT -Pn -n --max-rtt-timeout 300ms --max-retries 0 --host-timeout 30s`
  - `ip-scan`: `--config bench/ipscan.toml` → `concurrency=4096, max_rate=0 (unlimited), timeout=300ms, only_store_open=true`
- **Trials**: 3 per scenario

## Per-scenario results

All numbers in **seconds** (lower is better). RSS in **KiB**.

Note: nmap wall time varies dramatically between trials — when the
kernel returns RST immediately for a silent IP, nmap finishes in <100 ms;
when it has to wait the full `--host-timeout 30s` per IP, nmap takes
30 s. ip-scan hits every timeout up front and is therefore much more
stable. We report p50 (median) and p95 to surface that.

### `1-1024`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.533 | 44,400,640 | 0 |
| ip-scan | 2 | 5.260 | 46,399,488 | 0 |
| ip-scan | 3 | 4.657 | 45,654,016 | 0 |
| nmap | 1 | 0.155 | 8,806,400 | 1024 |
| nmap | 2 | 19.464 | 8,814,592 | 869 |
| nmap | 3 | 0.198 | 8,818,688 | 1024 |

**ip-scan p50** = 4.657s (max 5.260s, min 4.533s)  
**nmap p50**    = 0.198s, **p95** = 17.537s (max 19.464s, min 0.155s)  
→ worst-case nmap / median ip-scan = **3.8× faster**

### `top100`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 2.730 | 30,269,440 | 5 |
| ip-scan | 2 | 0.723 | 11,735,040 | 0 |
| ip-scan | 3 | 0.700 | 11,657,216 | 0 |
| nmap | 1 | 0.067 | 8,593,408 | 100 |
| nmap | 2 | 6.197 | 8,589,312 | 0 |
| nmap | 3 | 0.083 | 8,597,504 | 100 |

**ip-scan p50** = 0.723s (max 2.730s, min 0.700s)  
**nmap p50**    = 0.083s, **p95** = 5.586s (max 6.197s, min 0.067s)  
→ worst-case nmap / median ip-scan = **7.7× faster**

### `top1000`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.486 | 44,216,320 | 0 |
| ip-scan | 2 | 4.475 | 46,178,304 | 0 |
| ip-scan | 3 | 4.530 | 45,723,648 | 0 |
| nmap | 1 | 30.100 | 8,581,120 | 0 |
| nmap | 2 | 17.715 | 8,814,592 | 749 |
| nmap | 3 | 30.188 | 8,622,080 | 0 |

**ip-scan p50** = 4.486s (max 4.530s, min 4.475s)  
**nmap p50**    = 30.100s, **p95** = 30.179s (max 30.188s, min 17.715s)  
→ worst-case nmap / median ip-scan = **6.7× faster**

## Overall summary

| scenario | ip-scan p50 | nmap p50 | nmap p95 | p95 speedup |
|----------|------------:|---------:|---------:|------------:|
| `1-1024` | 4.657 s | 0.198 s | 17.537 s | **3.8×** |
| `top100` | 0.723 s | 0.083 s | 5.586 s | **7.7×** |
| `top1000` | 4.486 s | 30.100 s | 30.179 s | **6.7×** |

**Geometric mean (nmap p95 vs ip-scan p50): 5.8× faster**

## How to reproduce

```bash
cargo build --release
./bench/run.sh 3        # 3 trials per scenario
python3 bench/report.py
```

Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.
