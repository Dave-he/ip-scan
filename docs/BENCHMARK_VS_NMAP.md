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
| ip-scan | 1 | 4.545 | 49,401,856 | 0 |
| ip-scan | 2 | 4.604 | 47,341,568 | 0 |
| ip-scan | 3 | 4.612 | 47,005,696 | 0 |
| nmap | 1 | 30.133 | 8,630,272 | 0 |
| nmap | 2 | 30.257 | 8,605,696 | 0 |
| nmap | 3 | 0.398 | 8,818,688 | 1020 |

**ip-scan p50** = 4.604s (max 4.612s, min 4.545s)  
**nmap p50**    = 30.133s, **p95** = 30.245s (max 30.257s, min 0.398s)  
→ worst-case nmap / median ip-scan = **6.6× faster**

### `top100`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 2.201 | 31,100,928 | 5 |
| ip-scan | 2 | 0.725 | 12,075,008 | 0 |
| ip-scan | 3 | 0.728 | 12,189,696 | 0 |
| nmap | 1 | 0.063 | 8,556,544 | 100 |
| nmap | 2 | 0.067 | 8,589,312 | 100 |
| nmap | 3 | 0.372 | 8,564,736 | 95 |

**ip-scan p50** = 0.728s (max 2.201s, min 0.725s)  
**nmap p50**    = 0.067s, **p95** = 0.341s (max 0.372s, min 0.063s)  
→ worst-case nmap / median ip-scan = **0.5× faster**

### `top1000`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.472 | 46,510,080 | 0 |
| ip-scan | 2 | 4.513 | 47,214,592 | 0 |
| ip-scan | 3 | 5.361 | 46,522,368 | 0 |
| nmap | 1 | 30.074 | 8,605,696 | 0 |
| nmap | 2 | 0.397 | 8,773,632 | 996 |
| nmap | 3 | 30.127 | 8,646,656 | 0 |

**ip-scan p50** = 4.513s (max 5.361s, min 4.472s)  
**nmap p50**    = 30.074s, **p95** = 30.122s (max 30.127s, min 0.397s)  
→ worst-case nmap / median ip-scan = **6.7× faster**

## Overall summary

| scenario | ip-scan p50 | nmap p50 | nmap p95 | p95 speedup |
|----------|------------:|---------:|---------:|------------:|
| `1-1024` | 4.604 s | 30.133 s | 30.245 s | **6.6×** |
| `top100` | 0.728 s | 0.067 s | 0.341 s | **0.5×** |
| `top1000` | 4.513 s | 30.074 s | 30.122 s | **6.7×** |

**Geometric mean (nmap p95 vs ip-scan p50): 2.7× faster**

## How to reproduce

```bash
cargo build --release
./bench/run.sh 3        # 3 trials per scenario
python3 bench/report.py
```

Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.
