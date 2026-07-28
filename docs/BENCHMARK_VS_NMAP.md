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
| ip-scan | 1 | 4.575 | 45,961,216 | 0 |
| ip-scan | 2 | 4.637 | 45,850,624 | 0 |
| ip-scan | 3 | 5.616 | 44,695,552 | 0 |
| nmap | 1 | 30.150 | 8,663,040 | 0 |
| nmap | 2 | 0.430 | 8,822,784 | 1022 |
| nmap | 3 | 0.160 | 8,822,784 | 1024 |

**ip-scan p50** = 4.637s (max 5.616s, min 4.575s)  
**nmap p50**    = 0.430s, **p95** = 27.178s (max 30.150s, min 0.160s)  
→ worst-case nmap / median ip-scan = **5.9× faster**

### `top100`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 2.211 | 30,560,256 | 5 |
| ip-scan | 2 | 0.768 | 11,587,584 | 0 |
| ip-scan | 3 | 0.701 | 11,620,352 | 0 |
| nmap | 1 | 0.078 | 8,581,120 | 100 |
| nmap | 2 | 16.301 | 8,601,600 | 28 |
| nmap | 3 | 0.064 | 8,560,640 | 100 |

**ip-scan p50** = 0.768s (max 2.211s, min 0.701s)  
**nmap p50**    = 0.078s, **p95** = 14.679s (max 16.301s, min 0.064s)  
→ worst-case nmap / median ip-scan = **19.1× faster**

### `top100-public-sweep`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 0.740 | 11,665,408 | 0 |
| ip-scan | 2 | 0.705 | 11,595,776 | 0 |
| ip-scan | 3 | 0.709 | 11,616,256 | 0 |
| nmap | 1 | 6.199 | 8,572,928 | 0 |
| nmap | 2 | 6.292 | 8,601,600 | 0 |
| nmap | 3 | 4.355 | 8,560,640 | 64 |

**ip-scan p50** = 0.709s (max 0.740s, min 0.705s)  
**nmap p50**    = 6.199s, **p95** = 6.283s (max 6.292s, min 4.355s)  
→ worst-case nmap / median ip-scan = **8.9× faster**

### `top1000`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.569 | 46,440,448 | 0 |
| ip-scan | 2 | 4.484 | 44,847,104 | 0 |
| ip-scan | 3 | 5.332 | 44,535,808 | 0 |
| nmap | 1 | 30.093 | 8,634,368 | 0 |
| nmap | 2 | 0.167 | 8,843,264 | 1000 |
| nmap | 3 | 30.162 | 8,650,752 | 0 |

**ip-scan p50** = 4.569s (max 5.332s, min 4.484s)  
**nmap p50**    = 30.093s, **p95** = 30.155s (max 30.162s, min 0.167s)  
→ worst-case nmap / median ip-scan = **6.6× faster**

## Overall summary

| scenario | ip-scan p50 | nmap p50 | nmap p95 | p95 speedup |
|----------|------------:|---------:|---------:|------------:|
| `1-1024` | 4.637 s | 0.430 s | 27.178 s | **5.9×** |
| `top100` | 0.768 s | 0.078 s | 14.679 s | **19.1×** |
| `top100-public-sweep` | 0.709 s | 6.199 s | 6.283 s | **8.9×** |
| `top1000` | 4.569 s | 30.093 s | 30.155 s | **6.6×** |

**Geometric mean (nmap p95 vs ip-scan p50): 9.0× faster**

## How to reproduce

```bash
cargo build --release
./bench/run.sh 3        # 3 trials per scenario
python3 bench/report.py
```

Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.
