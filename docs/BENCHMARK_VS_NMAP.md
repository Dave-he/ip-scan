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

### `1-1024`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.525 | 48,463,872 | 0 |
| ip-scan | 2 | 4.611 | 48,566,272 | 0 |
| ip-scan | 3 | 4.946 | 46,010,368 | 0 |
| nmap | 1 | 201.620 | 7,602,176 | 0 |
| nmap | 2 | 201.785 | 7,618,560 | 0 |
| nmap | 3 | 104.493 | 7,585,792 | 0 |

**median** ip-scan = 4.611s, nmap = 201.620s → **43.7× faster**

### `top100`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 2.978 | 30,957,568 | 5 |
| ip-scan | 2 | 1.043 | 12,136,448 | 0 |
| ip-scan | 3 | 0.678 | 12,165,120 | 0 |
| nmap | 1 | 104.962 | 6,647,808 | 0 |
| nmap | 2 | 77.875 | 6,660,096 | 0 |
| nmap | 3 | 168.877 | 6,696,960 | 0 |

**median** ip-scan = 1.043s, nmap = 104.962s → **100.6× faster**

### `top1000`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.475 | 47,280,128 | 0 |
| ip-scan | 2 | 4.439 | 49,434,624 | 0 |
| ip-scan | 3 | 4.424 | 46,350,336 | 0 |
| nmap | 1 | 176.796 | 7,614,464 | 0 |
| nmap | 2 | 77.278 | 7,643,136 | 0 |
| nmap | 3 | 88.524 | 7,647,232 | 0 |

**median** ip-scan = 4.439s, nmap = 88.524s → **19.9× faster**

## Overall summary

| scenario | ip-scan p50 (s) | nmap p50 (s) | speedup |
|----------|----------------:|-------------:|--------:|
| `1-1024` | 4.611 | 201.620 | **43.7×** |
| `top100` | 1.043 | 104.962 | **100.6×** |
| `top1000` | 4.439 | 88.524 | **19.9×** |

**Geometric mean speedup across all scenarios: 44.4×**

## How to reproduce

```bash
cargo build --release
./bench/run.sh 3        # 3 trials per scenario
python3 bench/report.py
```

Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.
