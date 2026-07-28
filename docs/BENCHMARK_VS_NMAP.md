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
  - `ip-scan`: `--config bench/ipscan.toml` → `concurrency=4096, max_rate=1_000_000, timeout=300ms, only_store_open=true`
- **Trials**: 3 per scenario

## Per-scenario results

All numbers in **seconds** (lower is better). RSS in **KiB**.

### `1-1024`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.517 | 26,451,968 | 0 |
| ip-scan | 2 | 88.280 | 25,083,904 | 0 |
| ip-scan | 3 | 5.225 | 26,755,072 | 0 |
| nmap | 1 | 154.285 | 7,602,176 | 0 |
| nmap | 2 | 122.698 | 7,614,464 | 0 |
| nmap | 3 | 128.629 | 7,593,984 | 0 |

**median** ip-scan = 5.225s, nmap = 128.629s → **24.6× faster**

### `top100`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 3.426 | 24,690,688 | 5 |
| ip-scan | 2 | 1.768 | 11,350,016 | 0 |
| ip-scan | 3 | 0.709 | 11,419,648 | 0 |
| nmap | 1 | 77.813 | 6,692,864 | 0 |
| nmap | 2 | 74.713 | 6,688,768 | 0 |
| nmap | 3 | 74.254 | 6,680,576 | 0 |

**median** ip-scan = 1.768s, nmap = 74.713s → **42.3× faster**

### `top1000`

| tool | trial | wall (s) | RSS (KiB) | opens |
|------|------:|---------:|----------:|------:|
| ip-scan | 1 | 4.490 | 26,464,256 | 0 |
| ip-scan | 2 | 5.694 | 26,779,648 | 0 |
| ip-scan | 3 | 5.061 | 26,361,856 | 0 |
| nmap | 1 | 117.000 | 7,651,328 | 0 |
| nmap | 2 | 88.659 | 7,622,656 | 0 |
| nmap | 3 | 172.641 | 7,630,848 | 0 |

**median** ip-scan = 5.061s, nmap = 117.000s → **23.1× faster**

## Overall summary

| scenario | ip-scan p50 (s) | nmap p50 (s) | speedup |
|----------|----------------:|-------------:|--------:|
| `1-1024` | 5.225 | 128.629 | **24.6×** |
| `top100` | 1.768 | 74.713 | **42.3×** |
| `top1000` | 5.061 | 117.000 | **23.1×** |

**Geometric mean speedup across all scenarios: 28.9×**

## How to reproduce

```bash
cargo build --release
./bench/run.sh 3        # 3 trials per scenario
python3 bench/report.py
```

Raw per-trial logs and intermediate CSV are kept under `bench/raw/`.
