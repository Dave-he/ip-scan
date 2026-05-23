# IP-Scan AI Agent Skill

## Overview

**ip-scan** is a high-performance Rust port scanner built with Tokio async runtime. It supports IPv4/IPv6 scanning, TCP connect scanning, and SYN half-open scanning (requires root). Results are stored in SQLite with bitmap optimization for efficient storage.

### Key Features
- Async TCP connect scanning and SYN scanning
- Bitmap-based deduplication (60x+ space efficiency)
- SQLite persistence with scan round tracking
- Built-in rate limiting (token bucket algorithm)
- GeoIP enrichment (MaxMind DB)
- REST API with web UI
- Continuous loop scanning mode
- Resume from previous scan position

---

## Build Instructions

### Prerequisites
- Rust 1.75+ (install via `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- macOS/Linux: No additional dependencies
- Windows: Npcap SDK for SYN scan support

### Build Commands

```bash
# Development build
cargo build

# Release build (recommended for production)
cargo build --release

# Run directly
cargo run --release -- [OPTIONS]

# The binary is at:
# ./target/release/ip-scan
```

### Windows (SYN scan support)
```powershell
# Set Npcap SDK path, then build
$env:LIB = if ($env:LIB) { "$env:LIB;D:\npcap-sdk-1.15\Lib\x64" } else { "D:\npcap-sdk-1.15\Lib\x64" }
cargo build --release
```

---

## CLI Arguments Reference

All flags also support environment variables (prefix `SCAN_`).

### Core Arguments

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--start-ip <IP>` | `-s` | `0.0.0.0` | Start IP address |
| `--end-ip <IP>` | `-e` | `255.255.255.255` | End IP address |
| `--ports <PORTS>` | `-p` | `21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017` | Port list/range (comma-separated or range) |
| `--timeout <MS>` | `-t` | `500` | Connection timeout in milliseconds |
| `--concurrency <NUM>` | `-c` | `100` | Concurrent connections |
| `--database <PATH>` | `-d` | `scan_results.db` | SQLite database file path |

### Mode Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--loop-mode` | `-l` | Enable infinite loop scanning (default: true) |
| `--ipv4` | | Scan IPv4 addresses |
| `--ipv6` | | Scan IPv6 addresses |
| `--syn` | | Enable SYN scan mode (requires root/admin) |
| `--verbose` | `-v` | Enable debug logging |

### Storage & Network

| Flag | Default | Description |
|------|---------|-------------|
| `--only-store-open` | true | Only store open ports (saves space) |
| `--skip-private` | true | Skip private IP ranges (10.x, 172.16-31.x, 192.168.x) |
| `--no-geo` | false | Disable geolocation lookup |
| `--geoip-db <PATH>` | None | MaxMind GeoIP database path |

### API Server

| Flag | Default | Description |
|------|---------|-------------|
| `--api` | false | Enable API server mode |
| `--api-only` | false | Run only API server (no scanning) |
| `--no-api` | false | Run only scanner (no API) |
| `--api-host` | `0.0.0.0` | API server bind address |
| `--api-port` | `8080` | API server port |
| `--swagger-ui` | true | Enable Swagger UI |

### Performance Tuning

| Flag | Default | Description |
|------|---------|-------------|
| `--worker-threads` | CPU cores | Tokio worker thread count |
| `--pipeline-buffer` | `2000` | IP pipeline buffer size |
| `--result-buffer` | `10000` | Scan result buffer size |
| `--db-batch-size` | `2000` | Database batch insert size |
| `--flush-interval-ms` | `1000` | Database flush interval |
| `--max-rate` | `100000` | Max scan rate (requests/second) |
| `--rate-window-s` | `1` | Rate limiter window duration |

### Config File

```bash
# Option 1: --config flag
ip-scan --config /path/to/config.toml

# Option 2: positional argument
ip-scan /path/to/config.toml

# Option 3: auto-detect (looks for config.toml in current directory)
ip-scan

# Option 4: environment variable
SCAN_CONFIG=/path/to/config.toml ip-scan
```

---

## Scan Presets

### Quick Scan
Fast scan of a single host using common ports.

```bash
ip-scan \
  --start-ip 127.0.0.1 \
  --end-ip 127.0.0.1 \
  --ports 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017 \
  --timeout 200 \
  --concurrency 1000 \
  --loop-mode false \
  --max-rate 200000
```

**Characteristics:**
- Timeout: 200ms
- Concurrency: 1000
- Ports: 18 common ports
- Max rate: 200,000 req/s
- Use case: Quick host discovery

### Standard Scan
Balanced scan for typical network ranges.

```bash
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017 \
  --timeout 500 \
  --concurrency 100 \
  --loop-mode false \
  --max-rate 100000
```

**Characteristics:**
- Timeout: 500ms
- Concurrency: 100
- Ports: 18 common ports
- Max rate: 100,000 req/s
- Use case: LAN scanning, daily checks

### Deep Scan
Thorough scan with all ports.

```bash
ip-scan \
  --start-ip 192.168.1.100 \
  --end-ip 192.168.1.100 \
  --ports 1-65535 \
  --timeout 2000 \
  --concurrency 500 \
  --loop-mode false \
  --max-rate 50000
```

**Characteristics:**
- Timeout: 2000ms
- Concurrency: 500
- Ports: All 65535 ports
- Max rate: 50,000 req/s
- Use case: Single host deep audit

---

## Common Use Cases

### 1. Scan Localhost Common Ports

```bash
ip-scan \
  --start-ip 127.0.0.1 \
  --end-ip 127.0.0.1 \
  --ports 1-1024 \
  --timeout 200 \
  --concurrency 500 \
  --loop-mode false \
  --verbose
```

### 2. Scan a Single IP

```bash
# Single IP, all ports
ip-scan \
  --start-ip 192.168.1.100 \
  --end-ip 192.168.1.100 \
  --ports 1-65535 \
  --timeout 1000 \
  --concurrency 200 \
  --loop-mode false \
  --database single_host_scan.db
```

### 3. Scan a CIDR Range

ip-scan uses start/end IP instead of CIDR notation. Convert CIDR to start/end:

```bash
# /24 range (254 hosts)
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 80,443,22,3389 \
  --timeout 500 \
  --concurrency 100 \
  --loop-mode false

# /16 range (65,534 hosts)
ip-scan \
  --start-ip 10.0.0.1 \
  --end-ip 10.0.255.254 \
  --ports 22,80,443 \
  --timeout 1000 \
  --concurrency 200 \
  --loop-mode false
```

### 4. Scan a Port Range

```bash
# Web ports only
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 80,443,8080,8443 \
  --timeout 300 \
  --concurrency 100 \
  --loop-mode false

# Common service ports
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017 \
  --timeout 500 \
  --concurrency 100 \
  --loop-mode false
```

### 5. SYN Scan vs Connect Scan

**Connect Scan (default, no special privileges needed):**
```bash
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 80,443,22 \
  --timeout 500 \
  --concurrency 100 \
  --loop-mode false
```

**SYN Scan (requires root/admin, faster and stealthier):**
```bash
# Linux/macOS
sudo ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 80,443,22 \
  --syn \
  --timeout 2000 \
  --concurrency 500 \
  --loop-mode false
```

**Key Differences:**
| | Connect Scan | SYN Scan |
|--|--------------|----------|
| Privileges | None needed | Root/Admin required |
| Speed | Slower (full TCP handshake) | Faster (half-open) |
| Stealth | Logged by target | Less likely to be logged |
| Implementation | `tokio::net::TcpStream` | Raw sockets via `pnet` |

**Note:** If SYN scan fails due to permissions, the scanner automatically falls back to connect scan.

### 6. API Server Mode

```bash
# Start API server only (no scanning)
ip-scan --api-only --api-port 8080 --database scan_results.db

# Start scanner + API server together
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --ports 22,80,443 \
  --api \
  --api-port 8080

# Scanner only (no API)
ip-scan \
  --start-ip 192.168.1.1 \
  --end-ip 192.168.1.254 \
  --no-api
```

**API Endpoints** (base URL: `http://localhost:8080/api/v1/`):

```
GET  /api/v1/results              - Paginated scan results
GET  /api/v1/results/{ip}         - Results for specific IP
GET  /api/v1/results/port/{port}  - Results for specific port
GET  /api/v1/stats                - Overall statistics
GET  /api/v1/stats/top-ports      - Top open ports
POST /api/v1/scan/start           - Start scan task
POST /api/v1/scan/stop            - Stop scan task
GET  /api/v1/scan/status          - Scan status
GET  /api/v1/scan/history         - Scan history
GET  /api/v1/export/csv           - Export as CSV
GET  /api/v1/export/json          - Export as JSON
```

**Web UI:** Access at `http://localhost:8080/`

---

## Performance Tips

### Scan Speed Guidelines

| Scenario | Concurrency | Timeout | Rate Limit | Expected Speed |
|----------|-------------|---------|------------|----------------|
| LAN C-class | 10-50 | 200-500ms | 10,000/s | ~250 IPs/s |
| LAN B-class | 50-200 | 500-1000ms | 10,000/s | ~800 IPs/s |
| Public internet | 50-200 | 1000-3000ms | 5,000/s | ~400 IPs/s |
| Wide-area scan | 200-1000 | 2000-5000ms | 10,000/s | ~1000 IPs/s |

### Optimization Strategies

1. **Reduce timeout for responsive networks:**
   ```bash
   --timeout 200   # Fast LAN
   --timeout 500   # Standard
   --timeout 2000  # Internet/high latency
   ```

2. **Increase concurrency for faster scans:**
   ```bash
   --concurrency 500   # Moderate
   --concurrency 1000  # Aggressive
   ```

3. **Set rate limits to avoid triggering firewalls:**
   ```bash
   --max-rate 5000     # Safe for sensitive networks
   --max-rate 100000   # Fast for trusted networks
   ```

4. **Use SYN scan for speed (requires root):**
   - Up to 10x faster than connect scan
   ```bash
   sudo ip-scan --syn --concurrency 500 ...
   ```

5. **Only store open ports to save space:**
   ```bash
   --only-store-open   # Default, recommended
   ```

6. **Skip private IPs when scanning public ranges:**
   ```bash
   --skip-private   # Default, recommended
   ```

7. **Adjust buffer sizes for high-throughput scans:**
   ```bash
   --pipeline-buffer 5000    # IP pipeline
   --result-buffer 20000     # Result buffer
   --db-batch-size 5000      # DB batch size
   ```

8. **Use worker threads matching CPU:**
   ```bash
   --worker-threads 8   # Explicit thread count
   # Default: auto-detects CPU cores
   ```

### Time Estimation

```
Time = (IP_count * Port_count) / Concurrency * Avg_Response_Time

Example: C-class scan (254 IPs, 18 ports, concurrency=100, 10ms avg response)
Time = 254 * 18 / 100 * 0.01s ≈ 0.46 seconds (theoretical)
With rate limiting (10000/s): ~0.46 seconds

Example: B-class scan (65534 IPs, 18 ports, concurrency=200, 10ms avg response)  
Time = 65534 * 18 / 200 * 0.01s ≈ 59 seconds (theoretical)
With rate limiting (100000/s): ~12 seconds
```

---

## Reading Scan Results from SQLite

### Database Schema

The database contains these key tables:

```sql
-- Bitmap storage (space-efficient)
port_bitmaps (
    port, ip_type, scan_round, bitmap, open_count, last_updated
)

-- Detailed open port records
open_ports_detail (
    ip_address, ip_type, port, scan_round, first_seen, last_seen
)

-- Metadata (scan progress, rounds)
scan_metadata (
    key, value, updated_at
)

-- IP geolocation data
ip_details (
    ip_address, country, region, city, isp, asn, source, updated_at
)
```

### Common Queries

```bash
# Connect to database
sqlite3 scan_results.db
```

#### 1. Check Scan Progress

```sql
-- Current scan round
SELECT value FROM scan_metadata WHERE key = 'current_round';

-- Last scanned IP
SELECT value FROM scan_metadata WHERE key = 'last_ip';

-- All metadata
SELECT key, value FROM scan_metadata;
```

#### 2. View Open Ports Summary

```sql
-- Total open port records and unique IPs
SELECT 
    COUNT(*) as total_records,
    COUNT(DISTINCT ip_address) as unique_ips
FROM open_ports_detail;

-- Top 10 most common open ports
SELECT port, COUNT(*) as ip_count
FROM open_ports_detail
GROUP BY port
ORDER BY ip_count DESC
LIMIT 10;
```

#### 3. Query Specific IP Results

```sql
-- All open ports for a specific IP
SELECT ip_address, port, scan_round, first_seen, last_seen
FROM open_ports_detail
WHERE ip_address = '192.168.1.100'
ORDER BY port;

-- All IPs with a specific port open
SELECT ip_address, scan_round, first_seen, last_seen
FROM open_ports_detail
WHERE port = 80
ORDER BY ip_address;
```

#### 4. Scan Statistics by Round

```sql
-- Stats per scan round
SELECT 
    scan_round,
    COUNT(*) as total_open_records,
    COUNT(DISTINCT ip_address) as unique_ips,
    GROUP_CONCAT(DISTINCT port) as ports_found
FROM open_ports_detail
GROUP BY scan_round
ORDER BY scan_round;

-- Port statistics for current round
SELECT port, open_count
FROM port_bitmaps
WHERE scan_round = (SELECT value FROM scan_metadata WHERE key = 'current_round')
ORDER BY open_count DESC
LIMIT 20;
```

#### 5. Geolocation Queries

```sql
-- IPs with geolocation data
SELECT 
    o.ip_address, 
    o.port, 
    i.country, 
    i.city, 
    i.isp
FROM open_ports_detail o
LEFT JOIN ip_details i ON o.ip_address = i.ip_address
WHERE i.country IS NOT NULL
ORDER BY i.country
LIMIT 50;

-- Count IPs by country
SELECT 
    i.country, 
    COUNT(DISTINCT o.ip_address) as ip_count
FROM open_ports_detail o
JOIN ip_details i ON o.ip_address = i.ip_address
GROUP BY i.country
ORDER BY ip_count DESC;
```

#### 6. Export Data

```bash
# Export open ports as CSV
sqlite3 -header -csv scan_results.db \
  "SELECT ip_address, port, scan_round, first_seen, last_seen 
   FROM open_ports_detail 
   ORDER BY ip_address, port" > open_ports.csv

# Export with geolocation
sqlite3 -header -csv scan_results.db \
  "SELECT o.ip_address, o.port, i.country, i.city, i.isp
   FROM open_ports_detail o
   LEFT JOIN ip_details i ON o.ip_address = i.ip_address
   ORDER BY o.ip_address" > scan_results_with_geo.csv

# Export as JSON
sqlite3 scan_results.db \
  "SELECT json_group_array(
     json_object(
       'ip', ip_address,
       'port', port,
       'round', scan_round,
       'first_seen', first_seen,
       'last_seen', last_seen
     )
   ) FROM open_ports_detail;" > results.json
```

#### 7. Database Maintenance

```bash
# Check database size
sqlite3 scan_results.db "SELECT page_count * page_size / 1024 / 1024 || ' MB' FROM pragma_page_count(), pragma_page_size();"

# Vacuum database (reclaim space)
sqlite3 scan_results.db "VACUUM;"

# Delete old scan rounds (keep last 5)
sqlite3 scan_results.db "DELETE FROM open_ports_detail WHERE scan_round < (SELECT MAX(scan_round) - 5 FROM open_ports_detail);"

# Backup database
sqlite3 scan_results.db ".backup scan_results_backup.db"
```

---

## Configuration File Example

```toml
# config.toml

[api]
enabled = true
host = "0.0.0.0"
port = 8080

[scan]
# IP range (uncomment to set specific range)
# start_ip = "192.168.1.1"
# end_ip = "192.168.1.254"

ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"
timeout = 500
concurrency = 100
database = "scan_results.db"
verbose = false
loop_mode = true
ipv4 = true
ipv6 = false
only_store_open = true
skip_private = true
syn = false

[rate_limit]
max_rate = 100000
window_duration = 1
```

---

## Environment Variables

All CLI flags can be set via environment variables:

```bash
export SCAN_START_IP="192.168.1.1"
export SCAN_END_IP="192.168.1.254"
export SCAN_PORTS="22,80,443"
export SCAN_TIMEOUT="500"
export SCAN_CONCURRENCY="100"
export SCAN_DATABASE="scan_results.db"
export SCAN_VERBOSE="true"
export SCAN_LOOP_MODE="false"
export SCAN_IPV4="true"
export SCAN_IPV6="false"
export SCAN_ONLY_OPEN="true"
export SCAN_SKIP_PRIVATE="true"
export SCAN_SYN="false"
export SCAN_API="false"
export SCAN_API_PORT="8080"
export SCAN_API_HOST="0.0.0.0"
export SCAN_NO_GEO="false"
export SCAN_GEOIP_DB="/path/to/GeoLite2-City.mmdb"
export SCAN_MAX_RATE="100000"
```

---

## Quick Reference Card

```
# Quick localhost scan
ip-scan -s 127.0.0.1 -e 127.0.0.1 -p 1-1024 -t 200 -c 500 -l false -v

# LAN scan
ip-scan -s 192.168.1.1 -e 192.168.1.254 -p 22,80,443 -t 500 -c 100 -l false

# Single host deep scan
ip-scan -s 192.168.1.100 -e 192.168.1.100 -p 1-65535 -t 2000 -c 500 -l false

# SYN scan (needs root)
sudo ip-scan -s 10.0.0.1 -e 10.0.255.254 -p 80,443,22 --syn -t 2000 -c 500 -l false

# API server only
ip-scan --api-only --api-port 8080

# Continuous monitoring
ip-scan -s 192.168.1.1 -e 192.168.1.254 -p 22,80,443 -c 50 -l true

# Public scan with rate limiting
ip-scan -s 1.0.0.1 -e 1.255.255.254 -p 80,443 -t 3000 -c 200 -l false --max-rate 5000
```
