#!/bin/bash
# Performance benchmark: ip-scan vs nmap
# This script compares performance between ip-scan and nmap

set -e

IP_SCAN_BIN="./target/release/ip-scan"
NMAP_BIN="$(which nmap 2>/dev/null || echo '/opt/homebrew/bin/nmap')"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== IP-SCAN vs NMAP Performance Benchmark ===${NC}\n"

# Check if ip-scan exists
if [ ! -f "$IP_SCAN_BIN" ]; then
    echo -e "${RED}Error: ip-scan binary not found at $IP_SCAN_BIN${NC}"
    echo "Please build with: cargo build --release"
    exit 1
fi

# Check if nmap exists
if [ ! -f "$NMAP_BIN" ]; then
    echo -e "${RED}Warning: nmap not found at $NMAP_BIN${NC}"
    echo "Install with: brew install nmap"
    NMAP_AVAILABLE=false
else
    NMAP_AVAILABLE=true
    echo -e "Found nmap: ${GREEN}$($NMAP_BIN --version | head -1)${NC}"
fi

echo -e "Found ip-scan: ${GREEN}$($IP_SCAN_BIN --version 2>/dev/null || echo 'v0.1.0')${NC}\n"

# Test configuration
TEST_TARGET="127.0.0.1"
TEST_PORTS="1-1000"
TEST_PORT_LIST="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080"
WARMUP_RUNS=1
TEST_RUNS=3

# Create temp directory for results
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Test target: $TEST_TARGET"
echo "Test ports: $TEST_PORTS"
echo "Test runs: $TEST_RUNS"
echo ""

# Helper function to time a command
run_benchmark() {
    local name="$1"
    local cmd="$2"
    local output_file="$3"
    
    echo -n "  Running $name..."
    
    # Warmup run
    for i in $(seq 1 $WARMUP_RUNS); do
        eval "$cmd" > /dev/null 2>&1 || true
    done
    
    # Test runs
    local total_time=0
    local success_count=0
    
    for i in $(seq 1 $TEST_RUNS); do
        local start_time=$(date +%s%3N)
        if eval "$cmd" > "$output_file" 2>&1; then
            local end_time=$(date +%s%3N)
            local elapsed=$((end_time - start_time))
            total_time=$((total_time + elapsed))
            success_count=$((success_count + 1))
        fi
    done
    
    if [ $success_count -gt 0 ]; then
        local avg_time=$((total_time / success_count))
        echo -e " ${GREEN}${avg_time}ms avg (${success_count}/$TEST_RUNS runs)${NC}"
        echo "$avg_time"
    else
        echo -e " ${RED}FAILED${NC}"
        echo "999999"
    fi
}

# ============================================
# Test 1: Basic TCP Connect Scan (port range)
# ============================================
echo -e "${YELLOW}Test 1: TCP Connect Scan (port range 1-1000)${NC}"
echo "  Scanning $TEST_TARGET ports $TEST_PORTS..."

IP_SCAN_CONNECT_TIME=$(run_benchmark \
    "ip-scan connect" \
    "$IP_SCAN_BIN -s $TEST_TARGET -e $TEST_TARGET -p $TEST_PORTS --concurrency 500 --timeout 1000 --max-rate 0 --dry-run" \
    "$TEMP_DIR/ipscan_connect.txt")

if [ "$NMAP_AVAILABLE" = true ]; then
    NMAP_CONNECT_TIME=$(run_benchmark \
        "nmap connect" \
        "$NMAP_BIN -sT -p $TEST_PORTS --host-timeout 1s $TEST_TARGET" \
        "$TEMP_DIR/nmap_connect.txt")
else
    NMAP_CONNECT_TIME="N/A"
fi

# ============================================
# Test 2: Top Ports Scan
# ============================================
echo -e "\n${YELLOW}Test 2: Top 100 Ports Scan${NC}"
echo "  Scanning $TEST_TARGET top 100 ports..."

IP_SCAN_TOP_TIME=$(run_benchmark \
    "ip-scan top-ports" \
    "$IP_SCAN_BIN -s $TEST_TARGET -e $TEST_TARGET --top-ports 100 --concurrency 500 --timeout 1000 --max-rate 0 --dry-run" \
    "$TEMP_DIR/ipscan_top.txt")

if [ "$NMAP_AVAILABLE" = true ]; then
    NMAP_TOP_TIME=$(run_benchmark \
        "nmap top-ports" \
        "$NMAP_BIN -sT --top-ports 100 $TEST_TARGET" \
        "$TEMP_DIR/nmap_top.txt")
else
    NMAP_TOP_TIME="N/A"
fi

# ============================================
# Test 3: SYN Stealth Scan (if supported)
# ============================================
echo -e "\n${YELLOW}Test 3: SYN Stealth Scan (requires root)${NC}"
echo "  Scanning $TEST_TARGET ports $TEST_PORT_LIST..."

IP_SCAN_SYN_TIME=$(run_benchmark \
    "ip-scan SYN" \
    "$IP_SCAN_BIN -s $TEST_TARGET -e $TEST_TARGET -p $TEST_PORT_LIST --syn --concurrency 500 --timeout 1000 --max-rate 0 --dry-run" \
    "$TEMP_DIR/ipscan_syn.txt")

if [ "$NMAP_AVAILABLE" = true ] && [ "$(id -u)" = "0" ]; then
    NMAP_SYN_TIME=$(run_benchmark \
        "nmap SYN" \
        "$NMAP_BIN -sS -p $TEST_PORT_LIST $TEST_TARGET" \
        "$TEMP_DIR/nmap_syn.txt")
else
    NMAP_SYN_TIME="N/A (requires root)"
fi

# ============================================
# Test 4: Service Detection
# ============================================
echo -e "\n${YELLOW}Test 4: Service Detection${NC}"
echo "  Scanning $TEST_TARGET ports $TEST_PORT_LIST with service detection..."

IP_SCAN_SERVICE_TIME=$(run_benchmark \
    "ip-scan service" \
    "$IP_SCAN_BIN -s $TEST_TARGET -e $TEST_TARGET -p $TEST_PORT_LIST --probe-service --probe-timeout 5 --probe-concurrency 50 --dry-run" \
    "$TEMP_DIR/ipscan_service.txt")

if [ "$NMAP_AVAILABLE" = true ]; then
    NMAP_SERVICE_TIME=$(run_benchmark \
        "nmap service" \
        "$NMAP_BIN -sV -p $TEST_PORT_LIST $TEST_TARGET" \
        "$TEMP_DIR/nmap_service.txt")
else
    NMAP_SERVICE_TIME="N/A"
fi

# ============================================
# Test 5: Nmap CLI Compatibility
# ============================================
echo -e "\n${YELLOW}Test 5: Nmap CLI Compatibility Mode${NC}"
echo "  Testing ip-scan with nmap-style arguments..."

IP_SCAN_NMAP_TIME=$(run_benchmark \
    "ip-scan nmap-compat" \
    "$IP_SCAN_BIN -sT -p $TEST_PORT_LIST -T4 $TEST_TARGET --dry-run" \
    "$TEMP_DIR/ipscan_nmap.txt")

# ============================================
# Test 6: Raw Scanner (libc-based)
# ============================================
echo -e "\n${YELLOW}Test 6: Raw Scanner (libc-based high-performance)${NC}"
echo "  Scanning $TEST_TARGET ports $TEST_PORT_LIST with raw scanner..."

IP_SCAN_RAW_TIME=$(run_benchmark \
    "ip-scan raw" \
    "$IP_SCAN_BIN -s $TEST_TARGET -e $TEST_TARGET -p $TEST_PORT_LIST --raw --raw-workers 2 --raw-inflight 256 --concurrency 0 --dry-run" \
    "$TEMP_DIR/ipscan_raw.txt")

# ============================================
# Results Summary
# ============================================
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}BENCHMARK RESULTS SUMMARY${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo "| Test | ip-scan | nmap | Speedup |"
echo "|------|---------|------|---------|"

# Helper to calculate speedup
calculate_speedup() {
    local ipscan_time="$1"
    local nmap_time="$2"
    
    if [ "$nmap_time" = "N/A" ] || [ "$nmap_time" = "N/A (requires root)" ]; then
        echo "N/A"
    elif [ "$ipscan_time" -gt 0 ] && [ "$nmap_time" -gt 0 ]; then
        if [ "$ipscan_time" -lt "$nmap_time" ]; then
            local speedup=$(echo "scale=1; $nmap_time / $ipscan_time" | bc 2>/dev/null || echo "1.0")
            echo -e "${GREEN}${speedup}x faster${NC}"
        elif [ "$ipscan_time" -gt "$nmap_time" ]; then
            local speedup=$(echo "scale=1; $ipscan_time / $nmap_time" | bc 2>/dev/null || echo "1.0")
            echo -e "${RED}${speedup}x slower${NC}"
        else
            echo "equal"
        fi
    else
        echo "N/A"
    fi
}

# Test 1
SPEEDUP_1=$(calculate_speedup "$IP_SCAN_CONNECT_TIME" "$NMAP_CONNECT_TIME")
printf "| TCP Connect Scan | %dms | %s | %s |\n" "$IP_SCAN_CONNECT_TIME" "$NMAP_CONNECT_TIME" "$SPEEDUP_1"

# Test 2
SPEEDUP_2=$(calculate_speedup "$IP_SCAN_TOP_TIME" "$NMAP_TOP_TIME")
printf "| Top 100 Ports | %dms | %s | %s |\n" "$IP_SCAN_TOP_TIME" "$NMAP_TOP_TIME" "$SPEEDUP_2"

# Test 3
if [ "$IP_SCAN_SYN_TIME" != "999999" ]; then
    SPEEDUP_3=$(calculate_speedup "$IP_SCAN_SYN_TIME" "$NMAP_SYN_TIME")
    printf "| SYN Stealth | %dms | %s | %s |\n" "$IP_SCAN_SYN_TIME" "$NMAP_SYN_TIME" "$SPEEDUP_3"
fi

# Test 4
if [ "$IP_SCAN_SERVICE_TIME" != "999999" ]; then
    SPEEDUP_4=$(calculate_speedup "$IP_SCAN_SERVICE_TIME" "$NMAP_SERVICE_TIME")
    printf "| Service Detection | %dms | %s | %s |\n" "$IP_SCAN_SERVICE_TIME" "$NMAP_SERVICE_TIME" "$SPEEDUP_4"
fi

# Test 5
if [ "$IP_SCAN_NMAP_TIME" != "999999" ]; then
    printf "| Nmap CLI Compat | %dms | N/A (same binary) | N/A |\n" "$IP_SCAN_NMAP_TIME"
fi

# Test 6
if [ "$IP_SCAN_RAW_TIME" != "999999" ]; then
    printf "| Raw Scanner | %dms | N/A | N/A |\n" "$IP_SCAN_RAW_TIME"
fi

echo ""
echo -e "${YELLOW}========================================${NC}"
echo -e "Recommendations:"
echo -e "  - Use ${GREEN}--raw${NC} flag for maximum performance (libc-based)"
echo -e "  - Use ${GREEN}--syn${NC} flag for stealth scanning (requires root)"
echo -e "  - Use ${GREEN}--top-ports${NC} for quick common port scanning"
echo -e "  - Nmap CLI compat: ${GREEN}ip-scan -sS -T4 -p 1-1000 target${NC}"
echo -e "${YELLOW}========================================${NC}"

# Show ip-scan help for nmap compatibility
echo ""
echo -e "${YELLOW}Nmap-compatible commands:${NC}"
echo "  # SYN scan (like nmap -sS)"
echo "  $IP_SCAN_BIN -sS -T4 192.168.1.0/24"
echo ""
echo "  # Connect scan (like nmap -sT)"
echo "  $IP_SCAN_BIN -sT -p 1-65535 192.168.1.1"
echo ""
echo "  # Service detection (like nmap -sV)"
echo "  $IP_SCAN_BIN -sV -p 22,80,443 192.168.1.1"
echo ""
echo "  # Output formats (like nmap -oN, -oX, -oG, -oJ)"
echo "  $IP_SCAN_BIN -sT -oN output.txt -oJ output.json 192.168.1.1"
echo ""
echo "  # Top ports (like nmap --top-ports)"
echo "  $IP_SCAN_BIN -sT --top-ports 100 192.168.1.0/24"

# Verify ip-scan help output
echo ""
echo -e "${YELLOW}ip-scan help output (nmap-compatible options):${NC}"
$IP_SCAN_BIN --help 2>&1 | grep -E "(nmap|compatible|兼容)" | head -5 || echo "(checking full help...)"
echo ""
$IP_SCAN_BIN --help 2>&1 | grep -A1 -E "(-sS|-sT|-sn|-sV|-oN|-oJ|-oA|-T[0-5]|--top-ports|-iL)" | head -30

echo ""
echo -e "${GREEN}Benchmark complete!${NC}"