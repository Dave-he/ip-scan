# IP-Scan 用户手册

欢迎查阅 IP-Scan 详细用户手册。本手册涵盖了从基础安装到高级 SYN 扫描的所有内容。

## 目录
- [1. 简介](#1-简介)
- [2. 安装指南](#2-安装指南)
    - [Docker 部署](#docker-部署)
    - [本地编译](#本地编译)
    - [SYN 扫描环境准备](#syn-扫描环境准备)
- [3. 基础扫描 (Connect Mode)](#3-基础扫描-connect-mode)
- [4. 高级扫描 (SYN Mode)](#4-高级扫描-syn-mode)
    - [什么是 SYN 扫描](#什么是-syn-扫描)
    - [为什么使用 SYN 扫描](#为什么使用-syn-扫描)
    - [如何启用 SYN 扫描](#如何启用-syn-扫描)
- [5. 配置详解](#5-配置详解)
- [6. 性能调优](#6-性能调优)
- [7. 常见问题 (FAQ)](#7-常见问题-faq)

---

## 1. 简介
IP-Scan 是一个高性能、企业级的端口扫描工具。它采用 Rust 编写，基于 Tokio 异步运行时，支持数万并发连接。其独特之处在于结合了位图 (Bitmap) 存储技术，极大地降低了海量扫描数据的存储成本。

## 2. 安装指南

### Docker 部署
最简单的运行方式。注意：Docker 模式下默认仅支持 Connect 扫描。如需 SYN 扫描，需以特权模式运行并配置宿主机网络。

```bash
docker-compose up -d
```

### 本地编译
需要 Rust 环境 (1.75+)。

```bash
# 标准编译 (仅 Connect 扫描)
cargo build --release

# 启用 SYN 扫描特性的编译 (需要 Npcap/Libpcap)
cargo build --release --features syn
```

### SYN 扫描环境准备
SYN 扫描涉及原始套接字 (Raw Socket) 操作，需要系统级依赖。

#### Windows 用户
1. 下载并安装 [Npcap](https://npcap.com/#download)。
   - 安装时务必勾选 **"Install Npcap in WinPcap API-compatible Mode"**。
2. 下载 [Npcap SDK](https://npcap.com/#download)。
3. 将 SDK 中的 `Lib/x64` 目录路径添加到系统的 `LIB` 环境变量中，或在编译时指定。

#### Linux 用户
1. 安装 `libpcap` 开发包：
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libpcap-dev
   
   # CentOS/RHEL
   sudo yum install libpcap-devel
   ```
2. 运行程序时需要 root 权限或设置 `CAP_NET_RAW` 能力：
   ```bash
   sudo ./ip-scan ...
   # 或
   sudo setcap cap_net_raw+ep ./target/release/ip-scan
   ```

## 3. 基础扫描 (Connect Mode)
默认模式，使用 TCP 三次握手建立完整连接。
- **优点**：无需特殊权限，准确性高，穿越防火墙能力一般。
- **缺点**：速度较慢，会在目标主机留下完整连接日志。

```bash
./ip-scan --start-ip 192.168.1.1 --end-ip 192.168.1.254 --ports 80,443
```

## 4. 高级扫描 (SYN Mode)

### 什么是 SYN 扫描
SYN 扫描（也称半开放扫描）不建立完整的 TCP 连接。它只发送 SYN 包：
- 如果收到 `SYN-ACK`：端口开放（扫描器随后发送 RST 断开，不完成握手）。
- 如果收到 `RST`：端口关闭。
- 如果超时：端口被过滤。

### 为什么使用 SYN 扫描
1.  **极速**：不需要等待完整的握手过程，发包即走。
2.  **隐蔽**：不建立完整连接，许多应用层日志不会记录。
3.  **穿透性**：更能适应复杂的网络环境。

### 如何启用 SYN 扫描

1.  **确保编译时开启了 `syn` 特性**：
    ```bash
    cargo build --release --features syn
    ```

2.  **运行时添加 `--syn` 参数**（必须有管理员/Root权限）：
    ```bash
    # Windows (以管理员身份运行 PowerShell/CMD)
    ./target/release/ip-scan.exe --syn --start-ip 10.0.0.1 --end-ip 10.0.0.254 --ports 80

    # Linux
    sudo ./target/release/ip-scan --syn --start-ip 10.0.0.1 --end-ip 10.0.0.254 --ports 80
    ```

3.  **配置文件开启**：
    在 `config.toml` 中设置：
    ```toml
    syn = true
    ```

## 5. 配置详解
(此处参考 README 中的配置说明)

## 6. 性能调优
对于 SYN 扫描，速率限制 (Rate Limit) 是关键。
- 局域网：可设置 `--rate-limit 10000` 或更高。
- 互联网：建议 `--rate-limit 1000` - `5000`，避免被运营商阻断。

## 7. 常见问题 (FAQ)

**Q: 为什么 SYN 扫描显示编译错误？**
A: 检查是否安装了 Npcap SDK (Windows) 或 libpcap-dev (Linux)。

**Q: 运行 SYN 扫描报错 "Permission denied"？**
A: SYN 扫描需要构造原始数据包，必须使用管理员 (Windows) 或 Root (Linux) 权限运行。

**Q: SYN 扫描速度很快但结果很少？**
A: 可能是防火墙拦截了高频 SYN 包。尝试降低 `--rate-limit` 或检查本地防火墙设置。
