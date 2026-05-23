# IP-Scan 项目 Code Wiki

本文档旨在帮助开发者快速理解 IP-Scan 项目的整体架构、模块划分、核心实现及运行方式。

## 1. 项目简介

**IP-Scan** 是一个基于 Rust 和 Tokio 编写的高性能企业级 IPv4/IPv6 端口扫描工具。它不仅支持传统的 TCP Connect 扫描，还支持基于底层数据链路层的高性能 SYN 半连接扫描。此外，它配备了现代化的 Web 管理界面（基于 Actix-web 提供 REST API），支持百万级 IP 扫描的智能去重（Bitmap 算法）、实时监控、地理位置识别以及数据持久化（SQLite）。

---

## 2. 整体架构 (Overall Architecture)

### 2.1 系统架构

项目采用了清晰的分层架构，核心分为：Web前端、REST API 层、扫描引擎层（Scanner Engine）、数据访问层（DAO）。

- **Web 浏览器**：通过 HTTP 请求与后端交互，或由 Nginx 反向代理。
- **API 服务 (`actix-web`)**：提供 RESTful 接口供前端调用，支持扫描任务的启停、状态获取、结果查询等。
- **扫描引擎 (`tokio` 异步运行时)**：采用生产者-消费者模型，Producer 负责生成 IP，Consumer 负责执行并发扫描（支持 Connect / SYN 两种模式）。包含速率限制器（Rate Limiter）防止触发防火墙告警。
- **持久化 (`SQLite` + `Bitmap`)**：将海量的扫描结果通过 Bitmap 位图结构高度压缩后持久化存储到 SQLite 中。
- **第三方服务集成**：通过 `maxminddb` 本地库集成地理位置解析功能。

### 2.2 目录结构

```text
ip-scan/
├── src/
│   ├── main.rs              # 项目入口，启动 API Server 或 CLI Scanner
│   ├── cli.rs               # 命令行参数解析 (使用 clap)
│   ├── error.rs             # 统一的错误类型定义
│   ├── api/                 # REST API 模块 (基于 actix-web)
│   │   ├── mod.rs
│   │   ├── handlers.rs      # 请求处理逻辑
│   │   ├── models.rs        # 请求/响应数据结构定义
│   │   └── routes.rs        # 路由注册
│   ├── dao/                 # 数据访问对象 (Database Access)
│   │   ├── mod.rs
│   │   └── sqlite_db.rs     # 封装 rusqlite 数据库操作与 Bitmap 更新逻辑
│   ├── model/               # 领域数据模型
│   │   ├── bitmap.rs        # Bitmap 核心位图算法实现
│   │   ├── geo.rs           # IP 地理位置数据结构
│   │   ├── ip_range.rs      # CIDR/IP 范围的解析与迭代器
│   │   └── metrics.rs       # 扫描性能监控指标
│   └── service/             # 核心业务服务层
│       ├── mod.rs
│       ├── con_scanner.rs   # 基于 TCP Stream 的常规 Connect 扫描器
│       ├── syn_scanner.rs   # 基于 pnet 的高性能 SYN 半连接扫描器
│       ├── rate_limiter.rs  # 令牌桶算法实现的速率限制器
│       ├── scan_controller.rs # Web API 调用的扫描生命周期控制器
│       └── geo_service.rs   # IP 地理位置查询服务
├── web/                     # Web 前端静态文件 (HTML/CSS/JS)
├── Cargo.toml               # Rust 依赖及配置
└── config.toml              # 默认服务配置文件
```

---

## 3. 主要模块职责 (Main Module Responsibilities)

| 模块名称 | 核心职责 | 关键依赖/技术 |
| :--- | :--- | :--- |
| **CLI 模块** (`cli.rs`) | 负责处理终端命令行输入和配置文件解析，合并默认参数。 | `clap`, `toml` |
| **API 模块** (`api/*`) | 负责构建 HTTP Server，暴露 JSON API；使用 Swagger 生成交互式 API 文档。 | `actix-web`, `utoipa` |
| **Service 模块** (`service/*`) | **核心业务引擎**：控制扫描任务并发，区分 TCP 和 SYN 模式；实现速率控制；执行 GeoIP 补充。 | `tokio`, `pnet`, `maxminddb` |
| **DAO 模块** (`dao/*`) | 处理 SQLite 的建表、读写。包含创新性的分段 Bitmap 存储方案，极大优化了海量端口状态的落盘性能和空间占用。 | `rusqlite`, `bincode` |
| **Model 模块** (`model/*`) | 定义 IP 解析迭代器规则、数据结构序列化模型和运行时的监控指标。 | `serde`, `pnet_packet` |

---

## 4. 关键类与函数说明 (Key Classes & Functions)

### 4.1 扫描控制器: `ScanController` (位于 `service/scan_controller.rs`)
- **功能**：作为 Web API 和底层异步扫描引擎的桥梁，管理扫描生命周期（单例运行）。
- **关键函数**：
  - `start_scan(request, base_args)`: 启动后台 `tokio::spawn` 扫描任务，初始化扫描轮次并记录状态。
  - `stop_scan()`: 触发内部 `AtomicBool` 停止信号，中断当前正在运行的异步扫描任务。
  - `run_scan_task(...)`: 实际运行扫描的内部核心函数，根据参数选择实例化 `SynScanner` 还是 `ConScanner`。

### 4.2 扫描器: `ConScanner` & `SynScanner` (位于 `service/`)
- **功能**：执行具体的端口探测工作。
- **`ConScanner::new` / `SynScanner::new`**: 初始化扫描器，同时在后台 spawn 一个异步 DB Writer 线程，通过 MPSC Channel 接收扫描结果进行**批量刷盘**（`bulk_update_port_status`），极大降低 SQLite I/O。
- **`run_pipeline(rx, ports, callback)`**: 消费者核心逻辑。从通道 `rx` 接收待扫描的 IP，结合速率限制器 (`RateLimiter`) 控制速度，通过 Tokio 任务并发地对指定端口列表发起 TCP 连接或发送构造的 SYN 报文。

### 4.3 数据库访问: `SqliteDB` (位于 `dao/sqlite_db.rs`)
- **功能**：处理所有持久化相关的操作。
- **关键函数**：
  - `bulk_update_port_status(buffer, round)`: 核心性能优化点。接收一批 `(IP, Port, IsOpen)` 数据，通过位运算 (`bitmap.rs`) 将 IPv4 地址映射到 `port_bitmap_segments` 表中的二进制 BLOB 字段中。避免了为每个 IP/Port 组合创建独立记录。
  - `get_ips_missing_geo(limit)`: 取出尚未完成地理位置标记的 IP，供 `GeoService` 进行异步补充。

### 4.4 其他辅助模块
- **`RateLimiter::acquire()`**: 使用令牌桶算法限制每秒发包/连接的峰值，防止网络拥塞。
- **`IpRange::iter()`**: 提供高效的 IPv4 地址迭代器，避免将整个网段 IP 读入内存。

---

## 5. 依赖关系 (Dependencies)

项目 `Cargo.toml` 中核心的第三方依赖分析如下：

- **异步与并发**
  - `tokio`: 整个项目的异步 I/O 基石，提供线程池、定时器、Channel、TCP 异步连接。
  - `futures`: 配合 Tokio 处理异步流和并发集合。
- **网络与协议**
  - `pnet` (Packet Network): 提供跨平台的底层网络接口，用于抓包和构造裸报文（Raw Sockets），是 `SynScanner` 的核心依赖。
  - `actix-web`, `actix-cors`, `actix-files`: 高性能的 Rust Web 框架，用于构建后台管理系统。
  - `reqwest`: 异步 HTTP 客户端（处理外网请求或扩展服务）。
- **数据与持久化**
  - `rusqlite`: SQLite 官方 C 库的安全 Rust 绑定，并启用了 `bundled` 特性避免系统级依赖。
  - `maxminddb`: 用于解析 `.mmdb` 格式文件，实现离线的 IP 归属地查询。
  - `bincode`, `serde`, `serde_json`: 高效的二进制及 JSON 数据序列化。
- **工具与工程化**
  - `clap`: 提供强大的命令行参数解析。
  - `tracing`, `tracing-subscriber`: 结构化的日志框架，支持并发环境下的全链路追踪。
  - `utoipa`: 在编译期基于宏自动生成 OpenAPI (Swagger) 文档。

---

## 6. 项目运行方式 (How to run the project)

IP-Scan 支持多种运行模式：纯 API 模式、纯扫描器 CLI 模式，以及前后端一体的 Combined 模式。

### 6.1 Docker 部署 (推荐)
适用于不需要配置 Rust 环境的生产或测试环境。
```bash
# 启动服务 (包含 API 和内置 SQLite 卷映射)
docker-compose up -d

# 查看日志
docker logs -f ip-scanner

# 访问 Web UI
# 浏览器打开 http://localhost:8080
```

### 6.2 本地编译运行 (Linux/macOS)
适用于开发调试。
```bash
# 1. 编译 release 版本 (确保具有 Rust 1.75+ 环境)
cargo build --release

# 2. 启动默认的 Web UI 和 API
./target/release/ip-scan

# 3. 纯 CLI 扫描模式 (常规 TCP Connect 扫描)
./target/release/ip-scan --no-api --start-ip 192.168.1.1 --end-ip 192.168.1.254 --ports 22,80,443 --concurrency 20

# 4. 高性能 SYN 扫描模式 (需要 Root 权限！)
sudo ./target/release/ip-scan --syn --start-ip 10.0.0.0 --end-ip 10.255.255.255 --ports 80
```

### 6.3 Windows 编译要求
由于 SYN 扫描依赖数据链路层的收发包能力，在 Windows 平台需要额外安装 Npcap SDK：
1. 安装 [Npcap](https://npcap.com/)，勾选 “Install Npcap in WinPcap API-compatible Mode”。
2. 下载 Npcap SDK，并设置环境变量指向 SDK 的 Lib 目录：
   ```powershell
   $env:LIB = "$env:LIB;D:\npcap-sdk-1.15\Lib\x64"
   cargo build --release
   ```
3. 运行程序时需**以管理员身份启动终端**才能使用 `--syn` 参数。
