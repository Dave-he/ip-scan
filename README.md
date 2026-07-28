# IP-Scan

> Rust/Tokio 驱动的 IPv4/IPv6 资产发现与服务识别工具。仅对你拥有或获授权的网络执行扫描。

IP-Scan 不只是“端口是否打开”：扫描器写入开放端口的同时，后台 enrichment worker 持续消费新资产，补充 GeoIP、服务类型、Banner、HTTP 标题/Server、TLS 证书线索、RTT、OS guess 和资产分类，并统一保存到 SQLite，供 API、Web UI 和 CSV/JSON 导出使用。

---

## 目录

- [能力概览](#能力概览)
- [快速开始](#快速开始)
- [常用参数](#常用参数)
- [数据与 API](#数据与-api)
- [配置、部署与文档](#配置部署与文档)
- [安全边界](#安全边界)
- [依赖安全](#依赖安全)
- [许可证](#许可证)

---

## 能力概览

- **扫描**：IPv4/IPv6、单 IP/CIDR/范围、TCP connect；具备权限时可使用 SYN 半连接扫描（SYN 失败会自动降级到 connect 模式）。
- **流水线**：扫描结果写库后立即进入 GeoIP 与服务探测队列，不必等待整轮结束。
- **服务识别**：HTTP/HTTPS、SSH、FTP、SMTP、POP3/IMAP、Redis、MongoDB、Elasticsearch、MySQL/Postgres/MSSQL/Oracle 等 Banner/协议探测；HTTP 采集状态码、`<title>`、`Server` 和 Body 预览，并采样常见 Web 安全响应头。
- **TLS/主机线索**：HTTPS TLS 建连、证书 CN/Issuer/有效期/版本字段、TTL OS guess、RTT、版本字段。
- **数据**：SQLite WAL、批量写入、增量进度、扫描轮次、开放端口历史、Geo 信息、服务信息和轻量风险提示（`risk_score` 与 `risk_reasons`）。
- **接口**：Actix Web API、Swagger/OpenAPI、Web 管理界面、JSON/CSV/NDJSON 导出、Prometheus 指标。
- **工程性**：令牌桶限速、并发控制、超时、断点续扫、循环扫描、旧轮次清理、结构化日志、`--dry-run` 计划预览、nmap 风格参数（`-sS` / `-sV` / `-O` / `-A` / `-T0..-T5` / `-F`）。

> 想要更深入的“端口/服务 ↔ 网安知识”对照？请看 [docs/SECURITY_KNOWLEDGE.md](docs/SECURITY_KNOWLEDGE.md)。

---

## 快速开始

```bash
# 编译（需要 Rust 1.75+）
cargo build --release

# 先解析配置和目标，不创建数据库、不连接目标（CI/容器探针友好）
./target/release/ip-scan --dry-run --target 192.168.1.0/24 --ports 22,80,443
./target/release/ip-scan --dry-run --target 10.0.0.0/24 --output-format json

# 单次扫描：TCP connect，无需特权
./target/release/ip-scan \
  --target 192.168.1.0/24 \
  --ports 22,80,443,3306,5432,6379,8080 \
  --concurrency 100 \
  --timeout 500 \
  --probe-service \
  --no-api

# 启动 API + Web UI（含 Swagger、Prometheus 指标）
./target/release/ip-scan --api --target 192.168.1.0/24 --ports 22,80,443 --probe-service
# Web UI:         http://127.0.0.1:9090/
# OpenAPI JSON:   http://127.0.0.1:9090/api-docs/openapi.json
# Health:         http://127.0.0.1:9090/api/v1/healthz
# Stats JSON:     http://127.0.0.1:9090/api/v1/stats
# Stats Prometheus: http://127.0.0.1:9090/api/v1/stats/prometheus
# Round diff:     http://127.0.0.1:9090/api/v1/stats/changes?round=3&port=443

# 预设扫描（quick / standard / deep）
./target/release/ip-scan --preset quick   --target 192.168.1.0/24
./target/release/ip-scan --preset standard --target 192.168.1.0/24
./target/release/ip-scan --preset deep    --target 192.168.1.0/24

# SYN 半连接扫描（需要 Root/Admin；失败会自动降级为 connect）
sudo ./target/release/ip-scan --syn --target 192.168.1.0/24 --ports 80,443
```

本地验证：

```bash
cargo test --offline
cargo fmt --check
```

---

## 常用参数

| 参数 | 说明 |
|---|---|
| `--target` | IP、CIDR 或起止范围，例如 `10.0.0.0/24`、`192.168.1.1-192.168.1.255` |
| `--dry-run` | 输出合并后的扫描计划并退出，不打开 socket 或数据库；配合 `--output-format json` 可供脚本读取 |
| `--start-ip/--end-ip` | 传统范围写法 |
| `--ports` | `80`、`22,80,443`、`1-1024`、混合范围 |
| `--preset quick\|standard\|deep` | 预设扫描端口集合与并发/超时参数 |
| `--concurrency` | TCP 扫描并发数（同时进行的连接任务数） |
| `--timeout` | TCP 连接超时（毫秒） |
| `--probe-service` | 对新发现开放端口做 Banner/HTTP/TLS 探测（应用层探测） |
| `--probe-concurrency` | 单 IP 内服务探测并发数 |
| `--probe-timeout` | 服务探测超时（秒） |
| `--no-geo` | 禁用 GeoIP enrichment |
| `--geoip-db PATH` | MaxMind `.mmdb` 数据库路径（可选） |
| `--geo-concurrency` | GeoIP、WHOIS 和反向 DNS 并发数，默认 8 |
| `--syn` | SYN 半连接扫描，需要 root/admin 和平台抓包支持 |
| `--max-rate` | 统一令牌桶速率上限（packets/sec） |
| `--loop-mode` | 持续轮询扫描 |
| `--round-delay-ms` | 轮询扫描下两轮之间的间隔（毫秒，默认 0；扫描固定子网时建议 1000–5000 以免过度打同一段） |
| `--skip-private` | 跳过 RFC1918 私网 / loopback / link-local / multicast / reserved IPv4 |
| `--only-store-open` | 仅持久化开放端口（节省存储） |
| `--api` / `--api-only` / `--no-api` | 启用 API / 仅启动 API / 仅扫描 |
| `--api-host` / `--api-port` | API 绑定地址和端口 |
| `--database PATH` | SQLite 文件路径 |
| `--output-format text\|json` | `--dry-run` 输出格式 |
| `--verbose` | 输出 DEBUG 级别结构化日志 |

nmap 兼容参数：`--syn` 对应 `-sS`，`--probe-service` 对应 `-sV` / `-sC` / `-O` / `-A`，`-T0..-T5` 直接套用 nmap 时序模板，`-F` 切换到 Top 100 端口，`--top-ports N` 取 nmap 风格的 Top N。

所有 CLI 选项也支持对应的 `SCAN_*` 环境变量；并发数、超时、缓冲区和速率不能设置为 0，非法配置会在启动前直接报错。完整参数以 `ip-scan --help` 为准。反向 DNS 支持 IPv4 与压缩形式 IPv6，默认读取系统 `/etc/resolv.conf`，也可通过 `IP_SCAN_DNS_SERVER=192.0.2.53` 指定 DNS。

---

## 数据与 API

主要表：

- `open_ports_detail`：IP、端口、类型、首次/最近发现、扫描轮次
- `port_bitmaps`：高密度扫描状态与轮次
- `ip_details`：国家、地区、城市、ISP、ASN、反向 DNS、来源
- `service_info`：服务、协议、Banner、HTTP、TLS、版本、RTT、OS guess；服务摘要还提供风险分数和原因
- `scan_metadata`：运行状态、进度和轮次元数据
- `service_probe_state`：服务探测的退避重试状态（每 IP 每小时最多重试一次）

API 路径前缀为 `/api/v1/`，Swagger/OpenAPI 可查看实际路由和字段。服务信息查询示例：

```bash
curl http://127.0.0.1:9090/api/v1/services/192.168.1.10
curl http://127.0.0.1:9090/api-docs/openapi.json
```

`/api/v1/scan/status` 同时报告 CLI 与 API 发起的扫描；`source` 标识来源，`controllable` 表示能否通过 API 停止。完整字段定义见 [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) 与 [`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md)。

---

## 配置、部署与文档

- 示例配置：[`config.toml`](config.toml)
- 架构与流水线：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 前后端协议契约：[`docs/API_CONTRACT.md`](docs/API_CONTRACT.md)
- 数据字典：[`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md)
- 运维与安全：[`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- 网络安全知识：[`docs/SECURITY_KNOWLEDGE.md`](docs/SECURITY_KNOWLEDGE.md)
- 整体 Wiki：[`CodeWiki.md`](CodeWiki.md)
- AI/自动化修改规则：[`AGENTS.md`](AGENTS.md)
- 技能说明：[`SKILL_README.md`](SKILL_README.md)
- 贡献指南：[`CONTRIBUTING.md`](CONTRIBUTING.md)

Docker、反向代理和 Windows Npcap 说明见 `docker-compose.yml`、`Dockerfile`、`nginx.conf` 及架构文档。

---

## 安全边界

只扫描明确授权的资产。默认建议跳过私网或限制到实验网段；不要把公网大范围扫描、Banner 探测或高并发作为默认行为。SYN、服务探测和 TLS/HTTP 请求可能被目标侧记录或拦截，请遵守法律、合同和组织策略。

- 仅对你拥有书面授权的网络使用本工具。
- 私网/loopback/link-local 默认会被 `--skip-private` 跳过，公网任务请显式开启并控制速率。
- API 不要直接暴露公网；生产环境绑定内网并通过认证反向代理保护。
- `--probe-service` 会产生应用层请求（HTTP GET、TLS ClientHello、Banner 抓取），按目标方策略启用。
- SYN 模式需要 root/admin；connect 模式适合无特权和本地测试。

更多“安全-标志位-输出”的对照解释见 [`docs/SECURITY_KNOWLEDGE.md`](docs/SECURITY_KNOWLEDGE.md)。

---

## 依赖安全

HTTP enrichment 使用 reqwest 0.12 / rustls 0.23。WHOIS 依赖链仍有待迁移到维护中的 DNS 库；提交依赖变更前运行 `cargo audit --no-fetch --stale`，并审阅 CI 中的每一个显式 advisory ignore。

---

## 许可证

MIT，详见 [`LICENSE`](LICENSE)。