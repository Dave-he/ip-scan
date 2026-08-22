# IP-Scan

> Rust/Tokio 驱动的 IPv4/IPv6 资产发现与服务识别工具。仅对你拥有或获授权的网络执行扫描。

IP-Scan 不只是“端口是否打开”：扫描器写入开放端口的同时，后台 enrichment worker 持续消费新资产，补充 GeoIP、服务类型、Banner、HTTP 标题/Server、TLS 证书线索、RTT、OS guess 和资产分类，并统一保存到 SQLite，供 API、Web UI 和 CSV/JSON 导出使用。

## 能力概览

- **扫描**：IPv4/IPv6、单 IP/CIDR/范围、TCP connect；具备权限时可使用 SYN。
- **流水线**：扫描结果写库后立即进入 GeoIP 与服务探测队列，不必等待整轮结束。
- **服务识别**：HTTP/HTTPS、SSH、FTP、SMTP、POP3、IMAP、Redis 等 Banner/协议探测；HTTP 采集状态码、标题、Server 和 Body 预览。
- **TLS/主机线索**：HTTPS TLS 建连、证书 DER/CN 线索、TTL OS guess、RTT、版本字段。
- **数据**：SQLite WAL、批量写入、增量进度、扫描轮次、开放端口历史、Geo 信息、服务信息和轻量风险提示。
- **接口**：Actix Web API、Swagger/OpenAPI、Web 管理界面、JSON/CSV 导出。
- **工程性**：限速、并发控制、超时、断点续扫、循环扫描、旧轮次清理、结构化日志。

## 带宽测试 (`--bench-bandwidth`)

`ip-scan` 现在也能做端到端的带宽/RTT 测量：从 `lists/cn_top_1000.csv` 加载 2000+ 中文域名（百度/腾讯/阿里/字节/京东/B 站/CDN/政府/银行/AI/工具…），对每个域名多轮发起 `Range: bytes=0-1MiB` 的 HTTPS GET，分别记录 DNS / TCP / TTFB / Transfer 耗时，按 `bytes * 8 / transfer_ms` 给出 Mbps 吞吐量，并按 CV(median_throughput) ≤ 0.10 ∧ CV(median_rtt) ≤ 0.15 ∧ ok% ≥ 60% 连续 3 轮触发稳定性停止规则。

```bash
# 内置清单
./target/release/ip-scan --bench-bandwidth --node-id local-mac

# 自定义清单 + 更激进的并发
./target/release/ip-scan --bench-bandwidth \
    --bench-domain-file my-list.csv \
    --bench-concurrency 200 \
    --bench-bytes 2097152 \
    --bench-rounds 5 \
    --bench-output-dir results/bandwidth
```

报告写在 `results/bandwidth/<node_id>/<YYYY-MM-DD>/`：

- `bench-r{N}.jsonl.gz` — 每轮所有样本的 gzipped JSONL
- `bench.csv` — 全量 CSV（每行 = 一次样本，列同 JSONL）
- `bench-summary.md` — 每域名 n / ok% / p50 / p95 汇总表
- `scan_results.db` — 同步写入 `bandwidth_samples` 表，可 SQL 二次分析

样本字段：`ts, round, attempt, target, ip, port, dns_ms, tcp_ms, ttfb_ms, transfer_ms, total_ms, bytes, throughput_mbps, http_status, server, via, content_encoding, accept_ranges, range_ok, error, node_id`。`error` 取值包括 `dns_err / tcp_timeout / tcp_err / http_timeout / http_err / blocked / rate_limited / small_body`；空 = 成功。

## nmap 兼容

`ip-scan` 接受 nmap 风格 flag 的 long form：`--sS`、`--sT`、`--sV`、`--O`、`--A`、`--F`、`--top-ports N`、`--iL <file>`、`--T<n>`、`--oN <base>`、`--oX <base>`、`--oG <base>`、`--oJ <base>`、`--oA <base>` 等。

`--oN/--oX/--oG/--oJ/--oA` 在扫描结束后产出对应的 `.nmap` / `.xml` / `.gnmap` / `.json` 文件，可直接喂给 nmap 生态工具；`-oA <base>` 一次写三种。

```bash
./target/release/ip-scan -p 22,80,443 --oN scan.nmap --oA scan 127.0.0.1
# -> scan.nmap, scan.xml, scan.gnmap
```

完整的兼容矩阵与限制请见 [`docs/BENCHMARK_VS_NMAP.md`](docs/BENCHMARK_VS_NMAP.md)。

## 性能

`bench/run.sh` 在本机（6 核 macOS）跑 3 次/场景，结果（详见报告）：

| 场景 | ip-scan p50 | nmap p50 | nmap p95 | 加速比 |
|------|------------:|---------:|---------:|-------:|
| top100 | 0.7 s | 0.07 s | 0.34 s | 0.5× (nmap 较快) |
| top1000 | 4.5 s | 30.1 s | 30.1 s | **6.7×** |
| 1-1024 | 4.6 s | 30.1 s | 30.2 s | **6.6×** |

`top100` 这一档因 nmap 赶在 timeout 之前跑完，task-per-port 的开销大于 nmap 单流；超过这个量级，ip-scan 的高并发 token-bucket 路径稳定保持 ~7× 加速。

跑法：

```bash
cargo build --release
./bench/run.sh 3
python3 bench/report.py
```

## 依赖安全

HTTP enrichment 使用 reqwest 0.12 / rustls 0.23。WHOIS 依赖链仍有待迁移到维护中的 DNS 库；提交依赖变更前运行 `cargo audit --no-fetch --stale`，并审阅 CI 中的每一个显式 advisory ignore。

## 安全边界

只扫描明确授权的资产。默认建议跳过私网或限制到实验网段；不要把公网大范围扫描、Banner 探测或高并发作为默认行为。SYN、服务探测和 TLS/HTTP 请求可能被目标侧记录或拦截，请遵守法律、合同和组织策略。

## 分布式前端（多服务器）

`web/` 目录同时承载单节点嵌入式 UI 和多节点分布式控制台（旧的 `frontend/`
已合并进来）。把 `ip-scan` 部署到任意数量的服务器后，在本地启动前端连
接它们：

```bash
# 1. 在每台扫描节点上启动纯 API（记得加身份）
./ip-scan --api-only --node-id ali-sh --node-label "ali-shanghai" \
    --node-latitude 31.23 --node-longitude 121.47 --api-port 9090
./ip-scan --api-only --node-id tx-bj  --node-label "tx-beijing"  \
    --node-latitude 39.90 --node-longitude 116.40 --api-port 9090

# 2. 在任意机器上启动统一前端
node scripts/serve-frontend.mjs 4000
# 打开 http://localhost:4000 — 默认会自动连接 web/src/config.js 里写的两个节点
# 想换默认节点直接编辑 DEFAULT_NODES 数组；想运行时注入也可以：
#   <script>window.IPSCAN_DEFAULT_NODES = [...]</script>   (放在 index.html 之前)
# 用户在侧边栏点 X 删除 / + 服务器 添加任意节点后，配置就以用户为准、DEFAULT_NODES 失效
```

如果只是想看本机嵌入式 UI，直接 `cargo run -- --api` 然后访问
`http://127.0.0.1:9090/` 即可 —— 同一份 `web/` 既是嵌入式 UI，又是
分布式控制台，二者共用 BackendClient / Aggregator / 视图层。

前端会自动跨节点聚合结果，并提供 8 种浏览模式：
- **总览**：集群规模、节点贡献热力图、TOP 服务
- **地图视图**：全球 Leaflet 地图 · 每点一个独立 IP · 点击查看端口与服务 · 节点自身用紫色脉冲标记
- **服务类型**：按 service_name（ssh / http / mysql / redis …）聚合
- **IP 族**：IPv4 / IPv6 拆分 + 资产分类拆分 + **ASN / ISP 分布柱状图**
- **资产库**：可按服务 / 国家 / 风险等级过滤的独立 IP 列表 · 一键进入 IP 详情面板
- **节点列表 / 结果明细 / 扫描控制**
- **IP 详情面板（滑出式）**：在地图、结果、资产库任意位置点击 IP 即弹出，展示完整开放端口、Banner、HTTP title、TLS subject/issuer、原始抓包字节、同 ASN/ISP 的邻居 IP 数和风险评分

完整说明见 [](docs/DISTRIBUTED.md)。

## 下载与安装

每个 GitHub tag 都自动构建并发布跨平台产物（详见 `.github/workflows/release.yml`）：

| 资产 | 平台 | 说明 |
| --- | --- | --- |
| `ip-scan-linux-x86_64-musl` | Linux x86_64 | static-pie · 无动态依赖 · 推荐大多数服务器 |
| `ip-scan-linux-x86_64` | Linux x86_64 | glibc 动态链接 |
| `ip-scan-linux-aarch64-musl` | Linux aarch64 | ARM64 static-pie |
| `ip-scan-linux-aarch64` | Linux aarch64 | ARM64 glibc |
| `ip-scan-macos-x86_64` | macOS Intel | |
| `ip-scan-macos-aarch64` | macOS Apple Silicon | |
| `ip-scan-windows-x86_64` | Windows x86_64 | MSVC · 启用 SYN 时需要 Npcap |

每个 tarball / zip 同时打包二进制、`web/` 静态资源和 `config.toml`：

```bash
# Linux x86_64 (musl)
tar xzf ip-scan-linux-x86_64-musl.tar.gz
./ip-scan --api --node-id my-node --node-label "my-node"     --node-latitude 31.23 --node-longitude 121.47

# macOS Apple Silicon
tar xzf ip-scan-macos-aarch64.tar.gz
./ip-scan --api
```

或运行一键安装脚本（自动检测平台、下载最新 release 并校验 SHA256）：

```bash
curl -sSL https://raw.githubusercontent.com/Dave-he/ip-scan/main/scripts/install.sh | bash
```

Docker：

```bash
docker compose up -d     # 启动单机 + WebUI（端口 9090 / 4000）
```

手动编译参考 `docs/OPERATIONS.md` 与 `AGENTS.md` 中的交叉编译步骤。

## 快速开始

```bash
cargo build --release

# 先解析配置和目标，不创建数据库、不连接目标
./target/release/ip-scan --dry-run --target 192.168.1.0/24 --ports 22,80,443
./target/release/ip-scan \
  --target 192.168.1.0/24 \
  --ports 22,80,443,3306,5432,6379,8080 \
  --concurrency 100 \
  --timeout 500 \
  --probe-service \
  --no-api
```

启动 API 与 Web：

```bash
./target/release/ip-scan --api --target 192.168.1.0/24 --ports 22,80,443 --probe-service
# 默认: http://127.0.0.1:9090
# OpenAPI: http://127.0.0.1:9090/api-docs/openapi.json
# Prometheus: http://127.0.0.1:9090/api/v1/stats/prometheus
# Health: http://127.0.0.1:9090/api/v1/healthz
# Health: http://127.0.0.1:9090/api/v1/healthz
# Round changes: http://127.0.0.1:9090/api/v1/stats/changes?round=3&port=443
```

本地测试：

```bash
cargo test --offline
cargo fmt --check
```

## 常用参数

| 参数 | 说明 |
|---|---|
| `--target` | IP、CIDR 或起止范围，例如 `10.0.0.0/24` |
| `--dry-run` | 输出合并后的扫描计划并退出，不打开 socket 或数据库；配合 `--output-format json` 可供脚本读取 |
| `--start-ip/--end-ip` | 传统范围写法 |
| `--ports` | `80`、`22,80,443`、`1-1024`、混合范围 |
| `--preset quick\|standard\|deep` | 预设扫描端口集合 |
| `--concurrency` | TCP 扫描并发数 |
| `--timeout` | TCP 连接超时（毫秒） |
| `--probe-service` | 对新发现开放端口做 Banner/HTTP/TLS 探测 |
| `--probe-concurrency` | 单 IP 内服务探测并发数 |
| `--no-geo` | 禁用 GeoIP enrichment |
| `--geoip-db PATH` | MaxMind 数据库路径（可选） |
| `--geo-concurrency` | GeoIP、WHOIS 和反向 DNS 并发数，默认 8 |
| `--syn` | SYN 扫描，需要 root/admin 和平台抓包支持 |
| `--max-rate` | 统一速率上限 |
| `--loop-mode` | 持续轮询扫描 |
| `--round-delay-ms` | 轮询扫描下两轮之间的间隔（毫秒，默认 0；扫描固定子网时建议 1000–5000 以免过度打同一段） |
| `--skip-private` | 跳过 RFC1918 私网 IPv4 |
| `--api` / `--api-only` | 启用 API / 仅启动 API |
| `--database PATH` | SQLite 文件路径 |

所有 CLI 选项也支持对应的 `SCAN_*` 环境变量；并发数、超时、缓冲区和速率不能设置为 0，非法配置会在启动前直接报错。完整参数以 `ip-scan --help` 为准。反向 DNS 支持 IPv4 与压缩形式 IPv6，默认读取系统 `/etc/resolv.conf`，也可通过 `IP_SCAN_DNS_SERVER=192.0.2.53` 指定 DNS。

## 新增 API（IP 详情 / 资产库 / ASN 聚合）

`/api/v1/ip/{ip}` 单端点返回某 IP 的完整视图：地理、ASN、ISP、开放端口、服务识别、风险评分、同 ASN / ISP 邻居 IP 数。配合 `/api/v1/snapshots/{ip}` 还能看到 banner / HTTP title / TLS subject / 原始抓包首字节。

新增端点：

| 端点 | 说明 |
| --- | --- |
| `GET /api/v1/ip/{ip}` | 单 IP 详情 |
| `GET /api/v1/assets?page=&page_size=&country=&service=&category=&min_risk=` | 独立 IP 分页列表 |
| `GET /api/v1/snapshots/{ip}` | 抓包 + HTTP/TLS 元数据 |
| `GET /api/v1/stats/by-asn` | 按自治域聚合 |
| `GET /api/v1/stats/by-organization` | 按 ISP / 组织聚合 |

字段说明见 [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) 和 [`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md)。

## 数据与 API

主要表：

- `open_ports_detail`：IP、端口、类型、首次/最近发现、扫描轮次
- `port_bitmaps`：高密度扫描状态与轮次
- `ip_details`：国家、地区、城市、ISP、ASN、反向 DNS、来源
- `service_info`：服务、协议、Banner、HTTP、TLS、版本、RTT、OS guess；服务摘要还提供风险分数和原因
- `scan_metadata`：运行状态、进度和轮次元数据

API 路径前缀为 `/api/v1/`，Swagger/OpenAPI 可查看实际路由和字段。服务信息查询示例：

```bash
curl http://127.0.0.1:9090/api/v1/services/192.168.1.10
curl http://127.0.0.1:9090/api-docs/openapi.json
```

`/api/v1/scan/status` 同时报告 CLI 与 API 发起的扫描；`source` 标识来源，`controllable` 表示能否通过 API 停止。

## 配置、部署与文档

- 示例配置：[`config.toml`](config.toml)
- 架构与流水线：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 前后端协议契约：[`docs/API_CONTRACT.md`](docs/API_CONTRACT.md)
- 数据字典：[`docs/DATA_DICTIONARY.md`](docs/DATA_DICTIONARY.md)
- 运维与安全：[`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- 分布式多服务器前端：[`docs/DISTRIBUTED.md`](docs/DISTRIBUTED.md)
- AI/自动化修改规则：[`AGENTS.md`](AGENTS.md)
- 技能说明：[`SKILL_README.md`](SKILL_README.md)
- 贡献指南：[`CONTRIBUTING.md`](CONTRIBUTING.md)

Docker、反向代理和 Windows Npcap 说明见 `docker-compose.yml`、`Dockerfile`、`nginx.conf` 及架构文档。

## 许可证

MIT，详见 [`LICENSE`](LICENSE)。
