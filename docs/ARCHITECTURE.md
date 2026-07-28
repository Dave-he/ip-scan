# 架构与数据流

## 目标

IP-Scan 将“发现端口”和“理解资产”拆成可背压的流水线：扫描器负责高吞吐探测，SQLite 负责可靠落盘，enrichment worker 观察新落盘资产并异步补充上下文。所有派生任务共享一个轻量的 `Arc<TaskContext>`（只装 `metrics`、`rate_limiter`、`result_tx`、扫描轮次、超时），避免每个任务克隆整个 `ConScanner`；任务体只调用无状态的 `scan_port_with_retry` 自由函数。

```text
IP range producer (IpRange::iter)
      |
      v
TCP/SYN scanner ───► port_bitmaps / open_ports_detail ───► enrichment poller (1s tick)
                                                              │           │
                                                              ▼           ▼
                                                          GeoIP      ServiceProber
                                                              \         /
                                                               ▼       ▼
                                                        ip_details / service_info
                                                                  │
                                                  API / Web / JSON+CSV export
```

## 组件

- `model/`：`IpRange` 与迭代器、`Bitmap`、`ScanMetrics`、`IpGeoInfo`、`ServiceInfo` / `IpServiceSummary`、`port` 解析。
- `service/con_scanner.rs`：TCP connect 扫描、信号量、令牌桶速率限制、批量结果写入。
- `service/syn_scanner.rs`：需要平台能力的 SYN 发送/接收路径；依赖 `pnet_packet` / `pnet_transport`；失败时上层会自动降级为 connect。
- `service/service_prober.rs`：HTTP、Banner、TLS、RTT、轻量 OS 线索采集；并发和超时与扫描器解耦。
- `service/geo_service.rs`：MaxMind 或远程 GeoIP 查询。
- `service/rate_limiter.rs`：无锁令牌桶（`try_acquire` / `try_acquire_batch` / 异步 `acquire`）；`max_rate == 0` 表示不限速。
- `service/scan_controller.rs`：被 API 调用来启停扫描任务（仅控制 API 发起的扫描，CLI 扫描不可被 API 终止）。
- `service/optimized_scanner.rs`：基于 `OptimizedScanner` 的 Skill / 单点扫描接口。
- `main.rs`：扫描轮次和后台 enrichment 生命周期。
- `dao/sqlite_db.rs`：schema、迁移、批量写入、查询、历史清理、WAL checkpoint。
- `api/`：状态、结果、服务信息和导出接口（基于 `actix-web` + `utoipa`）。

## 并行与一致性

开放端口通过数据库作为耐久化边界。扫描器可以继续生产；Connect scanner 在端口分发阶段也施加有界 `JoinSet` 背压（`max_inflight = concurrency × 8`），即使扫描 1-65535 也不会瞬间创建数万任务。Geo 与服务探测各自受信号量限制（默认 `--geo-concurrency 8`、单 IP 内 `--probe-concurrency 50`）。写入使用幂等 UPSERT，进程中断后下一轮会继续补偿。循环扫描保留最新两个 bitmap 轮次用于变化比较，按最大轮次计算清理边界；扫描热路径不执行全库 `VACUUM`。每轮结束后会触发一次被动 WAL checkpoint（`PRAGMA wal_checkpoint(PASSIVE)`），避免长跑场景下 WAL 文件膨胀。

Redis INFO 等协议握手只保留必要版本字段，不持久化完整敏感响应。服务探测必须只对已确认开放的端口执行，并有独立超时和并发上限。所有外部请求都应可失败、可超时、不可阻塞扫描主路径。

## CLI / API 协调

CLI（`--loop-mode`、`--no-api`、`--api`、`--api-only`）与 API 控制器之间共享一份 `RuntimeScanState`：

- CLI 启动的扫描：`source=cli`，`controllable=false`。此时 `/scan/start` 返回 `409 Conflict`，`/scan/stop` 返回 `SCAN_NOT_API_CONTROLLABLE`，避免重复启动或误报停止成功。
- API 启动的扫描：`source=api`，`controllable=true`，可被 `/scan/stop` 停止。
- 默认无参数时进入 API-only 模式，方便做容器探针和只读 Web UI。

## 扩展点

新增采集器时：

1. 在 `ServiceInfo` 或独立模型添加字段与 serde/API 映射。
2. 在 SQLite 创建语句和迁移数组中加入兼容迁移。
3. 在 `enrich_discovered_assets` 中作为独立受控 job 接入。
4. 增加超时、限速、失败日志和单元测试。
5. 更新 README、API schema 和导出字段。

## 资产风险提示

HTTP 页面 Body 与 favicon 请求并发执行，避免 favicon enrichment 串行增加一次 RTT；HTTP 探测同时记录常见安全响应头，并通过 favicon hash 及保守的响应体/`Server` 签名识别 Nginx、Apache、PHP、WordPress、Django、React、Vue、jQuery 等 Web 技术（仅作线索，不是漏洞证明）。安全响应头（CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy）的覆盖情况记录在 `http_security_headers` 中，0/5 或 1/5 会触发“Web 安全响应头缺失较多”提示。

服务摘要会根据已识别服务计算轻量级风险提示（不是漏洞扫描结论）：Telnet、远程桌面、数据库/搜索服务、邮件/文件服务和 Web 暴露会产生不同权重，并返回 `risk_score`（0–100）与 `risk_reasons`。该分数用于排序和人工复核，不应替代经过验证的漏洞扫描。详细的“端口/服务 ↔ 网安解读”参见 [SECURITY_KNOWLEDGE.md](./SECURITY_KNOWLEDGE.md)。