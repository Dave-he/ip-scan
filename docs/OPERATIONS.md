# 运维与安全

## 启动前预览

使用 `--dry-run` 可以解析配置文件、目标、端口、并发和 enrichment 选项，而不会打开网络 socket 或创建数据库：

```bash
ip-scan --dry-run --target 192.168.1.0/24 --ports 22,80,443
```

适合 CI 配置检查、容器启动探针和生产任务变更前确认。自动化脚本可增加 `--output-format json` 获取结构化计划。

## 最小安全配置

- 只扫描书面授权的网段。
- 默认使用小网段、低并发、有限端口；公网任务显式确认后再运行。
- API 不要直接暴露公网；生产环境绑定内网并通过认证反向代理保护。
- `--probe-service` 会产生应用层请求，按目标方策略启用。
- SYN 模式需要 root/admin；connect 模式适合无特权和本地测试。

## DNS 与外部请求

反向 DNS 默认读取系统 resolver 配置；容器或受限网络可设置 `IP_SCAN_DNS_SERVER`。GeoIP、WHOIS、DNS、HTTP/TLS 和 favicon enrichment 都可能产生外部流量，应在组织网络策略允许时启用；启用服务探测会比纯端口扫描产生更多目标侧请求。

## 性能调优

- `--concurrency` 控制连接任务，`--max-rate` 控制速率上限；CLI 会在启动前拒绝 0 值并发、超时、缓冲区和速率配置。
- `--pipeline-buffer`、`--result-buffer` 和 `--db-batch-size` 影响内存与吞吐。
- GeoIP/WHOIS/DNS 使用独立 `--geo-concurrency`（默认 8），服务探测使用 `--probe-concurrency`；两者不要与扫描并发简单相加。
- SQLite 使用 WAL；定期备份数据库。循环模式保留最新两个 bitmap 轮次，旧轮次删除后由 SQLite 复用空间，不在扫描热路径执行全库 `VACUUM`。

## 监控

`/api/v1/stats/changes?round=3&port=443` 可对比相邻扫描轮次，返回新增/消失的 IPv4 端口状态，单次最多 10000 条。负载均衡器可检查 `/api/v1/healthz`；数据库不可用时返回 503。Prometheus 可抓取 `/api/v1/stats/prometheus`，当前提供开放记录数、唯一 IP 数、位图存储大小和扫描轮次。生产环境应通过内网、反向代理和访问控制保护该端点。

## 故障排查

1. 查看 `--verbose` 日志确认目标解析、超时和权限。
2. SYN 失败时先切换 connect 模式验证网络，再检查 Npcap/root。
3. Geo 没有结果时检查 MaxMind 路径或关闭 `--no-geo` 以外的配置。
4. 服务信息为空时确认端口开放、目标允许应用层握手，避免把超时误认为关闭。
5. 使用 `cargo test --offline`、`cargo fmt --check` 验证构建健康。

## 依赖安全审计

使用以下命令执行不联网审计（使用本机已缓存的 RustSec 数据库）：

```bash
cargo audit --no-fetch --stale
```

当前锁定依赖审计已通过升级 reqwest 0.12 / rustls 0.23 消除了 rustls-webpki 的漏洞，但 WHOIS 传递依赖仍触发 RUSTSEC-2024-0421；同时仍报告 `bincode`、`proc-macro-error`、`trust-dns` 的 unmaintained 警告，以及 `anyhow`/`rand` 的未来公告。CI 只对后两项 unsound advisory 保留显式、可审计的 ignore；升级依赖时必须重新运行测试、检查 TLS/WHOIS 行为，并删除对应 ignore，而不是静默隐藏审计结果。

## SQLite 性能

数据库初始化时启用 WAL、NORMAL 同步级别、5 秒 busy timeout、64 MiB page cache、64 MiB WAL 文件上限、自动 checkpoint 和内存临时表；启动时会截断已完成 checkpoint 的陈旧 WAL。busy timeout 用于平滑扫描器与 enrichment worker 的短时写入竞争；不要把它当成无限重试，长时间锁竞争仍应通过降低并发或拆分数据库实例处理。需要回收主数据库空闲页时，应在计划维护窗口停扫后执行 `VACUUM`，不得每轮执行。

## 服务探测退避

服务探测失败或返回空结果时会记录 `service_probe_state`，同一 IP 默认至少间隔一小时才会重试，避免不可达主机在后台轮询中持续消耗连接、超时和日志资源。发现新的开放服务后，仍会通过 `service_info` 的幂等记录继续处理。
