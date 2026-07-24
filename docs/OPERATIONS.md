# 运维与安全

## 最小安全配置

- 只扫描书面授权的网段。
- 默认使用小网段、低并发、有限端口；公网任务显式确认后再运行。
- API 不要直接暴露公网；生产环境绑定内网并通过认证反向代理保护。
- `--probe-service` 会产生应用层请求，按目标方策略启用。
- SYN 模式需要 root/admin；connect 模式适合无特权和本地测试。

## DNS 与外部请求

反向 DNS 默认读取系统 resolver 配置；容器或受限网络可设置 `IP_SCAN_DNS_SERVER`。GeoIP、WHOIS、DNS、HTTP/TLS 和 favicon enrichment 都可能产生外部流量，应在组织网络策略允许时启用；启用服务探测会比纯端口扫描产生更多目标侧请求。

## 性能调优

- `--concurrency` 控制连接任务，`--max-rate` 控制速率上限。
- `--pipeline-buffer`、`--result-buffer` 和 `--db-batch-size` 影响内存与吞吐。
- 服务探测使用独立 `--probe-concurrency`，不要与扫描并发简单相加。
- SQLite 使用 WAL；定期备份数据库，循环模式会清理过旧 bitmap 轮次。

## 监控

`/api/v1/stats/changes?round=3&port=443` 可对比相邻扫描轮次，返回新增/消失的 IPv4 端口状态，单次最多 10000 条。负载均衡器可检查 `/api/v1/healthz`；数据库不可用时返回 503。Prometheus 可抓取 `/api/v1/stats/prometheus`，当前提供开放记录数、唯一 IP 数、位图存储大小和扫描轮次。生产环境应通过内网、反向代理和访问控制保护该端点。

## 故障排查

1. 查看 `--verbose` 日志确认目标解析、超时和权限。
2. SYN 失败时先切换 connect 模式验证网络，再检查 Npcap/root。
3. Geo 没有结果时检查 MaxMind 路径或关闭 `--no-geo` 以外的配置。
4. 服务信息为空时确认端口开放、目标允许应用层握手，避免把超时误认为关闭。
5. 使用 `cargo test --offline`、`cargo fmt --check` 验证构建健康。
