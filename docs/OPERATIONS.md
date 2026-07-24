# 运维与安全

## 最小安全配置

- 只扫描书面授权的网段。
- 默认使用小网段、低并发、有限端口；公网任务显式确认后再运行。
- API 不要直接暴露公网；生产环境绑定内网并通过认证反向代理保护。
- `--probe-service` 会产生应用层请求，按目标方策略启用。
- SYN 模式需要 root/admin；connect 模式适合无特权和本地测试。

## DNS 与外部请求

反向 DNS 默认读取系统 resolver 配置；容器或受限网络可设置 `IP_SCAN_DNS_SERVER`。GeoIP、WHOIS、DNS、HTTP/TLS enrichment 都可能产生外部流量，应在组织网络策略允许时启用。

## 性能调优

- `--concurrency` 控制连接任务，`--max-rate` 控制速率上限。
- `--pipeline-buffer`、`--result-buffer` 和 `--db-batch-size` 影响内存与吞吐。
- 服务探测使用独立 `--probe-concurrency`，不要与扫描并发简单相加。
- SQLite 使用 WAL；定期备份数据库，循环模式会清理过旧 bitmap 轮次。

## 故障排查

1. 查看 `--verbose` 日志确认目标解析、超时和权限。
2. SYN 失败时先切换 connect 模式验证网络，再检查 Npcap/root。
3. Geo 没有结果时检查 MaxMind 路径或关闭 `--no-geo` 以外的配置。
4. 服务信息为空时确认端口开放、目标允许应用层握手，避免把超时误认为关闭。
5. 使用 `cargo test --offline`、`cargo fmt --check` 验证构建健康。
