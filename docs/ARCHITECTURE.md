# 架构与数据流

## 目标

IP-Scan 将“发现端口”和“理解资产”拆成可背压的流水线：扫描器负责高吞吐探测，SQLite 负责可靠落盘，enrichment worker 观察新落盘资产并异步补充上下文。

```text
IP range producer
      |
      v
TCP/SYN scanner -----> port_bitmaps/open_ports_detail -----> enrichment poller
                                                               |        |
                                                               v        v
                                                            GeoIP   ServiceProber
                                                               \      /
                                                                v    v
                                                            ip_details/service_info
                                                                  |
                                                        API / Web / export
```

## 组件

- `model/`：IP 范围、位图、指标、Geo 和服务信息模型。
- `service/con_scanner.rs`：TCP connect 扫描、信号量、速率限制、批量结果写入。
- `service/syn_scanner.rs`：需要平台能力的 SYN 发送/接收路径。
- `service/service_prober.rs`：HTTP、Banner、TLS、RTT 和轻量 OS 线索采集。
- `service/geo_service.rs`：MaxMind 或远程 GeoIP 查询。
- `main.rs`：扫描轮次和后台 enrichment 生命周期。
- `dao/sqlite_db.rs`：schema、迁移、批量写入、查询和历史清理。
- `api/`：状态、结果、服务信息和导出接口。

## 并行与一致性

开放端口通过数据库作为耐久化边界。扫描器可以继续生产，enrichment worker 每秒选取尚未补充的记录；Geo 与服务探测各自受信号量限制。写入使用幂等 UPSERT，进程中断后下一轮会继续补偿。

服务探测必须只对已确认开放的端口执行，并有独立超时和并发上限。所有外部请求都应可失败、可超时、不可阻塞扫描主路径。

## 扩展点

新增采集器时：

1. 在 `ServiceInfo` 或独立模型添加字段与 serde/API 映射。
2. 在 SQLite 创建语句和迁移数组中加入兼容迁移。
3. 在 `enrich_discovered_assets` 中作为独立受控 job 接入。
4. 增加超时、限速、失败日志和单元测试。
5. 更新 README、API schema 和导出字段。

## 资产风险提示

HTTP 探测同时记录常见安全响应头，并通过保守的响应体/Server 签名识别 Nginx、Apache、PHP、WordPress、Django、React、Vue、jQuery 等 Web 技术（仅作线索，不是漏洞证明）（CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy）的覆盖情况。服务摘要会根据已识别服务计算轻量级风险提示（不是漏洞扫描结论）：Telnet、远程桌面、数据库/搜索服务、邮件/文件服务和 Web 暴露会产生不同权重，并返回 `risk_score` 与 `risk_reasons`。该分数用于排序和人工复核，不应替代经过验证的漏洞扫描。
