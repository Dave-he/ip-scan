# 数据字典

本文档描述扫描结果中可被 API、Web 和导出使用的主要字段。字段可能为空；空值表示未启用对应 enrichment、目标未响应或探测器无法可靠解析，不表示字段为零。

## `open_ports_detail`

| 字段 | 含义 |
|---|---|
| `ip_address` | 目标 IP |
| `ip_type` | `IPv4` 或 `IPv6` |
| `port` | TCP 端口 |
| `scan_round` | 发现该记录的扫描轮次 |
| `first_seen` | 首次发现时间 |
| `last_seen` | 最近发现时间 |

## `ip_details`

| 字段 | 含义 |
|---|---|
| `country` / `region` / `city` | GeoIP 或 WHOIS 地理线索 |
| `isp` | ISP/组织线索 |
| `asn` | ASN/Origin AS 线索 |
| `reverse_dns` | PTR 主机名 |
| `source` | `MaxMind`、`Whois` 或远程 API 等来源 |

## `service_info`

| 字段 | 含义 |
|---|---|
| `service_name` | 按端口和 Banner 推断的服务 |
| `protocol` | 应用协议或 `tcp` |
| `banner` | 经截断的服务摘要 |
| `service_version` | 解析出的版本、Web 技术和 favicon hash 线索 |
| `http_title` | HTML `<title>` |
| `http_server` | HTTP `Server` 响应头 |
| `http_body_preview` | 清理后的有限 Body 预览 |
| `http_body_hash` | Body 内容哈希，用于变化/聚类线索 |
| `http_security_headers` | 常见安全 Header 覆盖情况 |
| `tls_subject` / `tls_issuer` | TLS 证书 CN/存在性线索 |
| `tls_version` | TLS 建连线索 |
| `rtt_ms` | 连接或 HTTP 请求往返时间 |
| `os_guess` | 基于 TTL 的粗粒度系统猜测 |
| `detected_at` | 服务信息采集时间 |

## `service_probe_state`

| 字段 | 含义 |
|---|---|
| `ip_address` | 尚未获得 `service_info` 的目标 IP，也是退避状态主键 |
| `last_probe` | 最近一次服务探测尝试的 RFC3339 时间；默认一小时后才允许重试 |

该表只控制后台 enrichment 的失败/空结果重试节奏，不作为资产或开放端口结论，也不通过 API 或导出直接暴露。

## 风险字段

服务摘要接口额外返回：

- `category`：资产类型，如 `web-server`、`database-server`。
- `risk_score`：0–100 的轻量暴露面排序分数。
- `risk_reasons`：触发分数的可解释原因。

风险分数不是 CVE、渗透测试或合规结论。确认漏洞前必须进行版本核验、配置审查和授权的专门测试。

## 变化接口

`/api/v1/stats/changes?round=3&port=443` 使用相邻 bitmap 轮次识别 `is_open` 状态变化，并返回 IP、端口和轮次。结果有上限，不代表变化全集。

## 运维接口

`/api/v1/healthz` 返回服务和数据库健康状态；数据库检查失败时返回 HTTP 503。

## 运维指标

`/api/v1/stats/prometheus` 提供 `ip_scan_open_port_records`、`ip_scan_unique_ips`、`ip_scan_database_bytes` 和 `ip_scan_round`。这些是观测指标，不是安全结论。

## 数据生命周期

- 扫描结果先进入 SQLite，enrichment 以幂等 UPSERT 补充信息。
- 网络超时和解析失败保留为空；服务探测按一小时退避重试，其他 enrichment 由后续轮次继续补偿。
- 服务 Banner、Body 预览和 WHOIS 数据可能包含敏感信息，生产环境应限制数据库、API 和导出文件访问。
- `port_bitmaps` 的旧扫描轮次会按配置清理；需要长期审计时应先备份数据库。
