# 网络安全知识对照表

> **定位**：把 IP-Scan 的每一个端口号、Banner 字段、HTTP 响应头、TLS 线索和 OS guess 翻译成可操作的网安解读。
>
> 本文档**不是漏洞定义或渗透测试结论**。任何结论性判断必须结合版本核验、配置审查和经过授权的复测。

---

## 1. 阅读本表的方式

IP-Scan 在三层输出信号里携带信息：

1. **端口/协议层**：`open_ports_detail` 的 `ip:port` 对。这是**可访问性**的最强信号。
2. **Banner / 应用层**：`service_info` 的 `service_name`、`banner`、`service_version`、`http_title`、`http_server`、`os_guess`。这是**指纹/版本**信号。
3. **配置 / 加密层**：`tls_subject`、`tls_issuer`、`tls_not_before`、`tls_not_after`、`tls_version`、`http_security_headers`。这是**纵深防御**信号。

读表时按这个顺序由粗到细：先看开放了哪些“硬暴露面”，再看 Banner 暴露了哪些版本线索，最后看 TLS/Header 暴露了哪些配置弱点。

---

## 2. 端口 ↔ 服务 ↔ 风险速查

下表把 IP-Scan 默认端口集（含 `ServiceInfo::guess_service_name` 与 `IpServiceSummary::categorize` / `assess_risk` 的内置规则）映射到常见风险点。`risk_score` 列就是后台 `IpServiceSummary::assess_risk` 给出的最高权重（0–100）。

| 端口 | 协议 | 服务名 | 含义与典型风险 | 默认 `risk_score` |
|---|---|---|---|---|
| 21 | TCP | ftp | 明文文件传输；口令、Banner、内容全程明文。SFTP/SCP/FTPS 是替代方案。 | 40 |
| 22 | TCP | ssh | 加密远程管理。关注 Banner 中 `OpenSSH` / `libssh` 版本，弱口令与密钥复用是主要风险。 | 0 |
| 23 | TCP | telnet | **明文远程管理**，包含口令嗅探与中间人风险；任何对外暴露都是高危。 | **90** |
| 25 | TCP | smtp | 邮件中继。开放转发（Open Relay）会被滥用为垃圾邮件跳板；关注 STARTTLS 支持情况。 | 40 |
| 53 | TCP/UDP | dns | DNS。递归开放 + 版本 BIND/PowerDNS 暴露可被用于反射放大与缓存投毒。 | 0（视配置） |
| 80 | TCP | http | 明文 HTTP；可能强制 301 → HTTPS，也可能仅是 Web 前端。 | 20 |
| 110 | TCP | pop3 | 明文邮件收取；早已被 POP3S (995) 取代，开放 110 多半是历史遗留。 | 40 |
| 111 | TCP/UDP | rpcbind | RPC 端口映射；互联网暴露是历史经典 NFS/rpc 漏洞利用入口。 | 视配置 |
| 135 | TCP | smb-rpc | Windows RPC；内部 AD 环境常见，外网暴露需立刻收敛。 | 视配置 |
| 139 | TCP | netbios-ssn | NetBIOS 会话；SMB 的明文时代协议，建议彻底关闭。 | 视配置 |
| 143 | TCP | imap | 明文邮件收取；同样应替换为 IMAPS (993)。 | 40 |
| 443 | TCP | https | TLS Web 服务。关注证书 CN/Issuer/有效期和 `tls_version`。 | 20 |
| 445 | TCP | smb | Windows SMB；WannaCry/EternalBlue 类漏洞的历史温床，必须禁止外网暴露。 | 视配置 |
| 465 | TCP | smtps | 隐式 TLS 的 SMTP 提交端口。 | 40 |
| 514 | UDP | syslog | 明文日志；伪造日志注入与未授权读取风险。 | 视配置 |
| 587 | TCP | submission | SMTP 提交端口（明文或 STARTTLS）。 | 40 |
| 636 | TCP | ldaps | 加密 LDAP。 | 视配置 |
| 873 | TCP | rsync | 文件同步；常见未鉴权 `rsync --daemon`，可被整盘镜像。 | 视配置 |
| 989/990 | TCP | ftps | FTP over TLS / FTP 控制通道加密。 | 40 |
| 993 | TCP | imaps | 加密 IMAP。 | 视配置 |
| 995 | TCP | pop3s | 加密 POP3。 | 视配置 |
| 1433 | TCP | mssql | SQL Server；强口令 + 防火墙白名单是基线。 | 75 |
| 1521 | TCP | oracle | Oracle DB；TNS 监听暴露常被扫描。 | 75 |
| 1723 | TCP | pptp | 已不安全的 VPN；建议替换为 WireGuard / OpenVPN / IPsec。 | 视配置 |
| 2049 | TCP | nfs | NFS；默认鉴权较弱，注意 `no_root_squash`。 | 视配置 |
| 2375/2376 | TCP | docker | Docker API；`2375` 是**未加密未鉴权**的远程 Docker 接口，是最严重的失分项之一。 | 视配置 |
| 3000 | TCP | http-alt | 常见 Node/React dev server、Grafana、Consul。 | 20 |
| 3306 | TCP | mysql | MySQL；鉴权失败次数与 LOAD DATA LOCAL INFILE 是常见利用点。 | 75 |
| 3389 | TCP | rdp | Windows 远程桌面；暴力破解、BlueKeep (CVE-2019-0708) 等漏洞历史暴露面广。 | **60** |
| 5000 | TCP | http-alt | Python/Flask、Airflow、Control Center 等开发栈。 | 20 |
| 5432 | TCP | postgresql | PostgreSQL；通常比 MySQL 鉴权更严，但仍需白名单。 | 75 |
| 5601 | TCP | kibana | Kibana（HTTP 暴露 + 早期未鉴权版本）。 | 20 |
| 5900 | TCP | vnc | VNC 远程桌面；常见弱口令，且无原生加密。 | **60** |
| 6379 | TCP | redis | Redis；**默认无鉴权**直接绑定 0.0.0.0 是公开悬赏池里的常客。 | **75** |
| 8000–8001 | TCP | http-alt | Django/Flask admin。 | 20 |
| 8080 | TCP | http-alt | 替代 HTTP；Tomcat、Spring Boot 默认端口。 | 20 |
| 8443 | TCP | https-alt | 替代 HTTPS；同上，关注证书与 Web 中间件版本。 | 20 |
| 8888 | TCP | http-alt | Jupyter Notebook / Mager / 各种控制台；常出现未鉴权面板。 | 20 |
| 9100 | TCP | jetdirect | 原始 TCP 打印（PJL）；可被用来读取打印作业 / 重置打印机。 | 视配置 |
| 9200 | TCP | elasticsearch | Elasticsearch；**历史默认无鉴权**，常被勒索脚本扫到。 | **75** |
| 11211 | TCP | memcached | Memcached；UDP 反射放大攻击源，**强烈不建议**公网暴露。 | 75 |
| 27017 | TCP | mongodb | MongoDB；**历史默认无鉴权**，2017 年大规模被勒索扫到。 | **75** |

> 风险评分（0–100）来源：`src/model/service_info.rs` 的 `IpServiceSummary::assess_risk`。分数用于**排序和人工复核**，不应替代漏洞扫描。

---

## 3. Banner 解读

`service_info.banner` 给出的是协议握手第一行 / 前若干字节（截断）。常见的可读字段：

### 3.1 SSH (22)

- 形如 `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`。
- 直接暴露 `OpenSSH` 版本、内核/发行版（`Ubuntu-3ubuntu0.6` 是 Debian 安全补丁编号）。攻击者可据此精确比对 CVE。
- 关注点：
  - `OpenSSH < 7.4` 的弱密钥协商；
  - `OpenSSH < 8.5` 的 `ssh-agent` / PKCS#11 历史 CVE；
  - `libssh` 在 0.6–0.7.x 的鉴权绕过；
  - 自定义 Banner `Authorized access only` 仅是法律告知，不构成任何保护。

### 3.2 FTP (21)

- 形如 `220 ProFTPD 1.3.5e Server` 或 `220 (vsFTPd 3.0.3)`。
- 关注点：未启用 TLS（FTPS = 990）、匿名账户 (`anonymous`) 启用、未禁用明文口令。

### 3.3 SMTP (25)

- 形如 `220 mail.example.com ESMTP Postfix`。
- 关注点：是否 `STARTTLS`、是否启用 `AUTH`、是否做 Open Relay（用 `ehlo` 后 `mail from:` 测试外发）。

### 3.4 HTTP (80 / 8080 / 8000 / …)

- `http_server` 形如 `nginx/1.18.0`、`Apache/2.4.41 (Ubuntu)`、`Microsoft-IIS/10.0`。
- `http_title` 暴露应用名（`Jenkins Dashboard`、`Kibana`、`Grafana`、`Welcome to nginx!`），常被用于指纹识别。
- `service_version` 在启用 favicon 指纹后会给出 Web 技术栈：`Nginx`、`Apache`、`PHP`、`WordPress`、`Django`、`React`、`Vue`、`jQuery` 等——**仅作线索，不是漏洞证明**。

### 3.5 Redis (6379)

- 形如 `-NOAUTH Authentication required.` 表示已开鉴权；连接成功直接是 `PING` → `+PONG` 则是**未鉴权**——必须立刻收敛。

### 3.6 MongoDB (27017)

- 旧版本（< 2.6）默认监听所有接口且无鉴权；现代版本默认 127.0.0.1。Banner 通常很短，但 `ismaster` 命令会回显版本。

### 3.7 Elasticsearch (9200)

- 形如 `You Know, for Search`；可匿名访问 `/_cat/indices` 通常就意味着“完全开放”。

---

## 4. HTTP 安全响应头

`http_security_headers` 用 `n/5` 形式记录以下 5 个常见头是否命中：

| 头 | 作用 | 缺失风险 |
|---|---|---|
| `Content-Security-Policy` | 限制脚本/资源来源 | XSS 利用面扩大 |
| `Strict-Transport-Security` | 强制 HTTPS | 中间人降级到 HTTP |
| `X-Content-Type-Options: nosniff` | 禁止 MIME 嗅探 | 旧的 IE MIME 嗅探利用 |
| `X-Frame-Options` / `frame-ancestors` | 防点击劫持 | UI-Redress 攻击 |
| `Referrer-Policy` | 控制 Referer 泄漏 | 跨站 Referer 泄漏内部 URL |

`0/5` 或 `1/5` 会触发 `Web 安全响应头缺失较多` 的 `risk_reasons`。HTTP 暴露都会得到至少 20 分的 `risk_score`。

---

## 5. TLS 线索

`service_info.tls_*` 是扫描器在 `--probe-service` 时做 TLS ClientHello 抓回来的：

| 字段 | 含义 | 解读 |
|---|---|---|
| `tls_subject` | 证书 CN/SAN | 是否与业务域名匹配；多域名/Pinning 异常说明需要重新签发 |
| `tls_issuer` | 颁发者 | 自签证书、对接测试用证书经常暴露内部 CA 名 |
| `tls_not_before` / `tls_not_after` | 有效期 | 临近过期、未生效（时钟漂移）、过期多年都是风险信号 |
| `tls_version` | 握手协议版本 | 出现 `TLSv1.0` / `TLSv1.1` 即说明仍支持弱协议，应禁用 |

`tls_not_after` 存在但 `tls_version` 缺失会触发 `TLS 证书信息不完整` 的 `risk_reasons`（35 分），常见于证书链配置错误导致抓取失败。

---

## 6. OS Guess 与 RTT

### 6.1 OS Guess

`os_guess` 由 `ServiceInfo::guess_os_from_ttl` 给出，基于初始 TTL 的粗粒度归类：

| TTL 区间 | 推测 |
|---|---|
| 0–32 | Windows (Vista+) |
| 33–64 | Linux/Unix/macOS |
| 65–128 | Windows (older) |
| 129–255 | UNIX（路由/封装后） |

注意：

- 经过的跳数会降低 TTL；这里的区间针对**抓包时观察到的剩余 TTL**。
- 该字段只是辅助，**不可作为安全策略依据**。

### 6.2 RTT

`rtt_ms` 是 TCP 三次握手 / HTTP GET 的往返时间。同一网段下 RTT 远高于均值的主机可能：

- 处于跨区域 / 跨运营商；
- 触发反爬限流后才响应；
- 链路存在 QoS 限速。

---

## 7. GeoIP 字段

`ip_details.country / region / city / isp / asn / reverse_dns`：

- `reverse_dns` 暴露内部主机名（如 `db-prod-03.corp.example.com`）时，应关注**主机命名约定本身**是否泄漏架构信息。
- `asn` 与 `isp` 可帮助判断资产是否在云上（`AS-XXX` 是 AWS/Azure/GCP/AliCloud/Tencent 等常见 ASN）。

---

## 8. CLI 标志 ↔ 安全语义

| CLI 标志 | 网安侧解读 |
|---|---|
| `--syn` | 半连接扫描，速度快、对目标侧日志“轻量”；需要 root/admin。注意 SYN 失败会自动降级到 connect。 |
| `--probe-service` | 启用后会产生 HTTP GET、TLS ClientHello、协议 Banner 抓取等应用层请求，会被 WAF / 蜜罐记录。生产环境慎用。 |
| `--skip-private` | 默认开启；只扫描授权公网时务必显式 `--skip-private false` 并保留显式目标文件。 |
| `--scan-public` | 显式开启“扫描公网 IPv4 空间”开关；默认关闭。开启前必须已有书面授权，否则违反项目安全边界与多数司法管辖区法律。 |
| `--max-rate` | 令牌桶速率上限（packets/sec）。设 0 表示不限速；公网任务请保持有限值（≥1000）以避免触发告警。 |
| `--round-delay-ms` | 循环扫描两轮间隔（毫秒）。固定子网循环建议 1000–5000，避免每分钟都打满同一段。 |
| `--only-store-open` | 仅持久化开放端口；显著减小数据库体积，且不会泄露 closed/filtered 状态。 |
| `--concurrency` | 同时进行的连接任务数。过大会触发上游 SYN cookie / 限速；先小流量验证。 |
| `--api` / `--api-only` | 启用后端口 9090 会暴露**全部**扫描结果与控制接口，生产环境必须内网 + 反向代理保护。 |
| `--dry-run` | 只解析配置，**不会**打开 socket 或创建数据库；适合 CI 配置校验与变更前确认；同时打印当前计划中的高敏感端口清单。 |

完整 CLI 参数见 `ip-scan --help`，对照矩阵见 [`README.md`](../README.md)。

---

## 9. 风险评分使用守则

`risk_score` 是一个**轻量级暴露面排序分数**，来源 `IpServiceSummary::assess_risk`：

1. 用于在 Web UI/API 中给资产排序，提醒先看高风险。
2. **不是** CVE、CVSS、漏洞扫描、合规、零日结果。
3. 同一服务在不同上下文的风险差异极大（如 SSH 在堡垒机 vs SSH 暴露在公网），**人工复核永远必要**。
4. 复核思路：
   - 该端口**应当**对外开放吗？（业务需求 vs 最小开放面）
   - 鉴权是否启用？版本是否在维护？
   - 加密是否启用？证书是否在有效期？
   - 日志是否被采集、是否能在 WAF / IDS 上看到对应告警？

---

## 10. 推荐的下一步动作

- **高危端口暴露**（如 23、3389、6379、9200、27017、445、5900）：立刻收敛到内网或加白名单。
- **明文协议**（21、23、25、110、143、514）：升级到 TLS 变体或更安全的替代。
- **HTTPS 但版本老旧**：禁用 TLS 1.0/1.1，确认证书链完整。
- **安全响应头缺失**：参考 OWASP Secure Headers Project 添加 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy。
- **Banner 暴露精确版本**：在反向代理 / WAF 层去掉 `Server` / `X-Powered-By`，减少指纹信息。
- **风险分高但需复核**：把 `risk_score >= 60` 的资产作为下一轮渗透测试 / 漏洞扫描的优先目标。

---

## 11. 参考资料

- OWASP Top 10 — <https://owasp.org/Top10/>
- NIST SP 800-42 — Guidelines on Network Security Testing
- CIS Benchmarks（操作系统 / 数据库加固基线）
- IANA Service Name and Transport Protocol Port Number Registry — <https://www.iana.org/assignments/service-names-port-numbers/>
- 项目内部：
  - [`ARCHITECTURE.md`](./ARCHITECTURE.md) — 流水线与并行模型
  - [`DATA_DICTIONARY.md`](./DATA_DICTIONARY.md) — 数据库字段定义
  - [`API_CONTRACT.md`](./API_CONTRACT.md) — 前后端接口契约
  - [`OPERATIONS.md`](./OPERATIONS.md) — 运维、限速、退避
  - [`../README.md`](../README.md) — 命令行与快速开始