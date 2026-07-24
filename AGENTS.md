# AI 工具规则

## 任务边界

- 默认按“授权资产发现”处理；不得为了验证而扫描未授权公网目标。
- 不得输出、提交或记录凭据、密钥、Cookie、完整敏感 Banner 或个人数据。
- 修改前先阅读相关模块、测试、README 和配置；不要凭猜测替换架构。

## 代码发现与修改

- 优先使用代码知识图谱的 `search_graph`、`trace_path`、`get_code_snippet`、`query_graph`、`get_architecture`。
- 图谱不可用时再使用 `rg`、`find` 和定向文件读取。
- 每次修改保持写入范围最小，避免覆盖用户已有改动；发现并发修改时先重新读取当前文件。
- 扫描主路径不能被 Geo、DNS、HTTP、TLS 或 Banner 探测阻塞；外部工作必须有超时、并发上限、速率限制和失败隔离。
- 数据库字段变更必须同时更新建表 SQL、迁移、读写、API/导出和测试。

## 验证门禁

提交前至少运行：

```bash
cargo fmt --check
cargo test --offline
```

涉及 API、CLI、数据库或扫描流水线时，还要运行对应的最小本地验证（包括健康检查、指标端点或数据库迁移），并记录结果。不得把“编译成功”当作端到端扫描完成的证明。

## 文档同步

新增 CLI 参数、API 字段、数据库字段、探测器或运行约束时，必须同步 README、`docs/ARCHITECTURE.md`、`docs/OPERATIONS.md`、`docs/DATA_DICTIONARY.md`、`docs/API_CONTRACT.md` 和相关 OpenAPI 注释。

## 依赖安全

- 修改依赖或 Cargo.lock 后必须运行 `cargo audit --no-fetch --stale`（若数据库可用）。
- 不得新增无说明的 `cargo audit` ignore；每个 ignore 必须记录受影响路径、为什么当前不可利用、替代方案和复查条件。
- 处理 TLS、HTTP、WHOIS 和 DNS 依赖升级时，必须同时跑离线测试和最小端到端验证。

## 交叉编译与远程部署（最优流程）

### 1. 本地交叉编译 (macOS → Linux x86_64)

```bash
# 安装 musl 交叉工具链（首次）
brew install filosottile/musl-cross/musl-cross

# 编译静态二进制
cargo build --release --target x86_64-unknown-linux-musl
```

前置配置：
- `.cargo/config.toml` 已设置 `[target.x86_64-unknown-linux-musl] linker = "x86_64-linux-musl-gcc"`
- `Cargo.toml` 中 openssl 已启用 `vendored` feature（否则交叉编译找不到系统 openssl）

产出：`target/x86_64-unknown-linux-musl/release/ip-scan`（~17MB stripped static-pie ELF，无动态依赖）

### 2. 打包部署包

```bash
tar czf /tmp/ip-scan-deploy.tar.gz \
  -C target/x86_64-unknown-linux-musl/release ip-scan \
  -C /Users/hyx/codespace/ip-scan web config.toml
```

约 6.8MB，包含二进制 + web 静态资源 + 配置。

### 3. 上传到服务器

```bash
scp -P 2222 /tmp/ip-scan-deploy.tar.gz root@<SERVER_IP>:/tmp/
```

两台服务器：
- **sshali**: `ssh -p 2222 root@39.103.188.33`（阿里云，磁盘紧张 ~1.3G free，无 Rust/screen）
- **sshtx**: `ssh -p 2222 root@43.133.224.11`（腾讯云，已装 Rust/screen）

### 4. 服务器端解压与启动

```bash
# SSH 连接（加保活防断线）
ssh -p 2222 -o ServerAliveInterval=10 root@<SERVER_IP>

# 停旧进程
pkill -f ip-scan || true

# 解压
mkdir -p /root/ip-scan
cd /root/ip-scan
tar xzf /tmp/ip-scan-deploy.tar.gz

# 安装 screen（若未安装）
apt-get install -y screen || yum install -y screen || true

# 启动（screen 保障断线后进程继续）
screen -dmS scan bash -c './ip-scan -s <START_IP> -e <END_IP> \
  --concurrency 1000 --timeout 500 --max-rate 5000 \
  --api --loop-mode > /tmp/scan.log 2>&1'

# 验证
screen -ls
curl -s http://127.0.0.1:9090/api/v1/stats | head
```

### 5. 远程状态检查与调试

```bash
# 重连 screen 查看日志
ssh -p 2222 -o ServerAliveInterval=10 root@<SERVER_IP>
screen -r scan

# 查看扫描日志
tail -f /tmp/scan.log

# 查看进程
ps aux | grep ip-scan

# API 健康检查
curl -s http://127.0.0.1:9090/api/v1/stats
curl -s http://127.0.0.1:9090/api/v1/top-ports?limit=5

# 数据库大小
du -sh /root/ip-scan/scan_results.db

# 磁盘空间
df -h /

# 终止扫描
pkill -f ip-scan
```

### 6. 关键注意事项

- **必须用 static-pie musl 二进制**：服务器无 Rust/glibc 兼容性保证，动态链接二进制会因 libc 版本不匹配无法运行
- **必须用 screen**：SSH 连接不稳定易断，`nohup` 不可靠；`screen -dmS` 可在断线后重连（`screen -r scan`）
- **SSH 加 `-o ServerAliveInterval=10`**：防止空闲超时断开
- **API 端口 9090**：默认端口 9090（非 3000），可通过 `--api-port` 或 config.toml 修改
- **磁盘空间**：sshali 仅 ~1.3G 可用，解压需 ~17MB 二进制 + 6.8MB tar，空间足够但不可放大量日志
- **旧进程清理**：部署前 `pkill -f ip-scan`，否则端口 9090 被占用
- **打包路径**：tar 的 `-C` 参数确保解压后目录结构正确（ip-scan 二进制在根，web/ 和 config.toml 在同级）
- **服务探测轮次**：`--api --loop-mode` 启动后，主扫描和 enrichment 探测交替运行；enrichment 自动补充之前缺失的 service probe

### 7. 快速部署一键脚本

```bash
# ===== 一键部署到 sshtx (43.133.224.11) =====
cargo build --release --target x86_64-unknown-linux-musl && \
tar czf /tmp/ip-scan-deploy.tar.gz \
  -C target/x86_64-unknown-linux-musl/release ip-scan \
  -C /Users/hyx/codespace/ip-scan web config.toml && \
scp -P 2222 /tmp/ip-scan-deploy.tar.gz root@43.133.224.11:/tmp/ && \
ssh -p 2222 -o ServerAliveInterval=10 root@43.133.224.11 \
  "pkill -f ip-scan || true; mkdir -p /root/ip-scan && cd /root/ip-scan && \
   tar xzf /tmp/ip-scan-deploy.tar.gz && \
   screen -dmS scan bash -c 'cd /root/ip-scan && ./ip-scan -s 43.133.224.0 -e 43.133.224.255 --concurrency 1000 --timeout 500 --max-rate 5000 --api --loop-mode > /tmp/scan.log 2>&1' && \
   sleep 1 && screen -ls"

# ===== 一键部署到 sshali (39.103.188.33) =====
cargo build --release --target x86_64-unknown-linux-musl && \
tar czf /tmp/ip-scan-deploy.tar.gz \
  -C target/x86_64-unknown-linux-musl/release ip-scan \
  -C /Users/hyx/codespace/ip-scan web config.toml && \
scp -P 2222 /tmp/ip-scan-deploy.tar.gz root@39.103.188.33:/tmp/ && \
ssh -p 2222 -o ServerAliveInterval=10 root@39.103.188.33 \
  "pkill -f ip-scan || true; mkdir -p /root/ip-scan && cd /root/ip-scan && \
   tar xzf /tmp/ip-scan-deploy.tar.gz && \
   screen -dmS scan bash -c 'cd /root/ip-scan && ./ip-scan -s 39.103.0.0 -e 39.103.255.255 --concurrency 1000 --timeout 500 --max-rate 5000 --api --loop-mode > /tmp/scan.log 2>&1' && \
   sleep 1 && screen -ls"

# ===== 远程检查状态（任一服务器）=====
ssh -p 2222 -o ServerAliveInterval=10 root@<SERVER_IP> \
  "curl -s http://127.0.0.1:9090/api/v1/stats && echo '---' && du -sh /root/ip-scan/scan_results.db && df -h / && screen -ls"
```

### 8. 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| `cannot execute: No such file or directory` | 动态链接二进制在目标 glibc 不兼容 | 用 musl static-pie 重新编译 |
| `Address already in use` | 旧进程未关闭 | `pkill -f ip-scan` 后重启 |
| `Address already in use: 9090` | 旧进程占 9090 | `lsof -i :9090` 或 `pkill -f ip-scan` |
| SSH 断线后进程消失 | 没用 screen | 必须用 `screen -dmS` |
| 磁盘空间不足 | 二进制 17MB + tar 6.8MB | sshali 仅 1.3G free，需清理旧文件 |
| `command not found: screen` | 未安装 screen | `apt-get install -y screen` 或 `yum install -y screen` |
| API 无响应 | 进程崩溃或未启动 | `screen -r scan` 看日志，`ps aux | grep ip-scan` |
| SSH 连接超时 | 网络波动/服务器负载高 | 加 `-o ServerAliveInterval=10 -o ConnectTimeout=30` |
