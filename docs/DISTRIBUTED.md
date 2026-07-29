# 分布式部署与多服务器前端

本项目原生支持前后端分离的分布式部署：把 `ip-scan` 服务端放到任意数量的节点
（阿里云、腾讯云、自建机房都行），然后在任意地方启动 `web/` 控制台，它会
自动连接所有节点、按节点聚合结果，并提供 7 种浏览模式。

> `frontend/` 已经被合并到 `web/` 里。`web/` 同时承载：
> 1. **嵌入式 UI** —— Rust 进程以 `cargo run -- --api` 启动后，`http://127.0.0.1:9090/`
>    直接渲染同一份控制台（自动添加本地节点）。
> 2. **分布式控制台** —— 通过 `scripts/serve-frontend.mjs` 在本地启动
>    静态文件服务器，浏览器里手动添加远端节点 URL。

## 1. 服务端：给每个节点打上身份

每个 ip-scan 实例都需要知道自己是谁。身份信息会通过 `/api/v1/system` 暴露，
前端据此区分节点来源、放置地图标记、汇总贡献。

CLI flag：

```bash
ip-scan --api-only \
    --node-id "node-ali" \
    --node-label "ali-shanghai" \
    --node-provider "Aliyun" \
    --node-latitude 31.2304 \
    --node-longitude 121.4737 \
    --api-port 9090
```

`config.toml` 等价写法：

```toml
[node]
id = "node-ali"
label = "ali-shanghai"
provider = "Aliyun"
latitude = 31.2304
longitude = 121.4737
```

CLI flag 优先级高于 config.toml；两者都没有时会回落到 `host:port`。

确认节点身份：

```bash
curl http://1.2.3.4:9090/api/v1/system | jq .
{
  "node_id": "node-ali",
  "node_label": "ali-shanghai",
  "node_provider": "Aliyun",
  "node_latitude": 31.2304,
  "node_longitude": 121.4737,
  ...
}
```

## 2. 跨节点聚合 API

服务端为分布式前端补充了若干聚合端点，单次调用即可拿到全节点的归类统计：

| 端点 | 用途 |
|------|------|
| `GET /api/v1/stats/by-ip-family` | IPv4 vs IPv6 拆分 |
| `GET /api/v1/stats/by-service` | 按 service_name 聚合 |
| `GET /api/v1/stats/by-category` | 按资产 category（web-server / database-server …）聚合 |
| `GET /api/v1/map/locations?limit=N` | 地理坐标 + 端口数 + 主服务（用于地图视图） |
| `GET /api/v1/results?page=1&page_size=50` | 结果明细（前端按 (ip, port) 跨节点去重） |
| `GET /api/v1/services?page=1&page_size=50` | 单 IP 服务详情 |
| `GET /api/v1/scan/status` | 节点扫描状态（running/idle + source + controllable） |
| `POST /api/v1/scan/start` | 远程启动扫描（支持 `probe_service` 字段） |
| `POST /api/v1/scan/stop` | 远程停止扫描 |

## 3. 部署多个扫描节点（默认纯后端）

`deploy.sh` 默认以 `MODE=pure` 部署：每个节点都是 `--api-only` 纯后端，
不带本地 scanner；扫描任务完全由前端通过 `/api/v1/scan/start` 触发。
这就是"前后端分离"的生产形态：服务器只暴露 API，扫描由操作员在
控制台里点击发起。

```bash
./deploy.sh                     # 纯后端部署到 sshali + sshtx
./deploy.sh sshali              # 仅部署到阿里云
MODE=full ./deploy.sh sshtx     # 部署 sshtx 为 scanner+API 综合模式
```

`MODE=full` 恢复原有的 scanner+API 综合行为（`--api --loop-mode
--preset fullpublic --probe-service`），适合无人值守的长时间扫描。

新增节点时建议：

1. 用不同的 `--node-id` / `--node-label` / `--node-provider`
2. 用不同的 `--database`（每台本地一份 SQLite）
3. 各自 `--node-latitude` / `--node-longitude` 用来在地图上画节点位置
4. 防火墙 / nginx 对外暴露 `--api-port`（默认 9090），只允许前端所在网段访问

## 4. 启动前端

前端是纯静态文件 + 一个小 Node 服务器（也可以用 nginx / caddy / Python http.server）。

```bash
# 默认从仓库根目录的 web/ 提供文件
node scripts/serve-frontend.mjs 4000

# 方式 B：用任意静态服务器
python3 -m http.server 4000 --directory web
```

打开 `http://127.0.0.1:4000/`，**首次访问会自动连接 `web/src/config.js`
里 `DEFAULT_NODES` 写的两个节点**（默认就是 sshali + sshtx），无需任何手动
操作。侧边栏底部「+ 服务器」可继续添加任意节点；删除 / 编辑后配置存到
`localStorage`，再次打开时仍以本地配置为准，`DEFAULT_NODES` 不再覆盖。

`DEFAULT_NODES` 支持以下覆盖方式：

```html
<!-- 静态注入：在 index.html 里、app.js 之前 -->
<script>
  window.IPSCAN_DEFAULT_NODES = [
    { id: 'prod-1', label: 'prod-1', url: 'http://1.2.3.4:9090' },
    { id: 'prod-2', label: 'prod-2', url: 'http://5.6.7.8:9090' },
  ];
</script>
```

每个 entry：`{ id, label, url, provider?, latitude?, longitude? }`；`url` 不
要带 `/api/v1`，`BackendClient` 会自动加。

## 5. 前端菜单 / 视图

| 菜单 | 内容 |
|------|------|
| 总览 | 集群规模、节点贡献热力图、TOP 服务 |
| 地图视图 | 全球 Leaflet 地图 · 每点表示一个独立 IP · 点击查看端口与服务 |
| 服务类型 | 按探测到的 service_name 聚合的卡片（ssh / http / mysql / redis …） |
| IP 族 | IPv4 vs IPv6 拆分 + 资产分类拆分 |
| 节点列表 | 每个节点单独的状态、目标范围、最新统计 |
| 结果明细 | 跨节点去重的 (ip, port) 表 · 支持搜索 + 分页 |
| 扫描控制 | 选择节点 → 发起 / 停止扫描，节点列表实时状态 |

所有视图都是 8 秒轮询一次的纯拉模式，节点离线会自动回退成灰态；任何视图都能
跨节点无缝切换，因为聚合层 (`web/src/aggregator.js`) 维护统一的快照。

## 6. 前端模块结构

```text
web/
├── index.html              # 主 HTML，引用所有模块
├── css/style.css           # 主题 + 视图样式
├── src/
│   ├── app.js              # 主入口：状态管理、视图路由、轮询
│   ├── api.js              # BackendClient: 每个后端的请求封装
│   ├── aggregator.js       # Aggregator: 跨节点合并
│   └── views/
│       ├── overview.js     # 总览视图
│       ├── map.js          # 地图视图（Leaflet）
│       ├── services.js     # 服务类型视图
│       ├── family.js       # IP 族视图
│       ├── servers.js      # 节点详情视图
│       ├── results.js      # 结果明细视图
│       └── scan.js         # 扫描控制视图
└── package.json
```

每个 view 文件是一个类，构造函数接受 `document`，调用 `render(state)` 用聚合快照
渲染自身。这样新增视图只需要再加一个文件即可。

## 7. CORS / 跨域

后端默认 `Cors::default().allow_any_origin()`，前端放在任何 origin 都能直接请求。
如要锁定到具体域名，编辑 `src/main.rs::start_api_server` 里的 Cors 配置。

## 8. 单元 / 端到端测试

```bash
# Rust：基础 + 新增 endpoint
cargo test --offline

# 前端模块：聚合逻辑 + 双后端冒烟
node scripts/test-frontend-e2e.mjs
```

`scripts/test-frontend-e2e.mjs` 默认连 `http://127.0.0.1:9301` 与
`http://127.0.0.1:9302`；可以用 `N1_URL` / `N2_URL` 环境变量覆盖。

## 9. 历史：`frontend/` 合并到 `web/`

旧版有两个目录：
- `web/` —— 单后端嵌入式 UI（顶部 brand bar + connection-bar）。
- `frontend/` —— 多节点分布式控制台（侧边栏 + 7 个视图）。

两者功能高度重叠，部署时也都要打包到 tarball。从 0.1.0 起只保留 `web/`
作为统一入口：
- 把 `frontend/src/*` `frontend/css/*` `frontend/index.html` `frontend/package.json` 全部迁入 `web/`。
- 删除 `frontend/` 目录。
- `scripts/serve-frontend.mjs` / `scripts/test-frontend-e2e.mjs` 改为读取 `web/`。
- `deploy.sh` tarball 不再包含 `frontend/`。
- `web/src/api.js` 把所有端点统一加上 `/api/v1` 前缀（之前漏写，
  导致 `BackendClient` 一直 404；这是当初 `frontend/` 没真正跑通的主因）。
- `StartScanRequest` 新增 `probe_service` 字段，对应控制台"启用服务探测"开关。

## 6. 新增视图：资产库、IP 详情

最新的 `web/` 控制台在前述 7 个视图基础上额外提供两个聚焦于结果展示的能力：

### 资产库（Assets）
- 入口：侧边栏 `资产库`（`◫`）
- 来自 `/api/v1/assets`，对独立 IP 列表进行分页、过滤（服务 / 国家 / 风险等级 ≥ X），点击任一行直接弹出 **IP 详情面板**。

### IP 详情面板
- 任意视图（地图 / 结果明细 / 资产库）点击 IP / 端口行都会触发。
- 数据来源：`/api/v1/ip/{ip}` + `/api/v1/snapshots/{ip}`，展示：
  - 完整开放端口列表（含 service_name / Banner / 首末次扫描时间）
  - TCP 抓包首字节（含十六进制 Raw bytes 折叠展开）
  - HTTP title / Server / TLS subject / TLS issuer / TLS 有效期
  - 同 ASN / 同 ISP 的邻居 IP 数（方便评估资产范围）
  - 风险评分（0-100）+ 风险原因
- 关闭方式：右上角 × 或切换视图。

## 7. 下载与安装

每个 release tag 都会自动构建下列产物并附带 `SHA256SUMS`：

| 资产 | 平台 | 说明 |
| --- | --- | --- |
| `ip-scan-linux-x86_64-musl.tar.gz` | Linux x86_64 | static-pie · 推荐大多数服务器 |
| `ip-scan-linux-x86_64.tar.gz` | Linux x86_64 | glibc 动态链接 |
| `ip-scan-linux-aarch64-musl.tar.gz` | Linux aarch64 | ARM64 static-pie |
| `ip-scan-linux-aarch64.tar.gz` | Linux aarch64 | ARM64 glibc |
| `ip-scan-macos-x86_64.tar.gz` | macOS Intel | |
| `ip-scan-macos-aarch64.tar.gz` | macOS Apple Silicon | |
| `ip-scan-windows-x86_64.zip` | Windows x86_64 | MSVC · 启用 SYN 时需要 Npcap |

每个 tarball 同时打包二进制 + `web/` 静态资源 + `config.toml`，
解压后立即可用：

```bash
tar xzf ip-scan-linux-x86_64-musl.tar.gz
./ip-scan --api --node-id my-node --node-label "my-node" --node-latitude 31.23 --node-longitude 121.47
```

详细流程见 `.github/workflows/release.yml`。
