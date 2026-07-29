# 分布式部署与多服务器前端

本项目原生支持前后端分离的分布式部署：把 `ip-scan` 服务端放到任意数量的节点
（阿里云、腾讯云、自建机房都行），然后在任意地方启动 `frontend/` 控制台，它会
自动连接所有节点、按节点聚合结果，并提供 5+ 种浏览模式。

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
| `POST /api/v1/scan/start` | 远程启动扫描 |
| `POST /api/v1/scan/stop` | 远程停止扫描 |

## 3. 部署多个扫描节点

最直接的方式就是用现有的 `deploy.sh`：它会同时部署到 `sshali` 与 `sshtx`
两台服务器，每台都已经是独立节点身份（继续通过 `--node-*` flag 或环境变量注入）。

新增节点时建议：

1. 用不同的 `--node-id` / `--node-label` / `--node-provider`
2. 用不同的 `--database`（每台本地一份 SQLite）
3. 各自 `--node-latitude` / `--node-longitude` 用来在地图上画节点位置
4. 防火墙 / nginx 对外暴露 `--api-port`（默认 9090），只允许前端所在网段访问

## 4. 启动独立前端

前端是纯静态文件 + 一个小 Node 服务器（也可以用 nginx / caddy / Python http.server）。

```bash
# 进入 frontend/ 目录
cd frontend

# 方式 A：用项目自带 Node 服务器
node ../scripts/serve-frontend.mjs 4000

# 方式 B：用任意静态服务器，例如
python3 -m http.server 4000
```

打开 `http://127.0.0.1:4000/`，点击右上角「+ 服务器」输入每个节点的 API 地址即可。
服务器列表保存在浏览器 localStorage，下次直接打开就能继续看到聚合视图。

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
跨节点无缝切换，因为聚合层 (`frontend/src/aggregator.js`) 维护统一的快照。

## 6. 前端模块结构

```text
frontend/
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

# 前端模块：纯 Node 检查 + 聚合逻辑
node scripts/test-frontend-e2e.mjs
```

`scripts/test-frontend-e2e.mjs` 会同时连两台后端（端口 9301 / 9302，默认 localhost），
跑通所有聚合路径并断言服务端返回。

## 9. 把前端打包到二进制里（可选）

如果想把前端和后端打包成单一可执行文件，可以在 `start_api_server` 里同时挂载
`Files::new("/ui", "./frontend")`：

```rust
app = app
    .service(Files::new("/", "./web").index_file("index.html"))
    .service(Files::new("/ui", "./frontend").index_file("index.html"));
```

然后访问 `http://node:9090/ui/` 即可，无需再单独部署前端。
