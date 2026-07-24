# IP-Scan 前后端协议契约

## 目标

Web 控制台与扫描服务通过版本化 HTTP JSON API 对接。前端不依赖具体服务器地址：用户可以在页面的 **Backend Connection** 输入任意兼容服务端地址，前端先完成协议发现，再使用同一套资源接口。

## 服务地址规则

前端支持以下输入形式：

- `http://127.0.0.1:9090`
- `http://scanner-a:9090/api/v1`
- 页面 URL 的 `?api=http://scanner-a:9090` 参数

未带 `/api/v1` 时，前端自动补全；地址保存在浏览器本地存储中。跨域服务端必须允许 GET/POST/OPTIONS，并允许 `Content-Type` 与 `Accept` 请求头。

## 协议发现顺序

1. `GET /api/v1/healthz`
2. `GET /api/v1/system`
3. 校验 `protocol == "ip-scan"` 和 `api_version == "v1"`
4. 读取 `capabilities` 和 `endpoints`
5. 只有发现成功后才启动统计、结果、历史的轮询

`/healthz` 用于快速判断数据库是否可用；`/system` 用于判断服务类型、版本、状态和能力。服务不可用时，前端必须显示断开状态，不能继续显示旧数据为实时数据。

## `/system` 响应

```json
{
  "protocol": "ip-scan",
  "api_version": "v1",
  "service": "ip-scan",
  "version": "0.1.0",
  "status": "ready",
  "database": "ok",
  "server_time": "2026-07-24T08:00:00Z",
  "capabilities": ["scan.control", "results.pagination"],
  "endpoints": ["/healthz", "/system", "/stats", "/results", "/services", "/scan", "/export"]
}
```

### 状态值

- `ready`：服务可接受业务请求
- `degraded`：服务进程可响应，但数据库或关键依赖异常
- `offline`：无法建立 HTTP 连接（仅由前端展示，不是服务端响应值）

## 资源接口

所有路径均相对于 `/api/v1`：

| 能力 | 方法 | 路径 | 前端用途 |
|---|---|---|---|
| 健康检查 | GET | `/healthz` | 连接测试、状态轮询 |
| 协议发现 | GET | `/system` | 版本和能力协商 |
| 统计 | GET | `/stats` | 指标卡片 |
| 端口分布 | GET | `/stats/top-ports?limit=10` | 服务分布图 |
| 结果列表 | GET | `/results?page=1&page_size=50` | 分页结果 |
| 服务摘要 | GET | `/services?page=1&page_size=500` | IP 星图和站点聚合 |
| 扫描状态 | GET | `/scan/status` | 状态轮询 |
| 启动扫描 | POST | `/scan/start` | 创建扫描任务 |
| 停止扫描 | POST | `/scan/stop` | 停止扫描任务 |
| 扫描历史 | GET | `/scan/history` | 历史列表 |
| 数据导出 | GET | `/export/json`、`/export/csv` | 下载快照 |

## 错误格式

业务失败统一返回 JSON：

```json
{
  "error": "Invalid pagination",
  "code": "INVALID_PAGINATION"
}
```

前端展示 `error`，使用 `code` 做可编程分类。网络失败、超时和 CORS 失败不伪装成业务错误，应显示“后端连接中断”并允许用户重新连接。

## 新增兼容服务端的要求

只要实现上述 `/healthz`、`/system`、`/stats`、`/results`、`/services`、`/scan` 和 `/export` 契约，页面即可复用。服务端可以使用不同数据库、扫描调度器或部署地址，但不得改变字段含义；新增能力通过 `capabilities` 增加，不应要求旧前端调用未知接口。
