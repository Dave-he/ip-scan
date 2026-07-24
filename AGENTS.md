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

涉及 API、CLI、数据库或扫描流水线时，还要运行对应的最小本地验证，并记录结果。不得把“编译成功”当作端到端扫描完成的证明。

## 文档同步

新增 CLI 参数、API 字段、数据库字段、探测器或运行约束时，必须同步 README、`docs/ARCHITECTURE.md`、`docs/OPERATIONS.md` 和相关 OpenAPI 注释。
