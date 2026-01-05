# GitHub Actions CI/CD 配置说明

本项目使用 GitHub Actions 实现完整的 CI/CD 流水线。

## 工作流程概览

### 1. 主 CI/CD 流水线 (`rust.yml`)

**触发条件：**
- 推送到 `master` 或 `main` 分支
- 创建 Pull Request
- 推送标签（`v*`）

**包含的任务：**

#### 代码质量检查
- **Format Check**: 使用 `cargo fmt` 检查代码格式
- **Clippy Check**: 使用 `cargo clippy` 进行代码质量检查
- **Security Audit**: 使用 `cargo audit` 进行安全审计

#### 多平台测试
- 操作系统: Ubuntu, macOS, Windows
- Rust 版本: stable, beta
- 包含构建、测试和 release 构建

#### Docker 镜像构建
- 自动构建 Docker 镜像
- 推送到 Docker Hub（需要配置 secrets）
- 使用 GitHub Actions 缓存加速构建

#### 自动发布
- 当推送 tag（如 `v1.0.0`）时触发
- 构建 Linux 和 Windows 二进制文件
- 自动创建 GitHub Release

#### 代码覆盖率
- 使用 `cargo-tarpaulin` 生成覆盖率报告
- 上传到 Codecov

### 2. 依赖更新 (`dependency-update.yml`)

**触发条件：**
- 每周一早上 8 点自动运行
- 手动触发

**功能：**
- 自动更新项目依赖
- 运行测试确保兼容性
- 创建 Pull Request

### 3. 安全扫描 (`security-scan.yml`)

**触发条件：**
- 推送到主分支
- Pull Request
- 每天凌晨 2 点自动扫描

**功能：**
- 使用 Trivy 扫描 Docker 镜像漏洞
- 上传结果到 GitHub Security
- 检测 CRITICAL 和 HIGH 级别漏洞

### 4. 性能基准测试 (`benchmark.yml`)

**触发条件：**
- 推送到主分支
- Pull Request
- 手动触发

**功能：**
- 运行性能基准测试
- 存储和对比历史数据
- 性能下降超过 200% 时发出警告

## 必需的 Secrets 配置

在 GitHub 仓库的 Settings > Secrets and variables > Actions 中配置：

### Docker Hub（可选，用于发布镜像）
```
DOCKER_USERNAME: 你的 Docker Hub 用户名
DOCKER_PASSWORD: 你的 Docker Hub 访问令牌
```

### Codecov（可选，用于代码覆盖率）
```
CODECOV_TOKEN: 你的 Codecov token
```

### GitHub Token
`GITHUB_TOKEN` 是自动提供的，无需手动配置。

## 本地测试

在推送代码前，可以在本地运行以下命令进行测试：

```bash
# 格式检查
cargo fmt --all -- --check

# 代码质量检查
cargo clippy --all-targets --all-features -- -D warnings

# 安全审计
cargo install cargo-audit
cargo audit

# 运行测试
cargo test --all-features

# 构建 release
cargo build --release
```

## 发布新版本

1. 更新 `Cargo.toml` 中的版本号
2. 提交更改
3. 创建并推送 tag：
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```
4. GitHub Actions 会自动：
   - 运行所有测试
   - 构建多平台二进制文件
   - 创建 GitHub Release
   - 构建并推送 Docker 镜像

## 工作流程状态徽章

可以在 README.md 中添加以下徽章：

```markdown
![CI](https://github.com/你的用户名/ip-scan/workflows/CI%2FCD%20Pipeline/badge.svg)
![Security](https://github.com/你的用户名/ip-scan/workflows/Docker%20Image%20Scan/badge.svg)
[![codecov](https://codecov.io/gh/你的用户名/ip-scan/branch/master/graph/badge.svg)](https://codecov.io/gh/你的用户名/ip-scan)
```

## 优化建议

1. **缓存优化**: 已配置 cargo 缓存，加速构建
2. **并行执行**: 多个 job 并行运行，节省时间
3. **条件执行**: 某些任务仅在特定条件下运行（如发布）
4. **失败快速**: 代码质量检查失败时，后续任务不会运行

## 故障排查

### 构建失败
- 检查 Rust 版本兼容性
- 查看依赖是否有冲突
- 确认所有测试通过

### Docker 推送失败
- 确认 Docker Hub secrets 配置正确
- 检查镜像名称是否正确
- 验证 Docker Hub 访问权限

### Release 创建失败
- 确认 tag 格式正确（`v*`）
- 检查 GITHUB_TOKEN 权限
- 验证二进制文件构建成功

## 自定义配置

可以根据项目需求修改工作流程：

1. 调整测试矩阵（操作系统、Rust 版本）
2. 修改触发条件
3. 添加额外的检查步骤
4. 配置通知（Slack、Email 等）
