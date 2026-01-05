## 贡献指南

感谢您对 IP-Scan 项目的关注！我们欢迎各种形式的贡献。

### 如何贡献

1. **Fork 项目**
   ```bash
   # 在 GitHub 上 Fork 项目
   # 然后克隆到本地
   git clone https://github.com/你的用户名/ip-scan.git
   cd ip-scan
   ```

2. **创建分支**
   ```bash
   git checkout -b feature/your-feature-name
   # 或
   git checkout -b fix/your-bug-fix
   ```

3. **进行开发**
   - 编写代码
   - 添加测试
   - 更新文档

4. **代码质量检查**
   ```bash
   # 格式化代码
   cargo fmt
   
   # 运行 Clippy
   cargo clippy --all-targets --all-features -- -D warnings
   
   # 运行测试
   cargo test --all-features
   
   # 安全审计
   cargo audit
   ```

5. **提交更改**
   ```bash
   git add .
   git commit -m "feat: 添加新功能描述"
   # 或
   git commit -m "fix: 修复某个问题"
   ```

6. **推送到 GitHub**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **创建 Pull Request**
   - 在 GitHub 上创建 Pull Request
   - 填写详细的描述
   - 等待 CI 检查通过
   - 等待代码审查

### 提交信息规范

我们使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

- `feat:` 新功能
- `fix:` 修复 bug
- `docs:` 文档更新
- `style:` 代码格式调整（不影响功能）
- `refactor:` 重构代码
- `perf:` 性能优化
- `test:` 添加或修改测试
- `chore:` 构建过程或辅助工具的变动

示例：
```
feat: 添加 IPv6 支持
fix: 修复并发扫描时的死锁问题
docs: 更新 README 中的安装说明
perf: 优化 bitmap 查询性能
```

### 代码规范

1. **Rust 代码风格**
   - 使用 `cargo fmt` 格式化代码
   - 遵循 Rust 官方风格指南
   - 添加必要的注释和文档

2. **测试要求**
   - 新功能必须包含单元测试
   - 确保所有测试通过
   - 测试覆盖率不应降低

3. **文档要求**
   - 公开 API 必须有文档注释
   - 复杂逻辑需要添加说明
   - 更新相关的 README 和文档

### Pull Request 检查清单

在提交 PR 之前，请确保：

- [ ] 代码已通过 `cargo fmt` 格式化
- [ ] 代码已通过 `cargo clippy` 检查
- [ ] 所有测试通过 `cargo test`
- [ ] 已添加必要的测试
- [ ] 已更新相关文档
- [ ] 提交信息符合规范
- [ ] CI 检查全部通过

### 报告问题

如果您发现了 bug 或有功能建议：

1. 在 [Issues](https://github.com/Dave-he/ip-scan/issues) 中搜索是否已有相关问题
2. 如果没有，创建新的 Issue
3. 提供详细的信息：
   - 问题描述
   - 复现步骤
   - 预期行为
   - 实际行为
   - 环境信息（操作系统、Rust 版本等）

### 开发环境设置

```bash
# 1. 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. 安装开发工具
rustup component add rustfmt clippy
cargo install cargo-audit cargo-edit

# 3. 克隆项目
git clone https://github.com/Dave-he/ip-scan.git
cd ip-scan

# 4. 构建项目
cargo build

# 5. 运行测试
cargo test
```

### 获取帮助

如果您在贡献过程中遇到问题：

- 查看 [文档](.github/WORKFLOWS.md)
- 在 Issue 中提问
- 联系维护者

### 行为准则

请遵守我们的行为准则：

- 尊重他人
- 接受建设性批评
- 关注对社区最有利的事情
- 对其他社区成员表现出同理心

### 许可证

通过贡献代码，您同意您的贡献将在 MIT 许可证下发布。

---

再次感谢您的贡献！🎉
