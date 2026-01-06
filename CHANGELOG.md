# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **SYN 扫描支持**: 高性能 SYN 半连接扫描模式,速度提升 10 倍以上
  - 通过 `--syn` 参数启用,需要 root/admin 权限
  - 基于 pnet 库实现原始套接字操作
  - 支持 Windows (Npcap SDK) 和 Linux/macOS
- **REST API 接口**: 完整的 RESTful API 支持
  - 扫描结果查询 (`/api/v1/results`)
  - 统计信息接口 (`/api/v1/stats`)
  - 扫描控制接口 (`/api/v1/scan/*`)
  - 数据导出接口 (CSV/JSON/NDJSON)
  - Swagger UI 文档支持
  - 三种运行模式: 纯扫描、纯API、混合模式
- **代码架构重构**: 按照 DAO/Model/Service 模式重构
  - `dao/` - 数据访问层 (SqliteDB)
  - `model/` - 数据模型 (Bitmap, IpRange, Metrics)
  - `service/` - 业务逻辑 (ConScanner, SynScanner, RateLimiter)
- **CI/CD 增强**: 
  - Windows CI 构建支持 (自动配置 Npcap SDK)
  - 多平台测试 (Ubuntu, macOS, Windows)
  - 代码质量检查 (fmt, clippy)
  - Docker 镜像构建和发布
  - 安全扫描 (Trivy)
- **文档完善**:
  - REST API 使用文档
  - SYN 扫描配置指南
  - Windows 构建说明
  - 性能优化指南
  - 故障排查指南

### Changed
- **Feature Flag 移除**: SYN 扫描从编译时 feature 改为运行时参数
- **依赖更新**: pnet 和 rand 改为常规依赖
- **数据库优化**: 修复索引创建顺序,提升查询性能
- **错误处理改进**: 更完善的错误处理和重试机制
- **代码质量提升**: 修复所有 Clippy 警告和未使用代码警告

### Fixed
- 修复 Windows CI 构建中 Packet.lib 链接错误
- 修复 SQLite 索引创建 "no such table" 错误
- 修复 tokio::sync::mpsc::channel 容量参数问题
- 移除未使用的导入和结构体字段

## [0.1.0] - 2024-01-05

### Added
- Initial release
- IPv4/IPv6 port scanning support
- Bitmap-based deduplication
- SQLite database storage
- Asynchronous scanning with Tokio
- Rate limiting
- Performance metrics
- Docker support
- Configurable via CLI, config file, and environment variables
- Structured logging with tracing
- Auto-retry mechanism
- Loop mode for continuous scanning
- Health checks

### Features
- High-performance concurrent scanning
- Memory-efficient bitmap storage
- Batch database operations
- Token bucket rate limiter
- Real-time metrics collection
- Docker Compose deployment
- Resource limits and health checks

### Performance
- Stream-based IP processing (50x memory reduction)
- Batch database commits (100x I/O reduction)
- Configurable concurrency (default: 1000)
- Rate limiting (default: 1000 req/s)

[Unreleased]: https://github.com/Dave-he/ip-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dave-he/ip-scan/releases/tag/v0.1.0
