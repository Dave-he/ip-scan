# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete GitHub Actions CI/CD pipeline
  - Multi-platform testing (Ubuntu, macOS, Windows)
  - Code quality checks (fmt, clippy)
  - Security audit
  - Docker image building and publishing
  - Automatic release creation
  - Code coverage reporting
- Dependency update automation
- Docker security scanning with Trivy
- Performance benchmark workflow
- Comprehensive documentation
  - Workflows documentation
  - Contributing guidelines
  - Issue templates
  - Pull request template

### Changed
- Updated README with CI/CD badges
- Enhanced project documentation

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
