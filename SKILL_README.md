
# IP Scan Skill 使用指南

## 概述

IP Scan Skill 是一个高性能的端口扫描工具库，专为 AI 调用设计。它提供简单易用的 API，可以快速扫描单个 IP 或 IP 范围。

## 快速开始

### 1. 单个 IP 快速扫描

```rust
use ip_scan::skill::IpScanSkill;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skill = IpScanSkill::new()?;
    
    // 扫描常用端口
    let result = skill.scan_common_ports("192.168.1.1").await?;
    println!("Open ports: {:?}", result.open_ports);
    
    // 扫描自定义端口
    let result = skill.quick_scan_single("192.168.1.1", "22,80,443,8080").await?;
    
    // 扫描全部端口
    let result = skill.scan_full_range("192.168.1.1", Some(1000)).await?;
    
    Ok(())
}
```

### 2. IP 范围扫描

```rust
use ip_scan::skill::{IpScanSkill, ScanConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let skill = IpScanSkill::new()?;
    
    let config = ScanConfig {
        start_ip: "192.168.1.1".to_string(),
        end_ip: Some("192.168.1.254".to_string()),
        ports: "22,80,443".to_string(),
        timeout_ms: 300,
        concurrency: 100,
        max_rate: 50000,
        only_open: true,
    };
    
    let summary = skill.scan_range(config).await?;
    
    println!("Total IPs scanned: {}", summary.total_ips);
    println!("Open ports found: {}", summary.open_ports_found);
    
    for result in summary.results {
        if !result.open_ports.is_empty() {
            println!("{}: {:?}", result.ip, result.open_ports);
        }
    }
    
    Ok(())
}
```

## API 参考

### IpScanSkill

主要的扫描技能类。

#### 方法

##### `new() -> Result<Self>`

创建一个新的扫描技能实例。

##### `with_database(db_path: &str) -> Result<Self>`

创建一个带有持久化数据库的扫描技能实例。

##### `quick_scan_single(target: &str, ports: &str) -> Result<ScanResult>`

快速扫描单个 IP 的指定端口。

- `target`: 目标 IP 地址
- `ports`: 端口字符串，支持格式如 "1-1000" 或 "22,80,443"

##### `scan_common_ports(target: &str) -> Result<ScanResult>`

扫描单个 IP 的常用端口（21, 22, 23, 25, 53, 80, 443 等）。

##### `scan_full_range(target: &str, concurrency: Option<usize>) -> Result<ScanResult>`

扫描单个 IP 的全部端口 (1-65535)。

##### `scan_range(config: ScanConfig) -> Result<ScanSummary>`

扫描 IP 范围。

### ScanResult

单个 IP 的扫描结果。

```rust
pub struct ScanResult {
    pub ip: String,
    pub ip_type: String,
    pub open_ports: Vec<u16>,
    pub scan_time_ms: u64,
    pub total_ports_scanned: usize,
}
```

### ScanConfig

范围扫描的配置。

```rust
pub struct ScanConfig {
    pub start_ip: String,
    pub end_ip: Option<String>,
    pub ports: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub max_rate: u64,
    pub only_open: bool,
}
```

### ScanSummary

范围扫描的总结。

```rust
pub struct ScanSummary {
    pub total_ips: usize,
    pub total_ports_scanned: usize,
    pub open_ports_found: usize,
    pub scan_duration_ms: u64,
    pub avg_ips_per_second: f64,
    pub results: Vec<ScanResult>,
}
```

## 性能优化建议

1. **并发数**: 对于局域网扫描，建议设置 100-500
2. **超时时间**: 局域网建议 200-500ms，公网建议 1000-2000ms
3. **速率限制**: 根据网络环境调整，避免触发防火墙
4. **端口范围**: 优先扫描常用端口以提高效率

## 示例

查看 `examples/skill_usage.rs` 获得完整的使用示例。

## 运行示例

```bash
cargo run --example skill_usage
```
