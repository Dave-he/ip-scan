mod cli;
mod ip_range;
mod bitmap;
mod bitmap_db;
mod bitmap_scanner;
mod metrics;
mod rate_limiter;

use anyhow::Result;
use clap::Parser;
use tracing::{info, error, Level};
use tracing_subscriber;

use cli::Args;
use bitmap_db::BitmapDatabase;
use ip_range::{IpRange, parse_port_range};
use bitmap_scanner::BitmapScanner;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse().merge_with_config()?;

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose { Level::DEBUG } else { Level::INFO })
        .with_target(false)
        .init();

    info!("IP Scanner starting (Bitmap Mode)");
    info!("Config: concurrency={}, timeout={}ms, db={}, loop={}, ipv4={}, ipv6={}, only_open={}, skip_private={}", 
        args.concurrency, args.timeout, args.database, args.loop_mode, args.ipv4, args.ipv6, args.only_store_open, args.skip_private);

    // Initialize bitmap database
    let db = BitmapDatabase::new(&args.database)?;
    info!("Database initialized");

    // Check for previous scan progress
    let (mut current_round, resume_ip, resume_ip_type) = db.get_progress()?
        .map(|(ip, ip_type, round)| {
            info!("Resuming from: {} ({}) round {}", ip, ip_type, round);
            (round, Some(ip), Some(ip_type))
        })
        .unwrap_or_else(|| {
            info!("Starting fresh scan");
            (1, None, None)
        });

    // Parse port range
    let ports = parse_port_range(&args.ports).map_err(|e| anyhow::anyhow!(e))?;
    info!("Scanning {} ports: {:?}", ports.len(), ports);

    loop {
        info!("=== Starting scan round {} ===", current_round);

        // Scan IPv4 if enabled
        if args.ipv4 {
            let (start_ip, end_ip) = args.start_ip.as_ref()
                .zip(args.end_ip.as_ref())
                .map(|(s, e)| (s.clone(), e.clone()))
                .unwrap_or_else(Args::get_default_ipv4_range);

            // Resume from last position if applicable
            let actual_start_ip = if resume_ip_type.as_deref() == Some("IPv4") {
                resume_ip.as_ref().map(|ip| {
                    info!("Resuming IPv4 from: {}", ip);
                    ip.clone()
                }).unwrap_or(start_ip)
            } else {
                start_ip
            };

            info!("Scanning IPv4: {} - {}", actual_start_ip, end_ip);
            match IpRange::new(&actual_start_ip, &end_ip) {
                Ok(ip_range) => {
                    const CHUNK_SIZE: usize = 1000;
                    let scanner = BitmapScanner::new(db.clone(), args.timeout, args.concurrency, current_round);
                    let start_time = std::time::Instant::now();
                    let mut total_processed = 0usize;
                    let mut chunk = Vec::with_capacity(CHUNK_SIZE);
                    
                    for ip in ip_range.iter() {
                        // Filter private IPs if enabled
                        if args.skip_private && Args::is_private_ipv4(&ip.to_string()) {
                            continue;
                        }
                        
                        chunk.push(ip);
                        
                        // Process chunk when it reaches CHUNK_SIZE
                        if chunk.len() >= CHUNK_SIZE {
                            let chunk_start = total_processed;
                            let chunk_to_scan = std::mem::replace(&mut chunk, Vec::with_capacity(CHUNK_SIZE));
                            
                            scanner.scan_range(chunk_to_scan, ports.clone(), move |current, _| {
                                if (chunk_start + current) % 100 == 0 {
                                    let rate = (chunk_start + current) as f64 / start_time.elapsed().as_secs_f64();
                                    info!("IPv4 Progress [R{}]: {} IPs - {:.2} IPs/sec", current_round, chunk_start + current, rate);
                                }
                            }).await?;
                            
                            total_processed += CHUNK_SIZE;
                        }
                    }
                    
                    // Process remaining IPs
                    if !chunk.is_empty() {
                        let chunk_start = total_processed;
                        scanner.scan_range(chunk, ports.clone(), move |current, _| {
                            let rate = (chunk_start + current) as f64 / start_time.elapsed().as_secs_f64();
                            info!("IPv4 Progress [R{}]: {} IPs - {:.2} IPs/sec", current_round, chunk_start + current, rate);
                        }).await?;
                    }

                    info!("IPv4 scan completed: {} IPs in {:.2}s ({:.2} IPs/sec)", 
                        total_processed, start_time.elapsed().as_secs_f64(), 
                        total_processed as f64 / start_time.elapsed().as_secs_f64());
                    scanner.get_metrics().print_summary();
                }
                Err(e) => error!("Failed to create IPv4 range: {}", e),
            }
        }

        // Print statistics
        let (total_results, unique_open) = db.get_stats()?;
        let memory_mb = db.get_memory_usage()? as f64 / 1024.0 / 1024.0;
        info!("=== Round {} Stats ===", current_round);
        info!("Total open records: {}, Unique IPs: {}, Memory: {:.2} MB", total_results, unique_open, memory_mb);

        // Show top ports
        if let Ok(port_stats) = db.get_stats_by_port(current_round) {
            info!("Top 10 open ports:");
            for (port, count) in port_stats.iter().take(10) {
                info!("  Port {}: {} IPs", port, count);
            }
        }

        if !args.loop_mode {
            info!("Loop mode disabled, exiting");
            break;
        }

        current_round = db.increment_round()?;
        info!("Starting round {} after 5s delay...", current_round);
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }

    Ok(())
}
