mod api;
mod cli;
mod dao;
mod model;
mod service;

use anyhow::Result;
use clap::Parser;
use tracing::{error, info, Level};

use cli::Args;
use dao::SqliteDB;
use service::GeoService;

fn main() -> Result<()> {
    let args = Args::parse().merge_with_config()?;
    let worker_threads = args.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> Result<()> {

    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .with_target(false)
        .init();

    // Determine running mode
    if args.api_only {
        info!("Starting in API-only mode");
        run_api_server(&args).await
    } else if args.no_api {
        info!("Starting in scanner-only mode");
        run_scanner(&args).await
    } else if args.api {
        info!("Starting in combined mode (scanner + API)");
        run_combined(&args).await
    } else {
        info!("Starting in scanner-only mode (default)");
        run_scanner(&args).await
    }
}

/// Run only the API server
async fn run_api_server(args: &Args) -> Result<()> {
    info!("API Server starting on {}:{}", args.api_host, args.api_port);
    
    // Initialize database
    let db = SqliteDB::new(&args.database)?;
    info!("Database initialized: {}", args.database);
    
    // Start API server
    start_api_server(db, args).await
}

/// Run only the scanner
async fn run_scanner(args: &Args) -> Result<()> {
    info!("Scanner starting");
    if args.syn {
        info!("Mode: SYN Scan (Requires Root/Admin)");
    } else {
        info!("Mode: Connect Scan");
    }

    info!("Config: concurrency={}, timeout={}ms, db={}, loop={}, ipv4={}, ipv6={}, only_open={}, skip_private={}", 
        args.concurrency, args.timeout, args.database, args.loop_mode, args.ipv4, args.ipv6, args.only_store_open, args.skip_private);

    // Initialize bitmap database
    let db = SqliteDB::new(&args.database)?;
    info!("Database initialized");

    // Initialize GeoService
    let geo_service = if !args.no_geo {
        info!("Initializing GeoIP service...");
        Some(GeoService::new(args.geoip_db.as_deref()))
    } else {
        info!("GeoIP lookup disabled");
        None
    };

    run_scanner_logic(db, args, geo_service).await
}

/// Run both scanner and API server
async fn run_combined(args: &Args) -> Result<()> {
    info!("Starting combined scanner and API server");
    
    // Initialize database
    let db = SqliteDB::new(&args.database)?;
    info!("Database initialized: {}", args.database);
    
    // Start scanner in background
    let scanner_args = args.clone();
    let scanner_db = db.clone();
    let scanner_handle = tokio::spawn(async move {
        let geo = if !scanner_args.no_geo { Some(GeoService::new(scanner_args.geoip_db.as_deref())) } else { None };
        if let Err(e) = run_scanner_logic(scanner_db, &scanner_args, geo).await {
            error!("Scanner error: {}", e);
        }
    });
    
    // Start API server
    let api_result = start_api_server(db, args).await;
    
    // Wait for scanner to finish (if it ever does in loop mode)
    let _ = scanner_handle.await;
    
    api_result
}

/// Start the API server
async fn start_api_server(db: SqliteDB, args: &Args) -> Result<()> {
    use actix_cors::Cors;
    use actix_web::{web, App, HttpServer};
    
    let db_data = web::Data::new(db);
    
    // Get OpenAPI documentation
    let openapi = api::ApiDoc::openapi();
    
    // Copy necessary args fields for closure
    let swagger_ui_enabled = args.swagger_ui || args.api || args.api_only;
    let api_host = args.api_host.clone();
    let api_port = args.api_port;
    
    info!("Starting HTTP server on {}:{}", api_host, api_port);
    
    let mut server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        
        let mut app = App::new()
            .wrap(cors)
            .app_data(db_data.clone())
            .configure(api::init_routes);
        
        if swagger_ui_enabled {
            let openapi_clone = openapi.clone();
            app = app.route("/api-docs/openapi.json", web::get().to(move || {
                let json = serde_json::to_string(&openapi_clone).unwrap_or_else(|_| "{}".to_string());
                actix_web::HttpResponse::Ok().content_type("application/json").body(json)
            }));
        }
        
        app
    });
    
    // Bind to specified address and port
    server = server.bind((api_host.as_str(), api_port))?;
    
    info!("API server started successfully");
    info!("API endpoints: http://{}:{}/api/v1/", args.api_host, args.api_port);
    info!("OpenAPI JSON: http://{}:{}/api-docs/openapi.json", args.api_host, args.api_port);
    
    server.run().await?;
    
    Ok(())
}

/// Scanner logic (extracted from original main function)
async fn run_scanner_logic(db: SqliteDB, args: &Args, geo_service: Option<GeoService>) -> Result<()> {
    use model::{parse_port_range, IpRange};
    use service::{ConScanner, SynScanner};
    
    // Check for previous scan progress
    let (mut current_round, resume_ip, resume_ip_type) = db
        .get_progress()?
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
            let (start_ip, end_ip) = args
                .start_ip
                .as_ref()
                .zip(args.end_ip.as_ref())
                .map(|(s, e)| (s.clone(), e.clone()))
                .unwrap_or_else(Args::get_default_ipv4_range);

            // Resume from last position if applicable
            let actual_start_ip = if resume_ip_type.as_deref() == Some("IPv4") {
                resume_ip
                    .as_ref()
                    .map(|ip| {
                        info!("Resuming IPv4 from: {}", ip);
                        ip.clone()
                    })
                    .unwrap_or(start_ip)
            } else {
                start_ip
            };

            info!("Scanning IPv4: {} - {}", actual_start_ip, end_ip);
            match IpRange::new(&actual_start_ip, &end_ip) {
                Ok(ip_range) => {
                    let start_time = std::time::Instant::now();

                    let (tx, rx) = tokio::sync::mpsc::channel(args.pipeline_buffer);

                    // Producer Task
                    let args_clone = args.clone();
                    let ip_iter = ip_range.iter();
                    let producer = tokio::spawn(async move {
                        for ip in ip_iter {
                            if args_clone.skip_private && Args::is_private_ipv4(&ip.to_string()) {
                                continue;
                            }
                            // Skip 0.0.0.0/8 range as it's not routable
                            if let std::net::IpAddr::V4(ipv4) = ip {
                                if ipv4.octets()[0] == 0 {
                                    continue;
                                }
                            }
                            if tx.send(ip).await.is_err() {
                                break;
                            }
                        }
                    });

                    // Consumer (Scanner)
                    let current_round_clone = current_round;

                    let metrics = if args.syn {
                        // SYN Scan Mode
                        match SynScanner::new(db.clone(), current_round, args.result_buffer, args.db_batch_size, args.flush_interval_ms, args.max_rate, args.rate_window_secs) {
                            Ok(scanner) => {
                                scanner
                                    .run_pipeline(rx, ports.clone(), move |total_scanned| {
                                        if total_scanned % 1000 == 0 {
                                            let elapsed = start_time.elapsed().as_secs_f64();
                                            let rate = total_scanned as f64 / elapsed;
                                            info!(
                                                "IPv4 Progress [R{}]: {} IPs - {:.2} packets/sec",
                                                current_round_clone, total_scanned, rate
                                            );
                                        }
                                    })
                                    .await?;
                                scanner.get_metrics().clone()
                            }
                            Err(e) => {
                                error!("Failed to initialize SYN scanner: {}", e);
                                return Err(e);
                            }
                        }
                    } else {
                        // Connect Scan Mode
                        let scanner = ConScanner::new(
                            db.clone(),
                            args.timeout,
                            args.concurrency,
                            current_round,
                            args.result_buffer,
                            args.db_batch_size,
                            args.flush_interval_ms,
                            args.max_rate,
                            args.rate_window_secs,
                        );
                        scanner
                            .run_pipeline(rx, ports.clone(), move |total_scanned| {
                                if total_scanned % 1000 == 0 {
                                    let elapsed = start_time.elapsed().as_secs_f64();
                                    let rate = total_scanned as f64 / elapsed;
                                    info!(
                                        "IPv4 Progress [R{}]: {} IPs - {:.2} IPs/sec",
                                        current_round_clone, total_scanned, rate
                                    );
                                }
                            })
                            .await?;
                        scanner.get_metrics().clone()
                    };

                    // Wait for producer
                    let _ = producer.await;

                    let total_processed = metrics.get_scanned();
                    info!(
                        "IPv4 scan completed: {} IPs in {:.2}s ({:.2} IPs/sec)",
                        total_processed,
                        start_time.elapsed().as_secs_f64(),
                        total_processed as f64 / start_time.elapsed().as_secs_f64()
                    );
                    metrics.print_summary();
                }
                Err(e) => error!("Failed to create IPv4 range: {}", e),
            }
        }

        // Geolocation Enrichment
        if let Some(geo) = &geo_service {
            // Process in batches to avoid holding up the loop too long, 
            // but enough to catch up with scanning speed eventually.
            // Since we scan fast, we might accumulate many IPs. 
            // Let's try to process up to 1000 per round for now.
            info!("Starting geolocation enrichment...");
            match db.get_ips_missing_geo(1000) {
                Ok(ips_to_enrich) => {
                    if !ips_to_enrich.is_empty() {
                        info!("Found {} IPs missing geolocation info", ips_to_enrich.len());
                        let mut enriched_count = 0;
                        
                        for ip in ips_to_enrich {
                            // Add a small delay to respect API rate limits if using API
                            // Ideally this should be handled inside GeoService or RateLimiter
                            match geo.lookup(&ip).await {
                                Ok(info) => {
                                    if let Err(e) = db.save_ip_geo_info(&info) {
                                        error!("Failed to save geo info for {}: {}", ip, e);
                                    } else {
                                        enriched_count += 1;
                                    }
                                }
                                Err(e) => error!("Failed to lookup geo info for {}: {}", ip, e),
                            }
                        }
                        info!("Enriched {} IPs with geolocation data", enriched_count);
                    }
                }
                Err(e) => error!("Failed to fetch IPs for enrichment: {}", e),
            }
        }

        // Print statistics
        let (total_results, unique_open) = db.get_stats()?;
        let memory_mb = db.get_memory_usage()? as f64 / 1024.0 / 1024.0;
        info!("=== Round {} Stats ===", current_round);
        info!(
            "Total open records: {}, Unique IPs: {}, Memory: {:.2} MB",
            total_results, unique_open, memory_mb
        );

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
