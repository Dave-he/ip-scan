//! API request handlers
//!
//! This module contains the request handlers for all API endpoints.

use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use tracing::error;

use crate::api::models::*;
use crate::dao::SqliteDB;
use crate::model::ServiceInfo;

/// Get paginated scan results with filtering
#[utoipa::path(
    get,
    path = "/api/v1/results",
    params(ResultsQuery),
    responses(
        (status = 200, description = "Successfully retrieved scan results", body = PaginatedResults),
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Results"
)]
pub async fn get_results(
    db: web::Data<SqliteDB>,
    query: web::Query<ResultsQuery>,
) -> impl Responder {
    // Validate pagination
    if let Err(err) = query.pagination.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: err,
            code: Some("INVALID_PAGINATION".to_string()),
        });
    }

    match db.get_scan_results(
        query.pagination.page,
        query.pagination.page_size,
        query.filter.ip.as_deref(),
        query.filter.port,
        query.filter.round,
        query.filter.ip_type.as_deref(),
    ) {
        Ok((results, total)) => {
            let total_pages = total.div_ceil(query.pagination.page_size);

            let api_results: Vec<ScanResult> = results
                .into_iter()
                .map(|r| ScanResult {
                    ip_address: r.ip_address,
                    ip_type: r.ip_type,
                    port: r.port,
                    scan_round: r.scan_round,
                    first_seen: r.first_seen,
                    last_seen: r.last_seen,
                    country: r.country,
                    region: r.region,
                    city: r.city,
                    isp: r.isp,
                    asn: r.asn,
                    reverse_dns: r.reverse_dns,
                    service_name: r.service_name,
                    banner: r.banner,
                    category: None,
                    risk_score: r.risk_score,
                    latitude: r.latitude,
                    longitude: r.longitude,
                })
                .collect();

            HttpResponse::Ok().json(PaginatedResults {
                results: api_results,
                total,
                page: query.pagination.page,
                page_size: query.pagination.page_size,
                total_pages,
            })
        }
        Err(e) => {
            error!("Failed to get scan results: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Get scan results for a specific IP
#[utoipa::path(
    get,
    path = "/api/v1/results/{ip}",
    params(
        ("ip" = String, Path, description = "IP address")
    ),
    responses(
        (status = 200, description = "Successfully retrieved scan results for IP", body = Vec<ScanResult>),
        (status = 404, description = "IP not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Results"
)]
pub async fn get_results_by_ip(db: web::Data<SqliteDB>, ip: web::Path<String>) -> impl Responder {
    match db.get_results_by_ip(&ip) {
        Ok(results) => {
            if results.is_empty() {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: format!("No scan results found for IP: {}", ip),
                    code: Some("IP_NOT_FOUND".to_string()),
                })
            } else {
                let api_results: Vec<ScanResult> = results
                    .into_iter()
                    .map(|r| ScanResult {
                        ip_address: r.ip_address,
                        ip_type: r.ip_type,
                        port: r.port,
                        scan_round: r.scan_round,
                        first_seen: r.first_seen,
                        last_seen: r.last_seen,
                        country: r.country,
                        region: r.region,
                        city: r.city,
                        isp: r.isp,
                        asn: r.asn,
                        reverse_dns: r.reverse_dns,
                        service_name: r.service_name,
                        banner: r.banner,
                        category: None,
                        risk_score: r.risk_score,
                        latitude: r.latitude,
                        longitude: r.longitude,
                    })
                    .collect();

                HttpResponse::Ok().json(api_results)
            }
        }
        Err(e) => {
            error!("Failed to get results for IP {}: {}", ip, e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Get scan results for a specific port
#[utoipa::path(
    get,
    path = "/api/v1/results/port/{port}",
    params(
        ("port" = u16, Path, description = "Port number")
    ),
    responses(
        (status = 200, description = "Successfully retrieved scan results for port", body = Vec<ScanResult>),
        (status = 404, description = "Port not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Results"
)]
pub async fn get_results_by_port(db: web::Data<SqliteDB>, port: web::Path<u16>) -> impl Responder {
    match db.get_results_by_port(*port) {
        Ok(results) => {
            if results.is_empty() {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: format!("No scan results found for port: {}", port),
                    code: Some("PORT_NOT_FOUND".to_string()),
                })
            } else {
                let api_results: Vec<ScanResult> = results
                    .into_iter()
                    .map(|r| ScanResult {
                        ip_address: r.ip_address,
                        ip_type: r.ip_type,
                        port: r.port,
                        scan_round: r.scan_round,
                        first_seen: r.first_seen,
                        last_seen: r.last_seen,
                        country: r.country,
                        region: r.region,
                        city: r.city,
                        isp: r.isp,
                        asn: r.asn,
                        reverse_dns: r.reverse_dns,
                        service_name: r.service_name,
                        banner: r.banner,
                        category: None,
                        risk_score: r.risk_score,
                        latitude: r.latitude,
                        longitude: r.longitude,
                    })
                    .collect();

                HttpResponse::Ok().json(api_results)
            }
        }
        Err(e) => {
            error!("Failed to get results for port {}: {}", port, e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Get scan results for a specific round
#[utoipa::path(
    get,
    path = "/api/v1/results/round/{round}",
    params(
        ("round" = i64, Path, description = "Scan round number")
    ),
    responses(
        (status = 200, description = "Successfully retrieved scan results for round", body = Vec<ScanResult>),
        (status = 404, description = "Round not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Results"
)]
pub async fn get_results_by_round(
    db: web::Data<SqliteDB>,
    round: web::Path<i64>,
) -> impl Responder {
    match db.get_results_by_round(*round) {
        Ok(results) => {
            if results.is_empty() {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: format!("No scan results found for round: {}", round),
                    code: Some("ROUND_NOT_FOUND".to_string()),
                })
            } else {
                let api_results: Vec<ScanResult> = results
                    .into_iter()
                    .map(|r| ScanResult {
                        ip_address: r.ip_address,
                        ip_type: r.ip_type,
                        port: r.port,
                        scan_round: r.scan_round,
                        first_seen: r.first_seen,
                        last_seen: r.last_seen,
                        country: r.country,
                        region: r.region,
                        city: r.city,
                        isp: r.isp,
                        asn: r.asn,
                        reverse_dns: r.reverse_dns,
                        service_name: r.service_name,
                        banner: r.banner,
                        category: None,
                        risk_score: r.risk_score,
                        latitude: r.latitude,
                        longitude: r.longitude,
                    })
                    .collect();

                HttpResponse::Ok().json(api_results)
            }
        }
        Err(e) => {
            error!("Failed to get results for round {}: {}", round, e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Lightweight health endpoint for load balancers and orchestration.
#[utoipa::path(
    get,
    path = "/api/v1/healthz",
    responses(
        (status = 200, description = "Database is available"),
        (status = 503, description = "Database is unavailable")
    ),
    tag = "Operations"
)]
pub async fn get_health(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_current_round() {
        Ok(round) => HttpResponse::Ok()
            .json(serde_json::json!({"status": "ok", "database": "ok", "round": round})),
        Err(e) => {
            error!("Health check failed: {}", e);
            HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({"status": "degraded", "database": "error"}))
        }
    }
}

/// Discover the backend protocol, capabilities and endpoint contract.
#[utoipa::path(
    get,
    path = "/api/v1/system",
    responses(
        (status = 200, description = "Backend protocol metadata", body = SystemInfoResponse),
        (status = 503, description = "Backend is degraded", body = SystemInfoResponse)
    ),
    tag = "Operations"
)]
pub async fn get_system_info(
    db: web::Data<SqliteDB>,
    node: web::Data<crate::api::NodeIdentity>,
) -> impl Responder {
    let (status, database) = match db.get_current_round() {
        Ok(_) => ("ready", "ok"),
        Err(_) => ("degraded", "error"),
    };
    let response = SystemInfoResponse {
        protocol: "ip-scan".to_string(),
        api_version: "v1".to_string(),
        service: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: status.to_string(),
        database: database.to_string(),
        server_time: chrono::Utc::now().to_rfc3339(),
        capabilities: vec![
            "scan.control".to_string(),
            "scan.status".to_string(),
            "results.pagination".to_string(),
            "results.export".to_string(),
            "services.enrichment".to_string(),
            "visualization.ip-map".to_string(),
            "observability.prometheus".to_string(),
            "distributed.cluster-node".to_string(),
        ],
        endpoints: vec![
            "/healthz".to_string(),
            "/system".to_string(),
            "/stats".to_string(),
            "/results".to_string(),
            "/services".to_string(),
            "/scan".to_string(),
            "/export".to_string(),
            "/stats/by-ip-family".to_string(),
            "/stats/by-service".to_string(),
            "/stats/by-category".to_string(),
            "/map/locations".to_string(),
        ],
        node_id: Some(node.id.clone()),
        node_label: node.label.clone(),
        node_provider: node.provider.clone(),
        node_latitude: node.latitude,
        node_longitude: node.longitude,
        current_target_start: node.current_target_start.clone(),
        current_target_end: node.current_target_end.clone(),
    };
    if status == "ready" {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

/// Get scan statistics
#[utoipa::path(
    get,
    path = "/api/v1/stats",
    responses(
        (status = 200, description = "Successfully retrieved statistics", body = StatsResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Statistics"
)]
pub async fn get_stats(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats() {
        Ok((total_open_records, unique_ips)) => {
            let memory_usage_bytes = db.get_memory_usage().unwrap_or(0);
            let memory_usage_mb = memory_usage_bytes as f64 / 1024.0 / 1024.0;

            let current_round = db.get_current_round().unwrap_or(1);
            let last_scan_time = db.get_last_scan_time().unwrap_or(None);

            HttpResponse::Ok().json(StatsResponse {
                total_open_records,
                unique_ips,
                memory_usage_mb,
                current_round,
                last_scan_time,
            })
        }
        Err(e) => {
            error!("Failed to get statistics: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve statistics".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Export operational metrics in Prometheus text format.
#[utoipa::path(
    get,
    path = "/api/v1/stats/prometheus",
    responses(
        (status = 200, description = "Prometheus metrics", body = String),
        (status = 500, description = "Failed to collect metrics")
    ),
    tag = "Operations"
)]
pub async fn get_prometheus_metrics(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats() {
        Ok((total_open_records, unique_ips)) => {
            let memory_bytes = db.get_memory_usage().unwrap_or(0);
            let round = db.get_current_round().unwrap_or(0);
            let body = format!(
                "# HELP ip_scan_open_port_records Current open IP/port records\n# TYPE ip_scan_open_port_records gauge\nip_scan_open_port_records {}\n# HELP ip_scan_unique_ips Unique IPs with open ports\n# TYPE ip_scan_unique_ips gauge\nip_scan_unique_ips {}\n# HELP ip_scan_bitmap_bytes Persisted bitmap storage in bytes\n# TYPE ip_scan_bitmap_bytes gauge\nip_scan_bitmap_bytes {}\n# HELP ip_scan_round Current scan round\n# TYPE ip_scan_round gauge\nip_scan_round {}\n",
                total_open_records, unique_ips, memory_bytes, round
            );
            HttpResponse::Ok()
                .content_type("text/plain; version=0.0.4")
                .body(body)
        }
        Err(e) => {
            error!("Failed to export Prometheus metrics: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Return bounded open/closed changes between two bitmap rounds.
#[utoipa::path(
    get,
    path = "/api/v1/stats/changes/{round}/{port}",
    params(
        ("round" = i64, Path, description = "Current scan round"),
        ("port" = u16, Path, description = "Port to compare")
    ),
    responses(
        (status = 200, description = "Changed IP addresses", body = Vec<crate::dao::PortChange>),
        (status = 400, description = "Invalid round or port", body = ErrorResponse),
        (status = 500, description = "Database error", body = ErrorResponse)
    ),
    tag = "Statistics"
)]
pub async fn get_bitmap_changes(
    db: web::Data<SqliteDB>,
    path: web::Path<(i64, u16)>,
) -> impl Responder {
    let (round, port) = path.into_inner();
    if round < 1 || port == 0 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Invalid round or port".to_string(),
            code: Some("INVALID_CHANGE_QUERY".to_string()),
        });
    }
    match db.get_bitmap_changes(round, port, 10_000) {
        Ok(changes) => HttpResponse::Ok().json(changes),
        Err(e) => {
            error!("Failed to retrieve bitmap changes: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve bitmap changes".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Get top ports statistics
#[utoipa::path(
    get,
    path = "/api/v1/stats/top-ports",
    params(
        ("limit" = Option<usize>, Query, description = "Number of top ports to return (default: 10, max: 100)")
    ),
    responses(
        (status = 200, description = "Successfully retrieved top ports", body = TopPortsResponse),
        (status = 400, description = "Invalid limit parameter", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Statistics"
)]
pub async fn get_top_ports(
    db: web::Data<SqliteDB>,
    query: web::Query<TopPortsQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(10);

    if limit == 0 || limit > 100 {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Limit must be between 1 and 100".to_string(),
            code: Some("INVALID_LIMIT".to_string()),
        });
    }

    // Get total count of all open ports first
    let total_all_ports = match db.get_total_open_ports_count() {
        Ok(count) => count,
        Err(e) => {
            error!("Failed to get total open ports count: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve statistics".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
    };

    match db.get_top_ports(limit) {
        Ok(port_stats) => {
            let ports: Vec<PortStats> = port_stats
                .into_iter()
                .map(|(port, count)| {
                    let percentage = if total_all_ports > 0 {
                        (count as f64 / total_all_ports as f64) * 100.0
                    } else {
                        0.0
                    };

                    PortStats {
                        port,
                        open_count: count,
                        percentage,
                    }
                })
                .collect();

            HttpResponse::Ok().json(TopPortsResponse {
                ports,
                total_open_ports: total_all_ports,
            })
        }
        Err(e) => {
            error!("Failed to get top ports: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve top ports".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Start a new scan
pub async fn start_scan(
    controller: web::Data<std::sync::Arc<tokio::sync::Mutex<crate::service::ScanController>>>,
    runtime_scan_state: web::Data<crate::service::RuntimeScanState>,
    request: web::Json<StartScanRequest>,
) -> impl Responder {
    use crate::cli::Args;

    if runtime_scan_state.is_cli_scan_running() {
        return HttpResponse::Conflict().json(ErrorResponse {
            error: "A CLI-managed scan is already running".to_string(),
            code: Some("SCAN_ALREADY_RUNNING".to_string()),
        });
    }

    // Create a minimal base args for scan controller
    let base_args = Args {
        config_flag: None,
        config_pos: None,
        start_ip: None,
        end_ip: None,
        ports: "80".to_string(),
        timeout: 500,
        concurrency: 100,
        database: "scan_results.db".to_string(),
        dry_run: false,
        verbose: false,
        loop_mode: false,
        scan_public: false,
        ipv4: true,
        ipv6: false,
        only_store_open: true,
        skip_private: true,
        syn: false,
        raw: false,
        raw_workers: None,
        raw_inflight: None,
        api: false,
        api_only: false,
        no_api: false,
        api_host: "127.0.0.1".to_string(),
        api_port: 9090,
        swagger_ui: false,
        target: None,
        preset: None,
        output_format: "text".to_string(),
        geoip_db: None,
        no_geo: false,
        probe_service: false,
        probe_timeout: 5,
        probe_concurrency: 50,
        geo_concurrency: 8,
        worker_threads: None,
        pipeline_buffer: 2000,
        result_buffer: 10000,
        db_batch_size: 2000,
        flush_interval_ms: 1000,
        max_rate: 100000,
        rate_window_secs: 1,
        round_delay_ms: 0,
        max_rounds: 4,
        nmap_sS: false,
        nmap_sT: false,
        nmap_sn: false,
        nmap_Pn: false,
        nmap_sV: false,
        nmap_O: false,
        nmap_A: false,
        nmap_sC: false,
        nmap_F: false,
        nmap_T: None,
        nmap_top_ports: None,
        nmap_iL: None,
        nmap_oN: None,
        nmap_oJ: None,
        nmap_oG: None,
        nmap_oX: None,
        nmap_oA: None,
        nmap_target: Vec::new(),
        node_id: None,
        node_label: None,
        node_provider: None,
        node_latitude: None,
        node_longitude: None,
    };

    // Get shared controller with async lock
    let controller_guard = controller.lock().await;

    // No strict validation - allow empty request, will use defaults
    match controller_guard
        .start_scan(request.into_inner(), &base_args)
        .await
    {
        Ok(scan_id) => HttpResponse::Ok().json(json!({
            "scan_id": scan_id,
            "message": "Scan started successfully"
        })),
        Err(e) => {
            error!("Failed to start scan: {}", e);
            HttpResponse::Conflict().json(ErrorResponse {
                error: format!("Failed to start scan: {}", e),
                code: Some("SCAN_START_FAILED".to_string()),
            })
        }
    }
}

/// Stop the current scan
#[utoipa::path(
    post,
    path = "/api/v1/scan/stop",
    responses(
        (status = 200, description = "Scan stopped successfully"),
        (status = 404, description = "No scan in progress", body = ErrorResponse),
        (status = 409, description = "CLI-managed scan is not API-controllable", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn stop_scan(
    controller: web::Data<std::sync::Arc<tokio::sync::Mutex<crate::service::ScanController>>>,
    runtime_scan_state: web::Data<crate::service::RuntimeScanState>,
) -> impl Responder {
    if runtime_scan_state.is_cli_scan_running() {
        return HttpResponse::Conflict().json(ErrorResponse {
            error: "The running scan is managed by the CLI and cannot be stopped via this endpoint"
                .to_string(),
            code: Some("SCAN_NOT_API_CONTROLLABLE".to_string()),
        });
    }

    // Get shared controller with async lock
    let controller_guard = controller.lock().await;

    match controller_guard.stop_scan().await {
        Ok(()) => HttpResponse::Ok().json(json!({
            "message": "Scan stopped successfully"
        })),
        Err(e) => {
            error!("Failed to stop scan: {}", e);
            HttpResponse::NotFound().json(ErrorResponse {
                error: format!("Failed to stop scan: {}", e),
                code: Some("SCAN_STOP_FAILED".to_string()),
            })
        }
    }
}

/// Get current scan status
#[utoipa::path(
    get,
    path = "/api/v1/scan/status",
    responses(
        (status = 200, description = "Retrieved API/CLI scan status and controllability"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn get_scan_status(
    controller: web::Data<std::sync::Arc<tokio::sync::Mutex<crate::service::ScanController>>>,
    runtime_scan_state: web::Data<crate::service::RuntimeScanState>,
    db: web::Data<SqliteDB>,
) -> impl Responder {
    // Get shared controller with async lock
    let controller_guard = controller.lock().await;

    // Merge API-controlled and CLI-controlled scanner state. In combined mode
    // the long-running CLI scanner is intentionally not owned by ScanController.
    let controller_status = controller_guard.get_status();
    let controller_running = controller_guard.is_running();
    let cli_running = runtime_scan_state.is_cli_scan_running();
    let scan_id = controller_guard.get_scan_id();
    let (effective_status, is_running, source, controllable) = if controller_running {
        (controller_status, true, Some("api"), true)
    } else if cli_running {
        (ScanStatus::Running, true, Some("cli"), false)
    } else {
        (controller_status, false, None, false)
    };

    // Get database metadata
    let stored_db_status = db
        .get_metadata("scan_status")
        .unwrap_or(Some("idle".to_string()))
        .unwrap_or("idle".to_string());
    let db_status = if cli_running {
        "running".to_string()
    } else {
        stored_db_status
    };
    let current_round = db.get_current_round().unwrap_or(1);
    let last_scan_time = db.get_last_scan_time().unwrap_or(None);

    // Get scan times from metadata
    let start_time = db.get_metadata("last_scan_start_time").ok().flatten();
    let stop_time = db.get_metadata("last_scan_stop_time").ok().flatten();

    HttpResponse::Ok().json(json!({
        "status": effective_status,
        "is_running": is_running,
        "source": source,
        "controllable": controllable,
        "scan_id": scan_id,
        "db_status": db_status,
        "current_round": current_round,
        "last_scan_time": last_scan_time,
        "start_time": start_time,
        "stop_time": stop_time,
        "next_scheduled_scan": null
    }))
}

/// Get scan history
#[utoipa::path(
    get,
    path = "/api/v1/scan/history",
    responses(
        (status = 200, description = "Successfully retrieved scan history"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn get_scan_history(db: web::Data<SqliteDB>) -> impl Responder {
    // Get scan history using the new public method
    match db.get_scan_history(50) {
        Ok(history) => {
            let scans: Vec<_> = history
                .into_iter()
                .map(|record| {
                    json!({
                        "round": record.round,
                        "start_time": record.start_time,
                        "end_time": record.end_time,
                        "total_open_ports": record.total_open_ports,
                        "ports_scanned": record.ports_scanned
                    })
                })
                .collect();

            HttpResponse::Ok().json(json!({
                "scans": scans
            }))
        }
        Err(e) => {
            error!("Failed to retrieve scan history: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve scan history".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}
/// Export scan results as CSV
#[utoipa::path(
    get,
    path = "/api/v1/export/csv",
    params(FilterQuery),
    responses(
        (status = 200, description = "CSV export successful", content_type = "text/csv"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Export"
)]
pub async fn export_csv(db: web::Data<SqliteDB>, query: web::Query<FilterQuery>) -> impl Responder {
    use futures::stream;

    const BATCH_SIZE: usize = 1000;
    let db_clone = db.clone();
    let ip_filter = query.ip.clone();
    let port_filter = query.port;
    let round_filter = query.round;
    let ip_type_filter = query.ip_type.clone();

    let stream = stream::unfold((1usize, false, true), move |(page, done, is_first)| {
        let db = db_clone.clone();
        let ip = ip_filter.clone();
        let ip_type = ip_type_filter.clone();

        async move {
            if done {
                return None;
            }

            match db.get_scan_results(
                page,
                BATCH_SIZE,
                ip.as_deref(),
                port_filter,
                round_filter,
                ip_type.as_deref(),
            ) {
                Ok((results, total)) => {
                    if results.is_empty() {
                        return None;
                    }

                    let mut csv_chunk = String::new();

                    if is_first {
                        csv_chunk
                            .push_str("ip_address,ip_type,port,scan_round,first_seen,last_seen\n");
                    }

                    for result in results {
                        csv_chunk.push_str(&format!(
                            "{},{},{},{},{},{}\n",
                            result.ip_address,
                            result.ip_type,
                            result.port,
                            result.scan_round,
                            result.first_seen,
                            result.last_seen
                        ));
                    }

                    let is_done = page * BATCH_SIZE >= total;
                    Some((
                        Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(csv_chunk)),
                        (page + 1, is_done, false),
                    ))
                }
                Err(e) => {
                    error!("Failed to export CSV batch: {}", e);
                    None
                }
            }
        }
    });

    HttpResponse::Ok()
        .content_type("text/csv")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"scan_results.csv\"",
        ))
        .streaming(stream)
}

/// Export scan results as JSON
#[utoipa::path(
    get,
    path = "/api/v1/export/json",
    params(FilterQuery),
    responses(
        (status = 200, description = "JSON export successful", body = Vec<ScanResult>),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Export"
)]
pub async fn export_json(
    db: web::Data<SqliteDB>,
    query: web::Query<FilterQuery>,
) -> impl Responder {
    // Limit export to prevent OOM
    const MAX_EXPORT_SIZE: usize = 50000;

    match db.get_scan_results(
        1,
        MAX_EXPORT_SIZE,
        query.ip.as_deref(),
        query.port,
        query.round,
        query.ip_type.as_deref(),
    ) {
        Ok((results, total)) => {
            if total > MAX_EXPORT_SIZE {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: format!(
                        "Export size too large ({} records). Please use filters to reduce the result set to under {} records.",
                        total, MAX_EXPORT_SIZE
                    ),
                    code: Some("EXPORT_SIZE_EXCEEDED".to_string()),
                });
            }

            let api_results: Vec<ScanResult> = results
                .into_iter()
                .map(|r| ScanResult {
                    ip_address: r.ip_address,
                    ip_type: r.ip_type,
                    port: r.port,
                    scan_round: r.scan_round,
                    first_seen: r.first_seen,
                    last_seen: r.last_seen,
                    country: r.country,
                    region: r.region,
                    city: r.city,
                    isp: r.isp,
                    asn: r.asn,
                    reverse_dns: r.reverse_dns,
                    service_name: r.service_name,
                    banner: r.banner,
                    category: None,
                    risk_score: r.risk_score,
                    latitude: r.latitude,
                    longitude: r.longitude,
                })
                .collect();

            HttpResponse::Ok().json(api_results)
        }
        Err(e) => {
            error!("Failed to export JSON: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to export scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Export scan results as NDJSON (Newline Delimited JSON)
#[utoipa::path(
    get,
    path = "/api/v1/export/ndjson",
    params(FilterQuery),
    responses(
        (status = 200, description = "NDJSON export successful", content_type = "application/x-ndjson"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Export"
)]
pub async fn export_ndjson(
    db: web::Data<SqliteDB>,
    query: web::Query<FilterQuery>,
) -> impl Responder {
    // Limit export to prevent OOM
    const MAX_EXPORT_SIZE: usize = 50000;

    match db.get_scan_results(
        1,
        MAX_EXPORT_SIZE,
        query.ip.as_deref(),
        query.port,
        query.round,
        query.ip_type.as_deref(),
    ) {
        Ok((results, total)) => {
            if total > MAX_EXPORT_SIZE {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    error: format!(
                        "Export size too large ({} records). Please use filters to reduce the result set to under {} records.",
                        total, MAX_EXPORT_SIZE
                    ),
                    code: Some("EXPORT_SIZE_EXCEEDED".to_string()),
                });
            }

            let mut ndjson_content = String::new();

            for result in results {
                let json_line = json!({
                    "ip_address": result.ip_address,
                    "ip_type": result.ip_type,
                    "port": result.port,
                    "scan_round": result.scan_round,
                    "first_seen": result.first_seen,
                    "last_seen": result.last_seen
                });

                ndjson_content.push_str(&serde_json::to_string(&json_line).unwrap_or_default());
                ndjson_content.push('\n');
            }

            HttpResponse::Ok()
                .content_type("application/x-ndjson")
                .body(ndjson_content)
        }
        Err(e) => {
            error!("Failed to export NDJSON: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to export scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

fn service_info_to_response(info: &ServiceInfo) -> ServiceInfoResponse {
    ServiceInfoResponse {
        ip: info.ip.clone(),
        port: info.port,
        service_name: info.service_name.clone(),
        protocol: info.protocol.clone(),
        banner: info.banner.clone(),
        http_title: info.http_title.clone(),
        http_server: info.http_server.clone(),
        http_body_preview: info.http_body_preview.clone(),
        tls_subject: info.tls_subject.clone(),
        tls_issuer: info.tls_issuer.clone(),
        tls_not_before: info.tls_not_before.clone(),
        tls_not_after: info.tls_not_after.clone(),
        tls_version: info.tls_version.clone(),
        service_version: info.service_version.clone(),
        http_body_hash: info.http_body_hash.clone(),
        http_security_headers: info.http_security_headers.clone(),
        rtt_ms: info.rtt_ms,
        os_guess: info.os_guess.clone(),
        detected_at: info.detected_at.clone(),
    }
}

pub async fn get_service_info_by_ip(
    db: web::Data<SqliteDB>,
    ip: web::Path<String>,
) -> impl Responder {
    match db.get_service_info_by_ip(&ip) {
        Ok(services) => {
            if services.is_empty() {
                HttpResponse::NotFound().json(ErrorResponse {
                    error: format!("No service info found for IP: {}", ip),
                    code: Some("IP_NOT_FOUND".to_string()),
                })
            } else {
                let category = crate::model::IpServiceSummary::categorize(&services);
                let (risk_score, risk_reasons) =
                    crate::model::IpServiceSummary::assess_risk(&services);
                let resp_services: Vec<ServiceInfoResponse> =
                    services.iter().map(service_info_to_response).collect();
                HttpResponse::Ok().json(IpServiceSummaryResponse {
                    ip: ip.to_string(),
                    services: resp_services,
                    ip_type: None,
                    category,
                    risk_score,
                    risk_reasons,
                })
            }
        }
        Err(e) => {
            error!("Failed to get service info for IP {}: {}", ip, e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve service info".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

pub async fn get_service_summaries(
    db: web::Data<SqliteDB>,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    if let Err(err) = query.validate() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: err,
            code: Some("INVALID_PAGINATION".to_string()),
        });
    }

    let offset = (query.page - 1) * query.page_size;

    match db.get_all_ip_service_summaries(query.page_size, offset) {
        Ok(summaries) => {
            let total = db.count_ips_with_service_info().unwrap_or(0);
            let resp_summaries: Vec<IpServiceSummaryResponse> = summaries
                .into_iter()
                .map(|s| {
                    let (risk_score, risk_reasons) =
                        crate::model::IpServiceSummary::assess_risk(&s.services);
                    IpServiceSummaryResponse {
                        ip: s.ip,
                        services: s.services.iter().map(service_info_to_response).collect(),
                        ip_type: s.ip_type,
                        category: s.category,
                        risk_score,
                        risk_reasons,
                    }
                })
                .collect();
            HttpResponse::Ok().json(ServiceSummaryListResponse {
                summaries: resp_summaries,
                total,
                page: query.page,
                page_size: query.page_size,
            })
        }
        Err(e) => {
            error!("Failed to get service summaries: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve service summaries".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Aggregate open-port records grouped by IP family (IPv4 vs IPv6).
/// Lightweight endpoint used by the IP-family view in the distributed
/// frontend.
#[utoipa::path(
    get,
    path = "/api/v1/stats/by-ip-family",
    responses(
        (status = 200, description = "IPv4 vs IPv6 aggregate", body = IpFamilyStatsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_stats_by_ip_family(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats_by_ip_family() {
        Ok((ipv4_unique_ips, ipv6_unique_ips, ipv4_open_ports, ipv6_open_ports)) => {
            HttpResponse::Ok().json(IpFamilyStatsResponse {
                ipv4_unique_ips,
                ipv6_unique_ips,
                ipv4_open_ports,
                ipv6_open_ports,
            })
        }
        Err(e) => {
            error!("Failed to get ip-family stats: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve ip-family stats".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Aggregate open-port records grouped by detected service_name.
/// The distributed frontend renders this as the "by service" view.
#[utoipa::path(
    get,
    path = "/api/v1/stats/by-service",
    responses(
        (status = 200, description = "Per-service aggregate", body = ServiceStatsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_stats_by_service(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats_by_service() {
        Ok(rows) => {
            let services: Vec<ServiceStatsEntry> = rows
                .into_iter()
                .map(|(service_name, unique_ips, open_ports)| ServiceStatsEntry {
                    service_name,
                    unique_ips,
                    open_ports,
                })
                .collect();
            let total_unique_ips = services.iter().map(|s| s.unique_ips).sum();
            HttpResponse::Ok().json(ServiceStatsResponse {
                services,
                total_unique_ips,
            })
        }
        Err(e) => {
            error!("Failed to get service stats: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve service stats".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Aggregate open-port records grouped by the asset category that
/// `IpServiceSummary::categorize` derives from the detected services.
/// Drives the asset-category donut / list in the distributed frontend.
#[utoipa::path(
    get,
    path = "/api/v1/stats/by-category",
    responses(
        (status = 200, description = "Per-category aggregate", body = CategoryStatsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_stats_by_category(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats_by_category() {
        Ok(rows) => {
            let categories: Vec<CategoryStatsEntry> = rows
                .into_iter()
                .map(|(category, unique_ips)| CategoryStatsEntry {
                    category,
                    unique_ips,
                })
                .collect();
            let total_unique_ips = categories.iter().map(|c| c.unique_ips).sum();
            HttpResponse::Ok().json(CategoryStatsResponse {
                categories,
                total_unique_ips,
            })
        }
        Err(e) => {
            error!("Failed to get category stats: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve category stats".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Return geo-located IPs for the distributed frontend's map view. Limit
/// caps the response size so a single fetch stays under a few hundred KB
/// even when scanning thousands of hosts.
#[utoipa::path(
    get,
    path = "/api/v1/map/locations",
    params(
        ("limit" = Option<usize>, Query, description = "Maximum IPs to return (default: 1000, max: 10000)")
    ),
    responses(
        (status = 200, description = "Geo-located IPs", body = IpLocationsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_map_locations(
    db: web::Data<SqliteDB>,
    query: web::Query<crate::api::models::TopPortsQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(1000).clamp(1, 10_000);
    match db.get_ip_locations(limit) {
        Ok(locations) => {
            // Augment each location with the open-port count and the most
            // common service_name (cheap GROUP BY using existing indexes).
            let mut augmented: Vec<IpLocationResponse> = Vec::with_capacity(locations.len());
            let conn_total = match db.get_stats() {
                Ok(_) => 0usize, // placeholder so the borrow ends before conn re-acquire
                Err(_) => 0,
            };
            let _ = conn_total;
            for loc in locations {
                let (open_ports, top_service) = match db.get_ip_top_service(&loc.ip) {
                    Ok((c, s)) => (c, s),
                    Err(_) => (0, None),
                };
                let ip_type = if loc.ip.contains(':') {
                    Some("IPv6".to_string())
                } else {
                    Some("IPv4".to_string())
                };
                augmented.push(IpLocationResponse {
                    ip: loc.ip,
                    ip_type,
                    country: loc.country,
                    city: loc.city,
                    latitude: loc.latitude.unwrap_or(0.0),
                    longitude: loc.longitude.unwrap_or(0.0),
                    open_ports,
                    top_service,
                });
            }
            let total = db.count_ip_locations().unwrap_or(augmented.len());
            HttpResponse::Ok().json(IpLocationsResponse {
                locations: augmented,
                total,
                limit,
            })
        }
        Err(e) => {
            error!("Failed to get map locations: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve map locations".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

// ── IP detail / aggregates ──────────────────────────────────────────

/// Aggregate everything we know about one IP: geo, ASN, ISP, all open
/// ports, detected services, risk assessment, and how many other IPs
/// share the same ASN / ISP. Single endpoint that drives the IP detail
/// panel in the distributed frontend.
#[utoipa::path(
    get,
    path = "/api/v1/ip/{ip}",
    params(("ip" = String, Path, description = "IP address")),
    responses(
        (status = 200, description = "Comprehensive IP detail", body = IpDetailResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Results"
)]
pub async fn get_ip_detail(db: web::Data<SqliteDB>, ip: web::Path<String>) -> impl Responder {
    let ip_str = ip.to_string();
    let geo = match db.get_ip_detail(&ip_str) {
        Ok(g) => g,
        Err(e) => {
            error!("Failed to read geo info for {ip_str}: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to read ip details".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
    };
    let rows = match db.get_results_by_ip(&ip_str) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to read results for {ip_str}: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to read scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
    };
    let services = match db.get_service_info_by_ip(&ip_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read services for {ip_str}: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to read service info".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
    };
    let (category, risk_score, risk_reasons) = if services.is_empty() {
        ("unknown".to_string(), 0u8, Vec::new())
    } else {
        let cat = crate::model::IpServiceSummary::categorize(&services);
        let (score, reasons) = crate::model::IpServiceSummary::assess_risk(&services);
        (cat, score, reasons)
    };
    let first_seen = rows.iter().map(|r| r.first_seen.clone()).min();
    let last_seen = rows.iter().map(|r| r.last_seen.clone()).max();

    // Build ScanResult entries with risk score per port
    let mut open_ports: Vec<ScanResult> = rows
        .into_iter()
        .map(|r| {
            let port_services: Vec<ServiceInfo> = services
                .iter()
                .filter(|s| s.port == r.port)
                .cloned()
                .collect();
            ScanResult {
                ip_address: r.ip_address.clone(),
                ip_type: r.ip_type,
                port: r.port,
                scan_round: r.scan_round,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                country: r.country.clone(),
                region: r.region,
                city: r.city.clone(),
                isp: r.isp.clone(),
                asn: r.asn.clone(),
                reverse_dns: r.reverse_dns.clone(),
                service_name: r.service_name.clone(),
                banner: r.banner.clone(),
                category: if port_services.is_empty() {
                    None
                } else {
                    Some(category.clone())
                },
                risk_score: if port_services.is_empty() {
                    None
                } else {
                    let (s, _) = crate::model::IpServiceSummary::assess_risk(&port_services);
                    Some(s)
                },
                latitude: r.latitude,
                longitude: r.longitude,
            }
        })
        .collect();

    // Compute peer counts only when ASN/ISP present to avoid extra DB chatter
    let asn_peer_count = geo
        .asn
        .as_deref()
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .map(|s| db.count_asn_peers(s).unwrap_or(0));
    let isp_peer_count = geo
        .isp
        .as_deref()
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .map(|s| db.count_isp_peers(s).unwrap_or(0));

    // Stable sort: ports ordered ascending for predictability
    open_ports.sort_by_key(|p| p.port);

    HttpResponse::Ok().json(IpDetailResponse {
        ip: geo.ip,
        ip_type: open_ports
            .first()
            .map(|p| p.ip_type.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        country: geo.country,
        region: geo.region,
        city: geo.city,
        isp: geo.isp,
        asn: geo.asn,
        reverse_dns: geo.reverse_dns,
        latitude: geo.latitude,
        longitude: geo.longitude,
        geo_source: Some(geo.source),
        first_seen,
        last_seen,
        open_ports,
        category,
        risk_score,
        risk_reasons,
        asn_peer_count,
        isp_peer_count,
    })
}

/// Aggregate stats grouped by ASN (e.g. `AS4134` -> unique IP count).
/// Drives the ASN bar / chart in the IP-family and overview views.
#[utoipa::path(
    get,
    path = "/api/v1/stats/by-asn",
    responses(
        (status = 200, description = "Per-ASN aggregate", body = AsnStatsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_stats_by_asn(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats_by_asn() {
        Ok(rows) => {
            let total_unique_ips: usize = rows.iter().map(|r| r.1).sum();
            let asns: Vec<AsnStatsEntry> = rows
                .into_iter()
                .map(|(asn, unique_ips, open_ports)| AsnStatsEntry {
                    asn,
                    unique_ips,
                    open_ports,
                })
                .collect();
            HttpResponse::Ok().json(AsnStatsResponse {
                asns,
                total_unique_ips,
            })
        }
        Err(e) => {
            error!("Failed to get asn stats: {e}");
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve asn stats".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

/// Aggregate stats grouped by ISP / organization.
#[utoipa::path(
    get,
    path = "/api/v1/stats/by-organization",
    responses(
        (status = 200, description = "Per-organization aggregate", body = OrgStatsResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Distributed"
)]
pub async fn get_stats_by_organization(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats_by_organization() {
        Ok(rows) => {
            let total_unique_ips: usize = rows.iter().map(|r| r.1).sum();
            let organizations: Vec<OrgStatsEntry> = rows
                .into_iter()
                .map(|(isp, unique_ips, open_ports)| OrgStatsEntry {
                    isp,
                    unique_ips,
                    open_ports,
                })
                .collect();
            HttpResponse::Ok().json(OrgStatsResponse {
                organizations,
                total_unique_ips,
            })
        }
        Err(e) => {
            error!("Failed to get organization stats: {e}");
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve organization stats".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/assets",
    params(AssetsQuery),
    responses(
        (status = 200, description = "Paginated asset list", body = AssetSummaryListResponse),
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Results"
)]
pub async fn list_assets(
    db: web::Data<SqliteDB>,
    query: web::Query<AssetsQuery>,
) -> impl Responder {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(50).clamp(1, 500);
    let (mut assets, total) = match db.list_assets(
        page,
        page_size,
        query.country.as_deref(),
        query.service.as_deref(),
        query.category.as_deref(),
        query.min_risk,
    ) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to list assets: {e}");
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve assets".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
    };
    if let Err(e) = db.enrich_assets(&mut assets) {
        error!("Failed to enrich assets: {e}");
    }
    let total_pages = if total == 0 {
        0
    } else {
        total.div_ceil(page_size).max(1)
    };
    HttpResponse::Ok().json(AssetSummaryListResponse {
        assets,
        total,
        page,
        page_size,
        total_pages,
    })
}

/// Captured TCP snapshots (raw banner / HTTP / TLS bytes) for a single
/// IP, one row per port. Drives the "IP preview" panel and the per-port
/// detail drawer in the distributed frontend.
#[utoipa::path(
    get,
    path = "/api/v1/snapshots/{ip}",
    params(("ip" = String, Path, description = "IP address")),
    responses(
        (status = 200, description = "TCP snapshots", body = TcpSnapshotListResponse),
        (status = 500, description = "Database error", body = ErrorResponse),
    ),
    tag = "Services"
)]
pub async fn get_tcp_snapshots_for_ip(
    db: web::Data<SqliteDB>,
    ip: web::Path<String>,
) -> impl Responder {
    let ip_str = ip.to_string();
    match db.get_tcp_snapshots_by_ip(&ip_str) {
        Ok(rows) => {
            let snapshots: Vec<TcpSnapshotResponse> = rows
                .into_iter()
                .map(|s| TcpSnapshotResponse {
                    ip: s.ip.clone(),
                    port: s.port,
                    protocol: s.protocol,
                    banner_first_line: s.banner_first_line,
                    banner_raw_hex: s.banner_raw_hex,
                    banner_raw_len: s.banner_raw_len,
                    http_status: s.http_status.map(|v| v as i64),
                    http_server: s.http_server,
                    http_title: s.http_title,
                    tls_subject: s.tls_subject,
                    tls_issuer: s.tls_issuer,
                    tls_version: s.tls_version,
                    tls_not_before: s.tls_not_before,
                    tls_not_after: s.tls_not_after,
                    tls_san: s.tls_san,
                    os_guess: s.os_guess,
                    rtt_ms: s.rtt_ms,
                    detected_technologies: s.detected_technologies,
                    purpose: s.purpose,
                    captured_at: s.captured_at,
                })
                .collect();
            HttpResponse::Ok().json(TcpSnapshotListResponse {
                ip: ip_str,
                snapshots,
            })
        }
        Err(e) => {
            error!("Failed to read snapshots for {ip_str}: {e}");
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to retrieve snapshots".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
}
