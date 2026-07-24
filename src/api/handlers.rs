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
                    city: r.city,
                    reverse_dns: r.reverse_dns,
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
                        city: r.city,
                        reverse_dns: r.reverse_dns,
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
                        city: r.city,
                        reverse_dns: r.reverse_dns,
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
                        city: r.city,
                        reverse_dns: r.reverse_dns,
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
pub async fn get_system_info(db: web::Data<SqliteDB>) -> impl Responder {
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
        ],
        endpoints: vec![
            "/healthz".to_string(),
            "/system".to_string(),
            "/stats".to_string(),
            "/results".to_string(),
            "/services".to_string(),
            "/scan".to_string(),
            "/export".to_string(),
        ],
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
    request: web::Json<StartScanRequest>,
) -> impl Responder {
    use crate::cli::Args;

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
        verbose: false,
        loop_mode: false,
        ipv4: true,
        ipv6: false,
        only_store_open: true,
        skip_private: true,
        syn: false,
        geoip_db: None,
        no_geo: false,
        worker_threads: None,
        pipeline_buffer: 2000,
        result_buffer: 10000,
        db_batch_size: 2000,
        flush_interval_ms: 1000,
        max_rate: 100000,
        rate_window_secs: 1,
        api: false,
        api_only: false,
        no_api: false,
        api_host: "127.0.0.1".to_string(),
        api_port: 9090,
        swagger_ui: false,
        target: None,
        preset: None,
        output_format: "text".to_string(),
        probe_service: false,
        probe_timeout: 5,
        probe_concurrency: 50,
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
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn stop_scan(
    controller: web::Data<std::sync::Arc<tokio::sync::Mutex<crate::service::ScanController>>>,
) -> impl Responder {
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
        (status = 200, description = "Successfully retrieved scan status"),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn get_scan_status(
    controller: web::Data<std::sync::Arc<tokio::sync::Mutex<crate::service::ScanController>>>,
    db: web::Data<SqliteDB>,
) -> impl Responder {
    // Get shared controller with async lock
    let controller_guard = controller.lock().await;

    // Get controller status
    let controller_status = controller_guard.get_status();
    let is_running = controller_guard.is_running();
    let scan_id = controller_guard.get_scan_id();

    // Get database metadata
    let db_status = db
        .get_metadata("scan_status")
        .unwrap_or(Some("idle".to_string()))
        .unwrap_or("idle".to_string());
    let current_round = db.get_current_round().unwrap_or(1);
    let last_scan_time = db.get_last_scan_time().unwrap_or(None);

    // Get scan times from metadata
    let start_time = db.get_metadata("last_scan_start_time").ok().flatten();
    let stop_time = db.get_metadata("last_scan_stop_time").ok().flatten();

    HttpResponse::Ok().json(json!({
        "status": controller_status,
        "is_running": is_running,
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
                    city: r.city,
                    reverse_dns: r.reverse_dns,
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
