//! API request handlers
//!
//! This module contains the request handlers for all API endpoints.

use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use tracing::error;

use crate::api::models::*;
use crate::dao::SqliteDB;

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

    match db.get_top_ports(limit) {
        Ok(port_stats) => {
            let total_open_ports: usize = port_stats.iter().map(|(_, count)| count).sum();

            let ports: Vec<PortStats> = port_stats
                .into_iter()
                .map(|(port, count)| {
                    let percentage = if total_open_ports > 0 {
                        (count as f64 / total_open_ports as f64) * 100.0
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
                total_open_ports,
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
#[utoipa::path(
    post,
    path = "/api/v1/scan/start",
    request_body = StartScanRequest,
    responses(
        (status = 202, description = "Scan started successfully"),
        (status = 400, description = "Invalid scan parameters", body = ErrorResponse),
        (status = 409, description = "Scan already in progress", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    tag = "Scan Control"
)]
pub async fn start_scan(
    db: web::Data<SqliteDB>,
    request: web::Json<StartScanRequest>,
) -> impl Responder {
    // Validate request parameters
    if let Some(ref ports) = request.ports {
        if ports.is_empty() {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Ports list cannot be empty".to_string(),
                code: Some("INVALID_PORTS".to_string()),
            });
        }
    } else {
        return HttpResponse::BadRequest().json(ErrorResponse {
            error: "Ports parameter is required".to_string(),
            code: Some("MISSING_PORTS".to_string()),
        });
    }

    // Check if a scan is already in progress by checking metadata
    match db.get_metadata("scan_status") {
        Ok(Some(status)) if status == "running" => {
            return HttpResponse::Conflict().json(ErrorResponse {
                error: "A scan is already in progress".to_string(),
                code: Some("SCAN_IN_PROGRESS".to_string()),
            });
        }
        Err(e) => {
            error!("Failed to check scan status: {}", e);
            return HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to check scan status".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            });
        }
        _ => {}
    }

    // Mark scan as running
    if let Err(e) = db.save_metadata("scan_status", "running") {
        error!("Failed to update scan status: {}", e);
        return HttpResponse::InternalServerError().json(ErrorResponse {
            error: "Failed to start scan".to_string(),
            code: Some("DATABASE_ERROR".to_string()),
        });
    }

    // Generate scan ID
    let scan_id = format!("scan-{}", chrono::Utc::now().timestamp());

    // Save scan parameters to metadata
    let _ = db.save_metadata("last_scan_id", &scan_id);
    let _ = db.save_metadata("last_scan_start_time", &chrono::Utc::now().to_rfc3339());

    let start_ip = request.start_ip.as_deref().unwrap_or("0.0.0.0");
    let end_ip = request.end_ip.as_deref().unwrap_or("255.255.255.255");

    HttpResponse::Accepted().json(json!({
        "message": "Scan start request accepted",
        "scan_id": scan_id,
        "status": "running",
        "target": format!("{} - {}", start_ip, end_ip),
        "ports": request.ports.as_deref().unwrap_or("")
    }))
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
pub async fn stop_scan(db: web::Data<SqliteDB>) -> impl Responder {
    // Check if a scan is running
    match db.get_metadata("scan_status") {
        Ok(Some(status)) if status == "running" => {
            // Mark scan as stopped
            if let Err(e) = db.save_metadata("scan_status", "stopped") {
                error!("Failed to update scan status: {}", e);
                return HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to stop scan".to_string(),
                    code: Some("DATABASE_ERROR".to_string()),
                });
            }

            // Save stop time
            let _ = db.save_metadata("last_scan_stop_time", &chrono::Utc::now().to_rfc3339());

            HttpResponse::Ok().json(json!({
                "message": "Scan stop request accepted",
                "status": "stopped"
            }))
        }
        Ok(Some(_)) | Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: "No scan in progress".to_string(),
            code: Some("NO_SCAN_RUNNING".to_string()),
        }),
        Err(e) => {
            error!("Failed to check scan status: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to check scan status".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
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
pub async fn get_scan_status(db: web::Data<SqliteDB>) -> impl Responder {
    // Get scan status from metadata
    let status = db
        .get_metadata("scan_status")
        .unwrap_or(Some("idle".to_string()))
        .unwrap_or("idle".to_string());
    let current_round = db.get_current_round().unwrap_or(1);
    let last_scan_time = db.get_last_scan_time().unwrap_or(None);

    // Get last scan ID if available
    let scan_id = db.get_metadata("last_scan_id").ok().flatten();

    // Get scan start time if available
    let start_time = db.get_metadata("last_scan_start_time").ok().flatten();

    // Get scan stop time if available
    let stop_time = db.get_metadata("last_scan_stop_time").ok().flatten();

    HttpResponse::Ok().json(json!({
        "status": status,
        "current_round": current_round,
        "last_scan_time": last_scan_time,
        "scan_id": scan_id,
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
    // Get results with filters
    match db.get_scan_results(
        1,
        100000, // Large page size for export
        query.ip.as_deref(),
        query.port,
        query.round,
        query.ip_type.as_deref(),
    ) {
        Ok((results, _)) => {
            let mut csv_content =
                String::from("ip_address,ip_type,port,scan_round,first_seen,last_seen\n");

            for result in results {
                csv_content.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    result.ip_address,
                    result.ip_type,
                    result.port,
                    result.scan_round,
                    result.first_seen,
                    result.last_seen
                ));
            }

            HttpResponse::Ok()
                .content_type("text/csv")
                .append_header((
                    "Content-Disposition",
                    "attachment; filename=\"scan_results.csv\"",
                ))
                .body(csv_content)
        }
        Err(e) => {
            error!("Failed to export CSV: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "Failed to export scan results".to_string(),
                code: Some("DATABASE_ERROR".to_string()),
            })
        }
    }
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
    // Get results with filters
    match db.get_scan_results(
        1,
        100000, // Large page size for export
        query.ip.as_deref(),
        query.port,
        query.round,
        query.ip_type.as_deref(),
    ) {
        Ok((results, _)) => {
            let api_results: Vec<ScanResult> = results
                .into_iter()
                .map(|r| ScanResult {
                    ip_address: r.ip_address,
                    ip_type: r.ip_type,
                    port: r.port,
                    scan_round: r.scan_round,
                    first_seen: r.first_seen,
                    last_seen: r.last_seen,
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
    // Get results with filters
    match db.get_scan_results(
        1,
        100000, // Large page size for export
        query.ip.as_deref(),
        query.port,
        query.round,
        query.ip_type.as_deref(),
    ) {
        Ok((results, _)) => {
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
