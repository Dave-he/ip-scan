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
    limit: web::Query<Option<usize>>,
) -> impl Responder {
    let limit = limit.into_inner().unwrap_or(10);

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
    _db: web::Data<SqliteDB>,
    _request: web::Json<StartScanRequest>,
) -> impl Responder {
    // TODO: Implement scan control logic
    // For now, return a placeholder response
    HttpResponse::Accepted().json(json!({
        "message": "Scan start request accepted",
        "scan_id": "placeholder-scan-id",
        "status": "queued"
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
pub async fn stop_scan(_db: web::Data<SqliteDB>) -> impl Responder {
    // TODO: Implement scan control logic
    HttpResponse::Ok().json(json!({
        "message": "Scan stop request accepted",
        "status": "stopping"
    }))
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
pub async fn get_scan_status(_db: web::Data<SqliteDB>) -> impl Responder {
    // TODO: Implement scan status logic
    HttpResponse::Ok().json(json!({
        "status": "idle",
        "current_round": 1,
        "last_scan_time": null,
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
pub async fn get_scan_history(_db: web::Data<SqliteDB>) -> impl Responder {
    // TODO: Implement scan history logic
    HttpResponse::Ok().json(json!({
        "scans": []
    }))
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
pub async fn export_csv(
    _db: web::Data<SqliteDB>,
    _query: web::Query<FilterQuery>,
) -> impl Responder {
    // TODO: Implement CSV export
    // For now, return a placeholder
    HttpResponse::Ok()
        .content_type("text/csv")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"scan_results.csv\"",
        ))
        .body("ip_address,ip_type,port,scan_round,first_seen,last_seen\n")
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
    _db: web::Data<SqliteDB>,
    _query: web::Query<FilterQuery>,
) -> impl Responder {
    // TODO: Implement JSON export
    // For now, return empty array
    HttpResponse::Ok().json(Vec::<ScanResult>::new())
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
    _db: web::Data<SqliteDB>,
    _query: web::Query<FilterQuery>,
) -> impl Responder {
    // TODO: Implement NDJSON export
    // For now, return empty
    HttpResponse::Ok()
        .content_type("application/x-ndjson")
        .body("")
}
