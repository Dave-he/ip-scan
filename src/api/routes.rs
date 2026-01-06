//! API route definitions
//!
//! This module defines all API routes and their configurations.

use actix_web::web;
use utoipa::OpenApi;

use crate::api::handlers;
use crate::api::models;

/// Configure results-related routes
pub fn config_results_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/results")
            .route("", web::get().to(handlers::get_results))
            .route("/{ip}", web::get().to(handlers::get_results_by_ip))
            .route("/port/{port}", web::get().to(handlers::get_results_by_port))
            .route(
                "/round/{round}",
                web::get().to(handlers::get_results_by_round),
            ),
    );
}

/// Configure statistics routes
pub fn config_stats_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/stats")
            .route("", web::get().to(handlers::get_stats))
            .route("/top-ports", web::get().to(handlers::get_top_ports)),
    );
}

/// Configure scan control routes
pub fn config_scan_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/scan")
            .route("/start", web::post().to(handlers::start_scan))
            .route("/stop", web::post().to(handlers::stop_scan))
            .route("/status", web::get().to(handlers::get_scan_status))
            .route("/history", web::get().to(handlers::get_scan_history)),
    );
}

/// Configure export routes
pub fn config_export_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/export")
            .route("/csv", web::get().to(handlers::export_csv))
            .route("/json", web::get().to(handlers::export_json))
            .route("/ndjson", web::get().to(handlers::export_ndjson)),
    );
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_results,
        handlers::get_results_by_ip,
        handlers::get_results_by_port,
        handlers::get_results_by_round,
        handlers::get_stats,
        handlers::get_top_ports,
        handlers::get_scan_status,
        handlers::get_scan_history,
        handlers::export_csv,
        handlers::export_json,
        handlers::export_ndjson,
    ),
    components(
        schemas(
            models::ScanResult,
            models::PaginatedResults,
            models::StatsResponse,
            models::PortStats,
            models::TopPortsResponse,
            models::ErrorResponse,
            models::PaginationQuery,
            models::FilterQuery,
            models::ResultsQuery,
            models::TopPortsQuery,
            models::StartScanRequest,
            models::ExportFormat,
            models::ScanStatus,
        )
    ),
    tags(
        (name = "Results", description = "Scan results endpoints"),
        (name = "Statistics", description = "Statistics endpoints"),
        (name = "Scan Control", description = "Scan control endpoints"),
        (name = "Export", description = "Data export endpoints"),
    )
)]
pub struct ApiDoc;
