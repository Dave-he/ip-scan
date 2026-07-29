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
    // IP-detail + asset-list views. Kept at /ip/{ip} (singular) so the
    // frontend can resolve any IP drill-down with a single GET.
    cfg.route("/ip/{ip}", web::get().to(handlers::get_ip_detail));
    cfg.route("/assets", web::get().to(handlers::list_assets));
    // Captured TCP snapshots (banner / HTTP / TLS) per IP.
    cfg.route(
        "/snapshots/{ip}",
        web::get().to(handlers::get_tcp_snapshots_for_ip),
    );
}

/// Configure statistics routes
pub fn config_stats_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/healthz", web::get().to(handlers::get_health));
    cfg.route("/system", web::get().to(handlers::get_system_info));
    cfg.service(
        web::scope("/stats")
            .route("", web::get().to(handlers::get_stats))
            .route(
                "/prometheus",
                web::get().to(handlers::get_prometheus_metrics),
            )
            .route(
                "/changes/{round}/{port}",
                web::get().to(handlers::get_bitmap_changes),
            )
            .route("/top-ports", web::get().to(handlers::get_top_ports))
            // Distributed / aggregation endpoints used by the standalone
            // frontend. Kept under the same /stats scope so a single
            // service block handles all stats traffic.
            .route(
                "/by-ip-family",
                web::get().to(handlers::get_stats_by_ip_family),
            )
            .route("/by-service", web::get().to(handlers::get_stats_by_service))
            .route(
                "/by-category",
                web::get().to(handlers::get_stats_by_category),
            )
            .route("/by-asn", web::get().to(handlers::get_stats_by_asn))
            .route(
                "/by-organization",
                web::get().to(handlers::get_stats_by_organization),
            ),
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

/// Configure service info routes
pub fn config_service_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/services")
            .route("", web::get().to(handlers::get_service_summaries))
            .route("/{ip}", web::get().to(handlers::get_service_info_by_ip)),
    );
}

/// Configure distributed / aggregation routes used by the standalone
/// frontend. Only /map is non-overlapping; the /stats aggregation routes
/// live in config_stats_routes to avoid duplicate web::scope("/stats")
/// blocks.
pub fn config_distributed_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/map").route("/locations", web::get().to(handlers::get_map_locations)));
}

/// OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::get_results,
        handlers::get_results_by_ip,
        handlers::get_results_by_port,
        handlers::get_results_by_round,
        handlers::get_ip_detail,
        handlers::list_assets,
        handlers::get_stats,
        handlers::get_prometheus_metrics,
        handlers::get_system_info,
        handlers::get_bitmap_changes,
        handlers::get_health,
        handlers::get_top_ports,
        handlers::get_scan_status,
        handlers::get_scan_history,
        handlers::export_csv,
        handlers::export_json,
        handlers::export_ndjson,
        handlers::get_stats_by_ip_family,
        handlers::get_stats_by_service,
        handlers::get_stats_by_category,
        handlers::get_stats_by_asn,
        handlers::get_stats_by_organization,
        handlers::get_map_locations,
        handlers::get_tcp_snapshots_for_ip,
    ),
    components(
        schemas(
            models::ScanResult,
            models::PaginatedResults,
            models::SystemInfoResponse,
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
            models::ServiceInfoResponse,
            models::IpServiceSummaryResponse,
            models::ServiceSummaryListResponse,
            models::IpFamilyStatsResponse,
            models::ServiceStatsResponse,
            models::ServiceStatsEntry,
            models::CategoryStatsResponse,
            models::CategoryStatsEntry,
            models::IpLocationResponse,
            models::IpLocationsResponse,
            models::IpDetailResponse,
            models::AsnStatsResponse,
            models::AsnStatsEntry,
            models::OrgStatsResponse,
            models::OrgStatsEntry,
            models::AssetSummary,
            models::AssetSummaryListResponse,
            models::TcpSnapshotResponse,
            models::TcpSnapshotListResponse,
            models::AssetsQuery,
            crate::dao::PortChange,
        )
    ),
    tags(
        (name = "Results", description = "Scan results endpoints"),
        (name = "Statistics", description = "Statistics endpoints"),
        (name = "Operations", description = "Health and monitoring endpoints"),
        (name = "Scan Control", description = "Scan control endpoints"),
        (name = "Export", description = "Data export endpoints"),
        (name = "Services", description = "Service detection endpoints"),
        (name = "Distributed", description = "Aggregation endpoints for the standalone distributed frontend"),
    )
)]
pub struct ApiDoc;
