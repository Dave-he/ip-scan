//! API module for exposing scan results
//!
//! This module provides REST API endpoints for accessing scan results,
//! statistics, and controlling the scanner.

mod handlers;
pub mod models;
mod routes;

use actix_web::web;

/// Initialize API routes
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(routes::config_results_routes)
            .configure(routes::config_stats_routes)
            .configure(routes::config_scan_routes)
            .configure(routes::config_export_routes),
    );
}

/// Re-export ApiDoc for OpenAPI documentation
pub use routes::ApiDoc;
