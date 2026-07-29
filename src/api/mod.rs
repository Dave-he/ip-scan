//! API module for exposing scan results
//!
//! This module provides REST API endpoints for accessing scan results,
//! statistics, and controlling the scanner.

mod handlers;
pub mod models;
mod routes;

use actix_web::web;

/// Identity block for this scanner node. The distributed frontend reads
/// this through `/api/v1/system` to label the node in the cluster view.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub id: String,
    pub label: Option<String>,
    pub provider: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub current_target_start: Option<String>,
    pub current_target_end: Option<String>,
}

impl NodeIdentity {
    pub fn from_args(args: &crate::cli::Args, api_host: &str, api_port: u16) -> Self {
        let id = args
            .node_id
            .clone()
            .unwrap_or_else(|| format!("{}:{}", api_host, api_port));
        Self {
            id,
            label: args.node_label.clone(),
            provider: args.node_provider.clone(),
            latitude: args.node_latitude,
            longitude: args.node_longitude,
            current_target_start: args.start_ip.clone().or_else(|| args.target.clone()),
            current_target_end: args.end_ip.clone(),
        }
    }
}

/// Initialize API routes
pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(routes::config_results_routes)
            .configure(routes::config_stats_routes)
            .configure(routes::config_scan_routes)
            .configure(routes::config_export_routes)
            .configure(routes::config_service_routes)
            .configure(routes::config_distributed_routes),
    );
}

/// Re-export ApiDoc for OpenAPI documentation
pub use routes::ApiDoc;
