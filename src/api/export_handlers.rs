//! Export handlers with streaming support
//!
//! This module provides streaming export functionality to handle large datasets
//! without loading everything into memory at once.

use actix_web::{web, HttpResponse, Responder};
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::pin::Pin;
use futures::Stream;
use tracing::error;

use crate::api::models::*;
use crate::dao::SqliteDB;

/// Export scan results as CSV with streaming
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
pub async fn export_csv_stream(
    db: web::Data<SqliteDB>,
    query: web::Query<FilterQuery>,
) -> impl Responder {
    const BATCH_SIZE: usize = 1000;

    // Clone for use in stream
    let db_clone = db.clone();
    let ip_filter = query.ip.clone();
    let port_filter = query.port;
    let round_filter = query.round;
    let ip_type_filter = query.ip_type.clone();

    // Create streaming response
    let stream: Pin<Box<dyn Stream<Item = Result<actix_web::web::Bytes, actix_web::Error>>>> =
        Box::pin(stream::unfold(
            (1usize, false, true),
            move |(page, done, is_first)| {
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
                            if results.is_em