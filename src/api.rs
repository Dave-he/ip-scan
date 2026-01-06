use actix_web::{web, App, HttpResponse, Responder};
use crate::dao::SqliteDB;
use utoipa::openapi::OpenApi;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/health", web::get().to(health))
            .route("/stats", web::get().to(stats)),
    );
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

async fn stats(db: web::Data<SqliteDB>) -> impl Responder {
    match db.get_stats() {
        Ok((total_results, unique_open)) => HttpResponse::Ok().json(serde_json::json!({
            "total_results": total_results,
            "unique_open": unique_open
        })),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

pub struct ApiDoc;

impl ApiDoc {
    pub fn openapi() -> OpenApi {
        use utoipa::openapi::Info;
        OpenApi {
            info: Info::new("IP-Scan API", "1.0.0"),
            ..Default::default()
        }
    }
}

pub fn openapi_json(doc: OpenApi) -> impl Fn() -> HttpResponse {
    move || {
        let json = serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string());
        HttpResponse::Ok()
            .content_type("application/json")
            .body(json)
    }
}
