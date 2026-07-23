use crate::model::ServiceInfo;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

const PROBE_TIMEOUT_SECS: u64 = 5;
const BANNER_READ_TIMEOUT_SECS: u64 = 3;
const BANNER_MAX_BYTES: usize = 2048;
const HTTP_BODY_PREVIEW_BYTES: usize = 512;

#[derive(Clone)]
pub struct ServiceProber {
    http_client: reqwest::Client,
    banner_timeout: Duration,
    concurrency: usize,
}

impl ServiceProber {
    pub fn new(timeout_secs: u64, concurrency: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs.max(1)))
            .connect_timeout(Duration::from_secs(timeout_secs.max(1)))
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .build()
            .unwrap_or_default();

        Self {
            http_client: client,
            banner_timeout: Duration::from_secs(BANNER_READ_TIMEOUT_SECS),
            concurrency,
        }
    }

    pub async fn probe_ip(&self, ip: &str, open_ports: &[u16]) -> Vec<ServiceInfo> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for &port in open_ports {
            let sem = semaphore.clone();
            let ip_owned = ip.to_string();
            let prober = self.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                prober.probe_port(&ip_owned, port).await
            });
        }

        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(Some(info)) = res {
                results.push(info);
            }
        }
        results
    }

    pub async fn probe_port(&self, ip: &str, port: u16) -> Option<ServiceInfo> {
        let mut info = ServiceInfo::new(ip.to_string(), port);
        info.service_name = ServiceInfo::guess_service_name(port).to_string();

        if ServiceInfo::is_probable_http_port(port) || ServiceInfo::is_probable_https_port(port) {
            self.probe_http(ip, port, &mut info).await;
        } else {
            self.probe_banner(ip, port, &mut info).await;
        }

        info.protocol = self.guess_protocol(&info);
        Some(info)
    }

    async fn probe_http(&self, ip: &str, port: u16, info: &mut ServiceInfo) {
        let scheme = if ServiceInfo::is_probable_https_port(port) {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}/", scheme, ip, port);

        match self.http_client.get(&url).send().await {
            Ok(resp) => {
                if let Some(server) = resp.headers().get("server") {
                    info.http_server = Some(server.to_str().unwrap_or("").to_string());
                }

                let status = resp.status();
                info.banner = Some(format!("HTTP {}", status.as_u16()));

                if let Ok(body) = resp.text().await {
                    if let Some(title) = self.extract_html_title(&body) {
                        info.http_title = Some(title);
                    }
                    let preview: String = body.chars().take(HTTP_BODY_PREVIEW_BYTES).collect();
                    let cleaned = preview
                        .replace(['\n', '\r', '\t'], " ")
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let trimmed = if cleaned.len() > 300 {
                        &cleaned[..300]
                    } else {
                        &cleaned
                    };
                    info.http_body_preview = Some(trimmed.to_string());
                }
            }
            Err(e) => {
                debug!("HTTP probe failed {}:{}: {}", ip, port, e);
                self.probe_banner(ip, port, info).await;
            }
        }
    }

    async fn probe_banner(&self, ip: &str, port: u16, info: &mut ServiceInfo) {
        let addr = format!("{}:{}", ip, port);
        let conn = timeout(
            Duration::from_secs(PROBE_TIMEOUT_SECS),
            TcpStream::connect(&addr),
        )
        .await;

        let Ok(Ok(mut stream)) = conn else {
            return;
        };

        let probe_data = match info.service_name.as_str() {
            "ftp" => b"\r\n".to_vec(),
            "smtp" => b"EHLO probe\r\n".to_vec(),
            "pop3" => b"\r\n".to_vec(),
            "imap" => b"a001 CAPABILITY\r\n".to_vec(),
            "redis" => b"INFO\r\n".to_vec(),
            _ => b"".to_vec(),
        };

        if !probe_data.is_empty() {
            let _ = stream.write_all(&probe_data).await;
        }

        let mut buf = vec![0u8; BANNER_MAX_BYTES];
        match timeout(self.banner_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buf[..n]);
                let first_line = banner.lines().next().unwrap_or("").to_string();
                info.banner = Some(first_line);
                self.parse_banner_info(info, &banner);
            }
            _ => {}
        }
    }

    fn parse_banner_info(&self, info: &mut ServiceInfo, banner: &str) {
        match info.service_name.as_str() {
            "ssh" => {
                if let Some(line) = banner.lines().next() {
                    if line.starts_with("SSH-") {
                        info.banner = Some(line.to_string());
                    }
                }
            }
            "ftp" => {
                if let Some(line) = banner.lines().next() {
                    if line.starts_with("220") {
                        info.http_server = Some(line.trim_start_matches("220 ").to_string());
                    }
                }
            }
            "redis" => {
                if banner.contains("redis_version") {
                    info.banner = Some("Redis".to_string());
                }
            }
            "mysql" if !banner.is_empty() => {
                info.banner = Some("MySQL".to_string());
            }
            _ => {}
        }
    }

    fn extract_html_title(&self, html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        if let Some(start) = lower.find("<title>") {
            if let Some(end) = lower.find("</title>") {
                let content = &html[start + 7..end];
                let cleaned = content.trim().chars().take(200).collect::<String>();
                if !cleaned.is_empty() {
                    return Some(cleaned);
                }
            }
        }
        None
    }

    fn guess_protocol(&self, info: &ServiceInfo) -> String {
        if !info.protocol.is_empty() {
            return info.protocol.clone();
        }

        match info.service_name.as_str() {
            "http" | "http-alt" => "http".to_string(),
            "https" | "https-alt" => "https".to_string(),
            "ssh" => "ssh".to_string(),
            "ftp" => "ftp".to_string(),
            "smtp" => "smtp".to_string(),
            "pop3" => "pop3".to_string(),
            "imap" => "imap".to_string(),
            "dns" => "dns".to_string(),
            "mysql" => "mysql".to_string(),
            "postgresql" => "postgresql".to_string(),
            "redis" => "redis".to_string(),
            "mongodb" => "mongodb".to_string(),
            "mssql" => "mssql".to_string(),
            "rdp" => "rdp".to_string(),
            "smb" => "smb".to_string(),
            _ => "tcp".to_string(),
        }
    }
}
