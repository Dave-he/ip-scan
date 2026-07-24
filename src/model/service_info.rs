use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub ip: String,
    pub port: u16,
    pub service_name: String,
    pub protocol: String,
    pub banner: Option<String>,
    pub http_title: Option<String>,
    pub http_server: Option<String>,
    pub http_body_preview: Option<String>,
    pub tls_subject: Option<String>,
    pub tls_issuer: Option<String>,
    pub tls_not_before: Option<String>,
    pub tls_not_after: Option<String>,
    pub tls_version: Option<String>,
    pub service_version: Option<String>,
    pub http_body_hash: Option<String>,
    pub http_security_headers: Option<String>,
    pub rtt_ms: Option<f64>,
    pub os_guess: Option<String>,
    pub detected_at: String,
}

impl ServiceInfo {
    pub fn new(ip: String, port: u16) -> Self {
        Self {
            ip,
            port,
            service_name: String::new(),
            protocol: String::new(),
            banner: None,
            http_title: None,
            http_server: None,
            http_body_preview: None,
            tls_subject: None,
            tls_issuer: None,
            tls_not_before: None,
            tls_not_after: None,
            tls_version: None,
            service_version: None,
            http_body_hash: None,
            http_security_headers: None,
            rtt_ms: None,
            os_guess: None,
            detected_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn guess_service_name(port: u16) -> &'static str {
        match port {
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            80 => "http",
            110 => "pop3",
            143 => "imap",
            443 => "https",
            445 => "smb",
            993 => "imaps",
            995 => "pop3s",
            1433 => "mssql",
            1521 => "oracle",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            5900 => "vnc",
            6379 => "redis",
            8080 => "http-alt",
            8443 => "https-alt",
            9200 => "elasticsearch",
            27017 => "mongodb",
            _ => "unknown",
        }
    }

    pub fn is_probable_http_port(port: u16) -> bool {
        matches!(port, 80 | 8080 | 8000 | 8888 | 3000 | 5000 | 9000)
    }

    pub fn is_probable_https_port(port: u16) -> bool {
        matches!(port, 443 | 8443)
    }

    pub fn guess_os_from_ttl(ttl: u32) -> Option<&'static str> {
        match ttl {
            0..=32 => Some("Windows (Vista+)"),
            33..=64 => Some("Linux/Unix/macOS"),
            65..=128 => Some("Windows (older)"),
            129..=255 => Some("UNIX (routing)"),
            _ => None,
        }
    }

    pub fn parse_version_from_banner(service_name: &str, banner: &str) -> Option<String> {
        match service_name {
            "ssh" => {
                if let Some(line) = banner.lines().next() {
                    if line.starts_with("SSH-") {
                        if let Some(idx) = line.find(' ') {
                            return Some(line[..idx].to_string());
                        }
                        return Some(line.to_string());
                    }
                }
            }
            "ftp" => {
                if let Some(line) = banner.lines().next() {
                    if line.starts_with("220 ") {
                        let version_part = line.trim_start_matches("220 ");
                        return Some(version_part.to_string());
                    }
                }
            }
            "smtp" => {
                if let Some(line) = banner.lines().next() {
                    if line.starts_with("220 ") || line.starts_with("220-") {
                        return Some(
                            line.trim_start_matches("220 ")
                                .trim_start_matches("220-")
                                .to_string(),
                        );
                    }
                }
            }
            "http" | "https" | "http-alt" | "https-alt" if !banner.is_empty() => {
                return Some(banner.to_string());
            }
            _ => {}
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpServiceSummary {
    pub ip: String,
    pub services: Vec<ServiceInfo>,
    pub ip_type: Option<String>,
    pub category: String,
    pub risk_score: u8,
    pub risk_reasons: Vec<String>,
}

impl IpServiceSummary {
    pub fn assess_risk(services: &[ServiceInfo]) -> (u8, Vec<String>) {
        let mut score = 0u8;
        let mut reasons = Vec::new();
        for service in services {
            let (points, reason) = match service.service_name.as_str() {
                "telnet" => (90, "Telnet 明文远程管理"),
                "redis" | "mongodb" | "elasticsearch" => (75, "数据库/搜索服务暴露"),
                "ftp" | "pop3" | "imap" | "smtp" => (40, "邮件或文件服务暴露"),
                "rdp" | "vnc" => (60, "远程桌面服务暴露"),
                "http" | "http-alt" | "https" | "https-alt" => (20, "Web 服务暴露"),
                _ => (0, ""),
            };
            score = score.max(points);
            if !reason.is_empty() && !reasons.iter().any(|r| r == reason) {
                reasons.push(reason.to_string());
            }
            if service.tls_not_after.is_some() && service.tls_version.is_none() {
                score = score.max(35);
                reasons.push("TLS 证书信息不完整".to_string());
            }
            if let Some(headers) = &service.http_security_headers {
                if headers.starts_with("0/") || headers.starts_with("1/") {
                    score = score.max(30);
                    reasons.push("Web 安全响应头缺失较多".to_string());
                }
            }
        }
        (score.min(100), reasons)
    }

    pub fn categorize(services: &[ServiceInfo]) -> String {
        let service_names: Vec<&str> = services.iter().map(|s| s.service_name.as_str()).collect();

        let has_web = service_names
            .iter()
            .any(|s| *s == "http" || *s == "https" || *s == "http-alt" || *s == "https-alt");
        let has_db = service_names.iter().any(|s| {
            *s == "mysql" || *s == "postgresql" || *s == "mongodb" || *s == "redis" || *s == "mssql"
        });
        let has_ssh = service_names.contains(&"ssh");
        let has_rdp = service_names.contains(&"rdp");
        let has_ftp = service_names.contains(&"ftp");
        let has_mail = service_names
            .iter()
            .any(|s| *s == "smtp" || *s == "pop3" || *s == "imap");

        if services.is_empty() {
            return "unknown".to_string();
        }

        if has_web && has_db {
            return "web-server".to_string();
        }
        if has_web && has_mail {
            return "web-mail-server".to_string();
        }
        if has_web {
            return "web-server".to_string();
        }
        if has_db && has_ssh {
            return "database-server".to_string();
        }
        if has_db {
            return "database-server".to_string();
        }
        if has_ssh && has_ftp {
            return "file-server".to_string();
        }
        if has_rdp {
            return "remote-desktop".to_string();
        }
        if has_mail {
            return "mail-server".to_string();
        }
        if has_ssh {
            return "linux-server".to_string();
        }
        if has_ftp {
            return "ftp-server".to_string();
        }
        "server".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{IpServiceSummary, ServiceInfo};

    #[test]
    fn risk_assessment_flags_dangerous_services() {
        let mut service = ServiceInfo::new("192.0.2.1".to_string(), 23);
        service.service_name = "telnet".to_string();
        let (score, reasons) = IpServiceSummary::assess_risk(&[service]);
        assert_eq!(score, 90);
        assert!(reasons.iter().any(|r| r.contains("Telnet")));
    }
}
