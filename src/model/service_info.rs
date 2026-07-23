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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpServiceSummary {
    pub ip: String,
    pub services: Vec<ServiceInfo>,
    pub ip_type: Option<String>,
    pub category: String,
}

impl IpServiceSummary {
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
