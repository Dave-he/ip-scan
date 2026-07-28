use serde::{Deserialize, Serialize};

/// Raw + parsed snapshot of the first bytes returned by an open TCP port.
///
/// This is the row that answers "what is this server doing?". A typical
/// snapshot stores:
/// * The raw bytes the server pushed on connect (banner or HTTP response head).
/// * The decoded textual first line (status, greeting).
/// * A short list of detected protocols / libraries / features (HTTP/1.1,
///   TLS 1.3, SSH-2.0-OpenSSH_9.6, Redis 7.2.4, …).
/// * Where available, the structured HTTP status + title + Server header,
///   and TLS subject/issuer/SANs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSnapshot {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub banner_first_line: Option<String>,
    pub banner_raw_hex: Option<String>,
    pub banner_raw_len: usize,
    pub http_status: Option<u16>,
    pub http_server: Option<String>,
    pub http_title: Option<String>,
    pub tls_subject: Option<String>,
    pub tls_issuer: Option<String>,
    pub tls_version: Option<String>,
    pub tls_san: Option<String>,
    pub tls_not_before: Option<String>,
    pub tls_not_after: Option<String>,
    pub os_guess: Option<String>,
    pub rtt_ms: Option<f64>,
    pub detected_technologies: Option<String>,
    /// Free-form human-readable purpose label for the port:
    /// "Web server (HTTPS)", "SSH login portal", "Database (Redis 7.2.4)", …
    pub purpose: Option<String>,
    pub captured_at: String,
}

impl TcpSnapshot {
    pub fn new(ip: String, port: u16) -> Self {
        Self {
            ip,
            port,
            protocol: String::new(),
            banner_first_line: None,
            banner_raw_hex: None,
            banner_raw_len: 0,
            http_status: None,
            http_server: None,
            http_title: None,
            tls_subject: None,
            tls_issuer: None,
            tls_version: None,
            tls_san: None,
            tls_not_before: None,
            tls_not_after: None,
            os_guess: None,
            rtt_ms: None,
            detected_technologies: None,
            purpose: None,
            captured_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Compute a short, fixed-size hex preview of the first 64 bytes. The
    /// DB already stores the human fields; the hex preview is what the Web
    /// UI uses to display "raw bytes" without paying for a full-text dump.
    pub fn preview_hex(raw: &[u8]) -> String {
        let n = raw.len().min(64);
        let mut s = String::with_capacity(n * 2);
        for b in &raw[..n] {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Best-effort "this port is doing X" label.
    pub fn describe_port(port: u16, banner: Option<&str>, http_title: Option<&str>) -> String {
        let base = match port {
            21 => "FTP 文件传输服务",
            22 => "SSH 远程登录",
            23 => "Telnet 明文远程管理",
            25 => "SMTP 邮件发送",
            53 => "DNS 域名解析",
            80 | 8080 | 8000 | 8888 | 3000 | 5000 | 9000 => "HTTP 网站服务",
            110 => "POP3 邮件接收",
            143 => "IMAP 邮件接收",
            443 | 8443 => "HTTPS 加密网站服务",
            445 => "SMB 文件共享",
            587 => "SMTP (Submission) 邮件发送",
            993 => "IMAPS 加密邮件接收",
            995 => "POP3S 加密邮件接收",
            1433 => "Microsoft SQL Server 数据库",
            1521 => "Oracle 数据库",
            1723 => "PPTP VPN",
            3306 => "MySQL 数据库",
            3389 => "RDP 远程桌面",
            5432 => "PostgreSQL 数据库",
            5900 | 5901 => "VNC 远程桌面",
            6379 => "Redis 缓存/键值数据库",
            9200 => "Elasticsearch 搜索",
            11211 => "Memcached 缓存",
            27017 => "MongoDB 文档数据库",
            _ => "TCP 自定义服务",
        };
        if let Some(t) = http_title {
            if !t.trim().is_empty() {
                return format!("{} ({})", base, t.trim());
            }
        }
        if let Some(b) = banner {
            let trimmed = b.trim();
            if !trimmed.is_empty() && trimmed.len() < 80 {
                return format!("{} ({})", base, trimmed);
            }
        }
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_port_uses_title_when_present() {
        let s = TcpSnapshot::describe_port(443, None, Some("Example · Login"));
        assert!(s.contains("HTTPS"));
        assert!(s.contains("Example · Login"));
    }

    #[test]
    fn describe_port_falls_back_to_banner() {
        let s = TcpSnapshot::describe_port(22, Some("SSH-2.0-OpenSSH_9.6"), None);
        assert!(s.contains("SSH"));
        assert!(s.contains("OpenSSH"));
    }

    #[test]
    fn preview_hex_truncates_and_zero_pads() {
        let s = TcpSnapshot::preview_hex(b"\x01ab");
        assert_eq!(s, "016162");
    }
}
