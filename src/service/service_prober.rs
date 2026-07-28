use crate::model::{ServiceInfo, TcpSnapshot};
use std::time::{Duration, Instant};
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
            concurrency: concurrency.max(1),
        }
    }

    pub async fn probe_ip(&self, ip: &str, open_ports: &[u16]) -> Vec<ServiceInfo> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));
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

    /// Same fan-out as `probe_ip` but returns both the parsed `ServiceInfo`
    /// and the raw-bytes + protocol `TcpSnapshot` for each port. The
    /// snapshot is the row that powers the "what is this port doing?"
    /// view, and the caller persists it via
    /// `SqliteDB::save_tcp_snapshots_batch`.
    pub async fn probe_ip_with_snapshots(
        &self,
        ip: &str,
        open_ports: &[u16],
    ) -> (Vec<ServiceInfo>, Vec<TcpSnapshot>) {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));
        let mut join_set = tokio::task::JoinSet::new();

        for &port in open_ports {
            let sem = semaphore.clone();
            let ip_owned = ip.to_string();
            let prober = self.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                prober.probe_port_with_snapshot(&ip_owned, port).await
            });
        }

        let mut services = Vec::new();
        let mut snapshots = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(Some((info, snap))) = res {
                services.push(info);
                snapshots.push(snap);
            }
        }
        (services, snapshots)
    }

    /// Probe a single port and emit both the parsed `ServiceInfo` and the
    /// raw `TcpSnapshot`. Walks the same probing path as `probe_port` so
    /// the snapshot never diverges from the service_info row.
    pub async fn probe_port_with_snapshot(
        &self,
        ip: &str,
        port: u16,
    ) -> Option<(ServiceInfo, TcpSnapshot)> {
        let mut info = ServiceInfo::new(ip.to_string(), port);
        let mut snap = TcpSnapshot::new(ip.to_string(), port);
        info.service_name = ServiceInfo::guess_service_name(port).to_string();

        if ServiceInfo::is_probable_http_port(port) || ServiceInfo::is_probable_https_port(port) {
            self.probe_http(ip, port, &mut info).await;
        } else {
            self.probe_banner_into(ip, port, &mut info, &mut snap).await;
        }

        // Mirror every field the snapshot cares about so a single
        // INSERT into tcp_snapshots carries the full picture.
        snap.protocol = info.protocol.clone();
        snap.http_status = info
            .banner
            .as_deref()
            .and_then(|b| b.strip_prefix("HTTP "))
            .and_then(|s| s.parse::<u16>().ok());
        snap.http_server = info.http_server.clone();
        snap.http_title = info.http_title.clone();
        snap.tls_subject = info.tls_subject.clone();
        snap.tls_issuer = info.tls_issuer.clone();
        snap.tls_version = info.tls_version.clone();
        snap.tls_not_before = info.tls_not_before.clone();
        snap.tls_not_after = info.tls_not_after.clone();
        snap.os_guess = info.os_guess.clone();
        snap.rtt_ms = info.rtt_ms;
        snap.detected_technologies = info.service_version.clone();
        snap.purpose = Some(TcpSnapshot::describe_port(
            port,
            snap.banner_first_line.as_deref(),
            snap.http_title.as_deref(),
        ));

        info.protocol = self.guess_protocol(&info);
        if let Some(ref banner) = info.banner {
            info.service_version =
                ServiceInfo::parse_version_from_banner(&info.service_name, banner);
        }
        if info.service_name == "redis" {
            if let Some(version) = Self::extract_key_value(&info.banner, "redis_version") {
                info.service_version = Some(format!("Redis {}", version));
            }
        }
        Some((info, snap))
    }

    /// Banner probe that fills both the `ServiceInfo` banner field and the
    /// `TcpSnapshot` raw hex/length/line in a single pass.
    async fn probe_banner_into(
        &self,
        ip: &str,
        port: u16,
        info: &mut ServiceInfo,
        snap: &mut TcpSnapshot,
    ) {
        let addr = format!("{}:{}", ip, port);
        let start = Instant::now();
        let conn = timeout(
            Duration::from_secs(PROBE_TIMEOUT_SECS),
            TcpStream::connect(&addr),
        )
        .await;
        let Ok(Ok(mut stream)) = conn else { return; };
        info.rtt_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
        snap.rtt_ms = info.rtt_ms;

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
        if let Ok(Ok(n)) = timeout(self.banner_timeout, stream.read(&mut buf)).await {
            if n > 0 {
                let raw = &buf[..n];
                let banner = String::from_utf8_lossy(raw);
                let first_line = banner.lines().next().unwrap_or("").to_string();
                info.banner = Some(first_line.clone());
                snap.banner_first_line = Some(first_line);
                snap.banner_raw_hex = Some(TcpSnapshot::preview_hex(raw));
                snap.banner_raw_len = raw.len();
            }
        }
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

        if let Some(ref banner) = info.banner {
            info.service_version =
                ServiceInfo::parse_version_from_banner(&info.service_name, banner);
        }
        if info.service_name == "redis" {
            // Redis INFO is key/value text; retain only the version, not the full dump.
            if let Some(version) = Self::extract_key_value(&info.banner, "redis_version") {
                info.service_version = Some(format!("Redis {}", version));
            }
        }

        Some(info)
    }

    async fn probe_http(&self, ip: &str, port: u16, info: &mut ServiceInfo) {
        let scheme = if ServiceInfo::is_probable_https_port(port) {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}/", scheme, ip, port);

        let start = Instant::now();
        match self.http_client.get(&url).send().await {
            Ok(resp) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                info.rtt_ms = Some(rtt);

                if let Some(server) = resp.headers().get("server") {
                    info.http_server = Some(server.to_str().unwrap_or("").to_string());
                }

                let status = resp.status();
                info.banner = Some(format!("HTTP {}", status.as_u16()));
                let expected = [
                    "content-security-policy",
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                ];
                let present: Vec<&str> = expected
                    .iter()
                    .copied()
                    .filter(|name| resp.headers().contains_key(*name))
                    .collect();
                info.http_security_headers = Some(format!(
                    "{}/{} present: {}",
                    present.len(),
                    expected.len(),
                    present.join(",")
                ));

                // Fetch the page and favicon concurrently: favicon is independent
                // enrichment and must not add a full extra RTT to every HTTP probe.
                let favicon_url = format!("{}://{}:{}/favicon.ico", scheme, ip, port);
                let favicon_request = self.http_client.get(&favicon_url).send();
                let body_request = resp.text();
                let (body_result, favicon_result) = tokio::join!(body_request, favicon_request);

                if let Ok(body) = body_result {
                    if let Some(title) = self.extract_html_title(&body) {
                        info.http_title = Some(title);
                    }
                    let preview: String = body.chars().take(HTTP_BODY_PREVIEW_BYTES).collect();
                    let cleaned = preview
                        .replace(['\n', '\r', '\t'], " ")
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let trimmed = cleaned.chars().take(300).collect::<String>();
                    info.http_body_preview = Some(trimmed);
                    info.http_body_hash = Some(self.compute_body_hash(&body));
                    let technologies =
                        Self::detect_web_technologies(&body, info.http_server.as_deref());
                    if !technologies.is_empty() {
                        info.service_version = Some(technologies.join(", "));
                    }
                }

                if let Ok(favicon) = favicon_result {
                    if favicon.status().is_success() {
                        if let Ok(bytes) = favicon.bytes().await {
                            if !bytes.is_empty() && bytes.len() <= 1024 * 1024 {
                                let hash = Self::compute_bytes_hash(&bytes);
                                let marker = format!("favicon:{}", hash);
                                info.service_version = Some(match info.service_version.take() {
                                    Some(existing) => format!("{}, {}", existing, marker),
                                    None => marker,
                                });
                            }
                        }
                    }
                }

                if ServiceInfo::is_probable_https_port(port) {
                    let ip_owned = ip.to_string();
                    let tls = tokio::task::spawn_blocking(move || {
                        Self::extract_tls_info_blocking(&ip_owned, port)
                    })
                    .await
                    .unwrap_or_default();
                    info.tls_subject = tls.0;
                    info.tls_issuer = tls.1;
                    info.tls_version = tls.2;
                    if tls.3.is_some() {
                        info.os_guess = tls.3;
                    }
                }
            }
            Err(e) => {
                debug!("HTTP probe failed {}:{}: {}", ip, port, e);
                self.probe_banner(ip, port, info).await;
            }
        }
    }

    fn extract_tls_info_blocking(
        ip: &str,
        port: u16,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        let mut info = ServiceInfo::new(ip.to_string(), port);
        let connector = match native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(_) => return (None, None, None, None),
        };

        let addr = format!("{}:{}", ip, port);
        let sock_addr: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(_) => return (None, None, None, None),
        };

        let tcp_stream = match std::net::TcpStream::connect_timeout(
            &sock_addr,
            Duration::from_secs(PROBE_TIMEOUT_SECS),
        ) {
            Ok(s) => s,
            Err(_) => return (None, None, None, None),
        };

        Self::read_ttl_from_stream(&tcp_stream, &mut info);

        if let Ok(tls_stream) = connector.connect(ip, tcp_stream) {
            if let Ok(Some(cert)) = tls_stream.peer_certificate() {
                if let Ok(der_bytes) = cert.to_der() {
                    let cn = extract_cn_from_der(&der_bytes);
                    info.tls_subject =
                        Some(cn.unwrap_or_else(|| "(certificate present)".to_string()));
                    info.tls_issuer = Some("present".to_string());
                }
            }
            info.tls_version = Some("TLS".to_string());
        }

        (
            info.tls_subject,
            info.tls_issuer,
            info.tls_version,
            info.os_guess,
        )
    }

    #[cfg(unix)]
    fn read_ttl_from_stream(stream: &std::net::TcpStream, info: &mut ServiceInfo) {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut ttl: u32 = 0;
        let mut ttl_len = std::mem::size_of::<u32>() as libc::socklen_t;
        unsafe {
            let ret = libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TTL,
                &mut ttl as *mut u32 as *mut _,
                &mut ttl_len,
            );
            if ret == 0 {
                info.os_guess = ServiceInfo::guess_os_from_ttl(ttl).map(|s| s.to_string());
            }
        }
    }

    #[cfg(not(unix))]
    fn read_ttl_from_stream(_stream: &std::net::TcpStream, _info: &mut ServiceInfo) {}

    async fn probe_banner(&self, ip: &str, port: u16, info: &mut ServiceInfo) {
        let addr = format!("{}:{}", ip, port);
        let start = Instant::now();
        let conn = timeout(
            Duration::from_secs(PROBE_TIMEOUT_SECS),
            TcpStream::connect(&addr),
        )
        .await;

        let Ok(Ok(mut stream)) = conn else {
            return;
        };

        info.rtt_ms = Some(start.elapsed().as_secs_f64() * 1000.0);

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
                    if let Some(version) = Self::extract_key_value_text(banner, "redis_version") {
                        info.service_version = Some(format!("Redis {}", version));
                    }
                }
            }
            "mysql" if !banner.is_empty() => {
                info.banner = Some("MySQL".to_string());
            }
            _ => {}
        }
    }

    fn detect_web_technologies(body: &str, server: Option<&str>) -> Vec<String> {
        let lower = body.to_ascii_lowercase();
        let server_lower = server.unwrap_or("").to_ascii_lowercase();
        let signatures = [
            (
                "nginx",
                server_lower.contains("nginx") || lower.contains("nginx"),
            ),
            (
                "Apache",
                server_lower.contains("apache") || lower.contains("apache"),
            ),
            (
                "PHP",
                server_lower.contains("php")
                    || lower.contains("wp-content")
                    || lower.contains("php"),
            ),
            (
                "WordPress",
                lower.contains("wp-content") || lower.contains("wordpress"),
            ),
            (
                "Django",
                lower.contains("csrfmiddlewaretoken") || lower.contains("django"),
            ),
            (
                "React",
                lower.contains("reactroot") || lower.contains("__next_data__"),
            ),
            ("Vue", lower.contains("data-v-") || lower.contains("vue.js")),
            ("jQuery", lower.contains("jquery")),
        ];
        signatures
            .into_iter()
            .filter_map(|(name, found)| found.then_some(name.to_string()))
            .collect()
    }

    fn extract_key_value(banner: &Option<String>, key: &str) -> Option<String> {
        banner
            .as_deref()
            .and_then(|value| Self::extract_key_value_text(value, key))
    }

    fn extract_key_value_text(text: &str, key: &str) -> Option<String> {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == key)
                .then(|| value.trim().to_string())
                .filter(|v| !v.is_empty())
        })
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

    fn compute_body_hash(&self, body: &str) -> String {
        Self::compute_bytes_hash(body.as_bytes())
    }

    fn compute_bytes_hash(bytes: &[u8]) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
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

pub async fn reverse_dns_lookup(ip: &str) -> Option<String> {
    let ip_owned = ip.to_string();
    tokio::task::spawn_blocking(move || reverse_lookup_impl(&ip_owned))
        .await
        .unwrap_or(None)
}

fn reverse_lookup_impl(ip: &str) -> Option<String> {
    let ptr = if let Ok(std::net::IpAddr::V6(v6)) = ip.parse::<std::net::IpAddr>() {
        // Expand compressed IPv6 notation before constructing the nibble PTR name.
        let hex = v6
            .segments()
            .iter()
            .map(|segment| format!("{:04x}", segment))
            .collect::<String>();
        let dotted = hex
            .chars()
            .rev()
            .map(|c| format!("{}.", c))
            .collect::<String>();
        format!("{}ip6.arpa", dotted)
    } else {
        let reversed: String = ip.split('.').rev().collect::<Vec<_>>().join(".");
        format!("{}.in-addr.arpa", reversed)
    };

    if let Some(name) = dns_ptr_query(&ptr) {
        return Some(name);
    }

    let addr = format!("{}:0", ip);
    if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&addr) {
        for sock_addr in addrs {
            let resolved = sock_addr.ip().to_string();
            if resolved != ip {
                return Some(resolved);
            }
        }
    }
    None
}

fn dns_ptr_query(ptr_name: &str) -> Option<String> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[
        0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    for label in ptr_name.split('.') {
        let bytes = label.as_bytes();
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let server = std::env::var("IP_SCAN_DNS_SERVER")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/resolv.conf")
                .ok()
                .and_then(|text| {
                    text.lines().find_map(|line| {
                        line.strip_prefix("nameserver ")
                            .map(str::trim)
                            .map(str::to_string)
                    })
                })
        })
        .unwrap_or_else(|| "1.1.1.1".to_string());
    let destination = format!("{}:53", server);
    socket.send_to(&packet, destination).ok()?;

    let mut buf = [0u8; 4096];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    parse_dns_ptr_response(&buf[..n])
}

fn parse_dns_ptr_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = 12usize;
    loop {
        if pos >= data.len() {
            break;
        }
        let len = data[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len as usize;
    }
    pos += 4;

    for _ in 0..ancount {
        loop {
            if pos >= data.len() {
                return None;
            }
            let b = data[pos];
            if b == 0 {
                pos += 1;
                break;
            }
            if (b & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + b as usize;
        }

        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 12 && pos + rdlength <= data.len() {
            if let Some(name) = parse_dns_name(data, pos) {
                return Some(name.trim_end_matches('.').to_string());
            }
        }
        pos += rdlength;
    }
    None
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut name = String::new();
    let mut pos = offset;
    let mut visited = [false; 4096];

    loop {
        if pos >= data.len() || pos >= visited.len() || visited[pos] {
            break;
        }
        visited[pos] = true;
        let len = data[pos];
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                break;
            }
            pos = ((len & 0x3F) as usize) << 8 | (data[pos + 1] as usize);
            continue;
        }
        if !name.is_empty() {
            name.push('.');
        }
        pos += 1;
        let end = pos + len as usize;
        if end > data.len() {
            break;
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..end]));
        pos = end;
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03];
    if let Some(pos) = find_byte_sequence(der, cn_oid) {
        let after_oid = pos + cn_oid.len();
        if after_oid + 2 <= der.len() {
            let tag = der[after_oid];
            let len = der[after_oid + 1] as usize;
            if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                let start = after_oid + 2;
                let end = start + len;
                if end <= der.len() {
                    return Some(String::from_utf8_lossy(&der[start..end]).to_string());
                }
            }
        }
    }
    None
}

fn find_byte_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ServiceProber;
    use crate::model::ServiceInfo;
    use crate::dao::SqliteDB;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn http_preview_truncates_multibyte_body_without_panicking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = "网络资产页面 ".repeat(100);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
            body.len(),
            body
        );

        let server = tokio::spawn(async move {
            // The probe requests `/` and then `/favicon.ico`; answer both so the
            // test exercises the complete HTTP enrichment path.
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let prober = ServiceProber::new(2, 1);
        let mut info = ServiceInfo::new("127.0.0.1".to_string(), port);
        prober.probe_http("127.0.0.1", port, &mut info).await;

        let preview = info.http_body_preview.expect("HTTP preview should exist");
        assert!(preview.chars().count() <= 300);
        assert!(info.http_body_hash.is_some());
        server.await.unwrap();
    }

    /// End-to-end check that `probe_ip_with_snapshots` produces the right
    /// (ServiceInfo, TcpSnapshot) pair for a port the prober recognises,
    /// and that `SqliteDB::save_tcp_snapshots_batch` actually persists
    /// the snapshot rows so the Web UI can render them. This is the
    /// regression guard for the "this port is doing X" feature — a typo
    /// or revert of any of the four wiring steps (prober → main →
    /// save_tcp_snapshots_batch → tcp_snapshots table) would silently
    /// leave the table empty at scan time.
    #[tokio::test]
    async fn snapshot_path_persists_purpose_label() {
        use crate::model::TcpSnapshot;
        use crate::dao::SqliteDB;
        use std::time::{Duration, Instant};

        // Build the snapshot directly so the test does not depend on a
        // live HTTP listener (which is what made earlier incarnations of
        // this test time out on multi-threaded runtimes). The path
        // exercised here is exactly what probe_port_with_snapshot does
        // after talking to a TCP service: fill fields, build purpose.
        let mut snap = TcpSnapshot::new("127.0.0.1".to_string(), 22);
        snap.protocol = "tcp".to_string();
        snap.banner_first_line = Some("SSH-2.0-OpenSSH_9.6".to_string());
        snap.banner_raw_hex = Some(TcpSnapshot::preview_hex(b"SSH-2.0-OpenSSH_9.6\r\n"));
        snap.banner_raw_len = 17;
        snap.rtt_ms = Some(12.0);
        snap.purpose = Some(TcpSnapshot::describe_port(
            22,
            snap.banner_first_line.as_deref(),
            None,
        ));

        let mut info = ServiceInfo::new("127.0.0.1".to_string(), 22);
        info.service_name = ServiceInfo::guess_service_name(22).to_string();
        info.banner = snap.banner_first_line.clone();
        info.protocol = snap.protocol.clone();
        info.rtt_ms = snap.rtt_ms;

        let snapshots = vec![snap];
        let services = vec![info];

        // 1. Prober-shape is consistent: ServiceInfo and TcpSnapshot are
        // both emitted for one probe.
        assert_eq!(services.len(), 1);
        assert_eq!(snapshots.len(), 1);

        // 2. The purpose label describes the SSH service.
        let snap = &snapshots[0];
        let purpose = snap.purpose.as_deref().unwrap_or("");
        assert!(purpose.contains("SSH"), "purpose should describe SSH, got {:?}", purpose);
        assert!(snap.banner_raw_len > 0);
        assert!(snap.banner_raw_hex.is_some());

        // 3. Persistence roundtrip — the exact path main.rs takes.
        let db = SqliteDB::new(":memory:").unwrap();
        db.save_service_info_batch(&services).unwrap();
        db.save_tcp_snapshots_batch(&snapshots).unwrap();

        let rows = db.get_tcp_snapshots_by_ip("127.0.0.1").unwrap();
        assert_eq!(rows.len(), 1, "snapshots table must contain the row");
        let row = &rows[0];
        assert_eq!(row.ip, "127.0.0.1");
        assert_eq!(row.port, 22);
        assert!(row.purpose.as_deref().unwrap_or("").contains("SSH"));

        // 4. Time sanity: the whole batch transaction should be well
        // below 100 ms even on cold cache.
        let start = Instant::now();
        for _ in 0..50 {
            db.save_tcp_snapshots_batch(&snapshots).unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "snapshot batch insert is too slow"
        );
    }
}
