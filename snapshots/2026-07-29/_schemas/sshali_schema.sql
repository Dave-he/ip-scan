CREATE TABLE port_bitmaps (
                port INTEGER NOT NULL,
                ip_type TEXT NOT NULL,
                scan_round INTEGER NOT NULL,
                bitmap BLOB NOT NULL,
                open_count INTEGER DEFAULT 0,
                last_updated TEXT NOT NULL,
                PRIMARY KEY (port, ip_type, scan_round)
            );
CREATE TABLE scan_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
CREATE TABLE open_ports_detail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                ip_type TEXT NOT NULL,
                port INTEGER NOT NULL,
                scan_round INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(ip_address, port)
            );
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE ip_details (
                ip_address TEXT PRIMARY KEY,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                asn TEXT,
                source TEXT NOT NULL,
                updated_at TEXT NOT NULL
            , reverse_dns TEXT);
CREATE TABLE service_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                service_name TEXT NOT NULL DEFAULT '',
                protocol TEXT NOT NULL DEFAULT '',
                banner TEXT,
                http_title TEXT,
                http_server TEXT,
                http_body_preview TEXT,
                tls_subject TEXT,
                tls_issuer TEXT,
                detected_at TEXT NOT NULL, tls_not_before TEXT, tls_not_after TEXT, tls_version TEXT, service_version TEXT, http_body_hash TEXT, http_security_headers TEXT, rtt_ms REAL, os_guess TEXT,
                UNIQUE(ip_address, port)
            );
CREATE TABLE service_probe_state (
                ip_address TEXT PRIMARY KEY,
                last_probe TEXT NOT NULL
            );
CREATE INDEX idx_port_round ON port_bitmaps(port, scan_round);
CREATE INDEX idx_open_ports_ip ON open_ports_detail(ip_address);
CREATE INDEX idx_open_ports_port ON open_ports_detail(port);
CREATE INDEX idx_open_ports_round ON open_ports_detail(scan_round);
CREATE INDEX idx_open_ports_last_seen ON open_ports_detail(last_seen DESC);
CREATE INDEX idx_service_info_ip ON service_info(ip_address);
CREATE INDEX idx_service_info_service ON service_info(service_name);
CREATE TABLE tcp_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT '',
                banner_first_line TEXT,
                banner_raw_hex TEXT,
                banner_raw_len INTEGER DEFAULT 0,
                http_status INTEGER,
                http_server TEXT,
                http_title TEXT,
                tls_subject TEXT,
                tls_issuer TEXT,
                tls_version TEXT,
                tls_san TEXT,
                tls_not_before TEXT,
                tls_not_after TEXT,
                os_guess TEXT,
                rtt_ms REAL,
                detected_technologies TEXT,
                purpose TEXT,
                captured_at TEXT NOT NULL,
                UNIQUE(ip_address, port)
            );
CREATE INDEX idx_tcp_snapshots_ip ON tcp_snapshots(ip_address);
CREATE INDEX idx_tcp_snapshots_purpose ON tcp_snapshots(purpose);
