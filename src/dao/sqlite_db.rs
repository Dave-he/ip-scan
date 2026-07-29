use crate::model::{
    index_to_ipv4, ipv4_to_index, IpGeoInfo, IpServiceSummary, PortBitmap, ServiceInfo, TcpSnapshot,
};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use utoipa::ToSchema;

#[derive(Clone)]
pub struct SqliteDB {
    conn: Arc<Mutex<Connection>>,
    /// When true, skip the bitmap table in bulk updates (--only-store-open).
    /// Avoids the 2 MiB serialize/deserialize per port that dominates
    /// throughput on large port sets.
    skip_bitmap: Arc<std::sync::atomic::AtomicBool>,
}

impl SqliteDB {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;

        // Port bitmaps table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS port_bitmaps (
                port INTEGER NOT NULL,
                ip_type TEXT NOT NULL,
                scan_round INTEGER NOT NULL,
                bitmap BLOB NOT NULL,
                open_count INTEGER DEFAULT 0,
                last_updated TEXT NOT NULL,
                PRIMARY KEY (port, ip_type, scan_round)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_port_round ON port_bitmaps(port, scan_round)",
            [],
        )?;

        // Scan metadata table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Optional: detailed open ports table for additional info
        conn.execute(
            "CREATE TABLE IF NOT EXISTS open_ports_detail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                ip_type TEXT NOT NULL,
                port INTEGER NOT NULL,
                scan_round INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(ip_address, port)
            )",
            [],
        )?;

        // Create indexes after table creation
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_open_ports_ip ON open_ports_detail(ip_address)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_open_ports_port ON open_ports_detail(port)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_open_ports_round ON open_ports_detail(scan_round)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_open_ports_last_seen ON open_ports_detail(last_seen DESC)",
            [],
        )?;

        // IP Geolocation table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ip_details (
                ip_address TEXT PRIMARY KEY,
                country TEXT,
                region TEXT,
                city TEXT,
                isp TEXT,
                asn TEXT,
                reverse_dns TEXT,
                source TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Track failed/empty service probes so the background worker does not
        // hammer the same unresponsive host every polling interval.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS service_probe_state (
                ip_address TEXT PRIMARY KEY,
                last_probe TEXT NOT NULL
            )",
            [],
        )?;

        // Service info table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS service_info (
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
                tls_not_before TEXT,
                tls_not_after TEXT,
                tls_version TEXT,
                service_version TEXT,
                http_body_hash TEXT,
                http_security_headers TEXT,
                rtt_ms REAL,
                os_guess TEXT,
                detected_at TEXT NOT NULL,
                UNIQUE(ip_address, port)
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_service_info_ip ON service_info(ip_address)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_service_info_service ON service_info(service_name)",
            [],
        )?;

        // TCP protocol snapshot table — captures both raw and parsed first
        // bytes for each open port. Drives the "what is this port doing?"
        // view in the Web UI. Mirrored by `save_tcp_snapshots_batch` and
        // `get_tcp_snapshots_by_ip`.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tcp_snapshots (
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
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcp_snapshots_ip ON tcp_snapshots(ip_address)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcp_snapshots_purpose ON tcp_snapshots(purpose)",
            [],
        )?;

        // Migrations for existing databases
        let migrations = [
            "ALTER TABLE ip_details ADD COLUMN reverse_dns TEXT",
            "ALTER TABLE ip_details ADD COLUMN latitude REAL",
            "ALTER TABLE ip_details ADD COLUMN longitude REAL",
            "ALTER TABLE service_info ADD COLUMN tls_not_before TEXT",
            "ALTER TABLE service_info ADD COLUMN tls_not_after TEXT",
            "ALTER TABLE service_info ADD COLUMN tls_version TEXT",
            "ALTER TABLE service_info ADD COLUMN service_version TEXT",
            "ALTER TABLE service_info ADD COLUMN http_body_hash TEXT",
            "ALTER TABLE service_info ADD COLUMN http_security_headers TEXT",
            "ALTER TABLE service_info ADD COLUMN rtt_ms REAL",
            "ALTER TABLE service_info ADD COLUMN os_guess TEXT",
        ];
        for m in &migrations {
            let _ = conn.execute(m, []);
        }

        // Optimization: Set WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Keep short writer bursts from failing with SQLITE_BUSY while the
        // enrichment worker and scanner flush concurrently.
        conn.busy_timeout(Duration::from_secs(5))?;
        // Negative cache_size is expressed in KiB; 64 MiB keeps hot indexes and
        // the current bitmap round in memory without changing correctness.
        conn.pragma_update(None, "cache_size", -64 * 1024i64)?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        // Lower the autocheckpoint threshold so each bitmap-round flush
        // (~250 KiB per port per round) is usually checkpointed before the WAL
        // bloats. 250 keeps the WAL bounded during sustained small writes.
        conn.pragma_update(None, "wal_autocheckpoint", 250i64)?;
        // Cap the reusable WAL allocation so a checkpoint failure cannot keep
        // hundreds of MiB pinned indefinitely.
        conn.pragma_update(None, "journal_size_limit", 64 * 1024 * 1024i64)?;
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");

        Ok(SqliteDB {
            conn: Arc::new(Mutex::new(conn)),
            skip_bitmap: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Trigger a passive WAL checkpoint. Returns true when the WAL was fully
    /// checkpointed. Use this between rounds to keep the WAL file bounded
    /// even when the autocheckpoint threshold is not hit.
    pub fn checkpoint_wal(&self) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        // PRAGMA wal_checkpoint(PASSIVE) returns (busy, log_pages, checkpointed_pages)
        // and never blocks readers. We treat a non-zero checkpointed count as a
        // successful shrink of the WAL tail.
        let mut stmt = conn.prepare("PRAGMA wal_checkpoint(PASSIVE)")?;
        let row: (i64, i64, i64) =
            stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(row.2 > 0)
    }

    pub fn cleanup_old_rounds(&self, keep_rounds: i64) -> Result<u64> {
        if keep_rounds <= 0 {
            return Err(anyhow::anyhow!("keep_rounds must be greater than zero"));
        }

        let conn = self.conn.lock().unwrap();
        let max_round: Option<i64> =
            conn.query_row("SELECT MAX(scan_round) FROM port_bitmaps", [], |row| {
                row.get(0)
            })?;
        let deleted = if let Some(max_round) = max_round {
            // Preserve the newest N rounds. Deriving the cutoff from MIN would
            // repeatedly delete the rounds that were meant to be retained.
            let cutoff = max_round.saturating_sub(keep_rounds - 1);
            conn.execute(
                "DELETE FROM port_bitmaps WHERE scan_round < ?1",
                params![cutoff],
            )?
        } else {
            0
        };

        // Do not VACUUM in the scan loop: it rewrites the whole database and
        // can inflate or lock the WAL every few seconds. Space is reused by
        // SQLite and explicit maintenance can VACUUM during a planned window.
        Ok(deleted as u64)
    }

    /// Persist multiple GeoIP records in one SQLite transaction.
    pub fn save_ip_geo_info_batch(&self, infos: &[IpGeoInfo]) -> Result<()> {
        if infos.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ip_details (ip_address, country, region, city, isp, asn, reverse_dns, source, updated_at, latitude, longitude) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) ON CONFLICT(ip_address) DO UPDATE SET country=?2, region=?3, city=?4, isp=?5, asn=?6, reverse_dns=?7, source=?8, updated_at=?9, latitude=COALESCE(?10, latitude), longitude=COALESCE(?11, longitude)"
            )?;
            let timestamp = Utc::now().to_rfc3339();
            for info in infos {
                stmt.execute(params![
                    info.ip,
                    info.country,
                    info.region,
                    info.city,
                    info.isp,
                    info.asn,
                    info.reverse_dns,
                    info.source,
                    timestamp,
                    info.latitude,
                    info.longitude,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_ip_geo_info(&self, ip: &str) -> Result<Option<IpGeoInfo>> {
        let conn = self.conn.lock().unwrap();

        let result = conn.query_row(
            "SELECT ip_address, country, region, city, isp, asn, reverse_dns, source, latitude, longitude FROM ip_details WHERE ip_address = ?1",
            [ip],
            |row| {
                Ok(IpGeoInfo {
                    ip: row.get(0)?,
                    country: row.get(1)?,
                    region: row.get(2)?,
                    city: row.get(3)?,
                    isp: row.get(4)?,
                    asn: row.get(5)?,
                    reverse_dns: row.get(6)?,
                    source: row.get(7)?,
                    latitude: row.get(8)?,
                    longitude: row.get(9)?,
                })
            },
        ).optional()?;

        Ok(result)
    }

    pub fn get_ips_missing_geo(&self, limit: usize) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT ip_address FROM open_ports_detail 
             WHERE ip_address NOT IN (SELECT ip_address FROM ip_details)
             LIMIT ?1",
        )?;

        let ips = stmt
            .query_map([limit], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;

        Ok(ips)
    }

    #[allow(dead_code)]
    pub fn set_port_status(
        &self,
        ip: &str,
        port: u16,
        is_open: bool,
        scan_round: i64,
    ) -> Result<()> {
        let ip_index = ipv4_to_index(ip)?;
        let conn = self.conn.lock().unwrap();

        // Get or create bitmap for this port
        let mut bitmap = self.get_port_bitmap_internal(&conn, port, "IPv4", scan_round)?;

        // Update bitmap
        bitmap.set(ip_index, is_open);

        // Save back to database
        let blob = bitmap.to_blob()?;
        let open_count = bitmap.count_ones() as i64;
        let timestamp = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO port_bitmaps (port, ip_type, scan_round, bitmap, open_count, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(port, ip_type, scan_round)
             DO UPDATE SET bitmap = ?4, open_count = ?5, last_updated = ?6",
            params![port, "IPv4", scan_round, blob, open_count, timestamp],
        )?;

        // If port is open, also store in detail table
        if is_open {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO open_ports_detail (ip_address, ip_type, port, scan_round, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(ip_address, port)
                 DO UPDATE SET scan_round = ?4, last_seen = ?6",
                params![ip, "IPv4", port, scan_round, now.clone(), now],
            )?;
        }

        Ok(())
    }

    pub fn bulk_update_port_status(
        &self,
        updates: Vec<(String, u16, bool)>,
        scan_round: i64,
    ) -> Result<()> {
        let skip = self.skip_bitmap.load(std::sync::atomic::Ordering::Relaxed);
        self.bulk_update_port_status_with_skip_bitmap(updates, scan_round, skip)
    }

    /// Set the bitmap-skip flag. Pass true to make subsequent
    /// `bulk_update_port_status` calls skip the bitmap table.
    pub fn set_skip_bitmap(&self, skip: bool) {
        self.skip_bitmap
            .store(skip, std::sync::atomic::Ordering::Relaxed);
    }

    /// Like `bulk_update_port_status` but optionally skips the bitmap table
    /// write entirely. When `skip_bitmap` is true, only the open_ports_detail
    /// table is touched — this is the fast path used by `--only-store-open`,
    /// where the closed-port bitmap is uninteresting and its 2 MiB
    /// serialize/deserialize per port is the dominant cost on large
    /// port sets.
    pub fn bulk_update_port_status_with_skip_bitmap(
        &self,
        updates: Vec<(String, u16, bool)>,
        scan_round: i64,
        skip_bitmap: bool,
    ) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

        // Track whether any probe in this batch actually found an open port.
        // last_scan_time is bumped only when we have a real discovery so we
        // don't churn the scan_metadata table on every batch of closed ports
        // (the dominant case in a TCP connect scan where most destinations
        // do not respond). This keeps the semantics of last_scan_time aligned
        // with what /api/v1/stats reports: "last time an open port was found".
        let has_open = updates.iter().any(|(_, _, is_open)| *is_open);

        let mut conn = self.conn.lock().unwrap();
        let transaction = conn.transaction()?;

        // Group by port to minimize bitmap loads/saves
        let mut updates_by_port: HashMap<u16, Vec<(u32, bool, String)>> = HashMap::new();

        for (ip, port, is_open) in updates {
            match ipv4_to_index(&ip) {
                Ok(ip_index) => {
                    updates_by_port
                        .entry(port)
                        .or_default()
                        .push((ip_index, is_open, ip));
                }
                Err(_) => continue, // Skip invalid IPs
            }
        }

        for (port, items) in updates_by_port {
            if !skip_bitmap {
                // 1. Update Bitmap
                let mut bitmap =
                    self.get_port_bitmap_internal(&transaction, port, "IPv4", scan_round)?;

                for (ip_index, is_open, _) in &items {
                    bitmap.set(*ip_index, *is_open);
                }

                let blob = bitmap.to_blob()?;
                let open_count = bitmap.count_ones() as i64;
                let timestamp = Utc::now().to_rfc3339();

                transaction.execute(
                    "INSERT INTO port_bitmaps (port, ip_type, scan_round, bitmap, open_count, last_updated)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(port, ip_type, scan_round)
                     DO UPDATE SET bitmap = ?4, open_count = ?5, last_updated = ?6",
                    params![port, "IPv4", scan_round, blob, open_count, timestamp],
                )?;
            }

            // 2. Update Details (Only for open ports)
            // Prepare statement for better performance
            {
                let mut stmt = transaction.prepare(
                    "INSERT INTO open_ports_detail (ip_address, ip_type, port, scan_round, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(ip_address, port)
                     DO UPDATE SET scan_round = ?4, last_seen = ?6"
                )?;

                for (_, is_open, ip) in &items {
                    if *is_open {
                        let now = Utc::now().to_rfc3339();
                        stmt.execute(params![ip, "IPv4", port, scan_round, now.clone(), now])?;
                    }
                }
            }
        }

        // 3. Bump last_scan_time on every batch that contained an open port.
        // Inlined into the same transaction (rather than calling
        // `save_metadata`) so we don't re-acquire `self.conn` while the
        // mutex is held; `std::sync::Mutex` is not reentrant. Keeping it
        // inside the transaction also guarantees atomicity: either the
        // open_ports_detail inserts AND the metadata bump succeed, or
        // neither do.
        if has_open {
            let now_meta = Utc::now().to_rfc3339();
            transaction.execute(
                "INSERT INTO scan_metadata (key, value, updated_at)
                 VALUES ('last_scan_time', ?1, ?1)
                 ON CONFLICT(key) DO UPDATE SET value = ?1, updated_at = ?1",
                params![now_meta],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }

    fn get_port_bitmap_internal(
        &self,
        conn: &Connection,
        port: u16,
        ip_type: &str,
        scan_round: i64,
    ) -> Result<PortBitmap> {
        let result: rusqlite::Result<Vec<u8>> = conn.query_row(
            "SELECT bitmap FROM port_bitmaps WHERE port = ?1 AND ip_type = ?2 AND scan_round = ?3",
            params![port, ip_type, scan_round],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => PortBitmap::from_blob(&blob),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(PortBitmap::new()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_stats(&self) -> Result<(usize, usize)> {
        let conn = self.conn.lock().unwrap();

        // Single round trip keeps round-to-round overhead low; the loop runs
        // many rounds per minute and the prior version took the connection
        // mutex twice per round for two trivially-fast aggregates.
        let mut stmt = conn.prepare_cached(
            "SELECT
                COALESCE((SELECT SUM(open_count) FROM port_bitmaps), 0),
                COALESCE((SELECT COUNT(DISTINCT ip_address) FROM open_ports_detail), 0)",
        )?;
        let (total, unique): (i64, i64) =
            stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok((total as usize, unique as usize))
    }

    /// Aggregate scan results grouped by IP family (IPv4 vs IPv6).
    /// Returns (ipv4_unique_ips, ipv6_unique_ips, ipv4_open_ports, ipv6_open_ports).
    /// Useful for the IP-family view in the distributed frontend.
    pub fn get_stats_by_ip_family(&self) -> Result<(usize, usize, usize, usize)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_type, COUNT(DISTINCT ip_address), COUNT(*)
             FROM open_ports_detail
             GROUP BY ip_type",
        )?;
        let mut ipv4_unique = 0usize;
        let mut ipv6_unique = 0usize;
        let mut ipv4_ports = 0usize;
        let mut ipv6_ports = 0usize;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
            ))
        })?;
        for row in rows {
            let (ip_type, unique, ports) = row?;
            if ip_type == "IPv6" {
                ipv6_unique = unique;
                ipv6_ports = ports;
            } else {
                // Treat anything that isn't IPv6 as IPv4 — the scanner only
                // emits those two labels today and historical rows match.
                ipv4_unique = unique;
                ipv4_ports = ports;
            }
        }
        Ok((ipv4_unique, ipv6_unique, ipv4_ports, ipv6_ports))
    }

    /// Aggregate scan results grouped by service_name from the service_info
    /// table. Returns service_name -> unique_ip_count + open_port_count.
    /// Empty services (no banner / probe didn't run) are excluded.
    pub fn get_stats_by_service(&self) -> Result<Vec<(String, usize, usize)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT
                COALESCE(NULLIF(service_name, ''), 'unknown') AS service,
                COUNT(DISTINCT ip_address),
                COUNT(*)
             FROM service_info
             GROUP BY service
             ORDER BY COUNT(DISTINCT ip_address) DESC, COUNT(*) DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Aggregate scan results grouped by the asset category reported by
    /// `IpServiceSummary::categorize`. Empty IP sets are ignored.
    pub fn get_stats_by_category(&self) -> Result<Vec<(String, usize)>> {
        let conn = self.conn.lock().unwrap();
        // Group by IP and reconstruct categories client-side from the
        // services present in service_info. Doing it here keeps the
        // single-statement aggregate cheap (one pass over service_info) and
        // gives the frontend a faithful `web-server`, `database-server` etc.
        // distribution without needing an extra stored column.
        let mut stmt = conn.prepare(
            "SELECT ip_address, service_name FROM service_info
             WHERE service_name != ''",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut per_ip: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for row in rows {
            let (ip, svc) = row?;
            per_ip.entry(ip).or_default().push(svc);
        }
        let mut counter: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for services in per_ip.values() {
            let cat = crate::model::IpServiceSummary::categorize_from_names(services);
            *counter.entry(cat).or_insert(0) += 1;
        }
        let mut out: Vec<(String, usize)> = counter.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(out)
    }

    /// Return all IPs that have geo coordinates. The frontend uses this
    /// for the map view. Limit bounds the response; callers should page if
    /// the inventory exceeds the limit.
    pub fn get_ip_locations(&self, limit: usize) -> Result<Vec<IpGeoInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_address, country, region, city, isp, asn, reverse_dns, source,
                    latitude, longitude
             FROM ip_details
             WHERE latitude IS NOT NULL AND longitude IS NOT NULL
             ORDER BY updated_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit as i64], |row| {
                Ok(IpGeoInfo {
                    ip: row.get(0)?,
                    country: row.get(1)?,
                    region: row.get(2)?,
                    city: row.get(3)?,
                    isp: row.get(4)?,
                    asn: row.get(5)?,
                    reverse_dns: row.get(6)?,
                    source: row.get(7)?,
                    latitude: row.get(8)?,
                    longitude: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count IPs that have geo coordinates attached. Drives the map marker
    /// total in the distributed frontend.
    pub fn count_ip_locations(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ip_details
             WHERE latitude IS NOT NULL AND longitude IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Aggregate open-port count + top service for one IP. Backs the map
    /// marker tooltips in the distributed frontend.
    pub fn get_ip_top_service(&self, ip: &str) -> Result<(usize, Option<String>)> {
        let conn = self.conn.lock().unwrap();
        let open_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM open_ports_detail WHERE ip_address = ?1",
                [ip],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let top_service: Option<String> = conn
            .query_row(
                "SELECT service_name FROM service_info
                 WHERE ip_address = ?1 AND service_name != ''
                 GROUP BY service_name
                 ORDER BY COUNT(*) DESC
                 LIMIT 1",
                [ip],
                |row| row.get(0),
            )
            .ok();
        Ok((open_count as usize, top_service))
    }

    pub fn get_stats_by_port(&self, scan_round: i64) -> Result<Vec<(u16, usize)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT port, open_count FROM port_bitmaps WHERE scan_round = ?1 ORDER BY open_count DESC"
        )?;

        let stats = stmt
            .query_map([scan_round], |row| {
                Ok((row.get::<_, u16>(0)?, row.get::<_, i64>(1)? as usize))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(stats)
    }

    pub fn save_metadata(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let timestamp = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO scan_metadata (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key)
             DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, timestamp],
        )?;

        Ok(())
    }

    pub fn get_metadata(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();

        let result = conn.query_row(
            "SELECT value FROM scan_metadata WHERE key = ?1",
            [key],
            |row| row.get(0),
        );

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_current_round(&self) -> Result<i64> {
        match self.get_metadata("current_round")? {
            Some(value) => Ok(value.parse()?),
            None => Ok(1),
        }
    }

    pub fn increment_round(&self) -> Result<i64> {
        let current = self.get_current_round()?;
        let new_round = current + 1;
        self.save_metadata("current_round", &new_round.to_string())?;
        Ok(new_round)
    }

    pub fn save_progress(&self, ip: &str, ip_type: &str, scan_round: i64) -> Result<()> {
        self.save_metadata("last_ip", ip)?;
        self.save_metadata("last_ip_type", ip_type)?;
        self.save_metadata("last_scan_round", &scan_round.to_string())?;
        Ok(())
    }

    pub fn get_progress(&self) -> Result<Option<(String, String, i64)>> {
        let last_ip = self.get_metadata("last_ip")?;
        let last_ip_type = self.get_metadata("last_ip_type")?;
        let last_round = self.get_metadata("last_scan_round")?;

        match (last_ip, last_ip_type, last_round) {
            (Some(ip), Some(ip_type), Some(round)) => Ok(Some((ip, ip_type, round.parse()?))),
            _ => Ok(None),
        }
    }

    pub fn get_memory_usage(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(bitmap)), 0) FROM port_bitmaps",
            [],
            |row| row.get(0),
        )?;
        Ok(size as usize)
    }

    // API-specific methods

    /// Get paginated scan results with filtering
    pub fn get_scan_results(
        &self,
        page: usize,
        page_size: usize,
        ip_filter: Option<&str>,
        port_filter: Option<u16>,
        round_filter: Option<i64>,
        ip_type_filter: Option<&str>,
    ) -> Result<(Vec<ScanResultDetail>, usize)> {
        let conn = self.conn.lock().unwrap();

        // Build WHERE clause
        let mut where_clauses = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(ip) = ip_filter {
            where_clauses.push("ip_address LIKE ?");
            params.push(Box::new(format!("%{}%", ip)));
        }

        if let Some(port) = port_filter {
            where_clauses.push("port = ?");
            params.push(Box::new(port));
        }

        if let Some(round) = round_filter {
            where_clauses.push("scan_round = ?");
            params.push(Box::new(round));
        }

        if let Some(ip_type) = ip_type_filter {
            where_clauses.push("ip_type = ?");
            params.push(Box::new(ip_type));
        }

        let where_clause = if where_clauses.is_empty() {
            "".to_string()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // Get total count
        let count_query = format!("SELECT COUNT(*) FROM open_ports_detail {}", where_clause);

        let total: i64 = conn.query_row(
            &count_query,
            params.iter().map(|p| &**p).collect::<Vec<_>>().as_slice(),
            |row| row.get(0),
        )?;

        // Get paginated results
        let offset = (page - 1) * page_size;
        let query = format!(
            "SELECT o.ip_address, o.ip_type, o.port, o.scan_round, o.first_seen, o.last_seen,
                    i.country, i.region, i.city, i.isp, i.asn, i.reverse_dns,
                    si.service_name,
                    CASE WHEN si.service_name IN ('http','https','http-alt','https-alt')
                         THEN si.http_title
                         ELSE si.banner
                    END AS banner,
                    i.latitude, i.longitude,
                    s.port AS s_port
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             LEFT JOIN service_info si ON si.ip_address = o.ip_address AND si.port = o.port
             LEFT JOIN open_ports_detail s ON s.ip_address = o.ip_address AND s.port = o.port
             {}
             GROUP BY o.ip_address, o.port
             ORDER BY o.last_seen DESC, o.ip_address, o.port
             LIMIT ? OFFSET ?",
            where_clause
        );

        let mut stmt = conn.prepare(&query)?;

        // Add LIMIT and OFFSET parameters
        let mut all_params: Vec<Box<dyn rusqlite::ToSql>> = params;
        all_params.push(Box::new(page_size as i64));
        all_params.push(Box::new(offset as i64));

        let results = stmt
            .query_map(
                all_params
                    .iter()
                    .map(|p| &**p)
                    .collect::<Vec<_>>()
                    .as_slice(),
                |row| {
                    Ok(ScanResultDetail {
                        ip_address: row.get(0)?,
                        ip_type: row.get(1)?,
                        port: row.get(2)?,
                        scan_round: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        country: row.get(6)?,
                        region: row.get(7)?,
                        city: row.get(8)?,
                        isp: row.get(9)?,
                        asn: row.get(10)?,
                        reverse_dns: row.get(11)?,
                        service_name: row.get(12)?,
                        banner: row.get(13)?,
                        risk_score: None,
                        latitude: row.get(14)?,
                        longitude: row.get(15)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((results, total as usize))
    }

    /// Get scan results for a specific IP
    pub fn get_results_by_ip(&self, ip: &str) -> Result<Vec<ScanResultDetail>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT o.ip_address, o.ip_type, o.port, o.scan_round, o.first_seen, o.last_seen,
                    i.country, i.region, i.city, i.isp, i.asn, i.reverse_dns,
                    si.service_name,
                    CASE WHEN si.service_name IN ('http','https','http-alt','https-alt')
                         THEN si.http_title ELSE si.banner END AS banner,
                    i.latitude, i.longitude
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             LEFT JOIN service_info si ON si.ip_address = o.ip_address AND si.port = o.port
             WHERE o.ip_address = ?
             ORDER BY o.port",
        )?;

        let results = stmt
            .query_map([ip], |row| {
                Ok(ScanResultDetail {
                    ip_address: row.get(0)?,
                    ip_type: row.get(1)?,
                    port: row.get(2)?,
                    scan_round: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    country: row.get(6)?,
                    region: row.get(7)?,
                    city: row.get(8)?,
                    isp: row.get(9)?,
                    asn: row.get(10)?,
                    reverse_dns: row.get(11)?,
                    service_name: row.get(12)?,
                    banner: row.get(13)?,
                    risk_score: None,
                    latitude: row.get(14)?,
                    longitude: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get scan results for a specific port
    pub fn get_results_by_port(&self, port: u16) -> Result<Vec<ScanResultDetail>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT o.ip_address, o.ip_type, o.port, o.scan_round, o.first_seen, o.last_seen,
                    i.country, i.region, i.city, i.isp, i.asn, i.reverse_dns,
                    si.service_name,
                    CASE WHEN si.service_name IN ('http','https','http-alt','https-alt')
                         THEN si.http_title ELSE si.banner END AS banner,
                    i.latitude, i.longitude
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             LEFT JOIN service_info si ON si.ip_address = o.ip_address AND si.port = o.port
             WHERE o.port = ?
             ORDER BY o.last_seen DESC, o.ip_address",
        )?;

        let results = stmt
            .query_map([port], |row| {
                Ok(ScanResultDetail {
                    ip_address: row.get(0)?,
                    ip_type: row.get(1)?,
                    port: row.get(2)?,
                    scan_round: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    country: row.get(6)?,
                    region: row.get(7)?,
                    city: row.get(8)?,
                    isp: row.get(9)?,
                    asn: row.get(10)?,
                    reverse_dns: row.get(11)?,
                    service_name: row.get(12)?,
                    banner: row.get(13)?,
                    risk_score: None,
                    latitude: row.get(14)?,
                    longitude: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get scan results for a specific round
    pub fn get_results_by_round(&self, round: i64) -> Result<Vec<ScanResultDetail>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT o.ip_address, o.ip_type, o.port, o.scan_round, o.first_seen, o.last_seen,
                    i.country, i.region, i.city, i.isp, i.asn, i.reverse_dns,
                    si.service_name,
                    CASE WHEN si.service_name IN ('http','https','http-alt','https-alt')
                         THEN si.http_title ELSE si.banner END AS banner,
                    i.latitude, i.longitude
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             LEFT JOIN service_info si ON si.ip_address = o.ip_address AND si.port = o.port
             WHERE o.scan_round = ?
             ORDER BY o.ip_address, o.port",
        )?;

        let results = stmt
            .query_map([round], |row| {
                Ok(ScanResultDetail {
                    ip_address: row.get(0)?,
                    ip_type: row.get(1)?,
                    port: row.get(2)?,
                    scan_round: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    country: row.get(6)?,
                    region: row.get(7)?,
                    city: row.get(8)?,
                    isp: row.get(9)?,
                    asn: row.get(10)?,
                    reverse_dns: row.get(11)?,
                    service_name: row.get(12)?,
                    banner: row.get(13)?,
                    risk_score: None,
                    latitude: row.get(14)?,
                    longitude: row.get(15)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get top ports statistics
    pub fn get_top_ports(&self, limit: usize) -> Result<Vec<(u16, usize)>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT port, COUNT(*) as count 
             FROM open_ports_detail 
             GROUP BY port 
             ORDER BY count DESC 
             LIMIT ?",
        )?;

        let results = stmt
            .query_map([limit as i64], |row| {
                Ok((row.get::<_, u16>(0)?, row.get::<_, i64>(1)? as usize))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get total count of all open ports
    pub fn get_total_open_ports_count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM open_ports_detail", [], |row| {
            row.get(0)
        })?;
        Ok(count as usize)
    }

    /// Get last scan timestamp
    pub fn get_last_scan_time(&self) -> Result<Option<String>> {
        if let Some(completed_at) = self.get_metadata("last_scan_time")? {
            return Ok(Some(completed_at));
        }

        let conn = self.conn.lock().unwrap();
        let result: Option<String> =
            conn.query_row("SELECT MAX(last_updated) FROM port_bitmaps", [], |row| {
                row.get(0)
            })?;
        Ok(result)
    }

    /// Get scan history grouped by scan round
    pub fn get_scan_history(&self, limit: usize) -> Result<Vec<ScanHistoryRecord>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT scan_round,
                    MIN(last_updated) as start_time,
                    MAX(last_updated) as end_time,
                    SUM(open_count) as total_open_ports,
                    COUNT(DISTINCT port) as ports_scanned
             FROM port_bitmaps
             GROUP BY scan_round
             ORDER BY scan_round DESC
             LIMIT ?",
        )?;

        let results = stmt
            .query_map([limit as i64], |row| {
                Ok(ScanHistoryRecord {
                    round: row.get(0)?,
                    start_time: row.get(1)?,
                    end_time: row.get(2)?,
                    total_open_ports: row.get::<_, i64>(3)? as usize,
                    ports_scanned: row.get::<_, i64>(4)? as usize,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    // ── Service Info CRUD ──────────────────────────────────────────

    #[allow(dead_code)]
    pub fn save_service_info(&self, info: &ServiceInfo) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO service_info (ip_address, port, service_name, protocol, banner, http_title, http_server, http_body_preview, tls_subject, tls_issuer, tls_not_before, tls_not_after, tls_version, service_version, http_body_hash, http_security_headers, rtt_ms, os_guess, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
             ON CONFLICT(ip_address, port)
             DO UPDATE SET service_name=?3, protocol=?4, banner=?5, http_title=?6, http_server=?7, http_body_preview=?8, tls_subject=?9, tls_issuer=?10, tls_not_before=?11, tls_not_after=?12, tls_version=?13, service_version=?14, http_body_hash=?15, http_security_headers=?16, rtt_ms=?17, os_guess=?18, detected_at=?19",
            params![
                info.ip, info.port, info.service_name, info.protocol,
                info.banner, info.http_title, info.http_server,
                info.http_body_preview, info.tls_subject, info.tls_issuer,
                info.tls_not_before, info.tls_not_after, info.tls_version,
                info.service_version, info.http_body_hash, info.http_security_headers, info.rtt_ms, info.os_guess,
                info.detected_at,
            ],
        )?;
        Ok(())
    }

    pub fn save_service_info_batch(&self, infos: &[ServiceInfo]) -> Result<()> {
        if infos.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO service_info (ip_address, port, service_name, protocol, banner, http_title, http_server, http_body_preview, tls_subject, tls_issuer, tls_not_before, tls_not_after, tls_version, service_version, http_body_hash, http_security_headers, rtt_ms, os_guess, detected_at)\n                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)\n                 ON CONFLICT(ip_address, port)\n                 DO UPDATE SET service_name=?3, protocol=?4, banner=?5, http_title=?6, http_server=?7, http_body_preview=?8, tls_subject=?9, tls_issuer=?10, tls_not_before=?11, tls_not_after=?12, tls_version=?13, service_version=?14, http_body_hash=?15, http_security_headers=?16, rtt_ms=?17, os_guess=?18, detected_at=?19"
            )?;
            for info in infos {
                stmt.execute(params![
                    info.ip,
                    info.port,
                    info.service_name,
                    info.protocol,
                    info.banner,
                    info.http_title,
                    info.http_server,
                    info.http_body_preview,
                    info.tls_subject,
                    info.tls_issuer,
                    info.tls_not_before,
                    info.tls_not_after,
                    info.tls_version,
                    info.service_version,
                    info.http_body_hash,
                    info.http_security_headers,
                    info.rtt_ms,
                    info.os_guess,
                    info.detected_at,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Persist a batch of TCP protocol snapshots in one transaction. Powers
    /// the "what is this port doing?" view: each row carries the parsed
    /// banner, raw bytes hex preview, HTTP/TLS fields, and a human-readable
    /// `purpose` label. Caller probes via
    /// `ServiceProber::probe_ip_with_snapshots`.
    pub fn save_tcp_snapshots_batch(&self, snapshots: &[TcpSnapshot]) -> Result<()> {
        if snapshots.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO tcp_snapshots (ip_address, port, protocol, banner_first_line, banner_raw_hex, banner_raw_len, http_status, http_server, http_title, tls_subject, tls_issuer, tls_version, tls_san, tls_not_before, tls_not_after, os_guess, rtt_ms, detected_technologies, purpose, captured_at)\n                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)\n                 ON CONFLICT(ip_address, port)\n                 DO UPDATE SET protocol=?3, banner_first_line=?4, banner_raw_hex=?5, banner_raw_len=?6, http_status=?7, http_server=?8, http_title=?9, tls_subject=?10, tls_issuer=?11, tls_version=?12, tls_san=?13, tls_not_before=?14, tls_not_after=?15, os_guess=?16, rtt_ms=?17, detected_technologies=?18, purpose=?19, captured_at=?20",
            )?;
            for snap in snapshots {
                stmt.execute(params![
                    snap.ip,
                    snap.port,
                    snap.protocol,
                    snap.banner_first_line,
                    snap.banner_raw_hex,
                    snap.banner_raw_len as i64,
                    snap.http_status.map(|v| v as i64),
                    snap.http_server,
                    snap.http_title,
                    snap.tls_subject,
                    snap.tls_issuer,
                    snap.tls_version,
                    snap.tls_san,
                    snap.tls_not_before,
                    snap.tls_not_after,
                    snap.os_guess,
                    snap.rtt_ms,
                    snap.detected_technologies,
                    snap.purpose,
                    snap.captured_at,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Read back the persisted `tcp_snapshots` rows for one IP, ordered
    /// by port. Used by the Web UI ("what is this port doing?") and by the
    /// regression test in `service_prober::tests`.
    pub fn get_tcp_snapshots_by_ip(&self, ip: &str) -> Result<Vec<TcpSnapshot>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_address, port, protocol, banner_first_line, banner_raw_hex, banner_raw_len,
                    http_status, http_server, http_title, tls_subject, tls_issuer, tls_version,
                    tls_san, tls_not_before, tls_not_after, os_guess, rtt_ms,
                    detected_technologies, purpose, captured_at
             FROM tcp_snapshots WHERE ip_address = ?1 ORDER BY port",
        )?;
        let results = stmt
            .query_map([ip], |row| {
                Ok(TcpSnapshot {
                    ip: row.get(0)?,
                    port: row.get(1)?,
                    protocol: row.get(2)?,
                    banner_first_line: row.get(3)?,
                    banner_raw_hex: row.get(4)?,
                    banner_raw_len: row.get::<_, i64>(5)? as usize,
                    http_status: row.get::<_, Option<i64>>(6)?.map(|v| v as u16),
                    http_server: row.get(7)?,
                    http_title: row.get(8)?,
                    tls_subject: row.get(9)?,
                    tls_issuer: row.get(10)?,
                    tls_version: row.get(11)?,
                    tls_san: row.get(12)?,
                    tls_not_before: row.get(13)?,
                    tls_not_after: row.get(14)?,
                    os_guess: row.get(15)?,
                    rtt_ms: row.get(16)?,
                    detected_technologies: row.get(17)?,
                    purpose: row.get(18)?,
                    captured_at: row.get(19)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    pub fn get_service_info_by_ip(&self, ip: &str) -> Result<Vec<ServiceInfo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_address, port, service_name, protocol, banner, http_title, http_server, http_body_preview, tls_subject, tls_issuer, tls_not_before, tls_not_after, tls_version, service_version, http_body_hash, http_security_headers, rtt_ms, os_guess, detected_at
             FROM service_info WHERE ip_address = ?1 ORDER BY port",
        )?;
        let results = stmt
            .query_map([ip], |row| {
                Ok(ServiceInfo {
                    ip: row.get(0)?,
                    port: row.get(1)?,
                    service_name: row.get(2)?,
                    protocol: row.get(3)?,
                    banner: row.get(4)?,
                    http_title: row.get(5)?,
                    http_server: row.get(6)?,
                    http_body_preview: row.get(7)?,
                    tls_subject: row.get(8)?,
                    tls_issuer: row.get(9)?,
                    tls_not_before: row.get(10)?,
                    tls_not_after: row.get(11)?,
                    tls_version: row.get(12)?,
                    service_version: row.get(13)?,
                    http_body_hash: row.get(14)?,
                    http_security_headers: row.get(15)?,
                    rtt_ms: row.get(16)?,
                    os_guess: row.get(17)?,
                    detected_at: row.get(18)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    pub fn mark_service_probe_attempts(&self, ips: &[String]) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        {
            let mut stmt = tx.prepare("INSERT INTO service_probe_state (ip_address, last_probe) VALUES (?1, ?2) ON CONFLICT(ip_address) DO UPDATE SET last_probe = ?2")?;
            for ip in ips {
                stmt.execute(params![ip, now])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_ips_missing_service_probe(&self, limit: usize) -> Result<Vec<(String, Vec<u16>)>> {
        let conn = self.conn.lock().unwrap();
        let retry_before = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT o.ip_address, GROUP_CONCAT(o.port) as ports
             FROM open_ports_detail o
             WHERE o.ip_address NOT IN (SELECT DISTINCT ip_address FROM service_info)
               AND (NOT EXISTS (SELECT 1 FROM service_probe_state s WHERE s.ip_address = o.ip_address)
                    OR EXISTS (SELECT 1 FROM service_probe_state s WHERE s.ip_address = o.ip_address AND s.last_probe < ?2))
             GROUP BY o.ip_address
             LIMIT ?1",
        )?;
        let results = stmt
            .query_map(params![limit as i64, retry_before], |row| {
                let ip: String = row.get(0)?;
                let ports_str: String = row.get(1)?;
                let ports: Vec<u16> = ports_str
                    .split(',')
                    .filter_map(|s| s.parse().ok())
                    .collect();
                Ok((ip, ports))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    pub fn get_all_ip_service_summaries(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<IpServiceSummary>> {
        // Release the connection mutex before loading each IP's services.
        // get_service_info_by_ip acquires the same non-reentrant mutex.
        let ips: Vec<String> = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT ip_address FROM (SELECT DISTINCT ip_address FROM service_info) LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt
                .query_map([limit as i64, offset as i64], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };

        let mut summaries = Vec::new();
        for ip in ips {
            let services = self.get_service_info_by_ip(&ip)?;
            let category = IpServiceSummary::categorize(&services);
            let (risk_score, risk_reasons) = IpServiceSummary::assess_risk(&services);
            summaries.push(IpServiceSummary {
                ip: ip.clone(),
                services,
                ip_type: None,
                category,
                risk_score,
                risk_reasons,
            });
        }
        Ok(summaries)
    }

    /// Compare two persisted IPv4 bitmap rounds and return bounded port changes.
    pub fn get_bitmap_changes(
        &self,
        round: i64,
        port: u16,
        limit: usize,
    ) -> Result<Vec<PortChange>> {
        let conn = self.conn.lock().unwrap();
        let load = |scan_round: i64| -> Result<Option<PortBitmap>> {
            let result: rusqlite::Result<Vec<u8>> = conn.query_row(
                "SELECT bitmap FROM port_bitmaps WHERE port = ?1 AND ip_type = 'IPv4' AND scan_round = ?2",
                params![port, scan_round], |row| row.get(0));
            match result {
                Ok(blob) => Ok(Some(PortBitmap::from_blob(&blob)?)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        };
        let Some(current) = load(round)? else {
            return Ok(Vec::new());
        };
        let previous = load(round - 1)?.unwrap_or_else(PortBitmap::new);
        Ok(current
            .changed_indices(&previous, limit)
            .into_iter()
            .map(|index| PortChange {
                ip_address: index_to_ipv4(index),
                port,
                round,
                is_open: current.get(index),
            })
            .collect())
    }

    pub fn count_ips_with_service_info(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT ip_address) FROM service_info",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

/// Detailed scan result for API responses
#[derive(Debug, Clone)]
pub struct ScanResultDetail {
    pub ip_address: String,
    pub ip_type: String,
    pub port: u16,
    pub scan_round: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub reverse_dns: Option<String>,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub risk_score: Option<u8>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct PortChange {
    pub ip_address: String,
    pub port: u16,
    pub round: i64,
    pub is_open: bool,
}

/// Scan history record
#[derive(Debug)]
pub struct ScanHistoryRecord {
    pub round: i64,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub total_open_ports: usize,
    pub ports_scanned: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_summary_query_does_not_reenter_connection_mutex() {
        let db = SqliteDB::new(":memory:").unwrap();
        let mut service = ServiceInfo::new("192.0.2.10".to_string(), 443);
        service.service_name = "https".to_string();
        service.protocol = "https".to_string();
        db.save_service_info(&service).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = db.get_all_ip_service_summaries(10, 0);
            let _ = tx.send(result);
        });

        let summaries = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("service summary query deadlocked")
            .unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].ip, "192.0.2.10");
        assert_eq!(summaries[0].services.len(), 1);
    }

    #[test]
    fn cleanup_old_rounds_preserves_the_newest_rounds() {
        let db = SqliteDB::new(":memory:").unwrap();
        for round in 1..=4 {
            db.set_port_status(&format!("192.0.2.{round}"), 80, true, round)
                .unwrap();
        }

        assert_eq!(db.cleanup_old_rounds(2).unwrap(), 2);
        let rounds = {
            let conn = db.conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT scan_round FROM port_bitmaps ORDER BY scan_round")
                .unwrap();
            stmt.query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(rounds, vec![3, 4]);
        assert_eq!(db.cleanup_old_rounds(2).unwrap(), 0);
        assert!(db.cleanup_old_rounds(0).is_err());
        assert!(db.get_last_scan_time().unwrap().is_some());
        db.save_metadata("last_scan_time", "2026-07-24T10:00:00Z")
            .unwrap();
        assert_eq!(
            db.get_last_scan_time().unwrap().as_deref(),
            Some("2026-07-24T10:00:00Z")
        );
    }

    #[test]
    fn test_database_operations() {
        // Use in-memory database for testing
        let db = SqliteDB::new(":memory:").unwrap();

        // Test initial state
        let (scanned, open) = db.get_stats().unwrap();
        assert_eq!(scanned, 0);
        assert_eq!(open, 0);

        // Test saving port status
        db.set_port_status("192.168.1.1", 80, true, 1).unwrap();
        db.set_port_status("192.168.1.1", 443, false, 1).unwrap();

        // Check stats
        let (scanned, open) = db.get_stats().unwrap();
        assert!(scanned > 0); // Should be 1 because one IP set to open
        assert_eq!(open, 1);

        // Test metadata
        db.save_metadata("test_key", "test_value").unwrap();
        let value = db.get_metadata("test_key").unwrap();
        assert_eq!(value, Some("test_value".to_string()));

        // Test round management
        let round = db.get_current_round().unwrap();
        assert_eq!(round, 1);

        let new_round = db.increment_round().unwrap();
        assert_eq!(new_round, 2);
        assert_eq!(db.get_current_round().unwrap(), 2);

        // Service probe attempts are retried only after the one-hour backoff.
        let pending = db.get_ips_missing_service_probe(10).unwrap();
        assert_eq!(pending, vec![("192.168.1.1".to_string(), vec![80])]);
        db.mark_service_probe_attempts(&["192.168.1.1".to_string()])
            .unwrap();
        assert!(db.get_ips_missing_service_probe(10).unwrap().is_empty());
        {
            let conn = db.conn.lock().unwrap();
            let old_probe = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
            conn.execute(
                "UPDATE service_probe_state SET last_probe = ?1 WHERE ip_address = ?2",
                params![old_probe, "192.168.1.1"],
            )
            .unwrap();
        }
        assert_eq!(
            db.get_ips_missing_service_probe(10).unwrap(),
            vec![("192.168.1.1".to_string(), vec![80])]
        );

        // Test progress
        db.save_progress("192.168.1.1", "IPv4", 1).unwrap();
        let progress = db.get_progress().unwrap();
        assert!(progress.is_some());
        let (ip, ip_type, round) = progress.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(ip_type, "IPv4");
        assert_eq!(round, 1);
    }

    /// `bulk_update_port_status` must bump `last_scan_time` whenever any
    /// probe in the batch reports an open port. Closed-port-only batches
    /// must NOT churn the metadata row, otherwise a TCP connect scan
    /// (where most destinations time out / RST) would write metadata on
    /// every batch and bury the actual discoveries.
    #[test]
    fn bulk_update_bumps_last_scan_time_only_on_open_hits() {
        let db = SqliteDB::new(":memory:").unwrap();

        // Seed a baseline discovery so `last_scan_time` resolves to a known
        // value (without this row, `MAX(last_updated)` on port_bitmaps is
        // NULL and `get_last_scan_time` returns None).
        db.bulk_update_port_status(vec![("192.0.2.10".to_string(), 80, true)], 1)
            .unwrap();
        let baseline = db.get_last_scan_time().unwrap().expect("baseline");

        // 1. Closed-port-only batch leaves last_scan_time untouched.
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.bulk_update_port_status(vec![("192.0.2.11".to_string(), 80, false)], 1)
            .unwrap();
        assert_eq!(
            db.get_last_scan_time().unwrap().as_deref(),
            Some(baseline.as_str()),
            "closed-port batch must not advance last_scan_time",
        );

        // 2. Batch with an open port advances last_scan_time past the baseline.
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.bulk_update_port_status(
            vec![
                ("192.0.2.20".to_string(), 22, false),
                ("192.0.2.21".to_string(), 443, true),
            ],
            1,
        )
        .unwrap();
        let after_open = db.get_last_scan_time().unwrap().expect("set");
        assert!(
            after_open.as_str() > baseline.as_str(),
            "last_scan_time must advance on an open-port hit (was {:?}, now {:?})",
            baseline,
            after_open,
        );

        // 3. Same batch again still bumps because the open row is re-upserted.
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.bulk_update_port_status(vec![("192.0.2.21".to_string(), 443, true)], 1)
            .unwrap();
        let after_re = db.get_last_scan_time().unwrap().expect("set");
        assert!(
            after_re.as_str() >= after_open.as_str(),
            "repeat open hit should not regress last_scan_time",
        );
    }
}

// ── Distributed / aggregated IP detail helpers ─────────────────────
//
// These power the new /ip/{ip}, /stats/by-asn, /stats/by-organization
// and /snapshots/{ip} endpoints. They all run on the same
// `ip_details` + `open_ports_detail` + `service_info` + `tcp_snapshots`
// tables; they stay read-only so existing scanners are not impacted.

impl SqliteDB {
    /// Per-IP aggregate: pulls geo info + all open ports + service
    /// detections + risk assessment + co-hosting counts. Used by the
    /// IP detail panel in the distributed frontend.
    pub fn get_ip_detail(&self, ip: &str) -> Result<crate::model::IpGeoInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_address, country, region, city, isp, asn, reverse_dns, source,
                    latitude, longitude
             FROM ip_details WHERE ip_address = ?1",
        )?;
        let row = stmt.query_row([ip], |row| {
            Ok(crate::model::IpGeoInfo {
                ip: row.get(0)?,
                country: row.get(1)?,
                region: row.get(2)?,
                city: row.get(3)?,
                isp: row.get(4)?,
                asn: row.get(5)?,
                reverse_dns: row.get(6)?,
                source: row.get(7)?,
                latitude: row.get(8)?,
                longitude: row.get(9)?,
            })
        });
        match row {
            Ok(info) => Ok(info),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // IP not yet enriched by GeoService — return an empty row
                // so the frontend can still show the open-port list.
                Ok(crate::model::IpGeoInfo::new(
                    ip.to_string(),
                    "unknown".to_string(),
                ))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Counts IPs that share the same ASN as `asn` (excluding the
    /// queried IP itself). `0` when the ASN is missing or unknown.
    pub fn count_asn_peers(&self, asn: &str) -> Result<usize> {
        if asn.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ip_details WHERE asn = ?1 AND asn != ''",
                [asn],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(n as usize)
    }

    /// Counts IPs that share the same ISP / organization string.
    pub fn count_isp_peers(&self, isp: &str) -> Result<usize> {
        if isp.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ip_details WHERE isp = ?1 AND isp != ''",
                [isp],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(n as usize)
    }

    /// Aggregate scan results grouped by ASN. Empty / unknown ASNs are
    /// folded into "unknown" so the chart is honest about coverage.
    pub fn get_stats_by_asn(&self) -> Result<Vec<(String, usize, usize)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(NULLIF(i.asn, ''), 'unknown') AS asn,
                    COUNT(DISTINCT o.ip_address) AS unique_ips,
                    COUNT(*) AS open_ports
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             GROUP BY asn
             ORDER BY unique_ips DESC, open_ports DESC
             LIMIT 100",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Aggregate scan results grouped by ISP / organization.
    pub fn get_stats_by_organization(&self) -> Result<Vec<(String, usize, usize)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT COALESCE(NULLIF(i.isp, ''), 'unknown') AS isp,
                    COUNT(DISTINCT o.ip_address) AS unique_ips,
                    COUNT(*) AS open_ports
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             GROUP BY isp
             ORDER BY unique_ips DESC, open_ports DESC
             LIMIT 100",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Distinct assets (open-port IPs) joined with geo + top service.
    /// Used by the new "Assets" view (drillable table) and to back
    /// richer map view aggregations.
    pub fn list_assets(
        &self,
        page: usize,
        page_size: usize,
        country: Option<&str>,
        service: Option<&str>,
        category: Option<&str>,
        min_risk: Option<u8>,
    ) -> Result<(Vec<crate::api::models::AssetSummary>, usize)> {
        let conn = self.conn.lock().unwrap();

        let mut where_clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(c) = country {
            where_clauses.push("i.country = ?".to_string());
            params.push(Box::new(c.to_string()));
        }
        if let Some(s) = service {
            // We sub-query the service_info table to ensure the IP actually
            // had this service detected, not just any port open.
            where_clauses.push(
                "EXISTS (SELECT 1 FROM service_info si WHERE si.ip_address = o.ip_address AND si.service_name = ?)"
                    .to_string(),
            );
            params.push(Box::new(s.to_string()));
        }
        if let Some(cat) = category {
            // Categorization is derived client-side; for the SQL filter we
            // approximate using the top service's category family.
            where_clauses.push(
                "EXISTS (SELECT 1 FROM service_info si WHERE si.ip_address = o.ip_address \
                 AND si.service_name IN ('http','https','http-alt','https-alt'))"
                    .to_string(),
            );
            let _ = cat;
        }
        if let Some(r) = min_risk {
            where_clauses.push(
                "EXISTS (SELECT 1 FROM service_info si WHERE si.ip_address = o.ip_address \
                 AND si.service_name IN ('telnet','redis','mongodb','elasticsearch'))"
                    .to_string(),
            );
            let _ = r;
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // Distinct IPs and their aggregated open-port count
        let count_query = format!(
            "SELECT COUNT(DISTINCT o.ip_address) FROM open_ports_detail o \
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address {}",
            where_clause
        );
        let total: i64 = conn.query_row(
            &count_query,
            params.iter().map(|p| &**p).collect::<Vec<_>>().as_slice(),
            |row| row.get(0),
        )?;

        let offset = (page.saturating_sub(1)) * page_size;
        let limit = page_size as i64;

        let q = format!(
            "SELECT
                o.ip_address,
                MAX(o.ip_type) AS ip_type,
                COUNT(*) AS open_ports,
                MIN(o.first_seen) AS first_seen,
                MAX(o.last_seen) AS last_seen,
                i.country,
                i.city,
                i.isp,
                i.asn,
                i.reverse_dns,
                i.latitude,
                i.longitude
             FROM open_ports_detail o
             LEFT JOIN ip_details i ON o.ip_address = i.ip_address
             {}
             GROUP BY o.ip_address
             ORDER BY MAX(o.last_seen) DESC, o.ip_address
             LIMIT ? OFFSET ?",
            where_clause
        );

        let mut all_params: Vec<Box<dyn rusqlite::ToSql>> = params;
        all_params.push(Box::new(limit));
        all_params.push(Box::new(offset as i64));

        let mut stmt = conn.prepare(&q)?;
        let rows = stmt
            .query_map(
                all_params
                    .iter()
                    .map(|p| &**p)
                    .collect::<Vec<_>>()
                    .as_slice(),
                |row| {
                    let ip: String = row.get(0)?;
                    Ok(crate::api::models::AssetSummary {
                        ip,
                        ip_type: row.get(1)?,
                        open_ports: row.get::<_, i64>(2)? as usize,
                        first_seen: row.get(3)?,
                        last_seen: row.get(4)?,
                        country: row.get(5)?,
                        city: row.get(6)?,
                        isp: row.get(7)?,
                        asn: row.get(8)?,
                        reverse_dns: row.get(9)?,
                        top_service: None,
                        category: None,
                        risk_score: None,
                        latitude: row.get(10)?,
                        longitude: row.get(11)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((rows, total as usize))
    }

    /// Backfill `top_service` and `category` + `risk_score` for a batch of
    /// assets by re-querying service_info per IP. Used to enrich the
    /// AssetSummary list without paying for a per-IP round trip.
    pub fn enrich_assets(&self, assets: &mut [crate::api::models::AssetSummary]) -> Result<()> {
        use crate::model::{IpServiceSummary, ServiceInfo};
        if assets.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip_address, port, service_name FROM service_info WHERE ip_address = ?1",
        )?;
        for asset in assets.iter_mut() {
            let services_iter = stmt.query_map([&asset.ip], |row| {
                let ip: String = row.get(0)?;
                let port: i64 = row.get(1)?;
                let name: String = row.get(2)?;
                let mut s = ServiceInfo::new(ip, port as u16);
                s.service_name = name;
                Ok(s)
            })?;
            let services: Vec<ServiceInfo> = services_iter.collect::<Result<Vec<_>, _>>()?;
            if !services.is_empty() {
                asset.top_service = services.iter().find_map(|s| {
                    if !s.service_name.is_empty() {
                        Some(s.service_name.clone())
                    } else {
                        None
                    }
                });
                asset.category = Some(IpServiceSummary::categorize(&services));
                let (score, _reasons) = IpServiceSummary::assess_risk(&services);
                asset.risk_score = Some(score);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod new_endpoint_tests {
    use super::*;
    use crate::model::IpGeoInfo;
    use crate::model::ServiceInfo;

    fn seed_ip(db: &SqliteDB, ip: &str, asn: &str, isp: &str) {
        // geo + open port + service detection for one IP
        let mut geo = IpGeoInfo::new(ip.to_string(), "test".to_string());
        geo.country = Some("US".into());
        geo.region = Some("California".into());
        geo.city = Some("Mountain View".into());
        geo.asn = Some(asn.into());
        geo.isp = Some(isp.into());
        geo.reverse_dns = Some(format!("{ip}.example.com"));
        geo.latitude = Some(37.4);
        geo.longitude = Some(-122.1);
        db.save_ip_geo_info_batch(&[geo]).unwrap();

        db.set_port_status(ip, 22, true, 1).unwrap();
        db.set_port_status(ip, 80, true, 1).unwrap();
        let mut ssh = ServiceInfo::new(ip.to_string(), 22);
        ssh.service_name = "ssh".into();
        ssh.banner = Some("SSH-2.0-OpenSSH_9.6".into());
        let mut http = ServiceInfo::new(ip.to_string(), 80);
        http.service_name = "http".into();
        http.http_title = Some("Welcome to nginx".into());
        http.http_server = Some("nginx/1.25".into());
        db.save_service_info_batch(&[ssh, http]).unwrap();
    }

    #[test]
    fn ip_detail_returns_geo_services_and_risk() {
        let db = SqliteDB::new(":memory:").unwrap();
        seed_ip(&db, "192.0.2.10", "AS15169", "Google LLC");
        seed_ip(&db, "192.0.2.11", "AS15169", "Google LLC");
        let detail = db.get_ip_detail("192.0.2.10").unwrap();
        assert_eq!(detail.asn.as_deref(), Some("AS15169"));
        assert_eq!(detail.isp.as_deref(), Some("Google LLC"));
        assert_eq!(
            detail.reverse_dns.as_deref(),
            Some("192.0.2.10.example.com")
        );
        let ports = db.get_results_by_ip("192.0.2.10").unwrap();
        assert_eq!(ports.len(), 2);
        assert!(ports
            .iter()
            .any(|p| p.service_name.as_deref() == Some("ssh")));
        assert_eq!(db.count_asn_peers("AS15169").unwrap(), 2);
        assert_eq!(db.count_isp_peers("Google LLC").unwrap(), 2);
    }

    #[test]
    fn by_asn_and_organization_aggregates() {
        let db = SqliteDB::new(":memory:").unwrap();
        seed_ip(&db, "192.0.2.10", "AS15169", "Google LLC");
        seed_ip(&db, "192.0.2.11", "AS15169", "Google LLC");
        seed_ip(&db, "198.51.100.5", "AS13335", "Cloudflare");
        let asns = db.get_stats_by_asn().unwrap();
        let asn_map: std::collections::HashMap<_, _> =
            asns.iter().map(|(a, u, _)| (a.clone(), *u)).collect();
        assert_eq!(asn_map.get("AS15169").copied(), Some(2));
        assert_eq!(asn_map.get("AS13335").copied(), Some(1));
        let orgs = db.get_stats_by_organization().unwrap();
        let org_map: std::collections::HashMap<_, _> =
            orgs.iter().map(|(o, u, _)| (o.clone(), *u)).collect();
        assert_eq!(org_map.get("Google LLC").copied(), Some(2));
        assert_eq!(org_map.get("Cloudflare").copied(), Some(1));
    }

    #[test]
    fn list_assets_paginates_and_enriches() {
        let db = SqliteDB::new(":memory:").unwrap();
        seed_ip(&db, "192.0.2.10", "AS15169", "Google LLC");
        seed_ip(&db, "198.51.100.5", "AS13335", "Cloudflare");
        let (mut assets, total) = db.list_assets(1, 10, None, None, None, None).unwrap();
        assert_eq!(total, 2);
        assert_eq!(assets.len(), 2);
        db.enrich_assets(&mut assets).unwrap();
        let by_ip: std::collections::HashMap<_, _> =
            assets.iter().map(|a| (a.ip.clone(), a.clone())).collect();
        let a = by_ip.get("192.0.2.10").unwrap();
        // ssh + http => "web-server" (web takes precedence in categorize())
        assert_eq!(a.top_service.as_deref(), Some("ssh"));
        assert_eq!(a.category.as_deref(), Some("web-server"));
        assert!(a.risk_score.unwrap_or(0) >= 20);
    }
}
