use std::collections::HashMap;
use anyhow::Result;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};
use chrono::Utc;
use crate::bitmap::{PortBitmap, ipv4_to_index};

#[derive(Clone)]
pub struct BitmapDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl BitmapDatabase {
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

        // Optimization: Set WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        Ok(BitmapDatabase {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    #[allow(dead_code)]
    pub fn set_port_status(&self, ip: &str, port: u16, is_open: bool, scan_round: i64) -> Result<()> {
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

    pub fn bulk_update_port_status(&self, updates: Vec<(String, u16, bool)>, scan_round: i64) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let transaction = conn.transaction()?;

        // Group by port to minimize bitmap loads/saves
        let mut updates_by_port: HashMap<u16, Vec<(u32, bool, String)>> = HashMap::new();
        
        for (ip, port, is_open) in updates {
            match ipv4_to_index(&ip) {
                Ok(ip_index) => {
                    updates_by_port.entry(port)
                        .or_default()
                        .push((ip_index, is_open, ip));
                },
                Err(_) => continue, // Skip invalid IPs
            }
        }

        for (port, items) in updates_by_port {
            // 1. Update Bitmap
            let mut bitmap = self.get_port_bitmap_internal(&transaction, port, "IPv4", scan_round)?;
            
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

        transaction.commit()?;
        Ok(())
    }

    fn get_port_bitmap_internal(&self, conn: &Connection, port: u16, ip_type: &str, scan_round: i64) -> Result<PortBitmap> {
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
        
        let total_scanned: i64 = conn.query_row(
            "SELECT COALESCE(SUM(open_count), 0) FROM port_bitmaps",
            [],
            |row| row.get(0)
        )?;

        let unique_open: usize = conn.query_row(
            "SELECT COUNT(*) FROM open_ports_detail",
            [],
            |row| row.get(0)
        )?;

        Ok((total_scanned as usize, unique_open))
    }

    pub fn get_stats_by_port(&self, scan_round: i64) -> Result<Vec<(u16, usize)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT port, open_count FROM port_bitmaps WHERE scan_round = ?1 ORDER BY open_count DESC"
        )?;
        
        let stats = stmt.query_map([scan_round], |row| {
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
            |row| row.get(0)
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
            (Some(ip), Some(ip_type), Some(round)) => {
                Ok(Some((ip, ip_type, round.parse()?)))
            }
            _ => Ok(None),
        }
    }

    pub fn get_memory_usage(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(bitmap)), 0) FROM port_bitmaps",
            [],
            |row| row.get(0)
        )?;
        Ok(size as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_operations() {
        // Use in-memory database for testing
        let db = BitmapDatabase::new(":memory:").unwrap();
        
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
        
        // Test progress
        db.save_progress("192.168.1.1", "IPv4", 1).unwrap();
        let progress = db.get_progress().unwrap();
        assert!(progress.is_some());
        let (ip, ip_type, round) = progress.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(ip_type, "IPv4");
        assert_eq!(round, 1);
    }
}
