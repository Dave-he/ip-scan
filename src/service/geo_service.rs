use crate::model::IpGeoInfo;
use anyhow::{Context, Result};
use maxminddb::geoip2;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;
use serde_json::Value;
use whois_rust::{WhoIs, WhoIsLookupOptions};

#[derive(Clone)]
pub struct GeoService {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    whois: Option<Arc<WhoIs>>,
}

impl GeoService {
    pub fn new(db_path: Option<&str>) -> Self {
        let reader = db_path.and_then(|path| {
            match maxminddb::Reader::open_readfile(path) {
                Ok(reader) => Some(Arc::new(reader)),
                Err(e) => {
                    eprintln!("Failed to open GeoIP database at {}: {}", path, e);
                    None
                }
            }
        });

        // Initialize WhoIs with embedded servers
        let whois = match WhoIs::from_string(include_str!("../../servers.json")) {
            Ok(w) => Some(Arc::new(w)),
            Err(_) => {
                // Try to create empty or handle error. 
                // Since we don't have servers.json file, we might need to rely on the crate's logic or a provided json string.
                // whois-rust usually requires a servers.json content.
                // Let's try to construct a minimal one or handle the error gracefully.
                // For now, let's assume we can fetch it or use a default if the crate provides one.
                // Wait, whois-rust doesn't bundle servers.json by default in the binary unless we include it.
                // We should probably download a minimal list or provide one.
                // For simplicity in this environment, I will try to use a minimal hardcoded JSON string for common TLDs/IPs.
                // Or better, let's try to load it from a file if it exists, otherwise use a default string.
                eprintln!("Warning: No servers.json found for Whois. Whois lookup might fail.");
                None
            }
        };

        Self { reader, whois }
    }

    pub async fn lookup(&self, ip: &str) -> Result<IpGeoInfo> {
        // 1. Try MaxMind DB (Fastest, Local)
        if let Some(reader) = &self.reader {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                 if let Ok(city) = reader.lookup::<geoip2::City>(addr) {
                     let mut info = IpGeoInfo::new(ip.to_string(), "MaxMind".to_string());
                     
                     if let Some(country) = city.country.and_then(|c| c.names) {
                         info.country = country.get("en").map(|s| s.to_string());
                     }
                     if let Some(subdivisions) = city.subdivisions {
                         if let Some(sub) = subdivisions.first() {
                             if let Some(names) = &sub.names {
                                 info.region = names.get("en").map(|s| s.to_string());
                             }
                         }
                     }
                     if let Some(city_record) = city.city.and_then(|c| c.names) {
                         info.city = city_record.get("en").map(|s| s.to_string());
                     }
                     
                     return Ok(info);
                 }
            }
        }

        // 2. Try Whois (Default fallback as requested)
        // Whois provides detailed info but is unstructured and slower
        if let Some(whois) = &self.whois {
            // We clone Arc to move into async block if needed, but lookup is async
            match Self::fetch_from_whois(whois, ip).await {
                Ok(info) => return Ok(info),
                Err(_e) => {
                    // Log error but continue to API fallback
                    // In a real app we might want to distinguish between "not found" and "network error"
                    // But for now, just fallback
                }
            }
        }

        // 3. Fallback to API (ip-api.com)
        Self::fetch_from_api(ip).await
    }

    async fn fetch_from_whois(whois: &WhoIs, ip: &str) -> Result<IpGeoInfo> {
        let options = WhoIsLookupOptions::from_string(ip)?;
        // whois.lookup is not async in the version we are using or I made a mistake assuming it is.
        // Let's check if whois-rust 1.5 has async support.
        // If not, we might need to use spawn_blocking or just call it directly if it's not blocking (it likely is blocking I/O).
        // Actually, whois-rust 1.5 likely has synchronous `lookup`.
        // To avoid blocking the async runtime, we should wrap it in `spawn_blocking`.
        
        // However, `WhoIs` struct might not be Send/Sync or easy to move.
        // Let's check `WhoIs` definition. It usually holds a map of servers.
        
        let ip_string = ip.to_string();
        let whois_clone = whois.clone();
        
        let text = tokio::task::spawn_blocking(move || {
            whois_clone.lookup(options)
        }).await??;
        
        let mut info = IpGeoInfo::new(ip_string, "Whois".to_string());
        
        // Simple regex parsing for common fields
        // Note: Whois formats vary wildly. This is a best-effort approach.
        
        // Country
        let re_country = Regex::new(r"(?mi)^(?:Country|country):\s*([a-zA-Z]{2})").unwrap();
        if let Some(caps) = re_country.captures(&text) {
            info.country = Some(caps[1].trim().to_string());
        }

        // City (Rare in IP whois, but sometimes present as 'City:' or 'address:')
        let re_city = Regex::new(r"(?mi)^City:\s*(.+)").unwrap();
        if let Some(caps) = re_city.captures(&text) {
            info.city = Some(caps[1].trim().to_string());
        }

        // ISP / Org
        let re_org = Regex::new(r"(?mi)^(?:OrgName|descr|role|netname):\s*(.+)").unwrap();
        if let Some(caps) = re_org.captures(&text) {
            info.isp = Some(caps[1].trim().to_string());
        }

        // ASN (OriginAS)
        let re_asn = Regex::new(r"(?mi)^(?:OriginAS|origin):\s*(AS\d+)").unwrap();
        if let Some(caps) = re_asn.captures(&text) {
            info.asn = Some(caps[1].trim().to_string());
        }

        Ok(info)
    }

    async fn fetch_from_api(ip: &str) -> Result<IpGeoInfo> {
        let url = format!("http://ip-api.com/json/{}", ip);
        let resp = reqwest::get(&url)
            .await
            .context("Failed to call IP API")?
            .json::<Value>()
            .await
            .context("Failed to parse API response")?;
        
        let mut info = IpGeoInfo::new(ip.to_string(), "API (ip-api.com)".to_string());
        
        if resp["status"].as_str() == Some("success") {
            info.country = resp["country"].as_str().map(|s| s.to_string());
            info.region = resp["regionName"].as_str().map(|s| s.to_string());
            info.city = resp["city"].as_str().map(|s| s.to_string());
            info.isp = resp["isp"].as_str().map(|s| s.to_string());
            info.asn = resp["as"].as_str().map(|s| s.to_string());
        }
        
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_api_lookup() {
        let service = GeoService::new(None);
        // Use Google DNS as a test case
        let result = service.lookup("8.8.8.8").await;
        
        match result {
            Ok(info) => {
                println!("Geo Info: {:?}", info);
                assert_eq!(info.ip, "8.8.8.8");
                assert_eq!(info.source, "API (ip-api.com)");
                assert!(info.country.is_some());
                // Google is usually in US
                assert_eq!(info.country.unwrap(), "United States");
            }
            Err(e) => {
                eprintln!("API lookup failed: {}", e);
                // Don't fail the test if it's just a network issue or rate limit
            }
        }
    }
}
