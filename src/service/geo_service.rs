use crate::model::IpGeoInfo;
use anyhow::{Context, Result};
use maxminddb::geoip2;
use regex::Regex;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use whois_rust::{WhoIs, WhoIsLookupOptions};

#[derive(Clone)]
pub struct GeoService {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    whois: Option<Arc<WhoIs>>,
}

impl GeoService {
    pub fn new(db_path: Option<&str>) -> Self {
        let reader = db_path.and_then(|path| match maxminddb::Reader::open_readfile(path) {
            Ok(reader) => Some(Arc::new(reader)),
            Err(e) => {
                eprintln!("Failed to open GeoIP database at {}: {}", path, e);
                None
            }
        });

        let whois = match WhoIs::from_string(include_str!("../../servers.json")) {
            Ok(w) => Some(Arc::new(w)),
            Err(_) => {
                eprintln!("Warning: No servers.json found for Whois. Whois lookup might fail.");
                None
            }
        };

        Self { reader, whois }
    }

    pub async fn lookup(&self, ip: &str) -> Result<IpGeoInfo> {
        let mut info = self.lookup_geo_only(ip).await?;

        let reverse = crate::service::reverse_dns_lookup(ip).await;
        info.reverse_dns = reverse;

        Ok(info)
    }

    async fn lookup_geo_only(&self, ip: &str) -> Result<IpGeoInfo> {
        if let Some(reader) = &self.reader {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                let lookup_result = reader.lookup(addr);
                if let Ok(lr) = lookup_result {
                    if lr.has_data() {
                        if let Ok(Some(city)) = lr.decode::<geoip2::City>() {
                            let mut info = IpGeoInfo::new(ip.to_string(), "MaxMind".to_string());

                            if !city.country.names.is_empty() {
                                info.country =
                                    city.country.names.english.map(|s: &str| s.to_string());
                            }
                            if let Some(sub) = city.subdivisions.first() {
                                if !sub.names.is_empty() {
                                    info.region = sub.names.english.map(|s: &str| s.to_string());
                                }
                            }
                            if !city.city.names.is_empty() {
                                info.city = city.city.names.english.map(|s: &str| s.to_string());
                            }

                            return Ok(info);
                        }
                    }
                }
            }
        }

        if let Some(whois) = &self.whois {
            if let Ok(info) = Self::fetch_from_whois(whois, ip).await {
                return Ok(info);
            }
        }

        Self::fetch_from_api(ip).await
    }

    async fn fetch_from_whois(whois: &WhoIs, ip: &str) -> Result<IpGeoInfo> {
        let options = WhoIsLookupOptions::from_string(ip)?;
        let ip_string = ip.to_string();
        let whois_clone = whois.clone();

        let text = tokio::task::spawn_blocking(move || whois_clone.lookup(options)).await??;

        let mut info = IpGeoInfo::new(ip_string, "Whois".to_string());

        let re_country = Regex::new(r"(?mi)^(?:Country|country):\s*([a-zA-Z]{2})").unwrap();
        if let Some(caps) = re_country.captures(&text) {
            info.country = Some(caps[1].trim().to_string());
        }

        let re_city = Regex::new(r"(?mi)^City:\s*(.+)").unwrap();
        if let Some(caps) = re_city.captures(&text) {
            info.city = Some(caps[1].trim().to_string());
        }

        let re_org = Regex::new(r"(?mi)^(?:OrgName|descr|role|netname):\s*(.+)").unwrap();
        if let Some(caps) = re_org.captures(&text) {
            info.isp = Some(caps[1].trim().to_string());
        }

        let re_asn = Regex::new(r"(?mi)^(?:OriginAS|origin):\s*(AS\d+)").unwrap();
        if let Some(caps) = re_asn.captures(&text) {
            info.asn = Some(caps[1].trim().to_string());
        }

        Ok(info)
    }

    async fn fetch_from_api(ip: &str) -> Result<IpGeoInfo> {
        let url = format!("http://ip-api.com/json/{}", ip);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        let resp = client
            .get(&url)
            .send()
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
        let result = service.lookup("8.8.8.8").await;

        match result {
            Ok(info) => {
                println!("Geo Info: {:?}", info);
                assert_eq!(info.ip, "8.8.8.8");
                assert_eq!(info.source, "API (ip-api.com)");
                assert!(info.country.is_some());
            }
            Err(e) => {
                eprintln!("API lookup failed: {}", e);
            }
        }
    }
}
