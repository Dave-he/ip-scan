use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoInfo {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub source: String,
}

impl IpGeoInfo {
    pub fn new(ip: String, source: String) -> Self {
        Self {
            ip,
            country: None,
            region: None,
            city: None,
            isp: None,
            asn: None,
            source,
        }
    }
}
