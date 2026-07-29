use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoInfo {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub asn: Option<String>,
    pub reverse_dns: Option<String>,
    pub source: String,
    /// Latitude in decimal degrees, when the geo source provided it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    /// Longitude in decimal degrees, when the geo source provided it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
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
            reverse_dns: None,
            source,
            latitude: None,
            longitude: None,
        }
    }

    pub fn with_coordinates(mut self, latitude: f64, longitude: f64) -> Self {
        self.latitude = Some(latitude);
        self.longitude = Some(longitude);
        self
    }
}
