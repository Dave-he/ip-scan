use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

impl IpRange {
    pub fn new(start: &str, end: &str) -> Result<Self, String> {
        let start_ip = IpAddr::from_str(start).map_err(|e| format!("Invalid start IP: {}", e))?;
        let end_ip = IpAddr::from_str(end).map_err(|e| format!("Invalid end IP: {}", e))?;

        if std::mem::discriminant(&start_ip) != std::mem::discriminant(&end_ip) {
            return Err("Start and end IP must be the same version".to_string());
        }

        Ok(IpRange {
            start: start_ip,
            end: end_ip,
        })
    }

    pub fn from_cidr(cidr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format, expected e.g. 192.168.1.0/24".to_string());
        }

        let ip: IpAddr = parts[0].parse().map_err(|e| format!("Invalid IP in CIDR: {}", e))?;
        let prefix_len: u8 = parts[1].parse().map_err(|e| format!("Invalid prefix length: {}", e))?;

        match ip {
            IpAddr::V4(ipv4) => {
                if prefix_len > 32 {
                    return Err("IPv4 prefix length must be 0-32".to_string());
                }
                let mask: u32 = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                let network = u32::from(ipv4) & mask;
                let broadcast = network | !mask;
                Ok(IpRange {
                    start: IpAddr::V4(Ipv4Addr::from(network)),
                    end: IpAddr::V4(Ipv4Addr::from(broadcast)),
                })
            }
            IpAddr::V6(ipv6) => {
                if prefix_len > 128 {
                    return Err("IPv6 prefix length must be 0-128".to_string());
                }
                let mask: u128 = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
                let network = u128::from(ipv6) & mask;
                let broadcast = network | !mask;
                Ok(IpRange {
                    start: IpAddr::V6(Ipv6Addr::from(network)),
                    end: IpAddr::V6(Ipv6Addr::from(broadcast)),
                })
            }
        }
    }

    pub fn parse_target(target: &str) -> Result<Self, String> {
        if target.contains('/') {
            Self::from_cidr(target)
        } else if target.contains('-') && !target.contains(':') {
            let parts: Vec<&str> = target.splitn(2, '-').collect();
            if parts.len() == 2 {
                let start = parts[0].trim();
                let end = parts[1].trim();
                if let Ok(start_ip) = start.parse::<IpAddr>() {
                    if let Ok(end_ip) = end.parse::<IpAddr>() {
                        return Ok(IpRange { start: start_ip, end: end_ip });
                    }
                    if let Some(_start_octets) = extract_last_octet(start) {
                        let prefix = start.rsplit_once('.').map(|(p, _)| p).unwrap_or(start);
                        let full_end = format!("{}.{}", prefix, end);
                        if let Ok(end_ip) = full_end.parse::<IpAddr>() {
                            return Ok(IpRange { start: start_ip, end: end_ip });
                        }
                    }
                }
                Err(format!("Invalid IP range: {}", target))
            } else {
                Err(format!("Invalid IP range: {}", target))
            }
        } else {
            let ip: IpAddr = target.parse().map_err(|e| format!("Invalid IP: {}", e))?;
            Ok(IpRange {
                start: ip,
                end: ip,
            })
        }
    }

    pub fn iter(&self) -> IpIterator {
        IpIterator::new(self.start, self.end)
    }

    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        match (self.start, self.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                (u32::from(e).saturating_sub(u32::from(s)) + 1) as usize
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                (u128::from(e).saturating_sub(u128::from(s)) + 1) as usize
            }
            _ => 0,
        }
    }
}

fn extract_last_octet(ip: &str) -> Option<u8> {
    ip.rsplit('.').next().and_then(|s| s.parse().ok())
}

pub struct IpIterator {
    current: IpAddr,
    end: IpAddr,
    finished: bool,
}

impl IpIterator {
    fn new(start: IpAddr, end: IpAddr) -> Self {
        IpIterator {
            current: start,
            end,
            finished: false,
        }
    }

    fn increment_ipv4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let num = u32::from(ip);
        if num == u32::MAX {
            None
        } else {
            Some(Ipv4Addr::from(num + 1))
        }
    }

    fn increment_ipv6(ip: Ipv6Addr) -> Option<Ipv6Addr> {
        let num = u128::from(ip);
        if num == u128::MAX {
            None
        } else {
            Some(Ipv6Addr::from(num + 1))
        }
    }
}

impl Iterator for IpIterator {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let result = self.current;

        if self.current == self.end {
            self.finished = true;
            return Some(result);
        }

        match self.current {
            IpAddr::V4(ipv4) => {
                if let Some(next) = Self::increment_ipv4(ipv4) {
                    self.current = IpAddr::V4(next);
                } else {
                    self.finished = true;
                }
            }
            IpAddr::V6(ipv6) => {
                if let Some(next) = Self::increment_ipv6(ipv6) {
                    self.current = IpAddr::V6(next);
                } else {
                    self.finished = true;
                }
            }
        }

        Some(result)
    }
}

pub fn parse_port_range(range: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();

    for part in range.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.contains('-') {
            let parts: Vec<&str> = part.split('-').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid port range: {}", part));
            }
            let start: u16 = parts[0]
                .parse()
                .map_err(|_| format!("Invalid start port: {}", parts[0]))?;
            let end: u16 = parts[1]
                .parse()
                .map_err(|_| format!("Invalid end port: {}", parts[1]))?;

            if start > end {
                return Err(format!("Start port must be <= end port: {}-{}", start, end));
            }

            ports.extend(start..=end);
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| format!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }

    ports.sort();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_range_ipv4() {
        let range = IpRange::new("192.168.1.1", "192.168.1.5").unwrap();
        let ips: Vec<IpAddr> = range.iter().collect();
        assert_eq!(ips.len(), 5);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
        assert_eq!(ips[4].to_string(), "192.168.1.5");
    }

    #[test]
    fn test_ip_range_ipv6() {
        let range = IpRange::new("2001:db8::1", "2001:db8::5").unwrap();
        let ips: Vec<IpAddr> = range.iter().collect();
        assert_eq!(ips.len(), 5);
        assert_eq!(ips[0].to_string(), "2001:db8::1");
        assert_eq!(ips[4].to_string(), "2001:db8::5");
    }

    #[test]
    fn test_invalid_range() {
        assert!(IpRange::new("192.168.1.1", "2001:db8::1").is_err());
    }

    #[test]
    fn test_single_ip() {
        let range = IpRange::new("192.168.1.1", "192.168.1.1").unwrap();
        let ips: Vec<IpAddr> = range.iter().collect();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_cidr_ipv4() {
        let range = IpRange::from_cidr("192.168.1.0/24").unwrap();
        assert_eq!(range.start.to_string(), "192.168.1.0");
        assert_eq!(range.end.to_string(), "192.168.1.255");
        assert_eq!(range.count(), 256);
    }

    #[test]
    fn test_cidr_ipv4_small() {
        let range = IpRange::from_cidr("10.0.0.100/30").unwrap();
        assert_eq!(range.start.to_string(), "10.0.0.100");
        assert_eq!(range.end.to_string(), "10.0.0.103");
        assert_eq!(range.count(), 4);
    }

    #[test]
    fn test_cidr_single_host() {
        let range = IpRange::from_cidr("192.168.1.1/32").unwrap();
        assert_eq!(range.count(), 1);
    }

    #[test]
    fn test_parse_target_cidr() {
        let range = IpRange::parse_target("192.168.1.0/24").unwrap();
        assert_eq!(range.count(), 256);
    }

    #[test]
    fn test_parse_target_single() {
        let range = IpRange::parse_target("192.168.1.1").unwrap();
        assert_eq!(range.count(), 1);
    }

    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("80").unwrap(), vec![80]);
        assert_eq!(parse_port_range("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_port_range("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_port_range("80,443,8080-8082").unwrap(), vec![80, 443, 8080, 8081, 8082]);
        assert!(parse_port_range("1-").is_err());
        assert!(parse_port_range("a").is_err());
        assert!(parse_port_range("5-1").is_err());
    }

    #[test]
    fn test_count() {
        let range = IpRange::new("192.168.1.1", "192.168.1.10").unwrap();
        assert_eq!(range.count(), 10);
    }
}
