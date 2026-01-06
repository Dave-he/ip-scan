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

    pub fn iter(&self) -> IpIterator {
        IpIterator::new(self.start, self.end)
    }
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
    if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            return Err("Invalid port range format".to_string());
        }

        let start: u16 = parts[0]
            .parse()
            .map_err(|_| "Invalid start port".to_string())?;
        let end: u16 = parts[1]
            .parse()
            .map_err(|_| "Invalid end port".to_string())?;

        if start > end {
            return Err("Start port must be less than or equal to end port".to_string());
        }

        Ok((start..=end).collect())
    } else if range.contains(',') {
        range
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<u16>()
                    .map_err(|_| format!("Invalid port: {}", s))
            })
            .collect()
    } else {
        let port: u16 = range
            .parse()
            .map_err(|_| "Invalid port number".to_string())?;
        Ok(vec![port])
    }
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
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("80").unwrap(), vec![80]);
        assert_eq!(parse_port_range("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_port_range("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert!(parse_port_range("1-").is_err());
        assert!(parse_port_range("a").is_err());
        assert!(parse_port_range("5-1").is_err());
    }
}
