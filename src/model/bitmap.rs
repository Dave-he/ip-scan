use anyhow::Result;

const SEGMENT_SIZE: usize = 2 * 1024 * 1024; // 2MB per segment (16,777,216 IPs)

pub struct PortBitmap {
    segments: std::collections::HashMap<u32, Vec<u8>>,
}

impl PortBitmap {
    pub fn new() -> Self {
        PortBitmap {
            segments: std::collections::HashMap::new(),
        }
    }

    pub fn from_blob(data: &[u8]) -> Result<Self> {
        // Deserialize from database blob
        let segments: std::collections::HashMap<u32, Vec<u8>> = bincode::deserialize(data)?;
        Ok(PortBitmap { segments })
    }

    pub fn to_blob(&self) -> Result<Vec<u8>> {
        // Serialize to database blob
        Ok(bincode::serialize(&self.segments)?)
    }

    fn get_segment_and_offset(ip_index: u32) -> (u32, u32) {
        let segment_id = ip_index >> 24; // High 8 bits
        let bit_offset = ip_index & 0xFFFFFF; // Low 24 bits
        (segment_id, bit_offset)
    }

    pub fn set(&mut self, ip_index: u32, value: bool) {
        let (segment_id, bit_offset) = Self::get_segment_and_offset(ip_index);

        let segment = self
            .segments
            .entry(segment_id)
            .or_insert_with(|| vec![0u8; SEGMENT_SIZE]);

        let byte_index = (bit_offset / 8) as usize;
        let bit_index = (bit_offset % 8) as u8;

        if value {
            segment[byte_index] |= 1 << bit_index;
        } else {
            segment[byte_index] &= !(1 << bit_index);
        }
    }

    #[allow(dead_code)]
    pub fn get(&self, ip_index: u32) -> bool {
        let (segment_id, bit_offset) = Self::get_segment_and_offset(ip_index);

        if let Some(segment) = self.segments.get(&segment_id) {
            let byte_index = (bit_offset / 8) as usize;
            let bit_index = (bit_offset % 8) as u8;
            (segment[byte_index] & (1 << bit_index)) != 0
        } else {
            false
        }
    }

    pub fn count_ones(&self) -> usize {
        self.segments
            .values()
            .map(|segment| {
                segment
                    .iter()
                    .map(|byte| byte.count_ones() as usize)
                    .sum::<usize>()
            })
            .sum()
    }
}

pub fn ipv4_to_index(ip: &str) -> Result<u32> {
    let addr: std::net::Ipv4Addr = ip.parse()?;
    Ok(u32::from(addr))
}

#[allow(dead_code)]
pub fn index_to_ipv4(index: u32) -> String {
    std::net::Ipv4Addr::from(index).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_operations() {
        let mut bitmap = PortBitmap::new();

        // Test set and get
        bitmap.set(100, true);
        assert!(bitmap.get(100));
        assert!(!bitmap.get(101));

        bitmap.set(100, false);
        assert!(!bitmap.get(100));
    }

    #[test]
    fn test_ip_conversion() {
        let ip = "192.168.1.100";
        let index = ipv4_to_index(ip).unwrap();
        let converted = index_to_ipv4(index);
        assert_eq!(ip, converted);
    }

    #[test]
    fn test_count_ones() {
        let mut bitmap = PortBitmap::new();
        bitmap.set(1, true);
        bitmap.set(100, true);
        bitmap.set(1000, true);
        assert_eq!(bitmap.count_ones(), 3);
    }

    #[test]
    fn test_serialization() {
        let mut bitmap = PortBitmap::new();
        bitmap.set(100, true);
        bitmap.set(200, true);

        let blob = bitmap.to_blob().unwrap();
        let restored = PortBitmap::from_blob(&blob).unwrap();

        assert!(restored.get(100));
        assert!(restored.get(200));
        assert!(!restored.get(300));
    }
}
