use anyhow::{anyhow, Result};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
#[cfg(target_os = "windows")]
use pnet_transport as transport;
#[cfg(not(target_os = "windows"))]
use pnet_transport::{self as transport, TransportChannelType, TransportProtocol};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info};

#[cfg(target_os = "windows")]
use pnet_datalink::{self as datalink, Channel, MacAddr};

#[cfg(target_os = "windows")]
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

#[cfg(target_os = "windows")]
use pnet_packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};

#[cfg(target_os = "windows")]
use pnet_packet::MutablePacket;

#[cfg(target_os = "windows")]
use regex::Regex;

#[cfg(target_os = "windows")]
use std::process::Command;

/// Result of a ping sweep
#[derive(Debug, Clone)]
pub struct PingResult {
    pub ip: Ipv4Addr,
    pub alive: bool,
    pub latency_ms: u64,
}

/// High-performance Ping Sweep Scanner for host discovery
pub struct PingScanner {
    rate_limiter: super::RateLimiter,
    active_hosts: Arc<Mutex<HashMap<Ipv4Addr, bool>>>,
    total_probes: Arc<AtomicUsize>,
    alive_hosts: Arc<AtomicUsize>,
    source_ip_cache: Arc<HashMap<Ipv4Addr, Ipv4Addr>>,
    default_source_ip: Ipv4Addr,
}

impl PingScanner {
    pub fn new(
        max_rate: u64,
        rate_window_secs: u64,
    ) -> Result<Self> {
        let rate_limiter =
            super::RateLimiter::new(max_rate as usize, Duration::from_secs(rate_window_secs));

        // Pre-build source IP cache
        let (source_ip_cache, default_source_ip) = Self::build_source_ip_cache();

        info!("Initializing Ping scanner");

        let active_hosts = Arc::new(Mutex::new(HashMap::new()));
        let active_hosts_clone = active_hosts.clone();

        // Spawn receiver thread
        #[cfg(not(target_os = "windows"))]
        {
            let protocol =
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
            let (_tx, mut rx) = match transport::transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to create raw socket for ping response: {}",
                        e
                    ))
                }
            };

            thread::spawn(move || {
                let mut iter = transport::ipv4_packet_iter(&mut rx);
                loop {
                    match iter.next() {
                        Ok((packet, _addr)) => {
                            if let Some(tcp) = TcpPacket::new(packet.payload()) {
                                // Accept SYN-ACK (open) or RST (host alive but port closed)
                                let flags = tcp.get_flags();
                                if flags & (TcpFlags::SYN | TcpFlags::ACK)
                                    == (TcpFlags::SYN | TcpFlags::ACK)
                                    || flags & TcpFlags::RST == TcpFlags::RST
                                {
                                    let src_ip = packet.get_source();
                                    if let IpAddr::V4(ipv4) = src_ip {
                                        debug!("Host alive: {}", ipv4);
                                        if let Ok(mut hosts) = active_hosts_clone.lock() {
                                            hosts.insert(ipv4, true);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Ping raw socket read error: {}", e);
                            break;
                        }
                    }
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            let (_gateway_ip, _gateway_mac, interface_ip) = Self::get_gateway_info_windows()
                .map_err(|e| {
                    anyhow!(
                        "Failed to get gateway info: {}. Make sure Npcap is installed.",
                        e
                    )
                })?;

            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| {
                    iface
                        .ips
                        .iter()
                        .any(|ip| ip.ip() == IpAddr::V4(interface_ip))
                })
                .ok_or(anyhow!(
                    "Could not find network interface for IP {}",
                    interface_ip
                ))?;

            let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(anyhow!("Unhandled channel type")),
                Err(e) => return Err(anyhow!("Failed to create datalink channel: {}", e)),
            };

            let active_hosts_rx = active_hosts.clone();
            let if_ip = interface_ip;
            thread::spawn(move || loop {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(frame) = EthernetPacket::new(packet) {
                            if frame.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(ip_header) = Ipv4Packet::new(frame.payload()) {
                                    if ip_header.get_next_level_protocol()
                                        == IpNextHeaderProtocols::Tcp
                                    {
                                        if let Some(tcp) = TcpPacket::new(ip_header.payload()) {
                                            let flags = tcp.get_flags();
                                            let is_alive = flags & (TcpFlags::SYN | TcpFlags::ACK)
                                                == (TcpFlags::SYN | TcpFlags::ACK)
                                                || flags & TcpFlags::RST == TcpFlags::RST;

                                            if is_alive
                                                && ip_header.get_destination() == if_ip
                                            {
                                                let src_ip = ip_header.get_source();
                                                if let IpAddr::V4(ipv4) = src_ip {
                                                    debug!("Host alive: {}", ipv4);
                                                    if let Ok(mut hosts) =
                                                        active_hosts_rx.lock()
                                                    {
                                                        hosts.insert(ipv4, true);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Ping datalink read error: {}", e);
                    }
                }
            });
        }

        Ok(PingScanner {
            rate_limiter,
            active_hosts,
            total_probes: Arc::new(AtomicUsize::new(0)),
            alive_hosts: Arc::new(AtomicUsize::new(0)),
            source_ip_cache,
            default_source_ip,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn send_one_syn_ping(
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_ip: Ipv4Addr,
        rng: &mut rand::rngs::ThreadRng,
    ) {
        // Use a temporary transport for ping
        if let Ok((mut tx, _rx)) = transport::transport_channel(
            4096,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        ) {
            let mut buf = [0u8; 20];
            if let Ok(mut tcp_packet) = MutableTcpPacket::new(&mut buf).ok_or(anyhow!("Failed")) {
                let src_port = rng.gen_range(33434..=33534); // Identifiable port range
                tcp_packet.set_source(src_port);
                tcp_packet.set_destination(dst_port);
                tcp_packet.set_sequence(rng.gen());
                tcp_packet.set_acknowledgement(0);
                tcp_packet.set_flags(TcpFlags::SYN);
                tcp_packet.set_window(64240);
                tcp_packet.set_data_offset(5);
                tcp_packet.set_urgent_ptr(0);
                let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dst_ip);
                tcp_packet.set_checksum(checksum);
                let _ = tx.send_to(tcp_packet, IpAddr::V4(dst_ip));
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn send_one_syn_ping_win(
        _dst_ip: Ipv4Addr,
        _dst_port: u16,
        _src_ip: Ipv4Addr,
        _rng: &mut rand::rngs::ThreadRng,
    ) {
        // Windows implementation would use Layer 2 send
    }

    #[cfg(target_os = "windows")]
    fn get_gateway_info_windows() -> Result<(Ipv4Addr, MacAddr, Ipv4Addr)> {
        let output = Command::new("route").args(&["print", "0.0.0.0"]).output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);

        let re =
            Regex::new(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)")?;
        let cap = re
            .captures(&output_str)
            .ok_or(anyhow!("Could not find default gateway in route print"))?;

        let gateway_ip: Ipv4Addr = cap[1].parse()?;
        let interface_ip: Ipv4Addr = cap[2].parse()?;

        let output = Command::new("arp")
            .args(&["-a", &gateway_ip.to_string()])
            .output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);

        let re_mac = Regex::new(
            r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})",
        )?;
        let cap_mac = re_mac
            .captures(&output_str)
            .ok_or(anyhow!("Could not find MAC for gateway {}", gateway_ip))?;

        let mac_str = cap_mac[1].replace("-", ":");
        let mac: MacAddr = mac_str.parse().map_err(|_| anyhow!("Invalid MAC format"))?;

        Ok((gateway_ip, mac, interface_ip))
    }

    fn build_source_ip_cache() -> (Arc<HashMap<Ipv4Addr, Ipv4Addr>>, Ipv4Addr) {
        let mut cache = HashMap::new();
        let mut default_src: Option<Ipv4Addr> = None;

        let interfaces = pnet_datalink::interfaces();
        for iface in &interfaces {
            for ip_net in &iface.ips {
                if let IpAddr::V4(ipv4_addr) = ip_net.ip() {
                    if !ipv4_addr.is_loopback() && !ipv4_addr.is_link_local() {
                        if default_src.is_none() {
                            default_src = Some(ipv4_addr);
                        }
                        cache.insert(ipv4_addr, ipv4_addr);
                    }
                }
            }
        }

        let default = default_src.unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));
        info!("Ping source IP cache: {} entries, default: {}", cache.len(), default);

        (Arc::new(cache), default)
    }

    /// Run ping sweep on a range of IPs. Returns list of alive IPs.
    pub async fn sweep_range(
        &self,
        start_ip: Ipv4Addr,
        end_ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Vec<Ipv4Addr>> {
        let start: u32 = start_ip.into();
        let end: u32 = end_ip.into();
        let total = (end.saturating_sub(start) + 1) as usize;

        info!("Starting ping sweep: {} IPs (timeout: {:?})", total, timeout);

        // Reset state
        if let Ok(mut hosts) = self.active_hosts.lock() {
            hosts.clear();
        }
        self.total_probes.store(0, Ordering::Relaxed);
        self.alive_hosts.store(0, Ordering::Relaxed);

        let ips_to_probe: Vec<Ipv4Addr> = (start..=end)
            .map(Ipv4Addr::from)
            .collect();

        // Send probes with rate limiting
        let rate_limiter = self.rate_limiter.clone();
        let cache = self.source_ip_cache.clone();
        let default_src = self.default_source_ip;

        for &ip in &ips_to_probe {
            rate_limiter.acquire().await;
            
            let src_ip = cache.get(&ip).copied().unwrap_or(default_src);
            let mut rng = rand::thread_rng();
            
            #[cfg(not(target_os = "windows"))]
            Self::send_one_syn_ping(ip, 80, src_ip, &mut rng);
            
            self.total_probes.fetch_add(1, Ordering::Relaxed);
        }

        info!("Sent {} ping probes, waiting for responses...", ips_to_probe.len());

        // Wait for responses with timeout
        let start_time = Instant::now();

        // Simple polling with sleep
        loop {
            let elapsed = start_time.elapsed();
            if elapsed >= timeout {
                break;
            }

            let alive_count = {
                if let Ok(hosts) = self.active_hosts.lock() {
                    hosts.len()
                } else {
                    0
                }
            };

            if alive_count > 0 && elapsed > Duration::from_millis(500) {
                // Give extra 500ms for late responses after first detection
                tokio::time::sleep(Duration::from_millis(500)).await;
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Collect alive hosts
        let alive_ips: Vec<Ipv4Addr> = {
            if let Ok(hosts) = self.active_hosts.lock() {
                hosts.keys().cloned().collect()
            } else {
                vec![]
            }
        };

        // Sort for consistent output
        let mut alive_ips = alive_ips;
        alive_ips.sort_by_key(|ip| u32::from(*ip));

        info!(
            "Ping sweep complete: {} alive hosts out of {} probed",
            alive_ips.len(),
            total
        );

        self.alive_hosts.store(alive_ips.len(), Ordering::Relaxed);

        Ok(alive_ips)
    }

    pub fn get_stats(&self) -> (usize, usize) {
        let total = self.total_probes.load(Ordering::Relaxed);
        let alive = self.alive_hosts.load(Ordering::Relaxed);
        (total, alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_ip_cache() {
        let (cache, default) = PingScanner::build_source_ip_cache();
        assert!(!cache.is_empty(), "Source IP cache should not be empty");
        assert_ne!(default, Ipv4Addr::new(0, 0, 0, 0));
    }
}
