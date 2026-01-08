use anyhow::{anyhow, Result};
use pnet_datalink::{self as datalink, Channel, MacAddr, NetworkInterface};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet, Ipv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
use pnet_packet::MutablePacket;
use pnet_transport::{self as transport, TransportChannelType, TransportProtocol};
use rand::Rng;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;

pub enum ScannerTx {
    L4(transport::TransportSender),
    L2 {
        sender: Box<dyn datalink::DataLinkSender>,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        src_ip: Ipv4Addr,
    },
}

// Ensure ScannerTx is Send (DataLinkSender is typically Send)
unsafe impl Send for ScannerTx {}

pub struct SynScanner {
    tx: Arc<Mutex<ScannerTx>>,
    rate_limiter: RateLimiter,
    metrics: ScanMetrics,
}

impl SynScanner {
    pub fn new(
        db: SqliteDB,
        scan_round: i64,
        result_buffer: usize,
        db_batch_size: usize,
        flush_interval_ms: u64,
        max_rate: u64,
        rate_window_secs: u64,
    ) -> Result<Self> {
        let metrics = ScanMetrics::new();
        let rate_limiter =
            RateLimiter::new(max_rate as usize, Duration::from_secs(rate_window_secs));
        let (result_tx, mut result_rx) = mpsc::channel(result_buffer);
        let db_clone = db.clone();
        
        // Spawn DB Writer Thread (Common for both modes)
        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(db_batch_size);
            let mut last_flush = Instant::now();
            let flush_interval = Duration::from_millis(flush_interval_ms);

            loop {
                let result = timeout(Duration::from_millis(100), result_rx.recv()).await;
                match result {
                    Ok(Some(item)) => {
                        buffer.push(item);
                        if buffer.len() >= db_batch_size {
                            if let Err(e) = db_clone
                                .bulk_update_port_status(std::mem::take(&mut buffer), scan_round)
                            {
                                error!("Failed to bulk update port status: {}", e);
                            }
                            last_flush = Instant::now();
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {}
                }

                if !buffer.is_empty() && last_flush.elapsed() >= flush_interval {
                    if let Err(e) =
                        db_clone.bulk_update_port_status(std::mem::take(&mut buffer), scan_round)
                    {
                        error!("Failed to bulk update port status (timer): {}", e);
                    }
                    last_flush = Instant::now();
                }
            }

            if !buffer.is_empty() {
                let _ = db_clone.bulk_update_port_status(buffer, scan_round);
            }
        });

        // Platform specific initialization
        #[cfg(target_os = "windows")]
        {
            info!("Initializing Windows Layer 2 SYN Scanner (Npcap)...");
            // 1. Get Gateway Info
            let (gateway_ip, gateway_mac, interface_ip) = Self::get_gateway_info_windows()
                .map_err(|e| anyhow!("Failed to get gateway info: {}. Make sure Npcap is installed.", e))?;
            
            info!("Gateway: {} ({}), Interface IP: {}", gateway_ip, gateway_mac, interface_ip);

            // 2. Find Interface
            let interfaces = datalink::interfaces();
            let interface = interfaces.into_iter()
                .find(|iface| iface.ips.iter().any(|ip| ip.ip() == IpAddr::V4(interface_ip)))
                .ok_or(anyhow!("Could not find network interface for IP {}", interface_ip))?;
            
            let src_mac = interface.mac.ok_or(anyhow!("Interface has no MAC address"))?;
            info!("Using Interface: {} ({})", interface.name, src_mac);

            // 3. Create Channel
            let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(anyhow!("Unhandled channel type")),
                Err(e) => return Err(anyhow!("Failed to create datalink channel: {}", e)),
            };

            // 4. Spawn L2 Receiver
            let metrics_clone = metrics.clone();
            thread::spawn(move || {
                loop {
                    match rx.next() {
                        Ok(packet) => {
                            if let Some(frame) = EthernetPacket::new(packet) {
                                if frame.get_ethertype() == EtherTypes::Ipv4 {
                                    if let Some(ip_header) = Ipv4Packet::new(frame.payload()) {
                                        if ip_header.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                            if let Some(tcp) = TcpPacket::new(ip_header.payload()) {
                                                if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                                                    let src_ip = ip_header.get_source();
                                                    let src_port = tcp.get_source();
                                                    
                                                    // Optional: Check destination matches our IP to avoid noise
                                                    if ip_header.get_destination() == interface_ip {
                                                        metrics_clone.increment_open();
                                                        debug!("Found open port: {}:{}", src_ip, src_port);
                                                        let _ = result_tx.blocking_send((src_ip.to_string(), src_port, true));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Datalink read errors can be frequent/benign, log trace
                            debug!("Datalink read error: {}", e);
                        }
                    }
                }
            });

            return Ok(SynScanner {
                tx: Arc::new(Mutex::new(ScannerTx::L2 {
                    sender: tx,
                    src_mac,
                    dst_mac: gateway_mac,
                    src_ip: interface_ip,
                })),
                rate_limiter,
                metrics,
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Linux/Unix Layer 4 Implementation
            let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
            let (tx, mut rx) = match transport::transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => return Err(anyhow!("Failed to create raw socket (Root/Admin required?): {}", e)),
            };

            let metrics_clone = metrics.clone();
            thread::spawn(move || {
                let mut iter = transport::ipv4_packet_iter(&mut rx);
                loop {
                    match iter.next() {
                        Ok((packet, _addr)) => {
                            if let Some(tcp) = TcpPacket::new(packet.payload()) {
                                if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                                    let src_ip = packet.get_source();
                                    let src_port = tcp.get_source();
                                    metrics_clone.increment_open();
                                    debug!("Found open port: {}:{}", src_ip, src_port);
                                    let _ = result_tx.blocking_send((src_ip.to_string(), src_port, true));
                                }
                            }
                        }
                        Err(e) => error!("Raw socket read error: {}", e),
                    }
                }
            });

            return Ok(SynScanner {
                tx: Arc::new(Mutex::new(ScannerTx::L4(tx))),
                rate_limiter,
                metrics,
            });
        }
    }

    #[cfg(target_os = "windows")]
    fn get_gateway_info_windows() -> Result<(Ipv4Addr, MacAddr, Ipv4Addr)> {
        // 1. Get Gateway IP and Interface IP via `route print 0.0.0.0`
        // Output format example:
        // 0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.187     35
        let output = Command::new("route")
            .args(&["print", "0.0.0.0"])
            .output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        let re = Regex::new(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)")?;
        let cap = re.captures(&output_str).ok_or(anyhow!("Could not find default gateway in route print"))?;
        
        let gateway_ip: Ipv4Addr = cap[1].parse()?;
        let interface_ip: Ipv4Addr = cap[2].parse()?;
        
        // 2. Get Gateway MAC via `arp -a <gateway_ip>`
        let output = Command::new("arp")
            .args(&["-a", &gateway_ip.to_string()])
            .output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Match MAC address (xx-xx-xx-xx-xx-xx)
        let re_mac = Regex::new(r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})")?;
        let cap_mac = re_mac.captures(&output_str).ok_or(anyhow!("Could not find MAC for gateway {}", gateway_ip))?;
        
        let mac_str = cap_mac[1].replace("-", ":");
        let mac: MacAddr = mac_str.parse().map_err(|_| anyhow!("Invalid MAC format"))?;
        
        Ok((gateway_ip, mac, interface_ip))
    }

    // Helper to find source IP for L4 (Linux)
    fn find_source_ip(dst_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let interfaces = datalink::interfaces();
        let mut best_if_ip: Option<Ipv4Addr> = None;
        for iface in interfaces {
            for ip_net in iface.ips {
                if let IpAddr::V4(ipv4_addr) = ip_net.ip() {
                    if ip_net.contains(IpAddr::V4(dst_ip)) {
                        return Some(ipv4_addr);
                    }
                    if !ipv4_addr.is_loopback() && best_if_ip.is_none() {
                        best_if_ip = Some(ipv4_addr);
                    }
                }
            }
        }
        best_if_ip
    }

    pub fn send_syn(&self, dst_ip: Ipv4Addr, dst_port: u16) -> Result<()> {
        let mut tx_lock = self.tx.lock().unwrap();

        match *tx_lock {
            ScannerTx::L4(ref mut tx) => {
                // Linux / Layer 4 Logic
                let src_ip = Self::find_source_ip(dst_ip).ok_or_else(|| {
                    anyhow!("Could not find suitable source IP for destination {}", dst_ip)
                })?;

                let mut vec = vec![0u8; 20];
                let mut tcp_packet = MutableTcpPacket::new(&mut vec).ok_or(anyhow!("Failed to create TCP packet"))?;

                let mut rng = rand::thread_rng();
                let src_port = rng.gen_range(1025..=65535);

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

                tx.send_to(tcp_packet, IpAddr::V4(dst_ip))?;
                self.metrics.increment_scanned();
                Ok(())
            },
            ScannerTx::L2 { ref mut sender, src_mac, dst_mac, src_ip } => {
                // Windows / Layer 2 Logic
                // Total size = 14 (Ethernet) + 20 (IPv4) + 20 (TCP) = 54 bytes
                const ETH_HEADER_LEN: usize = 14;
                const IP_HEADER_LEN: usize = 20;
                const TCP_HEADER_LEN: usize = 20;
                const TOTAL_LEN: usize = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;

                sender.build_and_send(1, TOTAL_LEN, &mut |packet| {
                    // 1. Ethernet Header
                    let mut eth = MutableEthernetPacket::new(packet).unwrap();
                    eth.set_destination(dst_mac);
                    eth.set_source(src_mac);
                    eth.set_ethertype(EtherTypes::Ipv4);

                    // 2. IPv4 Header
                    let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
                    ip.set_version(4);
                    ip.set_header_length(5);
                    ip.set_total_length((IP_HEADER_LEN + TCP_HEADER_LEN) as u16);
                    ip.set_ttl(64);
                    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                    ip.set_source(src_ip);
                    ip.set_destination(dst_ip);
                    // Checksum is calculated automatically by some NICs, but let's do it if pnet helper exists
                    // pnet::packet::ipv4::checksum(&ip.to_immutable())
                    let ip_checksum = ipv4::checksum(&ip.to_immutable());
                    ip.set_checksum(ip_checksum);

                    // 3. TCP Header
                    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
                    let mut rng = rand::thread_rng();
                    let src_port = rng.gen_range(1025..=65535);

                    tcp.set_source(src_port);
                    tcp.set_destination(dst_port);
                    tcp.set_sequence(rng.gen());
                    tcp.set_acknowledgement(0);
                    tcp.set_flags(TcpFlags::SYN);
                    tcp.set_window(64240);
                    tcp.set_data_offset(5);
                    tcp.set_urgent_ptr(0);
                    
                    let checksum = ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
                    tcp.set_checksum(checksum);
                });

                self.metrics.increment_scanned();
                Ok(())
            }
        }
    }

    pub async fn run_pipeline(
        &self,
        mut rx: mpsc::Receiver<IpAddr>,
        ports: Vec<u16>,
        progress_callback: impl Fn(usize) + Send + Sync + 'static,
    ) -> Result<()> {
        let mut total_sent = 0;

        while let Some(ip) = rx.recv().await {
            if let IpAddr::V4(ipv4) = ip {
                for port in &ports {
                    self.rate_limiter.acquire().await;
                    if let Err(e) = self.send_syn(ipv4, *port) {
                        // Rate limiting or temporary network error
                        // Don't spam logs
                        debug!(ip = %ipv4, port = port, error = %e, "Failed to send SYN");
                        self.metrics.increment_errors();
                    }
                }
                total_sent += 1;
                progress_callback(total_sent);
            }
        }

        Ok(())
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}
