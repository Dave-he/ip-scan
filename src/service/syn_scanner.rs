use anyhow::{anyhow, Result};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
#[cfg(target_os = "windows")]
use pnet_transport as transport;
#[cfg(not(target_os = "windows"))]
use pnet_transport::{self as transport, TransportChannelType, TransportProtocol};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error};

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

use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;

#[cfg(not(target_os = "windows"))]
pub enum ScannerTx {
    L4(transport::TransportSender),
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub enum ScannerTx {
    L4(transport::TransportSender),
    L2 {
        sender: Box<dyn datalink::DataLinkSender>,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        src_ip: Ipv4Addr,
    },
}

unsafe impl Send for ScannerTx {}

#[derive(Clone, Copy)]
struct SynPacket {
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

pub struct SynScanner {
    #[allow(dead_code)]
    tx: Arc<Mutex<ScannerTx>>,
    rate_limiter: RateLimiter,
    metrics: ScanMetrics,
    packet_tx: mpsc::Sender<SynPacket>,
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

        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(db_batch_size);
            let mut last_flush = Instant::now();
            let flush_interval = Duration::from_millis(flush_interval_ms);

            loop {
                tokio::select! {
                    result = result_rx.recv() => {
                        match result {
                            Some(item) => {
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
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
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

        #[cfg(target_os = "windows")]
        {
            tracing::info!("Initializing Windows Layer 2 SYN Scanner (Npcap)...");
            let (gateway_ip, gateway_mac, interface_ip) = Self::get_gateway_info_windows()
                .map_err(|e| {
                    anyhow!(
                        "Failed to get gateway info: {}. Make sure Npcap is installed.",
                        e
                    )
                })?;

            tracing::info!(
                "Gateway: {} ({}), Interface IP: {}",
                gateway_ip,
                gateway_mac,
                interface_ip
            );

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

            let src_mac = interface
                .mac
                .ok_or(anyhow!("Interface has no MAC address"))?;
            tracing::info!("Using Interface: {} ({})", interface.name, src_mac);

            let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => return Err(anyhow!("Unhandled channel type")),
                Err(e) => return Err(anyhow!("Failed to create datalink channel: {}", e)),
            };

            let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<SynPacket>();

            let tx_arc = Arc::new(Mutex::new(ScannerTx::L2 {
                sender: tx,
                src_mac,
                dst_mac: gateway_mac,
                src_ip: interface_ip,
            }));
            let tx_for_sender = tx_arc.clone();

            thread::spawn(move || {
                let mut tx_lock = tx_for_sender.lock().unwrap();
                if let ScannerTx::L2 {
                    ref mut sender,
                    src_mac,
                    dst_mac,
                    src_ip,
                } = *tx_lock
                {
                    let mut pkt_buffer = Vec::with_capacity(64);
                    loop {
                        pkt_buffer.clear();
                        match pkt_rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(pkt) => {
                                pkt_buffer.push(pkt);
                                while pkt_buffer.len() < 64 {
                                    match pkt_rx.try_recv() {
                                        Ok(p) => pkt_buffer.push(p),
                                        Err(_) => break,
                                    }
                                }
                                for pkt in &pkt_buffer {
                                    Self::send_syn_l2_internal(
                                        sender,
                                        src_mac,
                                        dst_mac,
                                        src_ip,
                                        pkt.dst_ip,
                                        pkt.dst_port,
                                    );
                                }
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                }
            });

            let metrics_rx_clone = metrics.clone();
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
                                            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)
                                                == (TcpFlags::SYN | TcpFlags::ACK)
                                            {
                                                let src_ip = ip_header.get_source();
                                                let src_port = tcp.get_source();

                                                if ip_header.get_destination() == interface_ip {
                                                    metrics_rx_clone.increment_open();
                                                    debug!(
                                                        "Found open port: {}:{}",
                                                        src_ip, src_port
                                                    );
                                                    let _ = result_tx.blocking_send((
                                                        src_ip.to_string(),
                                                        src_port,
                                                        true,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Datalink read error: {}", e);
                    }
                }
            });

            return Ok(SynScanner {
                tx: tx_arc,
                rate_limiter,
                metrics,
                packet_tx: Self::tokio_to_std_sender(pkt_tx),
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            let protocol =
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
            let (tx, mut rx) = match transport::transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to create raw socket (Root/Admin required?): {}",
                        e
                    ))
                }
            };

            let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<SynPacket>();

            let tx_arc = Arc::new(Mutex::new(ScannerTx::L4(tx)));
            let tx_for_sender = tx_arc.clone();

            thread::spawn(move || {
                let mut tx_lock = tx_for_sender.lock().unwrap();
                let ScannerTx::L4(ref mut tx) = *tx_lock;
                let mut pkt_buffer = Vec::with_capacity(64);
                loop {
                    pkt_buffer.clear();
                    match pkt_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(pkt) => {
                            pkt_buffer.push(pkt);
                            while pkt_buffer.len() < 64 {
                                match pkt_rx.try_recv() {
                                    Ok(p) => pkt_buffer.push(p),
                                    Err(_) => break,
                                }
                            }
                            for pkt in &pkt_buffer {
                                if let Err(e) =
                                    Self::send_syn_l4_internal(tx, pkt.dst_ip, pkt.dst_port)
                                {
                                    error!("Failed to send SYN packet: {}", e);
                                }
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });

            let metrics_rx_clone = metrics.clone();
            thread::spawn(move || {
                let mut iter = transport::ipv4_packet_iter(&mut rx);
                loop {
                    match iter.next() {
                        Ok((packet, _addr)) => {
                            if let Some(tcp) = TcpPacket::new(packet.payload()) {
                                if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)
                                    == (TcpFlags::SYN | TcpFlags::ACK)
                                {
                                    let src_ip = packet.get_source();
                                    let src_port = tcp.get_source();
                                    metrics_rx_clone.increment_open();
                                    debug!("Found open port: {}:{}", src_ip, src_port);
                                    let _ = result_tx.blocking_send((
                                        src_ip.to_string(),
                                        src_port,
                                        true,
                                    ));
                                }
                            }
                        }
                        Err(e) => error!("Raw socket read error: {}", e),
                    }
                }
            });

            Ok(SynScanner {
                tx: tx_arc,
                rate_limiter,
                metrics,
                packet_tx: Self::tokio_to_std_sender(pkt_tx),
            })
        }
    }

    fn tokio_to_std_sender(std_tx: std::sync::mpsc::Sender<SynPacket>) -> mpsc::Sender<SynPacket> {
        let (tokio_tx, mut tokio_rx) = mpsc::channel::<SynPacket>(4096);
        thread::spawn(move || {
            while let Some(pkt) = tokio_rx.blocking_recv() {
                if std_tx.send(pkt).is_err() {
                    break;
                }
            }
        });
        tokio_tx
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

    #[cfg(not(target_os = "windows"))]
    fn find_source_ip(dst_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let interfaces = pnet_datalink::interfaces();
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

    #[cfg(not(target_os = "windows"))]
    #[inline]
    fn send_syn_l4_internal(
        tx: &mut transport::TransportSender,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Result<()> {
        let src_ip = Self::find_source_ip(dst_ip).ok_or_else(|| {
            anyhow!(
                "Could not find suitable source IP for destination {}",
                dst_ip
            )
        })?;

        let mut vec = vec![0u8; 20];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut vec).ok_or(anyhow!("Failed to create TCP packet"))?;

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
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn send_syn_l2_internal(
        sender: &mut Box<dyn datalink::DataLinkSender>,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) {
        const ETH_HEADER_LEN: usize = 14;
        const IP_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        const TOTAL_LEN: usize = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;

        sender.build_and_send(1, TOTAL_LEN, &mut |packet| {
            let mut eth = MutableEthernetPacket::new(packet).unwrap();
            eth.set_destination(dst_mac);
            eth.set_source(src_mac);
            eth.set_ethertype(EtherTypes::Ipv4);

            let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((IP_HEADER_LEN + TCP_HEADER_LEN) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src_ip);
            ip.set_destination(dst_ip);
            let ip_checksum = ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(ip_checksum);

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
    }

    pub async fn send_syn(&self, dst_ip: Ipv4Addr, dst_port: u16) -> Result<()> {
        let pkt = SynPacket { dst_ip, dst_port };
        self.packet_tx
            .send(pkt)
            .await
            .map_err(|e| anyhow!("{}", e))?;
        self.metrics.increment_scanned();
        Ok(())
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
                    if let Err(e) = self.send_syn(ipv4, *port).await {
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
