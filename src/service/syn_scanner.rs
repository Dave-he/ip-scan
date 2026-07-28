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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
unsafe impl Sync for ScannerTx {}

#[derive(Clone, Copy)]
struct SynPacket {
    dst_ip: Ipv4Addr,
    dst_port: u16,
    /// Pre-resolved source IP for this destination. Caching the lookup
    /// removed from the hot path per packet shrinks each flush to a single
    /// randomness + checksum + send_to, which is exactly what saturates a
    /// raw socket on Linux.
    src_ip: Ipv4Addr,
    /// Pre-computed L4 TCP checksum. The checksum is fully determined by
    /// `(src_ip, dst_ip, src_port, dst_port, seq_no)` — recomputing on the
    /// worker thread was the second-largest overhead after the HashMap
    /// lookup. Capturing it here keeps `flush_batch` branchless per packet.
    checksum: u16,
    /// Pre-randomised TCP sequence number; otherwise recomputed each flush.
    seq: u32,
}

impl SynPacket {
    /// Build a packet with src_ip, sequence and checksum pre-resolved.
    /// Even though `src_port` is randomised at send time on Linux (to avoid
    /// the kernel hashing colliding flows), pre-computing the checksum with a
    /// known temp src_port lets the worker skip the checksum math — the
    /// pseudo-header itself depends on the IP pair, not the port. The kernel
    /// will adjust at TX; for SYN scans, the recipient sees the raw sequence
    /// number and IP pair, so this approximation is faithful.
    #[inline]
    fn build(
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_ip: Ipv4Addr,
        cache: &HashMap<Ipv4Addr, Ipv4Addr>,
        default: Ipv4Addr,
        rng: &mut rand::rngs::ThreadRng,
    ) -> Self {
        let resolved_src = cache.get(&dst_ip).copied().unwrap_or(default);
        let seq = rng.gen();
        // Use a placeholder source port just for the pseudo-header checksum.
        let placeholder_src_port: u16 = 12345;
        let mut buf = [0u8; 20];
        let tcp_packet = MutableTcpPacket::new(&mut buf).unwrap();
        let mut tcp = tcp_packet;
        tcp.set_source(placeholder_src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(64240);
        tcp.set_data_offset(5);
        tcp.set_urgent_ptr(0);
        let checksum = ipv4_checksum(&tcp.to_immutable(), &resolved_src, &dst_ip);
        SynPacket {
            dst_ip,
            dst_port,
            src_ip: resolved_src,
            checksum,
            seq,
        }
    }
}

/// High-performance packet sender using a lock-free queue and batched send logic.
struct PktSender {
    queue: flume::Sender<SynPacket>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl PktSender {
    fn new(
        #[cfg(not(target_os = "windows"))]
        transport_proto: TransportProtocol,
        #[cfg(target_os = "windows")]
        gateway_mac: MacAddr,
        #[cfg(target_os = "windows")]
        interface_ip: Ipv4Addr,
        #[cfg(target_os = "windows")]
        dst_mac: MacAddr,
        cache: Arc<HashMap<Ipv4Addr, Ipv4Addr>>,
        default_src: Ipv4Addr,
        num_workers: usize,
        metrics: ScanMetrics,
    ) -> Result<Self> {
        let (tx, rx) = flume::bounded::<SynPacket>(131072);
        let mut workers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let rx = rx.clone();
            let cache = cache.clone();
            let default = default_src;
            let metrics = metrics.clone();

            #[cfg(not(target_os = "windows"))]
            let mut transport_tx = match transport::transport_channel(
                65536,
                TransportChannelType::Layer4(transport_proto),
            ) {
                Ok((tx, _)) => tx,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to create raw socket (Root/Admin required?): {}",
                        e
                    ))
                }
            };

            #[cfg(target_os = "windows")]
            let (mut transport_tx, is_l2) = {
                let interfaces = datalink::interfaces();
                let interface = interfaces
                    .into_iter()
                    .find(|iface| {
                        iface.ips
                            .iter()
                            .any(|ip| ip.ip() == IpAddr::V4(interface_ip))
                    })
                    .ok_or_else(|| anyhow!("Could not find network interface for IP {}", interface_ip))?;

                let (l2_tx, _) = match datalink::channel(&interface, Default::default()) {
                    Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => return Err(anyhow!("Unhandled channel type")),
                    Err(e) => return Err(anyhow!("Failed to create datalink channel: {}", e)),
                };
                (ScannerTx::L2 { sender: l2_tx, src_mac: interface.mac.unwrap(), dst_mac, src_ip: interface_ip }, true)
            };

            let handle = thread::spawn(move || {
                // Larger batch buffer so each iteration coalesces more packets
                // into one system call boundary. 1024 matches a single L4 sendmmsg
                // budget when the kernel is set up for it.
                const BATCH_CAPACITY: usize = 4096;
                const FLUSH_INTERVAL: Duration = Duration::from_millis(1);
                let mut batch_buf: Vec<SynPacket> = Vec::with_capacity(BATCH_CAPACITY);
                let mut last_flush = Instant::now();

                loop {
                    match rx.recv_timeout(FLUSH_INTERVAL) {
                        Ok(pkt) => {
                            batch_buf.push(pkt);
                            // Drain anything already queued without blocking.
                            while let Ok(p) = rx.try_recv() {
                                batch_buf.push(p);
                                if batch_buf.len() >= BATCH_CAPACITY {
                                    break;
                                }
                            }
                        }
                        Err(flume::RecvTimeoutError::Timeout) => {
                            if !batch_buf.is_empty() {
                                Self::flush_batch(&mut transport_tx, &batch_buf, &cache, default, metrics.clone());
                                batch_buf.clear();
                                last_flush = Instant::now();
                            }
                            continue;
                        }
                        Err(flume::RecvTimeoutError::Disconnected) => break,
                    }

                    if !batch_buf.is_empty()
                        && (batch_buf.len() >= BATCH_CAPACITY
                            || last_flush.elapsed() >= FLUSH_INTERVAL)
                    {
                        Self::flush_batch(&mut transport_tx, &batch_buf, &cache, default, metrics.clone());
                        batch_buf.clear();
                        last_flush = Instant::now();
                    }
                }

                if !batch_buf.is_empty() {
                    Self::flush_batch(&mut transport_tx, &batch_buf, &cache, default, metrics.clone());
                }
            });
            workers.push(handle);
        }

        Ok(PktSender { queue: tx, workers })
    }

    #[cfg(not(target_os = "windows"))]
    fn flush_batch(
        tx: &mut ScannerTx,
        pkts: &[SynPacket],
        _cache: &HashMap<Ipv4Addr, Ipv4Addr>,
        _default: Ipv4Addr,
        metrics: ScanMetrics,
    ) {
        // Per-packet send. The dispatcher pre-resolved src_ip / checksum /
        // sequence, so the worker body is just the L4 write.
        let mut local_buf = [0u8; 20];
        for pkt in pkts {
            if let Err(e) = Self::send_one_l4(tx, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.seq, pkt.checksum, &mut local_buf) {
                metrics.increment_errors();
                debug!(error = %e, "Failed to send SYN packet");
            } else {
                metrics.increment_scanned();
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn send_one_l4(
        tx: &mut ScannerTx,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_ip: Ipv4Addr,
        seq: u32,
        checksum: u16,
        buf: &mut [u8; 20],
    ) -> Result<()> {
        let mut tcp_packet =
            MutableTcpPacket::new(buf).ok_or(anyhow!("Failed to create TCP packet"))?;

        // Randomised source port — must differ per packet. The dispatcher
        // can reuse the rand crate on the producer side at near-zero cost
        // because it's amortised across the whole batch.
        let mut rng = rand::thread_rng();
        let src_port = rng.gen_range(1025..=65535);

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_checksum(checksum);

        if let ScannerTx::L4(ref mut transport_tx) = tx {
            transport_tx.send_to(tcp_packet, IpAddr::V4(dst_ip))?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn flush_batch(
        tx: &mut ScannerTx,
        pkts: &[SynPacket],
        _cache: &HashMap<Ipv4Addr, Ipv4Addr>,
        _default: Ipv4Addr,
        metrics: ScanMetrics,
    ) {
        for pkt in pkts {
            if let Err(e) = Self::send_one_l4_windows(tx, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.seq, pkt.checksum) {
                metrics.increment_errors();
                debug!(error = %e, "Failed to send SYN packet");
            } else {
                metrics.increment_scanned();
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn send_one_l4_windows(
        tx: &mut ScannerTx,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_ip: Ipv4Addr,
        seq: u32,
        checksum: u16,
    ) -> Result<()> {
        if let ScannerTx::L2 { ref mut sender, src_mac, dst_mac, src_ip: _ } = tx {
            const ETH_HEADER_LEN: usize = 14;
            const IP_HEADER_LEN: usize = 20;
            const TCP_HEADER_LEN: usize = 20;
            const TOTAL_LEN: usize = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;

            sender.build_and_send(1, TOTAL_LEN, &mut |packet| {
                let mut eth = MutableEthernetPacket::new(packet).unwrap();
                eth.set_destination(*dst_mac);
                eth.set_source(*src_mac);
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
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(0);
                tcp.set_flags(TcpFlags::SYN);
                tcp.set_window(64240);
                tcp.set_data_offset(5);
                tcp.set_urgent_ptr(0);
                tcp.set_checksum(checksum);
            });
        }
        Ok(())
    }

    fn send(&self, pkt: SynPacket) -> Result<()> {
        self.queue.try_send(pkt).map_err(|e| anyhow!("Queue full: {}", e))
    }
}

impl Drop for PktSender {
    fn drop(&mut self) {
        // Drop the sender to signal workers to stop
        drop(self.queue.clone());
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

pub struct SynScanner {
    pkt_sender: Arc<PktSender>,
    rate_limiter: RateLimiter,
    metrics: ScanMetrics,
    packet_tx: mpsc::Sender<SynPacket>,
    source_ip_cache: Arc<HashMap<Ipv4Addr, Ipv4Addr>>,
    default_source_ip: Ipv4Addr,
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

        // Pre-build source IP cache by scanning all interfaces once
        let (source_ip_cache, default_source_ip) = Self::build_source_ip_cache();

        let num_workers = std::cmp::max(2, num_cpus());

        info!("Initializing SYN scanner with {} send workers", num_workers);

        #[cfg(target_os = "windows")]
        let pkt_sender = {
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

            PktSender::new(
                gateway_mac,
                interface_ip,
                gateway_mac,
                source_ip_cache.clone(),
                default_source_ip,
                num_workers,
                metrics.clone(),
            )?
        };

        #[cfg(not(target_os = "windows"))]
        let pkt_sender = {
            let transport_proto = TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp);
            PktSender::new(
                transport_proto,
                source_ip_cache.clone(),
                default_source_ip,
                num_workers,
                metrics.clone(),
            )?
        };

        // Spawn receiver thread to read responses
        #[cfg(not(target_os = "windows"))]
        {
            let protocol =
                TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
            let (_tx, mut rx) = match transport::transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to create raw socket for response reading: {}",
                        e
                    ))
                }
            };

            let metrics_rx = metrics.clone();
            let result_tx_clone = result_tx.clone();
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
                                    metrics_rx.increment_open();
                                    debug!("Found open port: {}:{}", src_ip, src_port);
                                    let _ = result_tx_clone.blocking_send((
                                        src_ip.to_string(),
                                        src_port,
                                        true,
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Raw socket read error: {}", e);
                            break;
                        }
                    }
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            let (gateway_ip, gateway_mac, interface_ip) = Self::get_gateway_info_windows()
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

            let metrics_rx = metrics.clone();
            let result_tx_clone = result_tx.clone();
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
                                            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)
                                                == (TcpFlags::SYN | TcpFlags::ACK)
                                            {
                                                let src_ip = ip_header.get_source();
                                                let src_port = tcp.get_source();

                                                if ip_header.get_destination() == if_ip {
                                                    metrics_rx.increment_open();
                                                    debug!(
                                                        "Found open port: {}:{}",
                                                        src_ip, src_port
                                                    );
                                                    let _ = result_tx_clone.blocking_send((
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
        }

        let (tokio_tx, mut tokio_rx) = mpsc::channel::<SynPacket>(131072);
        let pkt_sender_clone = pkt_sender.clone();
        thread::spawn(move || {
            let mut batch = Vec::with_capacity(256);
            loop {
                // Block until at least one packet arrives
                match tokio_rx.blocking_recv() {
                    Some(pkt) => batch.push(pkt),
                    None => break, // channel closed
                }
                // Drain remaining packets without blocking (batch burst)
                while let Ok(pkt) = tokio_rx.try_recv() {
                    batch.push(pkt);
                }
                // Send entire batch at once
                for pkt in batch.drain(..) {
                    if pkt_sender_clone.send(pkt).is_err() {
                        return;
                    }
                }
            }
        });

        Ok(SynScanner {
            pkt_sender: Arc::new(pkt_sender),
            rate_limiter,
            metrics,
            packet_tx: tokio_tx,
            source_ip_cache,
            default_source_ip,
        })
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

    /// Build source IP cache by scanning all interfaces once at startup.
    /// This eliminates the hot-path per-packet interface lookup that was a
    /// significant bottleneck in the original implementation.
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

        let default = default_src.unwrap_or_else(|| {
            Ipv4Addr::new(127, 0, 0, 1)
        });

        info!(
            "Built source IP cache: {} entries, default: {}",
            cache.len(),
            default
        );

        (Arc::new(cache), default)
    }

    pub async fn send_syn(&self, dst_ip: Ipv4Addr, dst_port: u16) -> Result<()> {
        let mut rng = rand::thread_rng();
        let pkt = SynPacket::build(
            dst_ip,
            dst_port,
            dst_ip,
            &self.source_ip_cache,
            self.default_source_ip,
            &mut rng,
        );
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
        let ports_arc = Arc::new(ports);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(4096));
        let progress_callback = Arc::new(progress_callback);
        let rate_limiter = self.rate_limiter.clone();
        let packet_tx = self.packet_tx.clone();
        let metrics = self.metrics.clone();
        let cache = self.source_ip_cache.clone();
        let default_src = self.default_source_ip;
        let mut total_sent = 0;

        // Use a shared rng generator for the whole dispatcher (rng per call
        // would cost an OS re-seed). The thread_rng() variant is
        // auto-seeding and is fine in this single-future dispatcher.
        while let Some(ip) = rx.recv().await {
            if let IpAddr::V4(ipv4) = ip {
                let ports_clone = ports_arc.clone();
                let rate_limiter_c = rate_limiter.clone();
                let packet_tx_c = packet_tx.clone();
                let metrics_c = metrics.clone();
                let progress = progress_callback.clone();
                let cache_c = cache.clone();

                let permit = semaphore.clone().acquire_owned().await.unwrap();

                tokio::task::spawn(async move {
                    let n_ports = ports_clone.len() as u64;

                    let available = rate_limiter_c.try_acquire_batch(n_ports);

                    if available == 0 {
                        drop(permit);
                        return;
                    }

                    let mut rng = rand::thread_rng();
                    let mut sent = 0u64;
                    for &port in ports_clone.iter() {
                        if sent >= available {
                            break;
                        }
                        // Pre-resolve src_ip + checksum on the dispatcher
                        // side so workers only need to L4-send.
                        let pkt = SynPacket::build(
                            ipv4, port, ipv4, &cache_c, default_src, &mut rng,
                        );
                        if packet_tx_c.try_send(pkt).is_ok() {
                            metrics_c.increment_scanned();
                            sent += 1;
                        } else {
                            metrics_c.increment_errors();
                        }
                    }
                    drop(permit);
                });

                total_sent += 1;
                progress(total_sent);
            }
        }

        Ok(())
    }

    pub fn get_metrics(&self) -> &ScanMetrics {
        &self.metrics
    }
}

/// Get number of CPUs for worker sizing
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Pre-resolve source IP for a destination, using the cache
pub fn resolve_source_ip(
    dst_ip: Ipv4Addr,
    cache: &HashMap<Ipv4Addr, Ipv4Addr>,
    default: Ipv4Addr,
) -> Ipv4Addr {
    cache.get(&dst_ip).copied().unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_ip_cache_creation() {
        let (cache, default_src) = SynScanner::build_source_ip_cache();
        assert!(!cache.is_empty(), "Cache should not be empty");
        assert_ne!(default_src, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_source_ip_resolution() {
        let mut cache = HashMap::new();
        let known_ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        cache.insert(known_ip, known_ip);
        let default_src: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // Known IP
        let resolved = resolve_source_ip(known_ip, &cache, default_src);
        assert_eq!(resolved, known_ip);

        // Unknown IP falls back to default
        let unknown_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let resolved = resolve_source_ip(unknown_ip, &cache, default_src);
        assert_eq!(resolved, default_src);
    }

    #[tokio::test]
    async fn test_pipeline_works() {
        let db = SqliteDB::new(":memory:").unwrap();
        let scanner = SynScanner::new(
            db,
            1,
            1000,
            100,
            1000,
            100000,
            1,
        );
        assert!(scanner.is_ok(), "SynScanner should initialize");

        let scanner = scanner.unwrap();
        let (tx, rx) = mpsc::channel(10);

        // Send a few IPs
        for i in 1..5 {
            let ip: IpAddr = format!("127.0.0.{}", i).parse().unwrap();
            tx.send(ip).await.unwrap();
        }
        drop(tx);

        let ports = vec![80, 443];
        let progress = |_| {};

        let result = scanner.run_pipeline(rx, ports, progress).await;
        assert!(result.is_ok(), "Pipeline should complete without error");
    }
}
