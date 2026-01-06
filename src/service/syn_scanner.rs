use anyhow::{anyhow, Result};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
use pnet_transport::{self as transport, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::RateLimiter;
use crate::dao::SqliteDB;
use crate::model::ScanMetrics;
use std::thread;
use tokio::time::timeout;

use pnet_datalink as datalink;
use rand::Rng;

pub struct SynScanner {
    tx: Arc<Mutex<transport::TransportSender>>,
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

        let metrics_clone = metrics.clone();
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

                                metrics_clone.increment_open();
                                debug!("Found open port: {}:{}", src_ip, src_port);

                                let _ =
                                    result_tx.blocking_send((src_ip.to_string(), src_port, true));
                            }
                        }
                    }
                    Err(e) => {
                        error!("Raw socket read error: {}", e);
                    }
                }
            }
        });

        Ok(SynScanner {
            tx: Arc::new(Mutex::new(tx)),
            rate_limiter,
            metrics,
        })
    }

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

        let mut tx = self.tx.lock().unwrap();
        tx.send_to(tcp_packet, IpAddr::V4(dst_ip))?;

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
                    // Rate Limit
                    self.rate_limiter.acquire().await;

                    // Send SYN
                    if let Err(e) = self.send_syn(ipv4, *port) {
                        error!(ip = %ipv4, port = port, error = %e, "Failed to send SYN");
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
