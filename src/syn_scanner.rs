use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use anyhow::{Result, anyhow};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags, ipv4_checksum};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use tracing::{info, error, debug};

use std::thread;
use crate::rate_limiter::RateLimiter;
use crate::metrics::ScanMetrics;
use crate::bitmap_db::BitmapDatabase;
use tokio::time::timeout;

pub struct SynScanner {
    tx: Arc<Mutex<transport::TransportSender>>,
    // We don't hold rx here because it's moved to the thread
    local_ip: Ipv4Addr,
    rate_limiter: RateLimiter,
    metrics: ScanMetrics,
    db: BitmapDatabase,
    scan_round: i64,
}

impl SynScanner {
    pub fn new(db: BitmapDatabase, scan_round: i64) -> Result<Self> {
        // 1. Determine Local IP
        let local_ip = Self::get_local_ip()?;
        info!("SYN Scanner using local IP: {}", local_ip);

        // 2. Create Raw Socket
        // Layer4(Ipv4(Tcp)) means we write TCP header, OS writes IPv4 header
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (tx, mut rx) = match transport::transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => return Err(anyhow!("Failed to create raw socket (Root/Admin required?): {}", e)),
        };

        // 3. Setup Metrics and RateLimiter
        let metrics = ScanMetrics::new();
        let rate_limiter = RateLimiter::new(100000, Duration::from_secs(1)); // Higher rate for SYN

        // 4. Setup Result Channel & DB Writer
        let (result_tx, mut result_rx) = mpsc::channel(10000);
        let db_clone = db.clone();
        
        // Spawn DB Writer (Same logic as BitmapScanner, could be shared)
        tokio::spawn(async move {
             let mut buffer = Vec::with_capacity(5000);
             let mut last_flush = Instant::now();
             const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
             const BATCH_SIZE: usize = 2000;

             loop {
                 let result = timeout(Duration::from_millis(100), result_rx.recv()).await;
                 match result {
                     Ok(Some(item)) => {
                         buffer.push(item);
                         if buffer.len() >= BATCH_SIZE {
                             if let Err(e) = db_clone.bulk_update_port_status(buffer.drain(..).collect(), scan_round) {
                                 error!("Failed to bulk update port status: {}", e);
                             }
                             last_flush = Instant::now();
                         }
                     }
                     Ok(None) => break,
                     Err(_) => {}
                 }

                 if !buffer.is_empty() && last_flush.elapsed() >= FLUSH_INTERVAL {
                     if let Err(e) = db_clone.bulk_update_port_status(buffer.drain(..).collect(), scan_round) {
                         error!("Failed to bulk update port status (timer): {}", e);
                     }
                     last_flush = Instant::now();
                 }
             }
             
             if !buffer.is_empty() {
                 let _ = db_clone.bulk_update_port_status(buffer, scan_round);
             }
        });

        // 5. Spawn Listener Thread
        // Listener needs to know which ports we are scanning? 
        // Ideally yes to filter, but for now we accept any SYN-ACK.
        // We use a blocking thread because pnet iter is blocking.
        let metrics_clone = metrics.clone();
        
        thread::spawn(move || {
            // pnet's iterator blocks. 
            // Warning: This iterator sees ALL TCP packets on the interface if not careful?
            // transport_channel(Layer4) usually only receives packets for the socket?
            // No, raw sockets usually see all traffic of that protocol.
            // We need to filter by our logic (e.g. is it a response to us?).
            // But we are stateless, so we assume any SYN-ACK to our ports is valid?
            // Or we just check flags.
            
            let mut iter = transport::ipv4_packet_iter(&mut rx);
            loop {
                match iter.next() {
                    Ok((packet, _addr)) => {
                        // packet is Ipv4Packet. payload is TCP.
                        if let Some(tcp) = TcpPacket::new(packet.payload()) {
                            if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                                // Found Open Port!
                                let src_ip = packet.get_source();
                                let src_port = tcp.get_source();
                                
                                // Optional: Filter out packets not destined to us?
                                // if packet.get_destination() != local_ip { continue; }
                                
                                metrics_clone.increment_open();
                                debug!("Found open port: {}:{}", src_ip, src_port);

                                // Send to DB Writer
                                let _ = result_tx.blocking_send((src_ip.to_string(), src_port, true));
                            } else if tcp.get_flags() & TcpFlags::RST != 0 {
                                // Port closed
                            }
                        }
                    }
                    Err(e) => {
                        error!("Raw socket read error: {}", e);
                        // Don't break loop on temporary errors?
                        // break; 
                    }
                }
            }
        });

        Ok(SynScanner {
            tx: Arc::new(Mutex::new(tx)),
            local_ip,
            rate_limiter,
            metrics,
            db,
            scan_round,
        })
    }

    fn get_local_ip() -> Result<Ipv4Addr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        match socket.local_addr()? {
            SocketAddr::V4(addr) => Ok(*addr.ip()),
            _ => Err(anyhow!("Failed to get local IPv4 address")),
        }
    }

    pub fn send_syn(&self, dst_ip: Ipv4Addr, dst_port: u16) -> Result<()> {
        let mut vec = vec![0u8; 20]; // TCP Header size
        let mut tcp_packet = MutableTcpPacket::new(&mut vec).ok_or(anyhow!("Failed to create TCP packet"))?;

        // Construct TCP Packet
        // Source port: use a hash or random? 
        // If we use fixed source port, OS might RST it because no bound socket.
        // Stateless scanning usually requires us to ignore OS RSTs or use firewall rules.
        // Here we just send.
        let src_port = 50000 + (dst_port % 10000); 
        
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(rand::random());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_urgent_ptr(0);
        
        // Checksum
        let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &self.local_ip, &dst_ip);
        tcp_packet.set_checksum(checksum);

        // Send
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
