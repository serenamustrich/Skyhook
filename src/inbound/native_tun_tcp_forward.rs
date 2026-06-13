use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::native_tun_flow::{FlowKey, FlowProtocol};
use super::native_tun_metrics::NativeTunMetrics;
use super::native_tun_packet::{extract_transport_ports, parse_ip_packet, TunIpPacket};
use super::native_tun_router::{resolve_native_route, NativeRouteTarget};
use crate::core::Runtime;
use crate::routing::Destination;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SESSIONS: usize = 10000;

/// TCP session state machine for NativeTcpForwarder
///
/// State transitions:
///   SynReceived -> Connecting (on ACK)
///   Connecting -> Established (on successful outbound connect)
///   Established -> FinWait (on FIN from client)
///   FinWait -> Closed (after sending FIN-ACK)
///   Any -> Closed (on RST or connect failure)
#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpSessionState {
    SynReceived,
    Connecting,
    Established,
    FinWait,
    Closed,
}

struct TcpForwardSession {
    state: TcpSessionState,
    client_next_seq: Arc<AtomicU32>,
    server_next_seq: Arc<AtomicU32>,
    bytes_tx: u64,
    last_activity: Instant,
    target: NativeRouteTarget,
    sniffer: PayloadSniffer,
    data_tx: Option<mpsc::Sender<Vec<u8>>>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

struct PayloadSniffer {
    buffer: Vec<u8>,
}

impl PayloadSniffer {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn inferred_host(&self) -> Option<String> {
        if self.buffer.len() >= 5 && self.buffer[0] == 0x16 && self.buffer[1] == 0x03 {
            if let Some(sni) = extract_tls_sni(&self.buffer) {
                return Some(sni);
            }
        }
        if let Ok(text) = std::str::from_utf8(&self.buffer) {
            for line in text.lines() {
                if let Some(rest) = line
                    .strip_prefix("Host:")
                    .or_else(|| line.strip_prefix("host:"))
                {
                    return Some(rest.trim().to_string());
                }
            }
        }
        None
    }
}

pub struct NativeTcpForwarder {
    sessions: HashMap<FlowKey, TcpForwardSession>,
    egress_tx: mpsc::Sender<Vec<u8>>,
    metrics: NativeTunMetrics,
}

impl NativeTcpForwarder {
    pub fn new(egress_tx: mpsc::Sender<Vec<u8>>, metrics: NativeTunMetrics) -> Self {
        Self {
            sessions: HashMap::new(),
            egress_tx,
            metrics,
        }
    }

    pub fn handle_packet(&mut self, packet: &[u8], _runtime: &std::sync::Arc<Runtime>) {
        let ip_packet = match parse_ip_packet(packet) {
            Ok(pkt) => pkt,
            Err(_) => return,
        };

        let (src_port, dst_port) = extract_transport_ports(&ip_packet);
        if src_port == 0 || dst_port == 0 {
            return;
        }

        let (protocol, src_ip, dst_ip, tcp_payload) = match &ip_packet {
            TunIpPacket::Ipv4(ipv4) => {
                if ipv4.protocol != 6 {
                    return;
                }
                let tcp_header_len = if ipv4.payload.len() >= 12 {
                    ((ipv4.payload[12] >> 4) as usize) * 4
                } else {
                    return;
                };
                let payload = if ipv4.payload.len() > tcp_header_len {
                    ipv4.payload[tcp_header_len..].to_vec()
                } else {
                    Vec::new()
                };
                (
                    FlowProtocol::Tcp,
                    std::net::IpAddr::V4(ipv4.source),
                    std::net::IpAddr::V4(ipv4.destination),
                    payload,
                )
            }
            _ => return,
        };

        let src = SocketAddr::new(src_ip, src_port);
        let dst = SocketAddr::new(dst_ip, dst_port);
        let flow_key = FlowKey { protocol, src, dst };

        let (flags, seq) = match &ip_packet {
            TunIpPacket::Ipv4(ipv4) if ipv4.payload.len() >= 14 => {
                let flags = ipv4.payload[13];
                let seq = u32::from_be_bytes([
                    ipv4.payload[4],
                    ipv4.payload[5],
                    ipv4.payload[6],
                    ipv4.payload[7],
                ]);
                (flags, seq)
            }
            _ => return,
        };

        let is_syn = (flags & 0x02) != 0;
        let is_ack = (flags & 0x10) != 0;
        let is_fin = (flags & 0x01) != 0;
        let is_rst = (flags & 0x04) != 0;

        if is_rst {
            self.sessions.remove(&flow_key);
            return;
        }

        if is_syn && !is_ack {
            // New connection - but check for duplicate SYN
            if self.sessions.contains_key(&flow_key) {
                // Duplicate SYN: resend SYN-ACK instead of creating new session
                self.send_syn_ack(&flow_key, dst_ip, dst_port, src_ip, src_port);
                return;
            }

            if self.sessions.len() >= MAX_SESSIONS {
                self.cleanup_expired_sessions();
            }

            let (data_tx, data_rx) = mpsc::channel(128);
            let session = TcpForwardSession {
                state: TcpSessionState::SynReceived,
                client_next_seq: Arc::new(AtomicU32::new(seq.wrapping_add(1))),
                server_next_seq: Arc::new(AtomicU32::new(1000)),
                bytes_tx: 0,
                last_activity: Instant::now(),
                target: NativeRouteTarget::Direct,
                sniffer: PayloadSniffer::new(),
                data_tx: Some(data_tx),
                data_rx: Some(data_rx),
            };
            self.sessions.insert(flow_key.clone(), session);
            self.metrics.record_tcp_session_opened();
            self.send_syn_ack(&flow_key, dst_ip, dst_port, src_ip, src_port);
        } else if let Some(session) = self.sessions.get_mut(&flow_key) {
            // Ignore data after FIN or RST
            if session.state == TcpSessionState::FinWait || session.state == TcpSessionState::Closed
            {
                return;
            }

            session.last_activity = Instant::now();

            if is_ack && session.state == TcpSessionState::SynReceived {
                session.state = TcpSessionState::Connecting;
            }

            if !tcp_payload.is_empty() {
                session.sniffer.feed(&tcp_payload);
                session.bytes_tx += tcp_payload.len() as u64;

                if let Some(tx) = &session.data_tx {
                    let _ = tx.try_send(tcp_payload.clone());
                }

                let ack_num = seq.wrapping_add(tcp_payload.len() as u32);
                session.client_next_seq.store(ack_num, Ordering::Relaxed);
                let server_seq = session.server_next_seq.load(Ordering::Relaxed);
                self.send_ack(
                    &flow_key,
                    dst_ip,
                    dst_port,
                    src_ip,
                    src_port,
                    seq,
                    tcp_payload.len() as u32,
                    server_seq,
                );
            }

            if is_fin {
                if let Some(session) = self.sessions.get_mut(&flow_key) {
                    session.state = TcpSessionState::FinWait;
                    let server_seq = session.server_next_seq.load(Ordering::Relaxed);
                    self.send_fin_ack(
                        &flow_key, dst_ip, dst_port, src_ip, src_port, seq, server_seq,
                    );
                }
            }
        }
    }

    pub async fn connect_and_pump(
        &mut self,
        flow_key: &FlowKey,
        runtime: &std::sync::Arc<Runtime>,
    ) {
        let session = match self.sessions.get_mut(flow_key) {
            Some(s) if s.state == TcpSessionState::Connecting => s,
            _ => return,
        };

        let host = session
            .sniffer
            .inferred_host()
            .unwrap_or_else(|| flow_key.dst.ip().to_string());
        let destination = Destination::new(host, flow_key.dst.port());
        let decision = runtime.decide(&destination);
        let route = resolve_native_route(runtime, &decision).await;

        session.target = route.target.clone();

        let dst = flow_key.dst;
        let egress_tx = self.egress_tx.clone();
        let flow_key_clone = flow_key.clone();

        let data_rx = session.data_rx.take();
        let server_next_seq = session.server_next_seq.clone();
        let client_next_seq = session.client_next_seq.clone();

        let connect_result: Result<crate::outbound::BoxedStream, anyhow::Error> = match &session
            .target
        {
            NativeRouteTarget::Direct => {
                session.state = TcpSessionState::Established;
                TcpStream::connect(dst)
                    .await
                    .map(|s| Box::new(s) as crate::outbound::BoxedStream)
                    .map_err(|e| e.into())
            }
            NativeRouteTarget::Outbound { name } => {
                session.state = TcpSessionState::Established;
                runtime.connect_named_outbound(name, &destination).await
            }
            NativeRouteTarget::Group { name } => match runtime.resolve_group_member(name).await {
                Ok(resolved) => {
                    session.state = TcpSessionState::Established;
                    runtime
                        .connect_named_outbound(&resolved, &destination)
                        .await
                }
                Err(e) => Err(e),
            },
            NativeRouteTarget::Country { code } => match runtime.resolve_country_best(code).await {
                Ok(resolved) => {
                    session.state = TcpSessionState::Established;
                    runtime
                        .connect_named_outbound(&resolved, &destination)
                        .await
                }
                Err(e) => Err(e),
            },
            NativeRouteTarget::Reject { reason } => {
                session.state = TcpSessionState::Closed;
                Err(anyhow::anyhow!("reject: {}", reason))
            }
            NativeRouteTarget::L3Profile { name } => {
                session.state = TcpSessionState::Closed;
                Err(anyhow::anyhow!(
                    "l3profile '{}' should use raw packet path",
                    name
                ))
            }
        };

        match connect_result {
            Ok(stream) => {
                let (mut read_half, mut write_half) = tokio::io::split(stream);
                let src_ip = flow_key_clone.src.ip();
                let src_port = flow_key_clone.src.port();
                let dst_ip = dst.ip();
                let dst_port = dst.port();

                // Pump data from client to outbound
                let pump_to_server = async move {
                    if let Some(mut rx) = data_rx {
                        while let Some(data) = rx.recv().await {
                            if write_half.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    }
                };

                // Pump data from outbound back to client (via egress)
                let pump_to_client = async move {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match read_half.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let seq = server_next_seq.fetch_add(n as u32, Ordering::Relaxed);
                                let ack = client_next_seq.load(Ordering::Relaxed);
                                let response = build_tcp_data_packet(
                                    dst_ip,
                                    dst_port,
                                    src_ip,
                                    src_port,
                                    &buf[..n],
                                    seq,
                                    ack,
                                );
                                let _ = egress_tx.send(response).await;
                            }
                            Err(_) => break,
                        }
                    }
                };

                tokio::spawn(async move {
                    tokio::select! {
                        _ = pump_to_server => {}
                        _ = pump_to_client => {}
                    }
                });
            }
            Err(e) => {
                tracing::warn!(flow = ?flow_key_clone, error = %e, "native_l4: connect failed");
                session.state = TcpSessionState::Closed;
                // Send RST to client on connect failure
                let server_seq = session.server_next_seq.load(Ordering::Relaxed);
                self.send_rst(
                    dst.ip(),
                    dst.port(),
                    flow_key_clone.src.ip(),
                    flow_key_clone.src.port(),
                    server_seq,
                );
                self.sessions.remove(&flow_key_clone);
            }
        }
    }

    fn send_syn_ack(
        &mut self,
        flow_key: &FlowKey,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
    ) {
        let session = match self.sessions.get(flow_key) {
            Some(s) => s,
            None => return,
        };
        let server_seq = session.server_next_seq.load(Ordering::Relaxed);
        let ack_num = session.client_next_seq.load(Ordering::Relaxed);
        let packet = build_tcp_packet_raw(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            &[],
            0x12,
            server_seq,
            ack_num,
        );
        session
            .server_next_seq
            .store(server_seq.wrapping_add(1), Ordering::Relaxed);
        let _ = self.egress_tx.try_send(packet);
        self.metrics.record_write(0);
    }

    #[allow(clippy::too_many_arguments)]
    fn send_ack(
        &self,
        _flow_key: &FlowKey,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        client_seq: u32,
        data_len: u32,
        server_seq: u32,
    ) {
        let packet = build_tcp_packet_raw(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            &[],
            0x10,
            server_seq,
            client_seq + data_len,
        );
        let _ = self.egress_tx.try_send(packet);
    }

    #[allow(clippy::too_many_arguments)]
    fn send_fin_ack(
        &self,
        _flow_key: &FlowKey,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        client_seq: u32,
        server_seq: u32,
    ) {
        let packet = build_tcp_packet_raw(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            &[],
            0x11,
            server_seq,
            client_seq + 1,
        );
        let _ = self.egress_tx.try_send(packet);
    }

    fn send_rst(
        &self,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
        seq: u32,
    ) {
        let packet = build_tcp_packet_raw(src_ip, src_port, dst_ip, dst_port, &[], 0x04, seq, 0);
        let _ = self.egress_tx.try_send(packet);
    }

    pub fn cleanup_expired_sessions(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, s| now.duration_since(s.last_activity) < SESSION_TIMEOUT);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn pending_connect_sessions(&self) -> Vec<FlowKey> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.state == TcpSessionState::Connecting)
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tcp_packet_raw(
    src_ip: std::net::IpAddr,
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    data: &[u8],
    flags: u8,
    seq: u32,
    ack_num: u32,
) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0x45);
    packet.push(0x00);
    let total_len = (20 + 20 + data.len()) as u16;
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    match src_ip {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    match dst_ip {
        std::net::IpAddr::V4(ip) => packet.extend_from_slice(&ip.octets()),
        _ => packet.extend_from_slice(&[0, 0, 0, 0]),
    }
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&ack_num.to_be_bytes());
    packet.push(0x50);
    packet.push(flags);
    packet.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(data);

    if let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) = (src_ip, dst_ip) {
        let ip_checksum = ipv4_checksum(&packet[..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        let tcp_checksum = tcp_checksum_ipv4(src, dst, &packet[20..]);
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = (tcp_checksum & 0xFF) as u8;
    }

    packet
}

fn build_tcp_data_packet(
    src_ip: std::net::IpAddr,
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    data: &[u8],
    seq: u32,
    ack_num: u32,
) -> Vec<u8> {
    build_tcp_packet_raw(src_ip, src_port, dst_ip, dst_port, data, 0x18, seq, ack_num)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    ones_complement_checksum(header)
}

fn tcp_checksum_ipv4(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let checksum = ones_complement_checksum(&pseudo);
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn extract_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }
    let handshake = &data[5..5 + record_len];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let mut offset = 4 + 2 + 32;
    if handshake.len() < offset + 1 {
        return None;
    }
    let session_id_len = handshake[offset] as usize;
    offset += 1 + session_id_len;

    if handshake.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if handshake.len() < offset + 1 {
        return None;
    }
    let compression_len = handshake[offset] as usize;
    offset += 1 + compression_len;

    if handshake.len() < offset + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    if handshake.len() < extensions_end {
        return None;
    }

    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]);
        let ext_len = u16::from_be_bytes([handshake[offset + 2], handshake[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > extensions_end {
            break;
        }

        if ext_type == 0x0000 && ext_len >= 5 {
            let sni_list_len =
                u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
            let mut sni_offset = offset + 2;
            if sni_list_len > 0 && sni_offset + 3 <= offset + ext_len {
                let name_type = handshake[sni_offset];
                sni_offset += 1;
                if name_type == 0 {
                    let name_len =
                        u16::from_be_bytes([handshake[sni_offset], handshake[sni_offset + 1]])
                            as usize;
                    sni_offset += 2;
                    if sni_offset + name_len <= offset + ext_len {
                        if let Ok(sni) =
                            std::str::from_utf8(&handshake[sni_offset..sni_offset + name_len])
                        {
                            return Some(sni.to_string());
                        }
                    }
                }
            }
        }
        offset += ext_len;
    }
    None
}
