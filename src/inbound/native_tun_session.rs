use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::native_tun_dns::DnsCache;
use super::native_tun_flow::FlowKey;
use super::native_tun_metrics::NativeTunMetrics;
use super::native_tun_packet::{
    build_ipv4_udp_response, extract_transport_ports, parse_ip_packet, parse_udp_datagram,
    TunIpPacket,
};
use super::native_tun_process::ProcessResolver;
use super::native_tun_router::NativeRouteTarget;
use super::native_tun_stack::{NativeTunStack, StackEvent};
use crate::core::Runtime;
use crate::outbound::BoxedStream;
use crate::routing::Destination;

const SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const SNIFF_MAX_BYTES: usize = 4096;
const DEFAULT_UDP_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

type SessionRead = tokio::io::ReadHalf<BoxedStream>;
type SessionWrite = tokio::io::WriteHalf<BoxedStream>;

pub struct NativeSessionManager {
    stack: NativeTunStack,
    tcp_sessions: HashMap<FlowKey, TcpSession>,
    udp_sessions: HashMap<FlowKey, UdpSession>,
    start_time: Instant,
    dns_cache: Arc<DnsCache>,
    process_resolver: Arc<ProcessResolver>,
    metrics: NativeTunMetrics,
    udp_response_timeout: Duration,
}

struct TcpSession {
    target: NativeRouteTarget,
    state: TcpSessionState,
    outbound: Option<SessionWrite>,
    inbound: Option<SessionRead>,
    sniffer: PayloadSniffer,
    bytes_tx: u64,
    bytes_rx: u64,
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    bytes_tx: u64,
    bytes_rx: u64,
    last_activity: Instant,
}

#[derive(PartialEq)]
enum TcpSessionState {
    WaitingForPayload,
    Established,
    Closed,
}

struct PayloadSniffer {
    buffer: Vec<u8>,
    start_time: Instant,
}

impl PayloadSniffer {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            start_time: Instant::now(),
        }
    }

    fn feed(&mut self, data: &[u8]) -> SniffResult {
        self.buffer.extend_from_slice(data);

        if extract_tls_sni_from_buffer(&self.buffer).is_some() {
            return SniffResult::Found;
        }

        if extract_http_host_from_buffer(&self.buffer).is_some() {
            return SniffResult::Found;
        }

        if self.buffer.len() >= SNIFF_MAX_BYTES || self.start_time.elapsed() >= SNIFF_TIMEOUT {
            return SniffResult::Expired;
        }

        SniffResult::NeedMore
    }

    fn inferred_host(&self) -> Option<String> {
        extract_tls_sni_from_buffer(&self.buffer)
            .or_else(|| extract_http_host_from_buffer(&self.buffer))
    }
}

enum SniffResult {
    NeedMore,
    Found,
    Expired,
}

fn extract_tls_sni_from_buffer(data: &[u8]) -> Option<String> {
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

    let mut offset = 4 + 2 + 32; // skip header + version + random
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

fn extract_http_host_from_buffer(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;

    if !text.starts_with("GET ")
        && !text.starts_with("POST ")
        && !text.starts_with("CONNECT ")
        && !text.starts_with("HEAD ")
        && !text.starts_with("PUT ")
    {
        return None;
    }

    for line in text.lines() {
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            return Some(rest.trim().to_string());
        }
    }

    None
}

impl NativeSessionManager {
    pub fn new(metrics: NativeTunMetrics) -> Self {
        Self {
            stack: NativeTunStack::new(),
            tcp_sessions: HashMap::new(),
            udp_sessions: HashMap::new(),
            start_time: Instant::now(),
            dns_cache: Arc::new(DnsCache::new()),
            process_resolver: Arc::new(ProcessResolver::new()),
            metrics,
            udp_response_timeout: DEFAULT_UDP_RESPONSE_TIMEOUT,
        }
    }

    pub fn with_udp_response_timeout(mut self, timeout: Duration) -> Self {
        self.udp_response_timeout = timeout;
        self
    }

    pub fn set_udp_response_timeout(&mut self, timeout: Duration) {
        self.udp_response_timeout = timeout;
    }

    pub fn dns_cache(&self) -> &Arc<DnsCache> {
        &self.dns_cache
    }

    pub fn process_resolver(&self) -> &Arc<ProcessResolver> {
        &self.process_resolver
    }

    pub fn stack_mut(&mut self) -> &mut NativeTunStack {
        &mut self.stack
    }

    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.stack.inject_packet(packet);
    }

    pub async fn process_events(&mut self, runtime: &Arc<Runtime>) {
        // Pre-parse injected packets to detect SYN and create sockets before polling
        self.prepare_tcp_sockets_for_syn_packets();

        let events = self.stack.poll(self.start_time);

        for event in events {
            match event {
                StackEvent::TcpSynReceived { flow_key, .. } => {
                    self.handle_tcp_syn(flow_key);
                }
                StackEvent::TcpData { flow_key, data } => {
                    self.handle_tcp_data(&flow_key, &data, runtime).await;
                }
                StackEvent::TcpClosed { flow_key } => {
                    self.handle_tcp_close(&flow_key);
                }
                StackEvent::UdpDatagram {
                    flow_key,
                    data,
                    src_endpoint: _,
                    dst_endpoint,
                } => {
                    self.handle_udp_datagram(&flow_key, &data, dst_endpoint, runtime)
                        .await;
                }
            }
        }

        self.drain_tcp_inbound().await;
        self.drain_udp_inbound().await;
        self.cleanup_expired_udp_sessions();
    }

    pub fn take_pending_writes(&mut self) -> Vec<Vec<u8>> {
        self.stack.take_pending_writes()
    }

    pub async fn handle_udp_packet(
        &mut self,
        packet: Vec<u8>,
        flow_key: &FlowKey,
        runtime: &Arc<Runtime>,
    ) -> Option<Vec<u8>> {
        let ip_packet = parse_ip_packet(&packet).ok()?;
        let (src_addr, dst_addr, payload) = match &ip_packet {
            TunIpPacket::Ipv4(ipv4) if ipv4.protocol == 17 => {
                let udp = parse_udp_datagram(&ipv4.payload).ok()?;
                (
                    SocketAddr::new(std::net::IpAddr::V4(ipv4.source), udp.source_port),
                    SocketAddr::new(std::net::IpAddr::V4(ipv4.destination), udp.dest_port),
                    udp.payload,
                )
            }
            TunIpPacket::Ipv6(ipv6) if ipv6.next_header == 17 => {
                let udp = parse_udp_datagram(&ipv6.payload).ok()?;
                (
                    SocketAddr::new(std::net::IpAddr::V6(ipv6.source), udp.source_port),
                    SocketAddr::new(std::net::IpAddr::V6(ipv6.destination), udp.dest_port),
                    udp.payload,
                )
            }
            _ => return None,
        };

        let host = self
            .dns_cache
            .lookup(&dst_addr.ip())
            .unwrap_or_else(|| dst_addr.ip().to_string());
        let mut destination = Destination::new(host, dst_addr.port());

        if let Some(proc_meta) = self.process_resolver.resolve(&src_addr) {
            if let Some(name) = proc_meta.process_name {
                destination.app = Some(crate::routing::AppIdentity {
                    name: Some(name),
                    path: proc_meta.executable_path,
                    bundle_id: proc_meta.bundle_id,
                });
            }
        }

        let decision = runtime.decide(&destination);
        let route = super::native_tun_router::resolve_native_route(runtime, &decision).await;

        match route.target {
            NativeRouteTarget::Direct => {
                self.metrics.record_direct_session();
                let timeout = self.udp_response_timeout;
                Self::udp_direct_exchange_with_timeout(src_addr, dst_addr, &payload, timeout).await
            }
            NativeRouteTarget::Outbound { name } => {
                self.metrics.record_proxy_session();
                runtime
                    .udp_exchange_named_outbound(&name, &destination, &payload)
                    .await
                    .ok()
                    .and_then(|response| {
                        build_udp_packet(
                            dst_addr.ip(),
                            dst_addr.port(),
                            src_addr.ip(),
                            src_addr.port(),
                            &response,
                        )
                    })
            }
            NativeRouteTarget::Group { name } => match runtime.resolve_group_member(&name).await {
                Ok(resolved) => {
                    self.metrics.record_group_resolved_session();
                    runtime
                        .udp_exchange_named_outbound(&resolved, &destination, &payload)
                        .await
                        .ok()
                        .and_then(|response| {
                            build_udp_packet(
                                dst_addr.ip(),
                                dst_addr.port(),
                                src_addr.ip(),
                                src_addr.port(),
                                &response,
                            )
                        })
                }
                Err(error) => {
                    tracing::warn!(flow = ?flow_key, group = %name, error = %error, "native_l4: udp group resolve failed");
                    None
                }
            },
            NativeRouteTarget::Country { code } => {
                match runtime.resolve_country_best(&code).await {
                    Ok(resolved) => {
                        self.metrics.record_country_resolved_session();
                        runtime
                            .udp_exchange_named_outbound(&resolved, &destination, &payload)
                            .await
                            .ok()
                            .and_then(|response| {
                                build_udp_packet(
                                    dst_addr.ip(),
                                    dst_addr.port(),
                                    src_addr.ip(),
                                    src_addr.port(),
                                    &response,
                                )
                            })
                    }
                    Err(error) => {
                        tracing::warn!(flow = ?flow_key, country = %code, error = %error, "native_l4: udp country resolve failed");
                        None
                    }
                }
            }
            NativeRouteTarget::Reject { reason } => {
                self.metrics.record_dropped(reason);
                None
            }
            NativeRouteTarget::L3Profile { .. } => None,
        }
    }

    async fn udp_direct_exchange_with_timeout(
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        let bind_addr = if dst_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await.ok()?;
        socket.send_to(payload, dst_addr).await.ok()?;
        let mut buf = vec![0u8; 65535];
        let (n, remote) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        buf.truncate(n);
        build_udp_packet(
            remote.ip(),
            remote.port(),
            src_addr.ip(),
            src_addr.port(),
            &buf,
        )
    }

    fn prepare_tcp_sockets_for_syn_packets(&mut self) {
        // Parse injected packets to detect TCP SYN and create listening sockets
        // This must happen before poll() so smoltcp can accept the connection
        let packets_to_check: Vec<Vec<u8>> = self.stack.peek_rx_packets();
        for packet in &packets_to_check {
            if let Ok(ip_packet) = parse_ip_packet(packet) {
                let (src_port, dst_port) = extract_transport_ports(&ip_packet);
                if src_port == 0 || dst_port == 0 {
                    continue;
                }

                let (protocol, src_ip, dst_ip) = match &ip_packet {
                    TunIpPacket::Ipv4(ipv4) => {
                        if ipv4.protocol != 6 {
                            continue; // Only TCP
                        }
                        (
                            super::native_tun_flow::FlowProtocol::Tcp,
                            std::net::IpAddr::V4(ipv4.source),
                            std::net::IpAddr::V4(ipv4.destination),
                        )
                    }
                    TunIpPacket::Ipv6(ipv6) => {
                        if ipv6.next_header != 6 {
                            continue;
                        }
                        (
                            super::native_tun_flow::FlowProtocol::Tcp,
                            std::net::IpAddr::V6(ipv6.source),
                            std::net::IpAddr::V6(ipv6.destination),
                        )
                    }
                };

                let src = std::net::SocketAddr::new(src_ip, src_port);
                let dst = std::net::SocketAddr::new(dst_ip, dst_port);
                let flow_key = FlowKey { protocol, src, dst };

                // Check if this is a SYN packet (first byte of TCP payload)
                if let TunIpPacket::Ipv4(ipv4) = &ip_packet {
                    let tcp_header_len = if ipv4.payload.len() >= 12 {
                        ((ipv4.payload[12] >> 4) as usize) * 4
                    } else {
                        continue;
                    };
                    if ipv4.payload.len() > tcp_header_len {
                        continue; // Has payload, not a pure SYN
                    }
                    if ipv4.payload.len() >= 14 {
                        let flags = ipv4.payload[13];
                        let is_syn = (flags & 0x02) != 0;
                        let is_ack = (flags & 0x10) != 0;
                        if is_syn && !is_ack && !self.tcp_sessions.contains_key(&flow_key) {
                            self.handle_tcp_syn(flow_key);
                        }
                    }
                }
            }
        }
    }

    fn handle_tcp_syn(&mut self, flow_key: FlowKey) {
        let local_port = flow_key.dst.port();
        self.stack.create_tcp_socket(flow_key.clone(), local_port);

        let session = TcpSession {
            target: NativeRouteTarget::Direct,
            state: TcpSessionState::WaitingForPayload,
            outbound: None,
            inbound: None,
            sniffer: PayloadSniffer::new(),
            bytes_tx: 0,
            bytes_rx: 0,
        };
        self.tcp_sessions.insert(flow_key, session);
        self.metrics.record_tcp_session_opened();
    }

    async fn handle_tcp_data(&mut self, flow_key: &FlowKey, data: &[u8], runtime: &Arc<Runtime>) {
        let handle = self.stack.tcp_handles().get(flow_key).copied();

        let session = match self.tcp_sessions.get_mut(flow_key) {
            Some(s) => s,
            None => return,
        };

        if session.state == TcpSessionState::Closed {
            return;
        }

        if session.state == TcpSessionState::Established {
            if let Some(write_half) = &mut session.outbound {
                let _ = write_half.write_all(data).await;
                session.bytes_tx += data.len() as u64;
            }
            return;
        }

        let sniff_result = session.sniffer.feed(data);

        match sniff_result {
            SniffResult::NeedMore => {}
            SniffResult::Found | SniffResult::Expired => {
                let dst_addr = flow_key.dst;
                let src_addr = flow_key.src;
                let host = session
                    .sniffer
                    .inferred_host()
                    .or_else(|| self.dns_cache.lookup(&dst_addr.ip()))
                    .unwrap_or_else(|| dst_addr.ip().to_string());
                let mut destination = Destination::new(host, dst_addr.port());

                if let Some(proc_meta) = self.process_resolver.resolve(&src_addr) {
                    if let Some(name) = proc_meta.process_name {
                        destination.app = Some(crate::routing::AppIdentity {
                            name: Some(name),
                            path: proc_meta.executable_path,
                            bundle_id: proc_meta.bundle_id,
                        });
                    }
                }

                let decision = runtime.decide(&destination);
                let route =
                    super::native_tun_router::resolve_native_route(runtime, &decision).await;

                session.target = route.target.clone();

                let connect_result =
                    Self::connect_for_target(&session.target, &destination, dst_addr, runtime)
                        .await;

                match connect_result {
                    Ok(stream) => {
                        let (read_half, write_half) = tokio::io::split(stream);
                        session.outbound = Some(write_half);
                        session.inbound = Some(read_half);
                        session.state = TcpSessionState::Established;

                        // Track metrics based on route target
                        match &session.target {
                            NativeRouteTarget::Direct => self.metrics.record_direct_session(),
                            NativeRouteTarget::Outbound { .. } => {
                                self.metrics.record_proxy_session()
                            }
                            NativeRouteTarget::Group { .. } => {
                                self.metrics.record_group_resolved_session()
                            }
                            NativeRouteTarget::Country { .. } => {
                                self.metrics.record_country_resolved_session()
                            }
                            _ => {}
                        }

                        // Send sniffer buffer to outbound
                        let sniffer_buffer = session.sniffer.buffer.clone();
                        if !sniffer_buffer.is_empty() {
                            if let Some(write_half) = &mut session.outbound {
                                let _ = write_half.write_all(&sniffer_buffer).await;
                                session.bytes_tx += sniffer_buffer.len() as u64;
                            }
                        }

                        // Send current data to outbound
                        if !data.is_empty() {
                            if let Some(write_half) = &mut session.outbound {
                                let _ = write_half.write_all(data).await;
                                session.bytes_tx += data.len() as u64;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(flow = ?flow_key, error = %e, "native_l4: connect failed");
                        if let Some(h) = handle {
                            self.stack.tcp_abort(h);
                        }
                        session.state = TcpSessionState::Closed;
                    }
                }
            }
        }
    }

    async fn connect_for_target(
        target: &NativeRouteTarget,
        destination: &Destination,
        dst_addr: std::net::SocketAddr,
        runtime: &Arc<Runtime>,
    ) -> anyhow::Result<BoxedStream> {
        match target {
            NativeRouteTarget::Direct => {
                tracing::info!(dest = %destination.authority(), "native_l4: connecting direct");
                let stream = TcpStream::connect(dst_addr).await?;
                Ok(Box::new(stream))
            }
            NativeRouteTarget::Outbound { name } => {
                tracing::info!(dest = %destination.authority(), outbound = %name, "native_l4: connecting outbound");
                runtime.connect_named_outbound(name, destination).await
            }
            NativeRouteTarget::Group { name } => {
                let resolved = runtime.resolve_group_member(name).await?;
                tracing::info!(dest = %destination.authority(), group = %name, resolved = %resolved, "native_l4: connecting via group");
                runtime.connect_named_outbound(&resolved, destination).await
            }
            NativeRouteTarget::Country { code } => {
                let resolved = runtime.resolve_country_best(code).await?;
                tracing::info!(dest = %destination.authority(), country = %code, resolved = %resolved, "native_l4: connecting via country");
                runtime.connect_named_outbound(&resolved, destination).await
            }
            NativeRouteTarget::Reject { reason } => {
                tracing::info!(dest = %destination.authority(), reason = %reason, "native_l4: rejecting");
                Err(anyhow::anyhow!("reject: {}", reason))
            }
            NativeRouteTarget::L3Profile { name } => {
                tracing::debug!(dest = %destination.authority(), profile = %name, "native_l4: l3profile should use raw path");
                Err(anyhow::anyhow!(
                    "l3profile '{}' should use raw packet path",
                    name
                ))
            }
        }
    }

    fn handle_tcp_close(&mut self, flow_key: &FlowKey) {
        if self.tcp_sessions.remove(flow_key).is_some() {
            self.metrics.record_tcp_session_closed();
        }
    }

    async fn handle_udp_datagram(
        &mut self,
        flow_key: &FlowKey,
        data: &[u8],
        dst_endpoint: smoltcp::wire::IpEndpoint,
        runtime: &Arc<Runtime>,
    ) {
        let dst_addr = SocketAddr::new(dst_endpoint.addr.into(), dst_endpoint.port);

        if let Some(session) = self.udp_sessions.get_mut(flow_key) {
            session.socket.send_to(data, dst_addr).await.ok();
            session.bytes_tx += data.len() as u64;
            session.last_activity = Instant::now();
            return;
        }

        let src_addr = flow_key.src;
        let host = self
            .dns_cache
            .lookup(&dst_addr.ip())
            .unwrap_or_else(|| dst_addr.ip().to_string());
        let mut destination = Destination::new(host, dst_addr.port());

        if let Some(proc_meta) = self.process_resolver.resolve(&src_addr) {
            if let Some(name) = proc_meta.process_name {
                destination.app = Some(crate::routing::AppIdentity {
                    name: Some(name),
                    path: proc_meta.executable_path,
                    bundle_id: proc_meta.bundle_id,
                });
            }
        }

        let decision = runtime.decide(&destination);
        let route = super::native_tun_router::resolve_native_route(runtime, &decision).await;

        match &route.target {
            NativeRouteTarget::Direct => {
                let socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        tracing::warn!(flow = ?flow_key, error = %e, "native_l4: udp bind failed");
                        return;
                    }
                };

                if let Err(e) = socket.send_to(data, dst_addr).await {
                    tracing::warn!(flow = ?flow_key, error = %e, "native_l4: udp send failed");
                    return;
                }

                let session = UdpSession {
                    socket,
                    bytes_tx: data.len() as u64,
                    bytes_rx: 0,
                    last_activity: Instant::now(),
                };
                self.udp_sessions.insert(flow_key.clone(), session);
                self.metrics.record_udp_session_opened();
                self.metrics.record_direct_session();
                tracing::info!(flow = ?flow_key, dest = %dst_addr, "native_l4: udp session created (direct)");
            }
            NativeRouteTarget::Reject { reason } => {
                self.metrics.record_dropped(reason.clone());
                tracing::info!(flow = ?flow_key, reason = %reason, "native_l4: udp rejected");
            }
            NativeRouteTarget::Outbound { name } => {
                self.metrics.record_proxy_session();
                match runtime
                    .udp_exchange_named_outbound(name, &destination, data)
                    .await
                {
                    Ok(response) => {
                        tracing::info!(flow = ?flow_key, outbound = %name, "native_l4: udp outbound ok");
                        // Build response IP/UDP packet and inject back
                        self.inject_udp_response(flow_key, &response);
                    }
                    Err(e) => {
                        tracing::warn!(flow = ?flow_key, outbound = %name, error = %e, "native_l4: udp outbound failed");
                    }
                }
            }
            NativeRouteTarget::Group { name } => match runtime.resolve_group_member(name).await {
                Ok(resolved) => {
                    match runtime
                        .udp_exchange_named_outbound(&resolved, &destination, data)
                        .await
                    {
                        Ok(response) => {
                            tracing::info!(flow = ?flow_key, group = %name, resolved = %resolved, "native_l4: udp group ok");
                            self.inject_udp_response(flow_key, &response);
                        }
                        Err(e) => {
                            tracing::warn!(flow = ?flow_key, group = %name, resolved = %resolved, error = %e, "native_l4: udp group failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(flow = ?flow_key, group = %name, error = %e, "native_l4: udp group resolve failed");
                }
            },
            NativeRouteTarget::Country { code } => match runtime.resolve_country_best(code).await {
                Ok(resolved) => {
                    match runtime
                        .udp_exchange_named_outbound(&resolved, &destination, data)
                        .await
                    {
                        Ok(response) => {
                            tracing::info!(flow = ?flow_key, country = %code, resolved = %resolved, "native_l4: udp country ok");
                            self.inject_udp_response(flow_key, &response);
                        }
                        Err(e) => {
                            tracing::warn!(flow = ?flow_key, country = %code, resolved = %resolved, error = %e, "native_l4: udp country failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(flow = ?flow_key, country = %code, error = %e, "native_l4: udp country resolve failed");
                }
            },
            NativeRouteTarget::L3Profile { name } => {
                tracing::debug!(flow = ?flow_key, profile = %name, "native_l4: udp l3profile should use raw path");
            }
        }
    }

    fn inject_udp_response(&mut self, flow_key: &FlowKey, response: &[u8]) {
        // Build a UDP response packet and inject it back into the stack
        // This creates an IP/UDP packet from the response data
        let src_ip = flow_key.dst.ip();
        let src_port = flow_key.dst.port();
        let dst_ip = flow_key.src.ip();
        let dst_port = flow_key.src.port();

        let packet = build_udp_packet(src_ip, src_port, dst_ip, dst_port, response);
        if let Some(packet) = packet {
            self.stack.inject_packet(packet);
        }
    }

    async fn drain_tcp_inbound(&mut self) {
        let mut to_process = Vec::new();
        let mut to_remove = Vec::new();

        for (flow_key, session) in &mut self.tcp_sessions {
            if session.state != TcpSessionState::Established {
                continue;
            }
            if let Some(read_half) = &mut session.inbound {
                let mut buf = vec![0u8; 8192];
                match tokio::time::timeout(Duration::from_millis(0), read_half.read(&mut buf)).await
                {
                    Ok(Ok(0)) => {
                        to_remove.push(flow_key.clone());
                    }
                    Ok(Ok(n)) => {
                        buf.truncate(n);
                        to_process.push((flow_key.clone(), buf));
                    }
                    Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Ok(Err(_)) => {
                        to_remove.push(flow_key.clone());
                    }
                    Err(_) => {
                        // timeout - no data available, skip
                    }
                }
            }
        }

        for flow_key in to_remove {
            self.handle_tcp_close(&flow_key);
        }

        for (flow_key, buf) in to_process {
            if let Some(handle) = self.stack.tcp_handles().get(&flow_key).copied() {
                self.stack.tcp_send(handle, &buf);
            }
            if let Some(session) = self.tcp_sessions.get_mut(&flow_key) {
                session.bytes_rx += buf.len() as u64;
            }
        }
    }

    async fn drain_udp_inbound(&mut self) {
        let mut to_process = Vec::new();

        for (flow_key, session) in &mut self.udp_sessions {
            let mut buf = vec![0u8; 65535];
            if let Ok(Ok((n, _src_addr))) =
                tokio::time::timeout(Duration::from_millis(0), session.socket.recv_from(&mut buf))
                    .await
            {
                buf.truncate(n);
                to_process.push((flow_key.clone(), buf));
            }
        }

        for (flow_key, buf) in to_process {
            if let Some(session) = self.udp_sessions.get_mut(&flow_key) {
                session.bytes_rx += buf.len() as u64;
                session.last_activity = Instant::now();
            }
        }
    }

    fn cleanup_expired_udp_sessions(&mut self) {
        let before = self.udp_sessions.len();
        self.udp_sessions
            .retain(|_, session| session.last_activity.elapsed() < UDP_IDLE_TIMEOUT);
        let closed = before - self.udp_sessions.len();
        for _ in 0..closed {
            self.metrics.record_udp_session_closed();
        }
    }
}

fn build_udp_packet(
    src_ip: std::net::IpAddr,
    src_port: u16,
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    match (src_ip, dst_ip) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            Some(build_ipv4_udp_response(src, dst, src_port, dst_port, data))
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            Some(build_ipv6_udp_response(src, dst, src_port, dst_port, data))
        }
        _ => None,
    }
}

fn build_ipv6_udp_response(
    source: std::net::Ipv6Addr,
    dest: std::net::Ipv6Addr,
    source_port: u16,
    dest_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let mut packet = Vec::with_capacity(40 + udp_length);

    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
    packet.push(17);
    packet.push(64);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&dest.octets());

    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&dest_port.to_be_bytes());
    packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(payload);

    let udp_checksum = calculate_udp_checksum_ipv6(source, dest, &packet[40..]);
    packet[46] = (udp_checksum >> 8) as u8;
    packet[47] = (udp_checksum & 0xFF) as u8;
    packet
}

fn calculate_udp_checksum_ipv6(
    source: std::net::Ipv6Addr,
    dest: std::net::Ipv6Addr,
    udp_segment: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&dest.octets());
    pseudo.extend_from_slice(&(udp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(17);
    pseudo.extend_from_slice(udp_segment);
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
