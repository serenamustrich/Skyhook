use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::native_tun_dns::DnsCache;
use super::native_tun_flow::FlowKey;
use super::native_tun_process::ProcessResolver;
use super::native_tun_router::NativeRouteTarget;
use super::native_tun_stack::{NativeTunStack, StackEvent};
use crate::core::Runtime;
use crate::outbound::BoxedStream;
use crate::routing::Destination;

const SNIFF_TIMEOUT: Duration = Duration::from_millis(100);
const SNIFF_MAX_BYTES: usize = 4096;

type SessionRead = tokio::io::ReadHalf<BoxedStream>;
type SessionWrite = tokio::io::WriteHalf<BoxedStream>;

pub struct NativeSessionManager {
    stack: NativeTunStack,
    sessions: HashMap<FlowKey, NativeSession>,
    start_time: Instant,
    dns_cache: Arc<DnsCache>,
    process_resolver: Arc<ProcessResolver>,
}

struct NativeSession {
    target: NativeRouteTarget,
    state: SessionState,
    outbound: Option<SessionWrite>,
    inbound: Option<SessionRead>,
    sniffer: PayloadSniffer,
    bytes_tx: u64,
    bytes_rx: u64,
}

#[derive(PartialEq)]
enum SessionState {
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
    pub fn new() -> Self {
        Self {
            stack: NativeTunStack::new(),
            sessions: HashMap::new(),
            start_time: Instant::now(),
            dns_cache: Arc::new(DnsCache::new()),
            process_resolver: Arc::new(ProcessResolver::new()),
        }
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
                _ => {}
            }
        }

        self.drain_inbound().await;
    }

    pub fn take_pending_writes(&mut self) -> Vec<Vec<u8>> {
        self.stack.take_pending_writes()
    }

    fn handle_tcp_syn(&mut self, flow_key: FlowKey) {
        let local_port = flow_key.dst.port();
        self.stack.create_tcp_socket(flow_key.clone(), local_port);

        let session = NativeSession {
            target: NativeRouteTarget::Direct,
            state: SessionState::WaitingForPayload,
            outbound: None,
            inbound: None,
            sniffer: PayloadSniffer::new(),
            bytes_tx: 0,
            bytes_rx: 0,
        };
        self.sessions.insert(flow_key, session);
    }

    async fn handle_tcp_data(&mut self, flow_key: &FlowKey, data: &[u8], runtime: &Arc<Runtime>) {
        let handle = self.stack.tcp_handles().get(flow_key).copied();

        let session = match self.sessions.get_mut(flow_key) {
            Some(s) => s,
            None => return,
        };

        if session.state == SessionState::Closed {
            return;
        }

        if session.state == SessionState::Established {
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
                        session.state = SessionState::Established;

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
                        session.state = SessionState::Closed;
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
        self.sessions.remove(flow_key);
    }

    async fn drain_inbound(&mut self) {
        let mut to_process = Vec::new();
        let mut to_remove = Vec::new();

        for (flow_key, session) in &mut self.sessions {
            if session.state != SessionState::Established {
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
            if let Some(session) = self.sessions.get_mut(&flow_key) {
                session.bytes_rx += buf.len() as u64;
            }
        }
    }
}
