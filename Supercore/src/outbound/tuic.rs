use std::{
    collections::HashMap,
    io::Error,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex as TokioMutex,
    time::timeout,
};
use uuid::Uuid;

use crate::routing::Destination;

use super::{
    transports::{
        connect_quic_endpoint, create_quic_endpoint, quic_client_config, random_u16,
        resolve_quic_remote,
    },
    udp::{RoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct TuicOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    congestion_control: Option<String>,
    udp_relay_mode: Option<String>,
    alpn: Option<String>,
    udp_sessions: TokioMutex<TuicUdpPool>,
}

#[derive(Default)]
struct TuicUdpPool {
    mode: Option<String>,
    sessions: RoundRobinSessionPool<TuicUdpSession>,
}

struct TuicUdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mode: String,
    associate_id: u16,
    next_packet_id: u16,
}

impl Drop for TuicUdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp(format!(
            "{}-session-pool",
            self.udp_relay_mode.as_deref().unwrap_or("native")
        ))
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let _udp_mode = self.udp_relay_mode.as_deref().unwrap_or("native");
        let _congestion_control = self.congestion_control.as_deref().unwrap_or("default");
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
        let connection = open_tuic_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            self.alpn.as_deref(),
            &user_id,
            &self.password,
            timeout_ms,
        )
        .await?;
        let (mut send, recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("tuic open stream timed out")?
        .context("tuic failed to open bidirectional stream")?;
        let request = build_tuic_connect_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        Ok(Box::new(TuicTcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
            recv,
            send,
        }))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mode = self
            .udp_relay_mode
            .as_deref()
            .unwrap_or("native")
            .to_ascii_lowercase();
        if !matches!(mode.as_str(), "native" | "quic") {
            return Err(anyhow!("unsupported tuic udp relay mode {mode}"));
        }
        let session_handle = self.tuic_udp_session(&mode, timeout_ms).await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let packet_id = session.next_packet_id;
                session.next_packet_id = session.next_packet_id.wrapping_add(1);
                let messages = build_tuic_packet_messages(
                    session.associate_id,
                    packet_id,
                    destination,
                    payload,
                    if session.mode == "quic" {
                        None
                    } else {
                        session.connection.max_datagram_size()
                    },
                )?;
                if session.mode == "quic" {
                    for message in messages {
                        let mut stream = timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.open_uni(),
                        )
                        .await
                        .context("tuic udp stream open timed out")?
                        .context("tuic failed to open udp stream")?;
                        stream.write_all(&message).await?;
                        stream.finish()?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let mut incoming = session.connection.accept_uni().await?;
                            let data = incoming
                                .read_to_end(65_535 + 512)
                                .await
                                .map_err(|error| anyhow!("tuic udp stream read failed: {error}"))?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &data,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp stream receive timed out")?
                } else {
                    for message in messages {
                        timeout(
                            Duration::from_millis(timeout_ms),
                            session.connection.send_datagram_wait(Bytes::from(message)),
                        )
                        .await
                        .context("tuic udp send timed out")?
                        .map_err(|error| anyhow!("tuic udp send failed: {error}"))?;
                    }
                    timeout(Duration::from_millis(timeout_ms), async {
                        let mut reassembly = TuicUdpReassembly::default();
                        loop {
                            let datagram = session.connection.read_datagram().await?;
                            if let Some(payload) = parse_tuic_packet_message(
                                &datagram,
                                session.associate_id,
                                &mut reassembly,
                            )? {
                                return Ok::<Vec<u8>, anyhow::Error>(payload);
                            }
                        }
                    })
                    .await
                    .context("tuic udp datagram receive timed out")?
                }
            }
            .await
        };
        if exchange.is_err() {
            self.remove_tuic_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl TuicOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        uuid: String,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        alpn: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            uuid,
            password,
            sni,
            skip_cert_verify,
            congestion_control,
            udp_relay_mode,
            alpn,
            udp_sessions: TokioMutex::new(TuicUdpPool::default()),
        }
    }

    async fn tuic_udp_session(
        &self,
        mode: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<TuicUdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.mode.as_deref() != Some(mode) {
            pool.sessions.clear();
            pool.mode = Some(mode.to_string());
        }
        if pool.sessions.len() < UDP_SESSION_POOL_SIZE {
            let user_id = Uuid::parse_str(&self.uuid)
                .map_err(|error| anyhow!("invalid tuic uuid for {}: {error}", self.name))?;
            let connection = open_tuic_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                self.alpn.as_deref(),
                &user_id,
                &self.password,
                timeout_ms,
            )
            .await?;
            let session = Arc::new(TokioMutex::new(TuicUdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                mode: mode.to_string(),
                associate_id: random_u16()?,
                next_packet_id: random_u16()?,
            }));
            pool.sessions.push(session.clone());
            return Ok(session);
        }
        pool.sessions
            .next()
            .ok_or_else(|| anyhow!("tuic UDP session pool is unexpectedly empty"))
    }

    async fn remove_tuic_udp_session(&self, target: &Arc<TokioMutex<TuicUdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.sessions.remove(target);
    }
}

struct TuicConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

struct TuicTcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for TuicTcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
    }
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

async fn open_tuic_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    alpn: Option<&str>,
    user_id: &Uuid,
    password: &str,
    timeout_ms: u64,
) -> anyhow::Result<TuicConnection> {
    if password.is_empty() {
        return Err(anyhow!("tuic password is empty"));
    }
    let remote = resolve_quic_remote("tuic", server, port).await?;
    let endpoint = create_quic_endpoint(remote)?;
    let server_name = sni.unwrap_or(server).to_string();
    let (endpoint, connection) = connect_quic_endpoint(
        endpoint,
        remote,
        &server_name,
        quic_client_config(skip_cert_verify, alpn.or(Some("h3")))?,
        timeout_ms,
        "tuic",
    )
    .await?;

    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, user_id.as_bytes(), password.as_bytes())
        .map_err(|_| anyhow!("tuic token export failed"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.extend_from_slice(&[0x05, 0x00]);
    auth.extend_from_slice(user_id.as_bytes());
    auth.extend_from_slice(&token);
    let mut stream = timeout(Duration::from_millis(timeout_ms), connection.open_uni())
        .await
        .context("tuic auth stream timed out")?
        .context("tuic failed to open auth stream")?;
    stream.write_all(&auth).await?;
    stream.finish()?;

    Ok(TuicConnection {
        endpoint,
        connection,
    })
}

pub(super) fn build_tuic_connect_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(32 + destination.host.len());
    output.extend_from_slice(&[0x05, 0x01]);
    encode_tuic_address(destination, &mut output)?;
    Ok(output)
}

#[derive(Default)]
pub(super) struct TuicUdpReassembly {
    packets: HashMap<u16, TuicUdpFragmentSet>,
}

struct TuicUdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

pub(super) fn build_tuic_packet_messages(
    associate_id: u16,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let single = build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, payload)?;
    let header_len =
        build_tuic_packet_fragment(associate_id, packet_id, 1, 0, destination, &[])?.len();
    let max_payload_len = match max_datagram_size {
        Some(max_size) => {
            if single.len() <= max_size {
                return Ok(vec![single]);
            }
            if header_len >= max_size {
                return Err(anyhow!(
                    "tuic udp header is too large for quic datagram: {} >= {}",
                    header_len,
                    max_size
                ));
            }
            (max_size - header_len).min(u16::MAX as usize)
        }
        None => {
            if payload.len() <= u16::MAX as usize {
                return Ok(vec![single]);
            }
            u16::MAX as usize
        }
    };
    let fragment_total = payload.len().div_ceil(max_payload_len);
    if fragment_total > u8::MAX as usize {
        return Err(anyhow!(
            "tuic udp payload needs too many fragments: {fragment_total}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_total);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_tuic_packet_fragment(
            associate_id,
            packet_id,
            fragment_total as u8,
            index as u8,
            destination,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_tuic_packet_fragment(
    associate_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: &Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(anyhow!("tuic udp fragment payload is too large"));
    }
    let mut output = Vec::with_capacity(48 + destination.host.len() + payload.len());
    output.extend_from_slice(&[0x05, 0x02]);
    output.extend_from_slice(&associate_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_total);
    output.push(fragment_id);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_tuic_address(destination, &mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

pub(super) fn parse_tuic_packet_message(
    data: &[u8],
    expected_associate_id: u16,
    reassembly: &mut TuicUdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if data.len() < 10 || data[0] != 0x05 || data[1] != 0x02 {
        return Ok(None);
    }
    let associate_id = u16::from_be_bytes([data[2], data[3]]);
    if associate_id != expected_associate_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let fragment_total = data[6];
    let fragment_id = data[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(anyhow!(
            "invalid tuic udp fragment id/count: {fragment_id}/{fragment_total}"
        ));
    }
    let payload_len = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mut cursor = 10;
    skip_tuic_address(data, &mut cursor)?;
    if cursor + payload_len > data.len() {
        return Err(anyhow!("tuic udp payload length exceeds packet"));
    }
    let payload = data[cursor..cursor + payload_len].to_vec();
    if fragment_total == 1 {
        return Ok(Some(payload));
    }
    push_tuic_udp_fragment(reassembly, packet_id, fragment_id, fragment_total, payload)
}

fn push_tuic_udp_fragment(
    reassembly: &mut TuicUdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| TuicUdpFragmentSet {
            total: fragment_total,
            fragments: vec![None; fragment_total as usize],
        });
    if entry.total != fragment_total {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent tuic udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing tuic udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output.extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing tuic udp fragment"))?);
    }
    Ok(Some(output))
}

fn encode_tuic_address(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    if let Ok(addr) = destination.host.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(addr) => {
                output.push(0x01);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                output.push(0x02);
                output.extend_from_slice(&addr.ip().octets());
                output.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    } else if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x02);
                output.extend_from_slice(&ip.octets());
            }
        }
        output.extend_from_slice(&destination.port.to_be_bytes());
    } else {
        if destination.host.len() > 255 {
            return Err(anyhow!("domain name too long"));
        }
        output.push(0x00);
        output.push(destination.host.len() as u8);
        output.extend_from_slice(destination.host.as_bytes());
        output.extend_from_slice(&destination.port.to_be_bytes());
    }
    Ok(())
}

fn skip_tuic_address(input: &[u8], cursor: &mut usize) -> anyhow::Result<()> {
    if *cursor >= input.len() {
        return Err(anyhow!("tuic address is missing"));
    }
    let address_type = input[*cursor];
    *cursor += 1;
    match address_type {
        0xff => Ok(()),
        0x00 => {
            if *cursor >= input.len() {
                return Err(anyhow!("tuic domain length is missing"));
            }
            let len = input[*cursor] as usize;
            *cursor += 1;
            if *cursor + len + 2 > input.len() {
                return Err(anyhow!("tuic domain address is truncated"));
            }
            *cursor += len + 2;
            Ok(())
        }
        0x01 => {
            if *cursor + 4 + 2 > input.len() {
                return Err(anyhow!("tuic ipv4 address is truncated"));
            }
            *cursor += 4 + 2;
            Ok(())
        }
        0x02 => {
            if *cursor + 16 + 2 > input.len() {
                return Err(anyhow!("tuic ipv6 address is truncated"));
            }
            *cursor += 16 + 2;
            Ok(())
        }
        other => Err(anyhow!("unsupported tuic address type {other}")),
    }
}
