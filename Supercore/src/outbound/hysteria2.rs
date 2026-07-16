use std::{
    collections::HashMap,
    io::{Error, ErrorKind, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use blake2::{digest::VariableOutput, Blake2bVar};
use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex as TokioMutex,
    task::JoinHandle,
    time::timeout,
};

use crate::routing::Destination;

use super::{
    target::destination_socket_addr,
    transports::{
        connect_quic_endpoint, create_quic_endpoint, encode_quic_varint, quic_client_config,
        random_u16, random_u32, read_quic_varint, read_quic_varint_from_slice, resolve_quic_remote,
    },
    udp::{create_bound_std_udp, RoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct Hysteria2Outbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    obfs: Option<String>,
    obfs_password: Option<String>,
    alpn: Option<String>,
    udp_sessions: TokioMutex<Hysteria2UdpPool>,
}

type Hysteria2UdpPool = RoundRobinSessionPool<Hysteria2UdpSession>;

struct Hysteria2UdpSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    session_id: u32,
    next_packet_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hysteria2ObfsKind {
    Salamander,
    Gecko,
}

#[derive(Debug, Clone)]
struct Hysteria2ObfsConfig {
    kind: Hysteria2ObfsKind,
    key: Vec<u8>,
}

impl Drop for Hysteria2UdpSession {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn capability(&self) -> OutboundCapability {
        match hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref()) {
            Ok(config) => OutboundCapability::tcp_udp(match config.map(|item| item.kind) {
                Some(Hysteria2ObfsKind::Salamander) => "quic-datagram-salamander-session-pool",
                Some(Hysteria2ObfsKind::Gecko) => "quic-datagram-gecko-session-pool",
                None => "quic-datagram-session-pool",
            }),
            Err(error) => OutboundCapability::unsupported(error.to_string()),
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let connection = open_hysteria2_connection(
            &self.server,
            self.port,
            self.sni.as_deref(),
            self.skip_cert_verify,
            &self.password,
            self.alpn.as_deref(),
            obfs_config.as_ref(),
            timeout_ms,
        )
        .await?;
        let (mut send, mut recv) = timeout(
            Duration::from_millis(timeout_ms),
            connection.connection.open_bi(),
        )
        .await
        .context("hysteria2 open stream timed out")?
        .context("hysteria2 failed to open bidirectional stream")?;
        let request = build_hysteria2_tcp_request(destination)?;
        send.write_all(&request).await?;
        send.flush().await?;
        read_hysteria2_tcp_response(&mut recv).await?;
        Ok(Box::new(Hysteria2TcpStream {
            _endpoint: connection.endpoint,
            connection: connection.connection,
            h3_driver: connection.h3_driver,
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
        let obfs_config =
            hysteria2_obfs_config(self.obfs.as_deref(), self.obfs_password.as_deref())?;
        let session_handle = self
            .hysteria2_udp_session(obfs_config.as_ref(), timeout_ms)
            .await?;

        let exchange = {
            let mut session = session_handle.lock().await;
            async {
                let packet_id = session.next_packet_id;
                session.next_packet_id = session.next_packet_id.wrapping_add(1);
                let messages = build_hysteria2_udp_messages(
                    session.session_id,
                    packet_id,
                    destination,
                    payload,
                    session.connection.max_datagram_size(),
                )?;
                for message in messages {
                    timeout(
                        Duration::from_millis(timeout_ms),
                        session.connection.send_datagram_wait(Bytes::from(message)),
                    )
                    .await
                    .context("hysteria2 udp send timed out")?
                    .map_err(|error| anyhow!("hysteria2 udp send failed: {error}"))?;
                }
                timeout(Duration::from_millis(timeout_ms), async {
                    let mut reassembly = Hysteria2UdpReassembly::default();
                    loop {
                        let datagram = session.connection.read_datagram().await?;
                        if let Some(payload) = parse_hysteria2_udp_message(
                            &datagram,
                            session.session_id,
                            &mut reassembly,
                        )? {
                            return Ok::<Vec<u8>, anyhow::Error>(payload);
                        }
                    }
                })
                .await
                .context("hysteria2 udp receive timed out")?
            }
            .await
        };
        if exchange.is_err() {
            self.remove_hysteria2_udp_session(&session_handle).await;
        }
        exchange
    }
}

impl Hysteria2Outbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        obfs: Option<String>,
        obfs_password: Option<String>,
        alpn: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            obfs,
            obfs_password,
            alpn,
            udp_sessions: TokioMutex::new(Hysteria2UdpPool::default()),
        }
    }

    async fn hysteria2_udp_session(
        &self,
        obfs_config: Option<&Hysteria2ObfsConfig>,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<Hysteria2UdpSession>>> {
        let mut pool = self.udp_sessions.lock().await;
        if pool.len() < UDP_SESSION_POOL_SIZE {
            let connection = open_hysteria2_connection(
                &self.server,
                self.port,
                self.sni.as_deref(),
                self.skip_cert_verify,
                &self.password,
                self.alpn.as_deref(),
                obfs_config,
                timeout_ms,
            )
            .await?;
            if !connection.udp_supported {
                connection
                    .connection
                    .close(quinn::VarInt::from_u32(0), b"supercore close");
                connection.h3_driver.abort();
                return Err(anyhow!("hysteria2 server does not support udp relay"));
            }
            let session = Arc::new(TokioMutex::new(Hysteria2UdpSession {
                _endpoint: connection.endpoint,
                connection: connection.connection,
                h3_driver: connection.h3_driver,
                session_id: random_u32()?,
                next_packet_id: random_u16()?,
            }));
            pool.push(session.clone());
            return Ok(session);
        }
        pool.next()
            .ok_or_else(|| anyhow!("hysteria2 UDP session pool is unexpectedly empty"))
    }

    async fn remove_hysteria2_udp_session(&self, target: &Arc<TokioMutex<Hysteria2UdpSession>>) {
        let mut pool = self.udp_sessions.lock().await;
        pool.remove(target);
    }
}

struct Hysteria2Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    udp_supported: bool,
}

#[derive(Debug)]
struct SalamanderUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    key: Arc<[u8]>,
    kind: Hysteria2ObfsKind,
    gecko: StdMutex<GeckoState>,
}

impl SalamanderUdpSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, key: &[u8], kind: Hysteria2ObfsKind) -> Self {
        Self {
            inner,
            key: Arc::from(key.to_vec().into_boxed_slice()),
            kind,
            gecko: StdMutex::new(GeckoState::default()),
        }
    }

    fn encode_salamander_packet(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut salt = [0u8; 8];
        getrandom::fill(&mut salt)
            .map_err(|error| Error::new(ErrorKind::Other, format!("salt failed: {error}")))?;
        let mask = salamander_mask(&self.key, &salt)?;
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.extend_from_slice(&salt);
        for (index, byte) in payload.iter().enumerate() {
            packet.push(byte ^ mask[index % mask.len()]);
        }
        Ok(packet)
    }

    fn decode_salamander_packet(&self, packet: &mut [u8], len: usize) -> std::io::Result<usize> {
        if len < 8 {
            return Ok(0);
        }
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&packet[..8]);
        let mask = salamander_mask(&self.key, &salt)?;
        let payload_len = len - 8;
        for payload_index in 0..payload_len {
            packet[payload_index] = packet[payload_index + 8] ^ mask[payload_index % mask.len()];
        }
        Ok(payload_len)
    }
}

impl quinn::AsyncUdpSocket for SalamanderUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "hysteria2 obfs does not support segmented udp transmits",
            ));
        }
        let packets = if self.kind == Hysteria2ObfsKind::Gecko
            && transmit
                .contents
                .first()
                .map(|byte| byte & 0x80 != 0)
                .unwrap_or(false)
        {
            let mut state = self
                .gecko
                .lock()
                .map_err(|_| Error::new(ErrorKind::Other, "gecko state lock poisoned"))?;
            build_gecko_fragments(&mut state, transmit.contents)?
        } else {
            vec![transmit.contents.to_vec()]
        };
        for payload in packets {
            let packet = self.encode_salamander_packet(&payload)?;
            let transmit = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            self.inner.try_send(&transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for index in 0..count {
                    if meta[index].len < 8 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    let len = meta[index].len;
                    let packet = &mut bufs[index][..len];
                    let payload_len = match self.decode_salamander_packet(packet, len) {
                        Ok(payload_len) => payload_len,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    if payload_len == 0 {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                        continue;
                    }
                    if self.kind == Hysteria2ObfsKind::Gecko && packet[0] & 0x80 != 0 {
                        let reassembled = {
                            let mut state = match self.gecko.lock() {
                                Ok(state) => state,
                                Err(_) => {
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::Other,
                                        "gecko state lock poisoned",
                                    )));
                                }
                            };
                            match parse_gecko_fragment(
                                &mut state,
                                meta[index].addr,
                                &packet[..payload_len],
                            ) {
                                Ok(reassembled) => reassembled,
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                        };
                        let Some(reassembled) = reassembled else {
                            meta[index].len = 0;
                            meta[index].stride = 0;
                            continue;
                        };
                        if reassembled.len() > bufs[index].len() {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::InvalidData,
                                "gecko reassembled packet exceeds receive buffer",
                            )));
                        }
                        bufs[index][..reassembled.len()].copy_from_slice(&reassembled);
                        meta[index].len = reassembled.len();
                        meta[index].stride = reassembled.len();
                    } else {
                        meta[index].len = payload_len;
                        meta[index].stride = payload_len;
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Default, Debug)]
struct GeckoState {
    next_msg_id: u8,
    reassembly: HashMap<(SocketAddr, u8), GeckoFragmentSet>,
}

#[derive(Debug)]
struct GeckoFragmentSet {
    total: u8,
    chunks: Vec<Option<Vec<u8>>>,
}

fn build_gecko_fragments(state: &mut GeckoState, payload: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    if payload.len() < 2 {
        return Ok(vec![payload.to_vec()]);
    }
    let max_fragments = payload.len().min(8).max(2);
    let mut random = [0u8; 1];
    getrandom::fill(&mut random)
        .map_err(|error| Error::new(ErrorKind::Other, format!("gecko random failed: {error}")))?;
    let total = 2 + (random[0] as usize % (max_fragments - 1));
    let msg_id = state.next_msg_id;
    state.next_msg_id = state.next_msg_id.wrapping_add(1);

    let mut offset = 0usize;
    let mut frames = Vec::with_capacity(total);
    for index in 0..total {
        let remaining = payload.len() - offset;
        let remaining_fragments = total - index;
        let chunk_len = if remaining_fragments == 1 {
            remaining
        } else {
            let max_len = remaining - (remaining_fragments - 1);
            let mut random = [0u8; 2];
            getrandom::fill(&mut random).map_err(|error| {
                Error::new(
                    ErrorKind::Other,
                    format!("gecko chunk random failed: {error}"),
                )
            })?;
            1 + (u16::from_be_bytes(random) as usize % max_len)
        };
        let chunk = &payload[offset..offset + chunk_len];
        offset += chunk_len;

        let mut random = [0u8; 1];
        getrandom::fill(&mut random).map_err(|error| {
            Error::new(
                ErrorKind::Other,
                format!("gecko padding random failed: {error}"),
            )
        })?;
        let pad_len = random[0] as usize % 64;
        let mut frame = Vec::with_capacity(5 + pad_len + chunk.len());
        frame.push(0x80);
        frame.push(msg_id);
        frame.push(((index as u8) << 4) | total as u8);
        frame.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            let mut padding = vec![0u8; pad_len];
            getrandom::fill(&mut padding).map_err(|error| {
                Error::new(ErrorKind::Other, format!("gecko padding failed: {error}"))
            })?;
            frame.extend_from_slice(&padding);
        }
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

fn parse_gecko_fragment(
    state: &mut GeckoState,
    source: SocketAddr,
    frame: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if frame.len() < 5 || frame[0] != 0x80 {
        return Ok(None);
    }
    let msg_id = frame[1];
    let chunk_idx = frame[2] >> 4;
    let total = frame[2] & 0x0f;
    if !(2..=8).contains(&total) || chunk_idx >= total {
        return Ok(None);
    }
    let pad_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if 5 + pad_len > frame.len() {
        return Ok(None);
    }
    let chunk = frame[5 + pad_len..].to_vec();
    if state.reassembly.len() > 256 {
        state.reassembly.clear();
    }
    let key = (source, msg_id);
    let entry = state
        .reassembly
        .entry(key)
        .or_insert_with(|| GeckoFragmentSet {
            total,
            chunks: vec![None; total as usize],
        });
    if entry.total != total {
        state.reassembly.remove(&key);
        return Ok(None);
    }
    entry.chunks[chunk_idx as usize] = Some(chunk);
    if !entry.chunks.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = state
        .reassembly
        .remove(&key)
        .ok_or_else(|| Error::new(ErrorKind::Other, "gecko reassembly entry missing"))?;
    let mut output = Vec::new();
    for chunk in entry.chunks {
        output.extend_from_slice(
            &chunk.ok_or_else(|| Error::new(ErrorKind::Other, "gecko fragment missing"))?,
        );
    }
    Ok(Some(output))
}

fn salamander_mask(key: &[u8], salt: &[u8; 8]) -> std::io::Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b init failed: {error}")))?;
    blake2::digest::Update::update(&mut hasher, key);
    blake2::digest::Update::update(&mut hasher, salt);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|error| Error::new(ErrorKind::Other, format!("blake2b failed: {error}")))?;
    Ok(output)
}

fn hysteria2_obfs_config(
    obfs: Option<&str>,
    obfs_password: Option<&str>,
) -> anyhow::Result<Option<Hysteria2ObfsConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match obfs.to_ascii_lowercase().as_str() {
        "salamander" | "gecko" => {
            let password = obfs_password
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("hysteria2 {obfs} obfs password is required"))?;
            let kind = if obfs.eq_ignore_ascii_case("gecko") {
                Hysteria2ObfsKind::Gecko
            } else {
                Hysteria2ObfsKind::Salamander
            };
            Ok(Some(Hysteria2ObfsConfig {
                kind,
                key: password.as_bytes().to_vec(),
            }))
        }
        other => Err(anyhow!("unsupported hysteria2 obfs mode {other}")),
    }
}

struct Hysteria2TcpStream {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    h3_driver: JoinHandle<()>,
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl Drop for Hysteria2TcpStream {
    fn drop(&mut self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"supercore close");
        self.h3_driver.abort();
    }
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
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

async fn open_hysteria2_connection(
    server: &str,
    port: u16,
    sni: Option<&str>,
    skip_cert_verify: bool,
    password: &str,
    alpn: Option<&str>,
    obfs_config: Option<&Hysteria2ObfsConfig>,
    timeout_ms: u64,
) -> anyhow::Result<Hysteria2Connection> {
    if password.is_empty() {
        return Err(anyhow!("hysteria2 password is empty"));
    }
    let remote = resolve_quic_remote("hysteria2", server, port).await?;
    let endpoint = if let Some(obfs_config) = obfs_config {
        let socket = create_bound_std_udp(remote)
            .context("failed to bind hysteria2 obfs udp socket")?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let inner = runtime
            .wrap_udp_socket(socket)
            .context("failed to wrap hysteria2 obfs udp socket")?;
        let socket = Arc::new(SalamanderUdpSocket::new(
            inner,
            &obfs_config.key,
            obfs_config.kind,
        ));
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .context("failed to create hysteria2 obfs quic endpoint")?
    } else {
        create_quic_endpoint(remote)?
    };
    let server_name = sni.unwrap_or(server).to_string();
    let (endpoint, connection) = connect_quic_endpoint(
        endpoint,
        remote,
        &server_name,
        quic_client_config(skip_cert_verify, alpn)?,
        timeout_ms,
        "hysteria2",
    )
    .await?;

    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut h3_connection, mut send_request) = h3::client::new(h3_connection)
        .await
        .context("hysteria2 http/3 client init failed")?;
    let h3_driver = tokio::spawn(async move {
        let _ = h3_connection.wait_idle().await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("hysteria-auth", password)
        .header("hysteria-cc-rx", "0")
        .header("hysteria-padding", "supercore")
        .body(())
        .context("failed to build hysteria2 auth request")?;
    let mut stream = match timeout(
        Duration::from_millis(timeout_ms),
        send_request.send_request(request),
    )
    .await
    .context("hysteria2 auth request timed out")?
    {
        Ok(stream) => stream,
        Err(error) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth request failed: {error}"));
        }
    };
    if let Err(error) = stream.finish().await {
        h3_driver.abort();
        return Err(anyhow!("hysteria2 auth finish failed: {error}"));
    }
    let response = match timeout(Duration::from_millis(timeout_ms), stream.recv_response()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response failed: {error}"));
        }
        Err(_) => {
            h3_driver.abort();
            return Err(anyhow!("hysteria2 auth response timed out"));
        }
    };
    if response.status().as_u16() != 233 {
        h3_driver.abort();
        return Err(anyhow!(
            "hysteria2 authentication failed with status {}",
            response.status()
        ));
    }

    let udp_supported = response
        .headers()
        .get("hysteria-udp")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    Ok(Hysteria2Connection {
        endpoint,
        connection,
        h3_driver,
        udp_supported,
    })
}

pub(super) fn build_hysteria2_tcp_request(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let address = destination_socket_addr(destination);
    let mut output = Vec::with_capacity(address.len() + 16);
    encode_quic_varint(0x401, &mut output)?;
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    encode_quic_varint(0, &mut output)?;
    Ok(output)
}

async fn read_hysteria2_tcp_response<R>(reader: &mut R) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut status = [0u8; 1];
    reader.read_exact(&mut status).await?;
    let message_len = read_quic_varint(reader).await?;
    if message_len > 4096 {
        return Err(anyhow!("hysteria2 tcp response message is too large"));
    }
    let mut message = vec![0u8; message_len as usize];
    reader.read_exact(&mut message).await?;
    let padding_len = read_quic_varint(reader).await?;
    if padding_len > 16 * 1024 {
        return Err(anyhow!("hysteria2 tcp response padding is too large"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    reader.read_exact(&mut padding).await?;
    if status[0] != 0x00 {
        let message = String::from_utf8_lossy(&message);
        return Err(anyhow!("hysteria2 tcp request failed: {message}"));
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct Hysteria2UdpReassembly {
    packets: HashMap<u16, Hysteria2UdpFragmentSet>,
}

struct Hysteria2UdpFragmentSet {
    total: u8,
    fragments: Vec<Option<Vec<u8>>>,
}

pub(super) fn build_hysteria2_udp_messages(
    session_id: u32,
    packet_id: u16,
    destination: &Destination,
    payload: &[u8],
    max_datagram_size: Option<usize>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let address = destination_socket_addr(destination);
    let single =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, payload)?;
    let Some(max_size) = max_datagram_size else {
        return Ok(vec![single]);
    };
    if single.len() <= max_size {
        return Ok(vec![single]);
    }

    let header_len =
        build_hysteria2_udp_message_fragment(session_id, packet_id, 0, 1, &address, &[])?.len();
    if header_len >= max_size {
        return Err(anyhow!(
            "hysteria2 udp header is too large for quic datagram: {} >= {}",
            header_len,
            max_size
        ));
    }
    let max_payload_len = max_size - header_len;
    let fragment_count = payload.len().div_ceil(max_payload_len);
    if fragment_count > u8::MAX as usize {
        return Err(anyhow!(
            "hysteria2 udp payload needs too many fragments: {fragment_count}"
        ));
    }
    let mut messages = Vec::with_capacity(fragment_count);
    for (index, chunk) in payload.chunks(max_payload_len).enumerate() {
        messages.push(build_hysteria2_udp_message_fragment(
            session_id,
            packet_id,
            index as u8,
            fragment_count as u8,
            &address,
            chunk,
        )?);
    }
    Ok(messages)
}

fn build_hysteria2_udp_message_fragment(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(12 + address.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    encode_quic_varint(address.len() as u64, &mut output)?;
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub(super) fn parse_hysteria2_udp_message(
    datagram: &[u8],
    expected_session_id: u32,
    reassembly: &mut Hysteria2UdpReassembly,
) -> anyhow::Result<Option<Vec<u8>>> {
    if datagram.len() < 8 {
        return Ok(None);
    }
    let session_id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if session_id != expected_session_id {
        return Ok(None);
    }
    let packet_id = u16::from_be_bytes([datagram[4], datagram[5]]);
    let fragment_id = datagram[6];
    let fragment_count = datagram[7];
    if fragment_count == 0 || fragment_id >= fragment_count {
        return Err(anyhow!(
            "invalid hysteria2 udp fragment id/count: {fragment_id}/{fragment_count}"
        ));
    }
    let mut cursor = 8;
    let address_len = read_quic_varint_from_slice(datagram, &mut cursor)? as usize;
    if cursor + address_len > datagram.len() {
        return Err(anyhow!("hysteria2 udp address length exceeds datagram"));
    }
    cursor += address_len;
    let payload = datagram[cursor..].to_vec();
    if fragment_count == 1 {
        return Ok(Some(payload));
    }
    push_hysteria2_udp_fragment(reassembly, packet_id, fragment_id, fragment_count, payload)
}

fn push_hysteria2_udp_fragment(
    reassembly: &mut Hysteria2UdpReassembly,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    payload: Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if reassembly.packets.len() > 64 {
        reassembly.packets.clear();
    }
    let entry = reassembly
        .packets
        .entry(packet_id)
        .or_insert_with(|| Hysteria2UdpFragmentSet {
            total: fragment_count,
            fragments: vec![None; fragment_count as usize],
        });
    if entry.total != fragment_count {
        reassembly.packets.remove(&packet_id);
        return Err(anyhow!("inconsistent hysteria2 udp fragment count"));
    }
    entry.fragments[fragment_id as usize] = Some(payload);
    if !entry.fragments.iter().all(Option::is_some) {
        return Ok(None);
    }
    let entry = reassembly
        .packets
        .remove(&packet_id)
        .ok_or_else(|| anyhow!("missing hysteria2 udp reassembly entry"))?;
    let mut output = Vec::new();
    for fragment in entry.fragments {
        output
            .extend_from_slice(&fragment.ok_or_else(|| anyhow!("missing hysteria2 udp fragment"))?);
    }
    Ok(Some(output))
}
