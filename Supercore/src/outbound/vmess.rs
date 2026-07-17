use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{BlockEncrypt, KeyInit as BlockKeyInit},
    Aes128,
};
use aes_gcm::{aead::Aead, Aes128Gcm};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use rustls_pki_types::ServerName;
use sha2::Sha256;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::Mutex as TokioMutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use crate::routing::Destination;

use super::{
    io::read_exact_or_eof,
    transports::{
        connect_tcp, open_grpc_tunnel, open_h2_tunnel, open_websocket_transport_without_headers,
        tls_client_config,
    },
    udp::{KeyedRoundRobinSessionPool, UDP_SESSION_POOL_SIZE},
    BoxedStream, Outbound, OutboundCapability,
};

pub(super) struct VmessOutbound {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    cipher: String,
    tls: bool,
    sni: Option<String>,
    skip_cert_verify: bool,
    network: Option<String>,
    ws_path: Option<String>,
    ws_host: Option<String>,
    grpc_service_name: Option<String>,
    udp_sessions: TokioMutex<KeyedRoundRobinSessionPool<VmessUdpSession>>,
}

struct VmessUdpSession {
    stream: BoxedStream,
    upload: VmessUploadState,
    download: VmessDownloadState,
    response_header_read: bool,
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_udp("vmess-command-udp-session-pool")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let stream = self.open_transport(timeout_ms).await?;
        setup_vmess_stream(stream, &user_id, cipher, destination).await
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let session_handle = self.vmess_udp_session(destination, timeout_ms).await?;
        let exchange = {
            let mut session = session_handle.lock().await;
            let VmessUdpSession {
                stream,
                upload,
                download,
                response_header_read,
            } = &mut *session;
            timeout(Duration::from_millis(timeout_ms), async {
                write_vmess_chunk(stream, upload, payload).await?;
                if !*response_header_read {
                    read_vmess_response_header(stream, download).await?;
                    *response_header_read = true;
                }
                read_vmess_chunk(stream, download)
                    .await?
                    .ok_or_else(|| anyhow!("vmess udp response ended before payload"))
            })
            .await
            .context("vmess udp exchange timed out")?
        };
        if exchange.is_err() {
            self.remove_vmess_udp_session(destination, &session_handle)
                .await;
        }
        exchange
    }
}

impl VmessOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        uuid: String,
        cipher: String,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
        network: Option<String>,
        ws_path: Option<String>,
        ws_host: Option<String>,
        grpc_service_name: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            uuid,
            cipher,
            tls,
            sni,
            skip_cert_verify,
            network,
            ws_path,
            ws_host,
            grpc_service_name,
            udp_sessions: TokioMutex::new(KeyedRoundRobinSessionPool::default()),
        }
    }

    async fn open_transport(&self, timeout_ms: u64) -> anyhow::Result<BoxedStream> {
        let network = self
            .network
            .as_deref()
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        if !matches!(
            network.as_str(),
            "tcp" | "ws" | "websocket" | "grpc" | "h2" | "http"
        ) {
            return Err(anyhow!("unsupported vmess network {network}"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;

        if self.tls {
            let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
            let mut tls_config = tls_client_config(self.skip_cert_verify)?;
            if matches!(network.as_str(), "grpc" | "h2" | "http") {
                tls_config.alpn_protocols = vec![b"h2".to_vec()];
            }
            let connector = TlsConnector::from(Arc::new(tls_config));
            let tls_server_name = ServerName::try_from(server_name.clone())
                .map_err(|error| anyhow!("invalid vmess server name: {error}"))?;
            let stream = timeout(
                Duration::from_millis(timeout_ms),
                connector.connect(tls_server_name, tcp),
            )
            .await
            .context("vmess tls handshake timed out")?
            .context("vmess tls handshake failed")?;
            if network == "ws" || network == "websocket" {
                return open_websocket_transport_without_headers(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network.as_str(), "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&server_name),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        } else {
            let stream = tcp;
            if network == "ws" || network == "websocket" {
                return open_websocket_transport_without_headers(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await;
            }
            if network == "grpc" {
                return open_grpc_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.grpc_service_name.as_deref(),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            if matches!(network.as_str(), "h2" | "http") {
                return open_h2_tunnel(
                    stream,
                    self.ws_host.as_deref().unwrap_or(&self.server),
                    self.ws_path.as_deref().unwrap_or("/"),
                    timeout_ms,
                )
                .await
                .map(|stream| Box::new(stream) as BoxedStream);
            }
            Ok(Box::new(stream))
        }
    }

    async fn vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<Arc<TokioMutex<VmessUdpSession>>> {
        let key = destination.authority();
        let mut pool = self.udp_sessions.lock().await;
        if pool.len(&key) < UDP_SESSION_POOL_SIZE {
            let session = Arc::new(TokioMutex::new(
                self.open_vmess_udp_session(destination, timeout_ms).await?,
            ));
            pool.push(key, Arc::clone(&session));
            return Ok(session);
        }
        pool.next(&key)
            .ok_or_else(|| anyhow!("vmess UDP session pool is unexpectedly empty"))
    }

    async fn open_vmess_udp_session(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<VmessUdpSession> {
        let user_id = Uuid::parse_str(&self.uuid)
            .map_err(|error| anyhow!("invalid vmess uuid for {}: {error}", self.name))?;
        let cipher = VmessCipher::from_name(&self.cipher)?;
        let mut stream = self.open_transport(timeout_ms).await?;
        let setup = build_vmess_setup_with_command(&user_id, cipher, destination, VMESS_CMD_UDP)?;
        timeout(Duration::from_millis(timeout_ms), async {
            stream.write_all(&setup.request).await?;
            stream.flush().await
        })
        .await
        .context("vmess udp session setup timed out")??;
        Ok(VmessUdpSession {
            stream,
            upload: setup.upload,
            download: setup.download,
            response_header_read: false,
        })
    }

    async fn remove_vmess_udp_session(
        &self,
        destination: &Destination,
        target: &Arc<TokioMutex<VmessUdpSession>>,
    ) {
        let mut pool = self.udp_sessions.lock().await;
        let key = destination.authority();
        pool.remove(&key, target);
    }
}

pub(super) const VMESS_TAG_LEN: usize = 16;
const VMESS_MAX_CHUNK_PLAINTEXT: usize = 8192;
const VMESS_CMD_TCP: u8 = 0x01;
const VMESS_CMD_UDP: u8 = 0x02;
type VmessMaskReader = digest::core_api::XofReaderCoreWrapper<sha3::Shake128ReaderCore>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmessCipher {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

struct VmessSetup {
    request: Vec<u8>,
    upload: VmessUploadState,
    download: VmessDownloadState,
}

pub(super) struct VmessUploadState {
    pub(super) cipher: Option<VmessAeadState>,
    pub(super) length_mask: VmessLengthMask,
}

pub(super) struct VmessDownloadState {
    pub(super) response_header_key: [u8; 16],
    pub(super) response_header_iv: [u8; 16],
    pub(super) response_authentication: u8,
    pub(super) cipher: Option<VmessAeadState>,
    pub(super) length_mask: VmessLengthMask,
}

pub(super) struct VmessLengthMask {
    reader: VmessMaskReader,
}

pub(super) struct VmessAeadState {
    cipher: VmessCipher,
    key: Vec<u8>,
    nonce: [u8; 12],
    counter: u16,
}

impl VmessCipher {
    fn from_name(name: &str) -> anyhow::Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::Chacha20Poly1305),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "none" => Ok(Self::None),
            _ => Err(anyhow!("unsupported vmess cipher {name}")),
        }
    }

    fn method_byte(self) -> u8 {
        match self {
            Self::Aes128Gcm => 3,
            Self::Chacha20Poly1305 => 4,
            Self::None => 5,
        }
    }

    fn tag_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm | Self::Chacha20Poly1305 => VMESS_TAG_LEN,
        }
    }
}

impl VmessLengthMask {
    pub(super) fn new(seed: &[u8]) -> Self {
        let mut shake = Shake128::default();
        sha3::digest::Update::update(&mut shake, seed);
        Self {
            reader: shake.finalize_xof(),
        }
    }

    fn next(&mut self) -> u16 {
        let mut mask = [0u8; 2];
        self.reader.read(&mut mask);
        u16::from_be_bytes(mask)
    }
}

impl VmessAeadState {
    pub(super) fn new(cipher: VmessCipher, key: &[u8], iv: &[u8]) -> anyhow::Result<Option<Self>> {
        if cipher == VmessCipher::None {
            return Ok(None);
        }
        if iv.len() < 12 {
            return Err(anyhow!("vmess iv is too short"));
        }
        let mut nonce = [0u8; 12];
        nonce[2..].copy_from_slice(&iv[2..12]);
        let key = match cipher {
            VmessCipher::Aes128Gcm => key.to_vec(),
            VmessCipher::Chacha20Poly1305 => vmess_chacha_key(key).to_vec(),
            VmessCipher::None => unreachable!(),
        };
        Ok(Some(Self {
            cipher,
            key,
            nonce,
            counter: 0,
        }))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.nonce;
        nonce[0..2].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), plaintext)
                .map_err(|_| anyhow!("vmess encrypt failed")),
            VmessCipher::None => Ok(plaintext.to_vec()),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match self.cipher {
            VmessCipher::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess aes-128-gcm key"))?
                .decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| anyhow!("invalid vmess chacha20-poly1305 key"))?
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), ciphertext)
                .map_err(|_| anyhow!("vmess decrypt failed")),
            VmessCipher::None => Ok(ciphertext.to_vec()),
        }
    }
}

async fn setup_vmess_stream<S>(
    mut stream: S,
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<BoxedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let setup = build_vmess_setup(user_id, cipher, destination)?;
    stream.write_all(&setup.request).await?;
    stream.flush().await?;
    Ok(Box::new(spawn_vmess_stream(
        stream,
        setup.upload,
        setup.download,
    )))
}

fn spawn_vmess_stream<S>(
    stream: S,
    mut upload_state: VmessUploadState,
    mut download_state: VmessDownloadState,
) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = write_vmess_chunk(&mut remote_write, &mut upload_state, &[]).await;
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    for chunk in buf[..n].chunks(VMESS_MAX_CHUNK_PLAINTEXT) {
                        if write_vmess_chunk(&mut remote_write, &mut upload_state, chunk)
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if read_vmess_response_header(&mut remote_read, &download_state)
            .await
            .is_err()
        {
            let _ = local_write.shutdown().await;
            return;
        }
        loop {
            match read_vmess_chunk(&mut remote_read, &mut download_state).await {
                Ok(Some(chunk)) => {
                    if local_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}

pub(super) async fn write_vmess_chunk<W>(
    writer: &mut W,
    state: &mut VmessUploadState,
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = match &mut state.cipher {
        Some(cipher) => cipher.encrypt(payload)?,
        None => payload.to_vec(),
    };
    if body.len() > u16::MAX as usize {
        return Err(anyhow!("vmess chunk is too large"));
    }
    let masked_len = (body.len() as u16) ^ state.length_mask.next();
    writer.write_all(&masked_len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub(super) async fn read_vmess_chunk<R>(
    reader: &mut R,
    state: &mut VmessDownloadState,
) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    if !read_exact_or_eof(reader, &mut length).await? {
        return Ok(None);
    }
    let body_len = (u16::from_be_bytes(length) ^ state.length_mask.next()) as usize;
    let tag_len = state
        .cipher
        .as_ref()
        .map(|cipher| cipher.cipher.tag_len())
        .unwrap_or(0);
    if body_len == tag_len {
        let mut eof = vec![0u8; body_len];
        if body_len > 0 {
            reader.read_exact(&mut eof).await?;
        }
        return Ok(None);
    }
    if body_len > u16::MAX as usize {
        return Err(anyhow!("vmess response chunk is too large"));
    }
    if body_len < tag_len {
        return Err(anyhow!("vmess response chunk is shorter than tag"));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    match &mut state.cipher {
        Some(cipher) => cipher.decrypt(&body).map(Some),
        None => Ok(Some(body)),
    }
}

async fn read_vmess_response_header<R>(
    reader: &mut R,
    state: &VmessDownloadState,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let len_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Len Key"]);
    let len_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header Len IV"]);
    let mut encrypted_len = [0u8; 2 + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_len).await?;
    let len = vmess_aes128gcm_decrypt(&len_key[..16], &len_nonce[..12], &[], &encrypted_len)?;
    if len.len() != 2 {
        return Err(anyhow!("invalid vmess response header length"));
    }
    let header_len = u16::from_be_bytes([len[0], len[1]]) as usize;

    let header_key = vmess_kdf(&state.response_header_key, &[b"AEAD Resp Header Key"]);
    let header_nonce = vmess_kdf(&state.response_header_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted_header = vec![0u8; header_len + VMESS_TAG_LEN];
    reader.read_exact(&mut encrypted_header).await?;
    let header = vmess_aes128gcm_decrypt(
        &header_key[..16],
        &header_nonce[..12],
        &[],
        &encrypted_header,
    )?;
    if header.len() < 4 {
        return Err(anyhow!("vmess response header is too short"));
    }
    if header[0] != state.response_authentication {
        return Err(anyhow!(
            "invalid vmess response auth value: expected {}, got {}",
            state.response_authentication,
            header[0]
        ));
    }
    Ok(())
}

fn build_vmess_setup(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
) -> anyhow::Result<VmessSetup> {
    build_vmess_setup_with_command(user_id, cipher, destination, VMESS_CMD_TCP)
}

fn build_vmess_setup_with_command(
    user_id: &Uuid,
    cipher: VmessCipher,
    destination: &Destination,
    command: u8,
) -> anyhow::Result<VmessSetup> {
    let instruction_key = vmess_instruction_key(user_id);
    let auth_id = vmess_auth_id(&instruction_key)?;

    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    getrandom::fill(&mut data_iv)
        .map_err(|error| anyhow!("failed to generate vmess iv: {error}"))?;
    getrandom::fill(&mut data_key)
        .map_err(|error| anyhow!("failed to generate vmess key: {error}"))?;
    let mut response_auth = [0u8; 1];
    getrandom::fill(&mut response_auth)
        .map_err(|error| anyhow!("failed to generate vmess response auth: {error}"))?;

    let response_header_iv = vmess_sha256_16(&data_iv);
    let response_header_key = vmess_sha256_16(&data_key);

    let mut header = Vec::with_capacity(316);
    header.push(0x01);
    header.extend_from_slice(&data_iv);
    header.extend_from_slice(&data_key);
    header.push(response_auth[0]);
    header.push(0x01 | 0x04);
    header.push(cipher.method_byte());
    header.push(0x00);
    header.push(command);
    encode_vmess_destination(destination, &mut header)?;
    let checksum = vmess_fnv1a(&header).to_be_bytes();
    header.extend_from_slice(&checksum);

    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow!("failed to generate vmess header nonce: {error}"))?;

    let len_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let encrypted_len = vmess_aes128gcm_encrypt(
        &len_key[..16],
        &len_nonce[..12],
        &auth_id,
        &(header.len() as u16).to_be_bytes(),
    )?;

    let header_key = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Key", &auth_id, &nonce],
    );
    let header_nonce = vmess_kdf(
        &instruction_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let encrypted_header =
        vmess_aes128gcm_encrypt(&header_key[..16], &header_nonce[..12], &auth_id, &header)?;

    let mut request =
        Vec::with_capacity(16 + encrypted_len.len() + nonce.len() + encrypted_header.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&encrypted_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&encrypted_header);

    Ok(VmessSetup {
        request,
        upload: VmessUploadState {
            cipher: VmessAeadState::new(cipher, &data_key, &data_iv)?,
            length_mask: VmessLengthMask::new(&data_iv),
        },
        download: VmessDownloadState {
            response_header_key,
            response_header_iv,
            response_authentication: response_auth[0],
            cipher: VmessAeadState::new(cipher, &response_header_key, &response_header_iv)?,
            length_mask: VmessLengthMask::new(&response_header_iv),
        },
    })
}

fn encode_vmess_destination(destination: &Destination, output: &mut Vec<u8>) -> anyhow::Result<()> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    if let Ok(ip) = destination.host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                output.push(0x01);
                output.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                output.push(0x03);
                output.extend_from_slice(&ip.octets());
            }
        }
        return Ok(());
    }
    let host = destination.host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err(anyhow!("vmess destination host is too long"));
    }
    output.push(0x02);
    output.push(host.len() as u8);
    output.extend_from_slice(host);
    Ok(())
}

pub(super) fn vmess_instruction_key(user_id: &Uuid) -> [u8; 16] {
    let mut data = user_id.as_bytes().to_vec();
    data.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    Md5::digest(&data).into()
}

fn vmess_auth_id(instruction_key: &[u8; 16]) -> anyhow::Result<[u8; 16]> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow!("system time before unix epoch: {error}"))?
        .as_secs();
    let mut auth = [0u8; 16];
    auth[0..8].copy_from_slice(&now.to_be_bytes());
    getrandom::fill(&mut auth[8..12])
        .map_err(|error| anyhow!("failed to generate vmess auth random: {error}"))?;
    let checksum = crc32c::crc32c(&auth[0..12]).to_be_bytes();
    auth[12..16].copy_from_slice(&checksum);

    let key = vmess_kdf(instruction_key, &[b"AES Auth ID Encryption"]);
    let cipher =
        Aes128::new_from_slice(&key[..16]).map_err(|_| anyhow!("invalid vmess auth key"))?;
    cipher.encrypt_block((&mut auth).into());
    Ok(auth)
}

pub(super) fn vmess_aes128gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm encrypt failed"))
}

pub(super) fn vmess_aes128gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("invalid vmess aes-gcm key"))?
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("vmess aes-gcm decrypt failed"))
}

pub(super) fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF".as_slice());
    keys.extend_from_slice(path);
    vmess_recursive_hash(&keys, keys.len(), key)
}

fn vmess_recursive_hash(keys: &[&[u8]], level: usize, data: &[u8]) -> [u8; 32] {
    if level == 0 {
        return Sha256::digest(data).into();
    }
    let (inner_pad, outer_pad) = vmess_hmac_pads(keys[level - 1]);
    let mut inner_input = Vec::with_capacity(inner_pad.len() + data.len());
    inner_input.extend_from_slice(&inner_pad);
    inner_input.extend_from_slice(data);
    let inner_digest = vmess_recursive_hash(keys, level - 1, &inner_input);

    let mut outer_input = Vec::with_capacity(outer_pad.len() + inner_digest.len());
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner_digest);
    vmess_recursive_hash(keys, level - 1, &outer_input)
}

fn vmess_hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let key_material = if key.len() > 64 {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, byte) in key_material.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    (inner, outer)
}

pub(super) fn vmess_sha256_16(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut output = [0u8; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn vmess_chacha_key(data: &[u8]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(data).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

pub(super) fn vmess_fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}
