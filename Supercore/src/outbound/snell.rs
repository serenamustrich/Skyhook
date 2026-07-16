use std::{io::Cursor, net::IpAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params as Argon2Params, Version as Argon2Version,
};
use async_trait::async_trait;
use bytes::BytesMut;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::Mutex,
    time::timeout,
};

use crate::{config::ShadowsocksPluginConfig, routing::Destination};

use super::{
    connect_tcp,
    shadowsocks::{
        apply_shadowsocks_plugin_request, encode_ss_chunk, increment_nonce, plugin_is_http_obfs,
        plugin_is_tls_obfs, read_http_obfs_response, read_ss_chunk, read_ss_chunk_from_tls_obfs,
        relay_shadowsocks_download, wrap_simple_obfs_tls_app_data, write_ss_plugin_chunk,
        SimpleObfsTlsDecoder, SsCipher, SS_CHUNK_SIZE, SS_NONCE_LEN, SS_TAG_LEN,
    },
    BoxedStream, IdlePool, Outbound, OutboundCapability,
};

pub(super) struct SnellOutbound {
    name: String,
    server: String,
    port: u16,
    psk: String,
    method: Option<String>,
    version: Option<u8>,
    obfs: Option<String>,
    obfs_host: Option<String>,
    reuse: bool,
    v4_pool: Arc<Mutex<SnellV4ConnectionPool>>,
}

impl SnellOutbound {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        psk: String,
        method: Option<String>,
        version: Option<u8>,
        obfs: Option<String>,
        obfs_host: Option<String>,
        reuse: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
            psk,
            method,
            version,
            obfs,
            obfs_host,
            reuse,
            v4_pool: Arc::new(Mutex::new(SnellV4ConnectionPool::default())),
        }
    }

    async fn connect_v4_reuse(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        snell_cipher(4, self.method.as_deref())?;
        let mut was_pooled = true;
        let mut connection = if let Some(connection) = self.v4_pool.lock().await.take() {
            connection
        } else {
            was_pooled = false;
            self.new_v4_pooled_connection(timeout_ms).await?
        };

        loop {
            let setup = timeout(Duration::from_millis(timeout_ms), async {
                connection
                    .writer
                    .write_request(destination, self.version.unwrap_or(4))
                    .await?;
                connection.reader.read_frame().await
            })
            .await;
            let reply = match setup {
                Ok(Ok(reply)) => reply,
                Ok(Err(_error)) if was_pooled => {
                    connection = self.new_v4_pooled_connection(timeout_ms).await?;
                    was_pooled = false;
                    continue;
                }
                Ok(Err(error)) => return Err(error).context("snell reuse handshake failed"),
                Err(_) if was_pooled => {
                    connection = self.new_v4_pooled_connection(timeout_ms).await?;
                    was_pooled = false;
                    continue;
                }
                Err(_) => return Err(anyhow!("snell reuse handshake timed out")),
            };
            validate_snell_response(&reply, "TCP connect")?;
            let initial_payload = reply.get(1..).unwrap_or_default().to_vec();
            return Ok(Box::new(spawn_snell_v4_reuse_stream(
                connection,
                Arc::clone(&self.v4_pool),
                initial_payload,
            )));
        }
    }

    async fn new_v4_pooled_connection(
        &self,
        timeout_ms: u64,
    ) -> anyhow::Result<SnellV4PooledConnection> {
        let plugin = snell_obfs_plugin(
            self.obfs.as_deref(),
            self.obfs_host.as_deref(),
            &self.server,
        )?;
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        SnellV4PooledConnection::new(
            Box::new(tcp),
            self.psk.as_bytes(),
            plugin,
            self.server.clone(),
            self.port,
        )
    }

    async fn connect_v4(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        snell_cipher(4, self.method.as_deref())?;
        let plugin = snell_obfs_plugin(
            self.obfs.as_deref(),
            self.obfs_host.as_deref(),
            &self.server,
        )?;
        let mut salt = [0u8; SNELL_V4_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate snell v4 salt: {error}"))?;
        let key = derive_snell_subkey(SsCipher::Aes128Gcm, self.psk.as_bytes(), &salt)?;
        let mut nonce = [0u8; SS_NONCE_LEN];
        let handshake = build_snell_tcp_handshake(destination, Some(4))?;
        let padding = snell_v4_initial_padding_len()?;
        let mut initial = salt.to_vec();
        initial.extend_from_slice(&encode_snell_v4_frame(
            &key, &mut nonce, &handshake, padding,
        )?);
        if let Some(plugin) = plugin.as_ref() {
            initial = apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?;
        }

        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let mut stream: BoxedStream = Box::new(tcp);
        stream.write_all(&initial).await?;
        stream.flush().await?;
        Ok(Box::new(spawn_snell_v4_stream(
            self.psk.as_bytes().to_vec(),
            key,
            nonce,
            stream,
            plugin,
        )))
    }

    async fn udp_exchange_v4(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        snell_cipher(4, self.method.as_deref())?;
        let exchange = async {
            let mut stream =
                connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
            let mut request_salt = [0u8; SNELL_V4_SALT_LEN];
            getrandom::fill(&mut request_salt)
                .map_err(|error| anyhow!("failed to generate snell v4 UDP salt: {error}"))?;
            let upload_key =
                derive_snell_subkey(SsCipher::Aes128Gcm, self.psk.as_bytes(), &request_salt)?;
            let mut upload_nonce = [0u8; SS_NONCE_LEN];
            let mut initial = request_salt.to_vec();
            initial.extend_from_slice(&encode_snell_v4_frame(
                &upload_key,
                &mut upload_nonce,
                &[1, SNELL_COMMAND_UDP, 0],
                snell_v4_initial_padding_len()?,
            )?);
            stream.write_all(&initial).await?;
            stream.flush().await?;

            let mut response_salt = [0u8; SNELL_V4_SALT_LEN];
            stream
                .read_exact(&mut response_salt)
                .await
                .context("failed to read snell v4 UDP response salt")?;
            let download_key =
                derive_snell_subkey(SsCipher::Aes128Gcm, self.psk.as_bytes(), &response_salt)?;
            let mut download_nonce = [0u8; SS_NONCE_LEN];
            let response =
                read_snell_v4_frame(&mut stream, &download_key, &mut download_nonce).await?;
            validate_snell_response(&response, "UDP associate")?;

            let packet = build_snell_udp_packet(destination, payload)?;
            if packet.len() > SS_CHUNK_SIZE {
                return Err(anyhow!("snell UDP payload is too large"));
            }
            let encrypted = encode_snell_v4_frame(&upload_key, &mut upload_nonce, &packet, 0)?;
            stream.write_all(&encrypted).await?;
            stream.flush().await?;

            let response =
                read_snell_v4_frame(&mut stream, &download_key, &mut download_nonce).await?;
            parse_snell_udp_response(&response)
        };

        timeout(Duration::from_millis(timeout_ms), exchange)
            .await
            .context("snell v4 UDP exchange timed out")?
    }
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "snell"
    }

    fn capability(&self) -> OutboundCapability {
        let mut limitations = Vec::new();
        let version = self.version.unwrap_or(3);
        let version_supported = matches!(version, 1..=5);
        let method = self.method.as_deref().unwrap_or(if version == 1 {
            "chacha20-ietf-poly1305"
        } else {
            "aes-128-gcm"
        });
        let method_supported = if version >= 4 {
            method.eq_ignore_ascii_case("aes-128-gcm")
        } else {
            matches!(
                method.to_ascii_lowercase().as_str(),
                "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305" | "chacha20-poly1305"
            )
        };
        let obfs = self
            .obfs
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());
        let obfs_supported = obfs
            .as_deref()
            .map(|value| {
                matches!(
                    value,
                    "none"
                        | "off"
                        | "http"
                        | "http_simple"
                        | "http-simple"
                        | "tls"
                        | "simple-obfs-tls"
                        | "obfs-tls"
                )
            })
            .unwrap_or(true);
        if !version_supported {
            limitations.push(format!("unsupported snell version {version}"));
        }
        if !method_supported {
            limitations.push(format!("unsupported snell method {method}"));
        }
        if !obfs_supported {
            limitations.push(format!(
                "unsupported snell obfs {}",
                obfs.as_deref().unwrap_or_default()
            ));
        }
        let reuse_supported = !self.reuse || matches!(version, 4 | 5);
        if !reuse_supported {
            limitations.push("snell connection reuse requires version 4 or 5".to_string());
        }
        let udp_supported = version_supported
            && method_supported
            && matches!(version, 3..=5)
            && obfs
                .as_deref()
                .map(|value| matches!(value, "none" | "off"))
                .unwrap_or(true);
        if version < 3 {
            limitations.push("snell udp requires version 3, 4, or 5".to_string());
        } else if !udp_supported && obfs_supported {
            limitations.push("snell udp over simple-obfs is not supported".to_string());
        }
        OutboundCapability {
            tcp_supported: version_supported
                && method_supported
                && obfs_supported
                && reuse_supported,
            udp_supported,
            udp_mode: Some(if udp_supported {
                if version >= 4 {
                    "snell-v4-framed-udp-over-tcp".to_string()
                } else {
                    "snell-v3-udp-over-tcp".to_string()
                }
            } else {
                "snell-aead-tcp".to_string()
            }),
            limitations,
        }
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        let version = validate_snell_version(self.version)?;
        if self.reuse && version < 4 {
            return Err(anyhow!(
                "snell connection reuse requires version 4 or 5; configured version is {version}"
            ));
        }
        if version >= 4 {
            if self.reuse {
                return self.connect_v4_reuse(destination, timeout_ms).await;
            }
            return self.connect_v4(destination, timeout_ms).await;
        }
        let cipher = snell_cipher(version, self.method.as_deref())?;
        let plugin = snell_obfs_plugin(
            self.obfs.as_deref(),
            self.obfs_host.as_deref(),
            &self.server,
        )?;
        let mut salt = vec![0u8; cipher.salt_len()];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate snell salt: {error}"))?;
        let subkey = derive_snell_subkey(cipher, self.psk.as_bytes(), &salt)?;

        let mut upload_nonce = vec![0u8; cipher.nonce_len()];
        let handshake = build_snell_tcp_handshake(destination, Some(version))?;
        let mut initial = salt;
        initial.extend_from_slice(&encode_ss_chunk(
            cipher,
            &subkey,
            &mut upload_nonce,
            &handshake,
        )?);
        if let Some(plugin) = plugin.as_ref() {
            initial = apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?;
        }

        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let mut stream: BoxedStream = Box::new(tcp);
        stream.write_all(&initial).await?;
        stream.flush().await?;

        Ok(Box::new(spawn_snell_stream(
            cipher,
            self.psk.as_bytes().to_vec(),
            subkey,
            upload_nonce,
            stream,
            plugin,
        )))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if self
            .obfs
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        {
            return Err(anyhow!(
                "snell UDP over simple-obfs is not supported; use plain Snell UDP"
            ));
        }

        let version = validate_snell_version(self.version)?;
        if version < 3 {
            return Err(anyhow!(
                "snell UDP requires version 3, 4, or 5; configured version is {version}"
            ));
        }
        if version >= 4 {
            return self.udp_exchange_v4(destination, payload, timeout_ms).await;
        }
        let cipher = snell_cipher(version, self.method.as_deref())?;
        let exchange = async {
            let mut stream =
                connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
            let mut request_salt = vec![0u8; cipher.salt_len()];
            getrandom::fill(&mut request_salt)
                .map_err(|error| anyhow!("failed to generate snell UDP salt: {error}"))?;
            let upload_key = derive_snell_subkey(cipher, self.psk.as_bytes(), &request_salt)?;
            let mut upload_nonce = vec![0u8; cipher.nonce_len()];

            let mut initial = request_salt;
            initial.extend_from_slice(&encode_ss_chunk(
                cipher,
                &upload_key,
                &mut upload_nonce,
                &[1, SNELL_COMMAND_UDP, 0],
            )?);
            stream.write_all(&initial).await?;
            stream.flush().await?;

            let mut response_salt = vec![0u8; cipher.salt_len()];
            stream
                .read_exact(&mut response_salt)
                .await
                .context("failed to read snell UDP response salt")?;
            let download_key = derive_snell_subkey(cipher, self.psk.as_bytes(), &response_salt)?;
            let mut download_nonce = vec![0u8; cipher.nonce_len()];
            let response = read_ss_chunk(cipher, &download_key, &mut download_nonce, &mut stream)
                .await?
                .ok_or_else(|| anyhow!("snell server closed before UDP ready response"))?;
            validate_snell_response(&response, "UDP associate")?;

            let packet = build_snell_udp_packet(destination, payload)?;
            let encrypted = encode_ss_chunk(cipher, &upload_key, &mut upload_nonce, &packet)?;
            stream.write_all(&encrypted).await?;
            stream.flush().await?;

            let response = read_ss_chunk(cipher, &download_key, &mut download_nonce, &mut stream)
                .await?
                .ok_or_else(|| anyhow!("snell server closed before UDP response"))?;
            parse_snell_udp_response(&response)
        };

        timeout(Duration::from_millis(timeout_ms), exchange)
            .await
            .context("snell UDP exchange timed out")?
    }
}

const SNELL_V4_POOL_SIZE: usize = 10;
const SNELL_V4_POOL_IDLE_AGE: Duration = Duration::from_secs(15);

struct SnellV4ConnectionPool {
    idle: IdlePool<SnellV4PooledConnection>,
}

impl Default for SnellV4ConnectionPool {
    fn default() -> Self {
        Self {
            idle: IdlePool::new(SNELL_V4_POOL_SIZE, SNELL_V4_POOL_IDLE_AGE),
        }
    }
}

impl SnellV4ConnectionPool {
    fn take(&mut self) -> Option<SnellV4PooledConnection> {
        self.idle.take()
    }

    fn put(&mut self, connection: SnellV4PooledConnection) {
        self.idle.put(connection);
    }
}

struct SnellV4PooledConnection {
    reader: SnellV4PooledReader,
    writer: SnellV4PooledWriter,
}

impl SnellV4PooledConnection {
    fn new(
        stream: BoxedStream,
        psk: &[u8],
        plugin: Option<ShadowsocksPluginConfig>,
        server: String,
        port: u16,
    ) -> anyhow::Result<Self> {
        let mut salt = [0u8; SNELL_V4_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|error| anyhow!("failed to generate snell v4 reuse salt: {error}"))?;
        let upload_key = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &salt)?;
        let (remote_read, remote_write) = tokio::io::split(stream);
        Ok(Self {
            reader: SnellV4PooledReader {
                remote: remote_read,
                plugin: plugin.clone(),
                psk: psk.to_vec(),
                download_key: None,
                download_nonce: [0u8; SS_NONCE_LEN],
                http_initialized: false,
                http_leftover: BytesMut::new(),
                tls_decoder: SimpleObfsTlsDecoder::new(),
            },
            writer: SnellV4PooledWriter {
                remote: remote_write,
                plugin,
                server,
                port,
                upload_key,
                upload_nonce: [0u8; SS_NONCE_LEN],
                salt,
                started: false,
            },
        })
    }
}

struct SnellV4PooledReader {
    remote: ReadHalf<BoxedStream>,
    plugin: Option<ShadowsocksPluginConfig>,
    psk: Vec<u8>,
    download_key: Option<Vec<u8>>,
    download_nonce: [u8; SS_NONCE_LEN],
    http_initialized: bool,
    http_leftover: BytesMut,
    tls_decoder: SimpleObfsTlsDecoder,
}

impl SnellV4PooledReader {
    async fn read_transport_exact(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        if plugin_is_tls_obfs(self.plugin.as_ref()) {
            return self
                .tls_decoder
                .read_exact_or_eof(&mut self.remote, length)
                .await?
                .ok_or_else(|| anyhow!("snell v4 reuse TLS-obfs stream ended unexpectedly"));
        }

        if plugin_is_http_obfs(self.plugin.as_ref()) && !self.http_initialized {
            let leftover = read_http_obfs_response(&mut self.remote).await?;
            self.http_leftover.extend_from_slice(&leftover);
            self.http_initialized = true;
        }

        let mut output = vec![0u8; length];
        let buffered = length.min(self.http_leftover.len());
        if buffered > 0 {
            let chunk = self.http_leftover.split_to(buffered);
            output[..buffered].copy_from_slice(&chunk);
        }
        if buffered < length {
            self.remote
                .read_exact(&mut output[buffered..])
                .await
                .context("snell v4 reuse stream ended unexpectedly")?;
        }
        Ok(output)
    }

    async fn read_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.download_key.is_none() {
            let salt = self.read_transport_exact(SNELL_V4_SALT_LEN).await?;
            self.download_key = Some(derive_snell_subkey(SsCipher::Aes128Gcm, &self.psk, &salt)?);
        }
        let key = self
            .download_key
            .as_ref()
            .expect("snell v4 download key initialized")
            .clone();
        let header_cipher = self
            .read_transport_exact(SNELL_V4_HEADER_CIPHER_LEN)
            .await?;
        let header = SsCipher::Aes128Gcm.decrypt(&key, &self.download_nonce, &header_cipher)?;
        increment_nonce(&mut self.download_nonce);
        if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
            return Err(anyhow!("invalid snell v4 reuse frame header"));
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_len == 0 {
            if padding_len != 0 {
                return Err(anyhow!("snell v4 reuse zero chunk cannot contain padding"));
            }
            return Ok(Vec::new());
        }
        if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
            return Err(anyhow!("snell v4 reuse frame is too large"));
        }
        let mut frame = self
            .read_transport_exact(padding_len + payload_len + SS_TAG_LEN)
            .await?;
        let (padding, payload_cipher) = frame.split_at_mut(padding_len);
        swap_snell_v4_padding(padding, payload_cipher);
        let payload = SsCipher::Aes128Gcm.decrypt(&key, &self.download_nonce, payload_cipher)?;
        increment_nonce(&mut self.download_nonce);
        Ok(payload)
    }
}

struct SnellV4PooledWriter {
    remote: WriteHalf<BoxedStream>,
    plugin: Option<ShadowsocksPluginConfig>,
    server: String,
    port: u16,
    upload_key: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    salt: [u8; SNELL_V4_SALT_LEN],
    started: bool,
}

impl SnellV4PooledWriter {
    async fn write_request(
        &mut self,
        destination: &Destination,
        version: u8,
    ) -> anyhow::Result<()> {
        let request = build_snell_tcp_handshake_with_reuse(destination, Some(version), true)?;
        let padding = if self.started {
            0
        } else {
            snell_v4_initial_padding_len()?
        };
        self.write_frame(&request, padding).await
    }

    async fn write_payload(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        for chunk in payload.chunks(SS_CHUNK_SIZE) {
            self.write_frame(chunk, 0).await?;
        }
        Ok(())
    }

    async fn write_zero(&mut self) -> anyhow::Result<()> {
        self.write_frame(&[], 0).await
    }

    async fn write_frame(&mut self, payload: &[u8], padding: usize) -> anyhow::Result<()> {
        let first_frame = !self.started;
        let encrypted =
            encode_snell_v4_frame(&self.upload_key, &mut self.upload_nonce, payload, padding)?;
        let wire = if first_frame {
            let mut initial = self.salt.to_vec();
            initial.extend_from_slice(&encrypted);
            if let Some(plugin) = self.plugin.as_ref() {
                apply_shadowsocks_plugin_request(plugin, &self.server, self.port, initial)?
            } else {
                initial
            }
        } else if plugin_is_tls_obfs(self.plugin.as_ref()) {
            wrap_simple_obfs_tls_app_data(&encrypted)
        } else {
            encrypted
        };
        self.remote.write_all(&wire).await?;
        self.remote.flush().await?;
        self.started = true;
        Ok(())
    }
}

const SNELL_COMMAND_CONNECT: u8 = 1;
const SNELL_COMMAND_CONNECT_REUSE: u8 = 5;
const SNELL_COMMAND_UDP: u8 = 6;
const SNELL_COMMAND_UDP_FORWARD: u8 = 1;
const SNELL_V4_SALT_LEN: usize = 16;
const SNELL_V4_HEADER_PLAIN_LEN: usize = 7;
const SNELL_V4_HEADER_CIPHER_LEN: usize = SNELL_V4_HEADER_PLAIN_LEN + SS_TAG_LEN;

fn validate_snell_version(version: Option<u8>) -> anyhow::Result<u8> {
    let version = version.unwrap_or(3);
    if matches!(version, 1..=5) {
        Ok(version)
    } else {
        Err(anyhow!(
            "unsupported snell version {version}; supported: 1, 2, 3, 4, 5"
        ))
    }
}

fn snell_cipher(version: u8, method: Option<&str>) -> anyhow::Result<SsCipher> {
    if version >= 4 {
        let method = method
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("aes-128-gcm");
        if !method.eq_ignore_ascii_case("aes-128-gcm") {
            return Err(anyhow!(
                "snell v4/v5 requires aes-128-gcm; configured method is {method}"
            ));
        }
        return Ok(SsCipher::Aes128Gcm);
    }
    let default_method = if version == 1 {
        "chacha20-ietf-poly1305"
    } else {
        "aes-128-gcm"
    };
    let method = method
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_method);
    let cipher = SsCipher::from_method(method)
        .with_context(|| format!("unsupported snell method {method}"))?;
    if cipher.is_blake3() {
        return Err(anyhow!(
            "snell does not support Shadowsocks 2022 method {method}"
        ));
    }
    Ok(cipher)
}

fn snell_obfs_plugin(
    obfs: Option<&str>,
    obfs_host: Option<&str>,
    server: &str,
) -> anyhow::Result<Option<ShadowsocksPluginConfig>> {
    let Some(obfs) = obfs.map(str::trim).filter(|value| {
        !value.is_empty()
            && !value.eq_ignore_ascii_case("none")
            && !value.eq_ignore_ascii_case("off")
    }) else {
        return Ok(None);
    };
    let mode = match obfs.to_ascii_lowercase().as_str() {
        "http" | "http_simple" | "http-simple" => "http_simple",
        "tls" | "simple-obfs-tls" | "obfs-tls" => "tls",
        _ => {
            return Err(anyhow!(
                "unsupported snell obfs {obfs}; supported: http, tls"
            ))
        }
    };
    Ok(Some(ShadowsocksPluginConfig {
        mode: mode.to_string(),
        host: Some(
            obfs_host
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(server)
                .to_string(),
        ),
        path: None,
        tls: false,
        skip_cert_verify: false,
    }))
}

fn build_snell_tcp_handshake(
    destination: &Destination,
    snell_version: Option<u8>,
) -> anyhow::Result<Vec<u8>> {
    build_snell_tcp_handshake_with_reuse(destination, snell_version, false)
}

fn build_snell_tcp_handshake_with_reuse(
    destination: &Destination,
    snell_version: Option<u8>,
    reuse: bool,
) -> anyhow::Result<Vec<u8>> {
    if destination.host.len() > 255 {
        return Err(anyhow!("snell destination host is too long"));
    }
    let command = match snell_version.unwrap_or(3) {
        2 => SNELL_COMMAND_CONNECT_REUSE,
        4 | 5 if reuse => SNELL_COMMAND_CONNECT_REUSE,
        1 | 3 | 4 | 5 => SNELL_COMMAND_CONNECT,
        version => {
            return Err(anyhow!(
                "unsupported snell version {version}; supported: 1, 2, 3, 4, 5"
            ))
        }
    };
    let mut output = Vec::with_capacity(4 + destination.host.len() + 2);
    output.push(1);
    output.push(command);
    output.push(0);
    output.push(destination.host.len() as u8);
    output.extend_from_slice(destination.host.as_bytes());
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

fn build_snell_udp_packet(destination: &Destination, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(destination.host.len() + payload.len() + 24);
    output.push(SNELL_COMMAND_UDP_FORWARD);
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            output.extend_from_slice(&[0, 4]);
            output.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            output.extend_from_slice(&[0, 6]);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if destination.host.len() > u8::MAX as usize {
                return Err(anyhow!("snell UDP destination host is too long"));
            }
            output.push(destination.host.len() as u8);
            output.extend_from_slice(destination.host.as_bytes());
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn parse_snell_udp_response(packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    if packet.is_empty() {
        return Err(anyhow!("snell UDP response is empty"));
    }
    let mut offset = 0;
    if packet[0] == SNELL_COMMAND_UDP_FORWARD {
        offset += 1;
        let address_len = *packet
            .get(offset)
            .ok_or_else(|| anyhow!("snell UDP response is missing address length"))?
            as usize;
        offset += 1;
        if address_len == 0 {
            let version = *packet
                .get(offset)
                .ok_or_else(|| anyhow!("snell UDP response is missing IP version"))?;
            offset += 1;
            offset += match version {
                4 => 4,
                6 => 16,
                _ => return Err(anyhow!("invalid snell UDP IP version {version}")),
            };
        } else {
            offset += address_len;
        }
    } else {
        offset += match packet[0] {
            4 => 1 + 4,
            6 => 1 + 16,
            version => return Err(anyhow!("invalid snell UDP response IP version {version}")),
        };
    }
    offset = offset
        .checked_add(2)
        .ok_or_else(|| anyhow!("snell UDP response offset overflow"))?;
    if offset > packet.len() {
        return Err(anyhow!("snell UDP response address is truncated"));
    }
    Ok(packet[offset..].to_vec())
}

fn validate_snell_response(response: &[u8], operation: &str) -> anyhow::Result<()> {
    match response.first().copied() {
        Some(0) => Ok(()),
        Some(2) => {
            let message = response
                .get(3..)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .unwrap_or("server error");
            Err(anyhow!("snell {operation} rejected: {message}"))
        }
        Some(code) => Err(anyhow!(
            "snell {operation} returned unsupported response {code}"
        )),
        None => Err(anyhow!("snell {operation} response is empty")),
    }
}

fn derive_snell_subkey(cipher: SsCipher, password: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
    let params = Argon2Params::new(8, 3, 1, Some(32))
        .map_err(|error| anyhow!("invalid snell argon2 params: {error}"))?;
    let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|error| anyhow!("failed to derive snell session key: {error}"))?;
    output.truncate(cipher.key_len());
    Ok(output)
}

fn snell_v4_initial_padding_len() -> anyhow::Result<usize> {
    let mut random = [0u8; 2];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow!("failed to generate snell v4 padding length: {error}"))?;
    Ok(0x100 + usize::from(u16::from_le_bytes(random) % 0x100))
}

fn encode_snell_v4_frame(
    key: &[u8],
    nonce: &mut [u8],
    payload: &[u8],
    padding_len: usize,
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    if payload.is_empty() && padding_len != 0 {
        return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
    }
    let mut header = [0u8; SNELL_V4_HEADER_PLAIN_LEN];
    header[0] = 4;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let header_cipher = SsCipher::Aes128Gcm.encrypt(key, nonce, &header)?;
    increment_nonce(nonce);

    let mut payload_cipher = if payload.is_empty() {
        Vec::new()
    } else {
        let encrypted = SsCipher::Aes128Gcm.encrypt(key, nonce, payload)?;
        increment_nonce(nonce);
        encrypted
    };
    let mut padding = vec![0u8; padding_len];
    if padding_len > 0 {
        getrandom::fill(&mut padding)
            .map_err(|error| anyhow!("failed to generate snell v4 padding: {error}"))?;
        swap_snell_v4_padding(&mut padding, &mut payload_cipher);
    }

    let mut frame = Vec::with_capacity(header_cipher.len() + padding.len() + payload_cipher.len());
    frame.extend_from_slice(&header_cipher);
    frame.extend_from_slice(&padding);
    frame.extend_from_slice(&payload_cipher);
    Ok(frame)
}

fn swap_snell_v4_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for index in (0..limit).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
    }
}

async fn read_snell_v4_frame<R>(
    reader: &mut R,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header_cipher = [0u8; SNELL_V4_HEADER_CIPHER_LEN];
    reader.read_exact(&mut header_cipher).await?;
    let header = SsCipher::Aes128Gcm.decrypt(key, nonce, &header_cipher)?;
    increment_nonce(nonce);
    if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
        return Err(anyhow!("invalid snell v4 frame header"));
    }
    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    if payload_len == 0 {
        if padding_len != 0 {
            return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
        }
        return Ok(Vec::new());
    }
    if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    let mut frame = vec![0u8; padding_len + payload_len + SS_TAG_LEN];
    reader.read_exact(&mut frame).await?;
    let (padding, payload_cipher) = frame.split_at_mut(padding_len);
    swap_snell_v4_padding(padding, payload_cipher);
    let payload = SsCipher::Aes128Gcm.decrypt(key, nonce, payload_cipher)?;
    increment_nonce(nonce);
    Ok(payload)
}

async fn read_snell_v4_frame_from_tls_obfs<R>(
    decoder: &mut SimpleObfsTlsDecoder,
    reader: &mut R,
    key: &[u8],
    nonce: &mut [u8],
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let header_cipher = decoder
        .read_exact_or_eof(reader, SNELL_V4_HEADER_CIPHER_LEN)
        .await?
        .ok_or_else(|| anyhow!("snell v4 TLS-obfs stream ended before frame header"))?;
    let header = SsCipher::Aes128Gcm.decrypt(key, nonce, &header_cipher)?;
    increment_nonce(nonce);
    if header.len() != SNELL_V4_HEADER_PLAIN_LEN || header[0] != 4 {
        return Err(anyhow!("invalid snell v4 frame header"));
    }
    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    if payload_len == 0 {
        if padding_len != 0 {
            return Err(anyhow!("snell v4 zero chunk cannot contain padding"));
        }
        return Ok(Vec::new());
    }
    if payload_len > SS_CHUNK_SIZE || padding_len > SS_CHUNK_SIZE {
        return Err(anyhow!("snell v4 frame is too large"));
    }
    let mut frame = decoder
        .read_exact_or_eof(reader, padding_len + payload_len + SS_TAG_LEN)
        .await?
        .ok_or_else(|| anyhow!("snell v4 TLS-obfs stream ended before frame payload"))?;
    let (padding, payload_cipher) = frame.split_at_mut(padding_len);
    swap_snell_v4_padding(padding, payload_cipher);
    let payload = SsCipher::Aes128Gcm.decrypt(key, nonce, payload_cipher)?;
    increment_nonce(nonce);
    Ok(payload)
}

fn spawn_snell_v4_reuse_stream(
    connection: SnellV4PooledConnection,
    pool: Arc<Mutex<SnellV4ConnectionPool>>,
    initial_payload: Vec<u8>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let SnellV4PooledConnection {
        mut reader,
        mut writer,
    } = connection;

    tokio::spawn(async move {
        let mut clean = true;
        let mut upload_closed = false;
        let mut peer_closed = false;
        if !initial_payload.is_empty() && local_write.write_all(&initial_payload).await.is_err() {
            clean = false;
        }

        let mut buffer = vec![0u8; SS_CHUNK_SIZE];
        while clean && !peer_closed {
            tokio::select! {
                local_result = local_read.read(&mut buffer), if !upload_closed => {
                    match local_result {
                        Ok(0) => {
                            if writer.write_zero().await.is_err() {
                                clean = false;
                            }
                            upload_closed = true;
                        }
                        Ok(length) => {
                            if writer.write_payload(&buffer[..length]).await.is_err() {
                                clean = false;
                            }
                        }
                        Err(_) => clean = false,
                    }
                }
                remote_result = reader.read_frame() => {
                    match remote_result {
                        Ok(payload) if payload.is_empty() => {
                            peer_closed = true;
                        }
                        Ok(payload) => {
                            if local_write.write_all(&payload).await.is_err() {
                                clean = false;
                            }
                        }
                        Err(_) => clean = false,
                    }
                }
            }
        }

        if clean && peer_closed && !upload_closed {
            if writer.write_zero().await.is_err() {
                clean = false;
            }
            upload_closed = true;
        }

        if clean && upload_closed && peer_closed {
            pool.lock()
                .await
                .put(SnellV4PooledConnection { reader, writer });
        }
        let _ = local_write.shutdown().await;
    });

    app_side
}

fn spawn_snell_v4_stream(
    psk: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: [u8; SS_NONCE_LEN],
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(length) => {
                    let Ok(frame) =
                        encode_snell_v4_frame(&upload_key, &mut nonce, &buf[..length], 0)
                    else {
                        break;
                    };
                    let write_result = if upload_tls_obfs {
                        remote_write
                            .write_all(&wrap_simple_obfs_tls_app_data(&frame))
                            .await
                    } else {
                        remote_write.write_all(&frame).await
                    };
                    if write_result.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_snell_v4_download(&psk, &mut chained, &mut local_write).await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_snell_v4_tls_download(&psk, remote_read, local_write).await;
        } else {
            relay_snell_v4_download(&psk, &mut remote_read, &mut local_write).await;
        }
    });

    app_side
}

async fn relay_snell_v4_download<R, W>(psk: &[u8], reader: &mut R, writer: &mut W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = [0u8; SNELL_V4_SALT_LEN];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(key) = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = [0u8; SS_NONCE_LEN];
    let response = match read_snell_v4_frame(reader, &key, &mut nonce).await {
        Ok(response) => response,
        Err(_) => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_snell_v4_frame(reader, &key, &mut nonce).await {
            Ok(payload) if payload.is_empty() => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(payload) => {
                if writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

async fn relay_snell_v4_tls_download<R, W>(psk: &[u8], mut reader: R, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, SNELL_V4_SALT_LEN)
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(key) = derive_snell_subkey(SsCipher::Aes128Gcm, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = [0u8; SS_NONCE_LEN];
    let response = match read_snell_v4_frame_from_tls_obfs(
        &mut decoder,
        &mut reader,
        &key,
        &mut nonce,
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_snell_v4_frame_from_tls_obfs(&mut decoder, &mut reader, &key, &mut nonce).await {
            Ok(payload) if payload.is_empty() => {
                let _ = writer.shutdown().await;
                break;
            }
            Ok(payload) => {
                if writer.write_all(&payload).await.is_err() {
                    break;
                }
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}

fn spawn_snell_stream(
    cipher: SsCipher,
    psk: Vec<u8>,
    upload_key: Vec<u8>,
    upload_nonce: Vec<u8>,
    stream: BoxedStream,
    plugin: Option<ShadowsocksPluginConfig>,
) -> DuplexStream {
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, mut remote_write) = tokio::io::split(stream);

    let upload_tls_obfs = plugin_is_tls_obfs(plugin.as_ref());
    tokio::spawn(async move {
        let mut nonce = upload_nonce;
        let mut buf = vec![0u8; SS_CHUNK_SIZE];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if write_ss_plugin_chunk(
                        cipher,
                        &upload_key,
                        &mut nonce,
                        &mut remote_write,
                        &buf[..n],
                        upload_tls_obfs,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if plugin_is_http_obfs(plugin.as_ref()) {
            match read_http_obfs_response(&mut remote_read).await {
                Ok(leftover) => {
                    let cursor = Cursor::new(leftover);
                    let mut chained = cursor.chain(remote_read);
                    relay_snell_download_with_response_salt(
                        cipher,
                        &psk,
                        &mut chained,
                        &mut local_write,
                    )
                    .await;
                }
                Err(_) => {
                    let _ = local_write.shutdown().await;
                }
            }
        } else if plugin_is_tls_obfs(plugin.as_ref()) {
            relay_snell_tls_download_with_response_salt(cipher, &psk, remote_read, local_write)
                .await;
        } else {
            relay_snell_download_with_response_salt(
                cipher,
                &psk,
                &mut remote_read,
                &mut local_write,
            )
            .await;
        }
    });

    app_side
}

async fn relay_snell_download_with_response_salt<R, W>(
    cipher: SsCipher,
    psk: &[u8],
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut response_salt = vec![0u8; cipher.salt_len()];
    if reader.read_exact(&mut response_salt).await.is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    let Ok(response_key) = derive_snell_subkey(cipher, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    let response = match read_ss_chunk(cipher, &response_key, &mut nonce, reader).await {
        Ok(Some(response)) => response,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    relay_shadowsocks_download(cipher, response_key, nonce, reader, writer).await;
}

async fn relay_snell_tls_download_with_response_salt<R, W>(
    cipher: SsCipher,
    psk: &[u8],
    mut reader: R,
    mut writer: W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut decoder = SimpleObfsTlsDecoder::new();
    let response_salt = match decoder
        .read_exact_or_eof(&mut reader, cipher.salt_len())
        .await
    {
        Ok(Some(value)) => value,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    let Ok(response_key) = derive_snell_subkey(cipher, psk, &response_salt) else {
        let _ = writer.shutdown().await;
        return;
    };
    let mut nonce = vec![0u8; cipher.nonce_len()];
    let response = match read_ss_chunk_from_tls_obfs(
        cipher,
        &response_key,
        &mut nonce,
        &mut decoder,
        &mut reader,
    )
    .await
    {
        Ok(Some(response)) => response,
        _ => {
            let _ = writer.shutdown().await;
            return;
        }
    };
    if validate_snell_response(&response, "TCP connect").is_err() {
        let _ = writer.shutdown().await;
        return;
    }
    if response.len() > 1 && writer.write_all(&response[1..]).await.is_err() {
        return;
    }
    loop {
        match read_ss_chunk_from_tls_obfs(
            cipher,
            &response_key,
            &mut nonce,
            &mut decoder,
            &mut reader,
        )
        .await
        {
            Ok(Some(plaintext)) => {
                if writer.write_all(&plaintext).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = writer.shutdown().await;
                break;
            }
            Err(_) => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }
}
