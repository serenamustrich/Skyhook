use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

use crate::routing::Destination;

use super::{
    apply_shadowsocks_plugin_request, build_snell_tcp_handshake, build_snell_udp_packet,
    connect_tcp, derive_snell_subkey, encode_snell_v4_frame, encode_ss_chunk,
    parse_snell_udp_response, read_snell_v4_frame, read_ss_chunk, snell_cipher, snell_obfs_plugin,
    snell_v4_initial_padding_len, spawn_snell_stream, spawn_snell_v4_reuse_stream,
    spawn_snell_v4_stream, validate_snell_response, validate_snell_version, BoxedStream, Outbound,
    OutboundCapability, SnellV4ConnectionPool, SnellV4PooledConnection, SsCipher,
    SNELL_COMMAND_UDP, SNELL_V4_SALT_LEN, SS_CHUNK_SIZE, SS_NONCE_LEN,
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
