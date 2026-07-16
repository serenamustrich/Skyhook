use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use md5::Md5;
use rustls_pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::routing::Destination;

use super::{
    io::read_exact_or_eof,
    target::encode_socks5_destination,
    transports::{connect_tcp, tls_client_config},
    util::hex_lower,
    BoxedStream, Outbound, OutboundCapability,
};

const DEFAULT_SID: u32 = 1;
const DEFAULT_AUTH_PADDING: usize = 30;
const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

pub(super) struct AnyTlsOutbound {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: Option<String>,
    skip_cert_verify: bool,
    alpn: Vec<String>,
}

impl AnyTlsOutbound {
    pub(super) fn new(
        name: String,
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_cert_verify: bool,
        alpn: Vec<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            alpn,
        }
    }
}

#[async_trait]
impl Outbound for AnyTlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "anytls"
    }

    fn capability(&self) -> OutboundCapability {
        OutboundCapability::tcp_only("anytls udp is not supported")
    }

    async fn connect(
        &self,
        destination: &Destination,
        timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        if self.password.is_empty() {
            return Err(anyhow!("anytls password is empty"));
        }
        let tcp = connect_tcp(&format!("{}:{}", self.server, self.port), timeout_ms).await?;
        let server_name = self.sni.as_deref().unwrap_or(&self.server).to_string();
        let mut tls_config = tls_client_config(self.skip_cert_verify)?;
        tls_config.alpn_protocols = self
            .alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tls_server_name = ServerName::try_from(server_name)
            .map_err(|error| anyhow!("invalid anytls server name: {error}"))?;
        let mut stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(tls_server_name, tcp),
        )
        .await
        .context("anytls tls handshake timed out")?
        .context("anytls tls handshake failed")?;

        let password_hash: [u8; 32] = Sha256::digest(self.password.as_bytes()).into();
        let mut auth = Vec::with_capacity(32 + 2 + DEFAULT_AUTH_PADDING);
        auth.extend_from_slice(&password_hash);
        auth.extend_from_slice(&(DEFAULT_AUTH_PADDING as u16).to_be_bytes());
        auth.resize(auth.len() + DEFAULT_AUTH_PADDING, 0);
        stream.write_all(&auth).await?;

        let settings = build_settings();
        write_frame(&mut stream, CMD_SETTINGS, 0, settings.as_bytes()).await?;
        write_frame(&mut stream, CMD_SYN, DEFAULT_SID, &[]).await?;

        let mut target = Vec::new();
        encode_socks5_destination(destination, &mut target)?;
        write_frame(&mut stream, CMD_PSH, DEFAULT_SID, &target).await?;
        stream.flush().await?;

        let mut early_data = Vec::new();
        loop {
            let frame = timeout(Duration::from_millis(timeout_ms), read_frame(&mut stream))
                .await
                .context("anytls stream open timed out")?
                .context("failed to read anytls stream-open frame")?
                .ok_or_else(|| anyhow!("anytls server closed during stream open"))?;
            match frame.command {
                CMD_SYNACK if frame.sid == DEFAULT_SID => {
                    if !frame.data.is_empty() {
                        return Err(anyhow!(
                            "anytls server rejected stream: {}",
                            String::from_utf8_lossy(&frame.data)
                        ));
                    }
                    break;
                }
                CMD_SERVER_SETTINGS | CMD_WASTE => {}
                CMD_PSH if frame.sid == DEFAULT_SID => {
                    early_data.extend_from_slice(&frame.data);
                    break;
                }
                CMD_ALERT => {
                    return Err(anyhow!(
                        "anytls alert: {}",
                        String::from_utf8_lossy(&frame.data)
                    ));
                }
                _ => {}
            }
        }

        Ok(Box::new(spawn_stream(stream, early_data)))
    }
}

struct Frame {
    command: u8,
    sid: u32,
    data: Vec<u8>,
}

fn build_settings() -> String {
    format!(
        "v=3\nclient=supercore/{}\npadding-md5={}",
        env!("CARGO_PKG_VERSION"),
        default_padding_md5()
    )
}

fn default_padding_md5() -> String {
    const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
    hex_lower(&Md5::digest(DEFAULT_PADDING_SCHEME.as_bytes()))
}

async fn write_frame<W>(writer: &mut W, command: u8, sid: u32, data: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.len() > u16::MAX as usize {
        return Err(anyhow!("anytls frame data is too large"));
    }
    let mut header = [0u8; 7];
    header[0] = command;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> anyhow::Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 7];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let command = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok(Some(Frame { command, sid, data }))
}

fn spawn_stream<S>(stream: S, early_data: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, relay_side) = tokio::io::duplex(64 * 1024);
    let (mut local_read, mut local_write) = tokio::io::split(relay_side);
    let (mut remote_read, remote_write) = tokio::io::split(stream);
    let remote_write = Arc::new(Mutex::new(remote_write));

    let upload_writer = remote_write.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => {
                    let mut writer = upload_writer.lock().await;
                    let _ = write_frame(&mut *writer, CMD_FIN, DEFAULT_SID, &[]).await;
                    let _ = writer.flush().await;
                    break;
                }
                Ok(n) => {
                    let mut writer = upload_writer.lock().await;
                    if write_frame(&mut *writer, CMD_PSH, DEFAULT_SID, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        if !early_data.is_empty() && local_write.write_all(&early_data).await.is_err() {
            let _ = local_write.shutdown().await;
            return;
        }
        loop {
            match read_frame(&mut remote_read).await {
                Ok(Some(frame)) => match frame.command {
                    CMD_PSH if frame.sid == DEFAULT_SID => {
                        if local_write.write_all(&frame.data).await.is_err() {
                            break;
                        }
                    }
                    CMD_FIN if frame.sid == DEFAULT_SID => {
                        let _ = local_write.shutdown().await;
                        break;
                    }
                    CMD_HEART_REQUEST => {
                        let mut writer = remote_write.lock().await;
                        let _ = write_frame(&mut *writer, CMD_HEART_RESPONSE, 0, &[]).await;
                        let _ = writer.flush().await;
                    }
                    CMD_ALERT => {
                        let _ = local_write.shutdown().await;
                        break;
                    }
                    CMD_WASTE | CMD_SERVER_SETTINGS | CMD_HEART_RESPONSE | CMD_SYNACK => {}
                    _ => {}
                },
                Ok(None) | Err(_) => {
                    let _ = local_write.shutdown().await;
                    break;
                }
            }
        }
    });

    app_side
}
