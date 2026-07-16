use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::lookup_host,
    time::timeout,
};

use super::tls::NoCertificateVerification;

pub(crate) fn quic_client_config(
    skip_cert_verify: bool,
    alpn: Option<&str>,
) -> anyhow::Result<quinn::ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    let protocols = alpn
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| item.as_bytes().to_vec())
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| vec![b"h3".to_vec()]);
    config.alpn_protocols = protocols;
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .context("failed to build quic rustls client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

pub(crate) async fn resolve_quic_remote(
    protocol: &str,
    server: &str,
    port: u16,
) -> anyhow::Result<SocketAddr> {
    lookup_host((server, port))
        .await
        .with_context(|| format!("failed to resolve {protocol} server {server}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("{protocol} server {server}:{port} did not resolve"))
}

pub(crate) fn quic_bind_addr(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()
    .expect("valid QUIC bind address")
}

pub(crate) async fn connect_quic_endpoint(
    mut endpoint: quinn::Endpoint,
    remote: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
    timeout_ms: u64,
    protocol: &str,
) -> anyhow::Result<(quinn::Endpoint, quinn::Connection)> {
    endpoint.set_default_client_config(client_config);
    let connection = timeout(
        Duration::from_millis(timeout_ms),
        endpoint.connect(remote, server_name)?,
    )
    .await
    .with_context(|| format!("{protocol} quic connect timed out"))?
    .with_context(|| format!("{protocol} quic connect failed"))?;
    Ok((endpoint, connection))
}

pub(crate) fn encode_quic_varint(value: u64, output: &mut Vec<u8>) -> anyhow::Result<()> {
    match value {
        0..=0x3f => output.push(value as u8),
        0x40..=0x3fff => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => return Err(anyhow!("quic varint value is too large")),
    }
    Ok(())
}

pub(crate) async fn read_quic_varint<R>(reader: &mut R) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..len {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        value = (value << 8) | byte[0] as u64;
    }
    Ok(value)
}

pub(crate) fn read_quic_varint_from_slice(input: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    if *cursor >= input.len() {
        return Err(anyhow!("quic varint is missing"));
    }
    let first = input[*cursor];
    let tag = first >> 6;
    let len = 1usize << tag;
    if *cursor + len > input.len() {
        return Err(anyhow!("quic varint is truncated"));
    }
    *cursor += 1;
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | input[*cursor] as u64;
        *cursor += 1;
    }
    Ok(value)
}

pub(crate) fn random_u16() -> anyhow::Result<u16> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).context("failed to generate random u16")?;
    Ok(u16::from_be_bytes(bytes))
}

pub(crate) fn random_u32() -> anyhow::Result<u32> {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).context("failed to generate random u32")?;
    Ok(u32::from_be_bytes(bytes))
}
