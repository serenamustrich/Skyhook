use std::sync::Arc;

use anyhow::Context;
use rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};

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
