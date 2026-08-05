use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use rustls::{
    client::{danger::ServerCertVerifier, ClientSessionStore, Resumption},
    crypto::aws_lc_rs,
    ClientConfig, RootCertStore,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::lookup_host,
    time::timeout,
};

use crate::outbound::context::active_dial_context;

use super::{
    order_addresses,
    tls::{pinned_certificate_chain_verifier, NoCertificateVerification},
};
use crate::outbound::udp::create_bound_std_udp;

#[derive(Debug, Clone, Default)]
pub(crate) struct QuicTransportTuning {
    pub(crate) stream_receive_window: Option<u64>,
    pub(crate) receive_window: Option<u64>,
    pub(crate) max_idle_timeout: Option<Duration>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) initial_mtu: Option<u16>,
    pub(crate) disable_mtu_discovery: bool,
}

#[cfg(test)]
pub(crate) fn quic_client_config(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
) -> anyhow::Result<quinn::ClientConfig> {
    quic_client_config_with_resumption(skip_cert_verify, alpn, congestion_control, None, false)
}

pub(crate) fn quic_client_config_with_controller(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
    controller: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
) -> anyhow::Result<quinn::ClientConfig> {
    quic_client_config_advanced(
        skip_cert_verify,
        alpn,
        congestion_control,
        None,
        false,
        Some(controller),
        None,
        None,
    )
}

pub(crate) fn quic_client_config_with_controller_and_tuning(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
    controller: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>,
    tuning: QuicTransportTuning,
) -> anyhow::Result<quinn::ClientConfig> {
    quic_client_config_advanced(
        skip_cert_verify,
        alpn,
        congestion_control,
        None,
        false,
        Some(controller),
        Some(tuning),
        None,
    )
}

pub(crate) fn quic_client_config_with_resumption(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
    session_store: Option<Arc<dyn ClientSessionStore>>,
    enable_early_data: bool,
) -> anyhow::Result<quinn::ClientConfig> {
    quic_client_config_advanced(
        skip_cert_verify,
        alpn,
        congestion_control,
        session_store,
        enable_early_data,
        None,
        None,
        None,
    )
}

pub(crate) fn quic_client_config_with_resumption_tuning_and_chain_pin(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
    session_store: Option<Arc<dyn ClientSessionStore>>,
    enable_early_data: bool,
    tuning: QuicTransportTuning,
    certificate_chain_pin: Option<[u8; 32]>,
) -> anyhow::Result<quinn::ClientConfig> {
    quic_client_config_advanced(
        skip_cert_verify,
        alpn,
        congestion_control,
        session_store,
        enable_early_data,
        None,
        Some(tuning),
        certificate_chain_pin,
    )
}

fn quic_client_config_advanced(
    skip_cert_verify: bool,
    alpn: Option<&str>,
    congestion_control: Option<&str>,
    session_store: Option<Arc<dyn ClientSessionStore>>,
    enable_early_data: bool,
    controller: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
    tuning: Option<QuicTransportTuning>,
    certificate_chain_pin: Option<[u8; 32]>,
) -> anyhow::Result<quinn::ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let verifier: Option<Arc<dyn ServerCertVerifier>> = if let Some(pin) = certificate_chain_pin {
        Some(pinned_certificate_chain_verifier(pin)?)
    } else if skip_cert_verify {
        Some(Arc::new(NoCertificateVerification))
    } else {
        None
    };
    let mut config = if let Some(verifier) = verifier {
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
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
    let active = active_dial_context();
    if let Some(session_store) = session_store {
        config.resumption = Resumption::store(session_store);
    }
    config.enable_early_data =
        enable_early_data || active.as_ref().is_some_and(|context| context.quic_zero_rtt);
    quic_client_config_from_rustls_advanced(config, congestion_control, controller, tuning, active)
}

pub(crate) fn quic_client_config_from_rustls(
    config: ClientConfig,
    congestion_control: Option<&str>,
    tuning: QuicTransportTuning,
    initial_window: Option<u64>,
) -> anyhow::Result<quinn::ClientConfig> {
    let controller = match initial_window {
        Some(window) => congestion_controller(congestion_control, Some(window))?,
        None => None,
    };
    quic_client_config_from_rustls_advanced(
        config,
        congestion_control,
        controller,
        Some(tuning),
        active_dial_context(),
    )
}

fn quic_client_config_from_rustls_advanced(
    config: ClientConfig,
    congestion_control: Option<&str>,
    controller: Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>,
    tuning: Option<QuicTransportTuning>,
    active: Option<crate::outbound::context::DialContext>,
) -> anyhow::Result<quinn::ClientConfig> {
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .context("failed to build quic rustls client config")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    if let Some(controller) = controller {
        transport_config.congestion_controller_factory(controller);
    } else {
        if let Some(controller) = congestion_controller(congestion_control, None)? {
            transport_config.congestion_controller_factory(controller);
        }
    }
    if let Some(tuning) = tuning {
        if let Some(window) = tuning.stream_receive_window {
            transport_config.stream_receive_window(
                quinn::VarInt::from_u64(window)
                    .map_err(|_| anyhow!("QUIC stream receive window is too large"))?,
            );
        }
        if let Some(window) = tuning.receive_window {
            transport_config.receive_window(
                quinn::VarInt::from_u64(window)
                    .map_err(|_| anyhow!("QUIC connection receive window is too large"))?,
            );
        }
        if let Some(idle_timeout) = tuning.max_idle_timeout {
            transport_config.max_idle_timeout(Some(
                idle_timeout
                    .try_into()
                    .map_err(|_| anyhow!("QUIC idle timeout is too large"))?,
            ));
        }
        transport_config.keep_alive_interval(tuning.keep_alive_interval);
        if let Some(mtu) = tuning.initial_mtu {
            let mtu = mtu.clamp(1_200, 65_527);
            transport_config.initial_mtu(mtu).min_mtu(mtu.min(1_200));
        }
        if tuning.disable_mtu_discovery {
            transport_config.mtu_discovery_config(None);
        }
    }
    if let Some(context) = active {
        if let Some(keepalive) = context.keepalive {
            transport_config.keep_alive_interval(Some(keepalive));
        }
        if let Some(mtu) = context.quic_mtu {
            let mtu = mtu.clamp(1_200, 65_527);
            transport_config.initial_mtu(mtu).min_mtu(mtu.min(1_200));
        }
    }
    client_config.transport_config(Arc::new(transport_config));
    Ok(client_config)
}

fn congestion_controller(
    congestion_control: Option<&str>,
    initial_window: Option<u64>,
) -> anyhow::Result<Option<Arc<dyn quinn::congestion::ControllerFactory + Send + Sync>>> {
    let name = congestion_control
        .unwrap_or("cubic")
        .trim()
        .to_ascii_lowercase();
    match name.as_str() {
        "" | "default" | "cubic" if initial_window.is_none() => Ok(None),
        "" | "default" | "cubic" => {
            let mut config = quinn::congestion::CubicConfig::default();
            config.initial_window(initial_window.expect("guarded initial window"));
            Ok(Some(Arc::new(config)))
        }
        "bbr" | "bbr_meta_v1" | "bbr-meta-v1" | "bbr_meta_v2" | "bbr-meta-v2" => {
            let mut config = quinn::congestion::BbrConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Ok(Some(Arc::new(config)))
        }
        "new-reno" | "new_reno" | "newreno" => {
            let mut config = quinn::congestion::NewRenoConfig::default();
            if let Some(window) = initial_window {
                config.initial_window(window);
            }
            Ok(Some(Arc::new(config)))
        }
        value => Err(anyhow!("unsupported QUIC congestion controller {value}")),
    }
}

pub(crate) struct ResumableQuicConnection {
    pub(crate) endpoint: quinn::Endpoint,
    pub(crate) connection: quinn::Connection,
    pub(crate) zero_rtt_accepted: Option<quinn::ZeroRttAccepted>,
}

pub(crate) async fn resolve_quic_remote(
    protocol: &str,
    server: &str,
    port: u16,
) -> anyhow::Result<SocketAddr> {
    let active = active_dial_context();
    let timeout_budget = active
        .as_ref()
        .map(|context| context.remaining_timeout())
        .unwrap_or_else(|| Duration::from_secs(10));
    if timeout_budget.is_zero() {
        return Err(anyhow!("{protocol} resolve deadline expired"));
    }
    let cancellation = active
        .as_ref()
        .map(|context| context.cancellation.clone())
        .unwrap_or_default();
    let strategy = active
        .as_ref()
        .map(|context| context.ip_version)
        .unwrap_or_default();
    let resolved = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("{protocol} resolve cancelled")),
        result = timeout(timeout_budget, lookup_host((server, port))) => {
            result
                .with_context(|| format!("{protocol} resolve timed out"))?
                .with_context(|| format!("failed to resolve {protocol} server {server}:{port}"))?
                .collect::<Vec<_>>()
        }
    };
    order_addresses(resolved, strategy)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{protocol} server {server}:{port} did not resolve"))
}

pub(crate) fn create_quic_endpoint(remote: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        create_bound_std_udp(remote)?,
        Arc::new(quinn::TokioRuntime),
    )
    .context("failed to create QUIC endpoint")
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
    let active = active_dial_context();
    let timeout_budget = active
        .as_ref()
        .map(|context| Duration::from_millis(timeout_ms).min(context.remaining_timeout()))
        .unwrap_or_else(|| Duration::from_millis(timeout_ms));
    let cancellation = active
        .as_ref()
        .map(|context| context.cancellation.clone())
        .unwrap_or_default();
    let connection = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("{protocol} quic connect cancelled")),
        result = timeout(timeout_budget, endpoint.connect(remote, server_name)?) => {
            result
                .with_context(|| format!("{protocol} quic connect timed out"))?
                .with_context(|| format!("{protocol} quic connect failed"))?
        }
    };
    Ok((endpoint, connection))
}

pub(crate) async fn connect_quic_endpoint_resumable(
    mut endpoint: quinn::Endpoint,
    remote: SocketAddr,
    server_name: &str,
    client_config: quinn::ClientConfig,
    attempt_zero_rtt: bool,
    timeout_ms: u64,
    protocol: &str,
) -> anyhow::Result<ResumableQuicConnection> {
    endpoint.set_default_client_config(client_config);
    let active = active_dial_context();
    let timeout_budget = active
        .as_ref()
        .map(|context| Duration::from_millis(timeout_ms).min(context.remaining_timeout()))
        .unwrap_or_else(|| Duration::from_millis(timeout_ms));
    if timeout_budget.is_zero() {
        return Err(anyhow!("{protocol} quic connect timed out"));
    }
    let cancellation = active
        .as_ref()
        .map(|context| context.cancellation.clone())
        .unwrap_or_default();
    let connecting = endpoint.connect(remote, server_name)?;
    let connecting = if attempt_zero_rtt {
        match connecting.into_0rtt() {
            Ok((connection, zero_rtt_accepted)) => {
                return Ok(ResumableQuicConnection {
                    endpoint,
                    connection,
                    zero_rtt_accepted: Some(zero_rtt_accepted),
                });
            }
            Err(connecting) => connecting,
        }
    } else {
        connecting
    };
    let connection = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("{protocol} quic connect cancelled")),
        result = timeout(timeout_budget, connecting) => {
            result
                .with_context(|| format!("{protocol} quic connect timed out"))?
                .with_context(|| format!("{protocol} quic connect failed"))?
        }
    };
    Ok(ResumableQuicConnection {
        endpoint,
        connection,
        zero_rtt_accepted: None,
    })
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
