use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Context};
use rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{config::SuperConfig, routing::Destination};

use super::Runtime;

impl Runtime {
    pub async fn exchange_dns_over_tcp(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if query.len() > u16::MAX as usize {
            return Err(anyhow!("dns query is too large"));
        }
        let config = self.config();
        if !config.dns.enabled {
            return Err(anyhow!("dns proxy is disabled"));
        }
        let cancellation = self.cancellation_token();
        let operation = async {
            match dns_upstream(&config) {
                DnsUpstream::Https(url) => {
                    timeout(Duration::from_millis(config.dns.timeout_ms), async {
                        let client = reqwest::Client::builder()
                            .build()
                            .context("failed to build doh client")?;
                        let response = client
                            .post(url)
                            .header("accept", "application/dns-message")
                            .header("content-type", "application/dns-message")
                            .body(query.to_vec())
                            .send()
                            .await?
                            .error_for_status()?
                            .bytes()
                            .await?;
                        Ok::<_, anyhow::Error>(response.to_vec())
                    })
                    .await
                    .map_err(|_| anyhow!("doh query timed out after {}ms", config.dns.timeout_ms))?
                }
                DnsUpstream::Tls { host, port, sni } => {
                    timeout(Duration::from_millis(config.dns.timeout_ms), async {
                        let tcp = TcpStream::connect((host.as_str(), port))
                            .await
                            .with_context(|| {
                                format!("failed to connect dot upstream {host}:{port}")
                            })?;
                        let connector = TlsConnector::from(Arc::new(dns_tls_client_config()?));
                        let server_name = ServerName::try_from(sni.clone())
                            .map_err(|error| anyhow!("invalid dot server name: {error}"))?;
                        let mut stream = connector
                            .connect(server_name, tcp)
                            .await
                            .context("dot tls handshake failed")?;
                        let mut framed = Vec::with_capacity(query.len() + 2);
                        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                        framed.extend_from_slice(query);
                        stream.write_all(&framed).await?;

                        let mut len = [0u8; 2];
                        stream.read_exact(&mut len).await?;
                        let response_len = u16::from_be_bytes(len) as usize;
                        let mut response = vec![0u8; response_len];
                        stream.read_exact(&mut response).await?;
                        Ok::<_, anyhow::Error>(response)
                    })
                    .await
                    .map_err(|_| anyhow!("dot query timed out after {}ms", config.dns.timeout_ms))?
                }
                DnsUpstream::Plain(destination) => {
                    timeout(Duration::from_millis(config.dns.timeout_ms), async {
                        let (mut stream, _decision, _outbound_name) =
                            self.connect_outbound(&destination).await?;
                        let mut framed = Vec::with_capacity(query.len() + 2);
                        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                        framed.extend_from_slice(query);
                        stream.write_all(&framed).await?;

                        let mut len = [0u8; 2];
                        stream.read_exact(&mut len).await?;
                        let response_len = u16::from_be_bytes(len) as usize;
                        let mut response = vec![0u8; response_len];
                        stream.read_exact(&mut response).await?;
                        Ok::<_, anyhow::Error>(response)
                    })
                    .await
                    .map_err(|_| {
                        anyhow!("dns over tcp timed out after {}ms", config.dns.timeout_ms)
                    })?
                }
                DnsUpstream::System => {
                    let mut servers = crate::inbound::dns::discover_system_dns_servers();
                    servers.extend(
                        config
                            .dns
                            .direct_nameserver
                            .iter()
                            .filter_map(|item| crate::inbound::dns::parse_plain_dns_server(item)),
                    );
                    let mut seen = HashSet::new();
                    servers.retain(|server| seen.insert(*server));
                    let budget = Duration::from_millis(config.dns.timeout_ms.clamp(100, 10_000));
                    let mut errors = Vec::new();
                    let mut successful = None;
                    for server in servers {
                        match crate::inbound::dns::exchange_system_dns_server(
                            server,
                            query,
                            budget,
                            &cancellation,
                        )
                        .await
                        {
                            Ok(response) => {
                                successful = Some(response);
                                break;
                            }
                            Err(error) => errors.push(format!("{server}: {error}")),
                        }
                    }
                    Ok(successful.ok_or_else(|| {
                        anyhow!(
                            "system DNS resolution failed: {}",
                            if errors.is_empty() {
                                "no system resolver discovered".to_string()
                            } else {
                                errors.join("; ")
                            }
                        )
                    })?)
                }
            }
        };

        tokio::select! {
            _ = cancellation.cancelled() => Err(anyhow!("dns query cancelled")),
            result = operation => result,
        }
    }
}

enum DnsUpstream {
    Plain(Destination),
    System,
    Https(String),
    Tls {
        host: String,
        port: u16,
        sni: String,
    },
}

fn dns_upstream(config: &SuperConfig) -> DnsUpstream {
    config
        .dns
        .nameserver
        .iter()
        .chain(config.dns.default_nameserver.iter())
        .find_map(|item| parse_dns_upstream(item))
        .unwrap_or_else(|| {
            if config.dns.server.ip().is_loopback() && config.dns.server.port() == 53 {
                DnsUpstream::System
            } else {
                DnsUpstream::Plain(Destination::new(
                    config.dns.server.ip().to_string(),
                    config.dns.server.port(),
                ))
            }
        })
}

fn parse_dns_upstream(value: &str) -> Option<DnsUpstream> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(value) {
        let scheme = url.scheme().to_ascii_lowercase();
        if matches!(scheme.as_str(), "https" | "doh") {
            let mut url = url;
            if scheme == "doh" {
                url.set_scheme("https").ok()?;
            }
            return Some(DnsUpstream::Https(url.to_string()));
        }
        if matches!(scheme.as_str(), "tls" | "dot") {
            let host = url.host_str()?.trim_matches(['[', ']']).to_string();
            let port = url.port().unwrap_or(853);
            let sni = url
                .query_pairs()
                .find_map(|(key, value)| {
                    matches!(key.as_ref(), "sni" | "servername").then(|| value.into_owned())
                })
                .unwrap_or_else(|| host.clone());
            return Some(DnsUpstream::Tls { host, port, sni });
        }
    }
    parse_dns_plain_destination(value).map(DnsUpstream::Plain)
}

fn parse_dns_plain_destination(value: &str) -> Option<Destination> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
        return Some(Destination::new(addr.ip().to_string(), addr.port()));
    }
    if let Ok(url) = Url::parse(value) {
        let scheme = url.scheme().to_ascii_lowercase();
        if !matches!(scheme.as_str(), "udp" | "tcp" | "dns") {
            return None;
        }
        let host = url.host_str()?.trim_matches(['[', ']']).to_string();
        let port = url.port().unwrap_or(53);
        return Some(Destination::new(host, port));
    }
    let (host, port) = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((value, 53));
    Some(Destination::new(host.trim_matches(['[', ']']), port))
}

pub(super) fn dns_tls_client_config() -> anyhow::Result<ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(config)
}
