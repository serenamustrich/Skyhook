use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::{config::DnsConfig, routing::Destination};

use super::{
    target::destination_socket_addr,
    transports::connect_tcp,
    udp::{create_bound_udp, resolve_udp_socket_addr},
    BoxedStream, Outbound, OutboundCapability,
};

pub(crate) struct DnsOutbound {
    name: String,
    config: DnsConfig,
}

impl DnsOutbound {
    pub(crate) fn new(name: String, config: DnsConfig) -> Self {
        Self { name, config }
    }

    fn resolver(&self) -> DnsResolver {
        DnsResolver::new(self.config.clone())
    }
}

#[async_trait]
impl Outbound for DnsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "dns"
    }

    fn capability(&self) -> OutboundCapability {
        if !self.config.enabled {
            return OutboundCapability::unsupported("DNS outbound requires dns.enabled");
        }
        OutboundCapability::udp_only(
            "internal-dns",
            "DNS outbound accepts raw DNS queries through UDP only",
        )
    }

    async fn connect(
        &self,
        _destination: &Destination,
        _timeout_ms: u64,
    ) -> anyhow::Result<BoxedStream> {
        Err(anyhow!(
            "DNS outbound does not expose a byte stream; use UDP DNS queries"
        ))
    }

    async fn udp_exchange(
        &self,
        destination: &Destination,
        payload: &[u8],
        timeout_ms: u64,
    ) -> anyhow::Result<Vec<u8>> {
        if destination.port != 53 {
            return Err(anyhow!(
                "DNS outbound only accepts destination port 53, got {}",
                destination.port
            ));
        }
        self.resolver().exchange(payload, timeout_ms).await
    }
}

#[derive(Clone)]
struct DnsResolver {
    config: DnsConfig,
}

impl DnsResolver {
    fn new(config: DnsConfig) -> Self {
        Self { config }
    }

    async fn exchange(&self, query: &[u8], timeout_ms: u64) -> anyhow::Result<Vec<u8>> {
        if query.is_empty() || query.len() > u16::MAX as usize {
            return Err(anyhow!("DNS query must contain between 1 and 65535 bytes"));
        }
        if !self.config.enabled {
            return Err(anyhow!("DNS outbound is disabled"));
        }
        let upstream = self.upstream().ok_or_else(|| {
            anyhow!("DNS outbound has no usable nameserver or default-nameserver")
        })?;
        timeout(
            Duration::from_millis(timeout_ms.max(1)),
            self.exchange_upstream(upstream, query),
        )
        .await
        .context("DNS outbound query timed out")?
    }

    fn upstream(&self) -> Option<DnsUpstream> {
        self.config
            .nameserver
            .iter()
            .chain(self.config.default_nameserver.iter())
            .find_map(|value| parse_upstream(value))
            .or_else(|| {
                Some(DnsUpstream::Udp(Destination::new(
                    self.config.server.ip().to_string(),
                    self.config.server.port(),
                )))
            })
    }

    async fn exchange_upstream(
        &self,
        upstream: DnsUpstream,
        query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        match upstream {
            DnsUpstream::Udp(destination) => {
                let target = resolve_udp_socket_addr(
                    &destination.host,
                    destination.port,
                    self.config.timeout_ms,
                )
                .await?;
                let socket = create_bound_udp(target)?;
                socket.send_to(query, target).await?;
                let mut response = vec![0u8; 65_535];
                let (length, source) = socket.recv_from(&mut response).await?;
                if source != target {
                    return Err(anyhow!(
                        "DNS UDP response came from unexpected source {source}"
                    ));
                }
                response.truncate(length);
                Ok(response)
            }
            DnsUpstream::Tcp(destination) => {
                let mut stream = connect_tcp(
                    &destination_socket_addr(&destination),
                    self.config.timeout_ms,
                )
                .await?;
                exchange_dns_tcp(&mut stream, query).await
            }
            DnsUpstream::Tls { host, port, sni } => {
                let tcp = TcpStream::connect((host.as_str(), port)).await?;
                let connector = TlsConnector::from(Arc::new(dns_tls_client_config()?));
                let server_name = ServerName::try_from(sni)
                    .map_err(|error| anyhow!("invalid DNS-over-TLS server name: {error}"))?;
                let mut stream = connector.connect(server_name, tcp).await?;
                exchange_dns_tcp(&mut stream, query).await
            }
            DnsUpstream::Https(url) => {
                let response = reqwest::Client::builder()
                    .timeout(Duration::from_millis(self.config.timeout_ms.max(1)))
                    .build()?
                    .post(url)
                    .header("accept", "application/dns-message")
                    .header("content-type", "application/dns-message")
                    .body(query.to_vec())
                    .send()
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?;
                Ok(response.to_vec())
            }
        }
    }
}

async fn exchange_dns_tcp<S>(stream: &mut S, query: &[u8]) -> anyhow::Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let response_len = stream.read_u16().await? as usize;
    if response_len == 0 {
        return Err(anyhow!("DNS TCP upstream returned an empty response"));
    }
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

enum DnsUpstream {
    Udp(Destination),
    Tcp(Destination),
    Tls {
        host: String,
        port: u16,
        sni: String,
    },
    Https(String),
}

fn parse_upstream(value: &str) -> Option<DnsUpstream> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(value) {
        let scheme = url.scheme().to_ascii_lowercase();
        let host = url.host_str()?.trim_matches(['[', ']']).to_string();
        match scheme.as_str() {
            "https" | "doh" => return Some(DnsUpstream::Https(url.to_string())),
            "tls" | "dot" => {
                let sni = url
                    .query_pairs()
                    .find_map(|(key, value)| {
                        matches!(key.as_ref(), "sni" | "servername").then(|| value.into_owned())
                    })
                    .unwrap_or_else(|| host.clone());
                return Some(DnsUpstream::Tls {
                    host,
                    port: url.port().unwrap_or(853),
                    sni,
                });
            }
            "tcp" => {
                return Some(DnsUpstream::Tcp(Destination::new(
                    host,
                    url.port().unwrap_or(53),
                )));
            }
            "udp" | "dns" => {
                return Some(DnsUpstream::Udp(Destination::new(
                    host,
                    url.port().unwrap_or(53),
                )));
            }
            _ => {}
        }
    }
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return Some(DnsUpstream::Udp(Destination::new(
            address.ip().to_string(),
            address.port(),
        )));
    }
    let (host, port) = value
        .rsplit_once(':')
        .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
        .unwrap_or((value, 53));
    Some(DnsUpstream::Udp(Destination::new(
        host.trim_matches(['[', ']']),
        port,
    )))
}

fn dns_tls_client_config() -> anyhow::Result<ClientConfig> {
    let provider = aws_lc_rs::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(config)
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn dns_outbound_round_trips_raw_query_over_udp() {
        let server = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("DNS test server");
        let port = server.local_addr().expect("DNS server address").port();
        let task = tokio::spawn(async move {
            let mut query = [0u8; 512];
            let (length, peer) = server.recv_from(&mut query).await.expect("DNS query");
            assert_eq!(&query[..length], b"skyhook-dns-query");
            server
                .send_to(b"skyhook-dns-response", peer)
                .await
                .expect("DNS response");
        });
        let mut config = DnsConfig::default();
        config.nameserver = vec![format!("udp://127.0.0.1:{port}")];
        let outbound = DnsOutbound::new("dns-out".to_string(), config);
        let response = outbound
            .udp_exchange(
                &Destination::new("dns.internal", 53),
                b"skyhook-dns-query",
                1_000,
            )
            .await
            .expect("DNS outbound response");
        assert_eq!(response, b"skyhook-dns-response");
        task.await.expect("DNS test server task");
    }

    #[tokio::test]
    async fn dns_outbound_round_trips_length_prefixed_query_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("DNS TCP test server");
        let port = listener.local_addr().expect("DNS server address").port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("DNS TCP connection");
            let query_len = stream.read_u16().await.expect("DNS query length") as usize;
            let mut query = vec![0u8; query_len];
            stream.read_exact(&mut query).await.expect("DNS query");
            assert_eq!(query, b"skyhook-dns-tcp-query");
            stream
                .write_all(&(b"skyhook-dns-tcp-response".len() as u16).to_be_bytes())
                .await
                .expect("DNS response length");
            stream
                .write_all(b"skyhook-dns-tcp-response")
                .await
                .expect("DNS response");
        });
        let mut config = DnsConfig::default();
        config.nameserver = vec![format!("tcp://127.0.0.1:{port}")];
        let outbound = DnsOutbound::new("dns-out".to_string(), config);
        let response = outbound
            .udp_exchange(
                &Destination::new("dns.internal", 53),
                b"skyhook-dns-tcp-query",
                1_000,
            )
            .await
            .expect("DNS outbound response");
        assert_eq!(response, b"skyhook-dns-tcp-response");
        task.await.expect("DNS test server task");
    }

    #[test]
    fn parses_secure_dns_upstreams() {
        assert!(matches!(
            parse_upstream("dot://cloudflare-dns.com:853"),
            Some(DnsUpstream::Tls { host, port, sni })
                if host == "cloudflare-dns.com" && port == 853 && sni == "cloudflare-dns.com"
        ));
        assert!(matches!(
            parse_upstream("https://cloudflare-dns.com/dns-query"),
            Some(DnsUpstream::Https(url)) if url == "https://cloudflare-dns.com/dns-query"
        ));
    }
}
