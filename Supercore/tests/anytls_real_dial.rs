use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use supercore::{config::OutboundConfig, outbound::build_outbounds, routing::Destination};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const PASSWORD: &str = "independent-anytls-test-password";
const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

struct AnyTlsTestServer {
    address: SocketAddr,
    accepted_sessions: Arc<AtomicUsize>,
    stream_ids: Arc<Mutex<Vec<u32>>>,
    heart_responses: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct ServerStreamState {
    target: Option<Destination>,
    uot_destination: Option<Destination>,
    pending: Vec<u8>,
}

impl AnyTlsTestServer {
    async fn start() -> anyhow::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let certificate = rcgen::generate_simple_self_signed(vec!["anytls.test".to_string()])?;
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let server_config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der], private_key)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let accepted_sessions = Arc::new(AtomicUsize::new(0));
        let stream_ids = Arc::new(Mutex::new(Vec::new()));
        let heart_responses = Arc::new(AtomicUsize::new(0));

        let task_accepted = Arc::clone(&accepted_sessions);
        let task_stream_ids = Arc::clone(&stream_ids);
        let task_heart_responses = Arc::clone(&heart_responses);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let accepted = Arc::clone(&task_accepted);
                let stream_ids = Arc::clone(&task_stream_ids);
                let heart_responses = Arc::clone(&task_heart_responses);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    accepted.fetch_add(1, Ordering::Relaxed);
                    if run_anytls_session(&mut stream, PASSWORD, &stream_ids, &heart_responses)
                        .await
                        .is_err()
                    {
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });

        Ok(Self {
            address,
            accepted_sessions,
            stream_ids,
            heart_responses,
            task,
        })
    }
}

impl Drop for AnyTlsTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run_anytls_session<S>(
    stream: &mut S,
    password: &str,
    stream_ids: &Mutex<Vec<u32>>,
    heart_responses: &AtomicUsize,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut password_hash = [0u8; 32];
    stream.read_exact(&mut password_hash).await?;
    let expected: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    if password_hash != expected {
        return Err(anyhow!("wrong anytls password hash"));
    }
    let padding_length = stream.read_u16().await? as usize;
    if padding_length > 4_096 {
        return Err(anyhow!("oversized anytls auth padding"));
    }
    let mut auth_padding = vec![0u8; padding_length];
    stream.read_exact(&mut auth_padding).await?;

    let mut states = HashMap::<u32, ServerStreamState>::new();
    loop {
        let Some((command, sid, data)) = read_frame(stream).await? else {
            return Ok(());
        };
        match command {
            CMD_WASTE => {}
            CMD_SETTINGS => {
                let settings = String::from_utf8(data)?;
                if !settings.lines().any(|line| line == "v=2")
                    || !settings
                        .lines()
                        .any(|line| line.starts_with("padding-md5="))
                {
                    return Err(anyhow!("invalid anytls v2 settings"));
                }
                write_frame(stream, CMD_SERVER_SETTINGS, 0, b"v=2").await?;
                write_frame(stream, CMD_HEART_REQUEST, 0, &[]).await?;
                stream.flush().await?;
            }
            CMD_SYN => {
                states.entry(sid).or_default();
                stream_ids.lock().expect("stream id lock").push(sid);
            }
            CMD_PSH => {
                let state = states
                    .get_mut(&sid)
                    .ok_or_else(|| anyhow!("PSH arrived before SYN"))?;
                if state.target.is_none() {
                    let (target, consumed) = parse_socks5_destination(&data)?;
                    if consumed != data.len() {
                        return Err(anyhow!("target frame has trailing bytes"));
                    }
                    state.target = Some(target);
                    write_frame(stream, CMD_SYNACK, sid, &[]).await?;
                    stream.flush().await?;
                    continue;
                }

                if state.target.as_ref().map(|target| target.host.as_str())
                    == Some("sp.v2.udp-over-tcp.arpa")
                {
                    state.pending.extend_from_slice(&data);
                    if state.uot_destination.is_none() {
                        if state.pending.first() != Some(&0) {
                            return Err(anyhow!("anytls UoT v2 packet mode is missing"));
                        }
                        let (destination, consumed) =
                            parse_socks5_destination(&state.pending[1..])?;
                        state.uot_destination = Some(destination);
                        state.pending.drain(..consumed + 1);
                    }
                    if state.pending.is_empty() {
                        continue;
                    }
                    let (destination, consumed) = parse_uot_destination(&state.pending)?;
                    if state.pending.len() < consumed + 2 {
                        return Err(anyhow!("anytls UoT datagram length is missing"));
                    }
                    let payload_length =
                        u16::from_be_bytes(state.pending[consumed..consumed + 2].try_into()?)
                            as usize;
                    if state.pending.len() != consumed + 2 + payload_length {
                        return Err(anyhow!("anytls UoT datagram length mismatch"));
                    }
                    let mut response = encode_uot_destination(&destination)?;
                    response.extend_from_slice(&(payload_length as u16).to_be_bytes());
                    response.extend_from_slice(&state.pending[consumed + 2..]);
                    state.pending.clear();
                    write_frame(stream, CMD_PSH, sid, &response).await?;
                } else {
                    write_frame(stream, CMD_PSH, sid, &data).await?;
                }
                stream.flush().await?;
            }
            CMD_FIN => {
                states.remove(&sid);
                write_frame(stream, CMD_FIN, sid, &[]).await?;
                stream.flush().await?;
            }
            CMD_HEART_RESPONSE => {
                heart_responses.fetch_add(1, Ordering::Relaxed);
            }
            other => return Err(anyhow!("unexpected anytls command {other}")),
        }
    }
}

async fn read_frame<R>(reader: &mut R) -> anyhow::Result<Option<(u8, u32, Vec<u8>)>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 7];
    let mut offset = 0;
    while offset < header.len() {
        let read = reader.read(&mut header[offset..]).await?;
        if read == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err(anyhow!("partial anytls frame header"))
            };
        }
        offset += read;
    }
    let length = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; length];
    reader.read_exact(&mut data).await?;
    Ok(Some((
        header[0],
        u32::from_be_bytes(header[1..5].try_into()?),
        data,
    )))
}

async fn write_frame<W>(writer: &mut W, command: u8, sid: u32, data: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(data.len()).context("test anytls frame is too large")?;
    writer.write_u8(command).await?;
    writer.write_u32(sid).await?;
    writer.write_u16(length).await?;
    writer.write_all(data).await?;
    Ok(())
}

fn parse_socks5_destination(input: &[u8]) -> anyhow::Result<(Destination, usize)> {
    let mut cursor = 1;
    let host = match input.first().copied() {
        Some(1) => {
            let address: [u8; 4] = input
                .get(cursor..cursor + 4)
                .context("short SOCKS5 IPv4")?
                .try_into()?;
            cursor += 4;
            IpAddr::V4(Ipv4Addr::from(address)).to_string()
        }
        Some(4) => {
            let address: [u8; 16] = input
                .get(cursor..cursor + 16)
                .context("short SOCKS5 IPv6")?
                .try_into()?;
            cursor += 16;
            IpAddr::V6(Ipv6Addr::from(address)).to_string()
        }
        Some(3) => {
            let length = *input.get(cursor).context("missing SOCKS5 domain length")? as usize;
            cursor += 1;
            let domain = input
                .get(cursor..cursor + length)
                .context("short SOCKS5 domain")?;
            cursor += length;
            String::from_utf8(domain.to_vec())?
        }
        other => return Err(anyhow!("invalid SOCKS5 address type {other:?}")),
    };
    let port = u16::from_be_bytes(
        input
            .get(cursor..cursor + 2)
            .context("missing SOCKS5 port")?
            .try_into()?,
    );
    cursor += 2;
    Ok((Destination::new(host, port), cursor))
}

fn parse_uot_destination(input: &[u8]) -> anyhow::Result<(Destination, usize)> {
    let mut cursor = 1;
    let host = match input.first().copied() {
        Some(0) => {
            let address: [u8; 4] = input
                .get(cursor..cursor + 4)
                .context("short UoT IPv4")?
                .try_into()?;
            cursor += 4;
            Ipv4Addr::from(address).to_string()
        }
        Some(1) => {
            let address: [u8; 16] = input
                .get(cursor..cursor + 16)
                .context("short UoT IPv6")?
                .try_into()?;
            cursor += 16;
            Ipv6Addr::from(address).to_string()
        }
        Some(2) => {
            let length = *input.get(cursor).context("missing UoT domain length")? as usize;
            cursor += 1;
            let domain = input
                .get(cursor..cursor + length)
                .context("short UoT domain")?;
            cursor += length;
            String::from_utf8(domain.to_vec())?
        }
        other => return Err(anyhow!("invalid UoT address type {other:?}")),
    };
    let port = u16::from_be_bytes(
        input
            .get(cursor..cursor + 2)
            .context("missing UoT port")?
            .try_into()?,
    );
    cursor += 2;
    Ok((Destination::new(host, port), cursor))
}

fn encode_uot_destination(destination: &Destination) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            output.push(0);
            output.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let domain = destination.host.as_bytes();
            output.push(2);
            output.push(u8::try_from(domain.len())?);
            output.extend_from_slice(domain);
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(output)
}

#[tokio::test]
async fn anytls_v2_reuses_one_session_for_tcp_and_uot_udp() -> anyhow::Result<()> {
    let server = AnyTlsTestServer::start().await?;
    let outbounds = build_outbounds(
        &[OutboundConfig::AnyTls {
            name: "anytls-e2e".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: PASSWORD.to_string(),
            sni: Some("anytls.test".to_string()),
            skip_cert_verify: true,
            alpn: Vec::new(),
            idle_session_check_interval: Some(30),
            idle_session_timeout: Some(30),
            min_idle_session: Some(1),
        }],
        None,
    )?;
    let outbound = outbounds.get("anytls-e2e").context("missing outbound")?;
    assert!(outbound.capability().tcp_supported);
    assert!(outbound.capability().udp_supported);

    let mut first = timeout(
        Duration::from_secs(5),
        outbound.connect(&Destination::new("first.test", 443), 5_000),
    )
    .await??;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut second = timeout(
        Duration::from_secs(5),
        outbound.connect(&Destination::new("second.test", 8443), 5_000),
    )
    .await??;

    let first_payload = (0..96 * 1_024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let second_payload = b"second multiplexed stream".to_vec();
    let first_exchange = async {
        first.write_all(&first_payload).await?;
        first.flush().await?;
        let mut response = vec![0u8; first_payload.len()];
        first.read_exact(&mut response).await?;
        anyhow::Ok(response)
    };
    let second_exchange = async {
        second.write_all(&second_payload).await?;
        second.flush().await?;
        let mut response = vec![0u8; second_payload.len()];
        second.read_exact(&mut response).await?;
        anyhow::Ok(response)
    };
    let (first_response, second_response) = tokio::try_join!(first_exchange, second_exchange)?;
    assert_eq!(first_response, first_payload);
    assert_eq!(second_response, second_payload);

    let udp_destination = Destination::new("udp.test", 53);
    let udp_response = outbound
        .udp_exchange(&udp_destination, b"uot-v2-datagram", 5_000)
        .await?;
    assert_eq!(udp_response, b"uot-v2-datagram");

    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut reused = outbound
        .connect(&Destination::new("third.test", 9443), 5_000)
        .await?;
    reused.write_all(b"reused-session").await?;
    reused.flush().await?;
    let mut reused_response = [0u8; 14];
    reused.read_exact(&mut reused_response).await?;
    assert_eq!(&reused_response, b"reused-session");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.accepted_sessions.load(Ordering::Relaxed), 1);
    let stream_ids = server.stream_ids.lock().expect("stream id lock").clone();
    assert!(stream_ids.len() >= 4, "stream ids: {stream_ids:?}");
    assert!(stream_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(server.heart_responses.load(Ordering::Relaxed) >= 1);
    Ok(())
}

#[tokio::test]
async fn anytls_v2_evicts_expired_idle_session() -> anyhow::Result<()> {
    let server = AnyTlsTestServer::start().await?;
    let outbounds = build_outbounds(
        &[OutboundConfig::AnyTls {
            name: "anytls-idle".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: PASSWORD.to_string(),
            sni: Some("anytls.test".to_string()),
            skip_cert_verify: true,
            alpn: Vec::new(),
            idle_session_check_interval: Some(1),
            idle_session_timeout: Some(1),
            min_idle_session: Some(0),
        }],
        None,
    )?;
    let outbound = outbounds.get("anytls-idle").context("missing outbound")?;

    let mut first = outbound
        .connect(&Destination::new("idle-first.test", 443), 5_000)
        .await?;
    first.write_all(b"before-idle").await?;
    let mut response = [0u8; 11];
    first.read_exact(&mut response).await?;
    assert_eq!(&response, b"before-idle");
    drop(first);

    tokio::time::sleep(Duration::from_millis(2_300)).await;
    let mut second = outbound
        .connect(&Destination::new("idle-second.test", 443), 5_000)
        .await?;
    second.write_all(b"after-idle").await?;
    let mut response = [0u8; 10];
    second.read_exact(&mut response).await?;
    assert_eq!(&response, b"after-idle");
    assert_eq!(server.accepted_sessions.load(Ordering::Relaxed), 2);
    Ok(())
}
