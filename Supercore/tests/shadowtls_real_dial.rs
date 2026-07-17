use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use hmac::{Hmac, Mac};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use supercore::{
    config::{OutboundConfig, ShadowsocksPluginConfig},
    outbound::build_outbounds,
    routing::Destination,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "independent-shadowtls-v3-password";
const TLS_HEADER_LEN: usize = 5;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;
const TLS13_HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
const CLIENT_HELLO_SESSION_ID_LENGTH_INDEX: usize = TLS_HEADER_LEN + 1 + 3 + 2 + 32;
const CLIENT_HELLO_SESSION_ID_START: usize = CLIENT_HELLO_SESSION_ID_LENGTH_INDEX + 1;
const CLIENT_HELLO_HMAC_INDEX: usize = CLIENT_HELLO_SESSION_ID_START + 28;

type ReferenceHmac = Hmac<Sha1>;

struct ShadowTlsTestStack {
    address: SocketAddr,
    authenticated: Arc<AtomicUsize>,
    camouflage_requests: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Destination>>>,
    errors: Arc<Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl ShadowTlsTestStack {
    async fn start() -> anyhow::Result<Self> {
        Self::start_with_hello_retry_request(false).await
    }

    async fn start_with_hello_retry_request(force_hrr: bool) -> anyhow::Result<Self> {
        let errors = Arc::new(Mutex::new(Vec::new()));
        let certificate = rcgen::generate_simple_self_signed(vec!["shadow.example".to_string()])?;
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.key_pair.serialize_der(),
        ));
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        if force_hrr {
            provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1];
        }
        let tls_config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], private_key)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let tls_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let tls_address = tls_listener.local_addr()?;
        let camouflage_requests = Arc::new(AtomicUsize::new(0));
        let tls_errors = Arc::clone(&errors);
        let tls_camouflage_requests = Arc::clone(&camouflage_requests);
        let tls_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tls_listener.accept().await else {
                    return;
                };
                let acceptor = tls_acceptor.clone();
                let errors = Arc::clone(&tls_errors);
                let camouflage_requests = Arc::clone(&tls_camouflage_requests);
                tokio::spawn(async move {
                    let mut stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            errors
                                .lock()
                                .expect("error lock")
                                .push(format!("TLS backend handshake failed: {error}"));
                            return;
                        }
                    };
                    let mut buffer = [0u8; 1_024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(length) => {
                                if buffer[..length].starts_with(b"GET / HTTP/1.1") {
                                    camouflage_requests.fetch_add(1, Ordering::Relaxed);
                                    let _ = stream
                                        .write_all(
                                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                                        )
                                        .await;
                                    let _ = stream.shutdown().await;
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        let targets = Arc::new(Mutex::new(Vec::new()));
        let data_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let data_address = data_listener.local_addr()?;
        let data_targets = Arc::clone(&targets);
        let data_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = data_listener.accept().await else {
                    return;
                };
                let targets = Arc::clone(&data_targets);
                tokio::spawn(async move {
                    let Ok(target) = read_socks_destination(&mut stream).await else {
                        return;
                    };
                    targets.lock().expect("target lock").push(target);
                    let mut buffer = vec![0u8; 32 * 1_024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(length) => {
                                if stream.write_all(&buffer[..length]).await.is_err()
                                    || stream.flush().await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let authenticated = Arc::new(AtomicUsize::new(0));
        let server_authenticated = Arc::clone(&authenticated);
        let server_errors = Arc::clone(&errors);
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let authenticated = Arc::clone(&server_authenticated);
                let errors = Arc::clone(&server_errors);
                tokio::spawn(async move {
                    if let Err(error) = run_shadowtls_server(
                        stream,
                        tls_address,
                        data_address,
                        PASSWORD.as_bytes(),
                        &authenticated,
                    )
                    .await
                    {
                        errors.lock().expect("error lock").push(error.to_string());
                    }
                });
            }
        });

        Ok(Self {
            address,
            authenticated,
            camouflage_requests,
            targets,
            errors,
            tasks: vec![server_task, tls_task, data_task],
        })
    }
}

impl Drop for ShadowTlsTestStack {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn run_shadowtls_server(
    mut client: TcpStream,
    tls_backend: SocketAddr,
    data_backend: SocketAddr,
    password: &[u8],
    authenticated_count: &AtomicUsize,
) -> anyhow::Result<()> {
    let client_hello = read_tls_record(&mut client)
        .await?
        .context("client closed before ClientHello")?;
    let authenticated = verify_client_hello(&client_hello, password)?;
    let mut backend = TcpStream::connect(tls_backend).await?;
    backend.write_all(&client_hello).await?;
    backend.flush().await?;

    if !authenticated {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
        return Ok(());
    }
    authenticated_count.fetch_add(1, Ordering::Relaxed);

    let mut server_hello = relay_until_handshake_type(&mut backend, &mut client, 0x02).await?;
    let mut server_random = extract_server_random(&server_hello)?;
    if server_random == TLS13_HELLO_RETRY_REQUEST_RANDOM {
        relay_until_handshake_type(&mut client, &mut backend, 0x01).await?;
        server_hello = relay_until_handshake_type(&mut backend, &mut client, 0x02).await?;
        server_random = extract_server_random(&server_hello)?;
    }

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    let switched = CancellationToken::new();
    let upload = relay_client_handshake_until_switch(
        &mut client_read,
        &mut backend_write,
        password,
        &server_random,
        switched.clone(),
    );
    let download = relay_tls_backend_handshake(
        &mut backend_read,
        &mut client_write,
        password,
        &server_random,
        switched.clone(),
    );
    let (upload, download) = tokio::join!(upload, download);
    let (initial_payload, upload_hmac) = upload?;
    download?;
    let _ = backend_write.shutdown().await;

    let mut data = TcpStream::connect(data_backend).await?;
    data.write_all(&initial_payload).await?;
    data.flush().await?;
    let (mut data_read, mut data_write) = data.into_split();
    let data_done = CancellationToken::new();
    let upload = relay_shadowtls_upload(
        &mut client_read,
        &mut data_write,
        upload_hmac,
        data_done.clone(),
    );
    let download_hmac = reference_hmac(password, &server_random, b"S")?;
    let download = relay_shadowtls_download(
        &mut data_read,
        &mut client_write,
        download_hmac,
        data_done.clone(),
    );
    let (upload, download) = tokio::join!(upload, download);
    upload?;
    download?;
    Ok(())
}

async fn relay_until_handshake_type<R, W>(
    reader: &mut R,
    writer: &mut W,
    handshake_type: u8,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let frame = read_tls_record(reader)
            .await?
            .with_context(|| format!("TLS stream closed before handshake type {handshake_type}"))?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        if frame[0] == CONTENT_TYPE_HANDSHAKE && frame.get(TLS_HEADER_LEN) == Some(&handshake_type)
        {
            return Ok(frame);
        }
    }
}

async fn relay_client_handshake_until_switch<R, W>(
    client: &mut R,
    backend: &mut W,
    password: &[u8],
    server_random: &[u8; 32],
    switched: CancellationToken,
) -> anyhow::Result<(Vec<u8>, ReferenceHmac)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut upload_hmac = reference_hmac(password, server_random, b"C")?;
    loop {
        let frame = read_tls_record(client)
            .await?
            .context("client closed before ShadowTLS switch")?;
        if frame[0] == CONTENT_TYPE_APPLICATION_DATA && frame.len() > TLS_HEADER_LEN + 4 {
            let received = &frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
            let payload = &frame[TLS_HEADER_LEN + 4..];
            let mut candidate = upload_hmac.clone();
            candidate.update(payload);
            if reference_digest(&candidate).as_slice() == received {
                upload_hmac = candidate;
                upload_hmac.update(received);
                switched.cancel();
                return Ok((payload.to_vec(), upload_hmac));
            }
        }
        backend.write_all(&frame).await?;
        backend.flush().await?;
    }
}

async fn relay_tls_backend_handshake<R, W>(
    backend: &mut R,
    client: &mut W,
    password: &[u8],
    server_random: &[u8; 32],
    switched: CancellationToken,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut handshake_hmac = reference_hmac(password, server_random, b"")?;
    let xor_key: [u8; 32] = Sha256::new()
        .chain_update(password)
        .chain_update(server_random)
        .finalize()
        .into();
    loop {
        tokio::select! {
            _ = switched.cancelled() => return Ok(()),
            frame = read_tls_record(backend) => {
                let Some(frame) = frame? else {
                    return Err(anyhow!("TLS backend closed before ShadowTLS switch"));
                };
                let frame = encode_backend_handshake_frame(frame, &mut handshake_hmac, &xor_key)?;
                client.write_all(&frame).await?;
                client.flush().await?;
            }
        }
    }
}

fn encode_backend_handshake_frame(
    frame: Vec<u8>,
    hmac: &mut ReferenceHmac,
    xor_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    if frame[0] != CONTENT_TYPE_APPLICATION_DATA {
        return Ok(frame);
    }
    let payload_len = u16::from_be_bytes([frame[3], frame[4]]) as usize;
    if frame.len() != TLS_HEADER_LEN + payload_len {
        return Err(anyhow!("TLS backend frame length mismatch"));
    }
    let mut payload = frame[TLS_HEADER_LEN..].to_vec();
    xor_repeating(&mut payload, xor_key);
    hmac.update(&payload);
    let digest = reference_digest(hmac);
    let wrapped_len = payload
        .len()
        .checked_add(4)
        .and_then(|length| u16::try_from(length).ok())
        .context("wrapped backend TLS frame is too large")?;
    let mut wrapped = frame[..TLS_HEADER_LEN].to_vec();
    wrapped[3..5].copy_from_slice(&wrapped_len.to_be_bytes());
    wrapped.extend_from_slice(&digest);
    wrapped.extend_from_slice(&payload);
    Ok(wrapped)
}

async fn relay_shadowtls_upload<R, W>(
    client: &mut R,
    data: &mut W,
    mut hmac: ReferenceHmac,
    done: CancellationToken,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let frame = match read_tls_record(client).await? {
            Some(frame) => frame,
            None => {
                done.cancel();
                let _ = data.shutdown().await;
                return Ok(());
            }
        };
        if frame[0] == CONTENT_TYPE_ALERT {
            done.cancel();
            let _ = data.shutdown().await;
            return Ok(());
        }
        if frame[0] != CONTENT_TYPE_APPLICATION_DATA || frame.len() <= TLS_HEADER_LEN + 4 {
            return Err(anyhow!("invalid ShadowTLS client data frame"));
        }
        let received = &frame[TLS_HEADER_LEN..TLS_HEADER_LEN + 4];
        let payload = &frame[TLS_HEADER_LEN + 4..];
        hmac.update(payload);
        if reference_digest(&hmac).as_slice() != received {
            return Err(anyhow!("ShadowTLS client data HMAC mismatch"));
        }
        hmac.update(received);
        data.write_all(payload).await?;
        data.flush().await?;
    }
}

async fn relay_shadowtls_download<R, W>(
    data: &mut R,
    client: &mut W,
    mut hmac: ReferenceHmac,
    done: CancellationToken,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1_024];
    loop {
        tokio::select! {
            _ = done.cancelled() => return Ok(()),
            read = data.read(&mut buffer) => {
                let length = read?;
                if length == 0 {
                    done.cancel();
                    return Ok(());
                }
                let payload = &buffer[..length];
                hmac.update(payload);
                let digest = reference_digest(&hmac);
                hmac.update(&digest);
                write_tls_app_data(client, &digest, payload).await?;
            }
        }
    }
}

async fn write_tls_app_data<W>(
    writer: &mut W,
    digest: &[u8; 4],
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(payload.len() + 4).context("test ShadowTLS frame too large")?;
    writer
        .write_all(&[
            CONTENT_TYPE_APPLICATION_DATA,
            0x03,
            0x03,
            (length >> 8) as u8,
            length as u8,
        ])
        .await?;
    writer.write_all(digest).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

fn verify_client_hello(frame: &[u8], password: &[u8]) -> anyhow::Result<bool> {
    if frame.len() <= CLIENT_HELLO_HMAC_INDEX + 4
        || frame[0] != CONTENT_TYPE_HANDSHAKE
        || frame[TLS_HEADER_LEN] != 0x01
        || frame[CLIENT_HELLO_SESSION_ID_LENGTH_INDEX] != 32
    {
        return Ok(false);
    }
    let received = &frame[CLIENT_HELLO_HMAC_INDEX..CLIENT_HELLO_HMAC_INDEX + 4];
    let mut hmac = ReferenceHmac::new_from_slice(password)?;
    hmac.update(&frame[TLS_HEADER_LEN..CLIENT_HELLO_HMAC_INDEX]);
    hmac.update(&[0u8; 4]);
    hmac.update(&frame[CLIENT_HELLO_HMAC_INDEX + 4..]);
    Ok(reference_digest(&hmac).as_slice() == received)
}

fn extract_server_random(frame: &[u8]) -> anyhow::Result<[u8; 32]> {
    if frame.len() < TLS_HEADER_LEN + 1 + 3 + 2 + 32
        || frame[0] != CONTENT_TYPE_HANDSHAKE
        || frame[TLS_HEADER_LEN] != 0x02
    {
        return Err(anyhow!(
            "invalid TLS backend ServerHello: record_type={}, handshake_type={}, len={}",
            frame.first().copied().unwrap_or_default(),
            frame.get(TLS_HEADER_LEN).copied().unwrap_or_default(),
            frame.len()
        ));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&frame[TLS_HEADER_LEN + 1 + 3 + 2..][..32]);
    Ok(random)
}

fn reference_hmac(
    password: &[u8],
    server_random: &[u8; 32],
    suffix: &[u8],
) -> anyhow::Result<ReferenceHmac> {
    let mut hmac = ReferenceHmac::new_from_slice(password)?;
    hmac.update(server_random);
    hmac.update(suffix);
    Ok(hmac)
}

fn reference_digest(hmac: &ReferenceHmac) -> [u8; 4] {
    let digest = hmac.clone().finalize().into_bytes();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn xor_repeating(payload: &mut [u8], key: &[u8]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

async fn read_tls_record<R>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_HEADER_LEN];
    let mut offset = 0;
    while offset < header.len() {
        let read = reader.read(&mut header[offset..]).await?;
        if read == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err(anyhow!("partial TLS record header"))
            };
        }
        offset += read;
    }
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = Vec::with_capacity(TLS_HEADER_LEN + payload_len);
    frame.extend_from_slice(&header);
    frame.resize(TLS_HEADER_LEN + payload_len, 0);
    reader.read_exact(&mut frame[TLS_HEADER_LEN..]).await?;
    Ok(Some(frame))
}

async fn read_socks_destination<R>(reader: &mut R) -> anyhow::Result<Destination>
where
    R: AsyncRead + Unpin,
{
    let address_type = reader.read_u8().await?;
    let host = match address_type {
        1 => {
            let mut address = [0u8; 4];
            reader.read_exact(&mut address).await?;
            IpAddr::V4(Ipv4Addr::from(address)).to_string()
        }
        4 => {
            let mut address = [0u8; 16];
            reader.read_exact(&mut address).await?;
            IpAddr::V6(Ipv6Addr::from(address)).to_string()
        }
        3 => {
            let length = reader.read_u8().await? as usize;
            let mut domain = vec![0u8; length];
            reader.read_exact(&mut domain).await?;
            String::from_utf8(domain)?
        }
        other => return Err(anyhow!("invalid SOCKS address type {other}")),
    };
    let port = reader.read_u16().await?;
    Ok(Destination::new(host, port))
}

#[tokio::test]
async fn shadowtls_v3_real_backend_handshake_and_large_tcp_round_trip() -> anyhow::Result<()> {
    let server = ShadowTlsTestStack::start().await?;
    let outbounds = build_outbounds(
        &[OutboundConfig::ShadowTls {
            name: "shadowtls-e2e".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: PASSWORD.to_string(),
            version: Some(3),
            sni: Some("shadow.example".to_string()),
            skip_cert_verify: true,
        }],
        None,
    )?;
    let outbound = outbounds.get("shadowtls-e2e").context("missing outbound")?;
    assert!(outbound.capability().tcp_supported);
    assert!(!outbound.capability().udp_supported);

    let destination = Destination::new("standalone.target", 443);
    let mut stream = outbound.connect(&destination, 5_000).await?;
    let payload = (0..96 * 1_024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut response = vec![0u8; payload.len()];
    let round_trip = async {
        stream.write_all(&payload).await?;
        stream.flush().await?;
        stream.read_exact(&mut response).await?;
        anyhow::Ok(())
    };
    match tokio::time::timeout(Duration::from_secs(5), round_trip).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Err(anyhow!(
                "ShadowTLS data round trip failed: {error}; authenticated={}, targets={:?}, errors={:?}",
                server.authenticated.load(Ordering::Relaxed),
                server.targets.lock().expect("target lock"),
                server.errors.lock().expect("error lock")
            ));
        }
        Err(_) => {
            return Err(anyhow!(
                "ShadowTLS data round trip timed out; authenticated={}, targets={:?}, errors={:?}",
                server.authenticated.load(Ordering::Relaxed),
                server.targets.lock().expect("target lock"),
                server.errors.lock().expect("error lock")
            ));
        }
    }
    assert_eq!(response, payload);
    drop(stream);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.authenticated.load(Ordering::Relaxed), 1);
    assert!(server
        .targets
        .lock()
        .expect("target lock")
        .contains(&destination));
    assert!(server.errors.lock().expect("error lock").is_empty());
    Ok(())
}

#[tokio::test]
async fn shadowtls_v3_survives_tls13_hello_retry_request() -> anyhow::Result<()> {
    let server = ShadowTlsTestStack::start_with_hello_retry_request(true).await?;
    let outbounds = build_outbounds(
        &[OutboundConfig::ShadowTls {
            name: "shadowtls-hrr".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: PASSWORD.to_string(),
            version: Some(3),
            sni: Some("shadow.example".to_string()),
            skip_cert_verify: true,
        }],
        None,
    )?;
    let destination = Destination::new("hrr.target", 443);
    let mut stream = match outbounds["shadowtls-hrr"]
        .connect(&destination, 5_000)
        .await
    {
        Ok(stream) => stream,
        Err(error) => {
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Err(anyhow!(
                "{error}; server errors={:?}",
                server.errors.lock().expect("error lock")
            ));
        }
    };
    stream.write_all(b"hello-retry-request").await?;
    stream.flush().await?;
    let mut response = [0u8; 19];
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"hello-retry-request");
    assert!(server
        .targets
        .lock()
        .expect("target lock")
        .contains(&destination));
    assert!(server.errors.lock().expect("error lock").is_empty());
    Ok(())
}

#[tokio::test]
async fn shadowsocks_none_over_shadowtls_v3_plugin_round_trip() -> anyhow::Result<()> {
    let server = ShadowTlsTestStack::start().await?;
    let destination = Destination::new("plugin.target", 8443);
    let outbounds = build_outbounds(
        &[OutboundConfig::Shadowsocks {
            name: "ss-shadowtls".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            method: "none".to_string(),
            password: "unused-for-none".to_string(),
            plugin: Some(ShadowsocksPluginConfig {
                mode: "shadow-tls".to_string(),
                host: Some("shadow.example".to_string()),
                path: None,
                tls: false,
                skip_cert_verify: true,
                password: Some(PASSWORD.to_string()),
                version: Some(3),
            }),
            udp_over_tcp: false,
            udp_over_tcp_version: 1,
        }],
        None,
    )?;
    let outbound = outbounds.get("ss-shadowtls").context("missing outbound")?;
    let mut stream = outbound.connect(&destination, 5_000).await?;
    stream.write_all(b"shadowtls-plugin-roundtrip").await?;
    stream.flush().await?;
    let mut response = [0u8; 26];
    stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"shadowtls-plugin-roundtrip");
    drop(stream);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(server
        .targets
        .lock()
        .expect("target lock")
        .contains(&destination));
    assert!(server.errors.lock().expect("error lock").is_empty());
    Ok(())
}

#[tokio::test]
async fn shadowtls_v3_rejects_wrong_password_and_untrusted_backend_certificate(
) -> anyhow::Result<()> {
    let server = ShadowTlsTestStack::start().await?;
    let configs = [
        OutboundConfig::ShadowTls {
            name: "wrong-password".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: "wrong-password".to_string(),
            version: Some(3),
            sni: Some("shadow.example".to_string()),
            skip_cert_verify: true,
        },
        OutboundConfig::ShadowTls {
            name: "untrusted-cert".to_string(),
            server: server.address.ip().to_string(),
            port: server.address.port(),
            password: PASSWORD.to_string(),
            version: Some(3),
            sni: Some("shadow.example".to_string()),
            skip_cert_verify: false,
        },
    ];
    let outbounds = build_outbounds(&configs, None)?;

    let password_error = outbounds["wrong-password"]
        .connect(&Destination::new("wrong.test", 443), 5_000)
        .await
        .err()
        .expect("wrong password must fail")
        .to_string();
    assert!(
        password_error.contains("authentication") || password_error.contains("handshake"),
        "{password_error}"
    );
    assert_eq!(server.camouflage_requests.load(Ordering::Relaxed), 1);

    let certificate_error = outbounds["untrusted-cert"]
        .connect(&Destination::new("cert.test", 443), 5_000)
        .await
        .err()
        .expect("untrusted backend certificate must fail")
        .to_string();
    assert!(
        certificate_error.contains("certificate") || certificate_error.contains("UnknownIssuer"),
        "{certificate_error}"
    );
    Ok(())
}
