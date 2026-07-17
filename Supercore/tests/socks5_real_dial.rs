use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{anyhow, Context};
use supercore::{
    config::OutboundConfig,
    outbound::{build_outbounds, Outbound},
    routing::Destination,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

const USERNAME: &str = "socks-user";
const PASSWORD: &str = "socks-password";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedDestination {
    command: u8,
    host: String,
    port: u16,
}

struct SocksHarness {
    port: u16,
    recorded: Arc<Mutex<Vec<RecordedDestination>>>,
    connections: Arc<AtomicUsize>,
    listener: JoinHandle<anyhow::Result<()>>,
    udp_relay: Option<JoinHandle<anyhow::Result<()>>>,
}

fn socks_config(port: u16, password: Option<&str>) -> OutboundConfig {
    OutboundConfig::Socks5 {
        name: "socks-test".to_string(),
        server: "127.0.0.1".to_string(),
        port,
        username: password.map(|_| USERNAME.to_string()),
        password: password.map(str::to_string),
    }
}

fn test_payload(seed: u8) -> Vec<u8> {
    (0..96 * 1024)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

async fn read_destination<S>(stream: &mut S, atyp: u8) -> anyhow::Result<(String, u16)>
where
    S: AsyncRead + Unpin,
{
    let host = match atyp {
        0x01 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut host = vec![0u8; length];
            stream.read_exact(&mut host).await?;
            String::from_utf8(host)?
        }
        0x04 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        value => return Err(anyhow!("unexpected SOCKS5 address type {value}")),
    };
    let port = stream.read_u16().await?;
    Ok((host, port))
}

fn parse_udp_destination(packet: &[u8]) -> anyhow::Result<(RecordedDestination, usize)> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(anyhow!("invalid SOCKS5 UDP header"));
    }
    let mut offset = 4;
    let host = match packet[3] {
        0x01 => {
            let address: [u8; 4] = packet
                .get(offset..offset + 4)
                .context("short IPv4 UDP target")?
                .try_into()?;
            offset += 4;
            std::net::Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let length = usize::from(*packet.get(offset).context("missing domain length")?);
            offset += 1;
            let host = String::from_utf8(
                packet
                    .get(offset..offset + length)
                    .context("short domain UDP target")?
                    .to_vec(),
            )?;
            offset += length;
            host
        }
        0x04 => {
            let address: [u8; 16] = packet
                .get(offset..offset + 16)
                .context("short IPv6 UDP target")?
                .try_into()?;
            offset += 16;
            std::net::Ipv6Addr::from(address).to_string()
        }
        value => return Err(anyhow!("unexpected SOCKS5 UDP address type {value}")),
    };
    let port = u16::from_be_bytes(
        packet
            .get(offset..offset + 2)
            .context("missing UDP target port")?
            .try_into()?,
    );
    offset += 2;
    Ok((
        RecordedDestination {
            command: 0x03,
            host,
            port,
        },
        offset,
    ))
}

async fn authenticate(
    stream: &mut TcpStream,
    expected_password: Option<&str>,
) -> anyhow::Result<bool> {
    let version = stream.read_u8().await?;
    let method_count = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    if version != 5 {
        return Err(anyhow!("invalid SOCKS5 greeting"));
    }
    if let Some(expected_password) = expected_password {
        assert!(methods.contains(&0x02));
        stream.write_all(&[0x05, 0x02]).await?;
        assert_eq!(stream.read_u8().await?, 0x01);
        let username_length = stream.read_u8().await? as usize;
        let mut username = vec![0u8; username_length];
        stream.read_exact(&mut username).await?;
        let password_length = stream.read_u8().await? as usize;
        let mut password = vec![0u8; password_length];
        stream.read_exact(&mut password).await?;
        let accepted = username == USERNAME.as_bytes() && password == expected_password.as_bytes();
        stream
            .write_all(&[0x01, if accepted { 0x00 } else { 0x01 }])
            .await?;
        Ok(accepted)
    } else {
        assert!(methods.contains(&0x00));
        stream.write_all(&[0x05, 0x00]).await?;
        Ok(true)
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    expected_password: Option<String>,
    relay_port: u16,
    payload_length: usize,
    recorded: Arc<Mutex<Vec<RecordedDestination>>>,
) -> anyhow::Result<()> {
    if !authenticate(&mut stream, expected_password.as_deref()).await? {
        return Ok(());
    }
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    assert_eq!(header[0], 0x05);
    assert_eq!(header[2], 0x00);
    let (host, port) = read_destination(&mut stream, header[3]).await?;
    recorded.lock().unwrap().push(RecordedDestination {
        command: header[1],
        host,
        port,
    });
    match header[1] {
        0x01 => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await?;
            let mut payload = vec![0u8; payload_length];
            stream.read_exact(&mut payload).await?;
            stream.write_all(&payload).await?;
            stream.shutdown().await?;
        }
        0x03 => {
            let mut response = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
            response.extend_from_slice(&relay_port.to_be_bytes());
            stream.write_all(&response).await?;
            sleep(Duration::from_secs(10)).await;
        }
        command => return Err(anyhow!("unexpected SOCKS5 command {command}")),
    }
    Ok(())
}

async fn start_socks_server(
    expected_password: Option<&str>,
    expected_connections: usize,
    udp_packets: usize,
    payload_length: usize,
) -> anyhow::Result<SocksHarness> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let relay_port = udp.local_addr()?.port();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));

    let udp_recorded = Arc::clone(&recorded);
    let udp_relay = (udp_packets > 0).then(|| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65_535];
            for _ in 0..udp_packets {
                let (length, peer) = udp.recv_from(&mut buffer).await?;
                let (destination, payload_offset) = parse_udp_destination(&buffer[..length])?;
                assert!(payload_offset < length);
                udp_recorded.lock().unwrap().push(destination);
                udp.send_to(&buffer[..length], peer).await?;
            }
            Ok(())
        })
    });

    let listener_recorded = Arc::clone(&recorded);
    let listener_connections = Arc::clone(&connections);
    let expected_password = expected_password.map(str::to_string);
    let listener = tokio::spawn(async move {
        for _ in 0..expected_connections {
            let (stream, _) = listener.accept().await?;
            listener_connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(handle_connection(
                stream,
                expected_password.clone(),
                relay_port,
                payload_length,
                Arc::clone(&listener_recorded),
            ));
        }
        Ok(())
    });

    Ok(SocksHarness {
        port,
        recorded,
        connections,
        listener,
        udp_relay,
    })
}

async fn tcp_exchange(
    outbound: Arc<dyn Outbound>,
    destination: Destination,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut stream = outbound.connect(&destination, 3_000).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

#[tokio::test]
async fn socks5_connects_domains_ipv4_ipv6_and_reuses_udp_pool() {
    let payload = test_payload(23);
    let harness = start_socks_server(None, 7, 5, payload.len()).await.unwrap();
    let config = socks_config(harness.port, None);
    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = Arc::clone(&outbounds["socks-test"]);
    for destination in [
        Destination::new("target.example", 443),
        Destination::new("198.51.100.7", 8443),
        Destination::new("2001:db8::9", 9443),
    ] {
        let response = tcp_exchange(Arc::clone(&outbound), destination, &payload)
            .await
            .unwrap();
        assert_eq!(response, payload);
    }
    for index in 0..5u8 {
        let udp_payload = vec![index; 1024];
        let response = outbound
            .udp_exchange(&Destination::new("dns.example", 53), &udp_payload, 3_000)
            .await
            .unwrap();
        assert_eq!(response, udp_payload);
    }

    timeout(Duration::from_secs(3), harness.listener)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(3), harness.udp_relay.unwrap())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(harness.connections.load(Ordering::SeqCst), 7);
    let recorded = harness.recorded.lock().unwrap().clone();
    assert!(recorded.contains(&RecordedDestination {
        command: 0x01,
        host: "target.example".to_string(),
        port: 443,
    }));
    assert!(recorded.contains(&RecordedDestination {
        command: 0x01,
        host: "198.51.100.7".to_string(),
        port: 8443,
    }));
    assert!(recorded.contains(&RecordedDestination {
        command: 0x01,
        host: "2001:db8::9".to_string(),
        port: 9443,
    }));
    assert_eq!(
        recorded
            .iter()
            .filter(|destination| destination.command == 0x03)
            .count(),
        9
    );
}

#[tokio::test]
async fn socks5_username_password_authenticates_and_rejects_bad_password() {
    let payload = test_payload(91);
    let harness = start_socks_server(Some(PASSWORD), 1, 0, payload.len())
        .await
        .unwrap();
    let config = socks_config(harness.port, Some(PASSWORD));
    let outbounds = build_outbounds(&[config], None).unwrap();
    let response = tcp_exchange(
        Arc::clone(&outbounds["socks-test"]),
        Destination::new("authenticated.example", 443),
        &payload,
    )
    .await
    .unwrap();
    assert_eq!(response, payload);
    timeout(Duration::from_secs(3), harness.listener)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let rejected = start_socks_server(Some(PASSWORD), 1, 0, payload.len())
        .await
        .unwrap();
    let config = socks_config(rejected.port, Some("wrong-password"));
    let outbounds = build_outbounds(&[config], None).unwrap();
    let error = match outbounds["socks-test"]
        .connect(&Destination::new("target.example", 443), 3_000)
        .await
    {
        Ok(_) => panic!("SOCKS5 unexpectedly accepted a bad password"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("authentication failed"),
        "{error:#}"
    );
    timeout(Duration::from_secs(3), rejected.listener)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn socks5_silent_authentication_reports_phase_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        sleep(Duration::from_secs(2)).await;
    });
    let config = socks_config(port, None);
    let outbounds = build_outbounds(&[config], None).unwrap();
    let error = match outbounds["socks-test"]
        .connect(&Destination::new("target.example", 443), 50)
        .await
    {
        Ok(_) => panic!("SOCKS5 unexpectedly completed against a silent server"),
        Err(error) => error,
    };
    assert!(
        format!("{error:#}").contains("SOCKS5 authentication timed out"),
        "{error:#}"
    );
    server.abort();
}
