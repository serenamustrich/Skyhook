use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::anyhow;
use rand::rng;
use russh::{
    keys::{ssh_key, PrivateKey},
    server::{self, Auth, Msg, Server as _, Session},
    Channel,
};
use supercore::{
    config::OutboundConfig,
    outbound::{build_outbounds, Outbound},
    routing::Destination,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

const USERNAME: &str = "ssh-user";
const PASSWORD: &str = "ssh-password";

#[derive(Clone)]
struct ReferenceSshServer {
    connections: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Destination>>>,
    authorized_key: ssh_key::PublicKey,
    disconnect_after_first_channel: Arc<AtomicBool>,
}

impl server::Server for ReferenceSshServer {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.connections.fetch_add(1, Ordering::SeqCst);
        self.clone()
    }
}

impl server::Handler for ReferenceSshServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, username: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if username == USERNAME && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        username: &str,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if username == USERNAME && public_key == &self.authorized_key {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        mut channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port = u16::try_from(port_to_connect)
            .map_err(|_| anyhow!("invalid direct-tcpip target port"))?;
        self.channels.fetch_add(1, Ordering::SeqCst);
        self.targets
            .lock()
            .unwrap()
            .push(Destination::new(host_to_connect, port));
        let disconnect_after_first_channel = Arc::clone(&self.disconnect_after_first_channel);
        let session_handle = session.handle();
        tokio::spawn(async move {
            let (mut writer, mut reader) = (channel.make_writer(), channel.make_reader());
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
            let _ = writer.shutdown().await;
            if disconnect_after_first_channel.swap(false, Ordering::SeqCst) {
                let _ = session_handle
                    .disconnect(
                        russh::Disconnect::ByApplication,
                        "test session rotation".to_string(),
                        String::new(),
                    )
                    .await;
            }
        });
        Ok(true)
    }
}

struct SshHarness {
    port: u16,
    fingerprint: String,
    client_private_key: String,
    connections: Arc<AtomicUsize>,
    channels: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<Destination>>>,
    task: JoinHandle<std::io::Result<()>>,
}

async fn start_ssh_server() -> anyhow::Result<SshHarness> {
    start_ssh_server_with_disconnect(false).await
}

async fn start_ssh_server_with_disconnect(
    disconnect_after_first_channel: bool,
) -> anyhow::Result<SshHarness> {
    let server_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519)?;
    let fingerprint = server_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let client_key = PrivateKey::random(&mut rng(), ssh_key::Algorithm::Ed25519)?;
    let client_private_key = client_key.to_openssh(ssh_key::LineEnding::LF)?.to_string();
    let connections = Arc::new(AtomicUsize::new(0));
    let channels = Arc::new(AtomicUsize::new(0));
    let targets = Arc::new(Mutex::new(Vec::new()));
    let mut server = ReferenceSshServer {
        connections: Arc::clone(&connections),
        channels: Arc::clone(&channels),
        targets: Arc::clone(&targets),
        authorized_key: client_key.public_key().clone(),
        disconnect_after_first_channel: Arc::new(AtomicBool::new(disconnect_after_first_channel)),
    };
    let config = Arc::new(server::Config {
        keys: vec![server_key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move { server.run_on_socket(config, &listener).await });
    Ok(SshHarness {
        port,
        fingerprint,
        client_private_key,
        connections,
        channels,
        targets,
        task,
    })
}

fn ssh_config(
    harness: &SshHarness,
    password: Option<&str>,
    private_key: Option<String>,
) -> OutboundConfig {
    OutboundConfig::Ssh {
        name: "ssh-test".to_string(),
        server: "127.0.0.1".to_string(),
        port: harness.port,
        username: USERNAME.to_string(),
        password: password.map(str::to_string),
        private_key,
        private_key_passphrase: None,
        host_key: vec![harness.fingerprint.clone()],
        host_key_algorithms: vec!["ssh-ed25519".to_string()],
        skip_host_key_verify: false,
        keepalive_interval_ms: 20,
        keepalive_max: 2,
    }
}

fn test_payload(seed: u8) -> Vec<u8> {
    (0..96 * 1024)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

async fn exchange(
    outbound: Arc<dyn Outbound>,
    destination: Destination,
    payload: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let mut stream = outbound.connect(&destination, 3_000).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await?;
    stream.shutdown().await?;
    Ok(response)
}

#[tokio::test]
async fn ssh_password_reuses_one_session_for_concurrent_direct_tcpip_channels() {
    let harness = start_ssh_server().await.unwrap();
    let config = ssh_config(&harness, Some(PASSWORD), None);
    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = Arc::clone(&outbounds["ssh-test"]);
    let first_payload = test_payload(17);
    let second_payload = test_payload(89);
    let (first, second) = tokio::join!(
        exchange(
            Arc::clone(&outbound),
            Destination::new("target.example", 443),
            first_payload.clone()
        ),
        exchange(
            outbound,
            Destination::new("2001:db8::11", 8443),
            second_payload.clone()
        )
    );
    assert_eq!(first.unwrap(), first_payload);
    assert_eq!(second.unwrap(), second_payload);
    assert_eq!(harness.connections.load(Ordering::SeqCst), 1);
    assert_eq!(harness.channels.load(Ordering::SeqCst), 2);
    let targets = harness.targets.lock().unwrap().clone();
    assert!(targets.contains(&Destination::new("target.example", 443)));
    assert!(targets.contains(&Destination::new("2001:db8::11", 8443)));
    harness.task.abort();
}

#[tokio::test]
async fn ssh_inline_private_key_authenticates_and_transfers_data() {
    let harness = start_ssh_server().await.unwrap();
    let config = ssh_config(&harness, None, Some(harness.client_private_key.clone()));
    let outbounds = build_outbounds(&[config], None).unwrap();
    let payload = test_payload(43);
    let response = exchange(
        Arc::clone(&outbounds["ssh-test"]),
        Destination::new("private-key.example", 22),
        payload.clone(),
    )
    .await
    .unwrap();
    assert_eq!(response, payload);
    assert_eq!(harness.connections.load(Ordering::SeqCst), 1);
    assert_eq!(harness.channels.load(Ordering::SeqCst), 1);
    harness.task.abort();
}

#[tokio::test]
async fn ssh_rejects_unpinned_server_key_before_authentication() {
    let harness = start_ssh_server().await.unwrap();
    let mut config = ssh_config(&harness, Some(PASSWORD), None);
    if let OutboundConfig::Ssh { host_key, .. } = &mut config {
        *host_key = vec!["SHA256:d3JvbmctaG9zdC1rZXk".to_string()];
    }
    let outbounds = build_outbounds(&[config], None).unwrap();
    let result = timeout(
        Duration::from_secs(3),
        outbounds["ssh-test"].connect(&Destination::new("target.example", 443), 3_000),
    )
    .await
    .unwrap();
    let error = match result {
        Ok(_) => panic!("SSH unexpectedly accepted an unpinned host key"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("key") || message.contains("Key") || message.contains("SSH"),
        "{message}"
    );
    assert_eq!(harness.channels.load(Ordering::SeqCst), 0);
    harness.task.abort();
}

#[tokio::test]
async fn ssh_reconnects_after_the_server_closes_a_completed_session() {
    let harness = start_ssh_server_with_disconnect(true).await.unwrap();
    let config = ssh_config(&harness, Some(PASSWORD), None);
    let outbounds = build_outbounds(&[config], None).unwrap();
    let outbound = Arc::clone(&outbounds["ssh-test"]);
    let first_payload = test_payload(9);
    let first = exchange(
        Arc::clone(&outbound),
        Destination::new("first.example", 443),
        first_payload.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first, first_payload);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let second_payload = test_payload(77);
    let second = exchange(
        outbound,
        Destination::new("second.example", 8443),
        second_payload.clone(),
    )
    .await
    .unwrap();
    assert_eq!(second, second_payload);
    assert_eq!(harness.connections.load(Ordering::SeqCst), 2);
    assert_eq!(harness.channels.load(Ordering::SeqCst), 2);
    harness.task.abort();
}
