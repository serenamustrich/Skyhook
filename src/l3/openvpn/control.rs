use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::packet::{self, OpenVpnPacket, P_ACK_V1, P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_V1};

const MAX_PACKET_SIZE: usize = 65535;
const HANDSHAKE_TIMEOUT_MS: u64 = 10000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenVpnState {
    Initial,
    ResetSent,
    ResetReceived,
    TlsClientHello,
    TlsHandshake,
    Established,
    Failed(String),
}

pub struct OpenVpnControlChannel {
    server: String,
    port: u16,
    state: OpenVpnState,
    session_id: [u8; 8],
    remote_session_id: Option<[u8; 8]>,
    packet_id: u32,
    socket: Option<Arc<UdpSocket>>,
    remote_addr: Option<SocketAddr>,
}

impl OpenVpnControlChannel {
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            state: OpenVpnState::Initial,
            session_id: packet::generate_session_id(),
            remote_session_id: None,
            packet_id: 0,
            socket: None,
            remote_addr: None,
        }
    }

    pub fn state(&self) -> &OpenVpnState {
        &self.state
    }

    pub async fn connect(&mut self) -> anyhow::Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(socket);

        let addr: SocketAddr = format!("{}:{}", self.server, self.port)
            .parse()
            .map_err(|e| anyhow!("invalid server address: {e}"))?;

        self.socket = Some(socket);
        self.remote_addr = Some(addr);

        // Step 1: Send HARD_RESET_CLIENT_V2
        self.send_hard_reset().await?;
        self.state = OpenVpnState::ResetSent;

        // Step 2: Wait for response
        let response = self.recv_packet().await?;

        match response.opcode {
            P_CONTROL_HARD_RESET_CLIENT_V2 => {
                self.remote_session_id = Some(response.session_id);
                self.state = OpenVpnState::ResetReceived;
            }
            P_CONTROL_V1 => {
                self.remote_session_id = Some(response.session_id);
                self.state = OpenVpnState::TlsClientHello;
            }
            other => {
                return Err(anyhow!("unexpected opcode during handshake: {}", other));
            }
        }

        // Send ACK for reset
        if let Some(remote_id) = self.remote_session_id {
            self.send_ack(remote_id, response.packet_id).await?;
        }

        // Step 3: Start TLS handshake
        self.state = OpenVpnState::TlsClientHello;

        // Build TLS ClientHello
        let client_hello = self.build_tls_client_hello()?;
        self.send_control(&client_hello).await?;

        // Wait for TLS ServerHello
        let server_hello = self.recv_packet().await?;
        if server_hello.opcode != P_CONTROL_V1 {
            return Err(anyhow!(
                "expected P_CONTROL_V1 during TLS, got {}",
                server_hello.opcode
            ));
        }

        // ACK the server hello
        if let Some(remote_id) = self.remote_session_id {
            self.send_ack(remote_id, server_hello.packet_id).await?;
        }

        self.state = OpenVpnState::TlsHandshake;

        Ok(())
    }

    fn build_tls_client_hello(&self) -> anyhow::Result<Vec<u8>> {
        // Build a minimal TLS ClientHello
        let mut hello = Vec::new();

        // TLS record header
        hello.push(0x16); // ContentType: Handshake
        hello.extend_from_slice(&[0x03, 0x01]); // TLS 1.0

        // Handshake message
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello

        // Client version
        handshake.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|e| anyhow!("failed to generate random: {e}"))?;
        handshake.extend_from_slice(&random);

        // Session ID (empty)
        handshake.push(0);

        // Cipher suites
        handshake.extend_from_slice(&[0x00, 0x0e]); // length = 7 * 2
        handshake.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        handshake.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384
        handshake.extend_from_slice(&[0x13, 0x03]); // TLS_CHACHA20_POLY1305_SHA256
        handshake.extend_from_slice(&[0xc0, 0x2b]); // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        handshake.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        handshake.extend_from_slice(&[0xc0, 0x2c]); // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        handshake.extend_from_slice(&[0xc0, 0x30]); // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

        // Compression methods (null only)
        handshake.push(1); // length
        handshake.push(0); // null compression

        // Extensions
        let mut extensions = Vec::new();

        // SNI extension
        let sni = self.server.as_bytes();
        extensions.extend_from_slice(&[0x00, 0x00]); // type: server_name
        let sni_ext_len = 5 + sni.len() as u16;
        extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
        let sni_list_len = 3 + sni.len() as u16;
        extensions.extend_from_slice(&sni_list_len.to_be_bytes());
        extensions.push(0); // host type: DNS
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(sni);

        // Add extensions length and data
        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        // Add handshake to record
        let handshake_len = handshake.len() as u16;
        hello.extend_from_slice(&handshake_len.to_be_bytes());
        hello.extend_from_slice(&handshake);

        Ok(hello)
    }

    async fn send_hard_reset(&mut self) -> anyhow::Result<()> {
        let packet = OpenVpnPacket {
            opcode: P_CONTROL_HARD_RESET_CLIENT_V2,
            session_id: self.session_id,
            packet_id: self.packet_id,
            payload: Vec::new(),
        };
        self.packet_id += 1;
        self.send_packet(&packet).await
    }

    async fn send_ack(&self, remote_session_id: [u8; 8], ack_packet_id: u32) -> anyhow::Result<()> {
        let packet = OpenVpnPacket {
            opcode: P_ACK_V1,
            session_id: self.session_id,
            packet_id: 0,
            payload: {
                let mut buf = Vec::new();
                buf.extend_from_slice(&remote_session_id);
                buf.push(1); // ack count
                buf.extend_from_slice(&ack_packet_id.to_be_bytes());
                buf
            },
        };
        self.send_packet(&packet).await
    }

    pub async fn send_control(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let packet = OpenVpnPacket {
            opcode: P_CONTROL_V1,
            session_id: self.session_id,
            packet_id: self.packet_id,
            payload: data.to_vec(),
        };
        self.packet_id += 1;
        self.send_packet(&packet).await
    }

    async fn send_packet(&self, packet: &OpenVpnPacket) -> anyhow::Result<()> {
        let socket = self.socket.as_ref().ok_or(anyhow!("not connected"))?;
        let addr = self.remote_addr.ok_or(anyhow!("no remote address"))?;
        let data = packet::serialize(packet);
        socket.send_to(&data, addr).await?;
        Ok(())
    }

    async fn recv_packet(&self) -> anyhow::Result<OpenVpnPacket> {
        let socket = self.socket.as_ref().ok_or(anyhow!("not connected"))?;
        let mut buf = vec![0u8; MAX_PACKET_SIZE];

        let (n, _addr) = timeout(
            Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            socket.recv_from(&mut buf),
        )
        .await
        .context("recv timed out")?
        .context("recv failed")?;

        packet::parse(&buf[..n])
    }
}
