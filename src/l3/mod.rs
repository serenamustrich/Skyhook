use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context};
use base64::Engine;
use blake2::{digest::Digest, Blake2s256};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey as WireGuardPublicKey, StaticSecret as WireGuardStaticSecret},
};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::Serialize;
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
    time::{sleep, timeout},
};

use crate::config::{L3Config, OutboundConfig, SuperConfig};

pub mod openvpn;

const WG_PACKET_BUFFER_SIZE: usize = 65_535;
const WG_MIN_HANDSHAKE_INTERVAL_SECS: u64 = 5;
const L3_PACKET_CHANNEL_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct L3Packet {
    pub profile: String,
    pub packet: Vec<u8>,
    pub direction: L3PacketDirection,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3PacketDirection {
    ToNetwork,
    ToTun,
}

#[derive(Debug, Clone)]
pub struct L3PacketSubmitResult {
    pub accepted: bool,
    pub profile: String,
    pub packet_len: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct L3Manager {
    inner: Arc<Mutex<L3ManagerInner>>,
}

#[derive(Debug)]
struct L3ManagerInner {
    config: L3Config,
    profiles: BTreeMap<String, L3Profile>,
    statuses: BTreeMap<String, L3TunnelStatus>,
    tasks: BTreeMap<String, L3Task>,
}

#[derive(Debug)]
struct L3Task {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
    outbound_packets: mpsc::Sender<Vec<u8>>,
    inbound_packets: broadcast::Sender<L3Packet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct L3Snapshot {
    pub enabled: bool,
    pub auto_start: bool,
    pub handshake_interval_secs: u64,
    pub start_timeout_ms: u64,
    pub profiles: Vec<L3ProfileSnapshot>,
    pub statuses: Vec<L3TunnelStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct L3ProfileSnapshot {
    pub name: String,
    pub protocol: L3Protocol,
    pub mode: String,
    pub endpoint: Option<String>,
    pub interface_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub mtu: Option<u16>,
    pub key_fingerprint: Option<String>,
    pub peer_fingerprint: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct L3TunnelStatus {
    pub name: String,
    pub protocol: L3Protocol,
    pub state: L3TunnelState,
    pub mode: String,
    pub endpoint: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum L3Protocol {
    WireGuard,
    OpenVpn,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum L3TunnelState {
    Stopped,
    Starting,
    Handshaking,
    Running,
    Degraded,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone)]
enum L3Profile {
    WireGuard(WireGuardProfile),
    OpenVpn(OpenVpnProfile),
}

#[derive(Debug, Clone)]
struct WireGuardProfile {
    name: String,
    server: String,
    port: u16,
    private_key: [u8; 32],
    public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    interface_ips: Vec<IpNet>,
    allowed_ips: Vec<IpNet>,
    reserved: Vec<u8>,
    mtu: Option<u16>,
}

#[derive(Debug, Clone)]
struct OpenVpnProfile {
    name: String,
    profile: Option<String>,
    inline_profile: Option<String>,
    parsed: Option<openvpn::OpenVpnParsedProfile>,
    parse_error: Option<String>,
}

impl L3Manager {
    pub fn new(config: &SuperConfig) -> Self {
        let (profiles, statuses) = build_l3_profiles(config);
        Self {
            inner: Arc::new(Mutex::new(L3ManagerInner {
                config: config.l3.clone(),
                profiles,
                statuses,
                tasks: BTreeMap::new(),
            })),
        }
    }

    pub fn reconcile_config(&self, config: &SuperConfig) {
        let (profiles, mut statuses) = build_l3_profiles(config);
        let mut inner = self.inner.lock().expect("l3 manager lock");
        inner.config = config.l3.clone();
        for name in inner.tasks.keys().cloned().collect::<Vec<_>>() {
            if !profiles.contains_key(&name) {
                if let Some(task) = inner.tasks.remove(&name) {
                    let _ = task.stop.send(true);
                }
            }
        }
        for (name, status) in inner.statuses.iter() {
            if profiles.contains_key(name) {
                statuses.insert(name.clone(), status.clone());
            }
        }
        inner.profiles = profiles;
        inner.statuses = statuses;
    }

    pub fn snapshot(&self) -> L3Snapshot {
        let inner = self.inner.lock().expect("l3 manager lock");
        L3Snapshot {
            enabled: inner.config.enabled,
            auto_start: inner.config.auto_start,
            handshake_interval_secs: inner.config.handshake_interval_secs,
            start_timeout_ms: inner.config.start_timeout_ms,
            profiles: inner
                .profiles
                .values()
                .map(L3Profile::snapshot)
                .collect::<Vec<_>>(),
            statuses: inner.statuses.values().cloned().collect::<Vec<_>>(),
        }
    }

    pub async fn start_all(&self) -> Vec<L3TunnelStatus> {
        let names = {
            let inner = self.inner.lock().expect("l3 manager lock");
            inner.profiles.keys().cloned().collect::<Vec<_>>()
        };
        let mut statuses = Vec::new();
        for name in names {
            statuses.push(self.start(&name).await);
        }
        statuses
    }

    pub async fn stop_all(&self) -> Vec<L3TunnelStatus> {
        let names = {
            let inner = self.inner.lock().expect("l3 manager lock");
            inner.statuses.keys().cloned().collect::<Vec<_>>()
        };
        let mut statuses = Vec::new();
        for name in names {
            statuses.push(self.stop(&name));
        }
        statuses
    }

    pub async fn start(&self, name: &str) -> L3TunnelStatus {
        let (profile, config) = {
            let mut inner = self.inner.lock().expect("l3 manager lock");
            if !inner.config.enabled {
                return status_for_missing(name, "l3 manager is disabled");
            }
            let Some(profile) = inner.profiles.get(name).cloned() else {
                return status_for_missing(name, "l3 profile does not exist");
            };
            if inner.tasks.contains_key(name) {
                return inner
                    .statuses
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| profile.initial_status());
            }
            let status = profile.starting_status();
            inner.statuses.insert(name.to_string(), status.clone());
            (profile, inner.config.clone())
        };

        match profile {
            L3Profile::WireGuard(profile) => {
                if let Err(error) = profile.validate() {
                    let status = profile.failed_status(error.to_string());
                    self.set_status(status.clone());
                    return status;
                }
                let (stop, stop_rx) = watch::channel(false);
                let (outbound_packet_tx, outbound_packet_rx) =
                    mpsc::channel(L3_PACKET_CHANNEL_SIZE);
                let (inbound_packet_tx, _) = broadcast::channel(L3_PACKET_CHANNEL_SIZE);
                let manager = self.clone();
                let name = profile.name.clone();
                let inbound_packets = inbound_packet_tx.clone();
                let handle = tokio::spawn(async move {
                    run_wireguard_profile(
                        manager,
                        profile,
                        config,
                        stop_rx,
                        outbound_packet_rx,
                        inbound_packets,
                    )
                    .await;
                });
                let mut inner = self.inner.lock().expect("l3 manager lock");
                inner.tasks.insert(
                    name.clone(),
                    L3Task {
                        stop,
                        handle,
                        outbound_packets: outbound_packet_tx,
                        inbound_packets: inbound_packet_tx,
                    },
                );
                inner
                    .statuses
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| status_for_missing(&name, "l3 status missing after start"))
            }
            L3Profile::OpenVpn(profile) => {
                let status = profile.unsupported_status();
                self.set_status(status.clone());
                status
            }
        }
    }

    pub fn stop(&self, name: &str) -> L3TunnelStatus {
        let mut inner = self.inner.lock().expect("l3 manager lock");
        let Some(profile) = inner.profiles.get(name).cloned() else {
            return status_for_missing(name, "l3 profile does not exist");
        };
        if let Some(task) = inner.tasks.remove(name) {
            let _ = task.stop.send(true);
            task.handle.abort();
        }
        let status = profile.stopped_status();
        inner.statuses.insert(name.to_string(), status.clone());
        status
    }

    fn set_status(&self, status: L3TunnelStatus) {
        let mut inner = self.inner.lock().expect("l3 manager lock");
        inner.statuses.insert(status.name.clone(), status);
    }

    pub async fn send_ip_packet(&self, profile: &str, packet: Vec<u8>) -> L3PacketSubmitResult {
        let packet_len = packet.len();
        let inner = self.inner.lock().expect("l3 manager lock");
        let Some(task) = inner.tasks.get(profile) else {
            return L3PacketSubmitResult {
                accepted: false,
                profile: profile.to_string(),
                packet_len,
                error: Some("l3 profile not running".to_string()),
            };
        };
        match task.outbound_packets.try_send(packet) {
            Ok(()) => L3PacketSubmitResult {
                accepted: true,
                profile: profile.to_string(),
                packet_len,
                error: None,
            },
            Err(error) => L3PacketSubmitResult {
                accepted: false,
                profile: profile.to_string(),
                packet_len,
                error: Some(format!("failed to enqueue packet: {error}")),
            },
        }
    }

    pub fn subscribe_ip_packets(
        &self,
        profile: &str,
    ) -> anyhow::Result<broadcast::Receiver<L3Packet>> {
        let inner = self.inner.lock().expect("l3 manager lock");
        let Some(task) = inner.tasks.get(profile) else {
            return Err(anyhow!("l3 profile not running"));
        };
        Ok(task.inbound_packets.subscribe())
    }
}

impl L3Profile {
    fn name(&self) -> &str {
        match self {
            Self::WireGuard(profile) => &profile.name,
            Self::OpenVpn(profile) => &profile.name,
        }
    }

    fn protocol(&self) -> L3Protocol {
        match self {
            Self::WireGuard(_) => L3Protocol::WireGuard,
            Self::OpenVpn(_) => L3Protocol::OpenVpn,
        }
    }

    fn endpoint(&self) -> Option<String> {
        match self {
            Self::WireGuard(profile) => Some(format!("{}:{}", profile.server, profile.port)),
            Self::OpenVpn(_) => None,
        }
    }

    fn initial_status(&self) -> L3TunnelStatus {
        L3TunnelStatus {
            name: self.name().to_string(),
            protocol: self.protocol(),
            state: L3TunnelState::Stopped,
            mode: self.mode(),
            endpoint: self.endpoint(),
            started_at: None,
            updated_at: Utc::now(),
            last_error: None,
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            details: self.initial_details(),
        }
    }

    fn starting_status(&self) -> L3TunnelStatus {
        let mut status = self.initial_status();
        status.state = L3TunnelState::Starting;
        status.updated_at = Utc::now();
        status.details.push("l3 tunnel start requested".to_string());
        status
    }

    fn stopped_status(&self) -> L3TunnelStatus {
        let mut status = self.initial_status();
        status.details.push("l3 tunnel stopped".to_string());
        status
    }

    fn mode(&self) -> String {
        match self {
            Self::WireGuard(_) => "native-wireguard-l3".to_string(),
            Self::OpenVpn(_) => "openvpn-profile-manager".to_string(),
        }
    }

    fn initial_details(&self) -> Vec<String> {
        match self {
            Self::WireGuard(profile) => {
                let mut details = vec![
                    format!("interface_ips={}", join_display(&profile.interface_ips)),
                    format!("allowed_ips={}", join_display(&profile.allowed_ips)),
                ];
                if profile.preshared_key.is_some() {
                    details.push("preshared_key=configured".to_string());
                }
                if !profile.reserved.is_empty() {
                    details.push(format!("reserved_bytes={}", profile.reserved.len()));
                }
                details
            }
            Self::OpenVpn(profile) => {
                let mut details = Vec::new();
                if let Some(path) = &profile.profile {
                    details.push(format!("profile={path}"));
                }
                if profile.inline_profile.is_some() {
                    details.push("inline_profile=configured".to_string());
                }
                details
            }
        }
    }

    fn snapshot(&self) -> L3ProfileSnapshot {
        match self {
            Self::WireGuard(profile) => L3ProfileSnapshot {
                name: profile.name.clone(),
                protocol: L3Protocol::WireGuard,
                mode: self.mode(),
                endpoint: self.endpoint(),
                interface_ips: profile
                    .interface_ips
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                allowed_ips: profile
                    .allowed_ips
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                mtu: profile.mtu,
                key_fingerprint: Some(key_fingerprint(&profile.private_key)),
                peer_fingerprint: Some(key_fingerprint(&profile.public_key)),
                notes: vec![
                    "native WireGuard Noise state machine is wired into the L3 manager"
                        .to_string(),
                    "packet encapsulation, decapsulation, keepalive, and handshake timers are active"
                        .to_string(),
                    "TUN packet bridge is the next integration point for full device routing"
                        .to_string(),
                ],
            },
            Self::OpenVpn(profile) => L3ProfileSnapshot {
                name: profile.name.clone(),
                protocol: L3Protocol::OpenVpn,
                mode: self.mode(),
                endpoint: None,
                interface_ips: Vec::new(),
                allowed_ips: Vec::new(),
                mtu: None,
                key_fingerprint: None,
                peer_fingerprint: None,
                notes: openvpn_profile_notes(profile),
            },
        }
    }
}

impl WireGuardProfile {
    fn validate(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() {
            return Err(anyhow!("wireguard server is empty"));
        }
        if self.port == 0 {
            return Err(anyhow!("wireguard port is zero"));
        }
        if self.allowed_ips.is_empty() {
            return Err(anyhow!("wireguard allowed_ips is empty"));
        }
        if self.interface_ips.is_empty() {
            return Err(anyhow!("wireguard interface ip list is empty"));
        }
        if let Some(psk) = self.preshared_key {
            if psk == [0u8; 32] {
                return Err(anyhow!("wireguard preshared_key must not be all zero"));
            }
        }
        Ok(())
    }

    fn failed_status(&self, error: String) -> L3TunnelStatus {
        L3TunnelStatus {
            name: self.name.clone(),
            protocol: L3Protocol::WireGuard,
            state: L3TunnelState::Failed,
            mode: "native-wireguard-l3".to_string(),
            endpoint: Some(format!("{}:{}", self.server, self.port)),
            started_at: None,
            updated_at: Utc::now(),
            last_error: Some(error),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            details: Vec::new(),
        }
    }
}

impl OpenVpnProfile {
    fn unsupported_status(&self) -> L3TunnelStatus {
        let mut details = Vec::new();
        if self.profile.is_some() || self.inline_profile.is_some() {
            details.push("profile loaded".to_string());
        }
        if let Some(error) = &self.parse_error {
            details.push(format!("parse_error={error}"));
        }
        details.push(
            "native OpenVPN control/data channels are not implemented in this L3 engine yet"
                .to_string(),
        );
        L3TunnelStatus {
            name: self.name.clone(),
            protocol: L3Protocol::OpenVpn,
            state: L3TunnelState::Unsupported,
            mode: "openvpn-profile-manager".to_string(),
            endpoint: None,
            started_at: None,
            updated_at: Utc::now(),
            last_error: Some("openvpn native data plane is not implemented yet".to_string()),
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            details,
        }
    }
}

fn openvpn_profile_notes(profile: &OpenVpnProfile) -> Vec<String> {
    let mut notes =
        vec!["native OpenVPN TLS/control/data channels are not implemented yet".to_string()];

    match (&profile.parsed, &profile.parse_error) {
        (Some(parsed), _) => {
            notes.push(format!("remote_count={}", parsed.remotes.len()));
            notes.push(format!("proto={:?}", parsed.proto));
            notes.push(format!("dev={:?}", parsed.dev));
            if !parsed.ciphers.is_empty() {
                notes.push(format!("ciphers={}", parsed.ciphers.join(",")));
            }
        }
        (None, Some(error)) => {
            notes.push(format!("parse_failed: {error}"));
        }
        (None, None) => {
            notes.push("no profile content to parse".to_string());
        }
    }

    notes
}

async fn run_wireguard_profile(
    manager: L3Manager,
    profile: WireGuardProfile,
    config: L3Config,
    mut stop_rx: watch::Receiver<bool>,
    mut outbound_packet_rx: mpsc::Receiver<Vec<u8>>,
    inbound_packets: broadcast::Sender<L3Packet>,
) {
    let started_at = Utc::now();
    let endpoint =
        match resolve_endpoint(&profile.server, profile.port, config.start_timeout_ms).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                manager.set_status(profile.failed_status(error.to_string()));
                return;
            }
        };
    let bind = if endpoint.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            manager
                .set_status(profile.failed_status(format!("wireguard udp bind failed: {error}")));
            return;
        }
    };
    let persistent_keepalive = Some(
        config
            .handshake_interval_secs
            .clamp(WG_MIN_HANDSHAKE_INTERVAL_SECS, u16::MAX as u64) as u16,
    );
    let mut tunnel = match build_wireguard_tunnel(&profile, persistent_keepalive) {
        Ok(tunnel) => tunnel,
        Err(error) => {
            manager.set_status(profile.failed_status(error.to_string()));
            return;
        }
    };

    let mut tx_packets = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_packets = 0u64;
    let mut rx_bytes = 0u64;
    let interval = Duration::from_secs(
        config
            .handshake_interval_secs
            .max(WG_MIN_HANDSHAKE_INTERVAL_SECS),
    );
    let mut network_buf = vec![0u8; WG_PACKET_BUFFER_SIZE];
    let mut tunnel_buf = vec![0u8; WG_PACKET_BUFFER_SIZE];

    let first_action = wireguard_action(tunnel.format_handshake_initiation(&mut network_buf, true));
    match send_wireguard_action(
        &manager,
        &profile,
        &socket,
        endpoint,
        first_action,
        &mut tx_packets,
        &mut tx_bytes,
        rx_packets,
        rx_bytes,
        started_at,
        config.start_timeout_ms,
        &tunnel,
        &inbound_packets,
    )
    .await
    {
        Ok(()) => {}
        Err(error) => {
            manager.set_status(profile.failed_status(error.to_string()));
            return;
        }
    }

    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                let _ = changed;
                manager.set_status(L3TunnelStatus {
                    name: profile.name.clone(),
                    protocol: L3Protocol::WireGuard,
                    state: L3TunnelState::Stopped,
                    mode: "native-wireguard-l3".to_string(),
                    endpoint: Some(endpoint.to_string()),
                    started_at: Some(started_at),
                    updated_at: Utc::now(),
                    last_error: None,
                    tx_packets,
                    rx_packets,
                    tx_bytes,
                    rx_bytes,
                    details: vec!["wireguard l3 task stopped".to_string()],
                });
                return;
            }
            packet = outbound_packet_rx.recv() => {
                match packet {
                    Some(packet) => {
                        let action = wireguard_action(tunnel.encapsulate(&packet, &mut tunnel_buf));
                        if let Err(error) = send_wireguard_action(
                            &manager,
                            &profile,
                            &socket,
                            endpoint,
                            action.with_note(format!("outbound_ip_packet_bytes={}", packet.len())),
                            &mut tx_packets,
                            &mut tx_bytes,
                            rx_packets,
                            rx_bytes,
                            started_at,
                            config.start_timeout_ms,
                            &tunnel,
                            &inbound_packets,
                        ).await {
                            manager.set_status(L3TunnelStatus {
                                name: profile.name.clone(),
                                protocol: L3Protocol::WireGuard,
                                state: L3TunnelState::Degraded,
                                mode: "native-wireguard-l3".to_string(),
                                endpoint: Some(endpoint.to_string()),
                                started_at: Some(started_at),
                                updated_at: Utc::now(),
                                last_error: Some(error.to_string()),
                                tx_packets,
                                rx_packets,
                                tx_bytes,
                                rx_bytes,
                                details: wireguard_status_details(&tunnel, vec!["outbound IP packet encapsulation failed".to_string()]),
                            });
                        }
                    }
                    None => {
                        manager.set_status(L3TunnelStatus {
                            name: profile.name.clone(),
                            protocol: L3Protocol::WireGuard,
                            state: L3TunnelState::Stopped,
                            mode: "native-wireguard-l3".to_string(),
                            endpoint: Some(endpoint.to_string()),
                            started_at: Some(started_at),
                            updated_at: Utc::now(),
                            last_error: None,
                            tx_packets,
                            rx_packets,
                            tx_bytes,
                            rx_bytes,
                            details: vec!["outbound packet channel closed".to_string()],
                        });
                        return;
                    }
                }
            }
            received = socket.recv_from(&mut network_buf) => {
                match received {
                    Ok((len, peer)) => {
                        rx_packets = rx_packets.saturating_add(1);
                        rx_bytes = rx_bytes.saturating_add(len as u64);
                        let action = wireguard_action(tunnel.decapsulate(
                            Some(peer.ip()),
                            &network_buf[..len],
                            &mut tunnel_buf,
                        ));
                        if let Err(error) = send_wireguard_action(
                            &manager,
                            &profile,
                            &socket,
                            endpoint,
                            action.with_note(format!("last_peer={peer}")).with_note(format!("last_packet_bytes={len}")),
                            &mut tx_packets,
                            &mut tx_bytes,
                            rx_packets,
                            rx_bytes,
                            started_at,
                            config.start_timeout_ms,
                            &tunnel,
                            &inbound_packets,
                        ).await {
                            manager.set_status(L3TunnelStatus {
                                name: profile.name.clone(),
                                protocol: L3Protocol::WireGuard,
                                state: L3TunnelState::Degraded,
                                mode: "native-wireguard-l3".to_string(),
                                endpoint: Some(endpoint.to_string()),
                                started_at: Some(started_at),
                                updated_at: Utc::now(),
                                last_error: Some(error.to_string()),
                                tx_packets,
                                rx_packets,
                                tx_bytes,
                                rx_bytes,
                                details: wireguard_status_details(&tunnel, vec!["network packet handling failed".to_string()]),
                            });
                        }
                    }
                    Err(error) => {
                        manager.set_status(profile.failed_status(format!(
                            "wireguard udp receive failed: {error}"
                        )));
                        return;
                    }
                }
            }
            _ = sleep(interval) => {
                let action = wireguard_action(tunnel.update_timers(&mut tunnel_buf))
                    .with_note("wireguard timer tick".to_string());
                if let Err(error) = send_wireguard_action(
                    &manager,
                    &profile,
                    &socket,
                    endpoint,
                    action,
                    &mut tx_packets,
                    &mut tx_bytes,
                    rx_packets,
                    rx_bytes,
                    started_at,
                    config.start_timeout_ms,
                    &tunnel,
                    &inbound_packets,
                ).await {
                    manager.set_status(L3TunnelStatus {
                        name: profile.name.clone(),
                        protocol: L3Protocol::WireGuard,
                        state: L3TunnelState::Degraded,
                        mode: "native-wireguard-l3".to_string(),
                        endpoint: Some(endpoint.to_string()),
                        started_at: Some(started_at),
                        updated_at: Utc::now(),
                        last_error: Some(error.to_string()),
                        tx_packets,
                        rx_packets,
                        tx_bytes,
                        rx_bytes,
                        details: wireguard_status_details(&tunnel, vec!["timer packet handling failed".to_string()]),
                    });
                }
            }
        }
    }
}

#[derive(Debug)]
enum WireGuardAction {
    Done {
        notes: Vec<String>,
    },
    WriteToNetwork {
        packet: Vec<u8>,
        notes: Vec<String>,
    },
    WriteToTunnel {
        packet: Vec<u8>,
        source: IpAddr,
        notes: Vec<String>,
    },
    Error {
        error: String,
        notes: Vec<String>,
    },
}

impl WireGuardAction {
    fn with_note(mut self, note: impl Into<String>) -> Self {
        let note = note.into();
        match &mut self {
            Self::Done { notes }
            | Self::WriteToNetwork { notes, .. }
            | Self::WriteToTunnel { notes, .. }
            | Self::Error { notes, .. } => notes.push(note),
        }
        self
    }
}

fn build_wireguard_tunnel(
    profile: &WireGuardProfile,
    persistent_keepalive: Option<u16>,
) -> anyhow::Result<Tunn> {
    let mut index_bytes = [0u8; 4];
    getrandom::fill(&mut index_bytes)
        .map_err(|error| anyhow!("failed to generate wireguard tunnel index: {error}"))?;
    let index = u32::from_le_bytes(index_bytes);
    Ok(Tunn::new(
        WireGuardStaticSecret::from(profile.private_key),
        WireGuardPublicKey::from(profile.public_key),
        profile.preshared_key,
        persistent_keepalive,
        index,
        None,
    ))
}

fn wireguard_action(result: TunnResult<'_>) -> WireGuardAction {
    match result {
        TunnResult::Done => WireGuardAction::Done { notes: Vec::new() },
        TunnResult::Err(error) => WireGuardAction::Error {
            error: format!("{error:?}"),
            notes: Vec::new(),
        },
        TunnResult::WriteToNetwork(packet) => WireGuardAction::WriteToNetwork {
            packet: packet.to_vec(),
            notes: Vec::new(),
        },
        TunnResult::WriteToTunnelV4(packet, source) => WireGuardAction::WriteToTunnel {
            packet: packet.to_vec(),
            source: IpAddr::V4(source),
            notes: Vec::new(),
        },
        TunnResult::WriteToTunnelV6(packet, source) => WireGuardAction::WriteToTunnel {
            packet: packet.to_vec(),
            source: IpAddr::V6(source),
            notes: Vec::new(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_wireguard_action(
    manager: &L3Manager,
    profile: &WireGuardProfile,
    socket: &UdpSocket,
    endpoint: SocketAddr,
    action: WireGuardAction,
    tx_packets: &mut u64,
    tx_bytes: &mut u64,
    rx_packets: u64,
    rx_bytes: u64,
    started_at: DateTime<Utc>,
    timeout_ms: u64,
    tunnel: &Tunn,
    inbound_packets: &broadcast::Sender<L3Packet>,
) -> anyhow::Result<()> {
    match action {
        WireGuardAction::Done { notes } => {
            let state = if tunnel.stats().0.is_some() {
                L3TunnelState::Running
            } else {
                L3TunnelState::Handshaking
            };
            manager.set_status(wireguard_status(
                profile,
                endpoint,
                tunnel,
                state,
                started_at,
                None,
                *tx_packets,
                rx_packets,
                *tx_bytes,
                rx_bytes,
                notes,
            ));
            Ok(())
        }
        WireGuardAction::WriteToNetwork { packet, notes } => {
            let sent = timeout(
                Duration::from_millis(timeout_ms.max(1)),
                socket.send_to(&packet, endpoint),
            )
            .await
            .context("wireguard network send timed out")?
            .context("wireguard network send failed")?;
            *tx_packets = tx_packets.saturating_add(1);
            *tx_bytes = tx_bytes.saturating_add(sent as u64);
            let state = if tunnel.stats().0.is_some() {
                L3TunnelState::Running
            } else {
                L3TunnelState::Handshaking
            };
            manager.set_status(wireguard_status(
                profile,
                endpoint,
                tunnel,
                state,
                started_at,
                None,
                *tx_packets,
                rx_packets,
                *tx_bytes,
                rx_bytes,
                notes
                    .into_iter()
                    .chain([
                        format!("network_packet_bytes={sent}"),
                        "wireguard packet written to network".to_string(),
                    ])
                    .collect(),
            ));
            Ok(())
        }
        WireGuardAction::WriteToTunnel {
            packet,
            source,
            notes,
        } => {
            let packet_len = packet.len();
            let l3_packet = L3Packet {
                profile: profile.name.clone(),
                packet,
                direction: L3PacketDirection::ToTun,
                timestamp: Utc::now(),
            };
            let (tun_state, tun_detail) = match inbound_packets.send(l3_packet) {
                Ok(receiver_count) => (
                    L3TunnelState::Running,
                    format!("tun_receivers={receiver_count}"),
                ),
                Err(broadcast::error::SendError(_)) => (
                    L3TunnelState::Degraded,
                    "tun_packet_drop_reason=no_receiver".to_string(),
                ),
            };
            manager.set_status(wireguard_status(
                profile,
                endpoint,
                tunnel,
                tun_state,
                started_at,
                None,
                *tx_packets,
                rx_packets,
                *tx_bytes,
                rx_bytes,
                notes
                    .into_iter()
                    .chain([
                        format!("decapsulated_ip_packet_bytes={packet_len}"),
                        format!("decapsulated_source={source}"),
                        tun_detail,
                    ])
                    .collect(),
            ));
            Ok(())
        }
        WireGuardAction::Error { error, notes } => {
            manager.set_status(wireguard_status(
                profile,
                endpoint,
                tunnel,
                L3TunnelState::Degraded,
                started_at,
                Some(error.clone()),
                *tx_packets,
                rx_packets,
                *tx_bytes,
                rx_bytes,
                notes,
            ));
            Err(anyhow!(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn wireguard_status(
    profile: &WireGuardProfile,
    endpoint: SocketAddr,
    tunnel: &Tunn,
    state: L3TunnelState,
    started_at: DateTime<Utc>,
    error: Option<String>,
    tx_packets: u64,
    rx_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    notes: Vec<String>,
) -> L3TunnelStatus {
    L3TunnelStatus {
        name: profile.name.clone(),
        protocol: L3Protocol::WireGuard,
        state,
        mode: "native-wireguard-l3".to_string(),
        endpoint: Some(endpoint.to_string()),
        started_at: Some(started_at),
        updated_at: Utc::now(),
        last_error: error,
        tx_packets,
        rx_packets,
        tx_bytes,
        rx_bytes,
        details: wireguard_status_details(tunnel, notes),
    }
}

fn wireguard_status_details(tunnel: &Tunn, notes: Vec<String>) -> Vec<String> {
    let (last_handshake, data_tx_bytes, data_rx_bytes, loss, rtt_ms) = tunnel.stats();
    let mut details = vec![
        "engine=boringtun-noise".to_string(),
        "l3_packet_engine=active".to_string(),
        format!("data_tx_bytes={data_tx_bytes}"),
        format!("data_rx_bytes={data_rx_bytes}"),
        format!("estimated_loss={loss:.3}"),
    ];
    if let Some(last_handshake) = last_handshake {
        details.push(format!(
            "last_handshake_age_secs={}",
            last_handshake.as_secs()
        ));
    }
    if let Some(rtt_ms) = rtt_ms {
        details.push(format!("last_rtt_ms={rtt_ms}"));
    }
    details.extend(notes);
    details
}

fn build_l3_profiles(
    config: &SuperConfig,
) -> (
    BTreeMap<String, L3Profile>,
    BTreeMap<String, L3TunnelStatus>,
) {
    let mut profiles = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    if !config.l3.enabled {
        return (profiles, statuses);
    }
    for outbound in &config.outbounds {
        let profile = match profile_from_outbound(outbound) {
            Ok(Some(profile)) => profile,
            Ok(None) => continue,
            Err(error) => {
                let name = outbound.name().to_string();
                statuses.insert(
                    name.clone(),
                    L3TunnelStatus {
                        name,
                        protocol: match outbound {
                            OutboundConfig::WireGuard { .. } => L3Protocol::WireGuard,
                            OutboundConfig::OpenVpn { .. } => L3Protocol::OpenVpn,
                            _ => continue,
                        },
                        state: L3TunnelState::Failed,
                        mode: "profile-parse".to_string(),
                        endpoint: None,
                        started_at: None,
                        updated_at: Utc::now(),
                        last_error: Some(error.to_string()),
                        tx_packets: 0,
                        rx_packets: 0,
                        tx_bytes: 0,
                        rx_bytes: 0,
                        details: Vec::new(),
                    },
                );
                continue;
            }
        };
        statuses
            .entry(profile.name().to_string())
            .or_insert_with(|| profile.initial_status());
        profiles.insert(profile.name().to_string(), profile);
    }
    (profiles, statuses)
}

fn profile_from_outbound(outbound: &OutboundConfig) -> anyhow::Result<Option<L3Profile>> {
    Ok(match outbound {
        OutboundConfig::WireGuard {
            name,
            server,
            port,
            private_key,
            public_key,
            preshared_key,
            ip,
            ipv6,
            allowed_ips,
            reserved,
            mtu,
        } => Some(L3Profile::WireGuard(WireGuardProfile {
            name: name.clone(),
            server: server.clone(),
            port: *port,
            private_key: decode_key(private_key, "wireguard private_key")?,
            public_key: decode_key(public_key, "wireguard public_key")?,
            preshared_key: preshared_key
                .as_deref()
                .map(|value| decode_key(value, "wireguard preshared_key"))
                .transpose()?,
            interface_ips: parse_ip_nets(ip.iter().chain(ipv6.iter()), "wireguard interface ip")?,
            allowed_ips: parse_ip_nets(allowed_ips.iter(), "wireguard allowed_ips")?,
            reserved: reserved.clone(),
            mtu: *mtu,
        })),
        OutboundConfig::OpenVpn {
            name,
            profile,
            inline_profile,
        } => {
            let profile_text = if let Some(text) = inline_profile {
                Some(text.clone())
            } else if let Some(path) = profile {
                Some(std::fs::read_to_string(path).with_context(|| {
                    format!("failed to read OpenVPN profile: {}", path.display())
                })?)
            } else {
                None
            };

            let (parsed, parse_error) = if let Some(text) = profile_text {
                match openvpn::parser::parse_openvpn_profile(&text) {
                    Ok(p) => (Some(p), None),
                    Err(e) => (None, Some(e.to_string())),
                }
            } else {
                (None, None)
            };

            Some(L3Profile::OpenVpn(OpenVpnProfile {
                name: name.clone(),
                profile: profile.as_ref().map(|path| path.display().to_string()),
                inline_profile: inline_profile.clone(),
                parsed,
                parse_error,
            }))
        }
        _ => None,
    })
}

async fn resolve_endpoint(host: &str, port: u16, timeout_ms: u64) -> anyhow::Result<SocketAddr> {
    timeout(
        Duration::from_millis(timeout_ms.max(1)),
        lookup_host((host, port)),
    )
    .await
    .context("wireguard endpoint resolve timed out")?
    .with_context(|| format!("failed to resolve wireguard endpoint {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow!("wireguard endpoint {host}:{port} resolved to no addresses"))
}

fn blake2s_hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn decode_key(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let compact = value.trim();
    let mut padded = compact.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    for candidate in [compact, padded.as_str()] {
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::URL_SAFE,
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(bytes) = engine.decode(candidate) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Ok(key);
                }
            }
        }
    }
    Err(anyhow!("{label} must be base64-encoded 32 bytes"))
}

fn parse_ip_nets<'a>(
    values: impl Iterator<Item = &'a String>,
    label: &str,
) -> anyhow::Result<Vec<IpNet>> {
    let mut output = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Ok(net) = value.parse::<IpNet>() {
            output.push(net);
            continue;
        }
        if let Ok(ip) = value.parse::<IpAddr>() {
            output.push(match ip {
                IpAddr::V4(ip) => IpNet::new(IpAddr::V4(ip), 32)?,
                IpAddr::V6(ip) => IpNet::new(IpAddr::V6(ip), 128)?,
            });
            continue;
        }
        return Err(anyhow!("invalid {label}: {value}"));
    }
    Ok(output)
}

fn key_fingerprint(key: &[u8; 32]) -> String {
    let hash = blake2s_hash(&[key]);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash[..8])
}

fn join_display<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

fn status_for_missing(name: &str, error: &str) -> L3TunnelStatus {
    L3TunnelStatus {
        name: name.to_string(),
        protocol: L3Protocol::WireGuard,
        state: L3TunnelState::Failed,
        mode: "l3-manager".to_string(),
        endpoint: None,
        started_at: None,
        updated_at: Utc::now(),
        last_error: Some(error.to_string()),
        tx_packets: 0,
        rx_packets: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        details: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_tunnel_engine_emits_handshake() {
        let private_key = [7u8; 32];
        let private = WireGuardStaticSecret::from(private_key);
        let public = WireGuardPublicKey::from(&private).to_bytes();
        let profile = WireGuardProfile {
            name: "wg".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key,
            public_key: public,
            preshared_key: None,
            interface_ips: vec!["10.0.0.2/32".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            reserved: Vec::new(),
            mtu: Some(1420),
        };
        let mut tunnel = build_wireguard_tunnel(&profile, Some(25)).unwrap();
        let mut buffer = vec![0u8; WG_PACKET_BUFFER_SIZE];

        let action = wireguard_action(tunnel.format_handshake_initiation(&mut buffer, true));

        match action {
            WireGuardAction::WriteToNetwork { packet, .. } => {
                assert_eq!(packet.len(), 148);
                assert_eq!(u32::from_le_bytes(packet[..4].try_into().unwrap()), 1);
            }
            other => panic!("expected wireguard handshake packet, got {other:?}"),
        }
    }

    #[test]
    fn wireguard_l3_packet_round_trip() {
        let private_key_a = [1u8; 32];
        let private_a = WireGuardStaticSecret::from(private_key_a);
        let public_a = WireGuardPublicKey::from(&private_a).to_bytes();

        let private_key_b = [2u8; 32];
        let private_b = WireGuardStaticSecret::from(private_key_b);
        let public_b = WireGuardPublicKey::from(&private_b).to_bytes();

        let profile_a = WireGuardProfile {
            name: "a".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51820,
            private_key: private_key_a,
            public_key: public_b,
            preshared_key: None,
            interface_ips: vec!["10.0.0.1/32".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            reserved: Vec::new(),
            mtu: Some(1420),
        };

        let profile_b = WireGuardProfile {
            name: "b".to_string(),
            server: "127.0.0.1".to_string(),
            port: 51821,
            private_key: private_key_b,
            public_key: public_a,
            preshared_key: None,
            interface_ips: vec!["10.0.0.2/32".parse().unwrap()],
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            reserved: Vec::new(),
            mtu: Some(1420),
        };

        let mut tunnel_a = build_wireguard_tunnel(&profile_a, Some(25)).unwrap();
        let mut tunnel_b = build_wireguard_tunnel(&profile_b, Some(25)).unwrap();

        let mut buf_a = vec![0u8; WG_PACKET_BUFFER_SIZE];
        let mut buf_b = vec![0u8; WG_PACKET_BUFFER_SIZE];

        // A -> handshake init -> B
        let action_a = wireguard_action(tunnel_a.format_handshake_initiation(&mut buf_a, true));
        let handshake_init = match action_a {
            WireGuardAction::WriteToNetwork { packet, .. } => packet,
            other => panic!("expected handshake init, got {other:?}"),
        };

        // B -> decapsulate init -> handshake response -> A
        let action_b = wireguard_action(tunnel_b.decapsulate(
            Some(IpAddr::V4([127, 0, 0, 1].into())),
            &handshake_init,
            &mut buf_b,
        ));
        let handshake_response = match action_b {
            WireGuardAction::WriteToNetwork { packet, .. } => packet,
            other => panic!("expected handshake response, got {other:?}"),
        };

        // A -> decapsulate response -> keepalive -> B
        let action_a = wireguard_action(tunnel_a.decapsulate(
            Some(IpAddr::V4([127, 0, 0, 1].into())),
            &handshake_response,
            &mut buf_a,
        ));
        let keepalive = match action_a {
            WireGuardAction::WriteToNetwork { packet, .. } => packet,
            other => panic!("expected keepalive, got {other:?}"),
        };

        // B -> decapsulate keepalive -> Done
        let action_b = wireguard_action(tunnel_b.decapsulate(
            Some(IpAddr::V4([127, 0, 0, 1].into())),
            &keepalive,
            &mut buf_b,
        ));
        match action_b {
            WireGuardAction::Done { .. } => {}
            other => panic!("expected done, got {other:?}"),
        }

        // Create a synthetic IPv4 packet (ICMP echo request)
        let mut ipv4_packet = vec![0u8; 28];
        ipv4_packet[0] = 0x45; // IPv4, IHL=5
        ipv4_packet[1] = 0x00; // DSCP/ECN
        ipv4_packet[2] = 0x00; // Total length high
        ipv4_packet[3] = 0x1c; // Total length low (28 bytes)
        ipv4_packet[4] = 0x00; // Identification high
        ipv4_packet[5] = 0x01; // Identification low
        ipv4_packet[6] = 0x40; // Flags (Don't Fragment)
        ipv4_packet[7] = 0x00; // Fragment offset
        ipv4_packet[8] = 0x40; // TTL=64
        ipv4_packet[9] = 0x01; // Protocol=ICMP
        ipv4_packet[12] = 10; // Source IP: 10.0.0.1
        ipv4_packet[13] = 0;
        ipv4_packet[14] = 0;
        ipv4_packet[15] = 1;
        ipv4_packet[16] = 10; // Dest IP: 10.0.0.2
        ipv4_packet[17] = 0;
        ipv4_packet[18] = 0;
        ipv4_packet[19] = 2;
        // ICMP header (type=8, code=0, checksum=0 for simplicity)
        ipv4_packet[20] = 0x08; // Type=Echo request
        ipv4_packet[21] = 0x00; // Code=0
        ipv4_packet[22] = 0x00; // Checksum high
        ipv4_packet[23] = 0x00; // Checksum low
        ipv4_packet[24] = 0x00; // Identifier high
        ipv4_packet[25] = 0x01; // Identifier low
        ipv4_packet[26] = 0x00; // Sequence high
        ipv4_packet[27] = 0x01; // Sequence low

        // A encapsulate IPv4 packet
        let action_a = wireguard_action(tunnel_a.encapsulate(&ipv4_packet, &mut buf_a));
        let encrypted_packet = match action_a {
            WireGuardAction::WriteToNetwork { packet, .. } => packet,
            other => panic!("expected encrypted packet, got {other:?}"),
        };

        // B decapsulate to get original IPv4 packet
        let action_b = wireguard_action(tunnel_b.decapsulate(
            Some(IpAddr::V4([127, 0, 0, 1].into())),
            &encrypted_packet,
            &mut buf_b,
        ));
        match action_b {
            WireGuardAction::WriteToTunnel { packet, source, .. } => {
                assert_eq!(packet, ipv4_packet);
                assert_eq!(source, IpAddr::V4([10, 0, 0, 1].into()));
            }
            other => panic!("expected WriteToTunnel with original packet, got {other:?}"),
        }
    }
}
