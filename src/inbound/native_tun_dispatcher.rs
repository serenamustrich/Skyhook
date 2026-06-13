use std::sync::Arc;

use tokio::sync::mpsc;

use super::native_tun_flow::{FlowKey, FlowProtocol};
use super::native_tun_metrics::NativeTunMetrics;
use super::native_tun_packet::{parse_ip_packet, TunIpPacket};
use super::native_tun_session::NativeSessionManager;
use super::native_tun_tcp_forward::NativeTcpForwarder;
use crate::core::Runtime;

pub struct L4DispatchResult {
    pub egress_packets: Vec<Vec<u8>>,
    pub tcp_session_count: usize,
    pub udp_session_count: usize,
}

pub struct NativeL4Dispatcher {
    tcp_forwarder: NativeTcpForwarder,
    session_manager: NativeSessionManager,
    egress_tx: mpsc::Sender<Vec<u8>>,
    egress_rx: mpsc::Receiver<Vec<u8>>,
    metrics: NativeTunMetrics,
}

impl NativeL4Dispatcher {
    pub fn new(metrics: NativeTunMetrics) -> Self {
        let session_manager = NativeSessionManager::new(metrics.clone());
        Self::with_session_manager(metrics, session_manager)
    }

    pub fn with_session_manager(
        metrics: NativeTunMetrics,
        session_manager: NativeSessionManager,
    ) -> Self {
        let (egress_tx, egress_rx) = mpsc::channel(256);
        let tcp_forwarder = NativeTcpForwarder::new(egress_tx.clone(), metrics.clone());

        Self {
            tcp_forwarder,
            session_manager,
            egress_tx,
            egress_rx,
            metrics,
        }
    }

    pub fn metrics(&self) -> &NativeTunMetrics {
        &self.metrics
    }

    pub fn session_manager(&self) -> &NativeSessionManager {
        &self.session_manager
    }

    pub fn session_manager_mut(&mut self) -> &mut NativeSessionManager {
        &mut self.session_manager
    }

    pub fn tcp_forwarder(&self) -> &NativeTcpForwarder {
        &self.tcp_forwarder
    }

    pub fn tcp_forwarder_mut(&mut self) -> &mut NativeTcpForwarder {
        &mut self.tcp_forwarder
    }

    pub async fn dispatch_packet(
        &mut self,
        packet: Vec<u8>,
        flow_key: &FlowKey,
        runtime: &Arc<Runtime>,
    ) -> L4DispatchResult {
        let is_tcp = flow_key.protocol == FlowProtocol::Tcp;

        if is_tcp {
            self.tcp_forwarder.handle_packet(&packet, runtime);
            let pending = self.tcp_forwarder.pending_connect_sessions();
            for fk in pending {
                self.tcp_forwarder.connect_and_pump(&fk, runtime).await;
            }
        } else {
            if let Some(response) = self
                .session_manager
                .handle_udp_packet(packet, flow_key, runtime)
                .await
            {
                let _ = self.egress_tx.send(response).await;
            }
        }

        self.session_manager.process_events(runtime).await;

        let mut egress_packets = Vec::new();

        while let Ok(packet) = self.egress_rx.try_recv() {
            egress_packets.push(packet);
        }

        let pending_writes = self.session_manager.take_pending_writes();
        egress_packets.extend(pending_writes);

        L4DispatchResult {
            egress_packets,
            tcp_session_count: self.tcp_forwarder.session_count(),
            udp_session_count: 0,
        }
    }

    pub async fn dispatch_packet_with_channel(
        &mut self,
        packet: Vec<u8>,
        flow_key: &FlowKey,
        runtime: &Arc<Runtime>,
        egress_tx: &mpsc::Sender<Vec<u8>>,
    ) {
        let is_tcp = flow_key.protocol == FlowProtocol::Tcp;

        if is_tcp {
            self.tcp_forwarder.handle_packet(&packet, runtime);
            let pending = self.tcp_forwarder.pending_connect_sessions();
            for fk in pending {
                self.tcp_forwarder.connect_and_pump(&fk, runtime).await;
            }
        } else {
            if let Some(response) = self
                .session_manager
                .handle_udp_packet(packet, flow_key, runtime)
                .await
            {
                let _ = egress_tx.send(response).await;
            }
        }

        self.session_manager.process_events(runtime).await;

        while let Ok(packet) = self.egress_rx.try_recv() {
            let _ = egress_tx.send(packet).await;
        }

        let pending_writes = self.session_manager.take_pending_writes();
        for packet in pending_writes {
            let _ = egress_tx.send(packet).await;
        }
    }

    pub fn cleanup_expired(&mut self) {
        self.tcp_forwarder.cleanup_expired_sessions();
    }

    pub fn tcp_session_count(&self) -> usize {
        self.tcp_forwarder.session_count()
    }

    pub fn is_tcp_packet(packet: &[u8]) -> bool {
        if let Ok(ip_pkt) = parse_ip_packet(packet) {
            matches!(ip_pkt, TunIpPacket::Ipv4(ref ipv4) if ipv4.protocol == 6)
        } else {
            false
        }
    }

    pub fn classify_packet(packet: &[u8]) -> Option<FlowProtocol> {
        let ip_pkt = parse_ip_packet(packet).ok()?;
        match ip_pkt {
            TunIpPacket::Ipv4(ref ipv4) => match ipv4.protocol {
                6 => Some(FlowProtocol::Tcp),
                17 => Some(FlowProtocol::Udp),
                _ => None,
            },
            TunIpPacket::Ipv6(ref ipv6) => match ipv6.next_header {
                6 => Some(FlowProtocol::Tcp),
                17 => Some(FlowProtocol::Udp),
                _ => None,
            },
        }
    }
}
