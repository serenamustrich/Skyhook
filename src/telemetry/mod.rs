use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex as StdMutex,
    },
    time::Instant,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::routing::Destination;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Serialize, Clone)]
pub struct RealtimeTraffic {
    pub snapshot: TrafficSnapshot,
    pub active_connections: usize,
    pub peak_upload_rate: u64,
    pub peak_download_rate: u64,
    pub peak_total_rate: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct ActiveConnectionEntry {
    pub id: Uuid,
    pub inbound: String,
    pub destination: Destination,
    pub outbound: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<ConnectionSubscription>,
    pub matched_rule: Option<String>,
    pub uploaded: u64,
    pub downloaded: u64,
    pub started_at: DateTime<Utc>,
    pub duration_secs: f64,
}

#[derive(Debug, Serialize, Clone)]
pub struct OutboundTrafficEntry {
    pub outbound: String,
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub connections: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProtocolTrafficEntry {
    pub protocol: String,
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub connections: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct ConnectionRecord {
    pub id: Uuid,
    pub inbound: String,
    pub destination: Destination,
    pub outbound: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<ConnectionSubscription>,
    pub matched_rule: Option<String>,
    pub uploaded: u64,
    pub downloaded: u64,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ConnectionSubscription {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct LogEvent {
    pub time: DateTime<Utc>,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub total_rate: u64,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct ProtocolTrafficStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queries: Option<u64>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct OutboundTrafficStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
}

#[derive(Debug, Serialize)]
pub struct DetailedTrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub total_rate: u64,
    pub protocols: HashMap<String, ProtocolTrafficStats>,
    pub outbounds: HashMap<String, OutboundTrafficStats>,
}

#[derive(Debug, Serialize, Clone)]
pub struct OutboundHealth {
    pub name: String,
    pub kind: String,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub last_latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub score: u8,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Telemetry {
    upload_total: AtomicU64,
    download_total: AtomicU64,
    tcp_bytes_in: AtomicU64,
    tcp_bytes_out: AtomicU64,
    tcp_connections: AtomicU64,
    udp_bytes_in: AtomicU64,
    udp_bytes_out: AtomicU64,
    udp_packets: AtomicU64,
    dns_queries: AtomicU64,
    dns_bytes: AtomicU64,
    outbound_traffic: RwLock<HashMap<String, OutboundTrafficStats>>,
    traffic_rate: StdMutex<TrafficRateState>,
    connections: RwLock<Vec<ConnectionRecord>>,
    logs: RwLock<VecDeque<LogEvent>>,
    outbound_health: RwLock<HashMap<String, OutboundHealth>>,
}

#[derive(Debug)]
struct TrafficRateState {
    last_upload_total: u64,
    last_download_total: u64,
    last_checked: Instant,
    upload_rate: u64,
    download_rate: u64,
    peak_upload_rate: u64,
    peak_download_rate: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            tcp_bytes_in: AtomicU64::new(0),
            tcp_bytes_out: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            udp_bytes_in: AtomicU64::new(0),
            udp_bytes_out: AtomicU64::new(0),
            udp_packets: AtomicU64::new(0),
            dns_queries: AtomicU64::new(0),
            dns_bytes: AtomicU64::new(0),
            outbound_traffic: RwLock::new(HashMap::new()),
            traffic_rate: StdMutex::new(TrafficRateState {
                last_upload_total: 0,
                last_download_total: 0,
                last_checked: Instant::now(),
                upload_rate: 0,
                download_rate: 0,
                peak_upload_rate: 0,
                peak_download_rate: 0,
            }),
            connections: RwLock::new(Vec::new()),
            logs: RwLock::new(VecDeque::new()),
            outbound_health: RwLock::new(HashMap::new()),
        }
    }
}

impl Telemetry {
    pub async fn open_connection(
        &self,
        inbound: impl Into<String>,
        destination: Destination,
        outbound: impl Into<String>,
        subscription: Option<ConnectionSubscription>,
        matched_rule: Option<String>,
        protocol: Protocol,
    ) -> Uuid {
        let outbound_str = outbound.into();
        if protocol == Protocol::Tcp {
            self.tcp_connections.fetch_add(1, Ordering::Relaxed);
        }
        if !outbound_str.is_empty() {
            let mut outbounds = self.outbound_traffic.write().await;
            let entry = outbounds
                .entry(outbound_str.clone())
                .or_insert_with(OutboundTrafficStats::default);
            entry.connections = entry.connections.saturating_add(1);
        }
        let id = Uuid::new_v4();
        self.connections.write().await.push(ConnectionRecord {
            id,
            inbound: inbound.into(),
            destination,
            outbound: outbound_str,
            subscription,
            matched_rule,
            uploaded: 0,
            downloaded: 0,
            started_at: Utc::now(),
            closed_at: None,
        });
        id
    }

    pub async fn add_transfer(
        &self,
        id: Uuid,
        uploaded: u64,
        downloaded: u64,
        protocol: Protocol,
        outbound: &str,
    ) {
        if uploaded > 0 {
            self.upload_total.fetch_add(uploaded, Ordering::Relaxed);
        }
        if downloaded > 0 {
            self.download_total.fetch_add(downloaded, Ordering::Relaxed);
        }
        match protocol {
            Protocol::Tcp => {
                if uploaded > 0 {
                    self.tcp_bytes_out.fetch_add(uploaded, Ordering::Relaxed);
                }
                if downloaded > 0 {
                    self.tcp_bytes_in.fetch_add(downloaded, Ordering::Relaxed);
                }
            }
            Protocol::Udp => {
                if uploaded > 0 {
                    self.udp_bytes_out.fetch_add(uploaded, Ordering::Relaxed);
                }
                if downloaded > 0 {
                    self.udp_bytes_in.fetch_add(downloaded, Ordering::Relaxed);
                }
                self.udp_packets.fetch_add(1, Ordering::Relaxed);
            }
            Protocol::Dns => {
                self.dns_queries.fetch_add(1, Ordering::Relaxed);
                self.dns_bytes
                    .fetch_add(uploaded.saturating_add(downloaded), Ordering::Relaxed);
            }
        }
        if !outbound.is_empty() {
            let mut outbounds = self.outbound_traffic.write().await;
            let entry = outbounds
                .entry(outbound.to_string())
                .or_insert_with(OutboundTrafficStats::default);
            entry.bytes_out = entry.bytes_out.saturating_add(uploaded);
            entry.bytes_in = entry.bytes_in.saturating_add(downloaded);
        }
        let mut connections = self.connections.write().await;
        if let Some(record) = connections.iter_mut().find(|item| item.id == id) {
            record.uploaded = record.uploaded.saturating_add(uploaded);
            record.downloaded = record.downloaded.saturating_add(downloaded);
        }
    }

    pub async fn close_connection(&self, id: Uuid) -> Option<ConnectionRecord> {
        let mut connections = self.connections.write().await;
        let mut closed = None;
        if let Some(record) = connections.iter_mut().find(|item| item.id == id) {
            record.closed_at = Some(Utc::now());
            closed = Some(record.clone());
        }
        let remove_before = Utc::now() - chrono::Duration::minutes(2);
        connections.retain(|item| {
            item.closed_at
                .map(|time| time > remove_before)
                .unwrap_or(true)
        });
        closed
    }

    pub async fn log(&self, level: impl Into<String>, message: impl Into<String>) {
        let mut logs = self.logs.write().await;
        logs.push_back(LogEvent {
            time: Utc::now(),
            level: level.into(),
            message: message.into(),
        });
        while logs.len() > 1000 {
            logs.pop_front();
        }
    }

    pub async fn record_outbound_result(
        &self,
        name: impl Into<String>,
        kind: impl Into<String>,
        success: bool,
        latency_ms: Option<u64>,
        error: Option<String>,
    ) {
        let name = name.into();
        let mut health = self.outbound_health.write().await;
        let item = health
            .entry(name.clone())
            .or_insert_with(|| OutboundHealth {
                name,
                kind: kind.into(),
                attempts: 0,
                successes: 0,
                failures: 0,
                last_latency_ms: None,
                last_error: None,
                score: 100,
                updated_at: Utc::now(),
            });
        item.attempts = item.attempts.saturating_add(1);
        if success {
            item.successes = item.successes.saturating_add(1);
            item.last_error = None;
            item.last_latency_ms = latency_ms;
        } else {
            item.failures = item.failures.saturating_add(1);
            item.last_error = error;
            item.last_latency_ms = latency_ms;
        }
        item.score = outbound_score(item.successes, item.failures, item.last_latency_ms);
        item.updated_at = Utc::now();
    }

    pub fn traffic(&self) -> TrafficSnapshot {
        let upload_total = self.upload_total.load(Ordering::Relaxed);
        let download_total = self.download_total.load(Ordering::Relaxed);
        let (upload_rate, download_rate) = self
            .traffic_rate
            .lock()
            .map(|mut state| {
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_checked).as_secs_f64();
                if elapsed >= 0.2 {
                    let upload_delta = upload_total.saturating_sub(state.last_upload_total);
                    let download_delta = download_total.saturating_sub(state.last_download_total);
                    state.upload_rate = (upload_delta as f64 / elapsed).round() as u64;
                    state.download_rate = (download_delta as f64 / elapsed).round() as u64;
                    state.last_upload_total = upload_total;
                    state.last_download_total = download_total;
                    state.last_checked = now;
                    if state.upload_rate > state.peak_upload_rate {
                        state.peak_upload_rate = state.upload_rate;
                    }
                    if state.download_rate > state.peak_download_rate {
                        state.peak_download_rate = state.download_rate;
                    }
                }
                (state.upload_rate, state.download_rate)
            })
            .unwrap_or((0, 0));
        TrafficSnapshot {
            upload_total,
            download_total,
            total: upload_total.saturating_add(download_total),
            upload_rate,
            download_rate,
            total_rate: upload_rate.saturating_add(download_rate),
        }
    }

    pub async fn detailed_traffic(&self) -> DetailedTrafficSnapshot {
        let snapshot = self.traffic();
        let mut protocols = HashMap::new();
        protocols.insert(
            "tcp".to_string(),
            ProtocolTrafficStats {
                bytes_in: self.tcp_bytes_in.load(Ordering::Relaxed),
                bytes_out: self.tcp_bytes_out.load(Ordering::Relaxed),
                connections: Some(self.tcp_connections.load(Ordering::Relaxed)),
                ..Default::default()
            },
        );
        protocols.insert(
            "udp".to_string(),
            ProtocolTrafficStats {
                bytes_in: self.udp_bytes_in.load(Ordering::Relaxed),
                bytes_out: self.udp_bytes_out.load(Ordering::Relaxed),
                packets: Some(self.udp_packets.load(Ordering::Relaxed)),
                ..Default::default()
            },
        );
        protocols.insert(
            "dns".to_string(),
            ProtocolTrafficStats {
                queries: Some(self.dns_queries.load(Ordering::Relaxed)),
                bytes_in: self.dns_bytes.load(Ordering::Relaxed),
                ..Default::default()
            },
        );
        let outbounds = self.outbound_traffic.read().await.clone();
        DetailedTrafficSnapshot {
            upload_total: snapshot.upload_total,
            download_total: snapshot.download_total,
            total: snapshot.total,
            upload_rate: snapshot.upload_rate,
            download_rate: snapshot.download_rate,
            total_rate: snapshot.total_rate,
            protocols,
            outbounds,
        }
    }

    pub fn realtime_traffic(&self) -> RealtimeTraffic {
        let snapshot = self.traffic();
        let (peak_upload, peak_download) = self
            .traffic_rate
            .lock()
            .map(|state| (state.peak_upload_rate, state.peak_download_rate))
            .unwrap_or((0, 0));
        let active_count = self
            .connections
            .try_read()
            .map(|c| c.iter().filter(|r| r.closed_at.is_none()).count())
            .unwrap_or(0);
        RealtimeTraffic {
            snapshot,
            active_connections: active_count,
            peak_upload_rate: peak_upload,
            peak_download_rate: peak_download,
            peak_total_rate: peak_upload.saturating_add(peak_download),
        }
    }

    pub async fn active_connections(&self) -> Vec<ActiveConnectionEntry> {
        let now = Utc::now();
        self.connections
            .read()
            .await
            .iter()
            .filter(|r| r.closed_at.is_none())
            .map(|r| ActiveConnectionEntry {
                id: r.id,
                inbound: r.inbound.clone(),
                destination: r.destination.clone(),
                outbound: r.outbound.clone(),
                subscription: r.subscription.clone(),
                matched_rule: r.matched_rule.clone(),
                uploaded: r.uploaded,
                downloaded: r.downloaded,
                started_at: r.started_at,
                duration_secs: (now - r.started_at).num_milliseconds() as f64 / 1000.0,
            })
            .collect()
    }

    pub async fn traffic_by_outbound(&self) -> Vec<OutboundTrafficEntry> {
        let mut map: HashMap<String, (u64, u64, usize)> = HashMap::new();
        for conn in self.connections.read().await.iter() {
            let entry = map.entry(conn.outbound.clone()).or_insert((0, 0, 0));
            entry.0 = entry.0.saturating_add(conn.uploaded);
            entry.1 = entry.1.saturating_add(conn.downloaded);
            entry.2 += 1;
        }
        let mut items: Vec<OutboundTrafficEntry> = map
            .into_iter()
            .map(
                |(outbound, (upload, download, connections))| OutboundTrafficEntry {
                    outbound,
                    upload,
                    download,
                    total: upload.saturating_add(download),
                    connections,
                },
            )
            .collect();
        items.sort_by(|a, b| b.total.cmp(&a.total));
        items
    }

    pub async fn traffic_by_protocol(&self) -> Vec<ProtocolTrafficEntry> {
        let mut map: HashMap<String, (u64, u64, usize)> = HashMap::new();
        for conn in self.connections.read().await.iter() {
            let protocol = classify_protocol(conn.destination.port);
            let entry = map.entry(protocol).or_insert((0, 0, 0));
            entry.0 = entry.0.saturating_add(conn.uploaded);
            entry.1 = entry.1.saturating_add(conn.downloaded);
            entry.2 += 1;
        }
        let mut items: Vec<ProtocolTrafficEntry> = map
            .into_iter()
            .map(
                |(protocol, (upload, download, connections))| ProtocolTrafficEntry {
                    protocol,
                    upload,
                    download,
                    total: upload.saturating_add(download),
                    connections,
                },
            )
            .collect();
        items.sort_by(|a, b| b.total.cmp(&a.total));
        items
    }

    pub async fn connections(&self) -> Vec<ConnectionRecord> {
        self.connections.read().await.clone()
    }

    pub async fn logs(&self) -> Vec<LogEvent> {
        self.logs.read().await.iter().cloned().rev().collect()
    }

    pub async fn outbound_health(&self) -> Vec<OutboundHealth> {
        let mut items = self
            .outbound_health
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        items
    }

    pub fn outbound_health_sync(&self) -> Vec<OutboundHealth> {
        let items = self
            .outbound_health
            .try_read()
            .map(|guard| guard.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        items
    }
}

fn outbound_score(successes: u64, failures: u64, latency_ms: Option<u64>) -> u8 {
    let total = successes + failures;
    if total == 0 {
        return 100;
    }
    let success_rate = successes as f64 / total as f64;
    let latency_penalty = latency_ms
        .map(|latency| (latency.saturating_sub(50).min(950) as f64 / 950.0) * 30.0)
        .unwrap_or(0.0);
    ((success_rate * 100.0 - latency_penalty).clamp(0.0, 100.0)).round() as u8
}

fn classify_protocol(port: u16) -> String {
    match port {
        53 | 853 | 5353 => "dns",
        80 | 8080 => "http",
        443 | 8443 => "https",
        25 | 465 | 587 => "smtp",
        110 | 995 => "pop3",
        143 | 993 => "imap",
        21 | 990 => "ftp",
        22 => "ssh",
        3306 => "mysql",
        5432 => "postgres",
        6379 => "redis",
        _ => "other",
    }
    .to_string()
}
