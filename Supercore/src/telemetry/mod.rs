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

#[derive(Debug, Serialize)]
pub struct TrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub total: u64,
    pub upload_rate: u64,
    pub download_rate: u64,
    pub total_rate: u64,
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
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            traffic_rate: StdMutex::new(TrafficRateState {
                last_upload_total: 0,
                last_download_total: 0,
                last_checked: Instant::now(),
                upload_rate: 0,
                download_rate: 0,
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
    ) -> Uuid {
        let id = Uuid::new_v4();
        self.connections.write().await.push(ConnectionRecord {
            id,
            inbound: inbound.into(),
            destination,
            outbound: outbound.into(),
            subscription,
            matched_rule,
            uploaded: 0,
            downloaded: 0,
            started_at: Utc::now(),
            closed_at: None,
        });
        id
    }

    pub async fn add_transfer(&self, id: Uuid, uploaded: u64, downloaded: u64) {
        if uploaded > 0 {
            self.upload_total.fetch_add(uploaded, Ordering::Relaxed);
        }
        if downloaded > 0 {
            self.download_total.fetch_add(downloaded, Ordering::Relaxed);
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
