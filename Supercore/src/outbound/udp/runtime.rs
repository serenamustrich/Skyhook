use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::{
    outbound::{
        context::{active_dial_context, DialContext},
        UdpNatMode,
    },
    routing::Destination,
};

const DEFAULT_MAX_IN_FLIGHT: usize = 64;
const DEFAULT_MAX_PENDING: usize = 256;
const DEFAULT_MAX_ASSOCIATIONS: usize = 4_096;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize)]
pub struct UdpRuntimeSnapshot {
    pub nat_mode: UdpNatMode,
    pub max_in_flight: usize,
    pub max_pending: usize,
    pub active: usize,
    pub waiting: usize,
    pub logical_associations: usize,
    pub attempts: u64,
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub cancelled: u64,
    pub backpressure_rejected: u64,
    pub queue_timed_out: u64,
    pub queue_cancelled: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub associations_created: u64,
    pub associations_evicted: u64,
}

struct AssociationState {
    last_used: Instant,
    packets: u64,
    uploaded: u64,
    downloaded: u64,
}

pub(crate) struct UdpRuntime {
    protocol: String,
    node: String,
    nat_mode: UdpNatMode,
    limiter: Semaphore,
    max_in_flight: usize,
    max_pending: usize,
    max_associations: usize,
    idle_timeout: Duration,
    waiting: AtomicUsize,
    active: AtomicUsize,
    attempts: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    timed_out: AtomicU64,
    cancelled: AtomicU64,
    backpressure_rejected: AtomicU64,
    queue_timed_out: AtomicU64,
    queue_cancelled: AtomicU64,
    uploaded_bytes: AtomicU64,
    downloaded_bytes: AtomicU64,
    associations_created: AtomicU64,
    associations_evicted: AtomicU64,
    associations: Mutex<HashMap<String, AssociationState>>,
}

impl UdpRuntime {
    pub(crate) fn new(
        protocol: impl Into<String>,
        node: impl Into<String>,
        nat_mode: UdpNatMode,
    ) -> Self {
        Self::with_limits(
            protocol,
            node,
            nat_mode,
            DEFAULT_MAX_IN_FLIGHT,
            DEFAULT_MAX_PENDING,
            DEFAULT_MAX_ASSOCIATIONS,
            DEFAULT_IDLE_TIMEOUT,
        )
    }

    fn with_limits(
        protocol: impl Into<String>,
        node: impl Into<String>,
        nat_mode: UdpNatMode,
        max_in_flight: usize,
        max_pending: usize,
        max_associations: usize,
        idle_timeout: Duration,
    ) -> Self {
        let max_in_flight = max_in_flight.max(1);
        Self {
            protocol: protocol.into(),
            node: node.into(),
            nat_mode,
            limiter: Semaphore::new(max_in_flight),
            max_in_flight,
            max_pending,
            max_associations: max_associations.max(1),
            idle_timeout,
            waiting: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            attempts: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            timed_out: AtomicU64::new(0),
            cancelled: AtomicU64::new(0),
            backpressure_rejected: AtomicU64::new(0),
            queue_timed_out: AtomicU64::new(0),
            queue_cancelled: AtomicU64::new(0),
            uploaded_bytes: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
            associations_created: AtomicU64::new(0),
            associations_evicted: AtomicU64::new(0),
            associations: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn exchange<C, F>(
        &self,
        context: &DialContext,
        payload: &[u8],
        operation: C,
    ) -> anyhow::Result<Vec<u8>>
    where
        C: FnOnce() -> F,
        F: Future<Output = anyhow::Result<Vec<u8>>>,
    {
        let waiting = self.waiting.fetch_add(1, Ordering::AcqRel) + 1;
        if waiting > self.max_pending {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            self.backpressure_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!(
                "UDP backpressure queue is full for {} ({}/{})",
                self.node,
                waiting - 1,
                self.max_pending
            ));
        }
        let wait_guard = CounterGuard::new(&self.waiting);
        let remaining = context.remaining_timeout();
        if remaining.is_zero() {
            self.queue_timed_out.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("UDP queue deadline expired for {}", self.node));
        }
        let permit = tokio::select! {
            _ = context.cancellation.cancelled() => {
                self.queue_cancelled.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow!("UDP queue wait cancelled for {}", self.node));
            }
            result = tokio::time::timeout(remaining, self.limiter.acquire()) => {
                match result {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(anyhow!("UDP runtime is closed for {}", self.node)),
                    Err(_) => {
                        self.queue_timed_out.fetch_add(1, Ordering::Relaxed);
                        return Err(anyhow!("UDP queue wait timed out for {}", self.node));
                    }
                }
            }
        };
        drop(wait_guard);

        self.active.fetch_add(1, Ordering::AcqRel);
        let active_guard = CounterGuard::new(&self.active);
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.uploaded_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        let association_key = udp_session_key_with_context(
            &self.protocol,
            &self.node,
            self.nat_mode,
            Some(&context.destination),
            Some(context),
        );
        self.record_start(&association_key, payload.len() as u64);

        let remaining = context.remaining_timeout();
        let result = if remaining.is_zero() {
            Err(anyhow!("UDP exchange deadline expired for {}", self.node))
        } else {
            let operation = operation();
            tokio::select! {
                biased;
                _ = context.cancellation.cancelled() => {
                    Err(anyhow!("UDP exchange cancelled for {}", self.node))
                }
                result = operation => result,
                _ = tokio::time::sleep_until(context.deadline.into()) => {
                    Err(anyhow!("UDP exchange timed out for {}", self.node))
                }
            }
        };

        match &result {
            Ok(response) => {
                self.completed.fetch_add(1, Ordering::Relaxed);
                self.downloaded_bytes
                    .fetch_add(response.len() as u64, Ordering::Relaxed);
                self.record_finish(&association_key, response.len() as u64);
            }
            Err(error) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                let message = format!("{error:#}");
                if message.contains("cancelled") {
                    self.cancelled.fetch_add(1, Ordering::Relaxed);
                } else if message.contains("timed out") || message.contains("deadline") {
                    self.timed_out.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(permit);
        drop(active_guard);
        result
    }

    pub(crate) fn snapshot(&self) -> UdpRuntimeSnapshot {
        let logical_associations = self.evict_idle_and_len();
        UdpRuntimeSnapshot {
            nat_mode: self.nat_mode,
            max_in_flight: self.max_in_flight,
            max_pending: self.max_pending,
            active: self.active.load(Ordering::Relaxed),
            waiting: self.waiting.load(Ordering::Relaxed),
            logical_associations,
            attempts: self.attempts.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            cancelled: self.cancelled.load(Ordering::Relaxed),
            backpressure_rejected: self.backpressure_rejected.load(Ordering::Relaxed),
            queue_timed_out: self.queue_timed_out.load(Ordering::Relaxed),
            queue_cancelled: self.queue_cancelled.load(Ordering::Relaxed),
            uploaded_bytes: self.uploaded_bytes.load(Ordering::Relaxed),
            downloaded_bytes: self.downloaded_bytes.load(Ordering::Relaxed),
            associations_created: self.associations_created.load(Ordering::Relaxed),
            associations_evicted: self.associations_evicted.load(Ordering::Relaxed),
        }
    }

    fn record_start(&self, key: &str, uploaded: u64) {
        let now = Instant::now();
        let Ok(mut associations) = self.associations.lock() else {
            return;
        };
        self.evict_idle_locked(&mut associations, now);
        if !associations.contains_key(key) && associations.len() >= self.max_associations {
            if let Some(oldest) = associations
                .iter()
                .min_by_key(|(_, state)| state.last_used)
                .map(|(key, _)| key.clone())
            {
                associations.remove(&oldest);
                self.associations_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
        let state = associations.entry(key.to_string()).or_insert_with(|| {
            self.associations_created.fetch_add(1, Ordering::Relaxed);
            AssociationState {
                last_used: now,
                packets: 0,
                uploaded: 0,
                downloaded: 0,
            }
        });
        state.last_used = now;
        state.packets = state.packets.saturating_add(1);
        state.uploaded = state.uploaded.saturating_add(uploaded);
    }

    fn record_finish(&self, key: &str, downloaded: u64) {
        let Ok(mut associations) = self.associations.lock() else {
            return;
        };
        if let Some(state) = associations.get_mut(key) {
            state.last_used = Instant::now();
            state.downloaded = state.downloaded.saturating_add(downloaded);
        }
    }

    fn evict_idle_and_len(&self) -> usize {
        let Ok(mut associations) = self.associations.lock() else {
            return 0;
        };
        self.evict_idle_locked(&mut associations, Instant::now());
        associations.len()
    }

    fn evict_idle_locked(
        &self,
        associations: &mut HashMap<String, AssociationState>,
        now: Instant,
    ) {
        let before = associations.len();
        associations.retain(|_, state| now.duration_since(state.last_used) < self.idle_timeout);
        self.associations_evicted
            .fetch_add((before - associations.len()) as u64, Ordering::Relaxed);
    }
}

pub(crate) fn udp_session_key(
    protocol: &str,
    node: &str,
    nat_mode: UdpNatMode,
    destination: Option<&Destination>,
) -> String {
    let active = active_dial_context();
    udp_session_key_with_context(protocol, node, nat_mode, destination, active.as_ref())
}

fn udp_session_key_with_context(
    protocol: &str,
    node: &str,
    nat_mode: UdpNatMode,
    destination: Option<&Destination>,
    context: Option<&DialContext>,
) -> String {
    let mut key = String::with_capacity(256);
    push_key_part(&mut key, protocol);
    push_key_part(&mut key, node);
    push_key_part(
        &mut key,
        match nat_mode {
            UdpNatMode::EndpointDependent => "endpoint-dependent",
            UdpNatMode::EndpointIndependent => "endpoint-independent",
        },
    );
    if nat_mode == UdpNatMode::EndpointDependent {
        push_key_part(
            &mut key,
            destination
                .map(Destination::authority)
                .as_deref()
                .unwrap_or(""),
        );
    }
    if let Some(context) = context {
        push_key_part(
            &mut key,
            context
                .source
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or(""),
        );
        push_key_part(
            &mut key,
            context
                .bind_address
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or(""),
        );
        push_key_part(&mut key, context.inbound_name.as_deref().unwrap_or(""));
        push_key_part(&mut key, context.inbound_type.as_deref().unwrap_or(""));
        push_key_part(&mut key, context.app_id.as_deref().unwrap_or(""));
        push_key_part(&mut key, context.subscription_id.as_deref().unwrap_or(""));
        push_key_part(&mut key, context.selected_group.as_deref().unwrap_or(""));
        push_key_part(&mut key, context.interface_name.as_deref().unwrap_or(""));
        push_key_part(&mut key, &format!("{:?}", context.ip_version));
        for dialer in &context.dialer_chain {
            push_key_part(&mut key, dialer);
        }
    }
    key
}

fn push_key_part(output: &mut String, value: &str) {
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
    output.push('|');
}

struct CounterGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> CounterGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        Self { counter }
    }
}

impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::sync::Notify;

    use crate::{
        outbound::context::{scope_dial_context, DialContext},
        routing::Destination,
    };

    use crate::outbound::UdpNatMode;

    use super::{udp_session_key, UdpRuntime};

    #[tokio::test]
    async fn endpoint_dependent_and_independent_keys_have_expected_scope() {
        let first = Destination::new("one.example", 53);
        let second = Destination::new("two.example", 53);
        let mut context = DialContext::new(first.clone(), 1_000);
        context.bind_address = Some("127.0.0.1:0".parse().unwrap());
        let (dependent_first, dependent_second, independent_first, independent_second) =
            scope_dial_context(&context, async {
                (
                    udp_session_key("test", "node", UdpNatMode::EndpointDependent, Some(&first)),
                    udp_session_key("test", "node", UdpNatMode::EndpointDependent, Some(&second)),
                    udp_session_key(
                        "test",
                        "node",
                        UdpNatMode::EndpointIndependent,
                        Some(&first),
                    ),
                    udp_session_key(
                        "test",
                        "node",
                        UdpNatMode::EndpointIndependent,
                        Some(&second),
                    ),
                )
            })
            .await;
        assert_ne!(dependent_first, dependent_second);
        assert_eq!(independent_first, independent_second);

        let mut other_context = DialContext::new(first.clone(), 1_000);
        other_context.bind_address = Some("127.0.0.2:0".parse().unwrap());
        let other_binding = scope_dial_context(&other_context, async {
            udp_session_key(
                "test",
                "node",
                UdpNatMode::EndpointIndependent,
                Some(&first),
            )
        })
        .await;
        assert_ne!(independent_first, other_binding);
    }

    #[tokio::test]
    async fn queue_is_bounded_and_rejected_operation_never_runs() {
        let runtime = Arc::new(UdpRuntime::with_limits(
            "test",
            "node",
            UdpNatMode::EndpointDependent,
            1,
            1,
            8,
            Duration::from_secs(60),
        ));
        let release = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let first_runtime = Arc::clone(&runtime);
        let first_release = Arc::clone(&release);
        let first_started = Arc::clone(&started);
        let first = tokio::spawn(async move {
            let context = DialContext::new(Destination::new("one.example", 53), 1_000);
            first_runtime
                .exchange(&context, b"one", || async move {
                    first_started.notify_one();
                    first_release.notified().await;
                    Ok(b"ok".to_vec())
                })
                .await
        });
        started.notified().await;

        let second_runtime = Arc::clone(&runtime);
        let second = tokio::spawn(async move {
            let context = DialContext::new(Destination::new("two.example", 53), 1_000);
            second_runtime
                .exchange(&context, b"two", || async { Ok(b"second".to_vec()) })
                .await
        });
        while runtime.snapshot().waiting != 1 {
            tokio::task::yield_now().await;
        }

        let rejected_context = DialContext::new(Destination::new("two.example", 53), 1_000);
        let error = runtime
            .exchange(&rejected_context, b"three", || async {
                panic!("backpressure-rejected operation must not execute");
                #[allow(unreachable_code)]
                Ok(Vec::new())
            })
            .await
            .expect_err("full queue must reject");
        assert!(error.to_string().contains("backpressure queue is full"));
        assert_eq!(runtime.snapshot().backpressure_rejected, 1);
        release.notify_one();
        first.await.expect("first join").expect("first exchange");
        second.await.expect("second join").expect("second exchange");
    }

    #[tokio::test]
    async fn queue_timeout_is_not_counted_as_an_executed_attempt() {
        let runtime = Arc::new(UdpRuntime::with_limits(
            "test",
            "node",
            UdpNatMode::EndpointDependent,
            1,
            2,
            8,
            Duration::from_secs(60),
        ));
        let release = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let first_runtime = Arc::clone(&runtime);
        let first_release = Arc::clone(&release);
        let first_started = Arc::clone(&started);
        let first = tokio::spawn(async move {
            let context = DialContext::new(Destination::new("one.example", 53), 1_000);
            first_runtime
                .exchange(&context, b"one", || async move {
                    first_started.notify_one();
                    first_release.notified().await;
                    Ok(b"ok".to_vec())
                })
                .await
        });
        started.notified().await;

        let context = DialContext::new(Destination::new("two.example", 53), 20);
        let error = runtime
            .exchange(&context, b"two", || async {
                panic!("queue-timed-out operation must not execute");
                #[allow(unreachable_code)]
                Ok(Vec::new())
            })
            .await
            .expect_err("queue wait must time out");
        assert!(error.to_string().contains("queue wait timed out"));
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.attempts, 1);
        assert_eq!(snapshot.queue_timed_out, 1);
        assert_eq!(snapshot.timed_out, 0);
        release.notify_one();
        first.await.expect("first join").expect("first exchange");
    }
}
