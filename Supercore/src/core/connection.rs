use std::{sync::Arc, time::Instant};

use anyhow::anyhow;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

use crate::{
    outbound::{context::DialContext, BoxedStream},
    routing::{Destination, RouteDecision},
    smart::DirectProbeRequest,
    subscription_store::SubscriptionStore,
    telemetry::Telemetry,
};

use super::Runtime;

impl Runtime {
    pub async fn open_connection_record(
        &self,
        inbound: &'static str,
        destination: Destination,
        outbound: String,
        matched_rule: Option<String>,
    ) -> uuid::Uuid {
        self.telemetry
            .open_connection(
                inbound,
                destination,
                outbound,
                self.active_subscription_context(),
                matched_rule,
            )
            .await
    }

    pub async fn close_connection_record(&self, id: uuid::Uuid) {
        let Some(record) = self.telemetry.close_connection(id).await else {
            return;
        };
        let duration_ms = record
            .closed_at
            .unwrap_or_else(chrono::Utc::now)
            .signed_duration_since(record.started_at)
            .num_milliseconds()
            .max(0);
        self.telemetry
            .log(
                "info",
                format!(
                    "connection closed id={} target={} outbound={} up={} down={} duration={}ms rule={}",
                    record.id,
                    record.destination.authority(),
                    record.outbound,
                    record.uploaded,
                    record.downloaded,
                    duration_ms,
                    record.matched_rule.as_deref().unwrap_or("-")
                ),
            )
            .await;
        let Some(subscription) = record.subscription else {
            return;
        };
        let store = SubscriptionStore::new(self.base_config().subscriptions.store_path);
        if let Err(error) = store.add_traffic(&subscription.id, record.uploaded, record.downloaded)
        {
            self.telemetry
                .log(
                    "warn",
                    format!(
                        "failed to persist traffic for subscription {}: {error}",
                        subscription.id
                    ),
                )
                .await;
        }
    }

    pub async fn connect_outbound(
        &self,
        destination: &Destination,
    ) -> anyhow::Result<(BoxedStream, RouteDecision, String)> {
        let (decision, outbound, connect_timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let decision = if let Some(decision) = self.smart_rules.decide(destination) {
                decision
            } else {
                state.router.decide(destination)
            };
            let outbound = state
                .outbounds
                .get(&decision.outbound)
                .cloned()
                .ok_or_else(|| anyhow!("selected outbound '{}' is missing", decision.outbound))?;
            (decision, outbound, state.config.core.connect_timeout_ms)
        };
        let outbound_name = outbound.name().to_string();
        let outbound_kind = outbound.kind().to_string();
        let mut dial_context = DialContext::new(destination.clone(), connect_timeout_ms);
        dial_context.cancellation = self.cancellation_token();
        dial_context.matched_rule = decision.matched_rule.clone();
        dial_context.app_id = destination.app.as_ref().and_then(|app| {
            app.bundle_id
                .clone()
                .or_else(|| app.name.clone())
                .or_else(|| app.path.clone())
        });
        let started = Instant::now();
        match outbound.connect_context(&dial_context).await {
            Ok(stream) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        true,
                        Some(latency_ms),
                        None,
                    )
                    .await;
                self.telemetry
                    .log(
                        "info",
                        format!(
                            "route ok trace={} target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms",
                            dial_context.trace_id,
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms
                        ),
                    )
                    .await;
                if self
                    .smart_rules
                    .record_connect_success(destination, &decision, latency_ms)
                    == DirectProbeRequest::Needed
                {
                    self.spawn_direct_probe(destination.clone());
                }
                Ok((stream, decision, outbound_name))
            }
            Err(error) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                let error_text = error.to_string();
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        false,
                        Some(latency_ms),
                        Some(error_text.clone()),
                    )
                    .await;
                self.telemetry
                    .log(
                        "warn",
                        format!(
                            "route failed trace={} target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms error={}",
                            dial_context.trace_id,
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            error_text
                        ),
                    )
                    .await;
                self.smart_rules
                    .record_connect_failure(destination, &decision);
                Err(error)
            }
        }
    }

    pub async fn exchange_udp(
        &self,
        inbound: &'static str,
        destination: Destination,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (decision, outbound, connect_timeout_ms) = {
            let state = self
                .state
                .read()
                .map_err(|_| anyhow!("runtime state lock poisoned"))?;
            let decision = if let Some(decision) = self.smart_rules.decide(&destination) {
                decision
            } else {
                state.router.decide(&destination)
            };
            let outbound = state
                .outbounds
                .get(&decision.outbound)
                .cloned()
                .ok_or_else(|| anyhow!("selected outbound '{}' is missing", decision.outbound))?;
            (decision, outbound, state.config.core.connect_timeout_ms)
        };
        let outbound_name = outbound.name().to_string();
        let outbound_kind = outbound.kind().to_string();
        let mut dial_context = DialContext::new(destination.clone(), connect_timeout_ms);
        dial_context.cancellation = self.cancellation_token();
        dial_context.matched_rule = decision.matched_rule.clone();
        dial_context.app_id = destination.app.as_ref().and_then(|app| {
            app.bundle_id
                .clone()
                .or_else(|| app.name.clone())
                .or_else(|| app.path.clone())
        });
        let id = self
            .open_connection_record(
                inbound,
                destination.clone(),
                outbound_name.clone(),
                decision.matched_rule.clone(),
            )
            .await;
        let started = Instant::now();
        let result = outbound.udp_exchange_context(&dial_context, payload).await;
        let latency_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(response) => {
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        true,
                        Some(latency_ms),
                        None,
                    )
                    .await;
                self.telemetry
                    .add_transfer(id, payload.len() as u64, response.len() as u64)
                    .await;
                self.telemetry
                    .log(
                        "info",
                        format!(
                            "udp route ok trace={} target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms bytes_up={} bytes_down={}",
                            dial_context.trace_id,
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            payload.len(),
                            response.len()
                        ),
                    )
                    .await;
                self.close_connection_record(id).await;
                Ok(response)
            }
            Err(error) => {
                let error_text = error.to_string();
                self.telemetry
                    .record_outbound_result(
                        outbound_name.clone(),
                        outbound_kind.clone(),
                        false,
                        Some(latency_ms),
                        Some(error_text.clone()),
                    )
                    .await;
                self.telemetry
                    .log(
                        "warn",
                        format!(
                            "udp route failed trace={} target={} outbound={} actual={} kind={} source={:?} rule={} latency={}ms error={}",
                            dial_context.trace_id,
                            destination.authority(),
                            decision.outbound,
                            outbound_name,
                            outbound_kind,
                            decision.source,
                            decision.matched_rule.as_deref().unwrap_or("-"),
                            latency_ms,
                            error_text
                        ),
                    )
                    .await;
                self.close_connection_record(id).await;
                Err(error)
            }
        }
    }

    pub async fn tunnel(
        &self,
        inbound: &'static str,
        destination: Destination,
        client: TcpStream,
    ) -> anyhow::Result<()> {
        let (remote, decision, outbound_name) = self.connect_outbound(&destination).await?;
        let id = self
            .open_connection_record(
                inbound,
                destination.clone(),
                outbound_name.clone(),
                decision.matched_rule.clone(),
            )
            .await;
        self.telemetry
            .log(
                "info",
                format!(
                    "connection opened inbound={} target={} actual={} selected={} source={:?} rule={}",
                    inbound,
                    destination.authority(),
                    outbound_name,
                    decision.outbound,
                    decision.source,
                    decision.matched_rule.as_deref().unwrap_or("-")
                ),
            )
            .await;

        let result = relay_bidirectional(
            self.telemetry.clone(),
            id,
            client,
            remote,
            self.cancellation_token(),
        )
        .await;
        self.close_connection_record(id).await;
        result
    }
}

async fn relay_bidirectional(
    telemetry: Arc<Telemetry>,
    id: uuid::Uuid,
    client: TcpStream,
    remote: BoxedStream,
    cancellation: CancellationToken,
) -> anyhow::Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);

    let upload = copy_counted(
        &mut client_read,
        &mut remote_write,
        telemetry.clone(),
        id,
        true,
    );
    let download = copy_counted(&mut remote_read, &mut client_write, telemetry, id, false);
    tokio::select! {
        _ = cancellation.cancelled() => Err(anyhow!("runtime is shutting down")),
        result = upload => result,
        result = download => result,
    }
}

async fn copy_counted<R, W>(
    reader: &mut R,
    writer: &mut W,
    telemetry: Arc<Telemetry>,
    id: uuid::Uuid,
    upload: bool,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
        if upload {
            telemetry.add_transfer(id, n as u64, 0).await;
        } else {
            telemetry.add_transfer(id, 0, n as u64).await;
        }
    }
}
