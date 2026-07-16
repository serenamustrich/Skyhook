use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
    time::Instant,
};

use anyhow::anyhow;
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinSet,
    time::{sleep, timeout, Duration},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    outbound::{
        context::DialContext,
        error::{classify_message, OutboundError},
        Outbound,
    },
    routing::Destination,
    smart,
    telemetry::Telemetry,
};

use super::{dns::dns_tls_client_config, Runtime};

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub name: String,
    pub kind: String,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub failure_kind: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProbeOptions {
    pub url: Option<String>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ProbeProgress {
    pub completed: u64,
    pub total: u64,
    pub name: String,
}

#[derive(Debug, Clone)]
struct ProbeTarget {
    destination: Destination,
    server_name: String,
    host_header: String,
    request_target: String,
    use_tls: bool,
}

impl Runtime {
    pub async fn probe_all_outbounds(&self) -> Vec<ProbeResult> {
        self.probe_all_outbounds_with(ProbeOptions::default()).await
    }

    pub async fn probe_all_outbounds_with(&self, options: ProbeOptions) -> Vec<ProbeResult> {
        self.probe_all_outbounds_with_progress(options, None).await
    }

    pub fn probe_target_count(&self, options: &ProbeOptions) -> u64 {
        if let Some(names) = normalized_probe_names(options.names.as_ref()) {
            return names.len() as u64;
        }
        self.state
            .read()
            .map(|state| {
                state
                    .outbounds
                    .values()
                    .filter(|outbound| outbound.kind() != "reject")
                    .count() as u64
            })
            .unwrap_or(0)
    }

    pub async fn probe_all_outbounds_with_progress(
        &self,
        options: ProbeOptions,
        progress: Option<tokio::sync::mpsc::UnboundedSender<ProbeProgress>>,
    ) -> Vec<ProbeResult> {
        let requested_names = normalized_probe_names(options.names.as_ref());
        let (probe_url, probe_timeout_ms, probe_concurrency, outbounds) = {
            let state = match self.state.read() {
                Ok(state) => state,
                Err(_) => return Vec::new(),
            };
            let requested_names = requested_names.clone();
            (
                options
                    .url
                    .unwrap_or_else(|| state.config.core.probe_url.clone()),
                sanitize_probe_timeout_ms(
                    options
                        .timeout_ms
                        .unwrap_or(state.config.core.probe_timeout_ms),
                ),
                sanitize_probe_concurrency(
                    options
                        .concurrency
                        .unwrap_or(state.config.core.probe_concurrency),
                ),
                state
                    .outbounds
                    .values()
                    .filter(|outbound| outbound.kind() != "reject")
                    .filter(|outbound| {
                        requested_names
                            .as_ref()
                            .map_or(true, |names| names.contains(outbound.name()))
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        let total = requested_names
            .as_ref()
            .map(|names| names.len() as u64)
            .unwrap_or(outbounds.len() as u64);
        let target = match ProbeTarget::from_url(&probe_url) {
            Ok(target) => target,
            Err(error) => {
                self.telemetry
                    .log("warn", format!("invalid probe url: {error:#}"))
                    .await;
                let mut results = outbounds
                    .into_iter()
                    .map(|outbound| ProbeResult {
                        name: outbound.name().to_string(),
                        kind: outbound.kind().to_string(),
                        success: false,
                        latency_ms: None,
                        failure_kind: Some("invalid_probe_url".to_string()),
                        error: Some(format!("invalid probe url: {error:#}")),
                    })
                    .collect::<Vec<_>>();
                results.extend(missing_probe_results(&results, requested_names.as_ref()));
                results.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
                publish_probe_progress(&progress, &results, total);
                return results;
            }
        };

        let mut jobs = JoinSet::new();
        let mut pending = outbounds.into_iter();
        for _ in 0..probe_concurrency {
            let Some(outbound) = pending.next() else {
                break;
            };
            spawn_probe_job(
                &mut jobs,
                outbound,
                target.clone(),
                probe_timeout_ms,
                self.telemetry.clone(),
                self.cancellation_token(),
            );
        }

        let mut results = Vec::new();
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(probe) => results.push(probe),
                Err(error) => results.push(ProbeResult {
                    name: "unknown".to_string(),
                    kind: "unknown".to_string(),
                    success: false,
                    latency_ms: None,
                    failure_kind: Some("probe_task_failed".to_string()),
                    error: Some(format!("probe task failed: {error}")),
                }),
            }
            if let Some(result) = results.last() {
                publish_probe_result_progress(&progress, results.len() as u64, total, &result.name);
            }
            if let Some(outbound) = pending.next() {
                spawn_probe_job(
                    &mut jobs,
                    outbound,
                    target.clone(),
                    probe_timeout_ms,
                    self.telemetry.clone(),
                    self.cancellation_token(),
                );
            }
        }
        for missing in missing_probe_results(&results, requested_names.as_ref()) {
            results.push(missing);
            if let Some(result) = results.last() {
                publish_probe_result_progress(&progress, results.len() as u64, total, &result.name);
            }
        }
        results.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
        results
    }

    pub(super) fn spawn_direct_probe(&self, destination: Destination) {
        let engine = self.smart_rules.clone();
        let cancellation = self.cancellation_token();
        let timeout_ms = self
            .state
            .read()
            .map(|state| {
                sanitize_probe_timeout_ms(state.config.smart_rules.direct_probe_timeout_ms)
            })
            .unwrap_or(500);
        tokio::spawn(async move {
            tokio::select! {
                _ = cancellation.cancelled() => {}
                outcome = smart::probe_direct_tcp(destination.clone(), timeout_ms) => {
                    engine.record_direct_probe_result(&destination, outcome);
                }
            }
        });
    }

    pub async fn background_probe_loop(self: Arc<Self>) {
        let interval_secs = self
            .state
            .read()
            .map(|state| state.config.core.probe_interval_secs)
            .unwrap_or(0);
        if interval_secs == 0 {
            return;
        }
        let cancellation = self.cancellation_token();

        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return,
                _ = sleep(Duration::from_secs(interval_secs)) => {}
            }
            let results = self.probe_all_outbounds().await;
            let ok_count = results.iter().filter(|item| item.success).count();
            self.telemetry
                .log(
                    "info",
                    format!(
                        "probe complete: {ok_count}/{} outbounds healthy",
                        results.len()
                    ),
                )
                .await;
        }
    }
}

fn publish_probe_progress(
    progress: &Option<tokio::sync::mpsc::UnboundedSender<ProbeProgress>>,
    results: &[ProbeResult],
    total: u64,
) {
    for (index, result) in results.iter().enumerate() {
        publish_probe_result_progress(progress, index as u64 + 1, total, &result.name);
    }
}

fn normalized_probe_names(names: Option<&Vec<String>>) -> Option<BTreeSet<String>> {
    names.map(|names| {
        names
            .iter()
            .map(|name| name.trim())
            .filter(|name| !name.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn missing_probe_results(
    results: &[ProbeResult],
    requested_names: Option<&BTreeSet<String>>,
) -> Vec<ProbeResult> {
    let Some(requested_names) = requested_names else {
        return Vec::new();
    };
    let returned = results
        .iter()
        .map(|result| result.name.as_str())
        .collect::<HashSet<_>>();
    requested_names
        .iter()
        .filter(|name| !returned.contains(name.as_str()))
        .map(|name| ProbeResult {
            name: name.clone(),
            kind: "unknown".to_string(),
            success: false,
            latency_ms: None,
            failure_kind: Some("outbound_not_found".to_string()),
            error: Some("outbound not found".to_string()),
        })
        .collect()
}

fn publish_probe_result_progress(
    progress: &Option<tokio::sync::mpsc::UnboundedSender<ProbeProgress>>,
    completed: u64,
    total: u64,
    name: &str,
) {
    if let Some(progress) = progress {
        let _ = progress.send(ProbeProgress {
            completed,
            total,
            name: name.to_string(),
        });
    }
}

fn sanitize_probe_timeout_ms(value: u64) -> u64 {
    value.clamp(1, 60_000)
}

fn sanitize_probe_concurrency(value: usize) -> usize {
    value.clamp(1, 1024)
}

fn spawn_probe_job(
    jobs: &mut JoinSet<ProbeResult>,
    outbound: Arc<dyn Outbound>,
    target: ProbeTarget,
    timeout_ms: u64,
    telemetry: Arc<Telemetry>,
    cancellation: CancellationToken,
) {
    jobs.spawn(
        async move { probe_one(outbound, target, timeout_ms, telemetry, cancellation).await },
    );
}

impl ProbeTarget {
    fn from_url(value: &str) -> anyhow::Result<Self> {
        let url = Url::parse(value)?;
        let use_tls = match url.scheme() {
            "http" => false,
            "https" => true,
            scheme => return Err(anyhow!("probe_url supports http/https, got {scheme}")),
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("probe_url is missing host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .unwrap_or(if use_tls { 443 } else { 80 });
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let request_target = match (url.path(), url.query()) {
            ("", None) => "/".to_string(),
            (path, None) => path.to_string(),
            (path, Some(query)) => format!("{path}?{query}"),
        };
        Ok(Self {
            destination: Destination::new(host.clone(), port),
            server_name: host,
            host_header,
            request_target,
            use_tls,
        })
    }

    fn http_request(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Supercore/{}\r\nConnection: close\r\n\r\n",
            self.request_target,
            self.host_header,
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes()
    }
}

async fn complete_probe_http<S>(stream: &mut S, target: &ProbeTarget) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&target.http_request()).await?;
    let mut data = [0u8; 512];
    let n = stream.read(&mut data).await?;
    if n == 0 {
        return Err(anyhow!("empty probe response"));
    }
    let status_line = std::str::from_utf8(&data[..n])
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("");
    if probe_status_is_healthy(status_line) {
        Ok(())
    } else {
        Err(anyhow!("unhealthy probe response: {status_line}"))
    }
}

async fn probe_one(
    outbound: Arc<dyn Outbound>,
    target: ProbeTarget,
    timeout_ms: u64,
    telemetry: Arc<Telemetry>,
    cancellation: CancellationToken,
) -> ProbeResult {
    let name = outbound.name().to_string();
    let kind = outbound.kind().to_string();
    let started = Instant::now();
    let result = tokio::select! {
        _ = cancellation.cancelled() => None,
        result = timeout(Duration::from_millis(timeout_ms), async {
        let mut context = DialContext::new(target.destination.clone(), timeout_ms);
        context.cancellation = cancellation.child_token();
        let mut stream = outbound.connect_context(&context).await?;
        if target.use_tls {
            let server_name = ServerName::try_from(target.server_name.clone())
                .map_err(|_| anyhow!("invalid probe TLS server name {}", target.server_name))?;
            let connector = TlsConnector::from(Arc::new(dns_tls_client_config()?));
            let mut tls_stream = connector.connect(server_name, stream).await?;
            complete_probe_http(&mut tls_stream, &target).await
        } else {
            complete_probe_http(&mut stream, &target).await
        }
        }) => Some(result),
    };

    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Some(Ok(Ok(()))) => {
            telemetry
                .record_outbound_result(name.clone(), kind.clone(), true, Some(latency_ms), None)
                .await;
            ProbeResult {
                name,
                kind,
                success: true,
                latency_ms: Some(latency_ms),
                failure_kind: None,
                error: None,
            }
        }
        Some(Ok(Err(error))) => {
            let error_msg = error.to_string();
            let failure_kind = error
                .downcast_ref::<OutboundError>()
                .map(|error| error.kind.probe_failure_kind().to_string())
                .unwrap_or_else(|| classify_probe_failure(&error_msg));
            telemetry
                .record_outbound_result(
                    name.clone(),
                    kind.clone(),
                    false,
                    Some(latency_ms),
                    Some(error_msg.clone()),
                )
                .await;
            ProbeResult {
                name,
                kind,
                success: false,
                latency_ms: Some(latency_ms),
                failure_kind: Some(failure_kind),
                error: Some(error_msg),
            }
        }
        Some(Err(_)) => {
            let error_msg = format!("probe timed out after {timeout_ms}ms");
            telemetry
                .record_outbound_result(
                    name.clone(),
                    kind.clone(),
                    false,
                    Some(timeout_ms),
                    Some(error_msg.clone()),
                )
                .await;
            ProbeResult {
                name,
                kind,
                success: false,
                latency_ms: Some(timeout_ms),
                failure_kind: Some("timeout".to_string()),
                error: Some(error_msg),
            }
        }
        None => {
            let error_msg = "probe cancelled".to_string();
            telemetry
                .record_outbound_result(
                    name.clone(),
                    kind.clone(),
                    false,
                    Some(latency_ms),
                    Some(error_msg.clone()),
                )
                .await;
            ProbeResult {
                name,
                kind,
                success: false,
                latency_ms: Some(latency_ms),
                failure_kind: Some("cancelled".to_string()),
                error: Some(error_msg),
            }
        }
    }
}

fn classify_probe_failure(error: &str) -> String {
    classify_message(error).probe_failure_kind().to_string()
}

fn probe_status_is_healthy(status_line: &str) -> bool {
    let mut parts = status_line.split_whitespace();
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.starts_with("HTTP/") {
        return false;
    }
    let Some(status) = parts.next() else {
        return false;
    };
    status
        .parse::<u16>()
        .map(|code| (200..400).contains(&code))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::config::SuperConfig;

    use super::{classify_probe_failure, ProbeOptions, Runtime};

    #[test]
    fn test_classify_probe_failure_protocol_not_implemented() {
        assert_eq!(
            classify_probe_failure(
                "protocol hysteria is recognized but native dialing is not implemented yet"
            ),
            "protocol_unsupported"
        );
    }

    #[test]
    fn test_classify_probe_failure_dns_lookup() {
        assert_eq!(
            classify_probe_failure("lookup example.com failed"),
            "dns_error"
        );
    }

    #[tokio::test]
    async fn invalid_probe_url_reports_every_requested_node_and_progress() {
        let runtime = Runtime::new(SuperConfig::default()).unwrap();
        let options = ProbeOptions {
            url: Some("://invalid".to_string()),
            timeout_ms: Some(500),
            concurrency: Some(2),
            names: Some(vec![
                "direct".to_string(),
                "missing".to_string(),
                "direct".to_string(),
                " ".to_string(),
            ]),
        };
        assert_eq!(runtime.probe_target_count(&options), 2);
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let results = runtime
            .probe_all_outbounds_with_progress(options, Some(progress_tx))
            .await;
        let mut progress = Vec::new();
        while let Some(item) = progress_rx.recv().await {
            progress.push(item);
        }

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "direct");
        assert_eq!(
            results[0].failure_kind.as_deref(),
            Some("invalid_probe_url")
        );
        assert_eq!(results[1].name, "missing");
        assert_eq!(
            results[1].failure_kind.as_deref(),
            Some("outbound_not_found")
        );
        assert_eq!(progress.len(), 2);
        assert_eq!(progress.last().unwrap().completed, 2);
        assert_eq!(progress.last().unwrap().total, 2);
    }
}
