use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{core::Runtime, geo, subscription_store::SubscriptionStore};

const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_FILES: usize = 10;
const DIAGNOSTIC_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, Serialize)]
pub(crate) struct DiagnosticExport {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    pub redacted: bool,
}

pub(crate) async fn build_doctor_report(runtime: &Runtime, redacted: bool) -> serde_json::Value {
    let config = runtime.config();
    let base_config = runtime.base_config();
    let store = SubscriptionStore::new(base_config.subscriptions.store_path.clone());
    let index = store.index();
    let subscriptions = index
        .as_ref()
        .map(|index| {
            index
                .subscriptions
                .iter()
                .map(|item| {
                    if redacted {
                        serde_json::json!({
                            "id_present": !item.id.is_empty(),
                            "node_count": item.node_count,
                            "supported_outbound_count": item.supported_outbound_count,
                            "unsupported_count": item.unsupported_count,
                            "has_url": item.url.is_some(),
                            "last_update_ok": item.last_update_error.is_none(),
                            "updated_at": item.updated_at,
                        })
                    } else {
                        serde_json::json!({
                            "id": item.id,
                            "name": item.name,
                            "node_count": item.node_count,
                            "supported_outbound_count": item.supported_outbound_count,
                            "unsupported_count": item.unsupported_count,
                            "has_url": item.url.is_some(),
                            "last_update_error": item.last_update_error,
                            "updated_at": item.updated_at,
                        })
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut provider_count = 0_usize;
    let mut provider_error_count = 0_usize;
    if let Ok(index) = index.as_ref() {
        for subscription in &index.subscriptions {
            if let Ok(document) = store.document(&subscription.id) {
                provider_count = provider_count
                    .saturating_add(document.proxy_providers.len())
                    .saturating_add(document.rule_providers.len());
                provider_error_count = provider_error_count.saturating_add(
                    document
                        .proxy_providers
                        .iter()
                        .filter(|provider| provider.last_error.is_some())
                        .count()
                        + document
                            .rule_providers
                            .iter()
                            .filter(|provider| provider.last_error.is_some())
                            .count(),
                );
            }
        }
    }

    let capabilities = runtime.outbound_capabilities();
    let unsupported_capabilities = capabilities
        .iter()
        .filter(|capability| !capability.tcp_supported && !capability.udp_supported)
        .count();
    let outbound_health = runtime.telemetry().outbound_health().await;
    let healthy_outbounds = outbound_health
        .iter()
        .filter(|item| item.successes > 0 && item.last_error.is_none())
        .count();
    let connections = runtime.telemetry().connections().await;
    let active_connections = connections
        .iter()
        .filter(|connection| connection.closed_at.is_none())
        .count();
    let logs = runtime.telemetry().logs().await;
    let log_levels = logs.iter().fold(BTreeMap::new(), |mut levels, log| {
        *levels.entry(log.level.clone()).or_insert(0_usize) += 1;
        levels
    });
    let geoip_path = geo::geoip_cache_path(&config.geo);
    let geosite_path = config.geo.cache_dir.join("geosite.dat");
    let active_subscription_present = index
        .as_ref()
        .ok()
        .and_then(|index| index.active_id.as_ref())
        .is_some();
    let checks = vec![
        doctor_check(
            "control_loopback",
            config.core.control_listen.ip().is_loopback(),
            "control API is restricted to loopback",
            "control API is not restricted to loopback",
        ),
        doctor_check(
            "default_outbound",
            config
                .outbounds
                .iter()
                .any(|outbound| outbound.name() == config.core.default_outbound),
            "default outbound exists",
            "default outbound is missing",
        ),
        doctor_check(
            "subscription_index",
            index.is_ok(),
            "subscription index is readable",
            "subscription index cannot be read",
        ),
        doctor_check(
            "active_subscription",
            !config.subscriptions.use_active || active_subscription_present,
            "active subscription state is valid",
            "active subscription is required but missing",
        ),
        doctor_check(
            "provider_cache",
            provider_error_count == 0,
            "provider caches have no recorded refresh errors",
            "one or more providers are using fallback data or failed to refresh",
        ),
        doctor_check(
            "geoip_cache",
            config.geo.geoip_url.is_none() || geoip_path.exists(),
            "GeoIP cache is available or not configured",
            "GeoIP source is configured but the cache is missing",
        ),
    ];

    serde_json::json!({
        "schema_version": 1,
        "generated_at": Utc::now(),
        "redacted": redacted,
        "version": {
            "core": env!("CARGO_PKG_VERSION"),
            "engine": "rust-native",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "runtime": {
            "summary": config.summary(),
            "mixed_listen": config.core.mixed_listen,
            "control_listen": config.core.control_listen,
            "default_outbound": if redacted { "<redacted>" } else { &config.core.default_outbound },
            "outbound_count": config.outbounds.len(),
            "rule_count": config.rules.len(),
            "rule_set_count": config.rule_sets.len(),
            "unsupported_capability_count": unsupported_capabilities,
            "tun_enabled": config.tun.enabled,
            "tun_stack": config.tun.stack,
            "dns_enabled": config.dns.enabled,
            "dns_enhanced_mode": config.dns.enhanced_mode,
        },
        "subscriptions": {
            "store_exists": store.root().exists(),
            "count": index.as_ref().map(|index| index.subscriptions.len()).unwrap_or(0),
            "active": active_subscription_present,
            "items": subscriptions,
        },
        "providers": {
            "count": provider_count,
            "error_count": provider_error_count,
        },
        "geo": {
            "geoip_configured": config.geo.geoip_url.is_some(),
            "geosite_configured": config.geo.geosite_url.is_some(),
            "geoip_cached": geoip_path.exists(),
            "geosite_cached": geosite_path.exists(),
        },
        "telemetry": {
            "traffic": runtime.telemetry().traffic(),
            "connection_count": connections.len(),
            "active_connection_count": active_connections,
            "health_record_count": outbound_health.len(),
            "healthy_outbound_count": healthy_outbounds,
            "log_count": logs.len(),
            "log_levels": log_levels,
            "raw_logs_included": false,
            "connection_destinations_included": false,
        },
        "capabilities": if redacted {
            serde_json::json!({
                "count": capabilities.len(),
                "unsupported_count": unsupported_capabilities,
            })
        } else {
            serde_json::json!(capabilities)
        },
        "checks": checks,
    })
}

pub(crate) async fn export_diagnostic_report(
    runtime: &Runtime,
    task_id: &str,
    cancellation: &CancellationToken,
) -> anyhow::Result<DiagnosticExport> {
    if cancellation.is_cancelled() {
        return Err(anyhow!("diagnostic export cancelled"));
    }
    let report = build_doctor_report(runtime, true).await;
    let encoded =
        serde_json::to_vec_pretty(&report).context("failed to encode diagnostic report")?;
    if encoded.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(anyhow!(
            "diagnostic report exceeds {} bytes",
            MAX_DIAGNOSTIC_BYTES
        ));
    }
    if cancellation.is_cancelled() {
        return Err(anyhow!("diagnostic export cancelled"));
    }

    let store = SubscriptionStore::new(runtime.base_config().subscriptions.store_path);
    let directory = store.root().join("diagnostics");
    fs::create_dir_all(&directory).with_context(|| {
        format!(
            "failed to create diagnostic directory {}",
            directory.display()
        )
    })?;
    let short_task_id = task_id.chars().take(8).collect::<String>();
    let path = directory.join(format!(
        "skyhook-diagnostic-{}-{short_task_id}.json",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
    fs::write(&temporary, &encoded)
        .with_context(|| format!("failed to write diagnostic report {}", temporary.display()))?;
    set_private_permissions(&temporary)?;
    if cancellation.is_cancelled() {
        let _ = fs::remove_file(&temporary);
        return Err(anyhow!("diagnostic export cancelled"));
    }
    fs::rename(&temporary, &path).with_context(|| {
        format!(
            "failed to replace diagnostic report {} with {}",
            path.display(),
            temporary.display()
        )
    })?;
    set_private_permissions(&path)?;
    prune_diagnostic_reports(&directory, &path);

    let sha256 = format!("{:x}", Sha256::digest(&encoded));
    Ok(DiagnosticExport {
        path,
        bytes: encoded.len() as u64,
        sha256,
        redacted: true,
    })
}

fn doctor_check(
    id: &'static str,
    passed: bool,
    success_message: &'static str,
    failure_message: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "status": if passed { "passed" } else { "warning" },
        "message": if passed { success_message } else { failure_message },
    })
}

fn set_private_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure diagnostic report {}", path.display()))?;
    }
    Ok(())
}

fn prune_diagnostic_reports(directory: &Path, preserve: &Path) {
    let now = SystemTime::now();
    let mut files = fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if path == preserve || path.extension().and_then(|item| item.to_str()) != Some("json") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((path, modified))
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|(_, modified)| *modified);

    for (path, modified) in &files {
        if now
            .duration_since(*modified)
            .is_ok_and(|age| age > DIAGNOSTIC_RETENTION)
        {
            let _ = fs::remove_file(path);
        }
    }
    let mut remaining = files
        .into_iter()
        .filter(|(path, _)| path.exists())
        .collect::<Vec<_>>();
    remaining.sort_by_key(|(_, modified)| *modified);
    let remove_count = remaining.len().saturating_sub(MAX_DIAGNOSTIC_FILES - 1);
    for (path, _) in remaining.into_iter().take(remove_count) {
        let _ = fs::remove_file(path);
    }
}
