use std::{fs, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::{GeoConfig, SuperConfig};

const MAX_GEO_ASSET_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GeoUpdateSummary {
    pub kind: String,
    pub source: String,
    pub path: PathBuf,
    pub updated: bool,
    pub bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GeoUpdateProgress {
    pub completed: u64,
    pub total: u64,
    pub kind: String,
}

pub async fn prepare_geo_assets(mut config: SuperConfig) -> SuperConfig {
    let summaries = match update_geo_assets(&config.geo).await {
        Ok(summaries) => summaries,
        Err(error) => {
            tracing::warn!(error = %error, "geo asset update failed");
            Vec::new()
        }
    };

    if config.geoip_database.is_none() {
        if let Some(summary) = summaries
            .iter()
            .find(|summary| summary.kind == "geoip" && summary.error.is_none())
        {
            config.geoip_database = Some(summary.path.clone());
        } else {
            let cached = geoip_cache_path(&config.geo);
            if cached.exists() {
                config.geoip_database = Some(cached);
            }
        }
    }

    config
}

pub async fn update_geo_assets(config: &GeoConfig) -> anyhow::Result<Vec<GeoUpdateSummary>> {
    update_geo_assets_with_progress(config, false, CancellationToken::new(), None).await
}

pub async fn update_geo_assets_with_progress(
    config: &GeoConfig,
    force: bool,
    cancellation: CancellationToken,
    progress: Option<tokio::sync::mpsc::UnboundedSender<GeoUpdateProgress>>,
) -> anyhow::Result<Vec<GeoUpdateSummary>> {
    if !force && !config.auto_update {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&config.cache_dir).with_context(|| {
        format!(
            "failed to create geo cache dir {}",
            config.cache_dir.display()
        )
    })?;

    let total = [config.geoip_url.as_deref(), config.geosite_url.as_deref()]
        .into_iter()
        .flatten()
        .filter(|url| !url.trim().is_empty())
        .count() as u64;
    let mut summaries = Vec::new();
    if let Some(url) = config.geoip_url.as_deref().filter(|url| !url.is_empty()) {
        summaries.push(
            download_geo_asset(
                "geoip",
                url,
                geoip_cache_path(config),
                config.update_timeout_secs,
                cancellation.clone(),
            )
            .await?,
        );
        if let Some(progress) = progress.as_ref() {
            let _ = progress.send(GeoUpdateProgress {
                completed: summaries.len() as u64,
                total,
                kind: "geoip".to_string(),
            });
        }
    }
    if let Some(url) = config.geosite_url.as_deref().filter(|url| !url.is_empty()) {
        summaries.push(
            download_geo_asset(
                "geosite",
                url,
                geosite_cache_path(config),
                config.update_timeout_secs,
                cancellation,
            )
            .await?,
        );
        if let Some(progress) = progress.as_ref() {
            let _ = progress.send(GeoUpdateProgress {
                completed: summaries.len() as u64,
                total,
                kind: "geosite".to_string(),
            });
        }
    }
    Ok(summaries)
}

pub fn geoip_cache_path(config: &GeoConfig) -> PathBuf {
    config.cache_dir.join("geoip.mmdb")
}

fn geosite_cache_path(config: &GeoConfig) -> PathBuf {
    config.cache_dir.join("geosite.dat")
}

async fn download_geo_asset(
    kind: &str,
    url: &str,
    path: PathBuf,
    timeout_secs: u64,
    cancellation: CancellationToken,
) -> anyhow::Result<GeoUpdateSummary> {
    let source = geo_source_label(url);
    let cancellation_state = cancellation.clone();
    let summary = match download_geo_asset_inner(url, &path, timeout_secs, cancellation).await {
        Ok((updated, bytes)) => GeoUpdateSummary {
            kind: kind.to_string(),
            source,
            path,
            updated,
            bytes,
            error: None,
        },
        Err(error) if cancellation_state.is_cancelled() => return Err(error),
        Err(error) => GeoUpdateSummary {
            kind: kind.to_string(),
            source,
            path,
            updated: false,
            bytes: 0,
            error: Some(error.to_string()),
        },
    };
    Ok(summary)
}

async fn download_geo_asset_inner(
    url: &str,
    path: &PathBuf,
    timeout_secs: u64,
    cancellation: CancellationToken,
) -> anyhow::Result<(bool, u64)> {
    let parsed = url::Url::parse(url).context("geo asset url is invalid")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("geo asset url must use http or https"));
    }
    let source = geo_source_label(url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .user_agent("Supercore/0.1")
        .no_proxy()
        .build()
        .context("failed to build geo download client")?;
    let response = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("geo update cancelled")),
        response = client.get(url).send() => {
            response.with_context(|| format!("failed to download geo asset from {source}"))?
        }
    };
    let mut response = response
        .error_for_status()
        .with_context(|| format!("geo asset endpoint returned an error from {source}"))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_GEO_ASSET_BYTES as u64)
    {
        return Err(anyhow!("geo asset exceeds {} bytes", MAX_GEO_ASSET_BYTES));
    }
    let mut bytes = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => return Err(anyhow!("geo update cancelled")),
            chunk = response.chunk() => {
                chunk.with_context(|| format!("failed to read geo asset from {source}"))?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len().saturating_add(chunk.len()) > MAX_GEO_ASSET_BYTES {
            return Err(anyhow!("geo asset exceeds {} bytes", MAX_GEO_ASSET_BYTES));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(anyhow!("downloaded geo asset is empty"));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create geo cache dir {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("download-{}", Uuid::new_v4().simple()));
    fs::write(&tmp, &bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    let updated = fs::read(path)
        .map(|existing| existing != bytes)
        .unwrap_or(true);
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to replace geo cache {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok((updated, bytes.len() as u64))
}

fn geo_source_label(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            })
        })
        .unwrap_or_else(|| "<redacted-geo-source>".to_string())
}
