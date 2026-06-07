use std::{fs, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context};
use serde::Serialize;

use crate::config::{GeoConfig, SuperConfig};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GeoUpdateSummary {
    pub kind: String,
    pub url: String,
    pub path: PathBuf,
    pub updated: bool,
    pub bytes: u64,
    pub error: Option<String>,
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
    if !config.auto_update {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&config.cache_dir).with_context(|| {
        format!(
            "failed to create geo cache dir {}",
            config.cache_dir.display()
        )
    })?;

    let mut summaries = Vec::new();
    if let Some(url) = config.geoip_url.as_deref().filter(|url| !url.is_empty()) {
        summaries.push(
            download_geo_asset(
                "geoip",
                url,
                geoip_cache_path(config),
                config.update_timeout_secs,
            )
            .await,
        );
    }
    if let Some(url) = config.geosite_url.as_deref().filter(|url| !url.is_empty()) {
        summaries.push(
            download_geo_asset(
                "geosite",
                url,
                geosite_cache_path(config),
                config.update_timeout_secs,
            )
            .await,
        );
    }
    Ok(summaries)
}

fn geoip_cache_path(config: &GeoConfig) -> PathBuf {
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
) -> GeoUpdateSummary {
    match download_geo_asset_inner(url, &path, timeout_secs).await {
        Ok((updated, bytes)) => GeoUpdateSummary {
            kind: kind.to_string(),
            url: url.to_string(),
            path,
            updated,
            bytes,
            error: None,
        },
        Err(error) => GeoUpdateSummary {
            kind: kind.to_string(),
            url: url.to_string(),
            path,
            updated: false,
            bytes: 0,
            error: Some(error.to_string()),
        },
    }
}

async fn download_geo_asset_inner(
    url: &str,
    path: &PathBuf,
    timeout_secs: u64,
) -> anyhow::Result<(bool, u64)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .user_agent("Skyhook/0.1")
        .build()
        .context("failed to build geo download client")?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to download geo asset {url}"))?
        .error_for_status()
        .with_context(|| format!("geo asset endpoint returned an error for {url}"))?;
    let bytes = response.bytes().await.context("failed to read geo asset")?;
    if bytes.is_empty() {
        return Err(anyhow!("downloaded geo asset is empty"));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create geo cache dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("download");
    fs::write(&tmp, &bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    let updated = fs::read(path)
        .map(|existing| existing != bytes.as_ref())
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
