use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::{fs as async_fs, sync::Semaphore, task::JoinSet, time::sleep};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    config::{
        OutboundConfig, RouteRule, RuleSetBehavior, RuleSetConfig, RuleTarget, SubscriptionConfig,
        SuperConfig,
    },
    subscription::{
        parse_rule_provider_rules, parse_subscription, SubscriptionDocument, SubscriptionNode,
    },
};

pub const DEFAULT_STORE_DIR: &str = "supercore-subscriptions";
const MAX_PROVIDER_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_SUBSCRIPTION_BODY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionIndex {
    pub version: u32,
    #[serde(default)]
    pub active_id: Option<String>,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    pub source_format: String,
    pub node_count: usize,
    pub supported_outbound_count: usize,
    pub unsupported_count: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub last_update_error: Option<String>,
    #[serde(default)]
    pub traffic_upload_total: u64,
    #[serde(default)]
    pub traffic_download_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionImportResult {
    pub meta: SubscriptionMeta,
    pub active_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionUpdateSummary {
    pub id: String,
    pub name: String,
    pub updated: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SubscriptionUpdateProgress {
    pub completed: u64,
    pub total: u64,
    pub id: String,
    pub name: String,
    pub updated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRefreshIssue {
    pub provider_type: String,
    pub name: String,
    pub message: String,
    pub used_fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRefreshSummary {
    pub id: String,
    pub name: String,
    pub committed: bool,
    pub updated: bool,
    pub provider_count: usize,
    pub refreshed_count: usize,
    pub fallback_count: usize,
    pub node_count: usize,
    pub rule_count: usize,
    #[serde(default)]
    pub issues: Vec<ProviderRefreshIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionUpdateOptions {
    pub timeout_secs: u64,
    pub retries: u8,
    pub concurrency: usize,
}

#[derive(Debug, Clone)]
pub struct SubscriptionStore {
    root: PathBuf,
}

#[derive(Debug, Default)]
struct ProviderRefreshStats {
    provider_count: usize,
    refreshed_count: usize,
    fallback_count: usize,
    issues: Vec<ProviderRefreshIssue>,
}

impl Default for SubscriptionIndex {
    fn default() -> Self {
        Self {
            version: 1,
            active_id: None,
            subscriptions: Vec::new(),
        }
    }
}

impl SubscriptionStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn index(&self) -> anyhow::Result<SubscriptionIndex> {
        self.load_index()
    }

    pub fn import_text(
        &self,
        name: Option<String>,
        url: Option<String>,
        text: &str,
        switch: bool,
    ) -> anyhow::Result<SubscriptionImportResult> {
        self.import_text_with_id(None, name, url, text, switch)
    }

    pub fn import_text_with_id(
        &self,
        id: Option<String>,
        name: Option<String>,
        url: Option<String>,
        text: &str,
        switch: bool,
    ) -> anyhow::Result<SubscriptionImportResult> {
        let mut document = parse_subscription(text)?;
        let now = Utc::now();
        let mut index = self.load_index()?;
        let id = id
            .filter(|item| !item.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
        self.resolve_proxy_providers(&id, &mut document)?;

        if let Some(position) = index.subscriptions.iter().position(|item| item.id == id) {
            let previous = index.subscriptions[position].clone();
            let mut meta = meta_from_document(
                previous.id,
                name.filter(|item| !item.trim().is_empty())
                    .unwrap_or(previous.name),
                url.or(previous.url),
                &document,
                previous.created_at,
                now,
                None,
            );
            meta.traffic_upload_total = previous.traffic_upload_total;
            meta.traffic_download_total = previous.traffic_download_total;

            self.resolve_rule_providers(&meta.id, &mut document)?;
            self.write_subscription_files(&meta, text, &document)?;
            let active_changed = index.active_id.is_none() || switch;
            if active_changed {
                index.active_id = Some(meta.id.clone());
            }
            index.subscriptions[position] = meta.clone();
            self.save_index(&index)?;
            return Ok(SubscriptionImportResult {
                meta,
                active_changed,
            });
        }

        let name = name
            .filter(|item| !item.trim().is_empty())
            .unwrap_or_else(|| inferred_name(url.as_deref(), &document, &id));
        let meta = meta_from_document(id, name, url, &document, now, now, None);

        self.resolve_rule_providers(&meta.id, &mut document)?;
        self.write_subscription_files(&meta, text, &document)?;
        let active_changed = index.active_id.is_none() || switch;
        if active_changed {
            index.active_id = Some(meta.id.clone());
        }
        index.subscriptions.push(meta.clone());
        self.save_index(&index)?;

        Ok(SubscriptionImportResult {
            meta,
            active_changed,
        })
    }

    pub async fn import_text_with_id_async(
        &self,
        id: Option<String>,
        name: Option<String>,
        url: Option<String>,
        text: &str,
        switch: bool,
        timeout_secs: u64,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<SubscriptionImportResult> {
        let id = id
            .filter(|item| !item.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
        let previous_document = self.document(&id).ok();
        let mut document = parse_subscription(text)?;
        let client = provider_http_client(timeout_secs)?;
        let mut stats = ProviderRefreshStats::default();
        self.resolve_proxy_providers_async(
            &id,
            &mut document,
            previous_document.as_ref(),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        self.resolve_rule_providers_async(
            &id,
            &mut document,
            previous_document.as_ref(),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        if cancellation.is_cancelled() {
            return Err(anyhow!("subscription import cancelled"));
        }
        self.commit_import_document(id, name, url, text, document, switch)
    }

    pub fn replace_text(&self, id: &str, text: &str) -> anyhow::Result<SubscriptionMeta> {
        let mut document = parse_subscription(text)?;
        self.resolve_proxy_providers(id, &mut document)?;
        self.resolve_rule_providers(id, &mut document)?;
        self.replace_document(id, text, document)
    }

    pub async fn replace_text_async(
        &self,
        id: &str,
        text: &str,
        timeout_secs: u64,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<SubscriptionMeta> {
        let previous_document = self.document(id)?;
        let mut document = parse_subscription(text)?;
        let client = provider_http_client(timeout_secs)?;
        let mut stats = ProviderRefreshStats::default();
        self.resolve_proxy_providers_async(
            id,
            &mut document,
            Some(&previous_document),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        self.resolve_rule_providers_async(
            id,
            &mut document,
            Some(&previous_document),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        if cancellation.is_cancelled() {
            return Err(anyhow!("subscription update cancelled"));
        }
        self.replace_document(id, text, document)
    }

    pub async fn refresh_providers(
        &self,
        id: &str,
        timeout_secs: u64,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<ProviderRefreshSummary> {
        let previous_meta = self
            .index()?
            .subscriptions
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        let previous_document = self.document(id)?;
        let source_path = self.subscription_dir(id).join("source.txt");
        let source = tokio::select! {
            _ = cancellation.cancelled() => return Err(anyhow!("provider refresh cancelled")),
            source = async_fs::read_to_string(&source_path) => {
                source.with_context(|| {
                    format!("failed to read subscription source {}", source_path.display())
                })?
            }
        };
        let mut document = parse_subscription(&source)?;
        let client = provider_http_client(timeout_secs)?;
        let mut stats = ProviderRefreshStats::default();

        self.resolve_proxy_providers_async(
            id,
            &mut document,
            Some(&previous_document),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        self.resolve_rule_providers_async(
            id,
            &mut document,
            Some(&previous_document),
            &client,
            cancellation,
            &mut stats,
        )
        .await?;
        if cancellation.is_cancelled() {
            return Err(anyhow!("provider refresh cancelled"));
        }

        let meta = self.replace_document(id, &source, document.clone())?;
        Ok(ProviderRefreshSummary {
            id: meta.id,
            name: previous_meta.name,
            committed: true,
            updated: stats.refreshed_count > 0,
            provider_count: stats.provider_count,
            refreshed_count: stats.refreshed_count,
            fallback_count: stats.fallback_count,
            node_count: document.nodes.len(),
            rule_count: document
                .rule_providers
                .iter()
                .map(|provider| provider.rules.len())
                .sum(),
            issues: stats.issues,
        })
    }

    pub fn mark_update_error(&self, id: &str, error: impl Into<String>) -> anyhow::Result<()> {
        let mut index = self.load_index()?;
        let item = index
            .subscriptions
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        item.last_update_error = Some(error.into());
        item.updated_at = Utc::now();
        self.save_index(&index)
    }

    pub fn set_active(&self, id: &str) -> anyhow::Result<SubscriptionMeta> {
        let mut index = self.load_index()?;
        let meta = index
            .subscriptions
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        index.active_id = Some(meta.id.clone());
        self.save_index(&index)?;
        Ok(meta)
    }

    pub fn add_traffic(
        &self,
        id: &str,
        uploaded: u64,
        downloaded: u64,
    ) -> anyhow::Result<Option<SubscriptionMeta>> {
        if uploaded == 0 && downloaded == 0 {
            return Ok(None);
        }
        let mut index = self.load_index()?;
        let Some(item) = index.subscriptions.iter_mut().find(|item| item.id == id) else {
            return Ok(None);
        };
        item.traffic_upload_total = item.traffic_upload_total.saturating_add(uploaded);
        item.traffic_download_total = item.traffic_download_total.saturating_add(downloaded);
        let meta = item.clone();
        self.save_index(&index)?;
        write_json_atomic(&self.subscription_dir(id).join("meta.json"), &meta)?;
        Ok(Some(meta))
    }

    pub fn active_meta(&self) -> anyhow::Result<Option<SubscriptionMeta>> {
        let index = self.load_index()?;
        let Some(active_id) = index.active_id else {
            return Ok(None);
        };
        Ok(index
            .subscriptions
            .into_iter()
            .find(|item| item.id == active_id))
    }

    pub fn active_document(&self) -> anyhow::Result<Option<SubscriptionDocument>> {
        let Some(meta) = self.active_meta()? else {
            return Ok(None);
        };
        self.document(&meta.id).map(Some)
    }

    pub fn document(&self, id: &str) -> anyhow::Result<SubscriptionDocument> {
        let path = self.subscription_dir(id).join("document.json");
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read subscription document {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("failed to parse subscription document {}", path.display()))
    }

    pub fn active_runtime_config(
        &self,
        base: SuperConfig,
        use_first_node_as_default: bool,
    ) -> anyhow::Result<SuperConfig> {
        let Some(document) = self.active_document()? else {
            return Ok(base);
        };
        Ok(runtime_config_from_document(
            base,
            &document,
            use_first_node_as_default,
        ))
    }

    pub async fn update_all_from_urls(&self) -> anyhow::Result<Vec<SubscriptionUpdateSummary>> {
        self.update_all_from_urls_with(SubscriptionUpdateOptions::default())
            .await
    }

    pub async fn update_from_url_with(
        &self,
        id: &str,
        options: SubscriptionUpdateOptions,
        cancellation: &CancellationToken,
    ) -> anyhow::Result<SubscriptionUpdateSummary> {
        let meta = self
            .index()?
            .subscriptions
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        let Some(url) = meta.url.clone() else {
            return Ok(SubscriptionUpdateSummary {
                id: meta.id,
                name: meta.name,
                updated: false,
                error: Some("subscription has no url".to_string()),
            });
        };
        let result: anyhow::Result<()> = async {
            let text = fetch_subscription_url_with_options(&url, options, cancellation).await?;
            self.replace_text_async(&meta.id, &text, options.timeout_secs, cancellation)
                .await?;
            Ok(())
        }
        .await;
        Ok(match result {
            Ok(()) => SubscriptionUpdateSummary {
                id: meta.id,
                name: meta.name,
                updated: true,
                error: None,
            },
            Err(_error) if cancellation.is_cancelled() => {
                return Err(anyhow!("subscription update cancelled"));
            }
            Err(error) => {
                let message = error.to_string();
                let _ = self.mark_update_error(&meta.id, message.clone());
                SubscriptionUpdateSummary {
                    id: meta.id,
                    name: meta.name,
                    updated: false,
                    error: Some(message),
                }
            }
        })
    }

    pub async fn update_all_from_urls_with(
        &self,
        options: SubscriptionUpdateOptions,
    ) -> anyhow::Result<Vec<SubscriptionUpdateSummary>> {
        self.update_all_from_urls_with_progress(options, CancellationToken::new(), None)
            .await
    }

    pub async fn update_all_from_urls_with_progress(
        &self,
        options: SubscriptionUpdateOptions,
        cancellation: CancellationToken,
        progress: Option<tokio::sync::mpsc::UnboundedSender<SubscriptionUpdateProgress>>,
    ) -> anyhow::Result<Vec<SubscriptionUpdateSummary>> {
        let index = self.index()?;
        let total = index.subscriptions.len() as u64;
        let semaphore = Arc::new(Semaphore::new(options.concurrency.max(1)));
        let mut jobs = JoinSet::new();

        for meta in index.subscriptions {
            let Some(url) = meta.url.clone() else {
                let summary = SubscriptionUpdateSummary {
                    id: meta.id,
                    name: meta.name,
                    updated: false,
                    error: Some("subscription has no url".to_string()),
                };
                jobs.spawn(async move { summary });
                continue;
            };

            let store = self.clone();
            let semaphore = semaphore.clone();
            let cancellation = cancellation.clone();
            jobs.spawn(async move {
                let permit = tokio::select! {
                    _ = cancellation.cancelled() => {
                        return SubscriptionUpdateSummary {
                            id: meta.id,
                            name: meta.name,
                            updated: false,
                            error: Some("subscription update cancelled".to_string()),
                        };
                    }
                    permit = semaphore.acquire_owned() => permit,
                };
                let _permit = match permit {
                    Ok(permit) => permit,
                    Err(error) => {
                        return SubscriptionUpdateSummary {
                            id: meta.id,
                            name: meta.name,
                            updated: false,
                            error: Some(format!("subscription update scheduler closed: {error}")),
                        };
                    }
                };
                let result: anyhow::Result<()> = async {
                    let text =
                        fetch_subscription_url_with_options(&url, options, &cancellation).await?;
                    store
                        .replace_text_async(&meta.id, &text, options.timeout_secs, &cancellation)
                        .await?;
                    Ok(())
                }
                .await;

                match result {
                    Ok(()) => SubscriptionUpdateSummary {
                        id: meta.id,
                        name: meta.name,
                        updated: true,
                        error: None,
                    },
                    Err(error) => {
                        let message = error.to_string();
                        let _ = store.mark_update_error(&meta.id, message.clone());
                        SubscriptionUpdateSummary {
                            id: meta.id,
                            name: meta.name,
                            updated: false,
                            error: Some(message),
                        }
                    }
                }
            });
        }

        let mut summaries = Vec::new();
        let mut completed = 0_u64;
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    jobs.abort_all();
                    while jobs.join_next().await.is_some() {}
                    return Err(anyhow!("subscription update cancelled"));
                }
                result = jobs.join_next() => {
                    let Some(result) = result else {
                        break;
                    };
                    let summary = match result {
                        Ok(summary) => summary,
                        Err(error) => SubscriptionUpdateSummary {
                            id: "unknown".to_string(),
                            name: "unknown".to_string(),
                            updated: false,
                            error: Some(format!("subscription update task failed: {error}")),
                        },
                    };
                    completed = completed.saturating_add(1);
                    if let Some(progress) = progress.as_ref() {
                        let _ = progress.send(SubscriptionUpdateProgress {
                            completed,
                            total,
                            id: summary.id.clone(),
                            name: summary.name.clone(),
                            updated: summary.updated,
                        });
                    }
                    summaries.push(summary);
                }
            }
        }
        summaries.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name).then_with(|| lhs.id.cmp(&rhs.id)));
        Ok(summaries)
    }

    fn load_index(&self) -> anyhow::Result<SubscriptionIndex> {
        let path = self.index_path();
        match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("failed to parse subscription index {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(SubscriptionIndex::default())
            }
            Err(error) => Err(error)
                .with_context(|| format!("failed to read subscription index {}", path.display())),
        }
    }

    fn save_index(&self, index: &SubscriptionIndex) -> anyhow::Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("failed to create store {}", self.root.display()))?;
        write_json_atomic(&self.index_path(), index)
    }

    fn write_subscription_files(
        &self,
        meta: &SubscriptionMeta,
        source: &str,
        document: &SubscriptionDocument,
    ) -> anyhow::Result<()> {
        let dir = self.subscription_dir(&meta.id);
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create subscription dir {}", dir.display()))?;
        fs::write(dir.join("source.txt"), source)
            .with_context(|| format!("failed to write subscription source {}", meta.id))?;
        write_json_atomic(&dir.join("meta.json"), meta)?;
        write_json_atomic(&dir.join("document.json"), document)?;
        Ok(())
    }

    fn replace_document(
        &self,
        id: &str,
        source: &str,
        document: SubscriptionDocument,
    ) -> anyhow::Result<SubscriptionMeta> {
        let mut index = self.load_index()?;
        let position = index
            .subscriptions
            .iter()
            .position(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        let previous = index.subscriptions[position].clone();
        let mut meta = meta_from_document(
            previous.id,
            previous.name,
            previous.url,
            &document,
            previous.created_at,
            Utc::now(),
            None,
        );
        meta.traffic_upload_total = previous.traffic_upload_total;
        meta.traffic_download_total = previous.traffic_download_total;
        self.write_subscription_files(&meta, source, &document)?;
        index.subscriptions[position] = meta.clone();
        self.save_index(&index)?;
        Ok(meta)
    }

    fn commit_import_document(
        &self,
        id: String,
        name: Option<String>,
        url: Option<String>,
        source: &str,
        document: SubscriptionDocument,
        switch: bool,
    ) -> anyhow::Result<SubscriptionImportResult> {
        let now = Utc::now();
        let mut index = self.load_index()?;
        if let Some(position) = index.subscriptions.iter().position(|item| item.id == id) {
            let previous = index.subscriptions[position].clone();
            let mut meta = meta_from_document(
                previous.id,
                name.filter(|item| !item.trim().is_empty())
                    .unwrap_or(previous.name),
                url.or(previous.url),
                &document,
                previous.created_at,
                now,
                None,
            );
            meta.traffic_upload_total = previous.traffic_upload_total;
            meta.traffic_download_total = previous.traffic_download_total;
            self.write_subscription_files(&meta, source, &document)?;
            let active_changed = index.active_id.is_none() || switch;
            if active_changed {
                index.active_id = Some(meta.id.clone());
            }
            index.subscriptions[position] = meta.clone();
            self.save_index(&index)?;
            return Ok(SubscriptionImportResult {
                meta,
                active_changed,
            });
        }

        let name = name
            .filter(|item| !item.trim().is_empty())
            .unwrap_or_else(|| inferred_name(url.as_deref(), &document, &id));
        let meta = meta_from_document(id, name, url, &document, now, now, None);
        self.write_subscription_files(&meta, source, &document)?;
        let active_changed = index.active_id.is_none() || switch;
        if active_changed {
            index.active_id = Some(meta.id.clone());
        }
        index.subscriptions.push(meta.clone());
        self.save_index(&index)?;
        Ok(SubscriptionImportResult {
            meta,
            active_changed,
        })
    }

    fn resolve_proxy_providers(
        &self,
        id: &str,
        document: &mut SubscriptionDocument,
    ) -> anyhow::Result<()> {
        if document.proxy_providers.is_empty() {
            return Ok(());
        }
        let provider_dir = self.subscription_dir(id).join("proxy-providers");
        fs::create_dir_all(&provider_dir).with_context(|| {
            format!(
                "failed to create proxy provider cache dir {}",
                provider_dir.display()
            )
        })?;

        let mut seen_names = document
            .nodes
            .iter()
            .map(|node| node.name.clone())
            .collect::<HashSet<_>>();
        let mut resolved_nodes = Vec::<SubscriptionNode>::new();

        for provider in &mut document.proxy_providers {
            let cache_path = provider_dir.join(format!("{}.txt", safe_file_name(&provider.name)));
            if provider.nodes.is_empty() {
                match load_proxy_provider_text(
                    self.root(),
                    provider.path.as_deref(),
                    provider.url.as_deref(),
                ) {
                    Ok(text) => match parse_proxy_provider_nodes(&text) {
                        Ok(nodes) => {
                            provider.nodes = nodes;
                            fs::write(&cache_path, text).with_context(|| {
                                format!(
                                    "failed to write proxy provider cache {}",
                                    cache_path.display()
                                )
                            })?;
                            provider.cache_path = Some(cache_path.display().to_string());
                            provider.last_error = None;
                        }
                        Err(error) => {
                            provider.last_error = Some(error.to_string());
                        }
                    },
                    Err(error) => {
                        if cache_path.exists() {
                            if let Ok(cached_text) = fs::read_to_string(&cache_path) {
                                if let Ok(cached_nodes) = parse_proxy_provider_nodes(&cached_text) {
                                    if !cached_nodes.is_empty() {
                                        provider.nodes = cached_nodes;
                                        provider.cache_path =
                                            Some(cache_path.display().to_string());
                                        provider.last_error =
                                            Some(format!("fetch failed, using cache: {}", error));
                                        continue;
                                    }
                                }
                            }
                        }
                        provider.last_error = Some(error.to_string());
                    }
                }
            }

            for node in &provider.nodes {
                if seen_names.insert(node.name.clone()) {
                    resolved_nodes.push(node.clone());
                }
            }
        }

        document.nodes.extend(resolved_nodes);
        Ok(())
    }

    fn resolve_rule_providers(
        &self,
        id: &str,
        document: &mut SubscriptionDocument,
    ) -> anyhow::Result<()> {
        if document.rule_providers.is_empty() {
            return Ok(());
        }
        let provider_dir = self.subscription_dir(id).join("rule-providers");
        fs::create_dir_all(&provider_dir).with_context(|| {
            format!(
                "failed to create rule provider cache dir {}",
                provider_dir.display()
            )
        })?;
        for provider in &mut document.rule_providers {
            let cache_path = provider_dir.join(format!("{}.txt", safe_file_name(&provider.name)));
            if provider.rules.is_empty() {
                match load_rule_provider_text(
                    self.root(),
                    provider.path.as_deref(),
                    provider.url.as_deref(),
                ) {
                    Ok(text) => {
                        provider.rules = parse_rule_provider_rules(&text);
                        fs::write(&cache_path, text).with_context(|| {
                            format!(
                                "failed to write rule provider cache {}",
                                cache_path.display()
                            )
                        })?;
                        provider.cache_path = Some(cache_path.display().to_string());
                        provider.last_error = None;
                    }
                    Err(error) => {
                        if cache_path.exists() {
                            if let Ok(cached_text) = fs::read_to_string(&cache_path) {
                                let cached_rules = parse_rule_provider_rules(&cached_text);
                                if !cached_rules.is_empty() {
                                    provider.rules = cached_rules;
                                    provider.cache_path = Some(cache_path.display().to_string());
                                    provider.last_error =
                                        Some(format!("fetch failed, using cache: {}", error));
                                    continue;
                                }
                            }
                        }
                        provider.last_error = Some(error.to_string());
                    }
                }
            } else {
                fs::write(&cache_path, provider.rules.join("\n")).with_context(|| {
                    format!(
                        "failed to write rule provider cache {}",
                        cache_path.display()
                    )
                })?;
                provider.cache_path = Some(cache_path.display().to_string());
                provider.last_error = None;
            }
        }
        Ok(())
    }

    async fn resolve_proxy_providers_async(
        &self,
        id: &str,
        document: &mut SubscriptionDocument,
        previous_document: Option<&SubscriptionDocument>,
        client: &reqwest::Client,
        cancellation: &CancellationToken,
        stats: &mut ProviderRefreshStats,
    ) -> anyhow::Result<()> {
        if document.proxy_providers.is_empty() {
            return Ok(());
        }
        let provider_dir = self.subscription_dir(id).join("proxy-providers");
        async_fs::create_dir_all(&provider_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create proxy provider cache dir {}",
                    provider_dir.display()
                )
            })?;
        let mut seen_names = document
            .nodes
            .iter()
            .map(|node| node.name.clone())
            .collect::<HashSet<_>>();
        let mut resolved_nodes = Vec::<SubscriptionNode>::new();

        for provider in &mut document.proxy_providers {
            if cancellation.is_cancelled() {
                return Err(anyhow!("provider refresh cancelled"));
            }
            stats.provider_count += 1;
            let cache_path = provider_dir.join(format!("{}.txt", safe_file_name(&provider.name)));
            if provider.nodes.is_empty() {
                let loaded = load_provider_text_async(
                    "proxy provider",
                    self.root(),
                    provider.path.as_deref(),
                    provider.url.as_deref(),
                    client,
                    cancellation,
                )
                .await
                .and_then(|text| {
                    let nodes = parse_proxy_provider_nodes(&text)?;
                    if nodes.is_empty() {
                        return Err(anyhow!("proxy provider payload contains no nodes"));
                    }
                    Ok((text, nodes))
                });
                match loaded {
                    Ok((text, nodes)) => {
                        write_text_atomic_async(&cache_path, &text).await?;
                        provider.nodes = nodes;
                        provider.cache_path = Some(cache_path.display().to_string());
                        provider.last_error = None;
                        stats.refreshed_count += 1;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let fallback =
                            cached_proxy_provider_nodes(&cache_path).await.or_else(|| {
                                previous_document
                                    .into_iter()
                                    .flat_map(|document| document.proxy_providers.iter())
                                    .find(|item| item.name == provider.name)
                                    .filter(|item| !item.nodes.is_empty())
                                    .map(|item| item.nodes.clone())
                            });
                        if let Some(nodes) = fallback {
                            provider.nodes = nodes;
                            provider.cache_path = Some(cache_path.display().to_string());
                            provider.last_error =
                                Some(format!("refresh failed, using previous cache: {message}"));
                            stats.fallback_count += 1;
                            stats.issues.push(ProviderRefreshIssue {
                                provider_type: "proxy".to_string(),
                                name: provider.name.clone(),
                                message,
                                used_fallback: true,
                            });
                        } else {
                            provider.last_error = Some(message.clone());
                            stats.issues.push(ProviderRefreshIssue {
                                provider_type: "proxy".to_string(),
                                name: provider.name.clone(),
                                message,
                                used_fallback: false,
                            });
                        }
                    }
                }
            }

            for node in &provider.nodes {
                if seen_names.insert(node.name.clone()) {
                    resolved_nodes.push(node.clone());
                }
            }
        }
        document.nodes.extend(resolved_nodes);
        Ok(())
    }

    async fn resolve_rule_providers_async(
        &self,
        id: &str,
        document: &mut SubscriptionDocument,
        previous_document: Option<&SubscriptionDocument>,
        client: &reqwest::Client,
        cancellation: &CancellationToken,
        stats: &mut ProviderRefreshStats,
    ) -> anyhow::Result<()> {
        if document.rule_providers.is_empty() {
            return Ok(());
        }
        let provider_dir = self.subscription_dir(id).join("rule-providers");
        async_fs::create_dir_all(&provider_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to create rule provider cache dir {}",
                    provider_dir.display()
                )
            })?;

        for provider in &mut document.rule_providers {
            if cancellation.is_cancelled() {
                return Err(anyhow!("provider refresh cancelled"));
            }
            stats.provider_count += 1;
            let cache_path = provider_dir.join(format!("{}.txt", safe_file_name(&provider.name)));
            if provider.rules.is_empty() {
                let loaded = load_provider_text_async(
                    "rule provider",
                    self.root(),
                    provider.path.as_deref(),
                    provider.url.as_deref(),
                    client,
                    cancellation,
                )
                .await
                .and_then(|text| {
                    let rules = parse_rule_provider_rules(&text);
                    if rules.is_empty() {
                        return Err(anyhow!("rule provider payload contains no rules"));
                    }
                    Ok((text, rules))
                });
                match loaded {
                    Ok((text, rules)) => {
                        write_text_atomic_async(&cache_path, &text).await?;
                        provider.rules = rules;
                        provider.cache_path = Some(cache_path.display().to_string());
                        provider.last_error = None;
                        stats.refreshed_count += 1;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let fallback =
                            cached_rule_provider_rules(&cache_path).await.or_else(|| {
                                previous_document
                                    .into_iter()
                                    .flat_map(|document| document.rule_providers.iter())
                                    .find(|item| item.name == provider.name)
                                    .filter(|item| !item.rules.is_empty())
                                    .map(|item| item.rules.clone())
                            });
                        if let Some(rules) = fallback {
                            provider.rules = rules;
                            provider.cache_path = Some(cache_path.display().to_string());
                            provider.last_error =
                                Some(format!("refresh failed, using previous cache: {message}"));
                            stats.fallback_count += 1;
                            stats.issues.push(ProviderRefreshIssue {
                                provider_type: "rule".to_string(),
                                name: provider.name.clone(),
                                message,
                                used_fallback: true,
                            });
                        } else {
                            provider.last_error = Some(message.clone());
                            stats.issues.push(ProviderRefreshIssue {
                                provider_type: "rule".to_string(),
                                name: provider.name.clone(),
                                message,
                                used_fallback: false,
                            });
                        }
                    }
                }
            } else {
                write_text_atomic_async(&cache_path, &provider.rules.join("\n")).await?;
                provider.cache_path = Some(cache_path.display().to_string());
                provider.last_error = None;
            }
        }
        Ok(())
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn subscription_dir(&self, id: &str) -> PathBuf {
        self.root.join("subscriptions").join(id)
    }
}

impl Default for SubscriptionUpdateOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            retries: 1,
            concurrency: 4,
        }
    }
}

impl From<&SubscriptionConfig> for SubscriptionUpdateOptions {
    fn from(config: &SubscriptionConfig) -> Self {
        Self {
            timeout_secs: config.update_timeout_secs,
            retries: config.update_retries,
            concurrency: config.update_concurrency,
        }
    }
}

pub fn runtime_config_from_document(
    mut base: SuperConfig,
    document: &SubscriptionDocument,
    use_first_node_as_default: bool,
) -> SuperConfig {
    let outbounds = document_runtime_outbounds(document);
    let first_name = outbounds.first().map(|item| item.name().to_string());
    append_unique_outbounds(&mut base.outbounds, outbounds);
    let known_names = base
        .outbounds
        .iter()
        .map(|item| item.name().to_string())
        .collect::<HashSet<_>>();
    let subscription_rules = document_runtime_rules(document, &known_names);
    append_unique_rule_sets(&mut base.rule_sets, document_runtime_rule_sets(document));
    let uses_subscription_rules = !subscription_rules.is_empty();
    if uses_subscription_rules {
        base.rules = merge_base_and_subscription_rules(base.rules, subscription_rules);
    }
    if use_first_node_as_default {
        if let Some(first_name) = first_name {
            base.core.default_outbound = first_name.clone();
            if !uses_subscription_rules {
                for rule in &mut base.rules {
                    if rule.target == RuleTarget::Match {
                        rule.outbound = first_name.clone();
                    }
                }
            }
        }
    }
    base
}

fn merge_base_and_subscription_rules(
    base_rules: Vec<RouteRule>,
    subscription_rules: Vec<RouteRule>,
) -> Vec<RouteRule> {
    let mut high_priority = Vec::new();
    let mut fallback = Vec::new();
    for rule in base_rules {
        if rule.target == RuleTarget::Match {
            fallback.push(rule);
        } else {
            high_priority.push(rule);
        }
    }
    high_priority
        .into_iter()
        .chain(subscription_rules)
        .chain(fallback)
        .collect()
}

fn append_unique_outbounds(target: &mut Vec<OutboundConfig>, new_items: Vec<OutboundConfig>) {
    for outbound in new_items {
        if let Some(existing) = target
            .iter_mut()
            .find(|item| item.name() == outbound.name())
        {
            *existing = outbound;
        } else {
            target.push(outbound);
        }
    }
}

fn append_unique_rule_sets(target: &mut Vec<RuleSetConfig>, new_items: Vec<RuleSetConfig>) {
    for rule_set in new_items {
        if let Some(existing) = target
            .iter_mut()
            .find(|item| item.name.eq_ignore_ascii_case(&rule_set.name))
        {
            *existing = rule_set;
        } else {
            target.push(rule_set);
        }
    }
}

fn document_runtime_rule_sets(document: &SubscriptionDocument) -> Vec<RuleSetConfig> {
    document
        .rule_providers
        .iter()
        .filter(|provider| !provider.name.trim().is_empty() && !provider.rules.is_empty())
        .map(|provider| RuleSetConfig {
            name: provider.name.clone(),
            behavior: rule_set_behavior(&provider.behavior),
            rules: provider.rules.clone(),
        })
        .collect()
}

fn rule_set_behavior(value: &str) -> RuleSetBehavior {
    match value.to_ascii_lowercase().as_str() {
        "domain" => RuleSetBehavior::Domain,
        "ipcidr" | "ip-cidr" | "ip_cidr" => RuleSetBehavior::IpCidr,
        _ => RuleSetBehavior::Classical,
    }
}

fn document_runtime_outbounds(document: &SubscriptionDocument) -> Vec<OutboundConfig> {
    let mut outbounds = document.supported_outbounds();
    let leaf_names = outbounds
        .iter()
        .map(|item| item.name().to_string())
        .collect::<HashSet<_>>();
    let provider_members = document
        .proxy_providers
        .iter()
        .map(|provider| {
            let members = provider
                .nodes
                .iter()
                .filter_map(|node| leaf_names.contains(&node.name).then(|| node.name.clone()))
                .collect::<Vec<_>>();
            (provider.name.clone(), members)
        })
        .collect::<HashMap<_, _>>();
    let mut known_names = leaf_names.clone();
    known_names.insert("direct".to_string());
    known_names.insert("reject".to_string());

    for group in &document.groups {
        if group.name.trim().is_empty() {
            continue;
        }
        let mut candidates = group
            .members
            .iter()
            .map(|member| {
                if member.eq_ignore_ascii_case("direct") {
                    "direct".to_string()
                } else if member.eq_ignore_ascii_case("reject") {
                    "reject".to_string()
                } else {
                    member.clone()
                }
            })
            .collect::<Vec<_>>();
        if group.include_all {
            candidates.extend(leaf_names.iter().cloned());
        }
        for provider in &group.providers {
            if let Some(members) = provider_members.get(provider) {
                candidates.extend(members.iter().cloned());
            }
        }
        let members = candidates
            .into_iter()
            .filter(|member| known_names.contains(member.as_str()))
            .fold(Vec::new(), |mut result, member| {
                if !result.contains(&member) {
                    result.push(member);
                }
                result
            });
        if members.is_empty() {
            continue;
        }
        outbounds.push(OutboundConfig::Group {
            name: group.name.clone(),
            kind: group.kind.clone(),
            members,
        });
        known_names.insert(group.name.clone());
    }

    outbounds
}

fn document_runtime_rules(
    document: &SubscriptionDocument,
    known_outbounds: &HashSet<String>,
) -> Vec<RouteRule> {
    document
        .rules
        .iter()
        .filter_map(|rule| clash_rule_to_route_rule(rule, known_outbounds))
        .collect()
}

fn clash_rule_to_route_rule(rule: &str, known_outbounds: &HashSet<String>) -> Option<RouteRule> {
    let parts = rule
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let kind = parts[0].to_ascii_uppercase();
    let (target, value, outbound) = match kind.as_str() {
        "DOMAIN" => (RuleTarget::Domain, parts.get(1)?.to_string(), parts.get(2)?),
        "DOMAIN-SUFFIX" => (
            RuleTarget::DomainSuffix,
            parts.get(1)?.trim_start_matches('.').to_string(),
            parts.get(2)?,
        ),
        "DOMAIN-KEYWORD" => (
            RuleTarget::DomainKeyword,
            parts.get(1)?.to_string(),
            parts.get(2)?,
        ),
        "IP-CIDR" | "IP-CIDR6" => (RuleTarget::IpCidr, parts.get(1)?.to_string(), parts.get(2)?),
        "PROCESS-NAME" => (
            RuleTarget::AppName,
            parts.get(1)?.to_string(),
            parts.get(2)?,
        ),
        "PROCESS-PATH" => (
            RuleTarget::AppPath,
            parts.get(1)?.to_string(),
            parts.get(2)?,
        ),
        "RULE-SET" | "GEOSITE" => (
            RuleTarget::RuleSet,
            parts.get(1)?.to_string(),
            parts.get(2)?,
        ),
        "GEOIP" => (RuleTarget::GeoIp, parts.get(1)?.to_string(), parts.get(2)?),
        "MATCH" | "FINAL" => (RuleTarget::Match, "*".to_string(), parts.get(1)?),
        _ => return None,
    };

    let outbound = normalize_rule_outbound(outbound, known_outbounds)?;
    Some(RouteRule {
        target,
        value,
        outbound,
    })
}

fn normalize_rule_outbound(value: &str, known_outbounds: &HashSet<String>) -> Option<String> {
    if value.eq_ignore_ascii_case("direct") {
        return Some("direct".to_string());
    }
    if value.eq_ignore_ascii_case("reject") {
        return Some("reject".to_string());
    }
    if known_outbounds.contains(value) {
        return Some(value.to_string());
    }
    known_outbounds
        .iter()
        .find(|item| item.eq_ignore_ascii_case(value))
        .cloned()
}

fn load_rule_provider_text(
    store_root: &Path,
    path: Option<&str>,
    url: Option<&str>,
) -> anyhow::Result<String> {
    load_provider_text("rule provider", store_root, path, url)
}

fn provider_http_client(timeout_secs: u64) -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.clamp(1, 300)))
        .no_proxy()
        .build()
        .context("failed to build provider HTTP client")
}

fn load_proxy_provider_text(
    store_root: &Path,
    path: Option<&str>,
    url: Option<&str>,
) -> anyhow::Result<String> {
    load_provider_text("proxy provider", store_root, path, url)
}

fn load_provider_text(
    kind: &str,
    store_root: &Path,
    path: Option<&str>,
    url: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(path) = path.filter(|item| !item.trim().is_empty()) {
        let path = PathBuf::from(path);
        let candidates = if path.is_absolute() {
            vec![path]
        } else {
            vec![store_root.join(&path), PathBuf::from(&path)]
        };
        for candidate in candidates {
            match fs::read_to_string(&candidate) {
                Ok(text) => return Ok(text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to read {kind} {}", candidate.display()));
                }
            }
        }
    }
    if let Some(url) = url.filter(|item| !item.trim().is_empty()) {
        return fetch_provider_url_blocking(kind, url);
    }
    Err(anyhow!(
        "{kind} has neither payload, readable path, nor url"
    ))
}

fn fetch_provider_url_blocking(kind: &str, url: &str) -> anyhow::Result<String> {
    let kind = kind.to_string();
    let url = url.to_string();
    let source = provider_source_label(&url);
    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .with_context(|| format!("failed to build {kind} HTTP client"))?;
        let response = client
            .get(&url)
            .header("User-Agent", "Supercore/0.1")
            .send()
            .with_context(|| format!("failed to download {kind} from {source}"))?
            .error_for_status()
            .with_context(|| format!("{kind} returned error status from {source}"))?;
        response
            .text()
            .with_context(|| format!("failed to read {kind} body from {source}"))
    })
    .join()
    .map_err(|_| anyhow!("provider download thread panicked"))?
}

async fn load_provider_text_async(
    kind: &str,
    store_root: &Path,
    path: Option<&str>,
    url: Option<&str>,
    client: &reqwest::Client,
    cancellation: &CancellationToken,
) -> anyhow::Result<String> {
    if let Some(path) = path.filter(|item| !item.trim().is_empty()) {
        let path = PathBuf::from(path);
        let candidates = if path.is_absolute() {
            vec![path]
        } else {
            vec![store_root.join(&path), PathBuf::from(&path)]
        };
        for candidate in candidates {
            let result = tokio::select! {
                _ = cancellation.cancelled() => {
                    return Err(anyhow!("provider refresh cancelled"));
                }
                result = async_fs::read_to_string(&candidate) => result,
            };
            match result {
                Ok(text) => return Ok(text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to read {kind} {}", candidate.display()));
                }
            }
        }
    }
    if let Some(url) = url.filter(|item| !item.trim().is_empty()) {
        return fetch_provider_url_async(kind, url, client, cancellation).await;
    }
    Err(anyhow!(
        "{kind} has neither payload, readable path, nor url"
    ))
}

async fn fetch_provider_url_async(
    kind: &str,
    url: &str,
    client: &reqwest::Client,
    cancellation: &CancellationToken,
) -> anyhow::Result<String> {
    let parsed = url::Url::parse(url).context("provider url is invalid")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("provider url must use http or https"));
    }
    let source = provider_source_label(url);
    let response = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("provider refresh cancelled")),
        response = client
            .get(url)
            .header("User-Agent", concat!("Supercore/", env!("CARGO_PKG_VERSION")))
            .send() => {
                response.with_context(|| format!("failed to download {kind} from {source}"))?
            }
    };
    let mut response = response
        .error_for_status()
        .with_context(|| format!("{kind} returned error status from {source}"))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_PROVIDER_BODY_BYTES as u64)
    {
        return Err(anyhow!(
            "{kind} body exceeds {} bytes",
            MAX_PROVIDER_BODY_BYTES
        ));
    }

    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => return Err(anyhow!("provider refresh cancelled")),
            chunk = response.chunk() => {
                chunk.with_context(|| format!("failed to read {kind} body from {source}"))?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_PROVIDER_BODY_BYTES {
            return Err(anyhow!(
                "{kind} body exceeds {} bytes",
                MAX_PROVIDER_BODY_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).with_context(|| format!("{kind} body from {source} is not UTF-8"))
}

async fn cached_proxy_provider_nodes(path: &Path) -> Option<Vec<SubscriptionNode>> {
    let text = async_fs::read_to_string(path).await.ok()?;
    let nodes = parse_proxy_provider_nodes(&text).ok()?;
    (!nodes.is_empty()).then_some(nodes)
}

async fn cached_rule_provider_rules(path: &Path) -> Option<Vec<String>> {
    let text = async_fs::read_to_string(path).await.ok()?;
    let rules = parse_rule_provider_rules(&text);
    (!rules.is_empty()).then_some(rules)
}

async fn write_text_atomic_async(path: &Path, text: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create provider cache dir {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
    async_fs::write(&tmp, text)
        .await
        .with_context(|| format!("failed to write provider cache {}", tmp.display()))?;
    async_fs::rename(&tmp, path).await.with_context(|| {
        format!(
            "failed to replace provider cache {} with {}",
            path.display(),
            tmp.display()
        )
    })
}

fn provider_source_label(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            })
        })
        .unwrap_or_else(|| "<redacted-provider-source>".to_string())
}

fn parse_proxy_provider_nodes(text: &str) -> anyhow::Result<Vec<SubscriptionNode>> {
    let document = parse_subscription(text)?;
    Ok(document.nodes)
}

fn safe_file_name(value: &str) -> String {
    let name = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.is_empty() {
        "ruleset".to_string()
    } else {
        name
    }
}

fn meta_from_document(
    id: String,
    name: String,
    url: Option<String>,
    document: &SubscriptionDocument,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_update_error: Option<String>,
) -> SubscriptionMeta {
    SubscriptionMeta {
        id,
        name,
        url,
        source_format: document.source_format.clone(),
        node_count: document.nodes.len(),
        supported_outbound_count: document.supported_outbounds().len(),
        unsupported_count: document.unsupported.len()
            + document
                .nodes
                .iter()
                .filter(|node| node.to_outbound_config().is_err())
                .count(),
        created_at,
        updated_at,
        last_update_error,
        traffic_upload_total: 0,
        traffic_download_total: 0,
    }
}

fn inferred_name(url: Option<&str>, document: &SubscriptionDocument, id: &str) -> String {
    if let Some(group) = document.groups.first() {
        if !group.name.trim().is_empty() {
            return group.name.clone();
        }
    }
    if let Some(url) = url {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host.to_string();
            }
        }
    }
    format!("subscription-{}", &id[..8])
}

fn write_json_atomic<T>(path: &Path, value: &T) -> anyhow::Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent().filter(|item| !item.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension(
        path.extension()
            .and_then(|item| item.to_str())
            .map(|item| format!("{item}.tmp"))
            .unwrap_or_else(|| "tmp".to_string()),
    );
    let text = serde_json::to_string_pretty(value)?;
    fs::write(&tmp_path, text)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

async fn fetch_subscription_url_with_options(
    url: &str,
    options: SubscriptionUpdateOptions,
    cancellation: &CancellationToken,
) -> anyhow::Result<String> {
    let timeout_secs = options.timeout_secs.clamp(1, 300);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .no_proxy()
        .build()?;
    let attempts = options.retries.saturating_add(1);
    let mut last_error = None;
    for attempt in 0..attempts {
        if cancellation.is_cancelled() {
            return Err(anyhow!("subscription update cancelled"));
        }
        match fetch_subscription_url_once(&client, url, cancellation).await {
            Ok(text) => return Ok(text),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    tokio::select! {
                        _ = cancellation.cancelled() => {
                            return Err(anyhow!("subscription update cancelled"));
                        }
                        _ = sleep(Duration::from_millis(250 * (attempt as u64 + 1))) => {}
                    }
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("subscription fetch failed")))
}

async fn fetch_subscription_url_once(
    client: &reqwest::Client,
    url: &str,
    cancellation: &CancellationToken,
) -> anyhow::Result<String> {
    let parsed = url::Url::parse(url).context("subscription url is invalid")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!("subscription url must use http or https"));
    }
    let source = provider_source_label(url);
    let response = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("subscription update cancelled")),
        response = client
            .get(url)
            .header(
                "User-Agent",
                concat!("Supercore/", env!("CARGO_PKG_VERSION")),
            )
            .send() => {
                response.with_context(|| format!("failed to download subscription from {source}"))?
            }
    };
    let mut response = response
        .error_for_status()
        .with_context(|| format!("subscription endpoint returned an error from {source}"))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_SUBSCRIPTION_BODY_BYTES as u64)
    {
        return Err(anyhow!(
            "subscription body exceeds {} bytes",
            MAX_SUBSCRIPTION_BODY_BYTES
        ));
    }
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => {
                return Err(anyhow!("subscription update cancelled"));
            }
            chunk = response.chunk() => {
                chunk.with_context(|| {
                    format!("failed to read subscription body from {source}")
                })?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BODY_BYTES {
            return Err(anyhow!(
                "subscription body exceeds {} bytes",
                MAX_SUBSCRIPTION_BODY_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).with_context(|| format!("subscription body from {source} is not UTF-8"))
}
