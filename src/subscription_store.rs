use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};
use uuid::Uuid;

use crate::{
    config::{
        OutboundConfig, RouteRule, RuleSetBehavior, RuleSetConfig, RuleTarget, SubscriptionConfig,
        SuperConfig,
    },
    subscription::{parse_rule_provider_rules, parse_subscription, SubscriptionDocument},
};

pub const DEFAULT_STORE_DIR: &str = "skyhook-subscriptions";

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

    pub fn replace_text(&self, id: &str, text: &str) -> anyhow::Result<SubscriptionMeta> {
        let mut index = self.load_index()?;
        let position = index
            .subscriptions
            .iter()
            .position(|item| item.id == id)
            .ok_or_else(|| anyhow!("subscription {id} does not exist"))?;
        let previous = index.subscriptions[position].clone();
        let mut document = parse_subscription(text)?;
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

        self.resolve_rule_providers(&meta.id, &mut document)?;
        self.write_subscription_files(&meta, text, &document)?;
        index.subscriptions[position] = meta.clone();
        self.save_index(&index)?;
        Ok(meta)
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

    pub async fn update_all_from_urls_with(
        &self,
        options: SubscriptionUpdateOptions,
    ) -> anyhow::Result<Vec<SubscriptionUpdateSummary>> {
        let index = self.index()?;
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
            jobs.spawn(async move {
                let _permit = semaphore.acquire_owned().await.expect("semaphore open");
                let result: anyhow::Result<()> = async {
                    let text = fetch_subscription_url_with_options(&url, options).await?;
                    store.replace_text(&meta.id, &text)?;
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
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(summary) => summaries.push(summary),
                Err(error) => summaries.push(SubscriptionUpdateSummary {
                    id: "unknown".to_string(),
                    name: "unknown".to_string(),
                    updated: false,
                    error: Some(format!("subscription update task failed: {error}")),
                }),
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
    let mut known_names = outbounds
        .iter()
        .map(|item| item.name().to_string())
        .collect::<HashSet<_>>();
    known_names.insert("direct".to_string());
    known_names.insert("reject".to_string());

    for group in &document.groups {
        if group.name.trim().is_empty() {
            continue;
        }
        let members = group
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
            .filter(|member| known_names.contains(member.as_str()))
            .collect::<Vec<_>>();
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
                    return Err(error).with_context(|| {
                        format!("failed to read rule provider {}", candidate.display())
                    });
                }
            }
        }
    }
    if let Some(url) = url.filter(|item| !item.trim().is_empty()) {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build rule provider HTTP client")?;
        let response = client
            .get(url)
            .header("User-Agent", "Skyhook/0.1")
            .send()
            .with_context(|| format!("failed to download rule provider {url}"))?
            .error_for_status()
            .with_context(|| format!("rule provider returned error status {url}"))?;
        return response
            .text()
            .with_context(|| format!("failed to read rule provider body {url}"));
    }
    Err(anyhow!(
        "rule provider has neither payload, readable path, nor url"
    ))
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
) -> anyhow::Result<String> {
    let timeout_secs = options.timeout_secs.clamp(1, 300);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    let attempts = options.retries.saturating_add(1);
    let mut last_error = None;
    for attempt in 0..attempts {
        match fetch_subscription_url_once(&client, url).await {
            Ok(text) => return Ok(text),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("subscription fetch failed")))
}

async fn fetch_subscription_url_once(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<String> {
    let response = client
        .get(url)
        .header("User-Agent", concat!("Skyhook/", env!("CARGO_PKG_VERSION")))
        .send()
        .await?
        .error_for_status()?;
    Ok(response.text().await?)
}
