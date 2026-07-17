use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, Subcommand};
use supercore::{
    api,
    config::{SubscriptionConfig, SuperConfig},
    core::{ProbeOptions, Runtime},
    geo, inbound, subscription,
    subscription_store::{SubscriptionStore, SubscriptionUpdateOptions, DEFAULT_STORE_DIR},
};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "supercore")]
#[command(version)]
#[command(about = "Rust-native Supercore proxy engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(short, long, default_value = "supercore.yaml")]
        config: PathBuf,
    },
    Check {
        #[arg(short, long, default_value = "supercore.yaml")]
        config: PathBuf,
    },
    Doctor {
        #[arg(short, long, default_value = "supercore.yaml")]
        config: PathBuf,
    },
    Probe {
        #[arg(short, long, default_value = "supercore.yaml")]
        config: PathBuf,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        concurrency: Option<usize>,
        #[arg(long)]
        names: Option<PathBuf>,
    },
    Tun {
        #[command(subcommand)]
        command: TunCommand,
    },
    ImportSubscription {
        #[arg(long, conflicts_with = "url")]
        file: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    #[command(name = "subscription", alias = "subscriptions")]
    Subscriptions {
        #[command(subcommand)]
        command: SubscriptionCommand,
    },
    ExampleConfig,
}

#[derive(Subcommand)]
enum TunCommand {
    Cleanup {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SubscriptionCommand {
    Inspect {
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
        #[arg(long)]
        id: Option<String>,
    },
    Import {
        #[arg(long, conflicts_with = "url")]
        file: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
        #[arg(long)]
        switch: bool,
    },
    List {
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
    },
    Use {
        id: String,
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
    },
    UpdateAll {
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
        #[arg(long)]
        timeout_secs: Option<u64>,
        #[arg(long)]
        retries: Option<u8>,
        #[arg(long)]
        concurrency: Option<usize>,
    },
    ExportActiveConfig {
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = DEFAULT_STORE_DIR)]
        store: PathBuf,
        #[arg(long)]
        use_first_node: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "supercore=info,info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Run { config } => {
            let base_config = load_base_config_for_run(&config).await?;
            let config = apply_active_subscription(base_config.clone())?;
            let mixed_addr: SocketAddr = config.core.mixed_listen;
            let control_addr: SocketAddr = config.core.control_listen;
            let subscription_config = config.subscriptions.clone();
            let runtime = Arc::new(Runtime::new_with_base(base_config, config)?);

            tracing::info!(%mixed_addr, %control_addr, "starting supercore");
            let probe_task = tokio::spawn(runtime.clone().background_probe_loop());
            let subscription_task = tokio::spawn(background_subscription_update_loop(
                runtime.clone(),
                subscription_config,
            ));

            let mut tasks = JoinSet::new();
            tasks.spawn(api::serve(runtime.clone()));
            if runtime.config().tun.enabled {
                tasks.spawn(inbound::tun::serve(runtime.clone()));
            }
            if runtime.config().dns.enabled && runtime.config().dns.listen.is_some() {
                tasks.spawn(inbound::dns::serve(runtime.clone()));
            }
            tasks.spawn(inbound::mixed::serve(runtime.clone()));

            let outcome = tokio::select! {
                signal = tokio::signal::ctrl_c() => signal.map_err(anyhow::Error::from),
                result = tasks.join_next() => match result {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(anyhow::Error::from(error)),
                    None => Ok(()),
                },
            };

            runtime.shutdown();
            let graceful = async {
                while let Some(result) = tasks.join_next().await {
                    if let Err(error) = result {
                        tracing::warn!(error = %error, "service task stopped during shutdown");
                    }
                }
            };
            if timeout(Duration::from_secs(5), graceful).await.is_err() {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }

            for mut task in [probe_task, subscription_task] {
                if timeout(Duration::from_secs(2), &mut task).await.is_err() {
                    task.abort();
                    let _ = task.await;
                }
            }
            outcome?;
        }
        Command::Check { config } => {
            let config = load_runtime_config(&config).await?;
            println!("Supercore config OK: {}", config.summary());
        }
        Command::Doctor { config } => {
            let config = load_runtime_config(&config).await?;
            println!("=== Supercore Doctor ===");
            println!();
            println!("Config: {}", config.summary());
            println!("Mixed listen: {}", config.core.mixed_listen);
            println!("Control listen: {}", config.core.control_listen);
            println!("Default outbound: {}", config.core.default_outbound);
            println!("TUN enabled: {}", config.tun.enabled);
            println!("DNS enabled: {}", config.dns.enabled);
            println!("Smart rules enabled: {}", config.smart_rules.enabled);
            println!();
            println!("Outbounds: {}", config.outbounds.len());
            let support_summary = summarize_outbound_support(&config);
            if let Some(error) = &support_summary.runtime_error {
                println!("Runtime capability analysis unavailable: {error}");
            }
            println!("Full outbound: {}", support_summary.full_count);
            println!("Partial outbound: {}", support_summary.partial_count);
            println!("Parse-only outbound: {}", support_summary.parse_only_count);
            println!(
                "Unsupported outbound: {}",
                support_summary.unsupported_count
            );
            println!("Group outbounds: {}", support_summary.group_count);
            let mut protocol_reports: Vec<_> = support_summary.by_protocol.iter().collect();
            protocol_reports.sort_by(|a, b| a.0.cmp(b.0));
            if !protocol_reports.is_empty() {
                println!("By protocol:");
                for (kind, counts) in protocol_reports {
                    println!(
                        "  {}: full={} partial={} parse-only={} unsupported={}",
                        kind,
                        counts.full_count,
                        counts.partial_count,
                        counts.parse_only_count,
                        counts.unsupported_count
                    );
                }
            }
            println!();
            println!("Rules: {}", config.rules.len());
            let mut rule_types: HashMap<String, usize> = HashMap::new();
            for rule in &config.rules {
                *rule_types.entry(format!("{:?}", rule.target)).or_insert(0) += 1;
            }
            for (target, count) in &rule_types {
                println!("  {}: {}", target, count);
            }
            println!();
            let store = SubscriptionStore::new(config.subscriptions.store_path.clone());
            match store.index() {
                Ok(index) => {
                    println!("Subscriptions: {}", index.subscriptions.len());
                    if let Some(active_id) = &index.active_id {
                        println!("Active subscription: {}", active_id);
                    }
                }
                Err(error) => {
                    println!("Subscriptions: error loading index: {}", error);
                }
            }
            println!();
            println!("=== Doctor Complete ===");
        }
        Command::Probe {
            config,
            timeout_ms,
            url,
            concurrency,
            names,
        } => {
            let config = load_runtime_config(&config).await?;
            let runtime = Runtime::new(config)?;
            let names_list = if let Some(names_path) = names {
                let content = fs::read_to_string(&names_path)?;
                Some(
                    content
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            let results = runtime
                .probe_all_outbounds_with(ProbeOptions {
                    url,
                    timeout_ms,
                    concurrency,
                    names: names_list,
                })
                .await;
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        Command::Tun { command } => match command {
            TunCommand::Cleanup { dry_run } => {
                println!(
                    "=== TUN Cleanup {}===\n",
                    if dry_run { "(dry-run) " } else { "" }
                );
                let check_routes = vec!["198.18.0.0/15"];
                for route in &check_routes {
                    let output = std::process::Command::new("netstat")
                        .args(["-rn", "-f", "inet"])
                        .output();
                    match output {
                        Ok(o) => {
                            let stdout = String::from_utf8_lossy(&o.stdout);
                            let found: Vec<_> =
                                stdout.lines().filter(|l| l.contains(*route)).collect();
                            if !found.is_empty() {
                                println!("Found {} route entries for {}:", found.len(), route);
                                for line in &found {
                                    println!("  {}", line);
                                }
                                if !dry_run {
                                    println!("  Removing {} routes...", found.len());
                                    for line in &found {
                                        let parts: Vec<&str> = line.split_whitespace().collect();
                                        if parts.len() >= 3 && parts[0] == *route {
                                            let gw = parts[1];
                                            let status = std::process::Command::new("sudo")
                                                .args(["route", "delete", "-net", *route, gw])
                                                .status();
                                            match status {
                                                Ok(s) if s.success() => println!(
                                                    "  Deleted route {} via {}",
                                                    *route, gw
                                                ),
                                                Ok(s) => println!(
                                                    "  Failed to delete route {} (exit {})",
                                                    *route, s
                                                ),
                                                Err(e) => println!(
                                                    "  Failed to delete route {}: {}",
                                                    *route, e
                                                ),
                                            }
                                        }
                                    }
                                }
                            } else {
                                println!("No {} routes found - clean.", route);
                            }
                        }
                        Err(e) => println!("Failed to check routes: {}", e),
                    }
                }
                let proxy_check = std::process::Command::new("scutil")
                    .args(["--proxy"])
                    .output();
                if let Ok(o) = proxy_check {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    if stdout.contains("127.0.0.1") {
                        println!("\nSystem proxy still points to 127.0.0.1");
                        if !dry_run {
                            println!("  Restoring system proxy...");
                            let services = ["Wi-Fi", "Ethernet"];
                            for svc in &services {
                                let _ = std::process::Command::new("networksetup")
                                    .args(["-setwebproxystate", svc, "off"])
                                    .status();
                                let _ = std::process::Command::new("networksetup")
                                    .args(["-setsecurewebproxystate", svc, "off"])
                                    .status();
                                let _ = std::process::Command::new("networksetup")
                                    .args(["-setsocksfirewallproxystate", svc, "off"])
                                    .status();
                            }
                            println!("  System proxy restored.");
                        }
                    } else {
                        println!("\nSystem proxy is clean.");
                    }
                }
                println!("\n=== TUN Cleanup Complete ===");
            }
        },
        Command::ImportSubscription { file, url, output } => {
            let text = read_subscription_source(file, url).await?;
            let document = subscription::parse_subscription(&text)?;
            let encoded = serde_json::to_string_pretty(&document)?;
            if let Some(output) = output {
                fs::write(&output, encoded)?;
                println!("Imported subscription: {}", output.display());
            } else {
                println!("{encoded}");
            }
        }
        Command::Subscriptions { command } => {
            handle_subscription_command(command).await?;
        }
        Command::ExampleConfig => {
            print!("{}", SuperConfig::example_yaml()?);
        }
    }
    Ok(())
}

async fn load_runtime_config(path: &Path) -> anyhow::Result<SuperConfig> {
    let config = SuperConfig::load(path)?;
    let config = maybe_prepare_geo_assets(config).await;
    apply_active_subscription(config)
}

async fn load_base_config_for_run(path: &Path) -> anyhow::Result<SuperConfig> {
    let config = SuperConfig::load(path)?;
    Ok(maybe_prepare_geo_assets(config).await)
}

async fn maybe_prepare_geo_assets(config: SuperConfig) -> SuperConfig {
    if config.geo.update_on_start {
        geo::prepare_geo_assets(config).await
    } else {
        config
    }
}

fn apply_active_subscription(config: SuperConfig) -> anyhow::Result<SuperConfig> {
    if !config.subscriptions.use_active {
        return Ok(config);
    }
    let store_path = config.subscriptions.store_path.clone();
    let use_first_node = config.subscriptions.use_first_node_as_default;
    SubscriptionStore::new(store_path).active_runtime_config(config, use_first_node)
}

async fn background_subscription_update_loop(runtime: Arc<Runtime>, config: SubscriptionConfig) {
    if !config.auto_update || config.update_interval_secs == 0 {
        return;
    }
    let store = SubscriptionStore::new(config.store_path.clone());
    let cancellation = runtime.cancellation_token();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = sleep(Duration::from_secs(config.update_interval_secs)) => {}
        }
        let result = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = store.update_all_from_urls_with((&config).into()) => result,
        };
        match result {
            Ok(results) => {
                let updated = results.iter().filter(|item| item.updated).count();
                tracing::info!(
                    updated,
                    total = results.len(),
                    "background subscription update complete"
                );
            }
            Err(error) => {
                tracing::warn!(error = %error, "background subscription update failed");
            }
        }
    }
}

async fn handle_subscription_command(command: SubscriptionCommand) -> anyhow::Result<()> {
    match command {
        SubscriptionCommand::Inspect { store, id } => {
            let store = SubscriptionStore::new(store);
            let index = store.index()?;
            println!("=== Subscription Inspect ===\n");
            println!("Total subscriptions: {}", index.subscriptions.len());
            if let Some(active_id) = &index.active_id {
                println!("Active subscription: {}", active_id);
            } else {
                println!("Active subscription: none");
            }
            println!();
            for sub in &index.subscriptions {
                let is_active = Some(&sub.id) == index.active_id.as_ref();
                let marker = if is_active { " [ACTIVE]" } else { "" };
                println!("  {}{}", sub.id, marker);
                println!("    Name: {}", sub.name);
                if let Some(active_id) = &id {
                    if sub.id != *active_id && !is_active {
                        continue;
                    }
                }
                let base_config = SuperConfig::default();
                match store.active_runtime_config(base_config, true) {
                    Ok(config) => {
                        println!("    Total outbounds: {}", config.outbounds.len());
                        let support_summary = summarize_outbound_support(&config);
                        if let Some(error) = &support_summary.runtime_error {
                            println!("    Runtime capability analysis unavailable: {error}");
                        }
                        println!("    Full outbound: {}", support_summary.full_count);
                        println!("    Partial outbound: {}", support_summary.partial_count);
                        println!(
                            "    Parse-only outbound: {}",
                            support_summary.parse_only_count
                        );
                        println!(
                            "    Unsupported outbound: {}",
                            support_summary.unsupported_count
                        );
                        println!("    Group outbounds: {}", support_summary.group_count);
                        println!("    Rules: {}", config.rules.len());
                        println!("    TUN enabled: {}", config.tun.enabled);
                        println!("    DNS enabled: {}", config.dns.enabled);
                        println!("    Smart rules enabled: {}", config.smart_rules.enabled);
                        if !support_summary.outbound_counts.is_empty() {
                            println!("    Outbound types:");
                            let mut types: Vec<_> =
                                support_summary.outbound_counts.iter().collect();
                            types.sort_by(|a, b| b.1.cmp(a.1));
                            for (kind, count) in types {
                                println!("      {}: {}", kind, count);
                            }
                        }
                        let mut rule_targets: HashMap<String, usize> = HashMap::new();
                        for rule in &config.rules {
                            *rule_targets
                                .entry(format!("{:?}", rule.target))
                                .or_insert(0) += 1;
                        }
                        if !rule_targets.is_empty() {
                            println!("    Rule types:");
                            let mut rules: Vec<_> = rule_targets.iter().collect();
                            rules.sort_by(|a, b| b.1.cmp(a.1));
                            for (target, count) in rules {
                                println!("      {}: {}", target, count);
                            }
                        }
                    }
                    Err(error) => {
                        println!("    Error building runtime config: {}", error);
                    }
                }
                println!();
            }
            println!("=== Inspect Complete ===");
        }
        SubscriptionCommand::Import {
            file,
            url,
            id,
            name,
            store,
            switch,
        } => {
            let source_url = url.clone();
            let text = read_subscription_source(file, url).await?;
            let result = SubscriptionStore::new(store)
                .import_text_with_id(id, name, source_url, &text, switch)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        SubscriptionCommand::List { store } => {
            let index = SubscriptionStore::new(store).index()?;
            println!("{}", serde_json::to_string_pretty(&index)?);
        }
        SubscriptionCommand::Use { id, store } => {
            let meta = SubscriptionStore::new(store).set_active(&id)?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }
        SubscriptionCommand::UpdateAll {
            store,
            timeout_secs,
            retries,
            concurrency,
        } => {
            let store = SubscriptionStore::new(store);
            let defaults = SubscriptionUpdateOptions::default();
            let summaries = store
                .update_all_from_urls_with(SubscriptionUpdateOptions {
                    timeout_secs: timeout_secs.unwrap_or(defaults.timeout_secs),
                    retries: retries.unwrap_or(defaults.retries),
                    concurrency: concurrency.unwrap_or(defaults.concurrency),
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&summaries)?);
        }
        SubscriptionCommand::ExportActiveConfig {
            base,
            output,
            store,
            use_first_node,
        } => {
            let base_config = match base {
                Some(path) => SuperConfig::load(&path)?,
                None => SuperConfig::default(),
            };
            let base_config = maybe_prepare_geo_assets(base_config).await;
            let config =
                SubscriptionStore::new(store).active_runtime_config(base_config, use_first_node)?;
            let encoded = serde_yaml::to_string(&config)?;
            if let Some(output) = output {
                fs::write(&output, encoded)?;
                println!("Exported active subscription config: {}", output.display());
            } else {
                print!("{encoded}");
            }
        }
    }
    Ok(())
}

fn outbound_api_kind(config: &supercore::config::OutboundConfig) -> String {
    use supercore::config::OutboundConfig;
    match config {
        OutboundConfig::Direct { .. } => "direct".to_string(),
        OutboundConfig::Reject { .. } => "reject".to_string(),
        OutboundConfig::Http { .. } => "http".to_string(),
        OutboundConfig::Socks5 { .. } => "socks5".to_string(),
        OutboundConfig::Shadowsocks { .. } => "shadowsocks".to_string(),
        OutboundConfig::Trojan { .. } => "trojan".to_string(),
        OutboundConfig::Vmess { .. } => "vmess".to_string(),
        OutboundConfig::Vless { .. } => "vless".to_string(),
        OutboundConfig::Hysteria2 { .. } => "hysteria2".to_string(),
        OutboundConfig::Tuic { .. } => "tuic".to_string(),
        OutboundConfig::Naive { .. } => "naive".to_string(),
        OutboundConfig::Ssr { .. } => "ssr".to_string(),
        OutboundConfig::Snell { .. } => "snell".to_string(),
        OutboundConfig::Hysteria { .. } => "hysteria".to_string(),
        OutboundConfig::AnyTls { .. } => "anytls".to_string(),
        OutboundConfig::ShadowTls { .. } => "shadowtls".to_string(),
        OutboundConfig::WireGuard { .. } => "wireguard".to_string(),
        OutboundConfig::Ssh { .. } => "ssh".to_string(),
        OutboundConfig::Mieru { .. } => "mieru".to_string(),
        OutboundConfig::Juicity { .. } => "juicity".to_string(),
        OutboundConfig::Masque { .. } => "masque".to_string(),
        OutboundConfig::OpenVpn { .. } => "openvpn".to_string(),
        OutboundConfig::Unknown { protocol, .. } => format!("unknown:{}", protocol),
        OutboundConfig::Group { kind, .. } => format!("group:{}", kind),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProtocolSupportSummary {
    full_count: usize,
    partial_count: usize,
    parse_only_count: usize,
    unsupported_count: usize,
}

impl ProtocolSupportSummary {
    fn record(&mut self, state: OutboundSupportState) {
        match state {
            OutboundSupportState::Full => self.full_count += 1,
            OutboundSupportState::Partial => self.partial_count += 1,
            OutboundSupportState::ParseOnly => self.parse_only_count += 1,
            OutboundSupportState::Unsupported => self.unsupported_count += 1,
        }
    }
}

#[derive(Debug, Default)]
struct OutboundSupportSummary {
    full_count: usize,
    partial_count: usize,
    parse_only_count: usize,
    unsupported_count: usize,
    group_count: usize,
    outbound_counts: HashMap<String, usize>,
    by_protocol: HashMap<String, ProtocolSupportSummary>,
    runtime_error: Option<String>,
}

fn accumulate_protocol_summary(
    summary: &mut OutboundSupportSummary,
    kind: String,
    state: OutboundSupportState,
) {
    *summary.outbound_counts.entry(kind.clone()).or_insert(0) += 1;
    if kind.starts_with("group:") {
        summary.group_count += 1;
    }
    summary.by_protocol.entry(kind).or_default().record(state);
    match state {
        OutboundSupportState::Full => summary.full_count += 1,
        OutboundSupportState::Partial => summary.partial_count += 1,
        OutboundSupportState::ParseOnly => summary.parse_only_count += 1,
        OutboundSupportState::Unsupported => summary.unsupported_count += 1,
    }
}

#[derive(Debug, Clone, Copy)]
enum OutboundSupportState {
    Full,
    Partial,
    ParseOnly,
    Unsupported,
}

fn summarize_outbound_support(config: &SuperConfig) -> OutboundSupportSummary {
    let runtime = match Runtime::new(config.clone()) {
        Ok(runtime) => runtime,
        Err(error) => {
            let mut summary = OutboundSupportSummary {
                runtime_error: Some(format!("{error}")),
                ..Default::default()
            };
            for outbound in &config.outbounds {
                let kind = outbound_api_kind(outbound);
                let state = classify_outbound_without_runtime(outbound);
                accumulate_protocol_summary(&mut summary, kind, state);
            }
            return summary;
        }
    };

    let mut summary = OutboundSupportSummary::default();
    for item in runtime.outbound_capabilities() {
        let state = classify_outbound_with_capability(&item);
        accumulate_protocol_summary(&mut summary, item.kind.clone(), state);
    }
    summary
}

fn classify_outbound_with_capability(
    snapshot: &supercore::core::OutboundCapabilitySnapshot,
) -> OutboundSupportState {
    if snapshot.kind.starts_with("group:") {
        return OutboundSupportState::Full;
    }
    if snapshot.kind == "reject" {
        return OutboundSupportState::Unsupported;
    }
    if snapshot.tcp_supported && snapshot.udp_supported && snapshot.limitations.is_empty() {
        return OutboundSupportState::Full;
    }
    if snapshot.tcp_supported || snapshot.udp_supported {
        return OutboundSupportState::Partial;
    }
    if snapshot.kind.starts_with("unknown:")
        || snapshot
            .limitations
            .iter()
            .any(|item| item.contains("not implemented yet"))
    {
        return OutboundSupportState::ParseOnly;
    }
    OutboundSupportState::Unsupported
}

fn classify_outbound_without_runtime(
    outbound: &supercore::config::OutboundConfig,
) -> OutboundSupportState {
    use supercore::config::OutboundConfig;
    match outbound {
        OutboundConfig::Group { .. } => OutboundSupportState::Full,
        OutboundConfig::Reject { .. } => OutboundSupportState::Unsupported,
        OutboundConfig::Unknown { .. }
        | OutboundConfig::Hysteria { .. }
        | OutboundConfig::Mieru { .. }
        | OutboundConfig::Juicity { .. }
        | OutboundConfig::Masque { .. }
        | OutboundConfig::OpenVpn { .. } => OutboundSupportState::ParseOnly,
        _ => OutboundSupportState::Partial,
    }
}

async fn read_subscription_source(
    file: Option<PathBuf>,
    url: Option<String>,
) -> anyhow::Result<String> {
    match (file, url) {
        (Some(path), None) => Ok(fs::read_to_string(path)?),
        (None, Some(url)) => {
            let response = reqwest::Client::builder()
                .timeout(Duration::from_secs(
                    SubscriptionUpdateOptions::default().timeout_secs,
                ))
                .build()?
                .get(url)
                .header(
                    "User-Agent",
                    concat!("Supercore/", env!("CARGO_PKG_VERSION")),
                )
                .send()
                .await?
                .error_for_status()?;
            Ok(response.text().await?)
        }
        (None, None) => Err(anyhow::anyhow!("provide --file or --url")),
        (Some(_), Some(_)) => Err(anyhow::anyhow!("provide only one of --file or --url")),
    }
}

#[cfg(test)]
mod doctor_summary_tests {
    use super::*;
    use std::collections::BTreeMap;
    use supercore::config::OutboundConfig;

    #[test]
    fn default_runtime_never_updates_subscriptions_during_startup() {
        assert!(!SuperConfig::default().subscriptions.update_on_start);
    }

    #[test]
    fn summarize_outbound_support_produces_protocol_level_counts() {
        let mut config = SuperConfig::default();
        config.outbounds = vec![
            OutboundConfig::Direct {
                name: "direct".to_string(),
            },
            OutboundConfig::Reject {
                name: "reject".to_string(),
            },
            OutboundConfig::Shadowsocks {
                name: "ss-node".to_string(),
                server: "ss.example".to_string(),
                port: 443,
                method: "aes-128-gcm".to_string(),
                password: "password".to_string(),
                plugin: None,
                udp_over_tcp: false,
                udp_over_tcp_version: 1,
            },
            OutboundConfig::Ssr {
                name: "ssr-node".to_string(),
                server: "ssr.example".to_string(),
                port: 443,
                method: "aes-128-cfb".to_string(),
                password: "pass".to_string(),
                protocol: "origin".to_string(),
                obfs: "plain".to_string(),
                protocol_param: None,
                obfs_param: None,
            },
            OutboundConfig::Hysteria {
                name: "hy2-node".to_string(),
                server: "hysteria.example".to_string(),
                port: 443,
                auth: None,
                auth_str: None,
                protocol: None,
                up: None,
                down: None,
                sni: None,
                skip_cert_verify: false,
                obfs: None,
            },
            OutboundConfig::OpenVpn {
                name: "ovpn-node".to_string(),
                profile: None,
                inline_profile: None,
            },
            OutboundConfig::Group {
                name: "group:us".to_string(),
                kind: "url-test".to_string(),
                members: vec!["direct".to_string(), "ss-node".to_string()],
            },
        ];
        config.outbounds.push(OutboundConfig::Unknown {
            name: "unknown-node".to_string(),
            protocol: "weird-protocol".to_string(),
            server: None,
            port: None,
            params: BTreeMap::new(),
        });

        let summary = summarize_outbound_support(&config);
        assert_eq!(summary.full_count, 4);
        assert_eq!(summary.partial_count, 0);
        assert_eq!(summary.parse_only_count, 3);
        assert_eq!(summary.unsupported_count, 1);
        assert_eq!(summary.group_count, 1);

        assert_eq!(
            summary
                .outbound_counts
                .get("direct")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            summary
                .outbound_counts
                .get("group:url-test")
                .copied()
                .unwrap_or_default(),
            1
        );

        assert_eq!(
            summary.by_protocol.get("direct").copied(),
            Some(ProtocolSupportSummary {
                full_count: 1,
                partial_count: 0,
                parse_only_count: 0,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("shadowsocks").copied(),
            Some(ProtocolSupportSummary {
                full_count: 1,
                partial_count: 0,
                parse_only_count: 0,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("ssr").copied(),
            Some(ProtocolSupportSummary {
                full_count: 1,
                partial_count: 0,
                parse_only_count: 0,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("hysteria").copied(),
            Some(ProtocolSupportSummary {
                full_count: 0,
                partial_count: 0,
                parse_only_count: 1,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("openvpn").copied(),
            Some(ProtocolSupportSummary {
                full_count: 0,
                partial_count: 0,
                parse_only_count: 1,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("group:url-test").copied(),
            Some(ProtocolSupportSummary {
                full_count: 1,
                partial_count: 0,
                parse_only_count: 0,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("unknown:weird-protocol").copied(),
            Some(ProtocolSupportSummary {
                full_count: 0,
                partial_count: 0,
                parse_only_count: 1,
                unsupported_count: 0,
            })
        );
        assert_eq!(
            summary.by_protocol.get("reject").copied(),
            Some(ProtocolSupportSummary {
                full_count: 0,
                partial_count: 0,
                parse_only_count: 0,
                unsupported_count: 1,
            })
        );
    }
}
