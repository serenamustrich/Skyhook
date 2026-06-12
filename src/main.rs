use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, Subcommand};
use skyhook::{
    api,
    config::{SubscriptionConfig, SuperConfig, TunBackend},
    core::{ProbeOptions, Runtime},
    geo, inbound, subscription,
    subscription_store::{SubscriptionStore, SubscriptionUpdateOptions, DEFAULT_STORE_DIR},
};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "skyhook")]
#[command(version)]
#[command(about = "Rust-native Skyhook proxy engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(short, long, default_value = "skyhook.yaml")]
        config: PathBuf,
    },
    Check {
        #[arg(short, long, default_value = "skyhook.yaml")]
        config: PathBuf,
    },
    Probe {
        #[arg(short, long, default_value = "skyhook.yaml")]
        config: PathBuf,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        url: Option<String>,
    },
    ImportSubscription {
        #[arg(long, conflicts_with = "url")]
        file: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Subscriptions {
        #[command(subcommand)]
        command: SubscriptionCommand,
    },
    ExampleConfig,
}

#[derive(Subcommand)]
enum SubscriptionCommand {
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "skyhook=info,info".into()),
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

            tracing::info!(%mixed_addr, %control_addr, "starting skyhook");
            tokio::spawn(runtime.clone().background_probe_loop());
            tokio::spawn(background_subscription_update_loop(subscription_config));
            if runtime.config().l3.enabled && runtime.config().l3.auto_start {
                let statuses = runtime.start_l3_all().await;
                let started = statuses
                    .iter()
                    .filter(|item| {
                        matches!(
                            item.state,
                            skyhook::l3::L3TunnelState::Starting
                                | skyhook::l3::L3TunnelState::Handshaking
                                | skyhook::l3::L3TunnelState::Running
                        )
                    })
                    .count();
                tracing::info!(started, total = statuses.len(), "l3 auto-start requested");
            }

            let mut tasks = JoinSet::new();
            tasks.spawn(api::serve(runtime.clone()));
            if runtime.config().tun.enabled {
                match runtime.config().tun.backend {
                    TunBackend::Tun2Proxy => {
                        tasks.spawn(inbound::tun::serve(runtime.clone()));
                    }
                    TunBackend::NativeL3 => {
                        if let Some(l3_name) = runtime.config().tun.l3_profile.clone() {
                            let status = runtime.start_l3(&l3_name).await;
                            tracing::info!(
                                l3_profile = l3_name,
                                state = ?status.state,
                                "native_l3: l3 profile start requested"
                            );
                        } else {
                            anyhow::bail!(
                                "native_l3 tun backend requires tun.l3_profile to be set"
                            );
                        }
                        tasks.spawn(inbound::native_tun::serve(runtime.clone()));
                    }
                }
            }
            if runtime.config().dns.enabled && runtime.config().dns.listen.is_some() {
                tasks.spawn(inbound::dns::serve(runtime.clone()));
            }
            tasks.spawn(inbound::mixed::serve(runtime));

            if let Some(result) = tasks.join_next().await {
                result??;
            }
        }
        Command::Check { config } => {
            let config = load_runtime_config(&config).await?;
            println!("Skyhook config OK: {}", config.summary());
        }
        Command::Probe {
            config,
            timeout_ms,
            url,
        } => {
            let config = load_runtime_config(&config).await?;
            let runtime = Runtime::new(config)?;
            let results = runtime
                .probe_all_outbounds_with(ProbeOptions {
                    url,
                    timeout_ms,
                    include_failed: true,
                    ..ProbeOptions::default()
                })
                .await;
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
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
    if config.subscriptions.update_on_start {
        let store = SubscriptionStore::new(config.subscriptions.store_path.clone());
        match store
            .update_all_from_urls_with((&config.subscriptions).into())
            .await
        {
            Ok(results) => {
                let updated = results.iter().filter(|item| item.updated).count();
                tracing::info!(
                    updated,
                    total = results.len(),
                    "startup subscription update complete"
                );
            }
            Err(error) => {
                tracing::warn!(error = %error, "startup subscription update failed");
            }
        }
    }
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

async fn background_subscription_update_loop(config: SubscriptionConfig) {
    if !config.auto_update || config.update_interval_secs == 0 {
        return;
    }
    let store = SubscriptionStore::new(config.store_path.clone());
    loop {
        sleep(Duration::from_secs(config.update_interval_secs)).await;
        match store.update_all_from_urls_with((&config).into()).await {
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
                .header("User-Agent", concat!("Skyhook/", env!("CARGO_PKG_VERSION")))
                .send()
                .await?
                .error_for_status()?;
            Ok(response.text().await?)
        }
        (None, None) => Err(anyhow::anyhow!("provide --file or --url")),
        (Some(_), Some(_)) => Err(anyhow::anyhow!("provide only one of --file or --url")),
    }
}
