//! The `aos-registry-hub` binary: local-first registry hub server.
//!
//! Local-first operation is a hard requirement of RFC-0004: this binary +
//! a sqlite file + `file://` registry sources is a *complete* hub. The
//! one-machine loop:
//!
//! ```text
//! aos-registry-hub --root ~/hub registry add demo file:///srv/demo \
//!     --trust-key 'demo:Ed25519:AAAA…'
//! aos-registry-hub --root ~/hub serve --listen 127.0.0.1:8420
//! # apr release --upload-url file:///srv/demo …   (publish)
//! # apm: url = "http://127.0.0.1:8420/demo/"      (consume)
//! ```
//!
//! `serve --dev` boots zero-config with a root under the current
//! directory and a periodic background re-index.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use aos_registry_hub::db::{Database, RegistryRecord};
use aos_registry_hub::fetch::fetch_for_url;
use aos_registry_hub::indexer::index_and_record;
use aos_registry_hub::server::{router, AppState};
use aos_registry_hub::validation::validate_presence;

#[derive(Parser)]
#[command(name = "aos-registry-hub", version, about = "AOS registry hub server")]
struct Cli {
    /// Hub state directory (holds hub.db).
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the hub server.
    Serve {
        /// Listen address.
        #[arg(long, default_value = "127.0.0.1:8420")]
        listen: String,
        /// Zero-config development mode: defaults --root to ./.aos-hub.
        #[arg(long)]
        dev: bool,
        /// Externally reachable base URL for setup snippets.
        #[arg(long)]
        external_url: Option<String>,
        /// Seconds between background re-index runs (0 disables).
        #[arg(long, default_value_t = 60)]
        reindex_interval: u64,
    },
    /// Manage registered registries.
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Re-index one registry (or all) now.
    Index {
        /// Registry slug; omit to index everything.
        slug: Option<String>,
    },
}

#[derive(Subcommand)]
enum RegistryCommand {
    /// Register a registry surface for indexing and serving.
    Add {
        /// URL path slug to serve the registry under.
        slug: String,
        /// Surface source: file:///path, /path, or http(s)://….
        source_url: String,
        /// Trust anchor in name:Ed25519:<base64> form (repeatable).
        #[arg(long = "trust-key")]
        trust_keys: Vec<String>,
        /// Index without signature verification (displayed as unverified).
        #[arg(long)]
        no_verify: bool,
    },
    /// List registered registries.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber_init();
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            listen,
            dev,
            external_url,
            reindex_interval,
        } => {
            let root = resolve_root(cli.root, dev)?;
            let db = Arc::new(Database::open(&root.join("hub.db"))?);
            index_all(&db).await;

            if reindex_interval > 0 {
                let db = Arc::clone(&db);
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(reindex_interval));
                    tick.tick().await; // first tick fires immediately; we already indexed
                    loop {
                        tick.tick().await;
                        index_all(&db).await;
                    }
                });
            }

            let external_url = external_url.unwrap_or_else(|| format!("http://{listen}"));
            let state = Arc::new(AppState { db, external_url });
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            tracing::info!(%listen, root = %root.display(), "aos-registry-hub serving");
            axum::serve(listener, router(state)).await?;
        }
        Command::Registry { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                RegistryCommand::Add {
                    slug,
                    source_url,
                    trust_keys,
                    no_verify,
                } => {
                    validate_slug(&slug)?;
                    let id = db.register_registry(&slug, &source_url, &trust_keys, !no_verify)?;
                    let registry = db
                        .registry_by_slug(&slug)?
                        .context("registry vanished after registration")?;
                    let fetch = fetch_for_url(&source_url)?;
                    match index_and_record(&db, fetch.as_ref(), &registry).await {
                        Ok(outcome) => {
                            println!(
                                "registered '{slug}' (id {id}): {} packages, {} releases, {} channels @ {}",
                                outcome.packages, outcome.releases, outcome.channels, outcome.commit,
                            );
                            run_presence_validation(&db, &registry).await;
                        }
                        Err(err) => {
                            println!("registered '{slug}' (id {id}); initial index failed: {err:#}")
                        }
                    }
                }
                RegistryCommand::List => {
                    for registry in db.list_registries()? {
                        let state = db
                            .index_status(registry.id)?
                            .map(|s| s.state)
                            .unwrap_or_else(|| "unknown".into());
                        println!("{}\t{}\t{}", registry.slug, registry.source_url, state);
                    }
                }
            }
        }
        Command::Index { slug } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            let registries = match slug {
                Some(slug) => vec![db
                    .registry_by_slug(&slug)?
                    .with_context(|| format!("no registry '{slug}'"))?],
                None => db.list_registries()?,
            };
            for registry in registries {
                let fetch = fetch_for_url(&registry.source_url)?;
                match index_and_record(&db, fetch.as_ref(), &registry).await {
                    Ok(outcome) => {
                        println!(
                            "{}: {} packages, {} releases, {} channels @ {}",
                            registry.slug,
                            outcome.packages,
                            outcome.releases,
                            outcome.channels,
                            outcome.commit,
                        );
                        run_presence_validation(&db, &registry).await;
                    }
                    Err(err) => println!("{}: index failed: {err:#}", registry.slug),
                }
            }
        }
    }
    Ok(())
}

/// Index every registered registry, logging failures without aborting;
/// each successful index is followed by presence validation of the
/// registry's committed caches.
async fn index_all(db: &Database) {
    let registries = match db.list_registries() {
        Ok(regs) => regs,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "listing registries");
            return;
        }
    };
    for registry in registries {
        let fetch = match fetch_for_url(&registry.source_url) {
            Ok(fetch) => fetch,
            Err(err) => {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "bad source url");
                continue;
            }
        };
        match index_and_record(db, fetch.as_ref(), &registry).await {
            Ok(_) => run_presence_validation(db, &registry).await,
            Err(err) => {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "index failed");
            }
        }
    }
}

/// Run presence validation for one registry, logging a one-line summary
/// per cache; validation problems are logged, never fatal.
async fn run_presence_validation(db: &Database, registry: &RegistryRecord) {
    match validate_presence(db, registry).await {
        Ok(summaries) => {
            for summary in &summaries {
                tracing::info!(
                    slug = %registry.slug,
                    cache = %summary.cache_url,
                    checked = summary.checked,
                    missing = summary.missing,
                    reachable = summary.reachable,
                    coverage = %format!("{:.1}%", summary.coverage_percent),
                    "presence validation"
                );
            }
        }
        Err(err) => {
            tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "presence validation failed");
        }
    }
}

fn resolve_root(root: Option<PathBuf>, dev: bool) -> Result<PathBuf> {
    let root = match root {
        Some(root) => root,
        None if dev => PathBuf::from(".aos-hub"),
        None => anyhow::bail!("--root is required (or use `serve --dev`)"),
    };
    std::fs::create_dir_all(&root)
        .with_context(|| format!("creating hub root {}", root.display()))?;
    Ok(root)
}

/// Reject slugs that would collide with reserved top-level routes or the
/// `/-/` namespace.
fn validate_slug(slug: &str) -> Result<()> {
    const RESERVED: &[&str] = &[
        "_assets", "healthz", "-", "login", "activate", "account", "new", "oauth2", "api",
    ];
    if slug.is_empty()
        || RESERVED.contains(&slug)
        || !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "invalid slug '{slug}': lowercase ascii, digits, '-', '_' only, not a reserved name"
        );
    }
    Ok(())
}

fn tracing_subscriber_init() {
    // tracing is a workspace-wide dependency but the subscriber is not;
    // a minimal logger keeps the binary self-contained.
    struct StderrLogger;
    impl tracing::Subscriber for StderrLogger {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.level() <= &tracing::Level::INFO
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Visitor(String);
            impl tracing::field::Visit for Visitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }
            let mut visitor = Visitor(String::new());
            event.record(&mut visitor);
            eprintln!("[{}]{}", event.metadata().level(), visitor.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    let _ = tracing::subscriber::set_global_default(StderrLogger);
}
