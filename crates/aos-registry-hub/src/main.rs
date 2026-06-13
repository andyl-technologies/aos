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
    /// Manage organizations.
    Org {
        #[command(subcommand)]
        command: OrgCommand,
    },
    /// Manage projects within an org.
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Manage storage bindings within an org.
    Binding {
        #[command(subcommand)]
        command: BindingCommand,
    },
    /// Re-index one registry (or all) now.
    Index {
        /// Registry slug; omit to index everything.
        slug: Option<String>,
    },
    /// Manage provisioning tokens.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Print recent audit entries at (or below) a scope.
    Audit {
        /// Scope path to filter on (use "" for instance-wide).
        scope: String,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Mint a provisioning token scoped to a registry canonical path.
    ///
    /// The secret is printed exactly once and never stored in plaintext;
    /// the token is owned by an auto-created `publisher` service account in
    /// the registry's org. Use the secret with
    /// `apr origin upload --upload-url http://hub/<path> \
    ///  --header "Authorization: Bearer <secret>"` after exchanging it at
    /// `/oauth2/token`, or pass the exchanged JWT directly.
    Mint {
        /// Canonical registry path: org/project/name (project may be empty).
        path: String,
        /// Permission verb to grant (repeatable): publish, read.
        #[arg(long = "permission", default_values_t = vec!["publish".to_string()])]
        permissions: Vec<String>,
        /// Days until the token expires (omit for a non-expiring token).
        #[arg(long)]
        expires_days: Option<i64>,
        /// Service account that owns the token (auto-created in the org).
        #[arg(long, default_value = "publisher")]
        owner: String,
    },
}

#[derive(Subcommand)]
enum OrgCommand {
    /// Create an organization.
    Add {
        /// URL-safe org slug.
        slug: String,
        /// Human-readable org name.
        name: String,
    },
    /// List organizations.
    List,
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Create a project at a materialized path under an org.
    Add {
        /// Owning org slug.
        org: String,
        /// Materialized path (use "" for an org-root project).
        path: String,
        /// Human-readable project name.
        name: String,
    },
    /// List an org's projects.
    List {
        /// Owning org slug.
        org: String,
    },
}

#[derive(Subcommand)]
enum BindingCommand {
    /// Create a local_fs storage binding under an org.
    Add {
        /// Owning org slug.
        org: String,
        /// Binding name, unique within the org.
        name: String,
        /// Filesystem path the binding roots at.
        #[arg(long)]
        root: String,
    },
    /// List an org's storage bindings.
    List {
        /// Owning org slug.
        org: String,
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
    /// Create a managed (org-owned, storage-bound) registry.
    Create {
        /// Canonical path: org/project/name (project may be empty: org//name).
        path: String,
        /// Storage binding name within the org (omit for unbound).
        #[arg(long)]
        binding: Option<String>,
        /// Sub-prefix under the binding root.
        #[arg(long, default_value = "")]
        prefix: String,
        /// Visibility: public, internal, or private.
        #[arg(long, default_value = "private")]
        visibility: String,
        /// Trust anchor in name:Ed25519:<base64> form (repeatable).
        #[arg(long = "trust-key")]
        trust_keys: Vec<String>,
    },
    /// Change a registry's visibility through an audited change-set.
    SetVisibility {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// New visibility: public, internal, or private.
        visibility: String,
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
            let state = Arc::new(AppState::new(db, external_url));
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
                RegistryCommand::Create {
                    path,
                    binding,
                    prefix,
                    visibility,
                    trust_keys,
                } => {
                    let (org_slug, project_path, name) = parse_canonical_path(&path)?;
                    let org = db
                        .org_by_slug(org_slug)?
                        .with_context(|| format!("no org '{org_slug}'"))?;
                    let binding_id = match &binding {
                        Some(name) => Some(
                            db.storage_binding_by_name(org.id, name)?
                                .with_context(|| {
                                    format!("no storage binding '{name}' in org '{org_slug}'")
                                })?
                                .id,
                        ),
                        None => None,
                    };
                    let id = db.create_managed_registry(
                        org.id,
                        project_path,
                        name,
                        &visibility,
                        binding_id,
                        &prefix,
                        &trust_keys,
                        true,
                    )?;
                    let registry = db
                        .registry_by_scope(org_slug, project_path, name)?
                        .context("registry vanished after creation")?;
                    println!(
                        "created managed registry '{}' (id {id}, {visibility})",
                        registry.slug
                    );
                }
                RegistryCommand::SetVisibility {
                    canonical,
                    visibility,
                } => {
                    if !matches!(visibility.as_str(), "public" | "internal" | "private") {
                        anyhow::bail!(
                            "invalid visibility '{visibility}': public, internal, or private"
                        );
                    }
                    let registry = db
                        .registry_by_slug(&canonical)?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    // The CLI actor is the local operator: an out-of-band
                    // `system` principal (no IAM check on the local path).
                    let actor = aos_registry_hub::domain::Principal::user(0);
                    let change_id = aos_registry_hub::config::change_registry_visibility(
                        &db,
                        &actor,
                        "system",
                        registry.id,
                        &visibility,
                    )?;
                    println!(
                        "set '{canonical}' visibility to {visibility} (change-set {change_id})"
                    );
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
        Command::Org { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                OrgCommand::Add { slug, name } => {
                    let id = db.create_org(&slug, &name)?;
                    println!("created org '{slug}' (id {id})");
                }
                OrgCommand::List => {
                    for org in db.list_orgs()? {
                        println!("{}\t{}", org.slug, org.name);
                    }
                }
            }
        }
        Command::Project { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                ProjectCommand::Add { org, path, name } => {
                    let org_record = db
                        .org_by_slug(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    let id = db.create_project(org_record.id, &path, &name)?;
                    println!("created project '{org}/{path}' (id {id})");
                }
                ProjectCommand::List { org } => {
                    let org_record = db
                        .org_by_slug(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    for project in db.list_projects(org_record.id)? {
                        println!("{}\t{}", project.path, project.name);
                    }
                }
            }
        }
        Command::Binding { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                BindingCommand::Add {
                    org,
                    name,
                    root: binding_root,
                } => {
                    let org_record = db
                        .org_by_slug(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    let id =
                        db.create_storage_binding(org_record.id, &name, "local_fs", &binding_root)?;
                    println!("created binding '{org}/{name}' (id {id}) -> {binding_root}");
                }
                BindingCommand::List { org } => {
                    let org_record = db
                        .org_by_slug(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    for binding in db.list_storage_bindings(org_record.id)? {
                        println!("{}\t{}\t{}", binding.name, binding.kind, binding.root);
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
        Command::Token { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                TokenCommand::Mint {
                    path,
                    permissions,
                    expires_days,
                    owner,
                } => mint_token(&db, &path, &permissions, expires_days, &owner)?,
            }
        }
        Command::Audit { scope } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            for entry in db.list_audit(&scope)? {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    entry.created_at,
                    entry.actor_label,
                    entry.action,
                    entry.scope,
                    entry.change_id.as_deref().unwrap_or("-"),
                );
            }
        }
    }
    Ok(())
}

/// Mint a provisioning token scoped to a registry's canonical path.
///
/// The token is owned by the `owner` service account in the registry's org
/// (auto-created if absent), is granted the requested permissions at the
/// registry scope (so the JWT it exchanges for authorizes the upload
/// facade), and is also recorded as a membership of the service account at
/// that scope. The secret is printed exactly once.
fn mint_token(
    db: &Database,
    path: &str,
    permissions: &[String],
    expires_days: Option<i64>,
    owner: &str,
) -> Result<()> {
    let (org_slug, project_path, name) = parse_canonical_path(path)?;
    let org = db
        .org_by_slug(org_slug)?
        .with_context(|| format!("no org '{org_slug}'"))?;
    let canonical = if project_path.is_empty() {
        format!("{org_slug}/{name}")
    } else {
        format!("{org_slug}/{project_path}/{name}")
    };

    let mut perms = Vec::new();
    for verb in permissions {
        let perm = aos_registry_hub::auth::permission_from_str(verb)
            .with_context(|| format!("unknown permission '{verb}' (expected publish or read)"))?;
        perms.push(perm);
    }

    // Find or create the owning service account.
    let sa_id = match db.service_account_by_name(org.id, owner)? {
        Some(id) => id,
        None => db.create_service_account(org.id, owner)?,
    };
    let principal = aos_registry_hub::domain::Principal::service_account(sa_id);

    // Grant the service account a maintainer role at the registry scope so
    // its effective authority covers the token's grants.
    db.grant_membership(
        "service_account",
        sa_id,
        &canonical,
        aos_registry_hub::domain::Role::Maintainer.as_str(),
    )?;

    let expires_at = expires_days.map(|days| now_secs() + days * 86_400);
    let (token_id, secret) = db.create_token(
        principal,
        &canonical,
        &perms,
        Some(&format!("publisher token for {canonical}")),
        expires_at,
    )?;

    println!("minted token {token_id} for '{canonical}' (owner service account '{owner}')");
    println!("scope: {canonical}");
    println!(
        "permissions: {}",
        perms
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("secret (shown once): {secret}");
    Ok(())
}

/// Current Unix time in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

/// Parse a `org/project…/name` canonical path into its `(org, project_path,
/// name)` parts.
///
/// The first segment is the org, the last is the registry name, and
/// everything in between (joined with `/`) is the project's materialized
/// path — empty for an org-root registry, which is written `org//name` or
/// just `org/name`.
///
/// # Errors
///
/// Returns an error when the path has fewer than two `/`-separated segments
/// (no org and name) or any non-project segment is empty.
fn parse_canonical_path(path: &str) -> Result<(&str, &str, &str), anyhow::Error> {
    let trimmed = path.trim_matches('/');
    let (org, rest) = trimmed
        .split_once('/')
        .with_context(|| format!("canonical path '{path}' must be org/project/name"))?;
    let (project_path, name) = match rest.rsplit_once('/') {
        Some((project, name)) => (project, name),
        None => ("", rest),
    };
    if org.is_empty() || name.is_empty() {
        anyhow::bail!("canonical path '{path}' must have a non-empty org and name");
    }
    Ok((org, project_path, name))
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
