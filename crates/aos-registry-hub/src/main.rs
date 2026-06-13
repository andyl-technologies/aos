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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

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
    /// Configure an org's OIDC single sign-on identity provider.
    Idp {
        #[command(subcommand)]
        command: IdpCommand,
    },
    /// Capture and verify email domains for SSO routing.
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },
    /// Manage hosted (hub-held) signing keys for an org.
    HostedKey {
        #[command(subcommand)]
        command: HostedKeyCommand,
    },
    /// Operate on a registry's channels.
    Channel {
        #[command(subcommand)]
        command: ChannelCommand,
    },
    /// Manage an org's outbound webhooks.
    Webhook {
        #[command(subcommand)]
        command: WebhookCommand,
    },
    /// Instance-wide settings (signup policy).
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    /// Run consistency validation and repairs against a registry's caches.
    Validate {
        #[command(subcommand)]
        command: ValidateCommand,
    },
    /// Mirror an upstream registry (full or pull-through).
    Mirror {
        #[command(subcommand)]
        command: MirrorCommand,
    },
    /// Manage a registry's serving frontends (direct or proxied domains).
    Frontend {
        #[command(subcommand)]
        command: FrontendCommand,
    },
}

#[derive(Subcommand)]
enum MirrorCommand {
    /// Mark a registry as a mirror of an upstream registry.
    ///
    /// `full` copies the verified upstream surface into the local binding on a
    /// schedule (set the mirror's trust keys to the upstream's anchors so
    /// consumers keep upstream trust). `pullthrough` serves reads by
    /// fetch-on-miss from upstream. `derived` (re-signed under the org's own
    /// roster) is deferred past v1 and rejected.
    Add {
        /// Canonical registry path or flat slug of the local mirror registry.
        canonical: String,
        /// Upstream registry surface URL (file:///path, /path, or http(s)://…).
        upstream_url: String,
        /// Mirror mode: full, pullthrough, or derived (deferred).
        #[arg(long, default_value = "full")]
        mode: String,
        /// Full-mirror sync cadence in seconds.
        #[arg(long = "schedule-secs", default_value_t = 3600)]
        schedule_secs: i64,
    },
    /// Run a full-mirror sync now (verify the upstream and copy it locally).
    Sync {
        /// Canonical registry path or flat slug of the local mirror registry.
        canonical: String,
    },
    /// Show a mirror's upstream, mode, and last sync state.
    Status {
        /// Canonical registry path or flat slug of the local mirror registry.
        canonical: String,
    },
}

#[derive(Subcommand)]
enum FrontendCommand {
    /// Add a serving frontend (domain) to a registry.
    Add {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// Domain the frontend serves (e.g. cdn.acme.com).
        domain: String,
        /// Serving mode: direct (probe-only) or proxied (hub facade).
        #[arg(long, default_value = "direct")]
        mode: String,
        /// Path prefix under the domain the surface lives at.
        #[arg(long = "base-path", default_value = "")]
        base_path: String,
        /// Consumer cache priority for an advertised cache frontend.
        #[arg(long, default_value_t = 100)]
        priority: i64,
    },
    /// List a registry's frontends.
    List {
        /// Canonical registry path or flat slug.
        canonical: String,
    },
}

#[derive(Subcommand)]
enum ValidateCommand {
    /// Run validation at a depth: presence (default), integrity, or deep.
    Run {
        /// Canonical registry slug to validate.
        canonical: String,
        /// Validation depth: presence | integrity | deep.
        #[arg(long, default_value = "presence")]
        depth: String,
    },
    /// Plan and execute repairs for a registry's missing cache objects.
    ///
    /// Copies missing objects from a cache that has them into caches that are
    /// missing them. file:// targets are repaired by copy; hub-served http
    /// facade targets by authenticated PUT; other http targets are left
    /// plan-only.
    Repair {
        /// Canonical registry slug to repair.
        canonical: String,
        /// Externally reachable base URL identifying this hub's facade caches.
        #[arg(long)]
        external_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum InstanceCommand {
    /// Set the instance signup policy: open or invite_only.
    SetSignupPolicy {
        /// New policy: `open` or `invite_only`.
        policy: String,
    },
    /// Show the current instance signup policy.
    ShowSignupPolicy,
}

#[derive(Subcommand)]
enum WebhookCommand {
    /// Subscribe an org's endpoint to registry events (prints the secret once).
    Add {
        /// Owning org slug.
        org: String,
        /// Destination URL events are POSTed to.
        url: String,
        /// Event type to subscribe to (repeatable; omit for all events).
        #[arg(long = "event")]
        events: Vec<String>,
        /// Shared HMAC secret (a random one is generated when omitted).
        #[arg(long)]
        secret: Option<String>,
    },
    /// List an org's webhook subscriptions (secrets are not shown).
    List {
        /// Owning org slug.
        org: String,
    },
    /// Remove a webhook by id.
    Rm {
        /// Webhook id.
        id: i64,
    },
}

#[derive(Subcommand)]
enum HostedKeyCommand {
    /// Enroll a fresh hosted signing key for an org (prints the public line).
    Create {
        /// Owning org slug.
        org: String,
        /// Operator-chosen key id, unique within the org.
        key_id: String,
    },
    /// Attach a hosted key to a registry (the direct web-advance path).
    Attach {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// Hosted key id within the registry's owning org.
        key_id: String,
    },
    /// List an org's hosted signing keys.
    List {
        /// Owning org slug.
        org: String,
    },
}

#[derive(Subcommand)]
enum ChannelCommand {
    /// Advance a channel server-side using the registry's hosted key.
    Advance {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// Channel name to advance.
        channel: String,
        /// Target release semver (must already be published).
        semver: String,
        /// Number of partitions to move (1–256).
        #[arg(long, default_value_t = 256)]
        count: usize,
    },
}

#[derive(Subcommand)]
enum IdpCommand {
    /// Set (or replace) an org's OIDC identity provider.
    Set(Box<IdpSetArgs>),
    /// Show an org's configured IdP (the client secret is never printed).
    Show {
        /// Owning org slug.
        org: String,
    },
}

/// Arguments for `idp set` (boxed in [`IdpCommand`] to keep variants small).
#[derive(Args)]
struct IdpSetArgs {
    /// Owning org slug.
    org: String,
    /// IdP issuer (the id_token `iss`).
    #[arg(long)]
    issuer: String,
    /// OAuth2 authorization endpoint.
    #[arg(long = "auth-url")]
    auth_url: String,
    /// OAuth2 token endpoint.
    #[arg(long = "token-url")]
    token_url: String,
    /// JWKS endpoint (RS256 signing keys).
    #[arg(long = "jwks-uri")]
    jwks_uri: String,
    /// OAuth2 client id.
    #[arg(long = "client-id")]
    client_id: String,
    /// OAuth2 client secret (sealed at rest; omit for a public client).
    #[arg(long = "client-secret")]
    client_secret: Option<String>,
    /// Space-separated scopes to request.
    #[arg(long, default_value = "openid email profile")]
    scopes: String,
    /// id_token claim carrying the user's groups.
    #[arg(long = "groups-claim")]
    groups_claim: Option<String>,
    /// group->role mapping as a JSON object (e.g. '{"admins":"admin"}').
    #[arg(long = "role-map", default_value = "{}")]
    role_map: String,
    /// Force org members through SSO (email-first login redirects).
    #[arg(long = "enforce-sso")]
    enforce_sso: bool,
    /// Disable just-in-time provisioning of unknown identities.
    #[arg(long = "no-jit")]
    no_jit: bool,
    /// Role a JIT user receives when no group maps.
    #[arg(long = "default-role", default_value = "viewer")]
    default_role: String,
}

#[derive(Subcommand)]
enum DomainCommand {
    /// Claim a domain for an org and print the DNS-TXT challenge to publish.
    Add {
        /// Owning org slug.
        org: String,
        /// Email domain to capture (e.g. acme.com).
        domain: String,
    },
    /// Verify a claimed domain.
    ///
    /// Offline-testable: pass `--txt <value>` to supply the resolved TXT
    /// record; it is matched against the stored challenge before the domain is
    /// marked verified. With no `--txt`, the domain is marked verified
    /// unconditionally (operators wire a real DNS resolver here).
    Verify {
        /// Domain to verify.
        domain: String,
        /// The TXT record value resolved from DNS (matched against the
        /// challenge).
        #[arg(long)]
        txt: Option<String>,
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
    /// Set per-org quota caps (omit a flag to leave that cap unlimited).
    SetQuota {
        /// Org slug.
        org: String,
        /// Maximum total stored bytes.
        #[arg(long = "max-bytes")]
        max_bytes: Option<i64>,
        /// Maximum total stored objects.
        #[arg(long = "max-objects")]
        max_objects: Option<i64>,
        /// Maximum number of registries.
        #[arg(long = "max-registries")]
        max_registries: Option<i64>,
        /// Maximum number of active tokens.
        #[arg(long = "max-tokens")]
        max_tokens: Option<i64>,
    },
    /// Export an org's SoR + registry surfaces to a directory.
    Export {
        /// Org slug.
        org: String,
        /// Output directory (manifest.json + per-registry surface copies).
        #[arg(long)]
        output: PathBuf,
    },
    /// Soft-delete an org with a grace window (default 30 days).
    Delete {
        /// Org slug.
        org: String,
        /// Grace window in days before the org is eligible for hard purge.
        #[arg(long, default_value_t = 30)]
        grace_days: i64,
    },
    /// Restore a soft-deleted org within its grace window.
    Restore {
        /// Org slug.
        org: String,
    },
    /// Hard-purge every soft-deleted org past its grace window now.
    Purge,
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
                        // Full mirrors due for a scheduled sync: verify the
                        // upstream surface and copy it into the local binding.
                        sync_due_mirrors(&db, now_secs()).await;
                        // Offboarding: hard-purge orgs past their grace window.
                        match aos_registry_hub::export::purge_expired_orgs(&db, now_secs()) {
                            Ok(purged) => {
                                for slug in &purged {
                                    tracing::info!(org = %slug, "purged expired org");
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %format!("{err:#}"), "org purge failed");
                            }
                        }
                        // Retention: prune repair-job history past the window so
                        // the append-only audit table cannot grow without bound.
                        let cutoff = now_secs() - REPAIR_JOB_RETENTION_SECS;
                        match db.prune_repair_jobs(cutoff) {
                            Ok(pruned) if pruned > 0 => {
                                tracing::info!(pruned, "pruned old repair jobs");
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(
                                    error = %format!("{err:#}"),
                                    "repair-job prune failed"
                                );
                            }
                        }
                    }
                });
            }

            // Drain the outbound-webhook delivery queue in the background.
            tokio::spawn(aos_registry_hub::webhook::run_delivery_worker(
                Arc::clone(&db),
                aos_registry_hub::fetch::hardened_client(),
            ));

            let external_url = external_url.unwrap_or_else(|| format!("http://{listen}"));
            let mut app_state = AppState::new(db, external_url);
            // In dev mode the "check your email" page shows the magic link
            // inline (the default LogMailer logs rather than sends).
            app_state.dev = dev;
            // Seal at-rest secrets (OIDC client secrets, hosted-key seeds) with
            // a real AES-256-GCM sealer keyed by the persisted instance key.
            // `--dev` keeps the reproducible XOR placeholder so local testing
            // does not depend on a generated key file.
            if !dev {
                app_state.sealer = aos_registry_hub::auth::seal::instance_sealer(&root)?.into();
            }
            let state = Arc::new(app_state);
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            tracing::info!(%listen, root = %root.display(), "aos-registry-hub serving");
            // `into_make_service_with_connect_info` injects the TCP peer
            // address as `ConnectInfo<SocketAddr>` so the rate limiter keys on
            // the real client when no trusted proxy fronts the hub.
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
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
                OrgCommand::SetQuota {
                    org,
                    max_bytes,
                    max_objects,
                    max_registries,
                    max_tokens,
                } => {
                    let org_record = db
                        .org_by_slug(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    db.set_org_quota(
                        org_record.id,
                        &aos_registry_hub::db::OrgQuota {
                            max_bytes,
                            max_objects,
                            max_registries,
                            max_tokens,
                        },
                    )?;
                    println!("set quota for org '{org}'");
                }
                OrgCommand::Export { org, output } => {
                    run_org_export(&db, &org, &output)?;
                }
                OrgCommand::Delete { org, grace_days } => {
                    let org_record = db
                        .org_by_slug_including_deleted(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    let grace_secs = grace_days.max(0) * 86_400;
                    if db.soft_delete_org(org_record.id, grace_secs)? {
                        println!(
                            "soft-deleted org '{org}' (grace {grace_days}d); it stops serving now \
                             and is purgeable after the grace window. Run `org export` first to \
                             keep a copy, or `org restore {org}` to undo."
                        );
                    } else {
                        println!("org '{org}' is already soft-deleted");
                    }
                }
                OrgCommand::Restore { org } => {
                    let org_record = db
                        .org_by_slug_including_deleted(&org)?
                        .with_context(|| format!("no org '{org}'"))?;
                    if db.restore_org(org_record.id)? {
                        println!("restored org '{org}'");
                    } else {
                        println!("org '{org}' was not soft-deleted");
                    }
                }
                OrgCommand::Purge => {
                    let purged = aos_registry_hub::export::purge_expired_orgs(&db, now_secs())?;
                    if purged.is_empty() {
                        println!("no orgs past their grace window");
                    } else {
                        for slug in &purged {
                            println!("purged org '{slug}'");
                        }
                    }
                }
            }
        }
        Command::Instance { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                InstanceCommand::SetSignupPolicy { policy } => {
                    let parsed = match policy.as_str() {
                        "open" => aos_registry_hub::db::SignupPolicy::Open,
                        "invite_only" => aos_registry_hub::db::SignupPolicy::InviteOnly,
                        other => {
                            anyhow::bail!("invalid policy '{other}': open or invite_only")
                        }
                    };
                    db.set_signup_policy(parsed)?;
                    println!("signup policy set to {}", parsed.as_str());
                }
                InstanceCommand::ShowSignupPolicy => {
                    println!("{}", db.signup_policy()?.as_str());
                }
            }
        }
        Command::Validate { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            match command {
                ValidateCommand::Run { canonical, depth } => {
                    let registry = db
                        .registry_by_slug(&canonical)?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    let depth = parse_depth(&depth)?;
                    let summaries =
                        aos_registry_hub::validation::validate_registry(&db, &registry, depth)
                            .await?;
                    for summary in &summaries {
                        println!(
                            "{}\tchecked={}\tmissing={}\tcorrupt={}\tcoverage={:.0}%\treachable={}",
                            summary.cache_url,
                            summary.checked,
                            summary.missing,
                            summary.corrupt,
                            summary.coverage_percent,
                            summary.reachable,
                        );
                    }
                }
                ValidateCommand::Repair {
                    canonical,
                    external_url,
                } => {
                    let registry = db
                        .registry_by_slug(&canonical)?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    // Validate presence first so the repair plan reflects the
                    // current cache state.
                    aos_registry_hub::validation::validate_presence(&db, &registry).await?;
                    let external_url =
                        external_url.unwrap_or_else(|| "http://127.0.0.1:8420".to_string());
                    let db = std::sync::Arc::new(db);
                    let authorizer = aos_registry_hub::server::HubRepairAuthorizer::new(
                        std::sync::Arc::clone(&db),
                        aos_registry_hub::auth::jwt::JwtKeys::random(),
                        external_url,
                    );
                    let client = aos_registry_hub::fetch::hardened_client();
                    let summary = aos_registry_hub::validation::run_repairs(
                        &db,
                        &client,
                        &registry,
                        &authorizer,
                    )
                    .await?;
                    println!(
                        "repairs: {} done, {} plan-only, {} failed",
                        summary.done, summary.plan_only, summary.failed,
                    );
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
        Command::Idp { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_idp_command(&db, &root, command)?;
        }
        Command::Domain { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_domain_command(&db, command)?;
        }
        Command::HostedKey { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_hosted_key_command(&db, &root, command)?;
        }
        Command::Channel { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_channel_command(&db, &root, command).await?;
        }
        Command::Webhook { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_webhook_command(&db, command)?;
        }
        Command::Mirror { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_mirror_command(&db, command).await?;
        }
        Command::Frontend { command } => {
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db"))?;
            run_frontend_command(&db, command)?;
        }
    }
    Ok(())
}

/// Handle the `mirror add`/`sync`/`status` subcommands.
///
/// `add` records the upstream + mode (rejecting `derived`, which is deferred);
/// `sync` runs a full-mirror sync now; `status` prints the upstream, mode, and
/// last-sync record.
async fn run_mirror_command(db: &Database, command: MirrorCommand) -> Result<()> {
    match command {
        MirrorCommand::Add {
            canonical,
            upstream_url,
            mode,
            schedule_secs,
        } => {
            if mode == "derived" {
                anyhow::bail!(
                    "derived mirroring (re-signing under the org's own roster) is deferred \
                     past v1 (RFC-0004 \"Mirroring other registries\", mode 2); use \
                     --mode full or --mode pullthrough"
                );
            }
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            db.create_mirror_source(registry.id, &upstream_url, &mode, true, schedule_secs)?;
            println!(
                "registry '{}' is now a {mode} mirror of {upstream_url}",
                registry.slug
            );
            if mode == "full" {
                println!(
                    "note: set this mirror's trust keys to the upstream's anchors so consumers \
                     keep upstream trust; run `mirror sync {canonical}` to sync now."
                );
            }
        }
        MirrorCommand::Sync { canonical } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let result = aos_registry_hub::mirror::sync_full_mirror(db, &registry).await?;
            println!(
                "synced '{}' @ {} · {} files · frontier {} · {} releases · {} channels",
                registry.slug,
                result.commit,
                result.files_copied,
                result.frontier.as_deref().unwrap_or("-"),
                result.releases,
                result.channels,
            );
        }
        MirrorCommand::Status { canonical } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            match db.mirror_source(registry.id)? {
                Some(source) => {
                    println!("upstream:   {}", source.upstream_url);
                    println!("mode:       {}", source.mode);
                    println!("verify:     {}", source.verify);
                    println!("schedule:   {}s", source.schedule_secs);
                    println!(
                        "last sync:  {} ({})",
                        source
                            .last_sync_at
                            .map(|t| t.to_string())
                            .unwrap_or_else(|| "never".into()),
                        source.last_sync_status.as_deref().unwrap_or("-"),
                    );
                    if let Some(error) = &source.last_sync_error {
                        println!("last error: {error}");
                    }
                    println!(
                        "frontier:   {}",
                        source.upstream_frontier.as_deref().unwrap_or("-")
                    );
                }
                None => println!("registry '{canonical}' is not a mirror"),
            }
        }
    }
    Ok(())
}

/// Handle the `frontend add`/`list` subcommands.
fn run_frontend_command(db: &Database, command: FrontendCommand) -> Result<()> {
    match command {
        FrontendCommand::Add {
            canonical,
            domain,
            mode,
            base_path,
            priority,
        } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let id = db.create_frontend(
                registry.id,
                &domain,
                &base_path,
                &mode,
                true,
                true,
                true,
                priority,
                true,
            )?;
            println!(
                "added {mode} frontend {id} for '{}': {domain}{base_path} (priority {priority})",
                registry.slug
            );
        }
        FrontendCommand::List { canonical } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            for frontend in db.list_frontends(registry.id)? {
                println!(
                    "{}\t{}{}\t{}\tpriority={}\tadvertised={}",
                    frontend.id,
                    frontend.domain,
                    frontend.base_path,
                    frontend.mode,
                    frontend.consumer_priority,
                    frontend.advertised,
                );
            }
        }
    }
    Ok(())
}

/// Handle the `webhook add`/`list`/`rm` subcommands.
///
/// `add` creates a subscription (generating a random HMAC secret when none is
/// supplied) and prints the secret exactly once; `list` shows an org's hooks
/// without their secrets; `rm` deletes one by id.
fn run_webhook_command(db: &Database, command: WebhookCommand) -> Result<()> {
    match command {
        WebhookCommand::Add {
            org,
            url,
            events,
            secret,
        } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            let secret =
                secret.unwrap_or_else(|| aos_registry_hub::auth::token::generate_token().0);
            let id = db.create_webhook(org_record.id, &url, &secret, &events)?;
            let subscribed = if events.is_empty() {
                "all events".to_string()
            } else {
                events.join(", ")
            };
            println!("created webhook {id} for org '{org}' -> {url} ({subscribed})");
            println!("signing secret (shown once): {secret}");
        }
        WebhookCommand::List { org } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            for hook in db.list_webhooks(org_record.id)? {
                let events = if hook.events.is_empty() {
                    "*".to_string()
                } else {
                    hook.events.join(",")
                };
                let state = if hook.active { "active" } else { "disabled" };
                println!("{}\t{}\t{}\t{}", hook.id, hook.url, events, state);
            }
        }
        WebhookCommand::Rm { id } => {
            if db.delete_webhook(id)? {
                println!("removed webhook {id}");
            } else {
                anyhow::bail!("no webhook with id {id}");
            }
        }
    }
    Ok(())
}

/// Handle the `hosted-key create`/`attach`/`list` subcommands.
///
/// `create` enrolls a key and prints its public trusted-key line (the only
/// time the public anchor is surfaced for copying); `attach` binds a key to a
/// registry; `list` shows an org's keys. The seed is sealed with the same
/// [`instance_sealer`](aos_registry_hub::auth::seal::instance_sealer) the
/// server uses, so the seed round-trips between this CLI and `serve`.
fn run_hosted_key_command(db: &Database, root: &Path, command: HostedKeyCommand) -> Result<()> {
    use aos_registry_hub::auth::seal::instance_sealer;
    match command {
        HostedKeyCommand::Create { org, key_id } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            let sealer = instance_sealer(root)?;
            let public = db.create_hosted_key(sealer.as_ref(), org_record.id, &key_id)?;
            println!("enrolled hosted key '{key_id}' in org '{org}'");
            println!("pin this trusted-key line as a registry anchor:");
            println!("{public}");
        }
        HostedKeyCommand::Attach { canonical, key_id } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let org_id = registry
                .org_id
                .with_context(|| format!("registry '{canonical}' is not org-owned"))?;
            let key = db
                .hosted_key_by_name(org_id, &key_id)?
                .with_context(|| format!("no hosted key '{key_id}' in the registry's org"))?;
            db.set_registry_hosted_key(registry.id, Some(key.id))?;
            println!(
                "attached hosted key '{key_id}' to registry '{}'",
                registry.slug
            );
        }
        HostedKeyCommand::List { org } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            for key in db.list_hosted_keys(org_record.id)? {
                println!("{}\t{}", key.key_id, key.public_key);
            }
        }
    }
    Ok(())
}

/// Handle the `channel advance` subcommand: a direct, hub-signed advance.
///
/// This is the hosted-key path. It errors clearly when the registry has no
/// hosted key, pointing at the prepared-operation/CLI flow instead.
async fn run_channel_command(db: &Database, root: &Path, command: ChannelCommand) -> Result<()> {
    use aos_registry_hub::auth::seal::instance_sealer;
    match command {
        ChannelCommand::Advance {
            canonical,
            channel,
            semver,
            count,
        } => {
            let registry = db
                .registry_by_slug(&canonical)?
                .with_context(|| format!("no registry '{canonical}'"))?;
            if registry.hosted_key_id.is_none() {
                anyhow::bail!(
                    "registry '{canonical}' has no hosted signing key; prepare the advance for \
                     client-side signing in the console (apr channel advance --from-hub), or \
                     attach a hosted key with `hosted-key attach`"
                );
            }
            let sealer = instance_sealer(root)?;
            let when = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let outcome = aos_registry_hub::signing::advance_channel(
                db,
                sealer.as_ref(),
                &registry,
                &channel,
                &semver,
                count.clamp(1, 256),
                when,
            )
            .await?;
            println!(
                "advanced '{}' to {} · {} partition(s) moved · {}% rolled out ({} of 256)",
                outcome.channel,
                outcome.release,
                outcome.moved,
                outcome.rollout_percent,
                outcome.at_target,
            );
        }
    }
    Ok(())
}

/// Handle the `idp set`/`idp show` subcommands.
///
/// `set` seals the client secret with the same
/// [`instance_sealer`](aos_registry_hub::auth::seal::instance_sealer) the
/// server uses before storing it, so the secret round-trips to `serve`;
/// `show` prints the configuration with the secret redacted.
fn run_idp_command(db: &Database, root: &Path, command: IdpCommand) -> Result<()> {
    use aos_registry_hub::auth::seal::instance_sealer;
    use aos_registry_hub::db::IdpConfigRecord;
    match command {
        IdpCommand::Set(args) => {
            let IdpSetArgs {
                org,
                issuer,
                auth_url,
                token_url,
                jwks_uri,
                client_id,
                client_secret,
                scopes,
                groups_claim,
                role_map,
                enforce_sso,
                no_jit,
                default_role,
            } = *args;
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            // Validate the role map and default role parse before storing.
            let _: serde_json::Value = serde_json::from_str(&role_map)
                .with_context(|| "--role-map must be a JSON object")?;
            if aos_registry_hub::domain::Role::parse(&default_role).is_none() {
                anyhow::bail!("invalid --default-role '{default_role}'");
            }
            let sealer = instance_sealer(root)?;
            let client_secret_enc = match &client_secret {
                Some(secret) => Some(sealer.seal(secret)?),
                None => None,
            };
            db.upsert_idp_config(&IdpConfigRecord {
                org_id: org_record.id,
                issuer,
                authorization_endpoint: auth_url,
                token_endpoint: token_url,
                jwks_uri,
                client_id,
                client_secret_enc,
                scopes,
                groups_claim,
                role_map_json: role_map,
                allow_jit: !no_jit,
                enforce_sso,
                default_role,
            })?;
            println!("configured OIDC IdP for org '{org}'");
        }
        IdpCommand::Show { org } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            match db.idp_config(org_record.id)? {
                Some(config) => {
                    println!("issuer:        {}", config.issuer);
                    println!("authorize:     {}", config.authorization_endpoint);
                    println!("token:         {}", config.token_endpoint);
                    println!("jwks:          {}", config.jwks_uri);
                    println!("client_id:     {}", config.client_id);
                    println!(
                        "client_secret: {}",
                        if config.client_secret_enc.is_some() {
                            "(sealed)"
                        } else {
                            "(none)"
                        }
                    );
                    println!("scopes:        {}", config.scopes);
                    println!(
                        "groups_claim:  {}",
                        config.groups_claim.as_deref().unwrap_or("-")
                    );
                    println!("role_map:      {}", config.role_map_json);
                    println!("allow_jit:     {}", config.allow_jit);
                    println!("enforce_sso:   {}", config.enforce_sso);
                    println!("default_role:  {}", config.default_role);
                }
                None => println!("org '{org}' has no OIDC IdP configured"),
            }
        }
    }
    Ok(())
}

/// Handle the `domain add`/`domain verify` subcommands.
fn run_domain_command(db: &Database, command: DomainCommand) -> Result<()> {
    match command {
        DomainCommand::Add { org, domain } => {
            let org_record = db
                .org_by_slug(&org)?
                .with_context(|| format!("no org '{org}'"))?;
            let challenge = db.add_org_domain(org_record.id, &domain)?;
            println!("claimed '{domain}' for org '{org}' (unverified)");
            println!("publish this TXT record at the domain, then run `domain verify`:");
            println!("  {challenge}");
        }
        DomainCommand::Verify { domain, txt } => {
            let record = db
                .org_domain(&domain)?
                .with_context(|| format!("domain '{domain}' is not claimed by any org"))?;
            if let Some(txt) = &txt {
                if txt.trim() != record.txt_challenge {
                    anyhow::bail!(
                        "TXT value does not match the challenge for '{domain}' (expected '{}')",
                        record.txt_challenge
                    );
                }
            }
            if db.verify_org_domain(&domain)? {
                println!("verified '{domain}'");
            } else {
                println!("domain '{domain}' is not claimed");
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

    // Per-org active-token quota (NULL/unset = unlimited).
    if let Some(max_tokens) = db.org_quota(org.id)?.max_tokens {
        if db.org_active_token_count(org.id)? >= max_tokens {
            anyhow::bail!("org active-token quota of {max_tokens} reached");
        }
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

/// How long a `repair_jobs` history row is retained before the serve loop
/// prunes it (30 days).
///
/// The repair-job table is an append-only audit; this retention bounds its
/// growth while keeping recent history for the health page.
const REPAIR_JOB_RETENTION_SECS: i64 = 30 * 86_400;

/// Current Unix time in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Export an org's SoR manifest and registry surfaces to `output`.
///
/// Writes `output/manifest.json` (the redacted SQL system of record) plus one
/// directory per registry under `output/registries/<slug-with-slashes>/`,
/// each a portable, re-servable surface copy.
fn run_org_export(db: &Database, org: &str, output: &Path) -> Result<()> {
    use aos_registry_hub::export::{export_org, export_registry_surface};

    std::fs::create_dir_all(output)
        .with_context(|| format!("creating export dir {}", output.display()))?;
    let manifest = export_org(db, org)?;
    let manifest_path = output.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    println!("wrote {}", manifest_path.display());

    // Copy each registry's surface (resolved through its storage binding).
    let org_record = db
        .org_by_slug_including_deleted(org)?
        .with_context(|| format!("no org '{org}'"))?;
    for registry in db.list_registries_including_org(org_record.id)? {
        let dest = output
            .join("registries")
            .join(registry.slug.replace('/', "_"));
        let copied = export_registry_surface(db, registry.id, &dest)?;
        if copied > 0 {
            println!(
                "copied {copied} surface files for '{}' -> {}",
                registry.slug,
                dest.display()
            );
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
            Ok(_) => {
                run_presence_validation(db, &registry).await;
                run_cache_probes(db, &registry).await;
                run_frontend_probes(db, &registry).await;
            }
            Err(err) => {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "index failed");
            }
        }
    }
}

/// Sync every full mirror whose schedule is due, then re-probe its frontends.
///
/// A full mirror is *due* when it has never synced or `schedule_secs` have
/// elapsed since its last attempt. Each sync verifies the upstream surface and
/// copies it into the local binding; a verification failure is recorded and
/// logged, never fatal to the loop.
async fn sync_due_mirrors(db: &Database, now: i64) {
    let sources = match db.list_mirror_sources() {
        Ok(sources) => sources,
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "listing mirror sources");
            return;
        }
    };
    for (registry_id, source) in sources {
        if source.mode != "full" {
            continue; // pull-through mirrors are served on demand, not synced.
        }
        let due = match source.last_sync_at {
            None => true,
            Some(last) => now - last >= source.schedule_secs,
        };
        if !due {
            continue;
        }
        let registry = match db.registry_by_id(registry_id) {
            Ok(Some(registry)) => registry,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "loading mirror registry");
                continue;
            }
        };
        match aos_registry_hub::mirror::sync_full_mirror(db, &registry).await {
            Ok(result) => tracing::info!(
                slug = %registry.slug,
                commit = %result.commit,
                files = result.files_copied,
                "full mirror synced"
            ),
            Err(err) => tracing::warn!(
                slug = %registry.slug,
                error = %format!("{err:#}"),
                "full mirror sync failed"
            ),
        }
    }
}

/// Probe each configured frontend's freshness for one registry, logging a
/// one-line summary per frontend; probe failures are logged, never fatal.
async fn run_frontend_probes(db: &Database, registry: &RegistryRecord) {
    let http = aos_registry_hub::fetch::hardened_client();
    match aos_registry_hub::probe::probe_frontends(db, &http, registry).await {
        Ok(probes) => {
            for probe in &probes {
                tracing::info!(
                    slug = %registry.slug,
                    frontend = %probe.base_url,
                    status = %probe.status.as_str(),
                    lag = ?probe.lag_releases,
                    latency_ms = probe.latency_ms,
                    "frontend freshness probe"
                );
            }
        }
        Err(err) => {
            tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "frontend probe failed");
        }
    }
}

/// Probe each committed cache's freshness for one registry, logging a one-line
/// summary per cache; probe failures are logged, never fatal.
async fn run_cache_probes(db: &Database, registry: &RegistryRecord) {
    let http = aos_registry_hub::fetch::hardened_client();
    match aos_registry_hub::probe::probe_caches(db, &http, registry).await {
        Ok(probes) => {
            for probe in &probes {
                tracing::info!(
                    slug = %registry.slug,
                    cache = %probe.cache_url,
                    status = %probe.status.as_str(),
                    latency_ms = probe.latency_ms,
                    "cache freshness probe"
                );
            }
        }
        Err(err) => {
            tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "cache probe failed");
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

/// Parse a validation-depth CLI argument.
fn parse_depth(depth: &str) -> Result<aos_registry_hub::validation::ValidationDepth> {
    use aos_registry_hub::validation::ValidationDepth;
    match depth {
        "presence" => Ok(ValidationDepth::Presence),
        "integrity" => Ok(ValidationDepth::Integrity),
        "deep" => Ok(ValidationDepth::Deep),
        other => anyhow::bail!("invalid depth '{other}': presence, integrity, or deep"),
    }
}

/// Reject slugs that would collide with reserved top-level routes or the
/// `/-/` namespace.
fn validate_slug(slug: &str) -> Result<()> {
    const RESERVED: &[&str] = &[
        "_assets", "healthz", "metrics", "-", "login", "activate", "account", "new", "oauth2",
        "api",
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
