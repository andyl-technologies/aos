//! The `aos-hub` binary: local-first registry hub server.
//!
//! Local-first operation is a hard requirement of RFC-0004: this binary, a
//! SQLite database, and local storage bindings form a complete hub. Ordinary
//! organization, registry, cache, binding, and delivery administration uses
//! the typed `aos hub` API; this process binary owns serving, indexing,
//! validation, deployment, and recovery only. A one-machine serving loop is:
//!
//! ```text
//! # Configure the organization, registry, bindings, and placements with `aos hub`.
//! aos-hub --root ~/hub serve --listen 127.0.0.1:8420
//! # apr release …                                 (publish)
//! # apm: url = "http://127.0.0.1:8420/demo/packages/" (consume)
//! ```
//!
//! `serve --dev` boots zero-config with a root under the current
//! directory and a periodic background re-index.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use aos_hub_core::fetch::SurfaceProvider as _;
use aos_hub_core::service::RouteReservationKeyring as _;
use clap::{Args, Parser, Subcommand};

use aos_hub::db::{Database, RegistryRecord};
use aos_hub::server::{router, AppState};
use aos_hub::validation::validate_presence;

#[derive(Parser)]
#[command(name = "aos-hub", version, about = "AOS registry hub server")]
struct Cli {
    /// Hub state directory (holds hub.db).
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Database target. The hard-cutover CLI admits only the native `local`
    /// database; Worker administration uses the typed Hub API.
    #[arg(long, global = true, default_value = "local")]
    target: String,
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
        /// Seed demo data on startup if the instance looks empty (dev).
        #[arg(long)]
        seed: bool,
        /// Externally reachable base URL for setup snippets.
        #[arg(long)]
        external_url: Option<String>,
        /// Masthead brand (company/operator name); overrides the stored one.
        #[arg(long)]
        brand: Option<String>,
        /// Seconds between background re-index runs (0 disables).
        #[arg(long, default_value_t = 60)]
        reindex_interval: u64,
        /// File containing the shared HMAC key used by a trusted TLS/VPN/L7
        /// ingress adapter to authenticate delivery assertions.
        #[arg(long, env = "HUB_DELIVERY_ATTESTATION_KEY_FILE")]
        delivery_attestation_key_file: Option<PathBuf>,
        /// JSON file containing native TLS-terminator probe signer material.
        #[arg(long, env = "HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE")]
        domain_probe_signer_manifest_file: Option<PathBuf>,
        /// Owner-private signed direct-publication manifest used by route probes.
        #[arg(long, env = "HUB_ROUTE_PUBLICATION_MANIFEST_FILE")]
        route_publication_manifest_file: Option<PathBuf>,
        /// Pinned Ed25519 public key for the signed direct-publication manifest.
        #[arg(long, env = "HUB_ROUTE_PUBLICATION_PUBLIC_KEY")]
        route_publication_public_key: Option<String>,
        /// Owner-private JSON file containing active and retained route URL
        /// reservation HMAC keys.
        #[arg(long, env = "HUB_ROUTE_RESERVATION_KEYS_FILE")]
        route_reservation_keys_file: Option<PathBuf>,
        /// Owner-private JSON map from immutable provider refs to secret files.
        #[arg(long, env = "HUB_SECRET_VERSION_MANIFEST_FILE")]
        secret_version_manifest_file: Option<PathBuf>,
        /// Scoped Cloudflare API token used by authenticated CDN route probes.
        #[arg(long, env = "HUB_CLOUDFLARE_API_TOKEN")]
        cloudflare_api_token: Option<String>,
    },
    /// Re-index one registry (or all) now.
    Index {
        /// Registry slug; omit to index everything.
        slug: Option<String>,
    },
    /// Run consistency validation and repairs against a registry's caches.
    Validate {
        #[command(subcommand)]
        command: ValidateCommand,
    },
    /// Recover a native deployment by migrating its local database and
    /// optionally bootstrapping the root admin.
    Init {
        /// Bootstrap (create or update) this root admin email, if given.
        #[arg(long)]
        root_email: Option<String>,
        /// The root admin password. Prefer --root-password-stdin.
        #[arg(long)]
        root_password: Option<String>,
        /// Read the root admin password from stdin (one line).
        #[arg(long)]
        root_password_stdin: bool,
    },
    /// Reset (or create) a root admin's password.
    ///
    /// This recovery command targets the native local database. Ordinary user
    /// administration uses the typed `aos hub` API.
    ResetRoot {
        /// The root admin email.
        #[arg(long)]
        email: String,
        /// The new password. Prefer --password-stdin.
        #[arg(long)]
        password: Option<String>,
        /// Read the new password from stdin (one line).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Inspect the database schema.
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
    /// Deploy and manage the serverless Worker on a hosting provider.
    Worker {
        #[command(subcommand)]
        command: WorkerCommand,
    },
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Print the migration statements as a JSON array (for tooling/tests).
    Dump,
}

/// The hosting provider for the serverless Worker deployment.
///
/// Only Cloudflare Workers is implemented today; the abstraction leaves room for
/// future providers (e.g. Fastly Compute) behind the same `worker` commands.
#[derive(Clone, Copy, clap::ValueEnum)]
enum Provider {
    /// Cloudflare Workers (HubDb Durable Object + R2 + KV), via `wrangler`.
    Cloudflare,
}

#[derive(Subcommand)]
enum WorkerCommand {
    /// Provision provider resources, deploy the Worker, and set its secrets.
    ///
    /// Provider-specific only: `HubDb` applies the closed schema on first use.
    Deploy(WorkerArgs),
    /// Provision the provider resources only (no deploy).
    Provision(WorkerArgs),
    /// Convenience: provision + deploy + set secrets in one shot.
    ///
    /// `HubDb` migrates its own schema on first use; when `--root-email`
    /// is given the root admin is bootstrapped via the seal-gated `HubDb`
    /// endpoint (auto when a `--domain` is bound, else the printed
    /// `worker bootstrap-root` command).
    Install(WorkerArgs),
    /// Create the instance root admin against a deployed Worker's seal-gated
    /// `HubDb` bootstrap endpoint.
    BootstrapRoot(BootstrapRootArgs),
    /// Authenticate with the hosting provider (browser OAuth, as an alternative
    /// to a provider API token in the environment).
    Login(ProviderOpt),
    /// Clear the hosting provider's stored credentials.
    Logout(ProviderOpt),
    /// Show the current hosting-provider authentication.
    Whoami(ProviderOpt),
}

/// The provider selector for `worker` subcommands that take no other options.
#[derive(Args)]
struct ProviderOpt {
    /// The hosting provider.
    #[arg(long, value_enum, default_value_t = Provider::Cloudflare)]
    provider: Provider,
}

/// Options for `worker bootstrap-root`: a direct seal-authenticated HTTP call to
/// a deployed Worker's `HubDb` root-bootstrap endpoint (no provider auth).
#[derive(Args)]
struct BootstrapRootArgs {
    /// Base URL of the deployed Worker (e.g. `https://hub.example.com` or the
    /// `*.workers.dev` URL).
    #[arg(long)]
    url: String,
    /// The root admin's email.
    #[arg(long)]
    email: String,
    /// The root admin's password (read interactively/stdin if omitted).
    #[arg(long)]
    password: Option<String>,
    /// Read the password from stdin.
    #[arg(long)]
    password_stdin: bool,
    /// The deployment's `HUB_SEAL_KEY` (falls back to the `HUB_SEAL_KEY` env var).
    #[arg(long)]
    seal_key: Option<String>,
}

/// Shared options for the `worker` deployment commands.
#[derive(Args)]
struct WorkerArgs {
    /// The hosting provider.
    #[arg(long, value_enum, default_value_t = Provider::Cloudflare)]
    provider: Provider,
    /// The Worker name. Also the default stem for the provisioned resource names
    /// (R2 bucket, KV namespace, and Durable Object), so one `--name` namespaces a whole
    /// install — important because those names are unique per Cloudflare account.
    #[arg(long, default_value = "aos-hub")]
    name: String,
    /// The R2 bucket holding the registry surfaces (default: `<name>-surfaces`).
    /// R2 bucket names are unique per account, so the default is derived from
    /// `--name` rather than a fixed string that would collide across installs.
    #[arg(long)]
    bucket: Option<String>,
    /// The KV namespace title for sessions (default: `<name>-sessions`).
    #[arg(long)]
    kv_title: Option<String>,
    /// Base for three account-unique rate-limit namespace IDs.
    #[arg(long, default_value_t = 1000)]
    rate_limit_namespace_base: u32,
    /// Exact HTTPS URL of an optional `aos-hub-egress` router.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_URL", requires = "egress_gateway_key")]
    egress_gateway_url: Option<String>,
    /// Canonical HTTPS control-plane origin (for example `https://aos.example.com`).
    #[arg(long, env = "HUB_EXTERNAL_URL")]
    external_url: Option<String>,
    /// Immutable source/build identity exposed for deployment verification.
    #[arg(long, env = "HUB_DEPLOYMENT_ID")]
    deployment_id: Option<String>,
    /// Bind the Worker to a custom domain (e.g. `aos.example.com`): `wrangler
    /// deploy` provisions its DNS record + edge cert, and its zone must be on the
    /// same Cloudflare account. Repeatable — pass `--domain` once per hostname to
    /// bind several typed delivery endpoint domains.
    ///
    /// The domains you pass are the Worker's complete managed custom-domain set:
    /// list every domain the Worker should serve. Omitting `--domain` entirely
    /// emits no route configuration, which leaves any already-bound custom
    /// domains untouched (it does NOT revert the Worker to `*.workers.dev`-only) —
    /// so a routine code redeploy needs no `--domain`. The free
    /// `<name>.<subdomain>.workers.dev` URL is always served regardless.
    ///
    /// The hub takes its canonical public URL (the `{url}/{slug}` push URL, the
    /// OIDC redirect_uri base, the WebAuthn relying-party ID, browse links) from
    /// whatever domain a request arrives on, so you do not configure it
    /// separately — set this and you're done.
    #[arg(long = "domain")]
    domains: Vec<String>,
    /// Bootstrap root admin email (paired with --root-password); install only.
    #[arg(long)]
    root_email: Option<String>,
    /// Bootstrap root admin password. Prefer --root-password-stdin.
    #[arg(long)]
    root_password: Option<String>,
    /// Read the root admin password from stdin (one line).
    #[arg(long)]
    root_password_stdin: bool,
    /// HS256 JWT signing secret; minted randomly when omitted.
    #[arg(long, env = "HUB_JWT_SECRET")]
    jwt_secret: Option<String>,
    /// At-rest AES-GCM sealing key; minted randomly when omitted.
    #[arg(long, env = "HUB_SEAL_KEY")]
    seal_key: Option<String>,
    /// `KEY_ID:KEY` already active on the optional egress router.
    #[arg(long, env = "HUB_EGRESS_GATEWAY_KEY", requires = "egress_gateway_url")]
    egress_gateway_key: Option<String>,
    /// Scoped Cloudflare API token used for route-control-plane observation.
    #[arg(long, env = "HUB_CLOUDFLARE_API_TOKEN")]
    cloudflare_api_token: Option<String>,
    /// Magic-link email relay endpoint (HUB_EMAIL_API_URL).
    #[arg(long)]
    email_relay_url: Option<String>,
    /// Bearer token for the email relay (HUB_EMAIL_API_TOKEN).
    #[arg(long)]
    email_api_token: Option<String>,
    /// Shared HMAC key for authenticated delivery assertions from an upstream
    /// TLS, VPN, or layer-7 adapter (HUB_DELIVERY_ATTESTATION_KEY).
    #[arg(long, env = "HUB_DELIVERY_ATTESTATION_KEY")]
    delivery_attestation_key: Option<String>,
    /// JSON file containing Worker TLS-terminator probe signer material.
    #[arg(long)]
    domain_probe_signer_manifest_file: Option<PathBuf>,
    /// Owner-private JSON file uploaded as the Worker's route-reservation keyring.
    #[arg(long, env = "HUB_ROUTE_RESERVATION_KEYS_FILE")]
    route_reservation_keys_file: Option<PathBuf>,
    /// Verified sender address for Cloudflare Email Service (HUB_EMAIL_FROM).
    /// Setting this adds the `EMAIL` [[send_email]] binding so transactional
    /// email is delivered through Email Service. The sender domain must already
    /// be onboarded in the Cloudflare dashboard (Email -> Email Sending) first.
    #[arg(long)]
    email_from: Option<String>,
    /// Disable Workers Observability (persistent Workers Logs + metrics).
    /// Observability is on by default so production errors are queryable.
    #[arg(long)]
    no_observability: bool,
    /// Fraction (0.0–1.0) of requests sampled into Workers Logs. Default 1.0
    /// (log every request); lower it to trade detail for log volume at scale.
    #[arg(long, default_value_t = 1.0)]
    head_sampling_rate: f64,
    /// Enable Logpush: stream the Worker's logs to an account Logpush job.
    #[arg(long)]
    logpush: bool,
}

impl WorkerArgs {
    /// The R2 bucket name, defaulting to `<name>-surfaces` (R2 bucket names are
    /// unique per account, so the default is per-install).
    fn bucket(&self) -> String {
        self.bucket
            .clone()
            .unwrap_or_else(|| format!("{}-surfaces", self.name))
    }

    /// The KV namespace title, defaulting to `<name>-sessions`.
    fn kv_title(&self) -> String {
        self.kv_title
            .clone()
            .unwrap_or_else(|| format!("{}-sessions", self.name))
    }
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
    /// missing them. Local placements are repaired by copy; Hub delivery
    /// routes use typed authenticated cache uploads; other HTTP targets remain
    /// plan-only.
    Repair {
        /// Canonical registry slug to repair.
        canonical: String,
        /// Externally reachable base URL identifying this Hub's cache routes.
        #[arg(long)]
        external_url: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber_init();
    let cli = Cli::parse();

    match cli.command {
        Command::Serve {
            listen,
            dev,
            seed,
            external_url,
            brand,
            reindex_interval,
            delivery_attestation_key_file,
            domain_probe_signer_manifest_file,
            route_publication_manifest_file,
            route_publication_public_key,
            route_reservation_keys_file,
            secret_version_manifest_file,
            cloudflare_api_token,
        } => {
            let root = resolve_root(cli.root, dev)?;
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            let listen_addr = listener
                .local_addr()
                .context("reading bound listen address")?;
            let external_url = external_url.unwrap_or_else(|| format!("http://{listen_addr}"));
            let db = Arc::new(Database::open(&root.join("hub.db")).await?);
            let default_storage_root = root.join("storage");
            std::fs::create_dir_all(&default_storage_root).with_context(|| {
                format!(
                    "creating default storage root {}",
                    default_storage_root.display()
                )
            })?;
            let default_storage_root = default_storage_root
                .to_str()
                .context("default storage root is not valid UTF-8")?;
            db.ensure_instance_default_binding("local_fs", Some(default_storage_root), None)
                .await?;
            let image_snapshots = aos_hub::image_snapshot::ImageSnapshotStore::open(&root)?;
            image_snapshots.load_tracked(&db).await?;
            let route_reservation_keys_path = route_reservation_keys_file
                .context("HUB_ROUTE_RESERVATION_KEYS_FILE is required for route management")?;
            let route_reservation_keys = String::from_utf8(
                aos_hub::auth::seal::read_secret_file(&route_reservation_keys_path).with_context(
                    || {
                        format!(
                            "reading route reservation keyring at {}",
                            route_reservation_keys_path.display()
                        )
                    },
                )?,
            )
            .context("route reservation keyring is not UTF-8")?;
            let route_reservation_keyring = Arc::new(
                aos_hub_core::service::ConfiguredRouteReservationKeyring::from_json(
                    &route_reservation_keys,
                )
                .context("invalid native route reservation keyring")?,
            );
            route_reservation_keyring
                .validate_referenced_versions(&db)
                .await
                .context("route reservation keyring cannot open this database")?;
            let seed_reservation_keys = route_reservation_keyring.snapshot()?;
            // Optional one-shot demo seed: populate an empty instance so the
            // server comes up with something to browse. seed_dev is idempotent
            // (it no-ops when the demo org already exists), so leaving --seed on
            // across restarts is safe.
            if seed {
                match aos_hub::seed::seed_dev_with_snapshots(
                    &db,
                    &root,
                    Arc::clone(&image_snapshots),
                    &aos_hub::seed::SeedRouteConfig {
                        listen_addr,
                        external_url: &external_url,
                        reservation_keys: &seed_reservation_keys,
                    },
                )
                .await
                {
                    Ok(aos_hub::seed::SeedOutcome::Seeded(report)) => report.print(),
                    Ok(aos_hub::seed::SeedOutcome::AlreadySeeded) => {
                        tracing::info!("seed skipped: demo data already present");
                    }
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "dev seed failed");
                    }
                }
            }
            let mut app_state = AppState::new(db, external_url).await;
            app_state.image_snapshots = Some(image_snapshots);
            if let Some(snapshots) = app_state.image_snapshots.clone() {
                let snapshot_db = Arc::clone(&app_state.db);
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                    loop {
                        tick.tick().await;
                        if let Err(error) = snapshots.collect(&snapshot_db, 100).await {
                            tracing::warn!(
                                error = %format!("{error:#}"),
                                "image snapshot collection failed"
                            );
                        }
                    }
                });
            }
            app_state.route_reservation_keyring = Some(route_reservation_keyring);
            if let Some(path) = delivery_attestation_key_file {
                let key = aos_hub::auth::seal::read_secret_file(&path).with_context(|| {
                    format!("reading delivery attestation key at {}", path.display())
                })?;
                app_state.delivery_attestation_verifier = Some(Arc::new(
                    aos_hub_core::delivery_attestation::DeliveryAttestationVerifier::new(&key)
                        .context("invalid delivery attestation key")?,
                ));
            }
            // In dev mode the "check your email" page shows the magic link
            // inline (the default LogMailer logs rather than sends).
            app_state.dev = dev;
            // Seal at-rest secrets (OIDC client secrets and the isolated draft
            // signing seed) with
            // a real AES-256-GCM sealer keyed by the persisted instance key.
            // `--dev` keeps the reproducible XOR placeholder so local testing
            // does not depend on a generated key file.
            if !dev {
                app_state.sealer = aos_hub::auth::seal::instance_sealer(&root)?.into();
            }
            if let Some(path) = secret_version_manifest_file {
                app_state.secret_versions =
                    aos_hub::coreports::load_secret_version_manifest(&path)?;
            }
            let index_surfaces = Arc::new(
                aos_hub::coreports::HubSurfaceProvider::new(
                    Arc::clone(&app_state.db),
                    app_state.http.clone(),
                    app_state.image_snapshots.clone(),
                )
                .with_credentials(Arc::clone(&app_state.secret_versions))
                .for_image_indexing(),
            );
            index_all(&app_state.db, index_surfaces.as_ref()).await;

            if reindex_interval > 0 {
                let db = Arc::clone(&app_state.db);
                let index_surfaces = Arc::clone(&index_surfaces);
                tokio::spawn(async move {
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(reindex_interval));
                    tick.tick().await; // first tick fires immediately; we already indexed
                    loop {
                        tick.tick().await;
                        index_all(&db, index_surfaces.as_ref()).await;
                        sync_due_mirrors(&db, now_secs()).await;
                        match aos_hub::export::purge_expired_orgs(&db, now_secs()).await {
                            Ok(purged) => {
                                for slug in &purged {
                                    tracing::info!(org = %slug, "purged expired org");
                                }
                            }
                            Err(err) => {
                                tracing::warn!(error = %format!("{err:#}"), "org purge failed");
                            }
                        }
                        let cutoff = now_secs() - REPAIR_JOB_RETENTION_SECS;
                        match db.prune_repair_jobs(cutoff).await {
                            Ok(pruned) if pruned > 0 => {
                                tracing::info!(pruned, "pruned old repair jobs");
                            }
                            Ok(_) => {}
                            Err(err) => tracing::warn!(
                                error = %format!("{err:#}"),
                                "repair-job prune failed"
                            ),
                        }
                    }
                });
            }
            let endpoint = std::env::var("HUB_DNS_JSON_ENDPOINT")
                .context("HUB_DNS_JSON_ENDPOINT is required for domain verification")?;
            let tls_verifier = aos_hub_core::topology_probe::DomainTlsProbeVerifier::new();
            let signer_manifest_path = domain_probe_signer_manifest_file.context(
                "HUB_DOMAIN_PROBE_SIGNER_MANIFEST_FILE is required for domain verification",
            )?;
            let signer_manifest = String::from_utf8(
                aos_hub::auth::seal::read_secret_file(&signer_manifest_path).with_context(
                    || {
                        format!(
                            "reading domain-probe signer manifest at {}",
                            signer_manifest_path.display()
                        )
                    },
                )?,
            )
            .context("domain-probe signer manifest is not UTF-8")?;
            app_state.domain_probe_terminator = Some(Arc::new(
                aos_hub_core::topology_probe::ManifestDomainProbeTerminatorProvider::from_json(
                    &signer_manifest,
                    "native_file",
                )
                .context("invalid native domain-probe signer manifest")?,
            ));
            let route_http: Arc<dyn aos_hub_core::web::console::ports::HttpClient> = Arc::new(
                aos_hub::coreports::HubHttpClient::new(app_state.http.clone()),
            );
            let mut controller = aos_hub_core::topology_probe::DomainProbeController::new(
                Arc::clone(&app_state.db),
                Arc::clone(&route_http),
                tls_verifier,
                endpoint,
                "native-hub",
            )?;
            controller = controller.with_storage_credential_probe(Arc::new(
                aos_hub::coreports::NativeStorageCredentialProbeProvider::new(
                    app_state.http.clone(),
                    Arc::clone(&app_state.secret_versions),
                ),
            ));
            let mut route_adapters =
                aos_hub_core::topology_probe::ControllerOwnedDeliveryRouteObservationProvider::new(
                );
            let mut has_route_adapter = false;
            match (
                route_publication_manifest_file,
                route_publication_public_key,
            ) {
                (Some(path), Some(public_key)) => {
                    let signed_manifest = String::from_utf8(
                        aos_hub::auth::seal::read_secret_file(&path).with_context(|| {
                            format!("reading route publication manifest at {}", path.display())
                        })?,
                    )
                    .context("route publication manifest is not UTF-8")?;
                    let direct = Arc::new(
                        aos_hub_core::topology_probe::SignedManifestDeliveryRouteObservationProvider::from_signed_json(
                            &signed_manifest,
                            &public_key,
                            now_secs(),
                            Arc::clone(&route_http),
                        )
                        .context("invalid signed route publication manifest")?,
                    );
                    route_adapters = route_adapters.with_direct(direct);
                    has_route_adapter = true;
                }
                (None, None) => {}
                _ => anyhow::bail!(
                    "HUB_ROUTE_PUBLICATION_MANIFEST_FILE and HUB_ROUTE_PUBLICATION_PUBLIC_KEY must be configured together"
                ),
            }
            if let Some(token) = cloudflare_api_token {
                let api =
                    Arc::new(aos_hub::coreports::CloudflareControlPlaneClient::new(token).await?);
                route_adapters = route_adapters.with_external(Arc::new(
                    aos_hub_core::topology_probe::CloudflareDeliveryRouteControlPlane::new(
                        api,
                        Arc::clone(&route_http),
                    ),
                ));
                has_route_adapter = true;
            }
            if has_route_adapter {
                controller = controller.with_route_observer(Arc::new(route_adapters));
            }
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    tick.tick().await;
                    if let Err(error) = controller.run_due(25).await {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "domain probe controller pass failed"
                        );
                    }
                }
            });
            let deletion_controller = aos_hub_core::gc_controller::CacheGcDeletionController::new(
                Arc::clone(&app_state.db),
                Arc::new(
                    aos_hub::coreports::HubSurfaceWriteProvider::new(
                        Arc::clone(&app_state.db),
                        app_state.http.clone(),
                    )
                    .with_credentials(Arc::clone(&app_state.secret_versions)),
                ),
            );
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    tick.tick().await;
                    if let Err(error) = deletion_controller.run_due(now_secs(), 100).await {
                        tracing::warn!(
                            error = %format!("{error:#}"),
                            "physical cache deletion controller pass failed"
                        );
                    }
                }
            });
            let inventory_db = Arc::clone(&app_state.db);
            let inventory_surfaces = aos_hub::coreports::HubSurfaceProvider::new(
                Arc::clone(&inventory_db),
                app_state.http.clone(),
                app_state.image_snapshots.clone(),
            )
            .with_credentials(Arc::clone(&app_state.secret_versions));
            let inventory_writers = aos_hub::coreports::HubSurfaceWriteProvider::new(
                Arc::clone(&inventory_db),
                app_state.http.clone(),
            )
            .with_credentials(Arc::clone(&app_state.secret_versions));
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    if let Err(error) = aos_hub_core::cache_scan::reap_due_cache_tombstones(
                        &inventory_db,
                        now_secs(),
                    )
                    .await
                    {
                        tracing::warn!(error = %format!("{error:#}"), "cache tombstone reap failed");
                    }
                    if let Err(error) = aos_hub_core::cache_scan::recover_expired_cache_writes(
                        &inventory_db,
                        &inventory_surfaces,
                        &inventory_writers,
                        now_secs(),
                        aos_hub_core::cache_scan::MAX_CLEANUP_ITEMS_PER_PASS,
                    )
                    .await
                    {
                        tracing::warn!(error = %format!("{error:#}"), "expired cache write recovery failed");
                    }
                    let caches = match inventory_db.list_binary_caches().await {
                        Ok(caches) => caches,
                        Err(error) => {
                            tracing::warn!(error = %format!("{error:#}"), "listing cache inventories failed");
                            continue;
                        }
                    };
                    for cache in caches
                        .into_iter()
                        .filter(|cache| cache.deleted_at.is_none())
                    {
                        if let Err(error) = aos_hub_core::cache_scan::rescan_cache(
                            &inventory_db,
                            &inventory_surfaces,
                            &cache,
                        )
                        .await
                        {
                            tracing::warn!(cache = %cache.slug, error = %format!("{error:#}"), "cache inventory pass failed");
                        }
                    }
                }
            });
            // Masthead brand (operator/company name): the --brand flag wins,
            // else the persisted instance_config['brand'], else empty (the
            // masthead then shows only the page crumbs).
            let brand = match brand {
                Some(brand) => brand,
                None => state_brand(&app_state).await?,
            };
            aos_hub::ui::render::set_brand(brand);
            // The console footer label is single-sourced in core; set it to this
            // binary's name + version so the footer reflects the serving hub.
            aos_hub::ui::render::set_app_version(concat!("aos-hub ", env!("CARGO_PKG_VERSION")));
            let state = Arc::new(app_state);
            // Resolve webhook signing material only inside the delivery worker;
            // control-plane rows and replay records carry immutable references.
            tokio::spawn(aos_hub::webhook::run_delivery_worker(
                Arc::clone(&state.db),
                state.http.clone(),
                Arc::clone(&state.secret_versions),
            ));
            tracing::info!(%listen, root = %root.display(), "aos-hub serving");
            // `into_make_service_with_connect_info` injects the TCP peer
            // address as `ConnectInfo<SocketAddr>` so the rate limiter keys on
            // the real client when no trusted proxy fronts the hub.
            axum::serve(
                listener,
                router(state)
                    .await
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
        Command::Validate { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                ValidateCommand::Run { canonical, depth } => {
                    let registry = db
                        .registry_by_slug(&canonical)
                        .await?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    let depth = parse_depth(&depth)?;
                    let summaries =
                        aos_hub::validation::validate_registry(&db, &registry, depth).await?;
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
                    ensure_local_target(&cli.target, "validate repair")?;
                    let registry = db
                        .registry_by_slug(&canonical)
                        .await?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    // Validate presence first so the repair plan reflects the
                    // current cache state.
                    aos_hub::validation::validate_presence(&db, &registry).await?;
                    let external_url =
                        external_url.unwrap_or_else(|| "http://127.0.0.1:8420".to_string());
                    let db = std::sync::Arc::new(db);
                    let authorizer = aos_hub::server::HubRepairAuthorizer::new(
                        std::sync::Arc::clone(&db),
                        aos_hub::auth::jwt::JwtKeys::random(),
                        external_url,
                    );
                    let client = aos_hub::fetch::hardened_client().await;
                    let summary =
                        aos_hub::validation::run_repairs(&db, &client, &registry, &authorizer)
                            .await?;
                    println!(
                        "repairs: {} done, {} plan-only, {} failed",
                        summary.done, summary.plan_only, summary.failed,
                    );
                }
            }
        }
        Command::Index { slug } => {
            let db = Arc::new(open_db(&cli.root, &cli.target).await?);
            let root = resolve_root(cli.root.clone(), false)?;
            let image_snapshots = aos_hub::image_snapshot::ImageSnapshotStore::open(&root)?;
            image_snapshots.load_tracked(&db).await?;
            let surfaces = aos_hub::coreports::HubSurfaceProvider::new(
                Arc::clone(&db),
                aos_hub::fetch::hardened_client().await,
                Some(image_snapshots),
            )
            .for_image_indexing();
            let registries = match slug {
                Some(slug) => vec![db
                    .registry_by_slug(&slug)
                    .await?
                    .with_context(|| format!("no registry '{slug}'"))?],
                None => db.list_registries().await?,
            };
            for registry in registries {
                let placement = db
                    .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(
                        registry.id,
                    ))
                    .await?;
                let placement_id = placement.id;
                let fetch = surfaces.placement_fetcher(&placement).await?;
                match aos_hub_core::indexer::index_and_record_from_placement(
                    db.as_ref(),
                    fetch.as_ref(),
                    &registry,
                    Some(placement_id),
                )
                .await
                {
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
        Command::Init {
            root_email,
            root_password,
            root_password_stdin,
        } => {
            // `open_db` opens and migrates the local database. Worker HubDb
            // bootstrap is handled by the Worker command family.
            let db = open_db(&cli.root, &cli.target).await?;
            let default_storage_root = resolve_root(cli.root.clone(), false)?.join("storage");
            std::fs::create_dir_all(&default_storage_root).with_context(|| {
                format!(
                    "creating default storage root {}",
                    default_storage_root.display()
                )
            })?;
            let default_storage_root = default_storage_root
                .to_str()
                .context("default storage root is not valid UTF-8")?;
            db.ensure_instance_default_binding("local_fs", Some(default_storage_root), None)
                .await?;
            println!("schema migrated ({})", cli.target);
            if let Some(email) = root_email {
                let plaintext = read_password(root_password, root_password_stdin)?;
                let (email, id) = ensure_root(&db, &email, &plaintext).await?;
                println!("root admin '{email}' ready (user id {id})");
            }
        }
        Command::ResetRoot {
            email,
            password,
            password_stdin,
        } => {
            let db = open_db(&cli.root, &cli.target).await?;
            let plaintext = read_password(password, password_stdin)?;
            let (email, id) = ensure_root(&db, &email, &plaintext).await?;
            println!("reset root password for '{email}' (user id {id})");
        }
        Command::Schema { command } => match command {
            SchemaCommand::Dump => {
                let stmts = aos_hub::db::migration_statements();
                println!("{}", serde_json::to_string_pretty(&stmts)?);
            }
        },
        Command::Worker { command } => {
            run_worker_command(&cli.root, command).await?;
        }
    }
    Ok(())
}

/// Creates-or-updates the root admin's password, running the exact `Database`
/// user/password path the native `user set-password` uses (so it works
/// identically over any `--target` backend).
///
/// Returns the normalised email and the user id.
///
/// # Errors
///
/// Returns an error if the password is empty, or any database step fails.
async fn ensure_root(db: &Database, email: &str, plaintext: &str) -> Result<(String, i64)> {
    let email = email.trim().to_lowercase();
    if plaintext.is_empty() {
        anyhow::bail!("password must not be empty");
    }
    let user_id = db.find_or_create_user(&email).await?;
    let hash = aos_hub::auth::password::hash_password(plaintext)?;
    db.set_user_password(user_id, &hash).await?;
    // Grant the root admin `Owner` at the canonical instance scope so it is a
    // true instance administrator: `Role::Owner` carries `Permission::IamAdmin`
    // at root, which authorizes creating organizations and administering the
    // whole instance. Without this the bootstrapped account can log in but, under
    // the default invite-only signup policy, cannot create an org or do anything.
    db.grant_membership(
        "user",
        user_id,
        aos_hub::domain::Scope::root().as_str(),
        aos_hub::domain::Role::Owner.as_str(),
    )
    .await?;
    Ok((email, user_id))
}

/// Reads a password from `password`, or stdin when `from_stdin`, trimming a
/// trailing newline.
///
/// # Errors
///
/// Returns an error if neither source is given, or stdin cannot be read.
fn read_password(password: Option<String>, from_stdin: bool) -> Result<String> {
    if let Some(p) = password {
        return Ok(p);
    }
    if from_stdin {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("reading password from stdin")?;
        return Ok(buf.trim_end_matches(['\n', '\r']).to_string());
    }
    anyhow::bail!("provide --password / --root-password or the --*-stdin form");
}

/// Dispatches the `worker` subcommands (provision/deploy/install) for the
/// selected hosting provider.
///
/// # Errors
///
/// Returns an error if the provider is unsupported, asset resolution fails, or
/// any provisioning/deploy/migration step fails.
async fn run_worker_command(_root: &Option<PathBuf>, command: WorkerCommand) -> Result<()> {
    use aos_hub::cloudflare;

    // `bootstrap-root` is a direct seal-authenticated HTTP call to the deployed
    // Worker's `HubDb` endpoint — it needs no provider assets/auth, so handle it
    // before the provider/asset setup.
    if let WorkerCommand::BootstrapRoot(args) = &command {
        let seal = args
            .seal_key
            .clone()
            .or_else(|| std::env::var("HUB_SEAL_KEY").ok())
            .context("no seal key: pass --seal-key or set HUB_SEAL_KEY (the deploy value)")?;
        let plaintext = read_password(args.password.clone(), args.password_stdin)?;
        let id =
            cloudflare::bootstrap_root_remote(&args.url, &seal, &args.email, &plaintext).await?;
        println!("root admin '{}' ready (user id {id})", args.email);
        return Ok(());
    }

    let provider = match &command {
        WorkerCommand::Deploy(a) | WorkerCommand::Provision(a) | WorkerCommand::Install(a) => {
            a.provider
        }
        WorkerCommand::Login(p) | WorkerCommand::Logout(p) | WorkerCommand::Whoami(p) => p.provider,
        // Handled above with an early return.
        WorkerCommand::BootstrapRoot(_) => Provider::Cloudflare,
    };
    // Only Cloudflare is implemented; the match documents the extension point
    // for future providers (each would resolve its own assets + auth).
    match provider {
        Provider::Cloudflare => {}
    }
    let assets = cloudflare::Assets::from_env()?;

    match &command {
        WorkerCommand::Login(_) => cloudflare::login(&assets).await?,
        WorkerCommand::Logout(_) => cloudflare::logout(&assets).await?,
        WorkerCommand::Whoami(_) => cloudflare::whoami(&assets).await?,
        // Handled by the early return at the top of this function.
        WorkerCommand::BootstrapRoot(_) => {}
        WorkerCommand::Provision(args) => {
            let cfg = provision_worker(&assets, args).await?;
            println!("provisioned: R2 {}, KV id {}", cfg.bucket, cfg.kv_id);
        }
        WorkerCommand::Deploy(args) => {
            deploy_worker(&assets, args).await?;
        }
        WorkerCommand::Install(args) => {
            // `HubDb` migrates its schema on first use; the root admin is
            // created via the seal-gated bootstrap endpoint.
            let seal = deploy_worker(&assets, args).await?;
            if let Some(email) = &args.root_email {
                let plaintext =
                    read_password(args.root_password.clone(), args.root_password_stdin)?;
                let Some(seal) = seal else {
                    anyhow::bail!(
                        "cannot bootstrap root: this deploy preserved an existing \
                         HUB_SEAL_KEY it does not know — pass --seal-key (the value \
                         used at deploy), or run `aos-hub worker bootstrap-root` \
                         against the deployed URL"
                    );
                };
                if let Some(domain) = args.domains.first() {
                    let base = format!("https://{domain}");
                    let id =
                        aos_hub::cloudflare::bootstrap_root_remote(&base, &seal, email, &plaintext)
                            .await?;
                    println!("root admin '{email}' ready (user id {id})");
                } else {
                    println!(
                        "deploy done — create the root admin against the Worker's \
                         *.workers.dev URL:\n  aos-hub worker bootstrap-root \
                         --url https://<name>.<subdomain>.workers.dev --email {email} \
                         --seal-key {seal}"
                    );
                }
            }
            if args.domains.is_empty() {
                println!(
                    "install complete: serving on the Worker's *.workers.dev URL \
                     (any existing custom domains left untouched)"
                );
            } else {
                println!("install complete: bound to {}", args.domains.join(", "));
            }
        }
    }
    Ok(())
}

/// Provisions the provider resources and resolves a [`cloudflare::DeployConfig`].
async fn provision_worker(
    assets: &aos_hub::cloudflare::Assets,
    args: &WorkerArgs,
) -> Result<aos_hub::cloudflare::DeployConfig> {
    let external_url = args
        .external_url
        .clone()
        .or_else(|| {
            args.domains
                .first()
                .map(|domain| format!("https://{domain}"))
        })
        .context("worker deploy requires --external-url or at least one --domain")?;
    let mut cfg = aos_hub::cloudflare::provision(
        assets,
        &args.name,
        &args.bucket(),
        &args.kv_title(),
        args.egress_gateway_url.as_deref(),
        &external_url,
        args.deployment_id.as_deref(),
        args.email_relay_url.as_deref(),
        &args.domains,
        aos_hub::cloudflare::RateLimitNamespaces::from_base(args.rate_limit_namespace_base)?,
    )
    .await?;
    // Apply the observability flags onto the provisioned config (provision()
    // defaults observability on; these let the operator tune or disable it).
    cfg.observability = !args.no_observability;
    cfg.head_sampling_rate = args.head_sampling_rate;
    cfg.logpush = args.logpush;
    // Email Service binding: emitted only when a verified sender is supplied.
    cfg.email_from = args.email_from.clone();
    Ok(cfg)
}

/// Provisions, deploys the bundled Worker wasm, and applies its runtime secrets.
///
/// Does **not** migrate the database — that is the provider-neutral `init` step.
/// Deploys the worker and returns the **effective** `HUB_SEAL_KEY` — the value
/// supplied via `--seal-key`/`HUB_SEAL_KEY`, or the one freshly minted by this
/// deploy — so the caller (`worker install`) can authenticate the seal-gated
/// `HubDb` root-bootstrap call. `None` when the seal was preserved from a prior
/// deploy (so this run does not know it).
async fn deploy_worker(
    assets: &aos_hub::cloudflare::Assets,
    args: &WorkerArgs,
) -> Result<Option<String>> {
    use aos_hub::cloudflare;

    let domain_probe_signer_manifest = args
        .domain_probe_signer_manifest_file
        .as_ref()
        .map(|path| {
            aos_hub::auth::seal::read_secret_file(path)
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(anyhow::Error::from)
                        .context("domain-probe signer manifest is not UTF-8")
                })
                .with_context(|| {
                    format!("reading domain-probe signer manifest at {}", path.display())
                })
        })
        .transpose()?;
    let route_reservation_keyring = args
        .route_reservation_keys_file
        .as_ref()
        .map(|path| {
            aos_hub::auth::seal::read_secret_file(path)
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(anyhow::Error::from)
                        .context("route reservation keyring is not UTF-8")
                })
                .with_context(|| format!("reading route reservation keyring at {}", path.display()))
        })
        .transpose()?;
    let secrets = cloudflare::Secrets {
        jwt_secret: args.jwt_secret.clone(),
        seal_key: args.seal_key.clone(),
        egress_gateway_key: args.egress_gateway_key.clone(),
        cloudflare_api_token: args.cloudflare_api_token.clone(),
        email_api_token: args.email_api_token.clone(),
        delivery_attestation_key: args.delivery_attestation_key.clone(),
        domain_probe_signer_manifest,
        route_reservation_keyring,
    };
    secrets.validate()?;
    let cfg = provision_worker(assets, args).await?;
    let applied = cloudflare::deploy(assets, &cfg, &secrets).await?;
    if applied.minted_jwt_secret.is_some() || applied.minted_seal_key.is_some() {
        println!("NOTE: store these freshly minted secrets — they are not recoverable:");
        if let Some(jwt) = &applied.minted_jwt_secret {
            println!("  HUB_JWT_SECRET={jwt}");
        }
        if let Some(seal) = &applied.minted_seal_key {
            println!("  HUB_SEAL_KEY={seal}");
        }
    }
    if args.domains.is_empty() {
        println!(
            "deployed: serving on the Worker's *.workers.dev URL \
             (any existing custom domains left untouched)"
        );
    } else {
        println!("deployed: bound to {}", args.domains.join(", "));
    }
    // The effective seal: supplied wins, else the env value, else a fresh mint.
    Ok(args
        .seal_key
        .clone()
        .or_else(|| std::env::var("HUB_SEAL_KEY").ok())
        .or(applied.minted_seal_key))
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

/// The persisted masthead brand (`instance_config['brand']`), or empty.
async fn state_brand(app_state: &AppState) -> Result<String> {
    Ok(app_state
        .db
        .instance_config_get("brand")
        .await?
        .unwrap_or_default())
}

/// Index every registered registry, logging failures without aborting;
/// each successful index is followed by presence validation of the
/// registry's committed caches.
async fn index_all(db: &Database, surfaces: &dyn aos_hub_core::fetch::SurfaceProvider) {
    let registries = match db.list_registries().await {
        Ok(regs) => regs,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "listing registries");
            return;
        }
    };
    for registry in registries {
        let placement = match db
            .reconciled_surface_reader(aos_hub_core::db::SurfaceTarget::Registry(registry.id))
            .await
        {
            Ok(placement) => placement,
            Err(err) => {
                tracing::warn!(slug = %registry.slug, error = %format!("{err:#}"), "resolving authoritative index placement failed");
                continue;
            }
        };
        let fetch = match surfaces.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(err) => {
                tracing::warn!(slug = %registry.slug, placement_id = placement.id, error = %format!("{err:#}"), "opening authoritative index placement failed");
                continue;
            }
        };
        let indexed = match aos_hub_core::indexer::index_and_record_from_placement(
            db,
            fetch.as_ref(),
            &registry,
            Some(placement.id),
        )
        .await
        {
            Ok(_) => true,
            Err(err) => {
                tracing::warn!(slug = %registry.slug, placement_id = placement.id, error = %format!("{err:#}"), "index failed");
                false
            }
        };
        if indexed {
            run_presence_validation(db, &registry).await;
            run_cache_probes(db, &registry).await;
        }
    }
}

/// Syncs every full mirror whose schedule is due.
///
/// A full mirror is *due* when it has never synced or `schedule_secs` have
/// elapsed since its last attempt. Each sync verifies the upstream surface and
/// copies it into the local binding; a verification failure is recorded and
/// logged, never fatal to the loop.
async fn sync_due_mirrors(db: &Database, now: i64) {
    let sources = match db.list_mirror_sources().await {
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
        let registry = match db.registry_by_id(registry_id).await {
            Ok(Some(registry)) => registry,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(error = %format!("{err:#}"), "loading mirror registry");
                continue;
            }
        };
        match aos_hub::mirror::sync_full_mirror(db, &registry).await {
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

async fn run_cache_probes(db: &Database, registry: &RegistryRecord) {
    let http = aos_hub::fetch::hardened_client().await;
    match aos_hub::probe::probe_caches(db, &http, registry).await {
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = std::fs::symlink_metadata(&root)
            .with_context(|| format!("inspecting hub root {}", root.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "hub root must be a directory, not a link"
        );
        anyhow::ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw(),
            "hub root must be owned by the effective user"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing hub root {}", root.display()))?;
    }
    Ok(root)
}

/// Opens the native database for the closed `local` target.
///
/// # Errors
///
/// Returns an error for an unknown target or if the local file cannot be opened.
async fn open_db(root: &Option<PathBuf>, target: &str) -> Result<Database> {
    if target == "local" {
        let root = resolve_root(root.clone(), false)?;
        return Database::open(&root.join("hub.db")).await;
    }
    // The Cloudflare hub's system of record is HubDb Durable Object SQLite,
    // administered through Worker endpoints rather than opened by this CLI.
    // `open_db` therefore serves only the local native-hub database.
    anyhow::bail!(
        "unknown --target '{target}' (expected: local). Use `aos-hub worker …` \
         (bootstrap-root / deploy) or the Worker API for a Cloudflare deployment."
    )
}

/// Rejects a non-local `--target` for commands that read or write the local
/// filesystem (surface exports, `file://` cache repairs) and so are only
/// meaningful against a local deployment — rather than silently degrading to an
/// empty/no-op result against a remote one.
///
/// # Errors
///
/// Returns an error when `target` is not `local`.
fn ensure_local_target(target: &str, command: &str) -> Result<()> {
    if target != "local" {
        anyhow::bail!(
            "`{command}` operates on the local filesystem and is only supported with \
             --target local; run it on the deployment host"
        );
    }
    Ok(())
}

/// Parse a validation-depth CLI argument.
fn parse_depth(depth: &str) -> Result<aos_hub::validation::ValidationDepth> {
    use aos_hub::validation::ValidationDepth;
    match depth {
        "presence" => Ok(ValidationDepth::Presence),
        "integrity" => Ok(ValidationDepth::Integrity),
        "deep" => Ok(ValidationDepth::Deep),
        other => anyhow::bail!("invalid depth '{other}': presence, integrity, or deep"),
    }
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
