//! The `aos-hub` binary: local-first registry hub server.
//!
//! Local-first operation is a hard requirement of RFC-0004: this binary +
//! a sqlite file + `file://` registry sources is a *complete* hub. The
//! one-machine loop:
//!
//! ```text
//! aos-hub --root ~/hub registry add demo file:///srv/demo \
//!     --trust-key 'demo:Ed25519:AAAA…'
//! aos-hub --root ~/hub serve --listen 127.0.0.1:8420
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

use aos_hub::coreports::into_core_fetch;
use aos_hub::db::{Database, RegistryRecord};
use aos_hub::fetch::{fetch_for_url, LocalFsFetch, SurfaceFetch};
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use aos_hub::validation::validate_presence;

#[derive(Parser)]
#[command(name = "aos-hub", version, about = "AOS registry hub server")]
struct Cli {
    /// Hub state directory (holds hub.db).
    #[arg(long, global = true)]
    root: Option<PathBuf>,

    /// Database backend for local operator commands (only `local` is supported).
    /// Cloudflare deployments are administered through the web/API surface.
    #[arg(long, global = true, default_value = "local")]
    target: String,

    /// Reserved at-rest sealing-key override. Local commands use the instance key.
    #[arg(long, global = true)]
    seal_key: Option<String>,

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
    /// Manage user accounts.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Populate a fresh hub with demo data (dev convenience).
    Seed,
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
    /// Manage hosted Nix binary caches (create, link, GC, pin, search).
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
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
    /// Manage IAM memberships (a principal's role at a scope).
    Member {
        #[command(subcommand)]
        command: MemberCommand,
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
    /// Apply native database migrations and optionally bootstrap the root admin.
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
    /// Reset (or create) a native deployment's root admin password.
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
    /// Cloudflare Workers (Durable Object SQLite, R2, and KV).
    Cloudflare,
}

#[derive(Subcommand)]
enum WorkerCommand {
    /// Provision resources, deploy the Worker, and preserve or set its secrets.
    Deploy(WorkerArgs),
    /// Provision the provider resources only (no deploy).
    Provision(WorkerArgs),
    /// Convenience: provision + deploy + set secrets in one shot.
    ///
    /// `HubDb` migrates its own schema on first use (no D1); when `--root-email`
    /// is given the root admin is bootstrapped via the seal-gated `HubDb`
    /// endpoint (auto when a `--domain` is bound, else the printed
    /// `worker bootstrap-root` command).
    Install(WorkerArgs),
    /// Create the instance root admin against a deployed Worker's seal-gated
    /// `HubDb` bootstrap endpoint (the D1-free replacement for `init` bootstrap).
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
    /// The Worker name and default stem for provisioned resource names.
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
    /// Bind the Worker to a custom domain (e.g. `aos.example.com`): `wrangler
    /// deploy` provisions its DNS record + edge cert, and its zone must be on the
    /// same Cloudflare account. Repeatable — pass `--domain` once per hostname to
    /// bind several (the hub's own domain plus per-registry/per-cache frontends).
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
    #[arg(long)]
    jwt_secret: Option<String>,
    /// At-rest AES-GCM sealing key; minted randomly when omitted.
    #[arg(long)]
    seal_key: Option<String>,
    /// Magic-link email relay endpoint (HUB_EMAIL_API_URL).
    #[arg(long)]
    email_relay_url: Option<String>,
    /// Bearer token for the email relay (HUB_EMAIL_API_TOKEN).
    #[arg(long)]
    email_api_token: Option<String>,
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
    /// Set the masthead brand (company/operator name; empty to clear).
    SetBrand {
        /// The brand text; pass "" to clear and show only page crumbs.
        brand: String,
    },
    /// Show the current masthead brand.
    ShowBrand,
    /// Set the instance-root crawl policy (robots.txt).
    SetRootCrawlPolicy {
        /// New policy: allow_all, allow_no_ai, or deny_all.
        policy: String,
    },
    /// Show the instance-root crawl policy.
    ShowRootCrawlPolicy,
    /// Set or clear the instance-root custom robots.txt body.
    SetRootRobots {
        /// Read the robots.txt body from this file; omit to clear and
        /// auto-generate.
        #[arg(long)]
        file: Option<String>,
    },
    /// Set or clear the instance-root custom llms.txt body.
    SetRootLlms {
        /// Read the llms.txt body from this file; omit to clear and
        /// auto-generate.
        #[arg(long)]
        file: Option<String>,
    },
    /// Set the default storage root for binding-less managed registries.
    SetDefaultStorageRoot {
        /// Filesystem path the native hub roots default-storage registries on.
        path: String,
    },
    /// Show the configured default storage root (blank when unset).
    ShowDefaultStorageRoot,
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
enum MemberCommand {
    /// Grant (or update) a service account's role at a scope.
    ///
    /// The service account is created in the org if absent. `scope` is a
    /// canonical scope string: `""` (instance root), an org slug (`andyl`), or a
    /// registry path (`andyl/main`); a broader scope grants the role over every
    /// resource beneath it. This is the admin escape hatch for issuing tokens
    /// that need more than `publish`/`read` (e.g. `registry.configure` for a
    /// cache push or a registry storage migration): grant the token's owner
    /// service account a covering role here, then `token mint --owner <name>`.
    Grant {
        /// Owning org slug (the service account's org).
        org: String,
        /// Service account name within the org (auto-created if absent).
        service_account: String,
        /// Role to grant: owner | admin | maintainer | publisher | reader.
        role: String,
        /// Canonical scope to grant at (defaults to the org slug).
        #[arg(long)]
        scope: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Set (or change) a user's login password.
    ///
    /// Reads the password from stdin by default (prompt-free; pipe it in), or
    /// pass --password for non-interactive use. Creates the user if absent, as
    /// an ops bootstrap convenience.
    SetPassword {
        /// User email address.
        email: String,
        /// Password to set; omit to read it from stdin instead.
        #[arg(long)]
        password: Option<String>,
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
    /// Create a storage binding under an org.
    Add {
        /// Owning org slug.
        org: String,
        /// Binding name, unique within the org.
        name: String,
        /// Backend kind: local_fs, s3, or r2.
        ///
        /// The deployment's serving runtime must support the kind (the native
        /// hub serves local_fs/s3; the Worker serves r2/s3). This offline CLI
        /// only validates that the kind is known.
        #[arg(long, default_value = "local_fs")]
        kind: String,
        /// Filesystem path or bucket/prefix the binding roots at.
        ///
        /// Spelled `--path` (not `--root`) so it never collides with the global
        /// `--root` hub-state-directory flag, which is `global = true` and would
        /// otherwise shadow a subcommand `--root` of a different type.
        #[arg(long)]
        path: String,
    },
    /// List an org's storage bindings.
    List {
        /// Owning org slug.
        org: String,
    },
    /// Set a binding's access mode and origin/credential metadata.
    SetAccess {
        /// Owning org slug.
        org: String,
        /// Binding name.
        name: String,
        /// Access mode: public (Direct-eligible) or private (proxied/presigned).
        #[arg(long)]
        access: String,
        /// S3/R2 API endpoint the hub writes objects through and presigns against.
        #[arg(long)]
        endpoint: Option<String>,
        /// Sealed credential reference for a private binding's signed reads.
        #[arg(long)]
        credential_ref: Option<String>,
    },
}

/// Manage hosted Nix binary caches — the substituter sibling of registries.
#[derive(Subcommand)]
enum CacheCommand {
    /// Create an org-owned cache backed by a storage binding (or the
    /// deployment's default storage when `--binding` is omitted).
    Create {
        /// Globally-unique URL slug to serve the cache under.
        slug: String,
        /// Owning org slug.
        #[arg(long)]
        org: String,
        /// Storage binding name within the org; omit to use default storage.
        #[arg(long)]
        binding: Option<String>,
        /// Display name (defaults to the slug).
        #[arg(long)]
        name: Option<String>,
        /// Sub-prefix under the binding root (defaults to the slug).
        #[arg(long)]
        prefix: Option<String>,
        /// Visibility: public | internal | private.
        #[arg(long, default_value = "private")]
        visibility: String,
        /// nix-cache-info Priority (lower = preferred).
        #[arg(long, default_value_t = 40)]
        priority: i64,
        /// NAR compression: zstd | xz | none.
        #[arg(long, default_value = "zstd")]
        compression: String,
        /// Clear the nix-cache-info WantMassQuery flag.
        #[arg(long)]
        no_mass_query: bool,
    },
    /// List caches (optionally filtered to one org).
    List {
        /// Restrict to one org's caches.
        #[arg(long)]
        org: Option<String>,
    },
    /// Show a cache's configuration, usage, links, and GC state.
    Show {
        /// Cache slug.
        slug: String,
    },
    /// Update a cache's mutable fields (only the flags you pass change).
    Update {
        /// Cache slug.
        slug: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        visibility: Option<String>,
        #[arg(long)]
        priority: Option<i64>,
        #[arg(long)]
        compression: Option<String>,
        /// Set WantMassQuery (true|false).
        #[arg(long)]
        mass_query: Option<bool>,
    },
    /// Remove a cache (soft-delete by default; --hard drops the row).
    Rm {
        /// Cache slug.
        slug: String,
        /// Hard-delete the row and cascade its links/policy/objects.
        #[arg(long)]
        hard: bool,
        /// Soft-delete grace before purge eligibility (e.g. 30d).
        #[arg(long, default_value = "30d")]
        grace: String,
    },
    /// Link a cache to a registry (advertise its URL and/or pin its packages).
    Link {
        /// Cache slug.
        cache: String,
        /// Registry slug.
        registry: String,
        /// The registry's live store paths pin GC roots in this cache.
        #[arg(long)]
        roots_packages: bool,
        /// Advertise this cache's URL in the registry's cache stack.
        #[arg(long)]
        advertise: bool,
    },
    /// Remove a cache⇄registry link.
    Unlink {
        /// Cache slug.
        cache: String,
        /// Registry slug.
        registry: String,
    },
    /// List a cache's registry links.
    Links {
        /// Cache slug.
        cache: String,
    },
    /// Set (replace) a cache's GC retention policy — omitted limits become
    /// unlimited (this is a full replace, not a merge).
    GcPolicy {
        /// Cache slug.
        cache: String,
        /// Soft byte cap (LRU-evict unrooted objects above it).
        #[arg(long)]
        max_bytes: Option<i64>,
        /// Soft object-count cap.
        #[arg(long)]
        max_objects: Option<i64>,
        /// Grace before an unreachable object is swept (e.g. 7d).
        #[arg(long)]
        ttl: Option<String>,
        /// Per linked registry, keep the N most-recent releases' closures.
        #[arg(long)]
        keep_versions: Option<i64>,
        /// Do not always retain live channel-frontier closures.
        #[arg(long)]
        no_keep_frontier: bool,
        /// Scheduled GC cadence (e.g. 1h).
        #[arg(long)]
        schedule: Option<String>,
    },
    /// Pin a store path as a manual GC root (optionally with a deadline).
    Pin {
        /// Cache slug.
        cache: String,
        /// Store-path hash component.
        store_hash: String,
        /// Expire the pin after this long (e.g. 14d); omit for unlimited.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Renew a manual pin's deadline in place (no re-upload).
    Renew {
        /// Cache slug.
        cache: String,
        /// Store-path hash component.
        store_hash: String,
        /// New deadline from now (e.g. 14d).
        #[arg(long)]
        ttl: String,
    },
    /// Remove a manual GC pin.
    Unpin {
        /// Cache slug.
        cache: String,
        /// Store-path hash component.
        store_hash: String,
    },
    /// List a cache's GC roots (manual + derived).
    Roots {
        /// Cache slug.
        cache: String,
    },
    /// Search a cache's objects by name, hash, or deriver.
    Search {
        /// Cache slug.
        cache: String,
        /// Substring to match.
        query: String,
        /// Maximum results.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Show one object's narinfo metadata.
    Info {
        /// Cache slug.
        cache: String,
        /// Store-path hash component.
        store_hash: String,
    },
    /// Print a store path's full transitive closure (the dependency graph).
    Closure {
        /// Cache slug.
        cache: String,
        /// Store-path hash component (the closure root).
        store_hash: String,
    },
    /// Garbage-collect a cache: sweep objects unreachable from its GC roots,
    /// subject to its GC policy (local `--target` only).
    Gc {
        /// Cache slug.
        cache: String,
        /// Report what would be reclaimed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// List a cache's recent GC runs.
    GcRuns {
        /// Cache slug.
        cache: String,
        /// Maximum runs.
        #[arg(long, default_value_t = 10)]
        limit: i64,
    },
}

/// Parse a duration like `30d`, `12h`, `15m`, `3600s` into seconds.
///
/// # Errors
///
/// Returns an error for an empty value, an unknown unit suffix, or a
/// non-numeric magnitude.
fn parse_duration_secs(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => anyhow::bail!("invalid duration '{s}' (use Ns, Nm, Nh, or Nd)"),
    };
    let n: i64 = num
        .parse()
        .with_context(|| format!("invalid duration magnitude in '{s}'"))?;
    if n < 0 {
        anyhow::bail!("duration '{s}' must not be negative");
    }
    n.checked_mul(mult)
        .with_context(|| format!("duration '{s}' is too large"))
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
        /// Storage binding name within the org (omit for default storage).
        #[arg(long)]
        binding: Option<String>,
        /// Sub-prefix under the storage root (omit to derive from the slug).
        #[arg(long)]
        prefix: Option<String>,
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
    /// Set a registry's crawl policy (robots.txt) through an audited change-set.
    SetCrawlPolicy {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// New policy: allow_all, allow_no_ai, or deny_all.
        policy: String,
    },
    /// Set or clear a registry's custom llms.txt body.
    SetLlmsTxt {
        /// Canonical registry path or flat slug.
        canonical: String,
        /// Read the llms.txt body from this file; omit to clear and
        /// auto-generate.
        #[arg(long)]
        file: Option<String>,
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
            seed,
            external_url,
            brand,
            reindex_interval,
        } => {
            let root = resolve_root(cli.root, dev)?;
            let db = Arc::new(Database::open(&root.join("hub.db")).await?);
            // Optional one-shot demo seed: populate an empty instance so the
            // server comes up with something to browse. seed_dev is idempotent
            // (it no-ops when the demo org already exists), so leaving --seed on
            // across restarts is safe.
            if seed {
                match aos_hub::seed::seed_dev(&db, &root).await {
                    Ok(aos_hub::seed::SeedOutcome::Seeded(report)) => report.print(),
                    Ok(aos_hub::seed::SeedOutcome::AlreadySeeded) => {
                        tracing::info!("seed skipped: demo data already present");
                    }
                    Err(err) => {
                        tracing::warn!(error = %format!("{err:#}"), "dev seed failed");
                    }
                }
            }
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
                        // Retention: prune repair-job history past the window so
                        // the append-only audit table cannot grow without bound.
                        let cutoff = now_secs() - REPAIR_JOB_RETENTION_SECS;
                        match db.prune_repair_jobs(cutoff).await {
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
            tokio::spawn(aos_hub::webhook::run_delivery_worker(
                Arc::clone(&db),
                aos_hub::fetch::hardened_client().await,
            ));

            let external_url = external_url.unwrap_or_else(|| format!("http://{listen}"));
            let mut app_state = AppState::new(db, external_url).await;
            // In dev mode the "check your email" page shows the magic link
            // inline (the default LogMailer logs rather than sends).
            app_state.dev = dev;
            // Seal at-rest secrets (OIDC client secrets, hosted-key seeds) with
            // a real AES-256-GCM sealer keyed by the persisted instance key.
            // `--dev` keeps the reproducible XOR placeholder so local testing
            // does not depend on a generated key file.
            if !dev {
                app_state.sealer = aos_hub::auth::seal::instance_sealer(&root)?.into();
            }
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
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
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
        Command::Registry { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                RegistryCommand::Add {
                    slug,
                    source_url,
                    trust_keys,
                    no_verify,
                } => {
                    validate_slug(&slug)?;
                    let id = db
                        .register_registry(&slug, &source_url, &trust_keys, !no_verify)
                        .await?;
                    let registry = db
                        .registry_by_slug(&slug)
                        .await?
                        .context("registry vanished after registration")?;
                    let fetch = into_core_fetch(fetch_for_url(&source_url).await?);
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
                        .org_by_slug(org_slug)
                        .await?
                        .with_context(|| format!("no org '{org_slug}'"))?;
                    let binding_id = match &binding {
                        Some(name) => Some(
                            db.storage_binding_by_name(org.id, name)
                                .await?
                                .with_context(|| {
                                    format!("no storage binding '{name}' in org '{org_slug}'")
                                })?
                                .id,
                        ),
                        None => None,
                    };
                    let id = db
                        .create_managed_registry(
                            org.id,
                            project_path,
                            name,
                            &visibility,
                            binding_id,
                            prefix.as_deref().unwrap_or_default(),
                            &trust_keys,
                            true,
                        )
                        .await?;
                    let registry = db
                        .registry_by_scope(org_slug, project_path, name)
                        .await?
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
                        .registry_by_slug(&canonical)
                        .await?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    // The CLI actor is the local operator: an out-of-band
                    // `system` principal (no IAM check on the local path).
                    let actor = aos_hub::domain::Principal::user(0);
                    let change_id = aos_hub::config::change_registry_visibility(
                        &db,
                        &actor,
                        "system",
                        registry.id,
                        &visibility,
                    )
                    .await?;
                    println!(
                        "set '{canonical}' visibility to {visibility} (change-set {change_id})"
                    );
                }
                RegistryCommand::SetCrawlPolicy { canonical, policy } => {
                    let parsed = aos_hub::crawl::CrawlPolicy::parse(&policy)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let registry = db
                        .registry_by_slug(&canonical)
                        .await?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    // The CLI actor is the local operator: an out-of-band
                    // `system` principal (no IAM check on the local path).
                    let actor = aos_hub::domain::Principal::user(0);
                    let change_id = aos_hub::config::change_registry_crawl_policy(
                        &db,
                        &actor,
                        "system",
                        registry.id,
                        parsed.as_str(),
                    )
                    .await?;
                    println!(
                        "set '{canonical}' crawl policy to {} (change-set {change_id})",
                        parsed.as_str()
                    );
                }
                RegistryCommand::SetLlmsTxt { canonical, file } => {
                    let registry = db
                        .registry_by_slug(&canonical)
                        .await?
                        .with_context(|| format!("no registry '{canonical}'"))?;
                    match file {
                        Some(path) => {
                            let body = std::fs::read_to_string(&path)
                                .with_context(|| format!("reading llms.txt from '{path}'"))?;
                            db.set_registry_llms_txt(&registry.slug, Some(&body))
                                .await?;
                            println!("set custom llms.txt for '{canonical}' ({path})");
                        }
                        None => {
                            db.set_registry_llms_txt(&registry.slug, None).await?;
                            println!("cleared custom llms.txt for '{canonical}' (auto-generated)");
                        }
                    }
                }
                RegistryCommand::List => {
                    for registry in db.list_registries().await? {
                        let state = db
                            .index_status(registry.id)
                            .await?
                            .map(|s| s.state)
                            .unwrap_or_else(|| "unknown".into());
                        println!("{}\t{}\t{}", registry.slug, registry.source_url, state);
                    }
                }
            }
        }
        Command::Org { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                OrgCommand::Add { slug, name } => {
                    validate_slug(&slug)?;
                    let id = db.create_org(&slug, &name).await?;
                    println!("created org '{slug}' (id {id})");
                }
                OrgCommand::List => {
                    for org in db.list_orgs().await? {
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
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    db.set_org_quota(
                        org_record.id,
                        &aos_hub::db::OrgQuota {
                            max_bytes,
                            max_objects,
                            max_registries,
                            max_tokens,
                        },
                    )
                    .await?;
                    println!("set quota for org '{org}'");
                }
                OrgCommand::Export { org, output } => {
                    ensure_local_target(&cli.target, "org export")?;
                    run_org_export(&db, &org, &output).await?;
                }
                OrgCommand::Delete { org, grace_days } => {
                    let org_record = db
                        .org_by_slug_including_deleted(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    let grace_secs = grace_days.max(0) * 86_400;
                    if db.soft_delete_org(org_record.id, grace_secs).await? {
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
                        .org_by_slug_including_deleted(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    if db.restore_org(org_record.id).await? {
                        println!("restored org '{org}'");
                    } else {
                        println!("org '{org}' was not soft-deleted");
                    }
                }
                OrgCommand::Purge => {
                    let purged = aos_hub::export::purge_expired_orgs(&db, now_secs()).await?;
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
        Command::User { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                UserCommand::SetPassword { email, password } => {
                    let email = email.trim().to_lowercase();
                    // Read the password from stdin unless --password is given.
                    // Trailing newline (the common `echo … |` case) is trimmed.
                    let plaintext = match password {
                        Some(p) => p,
                        None => {
                            use std::io::Read as _;
                            let mut buf = String::new();
                            std::io::stdin()
                                .read_to_string(&mut buf)
                                .context("reading password from stdin")?;
                            buf.trim_end_matches(['\n', '\r']).to_string()
                        }
                    };
                    if plaintext.is_empty() {
                        anyhow::bail!("password must not be empty");
                    }
                    // Create the user if absent (ops bootstrap convenience).
                    let user_id = db.find_or_create_user(&email).await?;
                    let hash = aos_hub::auth::password::hash_password(&plaintext)?;
                    db.set_user_password(user_id, &hash).await?;
                    println!("set password for '{email}' (user id {user_id})");
                }
            }
        }
        Command::Seed => {
            // Seed writes demo `file://` surfaces to disk, so it is local-only.
            let root = resolve_root(cli.root, false)?;
            let db = Database::open(&root.join("hub.db")).await?;
            match aos_hub::seed::seed_dev(&db, &root).await? {
                aos_hub::seed::SeedOutcome::Seeded(report) => report.print(),
                aos_hub::seed::SeedOutcome::AlreadySeeded => {
                    println!("already seeded: demo data is present; nothing to do");
                }
            }
        }
        Command::Instance { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                InstanceCommand::SetSignupPolicy { policy } => {
                    let parsed = match policy.as_str() {
                        "open" => aos_hub::db::SignupPolicy::Open,
                        "invite_only" => aos_hub::db::SignupPolicy::InviteOnly,
                        other => {
                            anyhow::bail!("invalid policy '{other}': open or invite_only")
                        }
                    };
                    db.set_signup_policy(parsed).await?;
                    println!("signup policy set to {}", parsed.as_str());
                }
                InstanceCommand::ShowSignupPolicy => {
                    println!("{}", db.signup_policy().await?.as_str());
                }
                InstanceCommand::SetBrand { brand } => {
                    db.instance_config_set("brand", &brand).await?;
                    if brand.is_empty() {
                        println!("brand cleared");
                    } else {
                        println!("brand set to {brand:?}");
                    }
                }
                InstanceCommand::ShowBrand => {
                    println!(
                        "{}",
                        db.instance_config_get("brand").await?.unwrap_or_default()
                    );
                }
                InstanceCommand::SetRootCrawlPolicy { policy } => {
                    let parsed = aos_hub::crawl::CrawlPolicy::parse(&policy)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    db.set_root_crawl_policy(parsed).await?;
                    println!("root crawl policy set to {}", parsed.as_str());
                }
                InstanceCommand::ShowRootCrawlPolicy => {
                    println!("{}", db.root_crawl_policy().await?.as_str());
                }
                InstanceCommand::SetRootRobots { file } => match file {
                    Some(path) => {
                        let body = std::fs::read_to_string(&path)
                            .with_context(|| format!("reading robots.txt from '{path}'"))?;
                        db.set_root_robots_body(Some(&body)).await?;
                        println!("set custom root robots.txt ({path})");
                    }
                    None => {
                        db.set_root_robots_body(None).await?;
                        println!("cleared custom root robots.txt (auto-generated)");
                    }
                },
                InstanceCommand::SetRootLlms { file } => match file {
                    Some(path) => {
                        let body = std::fs::read_to_string(&path)
                            .with_context(|| format!("reading llms.txt from '{path}'"))?;
                        db.set_root_llms_body(Some(&body)).await?;
                        println!("set custom root llms.txt ({path})");
                    }
                    None => {
                        db.set_root_llms_body(None).await?;
                        println!("cleared custom root llms.txt (auto-generated)");
                    }
                },
                InstanceCommand::SetDefaultStorageRoot { path } => {
                    db.set_default_storage_root(&path).await?;
                    println!("default storage root set to {path:?}");
                }
                InstanceCommand::ShowDefaultStorageRoot => {
                    println!("{}", db.default_storage_root().await?.unwrap_or_default());
                }
            }
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
        Command::Project { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                ProjectCommand::Add { org, path, name } => {
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    let id = db.create_project(org_record.id, &path, &name).await?;
                    println!("created project '{org}/{path}' (id {id})");
                }
                ProjectCommand::List { org } => {
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    for project in db.list_projects(org_record.id).await? {
                        println!("{}\t{}", project.path, project.name);
                    }
                }
            }
        }
        Command::Binding { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                BindingCommand::Add {
                    org,
                    name,
                    kind,
                    path: binding_root,
                } => {
                    aos_hub_core::binding::BindingKind::parse(&kind).with_context(|| {
                        format!(
                            "unknown storage binding kind '{kind}' (expected local_fs, s3, or r2)"
                        )
                    })?;
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    let id = db
                        .create_storage_binding(org_record.id, &name, &kind, &binding_root)
                        .await?;
                    println!(
                        "created binding '{org}/{name}' (id {id}, kind {kind}) -> {binding_root}"
                    );
                }
                BindingCommand::List { org } => {
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    for binding in db.list_storage_bindings(org_record.id).await? {
                        println!(
                            "{}\t{}\t{}\t{}",
                            binding.name, binding.kind, binding.access, binding.root
                        );
                    }
                }
                BindingCommand::SetAccess {
                    org,
                    name,
                    access,
                    endpoint,
                    credential_ref,
                } => {
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    let binding = db
                        .storage_binding_by_name(org_record.id, &name)
                        .await?
                        .with_context(|| format!("no binding '{org}/{name}'"))?;
                    db.set_storage_binding_access(
                        binding.id,
                        &access,
                        endpoint.as_deref(),
                        credential_ref.as_deref(),
                    )
                    .await?;
                    println!("binding '{org}/{name}' access set to {access}");
                }
            }
        }
        Command::Cache { command } => {
            // `Arc` so the GC arm can hand a shared handle to the write provider;
            // every other arm calls through the `Arc` deref unchanged.
            let db = std::sync::Arc::new(open_db(&cli.root, &cli.target).await?);
            match command {
                CacheCommand::Create {
                    slug,
                    org,
                    binding,
                    name,
                    prefix,
                    visibility,
                    priority,
                    compression,
                    no_mass_query,
                } => {
                    let org_record = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    // No `--binding` → the deployment's default storage.
                    let binding_id = match &binding {
                        Some(name) => Some(
                            db.storage_binding_by_name(org_record.id, name)
                                .await?
                                .with_context(|| format!("no binding '{org}/{name}'"))?
                                .id,
                        ),
                        None => None,
                    };
                    let display = name.unwrap_or_else(|| slug.clone());
                    let prefix = prefix.unwrap_or_else(|| slug.clone());
                    let id = db
                        .create_cache(
                            Some(org_record.id),
                            &slug,
                            &display,
                            binding_id,
                            &prefix,
                            None,
                            &visibility,
                            priority,
                            &compression,
                            !no_mass_query,
                        )
                        .await?;
                    let via = binding.as_deref().unwrap_or("default storage");
                    println!("created cache '{slug}' (id {id}) under org '{org}' via '{via}'");
                }
                CacheCommand::List { org } => {
                    let caches = match org {
                        Some(o) => {
                            let r = db
                                .org_by_slug(&o)
                                .await?
                                .with_context(|| format!("no org '{o}'"))?;
                            db.list_caches_for_org(r.id).await?
                        }
                        None => db.list_caches().await?,
                    };
                    for c in caches {
                        println!(
                            "{}\t{}\t{}\tprio={}\t{}",
                            c.slug, c.visibility, c.compression, c.priority, c.name
                        );
                    }
                }
                CacheCommand::Show { slug } => {
                    let c = db
                        .cache_by_slug(&slug)
                        .await?
                        .with_context(|| format!("no cache '{slug}'"))?;
                    let usage = db.cache_usage(c.id).await?;
                    let links = db.list_cache_links(c.id).await?;
                    let roots = db.list_cache_roots(c.id).await?;
                    let policy = db.cache_gc_policy(c.id).await?;
                    println!("slug:        {}", c.slug);
                    println!("name:        {}", c.name);
                    println!(
                        "org_id:      {}",
                        c.org_id
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "(instance)".into())
                    );
                    println!(
                        "binding_id:  {}",
                        c.storage_binding_id
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "(default storage)".into())
                    );
                    println!("prefix:      {}", c.prefix);
                    println!("visibility:  {}", c.visibility);
                    println!("priority:    {}", c.priority);
                    println!("compression: {}", c.compression);
                    println!("mass_query:  {}", c.want_mass_query);
                    println!("signed:      {}", c.hosted_key_id.is_some());
                    println!(
                        "usage:       {} bytes, {} objects",
                        usage.used_bytes, usage.object_count
                    );
                    println!("links:       {}", links.len());
                    println!("roots:       {}", roots.len());
                    println!(
                        "gc_policy:   {}",
                        if policy.is_some() { "set" } else { "default" }
                    );
                }
                CacheCommand::Update {
                    slug,
                    name,
                    visibility,
                    priority,
                    compression,
                    mass_query,
                } => {
                    let c = db
                        .cache_by_slug(&slug)
                        .await?
                        .with_context(|| format!("no cache '{slug}'"))?;
                    db.update_cache(
                        c.id,
                        &name.unwrap_or_else(|| c.name.clone()),
                        &visibility.unwrap_or_else(|| c.visibility.clone()),
                        priority.unwrap_or(c.priority),
                        &compression.unwrap_or_else(|| c.compression.clone()),
                        mass_query.unwrap_or(c.want_mass_query),
                        c.hosted_key_id,
                    )
                    .await?;
                    println!("updated cache '{slug}'");
                }
                CacheCommand::Rm { slug, hard, grace } => {
                    let c = db
                        .cache_by_slug(&slug)
                        .await?
                        .with_context(|| format!("no cache '{slug}'"))?;
                    if hard {
                        let removed = db.delete_cache(c.id).await?;
                        println!(
                            "{}",
                            if removed {
                                format!("hard-deleted cache '{slug}'")
                            } else {
                                format!("no cache '{slug}'")
                            }
                        );
                    } else {
                        let secs = parse_duration_secs(&grace)?;
                        let done = db.soft_delete_cache(c.id, now_secs() + secs).await?;
                        println!(
                            "{}",
                            if done {
                                format!("soft-deleted cache '{slug}' (purge after {grace})")
                            } else {
                                format!("cache '{slug}' was already soft-deleted")
                            }
                        );
                    }
                }
                CacheCommand::Link {
                    cache,
                    registry,
                    roots_packages,
                    advertise,
                } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let r = db
                        .registry_by_slug(&registry)
                        .await?
                        .with_context(|| format!("no registry '{registry}'"))?;
                    db.link_cache(c.id, r.id, roots_packages, advertise).await?;
                    println!(
                        "linked cache '{cache}' <-> registry '{registry}' (roots_packages={roots_packages}, advertise={advertise})"
                    );
                }
                CacheCommand::Unlink { cache, registry } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let r = db
                        .registry_by_slug(&registry)
                        .await?
                        .with_context(|| format!("no registry '{registry}'"))?;
                    let removed = db.unlink_cache(c.id, r.id).await?;
                    println!("{}", if removed { "unlinked" } else { "no such link" });
                }
                CacheCommand::Links { cache } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    for l in db.list_cache_links(c.id).await? {
                        let rslug = db
                            .registry_by_id(l.registry_id)
                            .await?
                            .map(|x| x.slug)
                            .unwrap_or_else(|| format!("#{}", l.registry_id));
                        println!(
                            "{rslug}\troots_packages={}\tadvertised={}",
                            l.roots_packages, l.advertised
                        );
                    }
                }
                CacheCommand::GcPolicy {
                    cache,
                    max_bytes,
                    max_objects,
                    ttl,
                    keep_versions,
                    no_keep_frontier,
                    schedule,
                } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let ttl_unreferenced_secs = ttl.map(|s| parse_duration_secs(&s)).transpose()?;
                    let schedule_secs = schedule.map(|s| parse_duration_secs(&s)).transpose()?;
                    db.set_cache_gc_policy(&aos_hub::db::CacheGcPolicy {
                        cache_id: c.id,
                        max_bytes,
                        max_objects,
                        ttl_unreferenced_secs,
                        keep_release_versions: keep_versions,
                        keep_channel_frontier: !no_keep_frontier,
                        schedule_secs,
                        updated_at: 0,
                    })
                    .await?;
                    println!("set GC policy for cache '{cache}'");
                }
                CacheCommand::Pin {
                    cache,
                    store_hash,
                    ttl,
                } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let expires_at = ttl
                        .map(|s| parse_duration_secs(&s).map(|secs| now_secs() + secs))
                        .transpose()?;
                    db.pin_cache_path(c.id, &store_hash, expires_at).await?;
                    match expires_at {
                        Some(e) => println!("pinned {store_hash} in cache '{cache}' until {e}"),
                        None => println!("pinned {store_hash} in cache '{cache}' (unlimited)"),
                    }
                }
                CacheCommand::Renew {
                    cache,
                    store_hash,
                    ttl,
                } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let expires_at = now_secs() + parse_duration_secs(&ttl)?;
                    db.pin_cache_path(c.id, &store_hash, Some(expires_at))
                        .await?;
                    println!("renewed pin {store_hash} in cache '{cache}' until {expires_at}");
                }
                CacheCommand::Unpin { cache, store_hash } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let removed = db.unpin_cache_path(c.id, &store_hash).await?;
                    println!(
                        "{}",
                        if removed {
                            "unpinned"
                        } else {
                            "no such manual pin"
                        }
                    );
                }
                CacheCommand::Roots { cache } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    for r in db.list_cache_roots(c.id).await? {
                        let exp = r
                            .expires_at
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "-".into());
                        println!(
                            "{}\t{}\t{}\texpires={}",
                            r.store_hash, r.root_kind, r.root_ref, exp
                        );
                    }
                }
                CacheCommand::Search {
                    cache,
                    query,
                    limit,
                } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    for o in db.search_cache_objects(c.id, &query, limit).await? {
                        println!("{}\t{}\t{} bytes", o.store_hash, o.store_name, o.file_size);
                    }
                }
                CacheCommand::Info { cache, store_hash } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    match db.cache_object(c.id, &store_hash).await? {
                        Some(o) => {
                            println!("StorePath:   {}", o.store_name);
                            println!("URL:         {}", o.nar_url);
                            println!("Compression: {}", o.compression);
                            println!("NarHash:     {}", o.nar_hash);
                            println!("NarSize:     {}", o.nar_size);
                            println!("FileHash:    {}", o.file_hash);
                            println!("FileSize:    {}", o.file_size);
                            if let Some(d) = &o.deriver {
                                println!("Deriver:     {d}");
                            }
                            println!("References:  {}", o.refs.join(" "));
                            if let Some(s) = &o.sig {
                                println!("Sig:         {s}");
                            }
                        }
                        None => println!("no object {store_hash} in cache '{cache}'"),
                    }
                }
                CacheCommand::Closure { cache, store_hash } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let mut seen = std::collections::HashSet::new();
                    let mut queue = std::collections::VecDeque::new();
                    queue.push_back(store_hash);
                    let mut total = 0i64;
                    let mut count = 0u64;
                    while let Some(h) = queue.pop_front() {
                        if count >= 10_000 {
                            println!("-- (truncated at 10000 paths)");
                            break;
                        }
                        if !seen.insert(h.clone()) {
                            continue;
                        }
                        match db.cache_object(c.id, &h).await? {
                            Some(o) => {
                                total += o.file_size;
                                count += 1;
                                for r in &o.refs {
                                    if !seen.contains(r) {
                                        queue.push_back(r.clone());
                                    }
                                }
                                println!(
                                    "{}\t{}\t{} bytes",
                                    o.store_hash, o.store_name, o.file_size
                                );
                            }
                            None => println!("{h}\t(missing)"),
                        }
                    }
                    println!("-- {count} paths, {total} bytes total");
                }
                CacheCommand::Gc { cache, dry_run } => {
                    // GC deletes surface files, so it needs the local writable
                    // surface; a d1/worker cache is GC'd by the deployed worker
                    // (the RunCacheGc RPC / its Cron), not this CLI.
                    ensure_local_target(&cli.target, "cache gc")?;
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    let writers = aos_hub::coreports::HubSurfaceWriteProvider::new(
                        std::sync::Arc::clone(&db),
                    );
                    let stats = aos_hub_core::gc::sweep_cache(
                        db.as_ref(),
                        &writers,
                        &c,
                        dry_run,
                        now_secs(),
                    )
                    .await?;
                    println!(
                        "gc {}: scanned {} retained {} deleted {} freed {}B{}",
                        cache,
                        stats.scanned,
                        stats.retained,
                        stats.deleted_objects,
                        stats.freed_bytes,
                        if dry_run { " (dry-run)" } else { "" }
                    );
                }
                CacheCommand::GcRuns { cache, limit } => {
                    let c = db
                        .cache_by_slug(&cache)
                        .await?
                        .with_context(|| format!("no cache '{cache}'"))?;
                    for r in db.list_cache_gc_runs(c.id, limit).await? {
                        println!(
                            "#{}\t{}\tscanned={} retained={} deleted={} freed={}B",
                            r.id, r.status, r.scanned, r.retained, r.deleted_objects, r.freed_bytes
                        );
                    }
                }
            }
        }
        Command::Index { slug } => {
            let db = open_db(&cli.root, &cli.target).await?;
            let registries = match slug {
                Some(slug) => vec![db
                    .registry_by_slug(&slug)
                    .await?
                    .with_context(|| format!("no registry '{slug}'"))?],
                None => db.list_registries().await?,
            };
            for registry in registries {
                let fetch = into_core_fetch(fetch_for_registry(&db, &registry).await?);
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
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                TokenCommand::Mint {
                    path,
                    permissions,
                    expires_days,
                    owner,
                } => mint_token(&db, &path, &permissions, expires_days, &owner).await?,
            }
        }
        Command::Member { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            match command {
                MemberCommand::Grant {
                    org,
                    service_account,
                    role,
                    scope,
                } => {
                    // Validate the role up front so a typo can't persist a
                    // membership that `effective_scopes` later silently drops.
                    aos_hub_core::domain::Role::parse(&role)
                        .with_context(|| format!("unknown role '{role}'"))?;
                    let org_rec = db
                        .org_by_slug(&org)
                        .await?
                        .with_context(|| format!("no org '{org}'"))?;
                    let sa_id = match db
                        .service_account_by_name(org_rec.id, &service_account)
                        .await?
                    {
                        Some(id) => id,
                        None => {
                            db.create_service_account(org_rec.id, &service_account)
                                .await?
                        }
                    };
                    let scope = scope.unwrap_or_else(|| org.clone());
                    db.grant_membership("service_account", sa_id, &scope, &role)
                        .await?;
                    println!(
                        "granted '{role}' at scope '{scope}' to service account '{org}/{service_account}' (id {sa_id})"
                    );
                }
            }
        }
        Command::Audit { scope } => {
            let db = open_db(&cli.root, &cli.target).await?;
            for entry in db.list_audit(&scope).await? {
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
            let db = open_db(&cli.root, &cli.target).await?;
            let sealer = build_sealer(&cli.root, &cli.target, &cli.seal_key)?;
            run_idp_command(&db, sealer.as_ref(), command).await?;
        }
        Command::Domain { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            run_domain_command(&db, command).await?;
        }
        Command::HostedKey { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            let sealer = build_sealer(&cli.root, &cli.target, &cli.seal_key)?;
            run_hosted_key_command(&db, sealer.as_ref(), command).await?;
        }
        Command::Channel { command } => {
            let db = Arc::new(open_db(&cli.root, &cli.target).await?);
            let sealer = build_sealer(&cli.root, &cli.target, &cli.seal_key)?;
            run_channel_command(db, sealer.as_ref(), command).await?;
        }
        Command::Webhook { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            run_webhook_command(&db, command).await?;
        }
        Command::Mirror { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            run_mirror_command(&db, command).await?;
        }
        Command::Frontend { command } => {
            let db = open_db(&cli.root, &cli.target).await?;
            run_frontend_command(&db, command).await?;
        }
        Command::Init {
            root_email,
            root_password,
            root_password_stdin,
        } => {
            // `open_db` opens-and-migrates: `Database::open` migrates the local
            // file; `Database::with_backend` migrates over D1. One unified path,
            // no public init endpoint.
            let db = open_db(&cli.root, &cli.target).await?;
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
    // Grant the root admin `Owner` at the instance-root scope (`""`) so it is a
    // true instance administrator: `Role::Owner` carries `Permission::IamAdmin`
    // at root, which authorizes creating organizations and administering the
    // whole instance. Without this the bootstrapped account can log in but, under
    // the default invite-only signup policy, cannot create an org or do anything.
    db.grant_membership("user", user_id, "", aos_hub::domain::Role::Owner.as_str())
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
            // RFC-0004 ch.14 Phase E: there is no D1. `HubDb` migrates its own
            // schema on first use; the root admin is created via the seal-gated
            // `HubDb` bootstrap endpoint (the D1-free replacement for the old
            // `init --target d1:` step).
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
    // No canonical URL is baked: the Worker derives it from each request's
    // origin (its `*.workers.dev` URL or a bound `--domain`), so it is passed
    // empty here and the `HUB_EXTERNAL_URL` var is omitted from the config.
    let mut cfg = aos_hub::cloudflare::provision(
        assets,
        &args.name,
        &args.bucket(),
        &args.kv_title(),
        "",
        args.email_relay_url.as_deref(),
        &args.domains,
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

    let cfg = provision_worker(assets, args).await?;
    let secrets = cloudflare::Secrets {
        jwt_secret: args.jwt_secret.clone(),
        seal_key: args.seal_key.clone(),
        email_api_token: args.email_api_token.clone(),
    };
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
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            db.create_mirror_source(registry.id, &upstream_url, &mode, true, schedule_secs)
                .await?;
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
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let result = aos_hub::mirror::sync_full_mirror(db, &registry).await?;
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
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            match db.mirror_source(registry.id).await? {
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
async fn run_frontend_command(db: &Database, command: FrontendCommand) -> Result<()> {
    match command {
        FrontendCommand::Add {
            canonical,
            domain,
            mode,
            base_path,
            priority,
        } => {
            let registry = db
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let id = db
                .create_frontend(
                    registry.id,
                    &domain,
                    &base_path,
                    &mode,
                    true,
                    true,
                    true,
                    priority,
                    true,
                )
                .await?;
            println!(
                "added {mode} frontend {id} for '{}': {domain}{base_path} (priority {priority})",
                registry.slug
            );
        }
        FrontendCommand::List { canonical } => {
            let registry = db
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            for frontend in db.list_frontends(registry.id).await? {
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
async fn run_webhook_command(db: &Database, command: WebhookCommand) -> Result<()> {
    match command {
        WebhookCommand::Add {
            org,
            url,
            events,
            secret,
        } => {
            let org_record = db
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            let secret = secret.unwrap_or_else(|| aos_hub::auth::token::generate_token().0);
            let id = db
                .create_webhook(org_record.id, &url, &secret, &events)
                .await?;
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
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            for hook in db.list_webhooks(org_record.id).await? {
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
            if db.delete_webhook(id).await? {
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
/// [`instance_sealer`](aos_hub::auth::seal::instance_sealer) the
/// server uses, so the seed round-trips between this CLI and `serve`.
async fn run_hosted_key_command(
    db: &Database,
    sealer: &dyn aos_hub_core::auth::seal::SecretSealer,
    command: HostedKeyCommand,
) -> Result<()> {
    match command {
        HostedKeyCommand::Create { org, key_id } => {
            let org_record = db
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            let public = db.create_hosted_key(sealer, org_record.id, &key_id).await?;
            println!("enrolled hosted key '{key_id}' in org '{org}'");
            println!("pin this trusted-key line as a registry anchor:");
            println!("{public}");
        }
        HostedKeyCommand::Attach { canonical, key_id } => {
            let registry = db
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            let org_id = registry
                .org_id
                .with_context(|| format!("registry '{canonical}' is not org-owned"))?;
            let key = db
                .hosted_key_by_name(org_id, &key_id)
                .await?
                .with_context(|| format!("no hosted key '{key_id}' in the registry's org"))?;
            db.set_registry_hosted_key(registry.id, Some(key.id))
                .await?;
            println!(
                "attached hosted key '{key_id}' to registry '{}'",
                registry.slug
            );
        }
        HostedKeyCommand::List { org } => {
            let org_record = db
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            for key in db.list_hosted_keys(org_record.id).await? {
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
async fn run_channel_command(
    db: Arc<Database>,
    sealer: &dyn aos_hub_core::auth::seal::SecretSealer,
    command: ChannelCommand,
) -> Result<()> {
    match command {
        ChannelCommand::Advance {
            canonical,
            channel,
            semver,
            count,
        } => {
            let registry = db
                .registry_by_slug(&canonical)
                .await?
                .with_context(|| format!("no registry '{canonical}'"))?;
            if registry.hosted_key_id.is_none() {
                anyhow::bail!(
                    "registry '{canonical}' has no hosted signing key; prepare the advance for \
                     client-side signing in the console (apr channel advance --from-hub), or \
                     attach a hosted key with `hosted-key attach`"
                );
            }
            let when = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let surface_write = aos_hub::coreports::HubSurfaceWriteProvider::new(Arc::clone(&db));
            let reindexer = aos_hub::coreports::HubReindexer::new(Arc::clone(&db));
            let outcome = aos_hub::signing::advance_channel(
                &db,
                sealer,
                &surface_write,
                &reindexer,
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
/// [`instance_sealer`](aos_hub::auth::seal::instance_sealer) the
/// server uses before storing it, so the secret round-trips to `serve`;
/// `show` prints the configuration with the secret redacted.
async fn run_idp_command(
    db: &Database,
    sealer: &dyn aos_hub_core::auth::seal::SecretSealer,
    command: IdpCommand,
) -> Result<()> {
    use aos_hub::db::IdpConfigRecord;
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
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            // Validate the role map and default role parse before storing.
            let _: serde_json::Value = serde_json::from_str(&role_map)
                .with_context(|| "--role-map must be a JSON object")?;
            if aos_hub::domain::Role::parse(&default_role).is_none() {
                anyhow::bail!("invalid --default-role '{default_role}'");
            }
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
            })
            .await?;
            println!("configured OIDC IdP for org '{org}'");
        }
        IdpCommand::Show { org } => {
            let org_record = db
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            match db.idp_config(org_record.id).await? {
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
async fn run_domain_command(db: &Database, command: DomainCommand) -> Result<()> {
    match command {
        DomainCommand::Add { org, domain } => {
            let org_record = db
                .org_by_slug(&org)
                .await?
                .with_context(|| format!("no org '{org}'"))?;
            let challenge = db.add_org_domain(org_record.id, &domain).await?;
            println!("claimed '{domain}' for org '{org}' (unverified)");
            println!("publish this TXT record at the domain, then run `domain verify`:");
            println!("  {challenge}");
        }
        DomainCommand::Verify { domain, txt } => {
            let record = db
                .org_domain(&domain)
                .await?
                .with_context(|| format!("domain '{domain}' is not claimed by any org"))?;
            if let Some(txt) = &txt {
                if txt.trim() != record.txt_challenge {
                    anyhow::bail!(
                        "TXT value does not match the challenge for '{domain}' (expected '{}')",
                        record.txt_challenge
                    );
                }
            }
            if db.verify_org_domain(&domain).await? {
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
async fn mint_token(
    db: &Database,
    path: &str,
    permissions: &[String],
    expires_days: Option<i64>,
    owner: &str,
) -> Result<()> {
    // A path with no `/` is an org-scoped (admin) token: its scope is the org
    // itself, spanning every registry and cache beneath it — needed for
    // org-level operations such as a managed-cache push (which gates on
    // `RegistryConfigure` at the org scope). Otherwise it is the usual registry
    // canonical path (`org/[project/]name`).
    let (org_slug, canonical): (String, String) = match path.trim_matches('/').split_once('/') {
        None => {
            let org = path.trim_matches('/').to_string();
            if org.is_empty() {
                anyhow::bail!("token path must be an org or org/project/name");
            }
            (org.clone(), org)
        }
        Some(_) => {
            let (org_slug, project_path, name) = parse_canonical_path(path)?;
            let canonical = if project_path.is_empty() {
                format!("{org_slug}/{name}")
            } else {
                format!("{org_slug}/{project_path}/{name}")
            };
            (org_slug.to_string(), canonical)
        }
    };
    let org = db
        .org_by_slug(&org_slug)
        .await?
        .with_context(|| format!("no org '{org_slug}'"))?;

    let mut perms = Vec::new();
    for verb in permissions {
        let perm = aos_hub::auth::permission_from_str(verb)
            .with_context(|| format!("unknown permission '{verb}' (expected publish or read)"))?;
        perms.push(perm);
    }

    // Per-org active-token quota (NULL/unset = unlimited).
    if let Some(max_tokens) = db.org_quota(org.id).await?.max_tokens {
        if db.org_active_token_count(org.id).await? >= max_tokens {
            anyhow::bail!("org active-token quota of {max_tokens} reached");
        }
    }

    // Find or create the owning service account.
    let sa_id = match db.service_account_by_name(org.id, owner).await? {
        Some(id) => id,
        None => db.create_service_account(org.id, owner).await?,
    };
    let principal = aos_hub::domain::Principal::service_account(sa_id);

    // Grant the service account a maintainer role at the registry scope so
    // its effective authority covers the token's grants.
    db.grant_membership(
        "service_account",
        sa_id,
        &canonical,
        aos_hub::domain::Role::Maintainer.as_str(),
    )
    .await?;

    let expires_at = expires_days.map(|days| now_secs() + days * 86_400);
    let (token_id, secret) = db
        .create_token(
            principal,
            &canonical,
            &perms,
            Some(&format!("publisher token for {canonical}")),
            expires_at,
        )
        .await?;

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

/// Resolve the surface fetcher for a registry.
///
/// Managed registries (and `file://` registration-only ones) serve from a
/// local surface — their storage-binding root or local path — which
/// [`Database::registry_surface_root`] resolves; their `source_url` is
/// empty, so they must not go through [`fetch_for_url`]. Everything else is
/// an `http(s)` registration-only source.
///
/// # Errors
///
/// Returns an error when the registry has neither a local surface nor a
/// usable source URL.
async fn fetch_for_registry(
    db: &Database,
    registry: &RegistryRecord,
) -> Result<Box<dyn SurfaceFetch>> {
    if let Some(root) = db.registry_surface_root(registry.id).await? {
        return Ok(Box::new(LocalFsFetch::new(root)));
    }
    fetch_for_url(&registry.source_url).await
}

/// The persisted masthead brand (`instance_config['brand']`), or empty.
async fn state_brand(app_state: &AppState) -> Result<String> {
    Ok(app_state
        .db
        .instance_config_get("brand")
        .await?
        .unwrap_or_default())
}

/// Export an org's SoR manifest and registry surfaces to `output`.
///
/// Writes `output/manifest.json` (the redacted SQL system of record) plus one
/// directory per registry under `output/registries/<slug-with-slashes>/`,
/// each a portable, re-servable surface copy.
async fn run_org_export(db: &Database, org: &str, output: &Path) -> Result<()> {
    use aos_hub::export::{export_org, export_registry_surface};

    std::fs::create_dir_all(output)
        .with_context(|| format!("creating export dir {}", output.display()))?;
    let manifest = export_org(db, org).await?;
    let manifest_path = output.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    println!("wrote {}", manifest_path.display());

    // Copy each registry's surface (resolved through its storage binding).
    let org_record = db
        .org_by_slug_including_deleted(org)
        .await?
        .with_context(|| format!("no org '{org}'"))?;
    for registry in db.list_registries_including_org(org_record.id).await? {
        let dest = output
            .join("registries")
            .join(registry.slug.replace('/', "_"));
        let copied = export_registry_surface(db, registry.id, &dest).await?;
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
    let registries = match db.list_registries().await {
        Ok(regs) => regs,
        Err(err) => {
            tracing::error!(error = %format!("{err:#}"), "listing registries");
            return;
        }
    };
    for registry in registries {
        let fetch = match fetch_for_registry(db, &registry).await {
            Ok(fetch) => into_core_fetch(fetch),
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

/// Probe each configured frontend's freshness for one registry, logging a
/// one-line summary per frontend; probe failures are logged, never fatal.
async fn run_frontend_probes(db: &Database, registry: &RegistryRecord) {
    let http = aos_hub::fetch::hardened_client().await;
    match aos_hub::probe::probe_frontends(db, &http, registry).await {
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
    Ok(root)
}

/// Opens the `Database` for the selected `--target`, so the admin commands share
/// one tree across deployment backends.
///
/// - `local` — the native sqlite file under `--root` ([`Database::open`]).
/// - `d1:<name>` — a live Cloudflare D1 database via the bundled `wrangler`
///   ([`cloudflare::WranglerD1Backend`], remote).
/// - `d1-local:<name>` — the local miniflare D1 engine (for testing).
///
/// The D1 targets attach via [`Database::with_backend`], which applies the shared
/// migrations idempotently.
///
/// # Errors
///
/// Returns an error for an unknown `--target`, or if the local file / D1 backend
/// cannot be opened.
async fn open_db(root: &Option<PathBuf>, target: &str) -> Result<Database> {
    if target == "local" {
        let root = resolve_root(root.clone(), false)?;
        return Database::open(&root.join("hub.db")).await;
    }
    // RFC-0004 ch.14 Phase E: there is no D1. The Cloudflare hub's system of
    // record is the `HubDb` Durable Object's colocated SQLite, which migrates
    // itself and is administered through the Worker's seal-gated endpoints
    // (`worker bootstrap-root`, the publish/RPC API) — not by the CLI opening the
    // database directly. The CLI's `open_db` serves only a `local` native-hub DB.
    anyhow::bail!(
        "unknown --target '{target}' (expected: local). The Cloudflare hub uses the \
         HubDb Durable Object — there is no D1 to open; use `aos-hub worker …` \
         (bootstrap-root / deploy) or the Worker API to administer it."
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

/// Builds the at-rest secret [`SecretSealer`] for the selected `--target`.
///
/// For `local`, the on-disk instance key under `--root`
/// ([`instance_sealer`](aos_hub::auth::seal::instance_sealer)). For a D1
/// target, the deployment's seal key from `--seal-key` (or the `HUB_SEAL_KEY`
/// environment variable) — the *same* key the running hub/Worker uses, so sealed
/// secrets round-trip — derived exactly as the Worker derives it (a key of the
/// right length is used verbatim, else SHA-256 of the string).
///
/// # Errors
///
/// Returns an error if the local instance key cannot be loaded, or if a D1
/// target has no `--seal-key`/`HUB_SEAL_KEY`, or the derived key is rejected.
fn build_sealer(
    root: &Option<PathBuf>,
    target: &str,
    seal_key: &Option<String>,
) -> Result<Box<dyn aos_hub_core::auth::seal::SecretSealer>> {
    use aos_hub_core::auth::seal::{parse_key, AesGcmSealer};

    if target == "local" {
        let root = resolve_root(root.clone(), false)?;
        return aos_hub::auth::seal::instance_sealer(&root);
    }
    let key_string = seal_key
        .clone()
        .or_else(|| std::env::var("HUB_SEAL_KEY").ok())
        .filter(|s| !s.is_empty())
        .context(
            "a non-local --target needs the deployment's seal key for this command; \
             pass --seal-key or set HUB_SEAL_KEY (the same value used at deploy)",
        )?;
    // Mirror the Worker's `sealer_from_secret`: a correctly-sized key is used
    // as-is, otherwise SHA-256 of the string is the instance key.
    let key = parse_key(key_string.as_bytes()).unwrap_or_else(|_| {
        use sha2::{Digest, Sha256};
        Sha256::digest(key_string.as_bytes()).to_vec()
    });
    Ok(Box::new(AesGcmSealer::new(&key)?))
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

/// Reject slugs that would collide with reserved top-level routes or the
/// `/-/` namespace, or that fall outside the canonical single-segment
/// charset.
///
/// Thin CLI adapter over the shared
/// [`aos_hub::domain::iam::validate_org_slug`] ruleset, so the CLI,
/// the Connect RPC, and the web console enforce the *same* slug grammar.
fn validate_slug(slug: &str) -> Result<()> {
    aos_hub::domain::iam::validate_org_slug(slug)
        .map_err(|e| anyhow::anyhow!("invalid slug '{slug}': {e}"))
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
