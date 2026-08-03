//! Arguments for `aos hub` — the registry-hub control-plane client.
//!
//! These subcommands interact with a running `aos-hub` purely through
//! its public ConnectRPC API (RFC-0004), never by touching the hub's database
//! directly. `login` exchanges a provisioning secret for that JWT. Public browse
//! reads (registries, releases, packages, channels) run anonymously; tenancy and
//! audit reads (`org`/`project`/`binding list`, audit, change-sets) take a
//! `--token` hub access JWT, as do the tenancy writes (`org`/`project`/`binding
//! create`). Further write operations are layered on in later RFC-0004 Phase 5
//! increments.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::hub`, which drives `aos_remote::HubClient`.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum HubCmd {
    /// Exchange a provisioning secret for a hub access JWT
    Login {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// The `aos_`-prefixed provisioning secret to exchange
        #[arg(long)]
        provisioning_token: String,
    },
    /// Inspect registries on a hub
    Registry {
        #[command(subcommand)]
        command: HubRegistryCmd,
    },
    /// Manage binary caches
    Cache {
        #[command(subcommand)]
        command: HubCacheCmd,
    },
    /// Manage organizations (the tenant boundary)
    Org {
        #[command(subcommand)]
        command: HubOrgCmd,
    },
    /// Manage projects within an org
    Project {
        #[command(subcommand)]
        command: HubProjectCmd,
    },
    /// Manage storage bindings within an org
    Binding {
        #[command(subcommand)]
        command: HubBindingCmd,
    },
    /// Manage outbound webhooks within an org
    Webhook {
        #[command(subcommand)]
        command: HubWebhookCmd,
    },
    /// View and edit deployment-wide instance settings (needs instance admin)
    Instance {
        #[command(subcommand)]
        command: HubInstanceCmd,
    },
    /// Draft and apply a forward revert of a change-set (needs registry.configure)
    RevertChangeset {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// The change-set id to revert
        #[arg(long)]
        change_id: String,
    },
    /// Mint a short-lived, registry-scoped upload credential (needs publish)
    MintUpload {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Canonical registry slug to mint an upload credential for
        #[arg(long)]
        slug: String,
    },
    /// List audit-log entries at a scope (newest first; needs --token)
    Audit {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (audit reads require audit.read on the scope)
        #[arg(long)]
        token: Option<String>,
        /// Scope path to filter on; omit for the instance-wide root scope
        #[arg(long, default_value = "")]
        scope: String,
    },
    /// List configuration change-sets at a scope (newest first; needs --token)
    Changesets {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (change-set reads require audit.read on the scope)
        #[arg(long)]
        token: Option<String>,
        /// Scope path to filter on; omit for the instance-wide root scope
        #[arg(long, default_value = "")]
        scope: String,
    },
}

#[derive(Subcommand)]
pub enum HubInstanceCmd {
    /// Show the deployment-wide instance settings (needs instance admin)
    Get {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (instance settings require iam.admin at the root)
        #[arg(long)]
        token: Option<String>,
    },
    /// Set or clear instance settings keys (needs instance admin)
    ///
    /// Pass one or more `key=value` pairs; an empty value (`key=`) clears the
    /// key to its default. Keys: site_title, tagline, announcement, tos_url,
    /// privacy_url, support_url, signup_policy, signup_domains, password_login,
    /// session_lifetime_secs, default_crawl_policy, max_upload_bytes.
    Set {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (instance settings require iam.admin at the root)
        #[arg(long)]
        token: Option<String>,
        /// One or more `key=value` assignments (empty value clears the key)
        #[arg(value_name = "KEY=VALUE", required = true)]
        assignments: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum HubOrgCmd {
    /// List the organizations you can see (needs --token)
    List {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (orgs are private; omit only to confirm none are public)
        #[arg(long)]
        token: Option<String>,
    },
    /// Create an org (the caller becomes its Owner; needs --token)
    Create {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug (the tenant identifier)
        #[arg(long)]
        slug: String,
        /// Human-readable org name
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HubProjectCmd {
    /// List the projects under an org
    List {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
    },
    /// Create a project at a path under an org (needs registry.configure)
    Create {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
        /// Materialized path within the org (omit for an org-root project)
        #[arg(long, default_value = "")]
        path: String,
        /// Human-readable project name
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum HubBindingCmd {
    /// List the storage bindings under an org
    List {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
    },
    /// Create a storage binding under an org (needs registry.configure)
    Create {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
        /// Binding name
        #[arg(long)]
        name: String,
        /// Backend kind: local_fs, s3, or r2
        #[arg(long, default_value = "local_fs")]
        kind: String,
        /// Backend root: an absolute path for local_fs, or the bucket (optionally
        /// bucket/sub-prefix) for s3/r2
        #[arg(long)]
        root: String,
        /// Endpoint origin URL for s3/r2 (e.g. https://<acct>.r2.cloudflarestorage.com)
        #[arg(long)]
        endpoint: Option<String>,
        /// Signing region for s3/r2 (defaults to "auto")
        #[arg(long)]
        region: Option<String>,
        /// Access mode for s3/r2: private (default) or public
        #[arg(long, default_value = "private")]
        access: String,
        /// Access key id for a private s3/r2 binding
        #[arg(long)]
        access_key_id: Option<String>,
        /// Secret access key for a private s3/r2 binding
        #[arg(long)]
        secret_access_key: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum HubWebhookCmd {
    /// List an org's webhook subscriptions (secrets are never shown)
    List {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
    },
    /// Create a webhook under an org (needs members.manage)
    Create {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Org slug
        #[arg(long)]
        org: String,
        /// Destination URL each subscribed event is POSTed to
        #[arg(long)]
        url: String,
        /// Event type to subscribe to (repeatable; omit to subscribe to all)
        #[arg(long = "event")]
        event: Vec<String>,
        /// Shared HMAC secret (omit to have the hub generate one)
        #[arg(long, default_value = "")]
        secret: String,
    },
    /// Delete a webhook by id (needs members.manage)
    Delete {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Webhook id
        #[arg(long)]
        id: i64,
    },
}

/// `aos hub cache` — binary-cache management over the Connect API.
#[derive(Subcommand)]
pub enum HubCacheCmd {
    /// Migrate a cache's surface to a different storage backend
    ChangeStorage {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (needs cache-admin authority)
        #[arg(long)]
        token: Option<String>,
        /// Cache slug
        slug: String,
        /// Target storage binding name; omit for the deployment default store
        #[arg(long)]
        binding: Option<String>,
    },
    /// Link (or update) a managed cache to a registry
    Link {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (needs registry.configure on the registry)
        #[arg(long)]
        token: Option<String>,
        /// Cache slug
        cache: String,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        registry: String,
        /// Advertise the cache to the registry's consumers (write-through to its
        /// committed registry.toml [[caches]] as a change request)
        #[arg(long)]
        advertise: bool,
        /// Pin the registry's packages as GC roots in this cache
        #[arg(long)]
        roots_packages: bool,
    },
    /// Remove a managed cache's link to a registry (and de-advertise it)
    Unlink {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (needs registry.configure on the registry)
        #[arg(long)]
        token: Option<String>,
        /// Cache slug
        cache: String,
        /// Registry slug
        registry: String,
    },
}

#[derive(Subcommand)]
pub enum HubRegistryCmd {
    /// List registries (public ones when unauthenticated)
    List {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
    },
    /// Show one registry by slug
    Get {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// Migrate a registry's surface to a different storage backend
    ChangeStorage {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (needs registry.configure on the registry scope)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
        /// Target storage binding name; omit for the deployment default store
        #[arg(long)]
        binding: Option<String>,
    },
    /// List a registry's verified releases (newest first)
    Releases {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// List a registry's published packages
    Packages {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// List a registry's rollout channels
    Channels {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// Create an org-owned managed registry (needs registry.configure)
    Create {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Owning org slug
        #[arg(long)]
        org: String,
        /// Owning project's materialized path (omit for an org-root registry)
        #[arg(long, default_value = "")]
        project_path: String,
        /// Registry name (the last canonical-path segment)
        #[arg(long)]
        name: String,
        /// Visibility: public | internal | private
        #[arg(long, default_value = "private")]
        visibility: String,
        /// Storage binding name within the org (omit for an unbound registry)
        #[arg(long, default_value = "")]
        binding: String,
        /// Sub-prefix under the binding root
        #[arg(long, default_value = "")]
        prefix: String,
        /// Pinned trust anchor in name:Ed25519:<base64> form (repeatable)
        #[arg(long = "trust-key")]
        trust_key: Vec<String>,
    },
    /// Show a registry's committed config commit log (newest first)
    Log {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// Show a textual diff of a registry's committed config between two commits
    Diff {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
        /// Base commit oid (omit to diff the whole tree as additions)
        #[arg(long, default_value = "")]
        from: String,
        /// Target commit oid (omit to default to the current HEAD)
        #[arg(long, default_value = "")]
        to: String,
    },
    /// List a registry's draft git-backed change requests
    ChangeRequests {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
    },
    /// Show full detail for one package (every version and platform)
    Package {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
        /// Package name
        name: String,
    },
    /// Show one rollout channel with its 256-partition map
    Channel {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT for authenticated access (omit for public reads)
        #[arg(long)]
        token: Option<String>,
        /// Registry slug (e.g. `acme/infra/prod/cdn`)
        slug: String,
        /// Channel name
        name: String,
    },
}
