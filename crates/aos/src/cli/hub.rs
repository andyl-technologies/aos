//! Arguments for `aos hub` — the registry-hub control-plane client.
//!
//! These subcommands interact with a running `aos-registry-hub` purely through
//! its public ConnectRPC API (RFC-0004), never by touching the hub's database
//! directly. `login` exchanges a provisioning secret for that JWT. Public browse
//! reads (registries, releases, packages, channels) run anonymously; tenancy and
//! audit reads (`org`/`project`/`binding list`, audit, change-sets) take a
//! `--token` hub access JWT, as do the tenancy writes (`org`/`project`/`binding
//! create`). Further write operations are layered on in later RFC-0004 Phase 5
//! increments.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::hub`, which drives `aos_remote::RegistryHubClient`.

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
        /// Backend kind (only `local_fs` is supported this phase)
        #[arg(long, default_value = "local_fs")]
        kind: String,
        /// Backend root (an absolute filesystem path for local_fs)
        #[arg(long)]
        root: String,
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
}
