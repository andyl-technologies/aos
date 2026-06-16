//! Arguments for `aos hub` — the registry-hub control-plane client.
//!
//! These subcommands interact with a running `aos-registry-hub` purely through
//! its public ConnectRPC API (RFC-0004), never by touching the hub's database
//! directly. Public browse reads (registries, releases, packages, channels) run
//! anonymously; tenancy and audit reads (orgs, projects, bindings, audit,
//! change-sets) take a `--token` hub access JWT. Write operations are layered on
//! in later RFC-0004 Phase 5 increments.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::hub`, which drives `aos_remote::RegistryHubClient`.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum HubCmd {
    /// Inspect registries on a hub
    Registry {
        #[command(subcommand)]
        command: HubRegistryCmd,
    },
    /// List the organizations you can see (needs --token)
    Orgs {
        /// Hub base URL (http:// or https://)
        #[arg(long)]
        hub: String,
        /// Hub access JWT (orgs are private; omit only to confirm none are public)
        #[arg(long)]
        token: Option<String>,
    },
    /// List the projects under an org
    Projects {
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
    /// List the storage bindings under an org
    Bindings {
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
