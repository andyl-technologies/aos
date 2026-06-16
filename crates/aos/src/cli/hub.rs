//! Arguments for `aos hub` — the registry-hub control-plane client.
//!
//! These subcommands interact with a running `aos-registry-hub` purely through
//! its public ConnectRPC API (RFC-0004), never by touching the hub's database
//! directly. Read operations work anonymously against the hub's public browse
//! surface; authenticated and write operations are layered on in later RFC-0004
//! Phase 5 increments.
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
}
