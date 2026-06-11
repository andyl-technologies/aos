//! Arguments for `aos token` — server-side provisioning-token management.
//!
//! `TokenCmd` defines the lifecycle operations on provisioning tokens
//! (`create`, `list`, `revoke`, `rotate`). These run against a local
//! `aos serve` instance over its trusted bootstrap Unix socket, so no
//! authentication flags are needed.
//!
//! Doc comments here are clap `--help` text; the implementation lives in
//! `commands::token`.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Create a new provisioning token
    Create {
        /// Views this token can access (repeatable)
        #[arg(short, long, required = true)]
        view: Vec<String>,
        /// Comma-separated permissions (e.g., "read,build")
        #[arg(short, long, default_value = "read")]
        permissions: String,
        /// Token expiry duration (e.g., "90d", "24h")
        #[arg(short, long)]
        expires: Option<String>,
        /// Optional comment / description
        #[arg(long)]
        comment: Option<String>,
    },
    /// List active provisioning tokens
    List,
    /// Revoke a provisioning token
    Revoke {
        /// Token ID to revoke
        #[arg(long)]
        token_id: String,
    },
    /// Rotate a provisioning token (revoke old + create new)
    Rotate {
        /// Token ID to rotate
        #[arg(long)]
        token_id: String,
    },
}
