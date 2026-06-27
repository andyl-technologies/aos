//! The `aos metadata` subcommand — the cross-cloud user-data fetch agent.
//!
//! A thin dispatcher over [`aos_package::metadata`], which owns the agent: the
//! DMI detection table, the `PlatformFetcher` trait and its per-platform
//! implementations, the config-drive mount helper, and the `/run/aos-metadata`
//! stash. This module only maps the parsed [`MetadataCmd`] to the production
//! entry points; all logic and tests live in `aos-package`.

use anyhow::Result;

use crate::cli::MetadataCmd;

/// Dispatch a parsed `aos metadata` subcommand to its agent entry point.
///
/// `detect` writes `/run/aos-metadata/platform.env`; `fetch` selects the
/// platform fetcher and stashes the untrusted payload + facts. Both are
/// transport-only: no signature is verified here (stage-2's job).
///
/// # Errors
///
/// Propagates any error from the agent: a failed probe/mount, a transport
/// failure after retries, or a stash write failure. A platform with no
/// user-data attached is not an error.
pub async fn run(command: &MetadataCmd) -> Result<()> {
    match command {
        MetadataCmd::Detect => aos_package::metadata::detect_main(),
        MetadataCmd::Fetch => aos_package::metadata::fetch_main().await,
    }
}
