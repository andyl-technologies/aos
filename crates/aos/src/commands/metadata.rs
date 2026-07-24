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
/// platform fetcher and stashes exact payload + facts; `authorize` applies the
/// measured trust policy before producing exact `host.nix`; and
/// `eval-provisioning` evaluates only the closed one-time projection.
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
        MetadataCmd::Authorize {
            trust,
            trusted_config_keys_dir,
        } => {
            let opts = aos_package::metadata::AuthorizeOptions {
                stash_dir: std::path::PathBuf::from(
                    aos_package::metadata::stash::DEFAULT_STASH_DIR,
                ),
                trust: trust.parse()?,
                trusted_config_key_dirs: trusted_config_keys_dir.clone(),
            };
            aos_package::metadata::authorize_main(&opts).await
        }
        MetadataCmd::EvalProvisioning {
            base_lib,
            eval_root,
            measured_boot,
        } => aos_package::metadata::eval_provisioning_main(
            &aos_package::metadata::EvalProvisioningOptions {
                stash_dir: std::path::PathBuf::from(
                    aos_package::metadata::stash::DEFAULT_STASH_DIR,
                ),
                base_lib: base_lib.clone(),
                eval_root: eval_root.clone(),
                measured_boot: *measured_boot,
            },
        ),
        MetadataCmd::VerifyBinding => aos_package::metadata::verify_binding_main(
            std::path::Path::new(aos_package::metadata::stash::DEFAULT_STASH_DIR),
        ),
    }
}
