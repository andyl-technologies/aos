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
            committed_source,
        } => aos_package::metadata::eval_provisioning_main(
            &aos_package::metadata::EvalProvisioningOptions {
                stash_dir: std::path::PathBuf::from(
                    aos_package::metadata::stash::DEFAULT_STASH_DIR,
                ),
                base_lib: base_lib.clone(),
                eval_root: eval_root.clone(),
                measured_boot: *measured_boot,
                committed_source: committed_source.as_deref().map(str::parse).transpose()?,
            },
        ),
        MetadataCmd::VerifyBinding => aos_package::metadata::verify_binding_main(
            std::path::Path::new(aos_package::metadata::stash::DEFAULT_STASH_DIR),
        ),
        MetadataCmd::PersistProvisioning {
            state_dir,
            module_abi,
            image_version,
        } => {
            aos_package::metadata::state::persist_provisioning_state(
                &aos_package::metadata::PersistProvisioningOptions {
                    stash_dir: std::path::PathBuf::from(
                        aos_package::metadata::stash::DEFAULT_STASH_DIR,
                    ),
                    state_dir: state_dir.clone(),
                    module_abi: *module_abi,
                    image_version: image_version.clone(),
                },
            )?;
            Ok(())
        }
        MetadataCmd::CacheRuntime { state_dir } => {
            aos_package::metadata::state::cache_runtime_input(
                std::path::Path::new(aos_package::metadata::stash::DEFAULT_STASH_DIR),
                state_dir,
            )?;
            Ok(())
        }
        MetadataCmd::RestoreRuntime { state_dir } => {
            aos_package::metadata::state::restore_runtime_input(
                std::path::Path::new(aos_package::metadata::stash::DEFAULT_STASH_DIR),
                state_dir,
            )?;
            Ok(())
        }
    }
}
