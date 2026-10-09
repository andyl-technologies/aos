//! Adopts an executor-authenticated fixture bundle through native deployment.
//!
//! The isolated qualification runner authenticates the original fixture archive,
//! source inventory, bundle NAR identities, and admission digest before invoking
//! this test-support command. A caller-supplied digest establishes integrity,
//! not independent source or TPM authority. The production deployment API keeps
//! the original descriptor, catalog, and ordered sources in the normal profile
//! generations and journals; later operator snapshots use ordinary APM admission.

use std::path::{Component, PathBuf};

use anyhow::{Result, bail, ensure};
use aos_ability_runtime::adapter::CancellationToken;
use aos_contract::Sha256Digest;
use aos_package::native_deployment::{NativeDeploymentCommand, apply};
use aos_release::artifact::require_store_path;

/// Applies the exact fixture bundle whose custody the runner already verified.
///
/// # Errors
/// Returns an error for malformed arguments, changed immutable inputs or NARs,
/// invalid admission, profile contention, journal errors, or failed native effects.
pub(super) fn adopt(arguments: &[String]) -> Result<()> {
    let command = command(arguments)?;
    apply(&command, &CancellationToken::default())
}

fn command(arguments: &[String]) -> Result<NativeDeploymentCommand> {
    if arguments.len() != 4 {
        bail!(
            "usage: aos-release-fleet-fixture adopt-native-fixture BUNDLE ADMISSION_SHA256 NIX_STORE PROFILE"
        );
    }

    require_store_path(&arguments[0], false)?;
    let input = PathBuf::from(&arguments[0]);
    let digest = Sha256Digest::parse(&arguments[1])?;
    let Some(store_root) = arguments[2].strip_suffix("/bin/nix-store") else {
        bail!("fixture adoption requires an immutable AOS nix-store executable");
    };
    require_store_path(store_root, false)?;

    let profile = PathBuf::from(&arguments[3]);
    ensure!(
        profile.is_absolute()
            && profile.components().all(|component| {
                matches!(component, Component::RootDir | Component::Normal(_))
            })
            && profile != std::path::Path::new("/"),
        "fixture adoption requires an absolute profile without traversal"
    );

    Ok(NativeDeploymentCommand {
        admission: input.join("admission.json"),
        input,
        state_directory: profile.join("deployment"),
        profile: Some(profile),
        nix_store: PathBuf::from(&arguments[2]),
        admission_sha256: digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<String> {
        vec![
            "/nix/store/00000000000000000000000000000000-fixture-bundle".into(),
            format!("sha256:{}", "a".repeat(64)),
            "/nix/store/11111111111111111111111111111111-nix/bin/nix-store".into(),
            "/var/lib/profiles/system".into(),
        ]
    }

    #[test]
    fn preserves_original_bundle_digest_and_authoritative_profile_journal() {
        let arguments = arguments();
        let command = command(&arguments).unwrap();

        assert_eq!(command.input, PathBuf::from(&arguments[0]));
        assert_eq!(command.admission, command.input.join("admission.json"));
        assert_eq!(
            command.admission_sha256,
            Sha256Digest::parse(&arguments[1]).unwrap()
        );
        assert_eq!(command.profile, Some(PathBuf::from(&arguments[3])));
        assert_eq!(
            command.state_directory,
            PathBuf::from(&arguments[3]).join("deployment")
        );
    }

    #[test]
    fn rejects_unpinned_or_noncanonical_inputs_before_deployment() {
        for (index, replacement) in [
            (0, "/tmp/bundle"),
            (
                0,
                "/nix/store/00000000000000000000000000000000-bundle/../other",
            ),
            (1, "invalid-digest"),
            (2, "/usr/bin/nix-store"),
            (
                2,
                "/nix/store/11111111111111111111111111111111-nix/bin/other",
            ),
            (3, "relative-profile"),
            (3, "/var/lib/profiles/../other"),
            (3, "/"),
        ] {
            let mut arguments = arguments();
            arguments[index] = replacement.into();

            assert!(command(&arguments).is_err(), "accepted {replacement}");
        }
        assert!(command(&[]).is_err());
    }
}
