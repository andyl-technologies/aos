//! Protected root admission of a separate-purpose Source hold signer pin.
//!
//! The optional AOSSPK01 credential contains only a public key. Root retains
//! its exact bytes after deployment/project pin admission; replay is allowed,
//! but removal, rotation, and reuse across owner roles fail closed.

#[cfg(all(test, target_os = "linux"))]
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::journal::JournalError;

#[cfg(all(test, target_os = "linux"))]
use aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1;

/// Reports a rejected Source-only signer pin admission.
#[derive(Debug, thiserror::Error)]
pub enum SourceHoldPinErrorV1 {
    /// The credential is malformed or reuses another policy-role key.
    #[error("invalid or reused Source hold signer pin")]
    InvalidPin,
    /// Protected root signer state is absent or changed.
    #[error("Source hold signer pin is not current")]
    StalePin,
    /// Protected root journal replay or durable admission failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Retains the exact same-owner native startup refusal and custody marker.
    #[error(transparent)]
    #[cfg(target_os = "linux")]
    NativeStartup(aos_sandbox_policy::native::RootStartupCredentialErrorV1),
}

/// Reconciles an optional Source-only public pin with fixed root authority.
///
/// This does not establish Source key custody, verify a readback, or admit Q04.
///
/// # Errors
///
/// Rejects malformed credentials, missing or changed root policy pins, key
/// reuse, pin removal or rotation, and failed protected journal replay.
pub fn admit_fixed_source_hold_pin_v1(
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), SourceHoldPinErrorV1> {
    #[cfg(target_os = "linux")]
    {
    aos_sandbox_policy::native::RootStartupJournalOriginalV1::admit_fixed_source_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(SourceHoldPinErrorV1::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (credential, deployment_generation, deployment_key, project_generation, project_key);
        Err(JournalError::UnsupportedProtectedOpen.into())
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn admit_source_hold_pin_in_journal_v1(
    journal: &mut aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), SourceHoldPinErrorV1> {
    journal.admit_source_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(SourceHoldPinErrorV1::from)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;
    use aos_sandbox_protocol::cache_owner_readback::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::JournalLimits;
    use crate::policy_compiler::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_pin::admit_controller_hold_pin_in_journal_v1;

    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;
    use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;

    #[test]
    fn source_pin_replays_and_rejects_rotation_removal_and_role_reuse() {
        let directory = tempfile::tempdir().expect("root pin directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let mut root = aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1::open_v1(
            directory.path(),
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let deployment = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let controller = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache = SigningKey::from_bytes(&[4; 32]).verifying_key();
        let source = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let controller_pin = encode_controller_hold_signer_credential_v1(3, &controller)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let cache_pin = encode_cache_owner_readback_signer_credential_v1(4, &cache).unwrap();
        let source_pin = encode_source_hold_readback_signer_credential_v1(5, &source).unwrap();

        assert!(
            admit_source_hold_pin_in_journal_v1(
                &mut root,
                Some(&source_pin),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
        admit_policy_signer_pins_in_journal_v1(&mut root, 1, &deployment, 2, &project).unwrap();
        admit_controller_hold_pin_in_journal_v1(
            &mut root,
            Some(&controller_pin),
            1,
            &deployment,
            2,
            &project,
        )
        .unwrap();
        admit_cache_readback_pin_in_journal_v1(
            &mut root,
            Some(&cache_pin),
            1,
            &deployment,
            2,
            &project,
        )
        .unwrap();
        admit_source_hold_pin_in_journal_v1(
            &mut root,
            Some(&source_pin),
            1,
            &deployment,
            2,
            &project,
        )
        .unwrap();
        drop(root);

        let mut root = aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1::open_v1(
            directory.path(),
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        admit_source_hold_pin_in_journal_v1(
            &mut root,
            Some(&source_pin),
            1,
            &deployment,
            2,
            &project,
        )
        .unwrap();
        let rotated = encode_source_hold_readback_signer_credential_v1(6, &source).unwrap();
        let reused_controller =
            encode_source_hold_readback_signer_credential_v1(5, &controller).unwrap();
        let reused_cache = encode_source_hold_readback_signer_credential_v1(5, &cache).unwrap();
        for rejected in [&rotated[..], &reused_controller, &reused_cache] {
            assert!(
                admit_source_hold_pin_in_journal_v1(
                    &mut root,
                    Some(rejected),
                    1,
                    &deployment,
                    2,
                    &project
                )
                .is_err()
            );
        }
        assert!(
            admit_source_hold_pin_in_journal_v1(&mut root, None, 1, &deployment, 2, &project)
                .is_err()
        );
        assert!(
            admit_source_hold_pin_in_journal_v1(
                &mut root,
                Some(&controller_pin),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
    }

    #[test]
    fn source_first_blocks_later_controller_and_cache_key_reuse() {
        let directory = tempfile::tempdir().expect("root pin directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let mut root = aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1::open_v1(
            directory.path(),
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        let deployment = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let source = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let source_pin = encode_source_hold_readback_signer_credential_v1(3, &source).unwrap();
        let controller_reuse = encode_controller_hold_signer_credential_v1(4, &source)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let cache_reuse = encode_cache_owner_readback_signer_credential_v1(5, &source).unwrap();

        admit_policy_signer_pins_in_journal_v1(&mut root, 1, &deployment, 2, &project).unwrap();
        admit_source_hold_pin_in_journal_v1(
            &mut root,
            Some(&source_pin),
            1,
            &deployment,
            2,
            &project,
        )
        .unwrap();
        assert!(
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&controller_reuse),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
        assert!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&cache_reuse),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
    }
}
