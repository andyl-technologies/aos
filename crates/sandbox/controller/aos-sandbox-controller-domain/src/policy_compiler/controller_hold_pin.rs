//! Protected root admission of a separate-purpose Controller hold signer pin.
//!
//! AOSCTK01 is optional and nonauthorizing. Root persists its exact bytes
//! only after the deployment/project pins match; removal, rotation, and reuse
//! of another policy role are closed without explicit reissuance.

#[cfg(all(test, target_os = "linux"))]
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::journal::JournalError;

/// Reports a rejected Controller-only signer pin admission.
#[derive(Debug, thiserror::Error)]
pub enum ControllerHoldPinErrorV1 {
    /// The pin is malformed or reuses another policy-role key.
    #[error("invalid or reused Controller hold signer pin")]
    InvalidPin,
    /// Root's protected signer state is absent or changed.
    #[error("Controller hold signer pin is not current")]
    StalePin,
    /// Protected root journal replay or commit failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Retains the exact same-owner native startup refusal and custody marker.
    #[error(transparent)]
    #[cfg(target_os = "linux")]
    NativeStartup(aos_sandbox_policy::native::RootStartupCredentialErrorV1),
}

/// Reconciles an optional Controller-only pin with fixed protected root state.
///
/// This is deployment admission only. It cannot verify a receipt, grant Q04,
/// or authorize Create.
///
/// # Errors
///
/// Rejects missing/changed root signer state, key reuse, removal, rotation,
/// malformed credentials, or failed durable admission.
pub fn admit_fixed_controller_hold_pin_v1(
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), ControllerHoldPinErrorV1> {
    #[cfg(target_os = "linux")]
    {
    aos_sandbox_policy::native::RootStartupJournalOriginalV1::admit_fixed_controller_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(ControllerHoldPinErrorV1::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (credential, deployment_generation, deployment_key, project_generation, project_key);
        Err(JournalError::UnsupportedProtectedOpen.into())
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn admit_controller_hold_pin_in_journal_v1(
    journal: &mut aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), ControllerHoldPinErrorV1> {
    journal.admit_controller_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(ControllerHoldPinErrorV1::from)
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
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    #[test]
    fn controller_pin_replays_and_rejects_role_reuse_rotation_and_removal() {
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
        let pin =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                4,
                &controller,
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();

        assert!(
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&pin),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
        admit_policy_signer_pins_in_journal_v1(&mut root, 1, &deployment, 2, &project).unwrap();
        admit_controller_hold_pin_in_journal_v1(&mut root, Some(&pin), 1, &deployment, 2, &project)
            .unwrap();

        drop(root);
        let mut root = aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1::open_v1(
            directory.path(),
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        admit_controller_hold_pin_in_journal_v1(&mut root, Some(&pin), 1, &deployment, 2, &project)
            .unwrap();
        assert!(
            admit_controller_hold_pin_in_journal_v1(&mut root, None, 1, &deployment, 2, &project)
                .is_err()
        );

        let rotated =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                5,
                &controller,
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        assert!(
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&rotated),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
        let reused =
            aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(
                4,
                &deployment,
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        assert!(
            admit_controller_hold_pin_in_journal_v1(
                &mut root,
                Some(&reused),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );

        let reused_cache =
            encode_cache_owner_readback_signer_credential_v1(4, &controller).unwrap();
        assert!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&reused_cache),
                1,
                &deployment,
                2,
                &project
            )
            .is_err()
        );
    }
}
