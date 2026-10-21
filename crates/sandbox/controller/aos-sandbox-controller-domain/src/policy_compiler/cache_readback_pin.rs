//! Protected root admission of a distinct Cache-owner readback signer pin.
//!
//! The `AOSCPK01` credential is public-only and does not authorize a policy
//! binding. Root admits it only after its deployment and project signer pins
//! already match the fixed credentials; exact replay is allowed, rotation is
//! closed, and the Cache key cannot reuse either policy signing key.

#[cfg(all(test, target_os = "linux"))]
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::journal::JournalError;

pub(super) use aos_sandbox_policy::journal_keys::CACHE_PIN_KEY;

/// Reports a rejected protected Cache readback pin admission.
#[derive(Debug, thiserror::Error)]
pub enum CacheReadbackPinErrorV1 {
    /// The credential is malformed or reuses a policy signer key.
    #[error("invalid or reused Cache readback signer pin")]
    InvalidPin,
    /// The root journal has missing, changed, or legacy signer state.
    #[error("Cache readback signer pin is not current")]
    StalePin,
    /// Root journal replay or durable admission failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Retains the exact same-owner native startup refusal and custody marker.
    #[error(transparent)]
    #[cfg(target_os = "linux")]
    NativeStartup(aos_sandbox_policy::native::RootStartupCredentialErrorV1),
}

/// Reconciles an optional Cache-only public pin with the fixed protected root.
///
/// This is a nonauthorizing prerequisite. It neither accepts a signed Cache
/// statement nor publishes a parentless Create binding.
///
/// # Errors
///
/// Rejects malformed credentials, key reuse, missing or changed policy pins,
/// Cache pin removal or rotation, and failed protected journal replay or commit.
pub fn admit_fixed_cache_readback_pin_v1(
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), CacheReadbackPinErrorV1> {
    #[cfg(target_os = "linux")]
    {
    aos_sandbox_policy::native::RootStartupJournalOriginalV1::admit_fixed_cache_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(CacheReadbackPinErrorV1::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (credential, deployment_generation, deployment_key, project_generation, project_key);
        Err(JournalError::UnsupportedProtectedOpen.into())
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn admit_cache_readback_pin_in_journal_v1(
    journal: &mut aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), CacheReadbackPinErrorV1> {
    journal.admit_cache_pin_v1(
        credential, deployment_generation, deployment_key, project_generation, project_key,
    ).map_err(CacheReadbackPinErrorV1::from)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use aos_sandbox_protocol::cache_owner_readback::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::JournalLimits;

    use super::*;
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    fn journal(directory: &Path) -> aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1 {
        let uid = fs::metadata(directory).expect("test root metadata").uid();
        aos_sandbox_policy::native::RootStartupFixedAdmissionFixtureV1::open_v1(
            directory,
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected test journal")
    }

    #[test]
    fn cache_pin_replays_durably_and_rejects_rotation_reuse_and_missing_policy() {
        let directory = tempfile::tempdir().expect("private root fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private root mode");
        let deployment = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let project = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let cache = SigningKey::from_bytes(&[4; 32]).verifying_key();
        let credential =
            encode_cache_owner_readback_signer_credential_v1(7, &cache).expect("cache credential");
        let rotated = encode_cache_owner_readback_signer_credential_v1(8, &cache)
            .expect("rotated credential");
        let reused = encode_cache_owner_readback_signer_credential_v1(7, &deployment)
            .expect("reused credential");
        let reused_project = encode_cache_owner_readback_signer_credential_v1(7, &project)
            .expect("reused project credential");
        let replaced = encode_cache_owner_readback_signer_credential_v1(
            7,
            &SigningKey::from_bytes(&[5; 32]).verifying_key(),
        )
        .expect("replacement credential");
        let mut root = journal(directory.path());

        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&credential),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        admit_policy_signer_pins_in_journal_v1(&mut root, 1, &deployment, 2, &project)
            .expect("policy pins");
        admit_cache_readback_pin_in_journal_v1(&mut root, None, 1, &deployment, 2, &project)
            .expect("legacy mode before Cache pin");
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&reused),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::InvalidPin)
        ));
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&reused_project),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::InvalidPin)
        ));
        admit_cache_readback_pin_in_journal_v1(
            &mut root,
            Some(&credential),
            1,
            &deployment,
            2,
            &project,
        )
        .expect("first Cache pin");
        admit_cache_readback_pin_in_journal_v1(
            &mut root,
            Some(&credential),
            1,
            &deployment,
            2,
            &project,
        )
        .expect("exact replay");
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(&mut root, None, 1, &deployment, 2, &project),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&rotated),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut root,
                Some(&replaced),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        drop(root);

        let mut reopened = journal(directory.path());
        admit_cache_readback_pin_in_journal_v1(
            &mut reopened,
            Some(&credential),
            1,
            &deployment,
            2,
            &project,
        )
        .expect("durable exact replay");
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut reopened,
                None,
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut reopened,
                Some(&credential),
                2,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::StalePin)
        ));
        let mut wrong_role = credential;
        wrong_role[..8].copy_from_slice(b"AOSPPK01");
        assert!(matches!(
            admit_cache_readback_pin_in_journal_v1(
                &mut reopened,
                Some(&wrong_role),
                1,
                &deployment,
                2,
                &project
            ),
            Err(CacheReadbackPinErrorV1::InvalidPin)
        ));
    }
}
