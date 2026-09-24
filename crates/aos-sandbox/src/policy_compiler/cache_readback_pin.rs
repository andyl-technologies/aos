//! Protected root admission of a distinct Cache-owner readback signer pin.
//!
//! The `AOSCPK01` credential is public-only and does not authorize a policy
//! binding. Root admits it only after its deployment and project signer pins
//! already match the fixed credentials; exact replay is allowed, rotation is
//! closed, and the Cache key cannot reuse either policy signing key.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

use super::deployment_head::{SIGNER_PINS_KEY, encode_policy_signer_pins_v1};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};

pub(super) const CACHE_PIN_KEY: &[u8] = b"\0aos-policy-cache-readback-pin-v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-cache-readback-pin-transaction.v1\0";

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
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_cache_readback_pin_in_journal_v1(
        &mut journal,
        credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
}

pub(super) fn admit_cache_readback_pin_in_journal_v1(
    journal: &mut Journal,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), CacheReadbackPinErrorV1> {
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| CacheReadbackPinErrorV1::InvalidPin)?;

    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
        return Err(CacheReadbackPinErrorV1::StalePin);
    }
    let Some(credential) = credential else {
        return if authority.get(CACHE_PIN_KEY)?.is_none() {
            Ok(())
        } else {
            Err(CacheReadbackPinErrorV1::StalePin)
        };
    };
    let cache = PinnedCacheOwnerReadbackSignerV1::decode(credential)
        .map_err(|_| CacheReadbackPinErrorV1::InvalidPin)?;
    if cache.verifying_key() == deployment_key || cache.verifying_key() == project_key {
        return Err(CacheReadbackPinErrorV1::InvalidPin);
    }
    match authority.get(CACHE_PIN_KEY)? {
        Some(current) if current == credential => return Ok(()),
        Some(_) => return Err(CacheReadbackPinErrorV1::StalePin),
        None => {}
    }

    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(credential)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| CacheReadbackPinErrorV1::InvalidPin)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            CACHE_PIN_KEY.to_vec(),
            credential.to_vec(),
        )],
    )?;
    authority.commit(&transaction)?;
    if authority.get(CACHE_PIN_KEY)? != Some(credential) {
        return Err(CacheReadbackPinErrorV1::StalePin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use crate::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::JournalLimits;

    use super::*;
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    fn journal(directory: &Path) -> Journal {
        let uid = fs::metadata(directory).expect("test root metadata").uid();
        Journal::open_protected_at_uid(
            directory,
            "authority.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected test journal")
        .0
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
