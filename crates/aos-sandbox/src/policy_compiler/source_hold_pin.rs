//! Protected root admission of a separate-purpose Source hold signer pin.
//!
//! The optional AOSSPK01 credential contains only a public key. Root retains
//! its exact bytes after deployment/project pin admission; replay is allowed,
//! but removal, rotation, and reuse across owner roles fail closed.

use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use crate::journal::{Journal, JournalError, RecordNamespace};

use super::cache_readback_pin::CACHE_PIN_KEY;
use super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::deployment_head::{SIGNER_PINS_KEY, encode_policy_signer_pins_v1};
use super::owner_pin_transaction::owner_pin_transaction;
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::source_hold_readback::PinnedSourceHoldReadbackSignerV1;

pub(super) const SOURCE_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-source-hold-pin-v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-source-hold-pin-transaction.v1\0";

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
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_source_hold_pin_in_journal_v1(
        &mut journal,
        credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
}

pub(super) fn admit_source_hold_pin_in_journal_v1(
    journal: &mut Journal,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), SourceHoldPinErrorV1> {
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| SourceHoldPinErrorV1::InvalidPin)?;

    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| SourceHoldPinErrorV1::StalePin)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
        return Err(SourceHoldPinErrorV1::StalePin);
    }
    let Some(credential) = credential else {
        return if authority.get(SOURCE_HOLD_PIN_KEY)?.is_none() {
            Ok(())
        } else {
            Err(SourceHoldPinErrorV1::StalePin)
        };
    };
    let source = PinnedSourceHoldReadbackSignerV1::decode(credential)
        .map_err(|_| SourceHoldPinErrorV1::InvalidPin)?;
    if source.verifying_key() == deployment_key || source.verifying_key() == project_key {
        return Err(SourceHoldPinErrorV1::InvalidPin);
    }
    if let Some(controller_pin) = authority.get(CONTROLLER_HOLD_PIN_KEY)? {
        let controller = PinnedControllerHoldSignerV1::decode(controller_pin)
            .map_err(|_| SourceHoldPinErrorV1::StalePin)?;
        if source.verifying_key() == controller.verifying_key() {
            return Err(SourceHoldPinErrorV1::InvalidPin);
        }
    }
    if let Some(cache_pin) = authority.get(CACHE_PIN_KEY)? {
        let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
            .map_err(|_| SourceHoldPinErrorV1::StalePin)?;
        if source.verifying_key() == cache.verifying_key() {
            return Err(SourceHoldPinErrorV1::InvalidPin);
        }
    }
    match authority.get(SOURCE_HOLD_PIN_KEY)? {
        Some(current) if current == credential => return Ok(()),
        Some(_) => return Err(SourceHoldPinErrorV1::StalePin),
        None => {}
    }

    let transaction = owner_pin_transaction(TRANSACTION_DOMAIN, SOURCE_HOLD_PIN_KEY, credential)?;
    authority.commit(&transaction)?;
    if authority.get(SOURCE_HOLD_PIN_KEY)? != Some(credential) {
        return Err(SourceHoldPinErrorV1::StalePin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::cache_residency::encode_cache_owner_readback_signer_credential_v1;
    use crate::journal::JournalLimits;
    use crate::policy_compiler::cache_readback_pin::admit_cache_readback_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_pin::admit_controller_hold_pin_in_journal_v1;
    use crate::policy_compiler::controller_hold_readback::encode_controller_hold_signer_credential_v1;
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;
    use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;

    #[test]
    fn source_pin_replays_and_rejects_rotation_removal_and_role_reuse() {
        let directory = tempfile::tempdir().expect("root pin directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut root, _) = Journal::open_protected_at_uid(
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
        let controller_pin = encode_controller_hold_signer_credential_v1(3, &controller).unwrap();
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

        let (mut root, _) = Journal::open_protected_at_uid(
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
        let (mut root, _) = Journal::open_protected_at_uid(
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
        let controller_reuse = encode_controller_hold_signer_credential_v1(4, &source).unwrap();
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
