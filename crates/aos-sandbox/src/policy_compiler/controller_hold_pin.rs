//! Protected root admission of a separate-purpose Controller hold signer pin.
//!
//! AOSCTK01 is optional and nonauthorizing. Root persists its exact bytes
//! only after the deployment/project pins match; removal, rotation, and reuse
//! of another policy role are closed without explicit reissuance.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::cache_residency::PinnedCacheOwnerReadbackSignerV1;
use crate::journal::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

use super::cache_readback_pin::CACHE_PIN_KEY;
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::deployment_head::{SIGNER_PINS_KEY, encode_policy_signer_pins_v1};
use super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};

pub(super) const CONTROLLER_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-controller-hold-pin-v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.policy-controller-hold-pin-transaction.v1\0";

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
    let (mut journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    admit_controller_hold_pin_in_journal_v1(
        &mut journal,
        credential,
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
}

pub(super) fn admit_controller_hold_pin_in_journal_v1(
    journal: &mut Journal,
    credential: Option<&[u8]>,
    deployment_generation: u64,
    deployment_key: &VerifyingKey,
    project_generation: u64,
    project_key: &VerifyingKey,
) -> Result<(), ControllerHoldPinErrorV1> {
    let policy_pins = encode_policy_signer_pins_v1(
        deployment_generation,
        deployment_key,
        project_generation,
        project_key,
    )
    .map_err(|_| ControllerHoldPinErrorV1::InvalidPin)?;
    let mut authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    super::binding_v2::ensure_root_binding_unheld(&authority)
        .map_err(|_| ControllerHoldPinErrorV1::StalePin)?;
    if authority.get(SIGNER_PINS_KEY)? != Some(policy_pins.as_slice()) {
        return Err(ControllerHoldPinErrorV1::StalePin);
    }
    let Some(credential) = credential else {
        return if authority.get(CONTROLLER_HOLD_PIN_KEY)?.is_none() {
            Ok(())
        } else {
            Err(ControllerHoldPinErrorV1::StalePin)
        };
    };
    let controller = PinnedControllerHoldSignerV1::decode(credential)
        .map_err(|_| ControllerHoldPinErrorV1::InvalidPin)?;
    if controller.verifying_key() == deployment_key || controller.verifying_key() == project_key {
        return Err(ControllerHoldPinErrorV1::InvalidPin);
    }
    if let Some(cache_pin) = authority.get(CACHE_PIN_KEY)? {
        let cache = PinnedCacheOwnerReadbackSignerV1::decode(cache_pin)
            .map_err(|_| ControllerHoldPinErrorV1::StalePin)?;
        if cache.verifying_key() == controller.verifying_key() {
            return Err(ControllerHoldPinErrorV1::InvalidPin);
        }
    }
    match authority.get(CONTROLLER_HOLD_PIN_KEY)? {
        Some(current) if current == credential => return Ok(()),
        Some(_) => return Err(ControllerHoldPinErrorV1::StalePin),
        None => {}
    }

    let digest = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(credential)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| ControllerHoldPinErrorV1::InvalidPin)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            CONTROLLER_HOLD_PIN_KEY.to_vec(),
            credential.to_vec(),
        )],
    )?;
    authority.commit(&transaction)?;
    if authority.get(CONTROLLER_HOLD_PIN_KEY)? != Some(credential) {
        return Err(ControllerHoldPinErrorV1::StalePin);
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
    use crate::policy_compiler::deployment_head::admit_policy_signer_pins_in_journal_v1;

    #[test]
    fn controller_pin_replays_and_rejects_role_reuse_rotation_and_removal() {
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
        let pin =
            super::super::controller_hold_readback::encode_controller_hold_signer_credential_v1(
                4,
                &controller,
            )
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
        let (mut root, _) = Journal::open_protected_at_uid(
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
            super::super::controller_hold_readback::encode_controller_hold_signer_credential_v1(
                5,
                &controller,
            )
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
            super::super::controller_hold_readback::encode_controller_hold_signer_credential_v1(
                4,
                &deployment,
            )
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
