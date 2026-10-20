//! Closed, Controller-purpose readback of one protected policy hold.
//!
//! The owner signs only while retaining its protected Controller writer and
//! rejoining the selected public Create source. The verifier authenticates an
//! owner statement, not a transferable lock or an all-owner policy cut.
//!
//! ```text
//! AOSCTW01 | version:u16 | reserved:u16 | signer-generation:u64 |
//! root-nonce:16 | root-session-cut:32 | Controller-UID:u32 |
//! journal-sequence:u64 | operation:16 | sandbox:16 | source:32 |
//! binding:32 | epoch:u64 | Ed25519 signature:64
//!
//! AOSCTK01 | signer-generation:u64 | Ed25519 public key:32 |
//! SHA-256(Controller-key-domain || preceding 48 bytes):32
//! ```

use aos_sandbox_policy::controller_readback::{
    ControllerHoldReadbackFieldsDataV1,
    CONTROLLER_HOLD_READBACK_BODY_BYTES_V1 as BODY_BYTES,
    controller_hold_readback_signature_preimage_v1,
    prepare_controller_hold_readback_data_v1,
};
#[cfg(test)]
use aos_sandbox_policy::controller_readback::CLOSED_CONTROLLER_HOLD_CREDENTIAL_BYTES_V1 as CREDENTIAL_BYTES;

use aos_sandbox_policy::controller_readback::{
    CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1, ControllerHoldReadbackChallengeV1,
    PinnedControllerHoldSignerV1, encode_controller_hold_signer_credential_v1,
    verify_controller_hold_readback_v1,
};

use std::path::Path;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::journal::controller::production_journal_limits;
use crate::journal::{ControllerPolicyHoldV1, Journal, JournalError, RecordNamespace};

use super::public_create_source::current_parentless_create_project_source_v1;

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

/// Signs a current protected Controller hold under its retained writer.
///
/// The signing key must be loaded from a distinct Controller-only credential.
/// This function never accepts a caller-supplied hold or source commitment.
/// The exact fixed journal path, current Create join, hold, and sequence are
/// checked before and after signing. The held V7 terminal flight uses this
/// receipt only as nonauthorizing Root-row evidence.
///
/// # Errors
///
/// Rejects a missing/released hold, stale Create join, unsafe or replaced
/// protected journal, changed sequence, or invalid signer generation.
pub fn sign_fixed_controller_hold_readback_v1(
    journal: &mut Journal,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    let uid = rustix::process::getuid().as_raw();
    sign_controller_hold_readback_at(
        journal,
        Path::new(CONTROLLER_DIRECTORY),
        uid,
        challenge,
        signer_generation,
        signing_key,
    )
}

fn sign_controller_hold_readback_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerHoldReadbackErrorV1::NonCanonical);
    }
    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    let held = journal
        .controller_policy_hold_v1()?
        .filter(|hold| hold.is_held())
        .ok_or(ControllerHoldReadbackErrorV1::Stale)?;
    require_current_source(journal, held)?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let fields = fields_from_hold(held, uid, snapshot.sequence());
    let bytes = sign_fields(fields, challenge, signer_generation, signing_key)?;

    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    if journal.controller_policy_hold_v1()? != Some(held) {
        return Err(ControllerHoldReadbackErrorV1::Stale);
    }
    require_current_source(journal, held)?;
    Ok(bytes)
}

fn fields_from_hold(
    held: ControllerPolicyHoldV1,
    uid: u32,
    sequence: u64,
) -> ControllerHoldReadbackFieldsDataV1 {
    ControllerHoldReadbackFieldsDataV1 {
        controller_uid: uid,
        journal_sequence: sequence,
        operation: held.operation(),
        sandbox: held.sandbox(),
        source: held.source(),
        binding: held.binding(),
        epoch: held.epoch(),
    }
}

// This is not the ordinary namespace snapshot path. Only the actual closed
// Q04 phase recipes/current history can join its mixed Controller ledger;
// output and cause belong to the same resident invocation before postchecks.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(in crate::policy_compiler) fn sign_q04_held_controller_v1(
    journal: &mut Journal,
    transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
    packet: &mut Option<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]>,
    first_cause: &mut Option<super::create_q04::CreateQ04ErrorV1>,
    postcheck_debt: &mut Option<super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    use super::create_q04::CreateQ04ErrorV1;

    if packet.is_some() || first_cause.is_some() || postcheck_debt.is_some() {
        first_cause.get_or_insert(CreateQ04ErrorV1::ChangedCut);
        return Err(());
    }
    let result = sign_q04_held_controller_original(
        journal, transitions, challenge, signer_generation, signing_key, original, packet, first_cause,
    );
    super::create_q04::finish_controller_q04_signing_v1(result, first_cause, postcheck_debt)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn sign_q04_held_controller_original(
    journal: &mut Journal,
    transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
    packet: &mut Option<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1]>,
    first_cause: &mut Option<super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), super::create_q04::CreateQ04ErrorV1> {
    use super::create_q04::CreateQ04ErrorV1;

    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerHoldReadbackErrorV1::NonCanonical.into());
    }
    let ledger = transitions.first().ok_or(CreateQ04ErrorV1::ChangedCut)?.ledger();
    let directory = Path::new(CONTROLLER_DIRECTORY);
    journal.require_protected_named_location(
        directory, CONTROLLER_JOURNAL, uid, production_journal_limits(),
    )?;
    let before = journal.q04_controller_signing_bookend_v1(ledger, Some(transitions))?;
    let held = before.2.filter(|hold| hold.is_held())
        .ok_or(ControllerHoldReadbackErrorV1::Stale)?;
    require_current_source(journal, held)?;
    let fields = fields_from_hold(held, uid, before.0);

    match sign_q04_fields(fields, challenge, signer_generation, signing_key, original) {
        Ok(returned) => *packet = Some(returned),
        Err(error) => *first_cause = Some(error.into()),
    }

    journal.require_protected_named_location(
        directory, CONTROLLER_JOURNAL, uid, production_journal_limits(),
    )?;
    if journal.q04_controller_signing_bookend_v1(ledger, Some(transitions))? != before {
        return Err(ControllerHoldReadbackErrorV1::Stale.into());
    }
    require_current_source(journal, held)?;
    let current = journal.controller_policy_hold_v1()?
        .filter(|hold| hold.is_held()).ok_or(ControllerHoldReadbackErrorV1::Stale)?;
    if fields_from_hold(current, uid, journal.snapshot_sequence()) != fields
        || journal.q04_controller_signing_bookend_v1(ledger, Some(transitions))? != before
    {
        return Err(ControllerHoldReadbackErrorV1::Stale.into());
    }
    Ok(())
}

fn require_current_source(
    journal: &mut Journal,
    held: ControllerPolicyHoldV1,
) -> Result<(), ControllerHoldReadbackErrorV1> {
    let source =
        current_parentless_create_project_source_v1(journal, held.operation(), held.sandbox())
            .map_err(|_| ControllerHoldReadbackErrorV1::Stale)?;
    if source.commitment() != held.source() {
        return Err(ControllerHoldReadbackErrorV1::Stale);
    }
    Ok(())
}

fn sign_fields(
    fields: ControllerHoldReadbackFieldsDataV1,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    let bytes = prepare_controller_hold_readback_data_v1(fields, challenge, signer_generation)
        .map_err(ControllerHoldReadbackErrorV1::from)?;
    let preimage = controller_hold_readback_signature_preimage_v1(&bytes);
    Ok(finish_fields(bytes, preimage, key))
}

fn finish_fields(
    mut bytes: [u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1],
    preimage: Vec<u8>,
    key: &SigningKey,
) -> [u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1] {
    let signature = key.sign(&preimage);
    // The old temporary ended at the signing statement, before copying.
    drop(preimage);
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    bytes
}

#[cfg(target_os = "linux")]
fn sign_q04_fields(
    fields: ControllerHoldReadbackFieldsDataV1,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], super::create_q04::CreateQ04ErrorV1> {
    let bytes = prepare_controller_hold_readback_data_v1(fields, challenge, signer_generation)
        .map_err(ControllerHoldReadbackErrorV1::from)?;
    let preimage = controller_hold_readback_signature_preimage_v1(&bytes);

    original.require_q04_signing_boundary()?;
    Ok(finish_fields(bytes, preimage, key))
}

#[cfg(test)]
pub(super) fn sign_test_controller_hold_readback_v1(
    held: ControllerPolicyHoldV1,
    controller_uid: u32,
    challenge: ControllerHoldReadbackChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<[u8; CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1], ControllerHoldReadbackErrorV1> {
    sign_fields(
        ControllerHoldReadbackFieldsDataV1 {
            controller_uid,
            journal_sequence: 7,
            operation: held.operation(),
            sandbox: held.sandbox(),
            source: held.source(),
            binding: held.binding(),
            epoch: held.epoch(),
        },
        challenge,
        signer_generation,
        key,
    )
}

/// Reports a rejected Controller-only readback or protected owner cut.
#[derive(Debug, thiserror::Error)]
pub enum ControllerHoldReadbackErrorV1 {
    /// The challenge, credential, or receipt is not canonical.
    #[error("noncanonical Controller hold readback")]
    NonCanonical,
    /// The held Controller record or root challenge is no longer current.
    #[error("stale Controller hold readback")]
    Stale,
    /// The dedicated Controller signature failed verification.
    #[error("invalid Controller hold readback signature")]
    Signature,
    /// Protected journal custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

impl From<aos_sandbox_policy::controller_readback::ControllerHoldReadbackDataErrorV1>
    for ControllerHoldReadbackErrorV1
{
    fn from(
        error: aos_sandbox_policy::controller_readback::ControllerHoldReadbackDataErrorV1,
    ) -> Self {
        use aos_sandbox_policy::controller_readback::ControllerHoldReadbackDataErrorV1 as Data;
        match error {
            Data::NonCanonical => Self::NonCanonical,
            Data::Stale => Self::Stale,
            Data::Signature => Self::Signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use ed25519_dalek::SigningKey;

    use super::*;

    fn fields() -> ControllerHoldReadbackFieldsDataV1 {
        ControllerHoldReadbackFieldsDataV1 {
            controller_uid: 811,
            journal_sequence: 7,
            operation: OperationId::from_bytes([1; 16]),
            sandbox: SandboxId::from_bytes([2; 16]),
            source: ObjectDigest::from_bytes([3; 32]),
            binding: ObjectDigest::from_bytes([4; 32]),
            epoch: 5,
        }
    }

    #[test]
    fn receipt_rejects_wrong_nonce_cut_role_generation_uid_and_signature() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = encode_controller_hold_signer_credential_v1(9, &key.verifying_key())
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .expect("Controller pin");
        let signer = PinnedControllerHoldSignerV1::decode(&credential)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .expect("pinned signer");
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .expect("root challenge");
        let bytes = sign_fields(fields(), challenge, 9, &key).expect("signed receipt");

        assert_eq!(
            verify_controller_hold_readback_v1(&bytes, &signer, challenge, 811)
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .expect("verified readback")
                .fields_data_v1(),
            fields()
        );
        assert!(
            verify_controller_hold_readback_v1(&bytes, &signer, challenge, 812)
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
        assert!(
            verify_controller_hold_readback_v1(
                &bytes,
                &signer,
                ControllerHoldReadbackChallengeV1::new([10; 16], ObjectDigest::from_bytes([9; 32]))
                    .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                    .unwrap(),
                811
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .is_err()
        );
        assert!(
            verify_controller_hold_readback_v1(
                &bytes,
                &signer,
                ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([10; 32]))
                    .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                    .unwrap(),
                811
            )
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .is_err()
        );

        let rotated = encode_controller_hold_signer_credential_v1(10, &key.verifying_key())
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .expect("rotated pin");
        let rotated = PinnedControllerHoldSignerV1::decode(&rotated)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        assert!(
            verify_controller_hold_readback_v1(&bytes, &rotated, challenge, 811)
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
        let wrong = SigningKey::from_bytes(&[11; 32]);
        let wrong = encode_controller_hold_signer_credential_v1(9, &wrong.verifying_key())
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let wrong = PinnedControllerHoldSignerV1::decode(&wrong)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        assert!(
            verify_controller_hold_readback_v1(&bytes, &wrong, challenge, 811)
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );

        let mut altered = bytes;
        altered[112] ^= 1;
        assert!(
            verify_controller_hold_readback_v1(&altered, &signer, challenge, 811)
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
        assert!(
            PinnedControllerHoldSignerV1::decode(key.verifying_key().as_bytes())
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
        assert!(
            PinnedControllerHoldSignerV1::decode(&[0; CREDENTIAL_BYTES])
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
        assert!(
            ControllerHoldReadbackChallengeV1::new([0; 16], challenge.cut())
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .is_err()
        );
    }

    #[test]
    fn protected_signer_rejects_hold_without_current_create_join() {
        let directory = tempfile::tempdir().expect("Controller directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            CONTROLLER_JOURNAL,
            production_journal_limits(),
            uid,
        )
        .expect("protected Controller writer");
        let challenge =
            ControllerHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))
                .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
                .unwrap();
        let signer = SigningKey::from_bytes(&[7; 32]);
        assert!(
            sign_controller_hold_readback_at(
                &mut journal,
                directory.path(),
                uid,
                challenge,
                3,
                &signer
            )
            .is_err()
        );

        let held = ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            5,
        )
        .unwrap();
        journal.acquire_controller_policy_hold_v1(held).unwrap();
        assert!(matches!(
            require_current_source(&mut journal, held),
            Err(ControllerHoldReadbackErrorV1::Stale)
        ));
        let result = sign_controller_hold_readback_at(
            &mut journal,
            directory.path(),
            uid,
            challenge,
            3,
            &signer,
        );
        assert!(
            matches!(
                result,
                Err(ControllerHoldReadbackErrorV1::Journal(
                    JournalError::ProtectedBoundary
                ))
            ),
            "{result:?}"
        );
    }
}
