//! Controller-owned currentness evidence for explicit project-source admission.
//!
//! The Controller signs an exact admitted parentless Create and publisher head
//! only while retaining its protected journal writer. Root must verify this
//! receipt against its own AOSCTK01 pin and join independent Source ancestry;
//! neither the receipt nor its copied journal sequence transfers writer custody.
//!
//! The canonical packet and strict raw verifier live in
//! `aos_sandbox_policy::controller_project_readback`; this module retains the
//! native Controller source, Publisher checks and real signing boundary.

use aos_sandbox_policy::controller_project_readback::{
    CONTROLLER_PROJECT_ADMISSION_BODY_BYTES_V1 as BODY_BYTES,
    CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1, ControllerProjectAdmissionDataErrorV1,
    ControllerProjectAdmissionChallengeV1, ControllerProjectAdmissionFieldsDataV1,
    controller_project_admission_signature_preimage_v1 as signature_preimage,
    prepare_controller_project_admission_body_v1,
};
#[cfg(test)]
use aos_sandbox_policy::controller_project_readback::verify_controller_project_admission_readback_v1;

use std::path::Path;

use aos_sandbox_model::model::{CacheDomainKind, RevocationMode};
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::controller::ControllerRequestScopeV1;
use crate::journal::controller::production_journal_limits;
use crate::journal::{Journal, JournalError, RecordNamespace};
use crate::publisher_admin::policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use aos_sandbox_protocol::domain_ledger::effect_history::EffectPlan;

use super::public_create_source::{
    CurrentCreatePolicySourceErrorV1, CurrentCreateProjectPolicySourceV1,
    current_parentless_create_project_source_for_operation_v1,
};

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

/// Signs exact current Controller Create and publisher fields under its writer.
///
/// The key must come from Controller-only credentials. This readback never
/// accepts caller-supplied publisher claims, creates a policy binding, or
/// admits a project source at Root. The caller retains this writer through
/// Source's proof and Root's final admission CAS.
///
/// # Errors
///
/// Rejects unsafe or replaced journal custody, a stale accepted Create,
/// publisher or revocation head, an outstanding Controller hold, or an invalid
/// signer generation.
#[allow(clippy::too_many_arguments)]
pub fn sign_fixed_controller_project_admission_readback_v1(
    journal: &mut Journal,
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    let uid = rustix::process::getuid().as_raw();
    sign_controller_project_admission_at(
        journal,
        Path::new(CONTROLLER_DIRECTORY),
        uid,
        operation,
        project,
        scope,
        effect_plan,
        challenge,
        signer_generation,
        signing_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_controller_project_admission_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    if journal
        .controller_policy_hold_v1()?
        .is_some_and(|hold| hold.is_held())
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale);
    }

    let source = current_parentless_create_project_source_for_operation_v1(
        journal,
        operation,
        project,
        scope,
        effect_plan,
    )?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::DesiredState)?
        .snapshot()?;
    let fields = fields_from_source(journal, &source, uid, snapshot.sequence())?;
    let packet = sign_fields(fields, challenge, signer_generation, signing_key)?;

    journal.require_protected_named_location(
        directory,
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::DesiredState)?
        .validate_snapshot_for_effect(&snapshot)?;
    let reread = current_parentless_create_project_source_for_operation_v1(
        journal,
        operation,
        project,
        scope,
        effect_plan,
    )?;
    if reread.commitment() != source.commitment()
        || reread.operation_revision() != source.operation_revision()
        || reread.projection_revision() != source.projection_revision()
        || journal
            .controller_policy_hold_v1()?
            .is_some_and(|hold| hold.is_held())
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale);
    }
    Ok(packet)
}

// The ordinary SingleNamespace route above deliberately stays unchanged.
// Q04 instead rejoins the captured real whole ledger/native prefix twice,
// while its caller retains the original Journal, credentials and flight.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(in crate::policy_compiler) fn sign_q04_current_controller_project_v1(
    journal: &mut Journal,
    ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
    packet: &mut Option<[u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1]>,
    first_cause: &mut Option<super::create_q04::CreateQ04ErrorV1>,
    postcheck_debt: &mut Option<super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    use super::create_q04::CreateQ04ErrorV1;

    if packet.is_some() || first_cause.is_some() || postcheck_debt.is_some() {
        first_cause.get_or_insert(CreateQ04ErrorV1::ChangedCut);
        return Err(());
    }
    let result = sign_q04_current_controller_project_original(
        journal, ledger, challenge, signer_generation, signing_key, original, packet, first_cause,
    );
    super::create_q04::finish_controller_q04_signing_v1(result, first_cause, postcheck_debt)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn sign_q04_current_controller_project_original(
    journal: &mut Journal,
    ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
    packet: &mut Option<[u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1]>,
    first_cause: &mut Option<super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), super::create_q04::CreateQ04ErrorV1> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || signer_generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical.into());
    }
    let directory = Path::new(CONTROLLER_DIRECTORY);
    journal.require_protected_named_location(
        directory, CONTROLLER_JOURNAL, uid, production_journal_limits(),
    )?;
    let before = journal.q04_controller_signing_bookend_v1(ledger, None)?;
    let source = ledger.signing_current_source(journal)?;
    let fields = fields_from_source(journal, &source, uid, before.0)?;

    // The actual signature or its typed error is resident before any later
    // original-name, full replay or current-field observation can fail.
    match sign_q04_fields(fields, challenge, signer_generation, signing_key, original) {
        Ok(returned) => *packet = Some(returned),
        Err(error) => *first_cause = Some(error.into()),
    }

    journal.require_protected_named_location(
        directory, CONTROLLER_JOURNAL, uid, production_journal_limits(),
    )?;
    if journal.q04_controller_signing_bookend_v1(ledger, None)? != before {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale.into());
    }
    let current = ledger.signing_current_source(journal)?;
    if fields_from_source(journal, &current, uid, before.0)? != fields
        || journal.q04_controller_signing_bookend_v1(ledger, None)? != before
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale.into());
    }
    Ok(())
}

fn fields_from_source(
    journal: &mut Journal,
    source: &CurrentCreateProjectPolicySourceV1,
    uid: u32,
    sequence: u64,
) -> Result<ControllerProjectAdmissionFieldsDataV1, ControllerProjectAdmissionReadbackErrorV1> {
    let publisher = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?;
    let revision = publisher
        .current_policy(source.project())?
        .ok_or(ControllerProjectAdmissionReadbackErrorV1::Stale)?;
    if revision.generation() != source.policy_generation()
        || revision.descriptor().digest() != source.policy_digest()
        || revision.canonical_policy() != source.canonical_policy()
        || source.cache_domain().kind() != CacheDomainKind::Project
        || source.cache_domain().domain_id().as_bytes() != source.project().as_bytes()
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale);
    }
    let revocation = revision.policy().revocation();
    let fields = ControllerProjectAdmissionFieldsDataV1 {
        controller_uid: uid,
        journal_sequence: sequence,
        operation: source.operation(),
        sandbox: source.sandbox(),
        project: source.project(),
        source_commitment: source.commitment(),
        publisher_generation: source.policy_generation(),
        publisher_digest: source.policy_digest(),
        cache_domain_head: source.cache_domain_head(),
        revocation_scope: source.revocation_scope(),
        revocation_generation: source.revocation_generation(),
        revocation_head: source.revocation_head(),
        revocation_mode: revocation.mode(),
        revocation_grace_nanos: revocation.grace_nanos(),
    };
    fields.validate(uid)?;
    Ok(fields)
}

// The prehold request signs complete original-row comparison DATA under this
// same genuine mixed Controller ledger. It is not the old SingleNamespace
// signer, an authority DTO or a detached currentness/funding certificate.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(in crate::policy_compiler) fn sign_q04_prehold_input_v1(
    journal: &mut Journal,
    ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
    metadata: &[u8; super::create_q04::PREHOLD_METADATA_BYTES],
    proposed: &[u8],
    current_packet: &[u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    signer_generation: u64,
    signing_key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
    resident_packet: &mut Vec<u8>,
    first_cause: &mut Option<super::create_q04::CreateQ04ErrorV1>,
    postcheck_debt: &mut Option<super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    use super::create_q04::{CreateQ04ErrorV1, finish_controller_q04_signing_v1};

    if first_cause.is_some() || postcheck_debt.is_some() || !resident_packet.is_empty() {
        return finish_controller_q04_signing_v1(
            Err(CreateQ04ErrorV1::ChangedCut), first_cause, postcheck_debt,
        );
    }
    let mut original_bookend = None;
    let mut original_fields = None;
    let signed = (|| {
        let before = journal.q04_controller_signing_bookend_v1(ledger, None)?;
        original_bookend = Some(before);
        let uid = journal.protected_owner_uid()?;
        if uid == 0 || uid != rustix::process::getuid().as_raw() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let source = ledger.signing_current_source(journal)?;
        let fields = fields_from_source(journal, &source, uid, before.0)?;
        original_fields = Some(fields);
        if signer_generation == 0
            || metadata[32..40] != signer_generation.to_be_bytes()
            || metadata[176..224] != before.1.to_bytes()
            || metadata[464..472] != before.0.to_be_bytes()
            || fields.journal_sequence != before.0
            || current_packet[12..20] != signer_generation.to_be_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let rows = ledger.original_rows();
        super::create_q04::encode_q04_prehold_body_v1(
            resident_packet,
            [metadata, rows[0], rows[1], rows[2], proposed, current_packet],
        )?;
        super::create_q04::sign_original_q04_prehold_body_v1(resident_packet, signing_key, original)
    })();

    // Park the actual signing/allocation error before any physical postcheck.
    // A successfully appended signature already belongs to resident_packet.
    let result = finish_controller_q04_signing_v1(signed, first_cause, postcheck_debt);
    let checked = (|| {
        let after = journal.q04_controller_signing_bookend_v1(ledger, None)?;
        if let Some(before) = original_bookend {
            if after != before {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        if let Some(before_fields) = original_fields {
            let source = ledger.signing_current_source(journal)?;
            let uid = journal.protected_owner_uid()?;
            let fields = fields_from_source(journal, &source, uid, after.0)?;
            if fields != before_fields {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            if journal.q04_controller_signing_bookend_v1(ledger, None)? != after {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        Ok(())
    })();
    let postflight = finish_controller_q04_signing_v1(checked, first_cause, postcheck_debt);
    result.and(postflight)
}

fn sign_fields(
    fields: ControllerProjectAdmissionFieldsDataV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    let bytes = prepare_controller_project_admission_body_v1(fields, challenge, signer_generation)?;
    let preimage = signature_preimage(&bytes[..BODY_BYTES]);
    Ok(finish_fields(bytes, preimage, key))
}

fn finish_fields(
    mut bytes: [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    preimage: Vec<u8>,
    key: &SigningKey,
) -> [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1] {
    let signature = key.sign(&preimage);
    // The old temporary ended at the signing statement, before copying.
    drop(preimage);
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    bytes
}

#[cfg(target_os = "linux")]
fn sign_q04_fields(
    fields: ControllerProjectAdmissionFieldsDataV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
    original: &super::source_genesis_root::OriginalRootGenesisFlightV1<'_>,
) -> Result<[u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1], super::create_q04::CreateQ04ErrorV1> {
    let bytes = prepare_controller_project_admission_body_v1(fields, challenge, signer_generation)?;
    let preimage = signature_preimage(&bytes[..BODY_BYTES]);

    original.require_q04_signing_boundary()?;
    Ok(finish_fields(bytes, preimage, key))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn sign_synthetic_controller_project_admission_v1(
    challenge: ControllerProjectAdmissionChallengeV1,
    project: ProjectId,
    operation: OperationId,
    source_commitment: ObjectDigest,
    publisher_digest: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_scope: RevocationScopeId,
    revocation_head: ObjectDigest,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    let fields = ControllerProjectAdmissionFieldsDataV1 {
        controller_uid: 811,
        journal_sequence: 1,
        operation,
        sandbox: SandboxId::from_bytes([2; 16]),
        project,
        source_commitment,
        publisher_generation: 1,
        publisher_digest,
        cache_domain_head,
        revocation_scope,
        revocation_generation: 1,
        revocation_head,
        revocation_mode: RevocationMode::DenyNew,
        revocation_grace_nanos: 0,
    };
    sign_fields(fields, challenge, signer_generation, key)
}
/// Reports a rejected Controller-owned project-admission readback.
#[derive(Debug, thiserror::Error)]
pub enum ControllerProjectAdmissionReadbackErrorV1 {
    /// The challenge or signed receipt is not canonical.
    #[error("noncanonical Controller project-admission readback")]
    NonCanonical,
    /// The accepted Create or publisher claim is no longer current.
    #[error("stale Controller project-admission readback")]
    Stale,
    /// The Controller-only signature failed verification.
    #[error("invalid Controller project-admission signature")]
    Signature,
    /// Protected journal custody failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The protected public Create join failed.
    #[error(transparent)]
    Source(#[from] CurrentCreatePolicySourceErrorV1),
    /// The current publisher revision could not be checked.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
}

impl From<ControllerProjectAdmissionDataErrorV1> for ControllerProjectAdmissionReadbackErrorV1 {
    fn from(error: ControllerProjectAdmissionDataErrorV1) -> Self {
        match error {
            ControllerProjectAdmissionDataErrorV1::NonCanonical => Self::NonCanonical,
            ControllerProjectAdmissionDataErrorV1::Stale => Self::Stale,
            ControllerProjectAdmissionDataErrorV1::Signature => Self::Signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use aos_sandbox_policy::controller_readback::{
        PinnedControllerHoldSignerV1, encode_controller_hold_signer_credential_v1,
    };

    fn fields() -> ControllerProjectAdmissionFieldsDataV1 {
        ControllerProjectAdmissionFieldsDataV1 {
            controller_uid: 811,
            journal_sequence: 7,
            operation: OperationId::from_bytes([1; 16]),
            sandbox: SandboxId::from_bytes([2; 16]),
            project: ProjectId::from_bytes([3; 16]),
            source_commitment: ObjectDigest::from_bytes([7; 32]),
            publisher_generation: 8,
            publisher_digest: ObjectDigest::from_bytes([9; 32]),
            cache_domain_head: ObjectDigest::from_bytes([10; 32]),
            revocation_scope: RevocationScopeId::from_bytes([11; 16]),
            revocation_generation: 12,
            revocation_head: ObjectDigest::from_bytes([13; 32]),
            revocation_mode: RevocationMode::Freeze,
            revocation_grace_nanos: 14,
        }
    }

    #[test]
    fn exact_receipt_rejects_changed_owner_pin_challenge_and_currentness() {
        let key = SigningKey::from_bytes(&[15; 32]);
        let credential = encode_controller_hold_signer_credential_v1(16, &key.verifying_key())
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .expect("Controller-only pin");
        let signer = PinnedControllerHoldSignerV1::decode(&credential)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .expect("pinned signer");
        let challenge = ControllerProjectAdmissionChallengeV1::new(
            [17; 16],
            ObjectDigest::from_bytes([18; 32]),
        )
        .expect("Root challenge");
        let packet = sign_fields(fields(), challenge, 16, &key).expect("signed packet");
        assert_eq!(
            verify_controller_project_admission_readback_v1(&packet, &signer, challenge, 811)
                .expect("exact Controller evidence")
                .fields_data_v1(),
            fields()
        );

        let changed_challenge =
            ControllerProjectAdmissionChallengeV1::new([19; 16], challenge.cut()).unwrap();
        assert!(
            verify_controller_project_admission_readback_v1(
                &packet,
                &signer,
                changed_challenge,
                811
            )
            .is_err()
        );
        assert!(
            verify_controller_project_admission_readback_v1(&packet, &signer, challenge, 812)
                .is_err()
        );
        let rotated = encode_controller_hold_signer_credential_v1(17, &key.verifying_key())
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        let rotated = PinnedControllerHoldSignerV1::decode(&rotated)
            .map_err(crate::policy_compiler::ControllerHoldReadbackErrorV1::from)
            .unwrap();
        assert!(
            verify_controller_project_admission_readback_v1(&packet, &rotated, challenge, 811)
                .is_err()
        );
        for offset in [128, 168, 200, 232, 256, 288, 289, 297] {
            let mut changed = packet;
            changed[offset] ^= 1;
            assert!(
                verify_controller_project_admission_readback_v1(&changed, &signer, challenge, 811)
                    .is_err()
            );
        }
    }
}
