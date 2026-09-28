//! Controller-owned currentness evidence for explicit project-source admission.
//!
//! The Controller signs an exact admitted parentless Create and publisher head
//! only while retaining its protected journal writer. Root must verify this
//! receipt against its own AOSCTK01 pin and join independent Source ancestry;
//! neither the receipt nor its copied journal sequence transfers writer custody.
//!
//! ```text
//! AOSCTP03 | version:u16 | reserved:u16 | signer-generation:u64 |
//! Root-nonce:16 | Root-cut:32 | Controller-UID:u32 | journal-sequence:u64 |
//! operation:16 | sandbox:16 | project:16 | source-commitment:32 |
//! publisher-generation:u64 | publisher-descriptor-digest:32 |
//! project-cache-domain-head:32 | revocation-scope:16 |
//! revocation-generation:u64 | revocation-head:32 | revocation-mode:u8 |
//! revocation-grace-nanos:u64 | reserved:3 | Ed25519-signature:64
//! ```

use std::path::Path;

use aos_sandbox_core::model::{CacheDomainKind, RevocationMode};
use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::controller::ControllerRequestScopeV1;
use crate::controller_service::journal::production_journal_limits;
use crate::journal::{Journal, JournalError, RecordNamespace};
use crate::publisher_policy::{PublisherPolicyError, PublisherPolicyLimits, PublisherPolicyStore};
use crate::reconciler::EffectPlan;

use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::public_create_source::{
    CurrentCreatePolicySourceErrorV1, CurrentCreateProjectPolicySourceV1,
    current_parentless_create_project_source_for_operation_v1,
};

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";
const MAGIC: &[u8; 8] = b"AOSCTP03";
const VERSION: u16 = 3;
const BODY_BYTES: usize = 300;
const SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.controller-project-admission.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";

/// Bounds the exact signed Controller project-admission receipt.
pub const CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Names one Root-owned admission session without nominating a publisher head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerProjectAdmissionChallengeV1 {
    nonce: [u8; 16],
    cut: ObjectDigest,
}

impl ControllerProjectAdmissionChallengeV1 {
    /// Constructs a nonzero Root-generated nonce and session commitment.
    ///
    /// # Errors
    ///
    /// Rejects a zero nonce or cut.
    pub fn new(
        nonce: [u8; 16],
        cut: ObjectDigest,
    ) -> Result<Self, ControllerProjectAdmissionReadbackErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
        }
        Ok(Self { nonce, cut })
    }

    /// Returns the Root-generated nonce.
    #[must_use]
    pub const fn nonce(self) -> [u8; 16] {
        self.nonce
    }

    /// Returns the Root-owned session commitment.
    #[must_use]
    pub const fn cut(self) -> ObjectDigest {
        self.cut
    }
}

/// Retains the exact Controller claims authenticated by the pinned role key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedControllerProjectAdmissionV1 {
    controller_uid: u32,
    journal_sequence: u64,
    operation: OperationId,
    sandbox: SandboxId,
    project: ProjectId,
    source_commitment: ObjectDigest,
    publisher_generation: u64,
    publisher_digest: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_scope: RevocationScopeId,
    revocation_generation: u64,
    revocation_head: ObjectDigest,
    revocation_mode: RevocationMode,
    revocation_grace_nanos: u64,
}

impl VerifiedControllerProjectAdmissionV1 {
    /// Returns the protected Controller owner UID claimed by the signer.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.controller_uid
    }

    /// Returns the checked diagnostic journal sequence.
    #[must_use]
    pub const fn journal_sequence(self) -> u64 {
        self.journal_sequence
    }

    /// Returns the exact admitted public Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the selected parentless sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the protected project partition.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the checked public Create and publisher join commitment.
    #[must_use]
    pub const fn source_commitment(self) -> ObjectDigest {
        self.source_commitment
    }

    /// Returns the current Controller publisher generation.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.publisher_generation
    }

    /// Returns the canonical current publisher policy descriptor digest.
    #[must_use]
    pub const fn publisher_digest(self) -> ObjectDigest {
        self.publisher_digest
    }

    /// Returns the current project disclosure-domain head.
    #[must_use]
    pub const fn cache_domain_head(self) -> ObjectDigest {
        self.cache_domain_head
    }

    /// Returns the publisher-selected revocation scope.
    #[must_use]
    pub const fn revocation_scope(self) -> RevocationScopeId {
        self.revocation_scope
    }

    /// Returns the current revocation generation.
    #[must_use]
    pub const fn revocation_generation(self) -> u64 {
        self.revocation_generation
    }

    /// Returns the current project revocation head.
    #[must_use]
    pub const fn revocation_head(self) -> ObjectDigest {
        self.revocation_head
    }

    /// Returns the current publisher policy's revocation mode.
    #[must_use]
    pub const fn revocation_mode(self) -> RevocationMode {
        self.revocation_mode
    }

    /// Returns the current publisher policy's revocation grace interval.
    #[must_use]
    pub const fn revocation_grace_nanos(self) -> u64 {
        self.revocation_grace_nanos
    }

    fn validate(self, expected_uid: u32) -> Result<(), ControllerProjectAdmissionReadbackErrorV1> {
        if expected_uid == 0
            || self.controller_uid != expected_uid
            || self.journal_sequence == 0
            || self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.source_commitment.as_bytes() == &[0; 32]
            || self.publisher_generation == 0
            || self.publisher_digest.as_bytes() == &[0; 32]
            || self.cache_domain_head.as_bytes() == &[0; 32]
            || self.revocation_scope.as_bytes() == &[0; 16]
            || self.revocation_generation == 0
            || self.revocation_head.as_bytes() == &[0; 32]
        {
            return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
        }
        Ok(())
    }
}

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

fn fields_from_source(
    journal: &mut Journal,
    source: &CurrentCreateProjectPolicySourceV1,
    uid: u32,
    sequence: u64,
) -> Result<VerifiedControllerProjectAdmissionV1, ControllerProjectAdmissionReadbackErrorV1> {
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
    let fields = VerifiedControllerProjectAdmissionV1 {
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

/// Verifies a Controller project-admission receipt against a Root-owned pin.
///
/// Root must independently load the AOSCTK01 pin and compare this receipt to
/// its signed project/deployment source and a current Source ancestry proof.
/// Verification alone cannot authorize admission, publication, or Create.
///
/// # Errors
///
/// Rejects a changed challenge, role generation, UID, canonical field, or
/// signature.
pub fn verify_controller_project_admission_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    expected_uid: u32,
) -> Result<VerifiedControllerProjectAdmissionV1, ControllerProjectAdmissionReadbackErrorV1> {
    if bytes.len() != CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let body = &bytes[..BODY_BYTES];
    if body[..8] != MAGIC[..]
        || take::<2>(body, 8)? != VERSION.to_be_bytes()
        || take::<2>(body, 10)? != [0; 2]
        || u64::from_be_bytes(take::<8>(body, 12)?) != signer.generation()
        || take::<16>(body, 20)? != challenge.nonce
        || take::<32>(body, 36)? != *challenge.cut.as_bytes()
        || take::<3>(body, 297)? != [0; 3]
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::Stale);
    }
    let fields = VerifiedControllerProjectAdmissionV1 {
        controller_uid: u32::from_be_bytes(take::<4>(body, 68)?),
        journal_sequence: u64::from_be_bytes(take::<8>(body, 72)?),
        operation: OperationId::from_bytes(take::<16>(body, 80)?),
        sandbox: SandboxId::from_bytes(take::<16>(body, 96)?),
        project: ProjectId::from_bytes(take::<16>(body, 112)?),
        source_commitment: ObjectDigest::from_bytes(take::<32>(body, 128)?),
        publisher_generation: u64::from_be_bytes(take::<8>(body, 160)?),
        publisher_digest: ObjectDigest::from_bytes(take::<32>(body, 168)?),
        cache_domain_head: ObjectDigest::from_bytes(take::<32>(body, 200)?),
        revocation_scope: RevocationScopeId::from_bytes(take::<16>(body, 232)?),
        revocation_generation: u64::from_be_bytes(take::<8>(body, 248)?),
        revocation_head: ObjectDigest::from_bytes(take::<32>(body, 256)?),
        revocation_mode: decode_revocation_mode(body[288])?,
        revocation_grace_nanos: u64::from_be_bytes(take::<8>(body, 289)?),
    };
    fields.validate(expected_uid)?;
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(&signature_preimage(body), &signature)
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::Signature)?;
    Ok(fields)
}

fn sign_fields(
    fields: VerifiedControllerProjectAdmissionV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    if signer_generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    fields.validate(fields.controller_uid)?;
    let mut bytes = [0; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[12..20].copy_from_slice(&signer_generation.to_be_bytes());
    bytes[20..36].copy_from_slice(&challenge.nonce);
    bytes[36..68].copy_from_slice(challenge.cut.as_bytes());
    bytes[68..72].copy_from_slice(&fields.controller_uid.to_be_bytes());
    bytes[72..80].copy_from_slice(&fields.journal_sequence.to_be_bytes());
    bytes[80..96].copy_from_slice(fields.operation.as_bytes());
    bytes[96..112].copy_from_slice(fields.sandbox.as_bytes());
    bytes[112..128].copy_from_slice(fields.project.as_bytes());
    bytes[128..160].copy_from_slice(fields.source_commitment.as_bytes());
    bytes[160..168].copy_from_slice(&fields.publisher_generation.to_be_bytes());
    bytes[168..200].copy_from_slice(fields.publisher_digest.as_bytes());
    bytes[200..232].copy_from_slice(fields.cache_domain_head.as_bytes());
    bytes[232..248].copy_from_slice(fields.revocation_scope.as_bytes());
    bytes[248..256].copy_from_slice(&fields.revocation_generation.to_be_bytes());
    bytes[256..288].copy_from_slice(fields.revocation_head.as_bytes());
    bytes[288] = encode_revocation_mode(fields.revocation_mode);
    bytes[289..297].copy_from_slice(&fields.revocation_grace_nanos.to_be_bytes());
    let signature = key.sign(&signature_preimage(&bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
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
    let fields = VerifiedControllerProjectAdmissionV1 {
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

fn encode_revocation_mode(mode: RevocationMode) -> u8 {
    match mode {
        RevocationMode::DenyNew => 1,
        RevocationMode::Freeze => 2,
        RevocationMode::Stop => 3,
    }
}

fn decode_revocation_mode(
    mode: u8,
) -> Result<RevocationMode, ControllerProjectAdmissionReadbackErrorV1> {
    match mode {
        1 => Ok(RevocationMode::DenyNew),
        2 => Ok(RevocationMode::Freeze),
        3 => Ok(RevocationMode::Stop),
        _ => Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical),
    }
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerProjectAdmissionReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(ControllerProjectAdmissionReadbackErrorV1::NonCanonical)
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::policy_compiler::encode_controller_hold_signer_credential_v1;

    fn fields() -> VerifiedControllerProjectAdmissionV1 {
        VerifiedControllerProjectAdmissionV1 {
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
            .expect("Controller-only pin");
        let signer = PinnedControllerHoldSignerV1::decode(&credential).expect("pinned signer");
        let challenge = ControllerProjectAdmissionChallengeV1::new(
            [17; 16],
            ObjectDigest::from_bytes([18; 32]),
        )
        .expect("Root challenge");
        let packet = sign_fields(fields(), challenge, 16, &key).expect("signed packet");
        assert_eq!(
            verify_controller_project_admission_readback_v1(&packet, &signer, challenge, 811)
                .expect("exact Controller evidence"),
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
        let rotated =
            encode_controller_hold_signer_credential_v1(17, &key.verifying_key()).unwrap();
        let rotated = PinnedControllerHoldSignerV1::decode(&rotated).unwrap();
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
