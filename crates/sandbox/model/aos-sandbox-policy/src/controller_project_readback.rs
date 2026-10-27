//! Owns Controller project-readback DATA and strict packet verification.
//!
//! Native Controller custody, current Publisher/source joins and signing stay
//! with their actual owner. Root separately retains its pins, original clock
//! and current Authority. Neither unsigned fields nor a signature replace them.
//!
//! ```text
//! AOSCTP03 | version3 | signer-generation | nonce16 | cut32 | Controller-UID |
//! sequence | Create/sandbox/project | Source/publisher/cache/revocation |
//! reserved3 | Ed25519-signature64
//! ```

use crate::controller_readback::PinnedControllerHoldSignerV1;
use aos_sandbox_model::model::RevocationMode;
use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, RevocationScopeId, SandboxId};
use ed25519_dalek::Signature;

const MAGIC: &[u8; 8] = b"AOSCTP03";
const VERSION: u16 = 3;
/// Bounds the existing unsigned body before its fixed64-byte signature.
pub const CONTROLLER_PROJECT_ADMISSION_BODY_BYTES_V1: usize = 300;
const BODY_BYTES: usize = CONTROLLER_PROJECT_ADMISSION_BODY_BYTES_V1;
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
    ) -> Result<Self, ControllerProjectAdmissionDataErrorV1> {
        if nonce == [0; 16] || cut.as_bytes() == &[0; 32] {
            return Err(ControllerProjectAdmissionDataErrorV1::NonCanonical);
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

/// Keeps unsigned comparison claims without authenticating a receipt or owner.
///
/// The actual Controller gathers these fields under its retained native
/// source/Publisher checks. Constructing or validating them does not verify a
/// signature or establish current role authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerProjectAdmissionFieldsDataV1 {
    /// Names the unsigned Controller UID claim.
    pub controller_uid: u32,
    /// Carries the unsigned diagnostic journal sequence.
    pub journal_sequence: u64,
    /// Names the unsigned public Create operation.
    pub operation: OperationId,
    /// Names the unsigned parentless sandbox.
    pub sandbox: SandboxId,
    /// Names the unsigned project partition.
    pub project: ProjectId,
    /// Carries the unsigned Create/source commitment.
    pub source_commitment: ObjectDigest,
    /// Carries the unsigned Publisher generation.
    pub publisher_generation: u64,
    /// Carries the unsigned Publisher policy digest.
    pub publisher_digest: ObjectDigest,
    /// Carries the unsigned project disclosure head.
    pub cache_domain_head: ObjectDigest,
    /// Names the unsigned revocation scope.
    pub revocation_scope: RevocationScopeId,
    /// Carries the unsigned revocation generation.
    pub revocation_generation: u64,
    /// Carries the unsigned revocation head.
    pub revocation_head: ObjectDigest,
    /// Carries the unsigned revocation mode.
    pub revocation_mode: RevocationMode,
    /// Carries the unsigned revocation grace interval.
    pub revocation_grace_nanos: u64,
}

impl ControllerProjectAdmissionFieldsDataV1 {
    /// Checks the same unsigned sentinel fields for the expected Controller UID.
    ///
    /// # Errors
    /// Rejects a zero required field or a changed Controller identity.
    pub fn validate(self, expected_uid: u32) -> Result<(), ControllerProjectAdmissionDataErrorV1> {
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
            return Err(ControllerProjectAdmissionDataErrorV1::NonCanonical);
        }
        Ok(())
    }
}

/// Retains only claims authenticated by the strict pinned-role raw verifier.
///
/// Its private transparent wrapper preserves the complete unsigned field
/// representation without exposing a supplied-parts authenticated constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct VerifiedControllerProjectAdmissionV1(ControllerProjectAdmissionFieldsDataV1);

impl VerifiedControllerProjectAdmissionV1 {
    /// Returns the protected Controller owner UID claimed by the signer.
    #[must_use]
    pub const fn controller_uid(self) -> u32 {
        self.0.controller_uid
    }

    /// Returns the checked diagnostic journal sequence.
    #[must_use]
    pub const fn journal_sequence(self) -> u64 {
        self.0.journal_sequence
    }

    /// Returns the exact admitted public Create operation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.0.operation
    }

    /// Returns the selected parentless sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.0.sandbox
    }

    /// Returns the protected project partition.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.0.project
    }

    /// Returns the checked public Create and publisher join commitment.
    #[must_use]
    pub const fn source_commitment(self) -> ObjectDigest {
        self.0.source_commitment
    }

    /// Returns the current Controller publisher generation.
    #[must_use]
    pub const fn publisher_generation(self) -> u64 {
        self.0.publisher_generation
    }

    /// Returns the canonical current publisher policy descriptor digest.
    #[must_use]
    pub const fn publisher_digest(self) -> ObjectDigest {
        self.0.publisher_digest
    }

    /// Returns the current project disclosure-domain head.
    #[must_use]
    pub const fn cache_domain_head(self) -> ObjectDigest {
        self.0.cache_domain_head
    }

    /// Returns the publisher-selected revocation scope.
    #[must_use]
    pub const fn revocation_scope(self) -> RevocationScopeId {
        self.0.revocation_scope
    }

    /// Returns the current revocation generation.
    #[must_use]
    pub const fn revocation_generation(self) -> u64 {
        self.0.revocation_generation
    }

    /// Returns the current project revocation head.
    #[must_use]
    pub const fn revocation_head(self) -> ObjectDigest {
        self.0.revocation_head
    }

    /// Returns the current publisher policy's revocation mode.
    #[must_use]
    pub const fn revocation_mode(self) -> RevocationMode {
        self.0.revocation_mode
    }

    /// Returns the current publisher policy's revocation grace interval.
    #[must_use]
    pub const fn revocation_grace_nanos(self) -> u64 {
        self.0.revocation_grace_nanos
    }
}

impl VerifiedControllerProjectAdmissionV1 {
    /// Copies authenticated claims into an explicitly unsigned DATA view.
    #[must_use]
    pub const fn fields_data_v1(self) -> ControllerProjectAdmissionFieldsDataV1 {
        self.0
    }
}

/// Verifies the original full packet against the independently held role pin.
///
/// This authenticates claims only; actual role, original-clock and protected
/// native currentness gates remain at every genuine consumer frontier.
///
/// # Errors
/// Rejects changed role/challenge/UID, noncanonical fields or strict signature.
pub fn verify_controller_project_admission_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    expected_uid: u32,
) -> Result<VerifiedControllerProjectAdmissionV1, ControllerProjectAdmissionDataErrorV1> {
    if bytes.len() != CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1 {
        return Err(ControllerProjectAdmissionDataErrorV1::NonCanonical);
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
        return Err(ControllerProjectAdmissionDataErrorV1::Stale);
    }
    let fields = ControllerProjectAdmissionFieldsDataV1 {
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
        .verify_strict(
            &controller_project_admission_signature_preimage_v1(body),
            &signature,
        )
        .map_err(|_| ControllerProjectAdmissionDataErrorV1::Signature)?;
    Ok(VerifiedControllerProjectAdmissionV1(fields))
}

/// Prepares the unchanged unsigned body with zero signature bytes.
///
/// The real native signer retains the output and independently checks its
/// original boundary before signing the existing preimage.
///
/// # Errors
/// Rejects a zero signer generation or noncanonical unsigned claims.
pub fn prepare_controller_project_admission_body_v1(
    fields: ControllerProjectAdmissionFieldsDataV1,
    challenge: ControllerProjectAdmissionChallengeV1,
    signer_generation: u64,
) -> Result<
    [u8; CONTROLLER_PROJECT_ADMISSION_READBACK_BYTES_V1],
    ControllerProjectAdmissionDataErrorV1,
> {
    if signer_generation == 0 {
        return Err(ControllerProjectAdmissionDataErrorV1::NonCanonical);
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
    Ok(bytes)
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
) -> Result<RevocationMode, ControllerProjectAdmissionDataErrorV1> {
    match mode {
        1 => Ok(RevocationMode::DenyNew),
        2 => Ok(RevocationMode::Freeze),
        3 => Ok(RevocationMode::Stop),
        _ => Err(ControllerProjectAdmissionDataErrorV1::NonCanonical),
    }
}

/// Forms signature input without signing, custody or native admission.
#[must_use]
pub fn controller_project_admission_signature_preimage_v1(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerProjectAdmissionDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|part| part.try_into().ok())
        .ok_or(ControllerProjectAdmissionDataErrorV1::NonCanonical)
}

/// Preserves the three existing Controller project-readback DATA failures.
#[derive(Debug, thiserror::Error)]
pub enum ControllerProjectAdmissionDataErrorV1 {
    /// A challenge or signed receipt field is noncanonical.
    #[error("noncanonical Controller project-admission readback")]
    NonCanonical,
    /// A signed role generation or exact current-field claim differs.
    #[error("stale Controller project-admission readback")]
    Stale,
    /// The exact dedicated Controller signature failed verification.
    #[error("invalid Controller project-admission signature")]
    Signature,
}
