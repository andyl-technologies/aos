//! Independent Source-only signature over a pre-Q04 project ancestry challenge.
//!
//! ```text
//! AOSQPR03 | version:u16=3 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce:16 | Root-cut:32 | project:16 | ancestry-head:32 |
//! AOSQPA01-digest:32 | Source directory/journal/lock identities:48 |
//! AOSQPV01-reservation-digest:32 |
//! Ed25519-signature:64
//! ```
//!
//! The signer obtains all fields from its read-only fixed-name replay. Root
//! checks this packet under its own pinned Source key and the Controller-held
//! AOSQPA01 row; it does not transfer the Source writer or authorize Create.
//! Completed terminals use distinct AOSQPR06 framing and signature domain:
//! pending AOSQPR04 abort evidence cannot be relabeled as a settlement.

use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::source_project_history::{SourceProjectAdmissionChallengeKindV1, SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1, SourceProjectAdmissionTerminalV1};
use super::source_hold_readback::{PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackChallengeV1, SourceHoldReadbackErrorV1};

const MAGIC: &[u8; 8] = b"AOSQPR03";
const VERSION: u16 = 3;
const RETIREMENT_MAGIC: &[u8; 8] = b"AOSQPR04";
const RETIREMENT_VERSION: u16 = 4;
const BODY_BYTES: usize = 232;
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-admission.readback.v1\0";
const RETIREMENT_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-retirement.readback.v1\0";
const RESERVATION_MAGIC: &[u8; 8] = b"AOSQPR05";
const RESERVATION_SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.source-project-reservation.readback.v1\0";
const RESERVATION_BODY_BYTES: usize = 136;
const COMPLETED_TERMINAL_MAGIC: &[u8; 8] = b"AOSQPR06";
/// Names the completed-terminal DATA signature domain.
#[doc(hidden)]
pub const COMPLETED_TERMINAL_SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.source-project-completed-terminal.readback.v1\0";
/// Bounds the completed-terminal unsigned DATA body.
#[doc(hidden)]
pub const COMPLETED_TERMINAL_BODY_BYTES: usize = 552;

/// Bounds the distinct signed actual-terminal packet.
///
/// ```text
/// AOSQPR06 | version:u16=6 | reserved[6]=0 | generation:u64 |
/// Source-sequence:u64 | actual-reservation:136 |
/// actual-challenge-or-zero:232 | actual-Source-terminal:152 | signature:64
/// ```
///
/// A cancellation occupies 120 terminal bytes followed by 32 zero bytes.
pub const SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1: usize =
    COMPLETED_TERMINAL_BODY_BYTES + 64;

/// Authenticates actual completed Source rows under an independently pinned key.
///
/// It proves historical terminal identity, not a fresh clock, Root admission,
/// retirement ACK, or transferable writer. Root must independently join its
/// retained intent/terminal and reject issues below its durable history floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSourceProjectTerminalReadbackV1 {
    terminal: SourceProjectAdmissionTerminalV1,
    sequence: u64,
}

impl VerifiedSourceProjectTerminalReadbackV1 {
    /// Returns the actual Source reservation authenticated by this packet.
    pub const fn reservation(self) -> SourceProjectAdmissionReservationV1 {
        self.terminal.reservation()
    }

    /// Returns the actual challenged row, absent for reservation cancellation.
    pub const fn challenge(self) -> Option<SourceProjectAdmissionChallengeV1> {
        self.terminal.challenge()
    }

    /// Returns the digest of the actual unpadded Source terminal.
    pub fn source_terminal_digest(self) -> ObjectDigest {
        self.terminal.source_terminal_digest()
    }

    /// Returns the exact Root terminal digest retained by Source.
    pub const fn root_terminal_digest(self) -> ObjectDigest {
        self.terminal.root_terminal_digest()
    }

    /// Returns the fixed names independently observed by the Source signer.
    pub const fn names(self) -> ProtectedJournalNamesV1 {
        self.terminal.reservation().names()
    }

    /// Returns the Source journal frame boundary at the completed observation.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Signs supplied canonical terminal DATA without a native writer proof.
///
/// # Errors
/// Rejects a zero sequence or signer generation.
pub fn sign_source_project_completed_terminal_fields_v1(
    terminal: SourceProjectAdmissionTerminalV1,
    sequence: u64,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if sequence == 0 || generation == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(COMPLETED_TERMINAL_MAGIC);
    bytes[8..10].copy_from_slice(&6_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..32].copy_from_slice(&sequence.to_be_bytes());
    bytes[32..168].copy_from_slice(&terminal.reservation().record_bytes());
    if let Some(challenge) = terminal.challenge() {
        bytes[168..400].copy_from_slice(&challenge.record_bytes());
    }
    bytes[400..552].copy_from_slice(&terminal.record_bytes());
    let signature = signing_key.sign(&signature_preimage(
        COMPLETED_TERMINAL_SIGNATURE_DOMAIN,
        &bytes[..COMPLETED_TERMINAL_BODY_BYTES],
    ));
    bytes[COMPLETED_TERMINAL_BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies the separate Source completed-terminal domain and actual row join.
///
/// It cannot relabel a pending abort readback as completed, synthesize ancestry,
/// or authorize Root retirement without Root's independently retained intent.
///
/// # Errors
///
/// Rejects noncanonical framing or row joins, wrong signer generation,
/// mismatched historical terminal challenge, or an invalid signature.
pub fn verify_source_project_completed_terminal_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
) -> Result<VerifiedSourceProjectTerminalReadbackV1, SourceHoldReadbackErrorV1> {
    if bytes.len() != SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1
        || bytes.get(..8) != Some(COMPLETED_TERMINAL_MAGIC)
        || take::<2>(bytes, 8)? != 6_u16.to_be_bytes()
        || take::<6>(bytes, 10)? != [0; 6]
        || take::<8>(bytes, 16)? != signer.generation().to_be_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, COMPLETED_TERMINAL_BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(
                COMPLETED_TERMINAL_SIGNATURE_DOMAIN,
                &bytes[..COMPLETED_TERMINAL_BODY_BYTES],
            ),
            &signature,
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)?;
    let reservation = SourceProjectAdmissionReservationV1::from_record_bytes(&bytes[32..168])
        .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?;
    let actual_challenge = if bytes[168..400] == [0; 232] {
        None
    } else {
        Some(
            SourceProjectAdmissionChallengeV1::from_record_bytes(&bytes[168..400])
                .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?,
        )
    };
    let terminal = SourceProjectAdmissionTerminalV1::from_record_parts(
        reservation,
        actual_challenge,
        &bytes[400..552],
    )
    .map_err(|_| SourceHoldReadbackErrorV1::NonCanonical)?;
    let sequence = u64::from_be_bytes(take::<8>(bytes, 24)?);
    if sequence == 0
        || reservation.client_nonce() != challenge.nonce()
        || terminal.root_terminal_digest() != challenge.cut()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    Ok(VerifiedSourceProjectTerminalReadbackV1 { terminal, sequence })
}

/// Bounds the exact Source-only project-admission readback packet.
pub const SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Bounds the distinct Source-only reservation packet.
pub const SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1: usize = RESERVATION_BODY_BYTES + 64;

/// Signs only the current pre-stage Source reservation and physical names.
pub fn sign_source_project_reservation_fields_v1(
    row: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0 {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(RESERVATION_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&row.client_nonce());
    bytes[40..56].copy_from_slice(row.project().as_bytes());
    bytes[56..88].copy_from_slice(row.record_digest().as_bytes());
    bytes[88..136].copy_from_slice(&row.names().to_bytes());
    let signature = signing_key.sign(&signature_preimage(
        RESERVATION_SIGNATURE_DOMAIN,
        &bytes[..RESERVATION_BODY_BYTES],
    ));
    bytes[RESERVATION_BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies the exact pre-stage Source reservation under Root's pinned key.
///
/// This packet asserts only Source's current read-only replay at signing;
/// Root must serialize stage versus cancellation under its own writer.
///
/// # Errors
///
/// Rejects changed reservation, signer generation, framing, or signature.
pub fn verify_source_project_reservation_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    expected: SourceProjectAdmissionReservationV1,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if bytes.len() != SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1
        || bytes.get(..8) != Some(RESERVATION_MAGIC)
        || take::<2>(bytes, 8)? != 1_u16.to_be_bytes()
        || take::<6>(bytes, 10)? != [0; 6]
        || take::<8>(bytes, 16)? != signer.generation().to_be_bytes()
        || take::<16>(bytes, 24)? != expected.client_nonce()
        || take::<16>(bytes, 40)? != *expected.project().as_bytes()
        || take::<32>(bytes, 56)? != *expected.record_digest().as_bytes()
        || take::<48>(bytes, 88)? != expected.names().to_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, RESERVATION_BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(
                RESERVATION_SIGNATURE_DOMAIN,
                &bytes[..RESERVATION_BODY_BYTES],
            ),
            &signature,
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

/// Signs supplied canonical project fields without a currentness grant.
///
/// # Errors
/// Rejects a noncanonical saved project association.
pub fn sign_source_project_admission_fields_v1(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if row.kind() != SourceProjectAdmissionChallengeKindV1::Admission {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    sign_fields(
        row,
        reservation,
        generation,
        signing_key,
        MAGIC,
        VERSION,
        SIGNATURE_DOMAIN,
    )
}

/// Signs supplied canonical project fields without a currentness grant.
///
/// # Errors
/// Rejects a noncanonical saved project association.
pub fn sign_source_project_retirement_fields_v1(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    sign_fields(
        row,
        reservation,
        generation,
        signing_key,
        RETIREMENT_MAGIC,
        RETIREMENT_VERSION,
        RETIREMENT_SIGNATURE_DOMAIN,
    )
}

fn sign_fields(
    row: SourceProjectAdmissionChallengeV1,
    reservation: SourceProjectAdmissionReservationV1,
    generation: u64,
    signing_key: &SigningKey,
    magic: &[u8; 8],
    version: u16,
    domain: &[u8],
) -> Result<[u8; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1], SourceHoldReadbackErrorV1> {
    if generation == 0
        || row.issue() != reservation.issue()
        || row.project() != reservation.project()
        || row.names() != reservation.names()
    {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    let mut bytes = [0; SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&version.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&row.nonce());
    bytes[40..72].copy_from_slice(row.cut().as_bytes());
    bytes[72..88].copy_from_slice(row.project().as_bytes());
    bytes[88..120].copy_from_slice(row.ancestry().as_bytes());
    bytes[120..152].copy_from_slice(row.record_digest().as_bytes());
    bytes[152..200].copy_from_slice(&row.names().to_bytes());
    bytes[200..232].copy_from_slice(reservation.record_digest().as_bytes());
    let signature = signing_key.sign(&signature_preimage(domain, &bytes[..BODY_BYTES]));
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
}

/// Verifies one Source-only packet against the exact Controller-held challenge.
///
/// The caller must load the Source-purpose pin independently and obtain the
/// expected AOSQPA01 row from retained Source writer custody. A packet alone
/// does not prove Root spent its nonce or that Controller retained its writer.
///
/// # Errors
///
/// Rejects wrong role generation, challenge, row, project, physical names,
/// canonical framing, or signature.
pub fn verify_source_project_admission_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
) -> Result<(), SourceHoldReadbackErrorV1> {
    if expected.kind() != SourceProjectAdmissionChallengeKindV1::Admission {
        return Err(SourceHoldReadbackErrorV1::NonCanonical);
    }
    verify_fields(
        bytes,
        signer,
        challenge,
        project,
        expected,
        reservation_digest,
        MAGIC,
        VERSION,
        SIGNATURE_DOMAIN,
    )
}

/// Verifies an exact Source-only retirement packet without granting ancestry.
///
/// This separate signature domain cannot be substituted for AOSQPR03 at Root
/// commit. It proves only the exact durable row and named Source journal.
///
/// # Errors
///
/// Rejects changed row, names, challenge, signer pin, framing, or signature.
pub fn verify_source_project_retirement_readback_v1(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
) -> Result<(), SourceHoldReadbackErrorV1> {
    verify_fields(
        bytes,
        signer,
        challenge,
        project,
        expected,
        reservation_digest,
        RETIREMENT_MAGIC,
        RETIREMENT_VERSION,
        RETIREMENT_SIGNATURE_DOMAIN,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_fields(
    bytes: &[u8],
    signer: &PinnedSourceHoldReadbackSignerV1,
    challenge: SourceHoldReadbackChallengeV1,
    project: ProjectId,
    expected: SourceProjectAdmissionChallengeV1,
    reservation_digest: aos_sandbox_core::ObjectDigest,
    magic: &[u8; 8],
    version: u16,
    domain: &[u8],
) -> Result<(), SourceHoldReadbackErrorV1> {
    if bytes.len() != SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1
        || project.as_bytes() == &[0; 16]
        || expected.nonce() != challenge.nonce()
        || expected.cut() != challenge.cut()
        || expected.project() != project
        || bytes.get(..8) != Some(magic)
        || take::<2>(bytes, 8)? != version.to_be_bytes()
        || take::<6>(bytes, 10)? != [0; 6]
        || take::<8>(bytes, 16)? != signer.generation().to_be_bytes()
        || take::<16>(bytes, 24)? != challenge.nonce()
        || take::<32>(bytes, 40)? != *challenge.cut().as_bytes()
        || take::<16>(bytes, 72)? != *project.as_bytes()
        || take::<32>(bytes, 88)? != *expected.ancestry().as_bytes()
        || take::<32>(bytes, 120)? != *expected.record_digest().as_bytes()
        || take::<48>(bytes, 152)? != expected.names().to_bytes()
        || take::<32>(bytes, 200)? != *reservation_digest.as_bytes()
    {
        return Err(SourceHoldReadbackErrorV1::Stale);
    }
    let signature = Signature::from_bytes(&take::<64>(bytes, BODY_BYTES)?);
    signer
        .verifying_key()
        .verify_strict(
            &signature_preimage(domain, &bytes[..BODY_BYTES]),
            &signature,
        )
        .map_err(|_| SourceHoldReadbackErrorV1::Signature)
}

/// Builds the domain-separated comparison signature preimage.
#[doc(hidden)]
pub fn signature_preimage(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len() + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(body);
    preimage
}

fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceHoldReadbackErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|field| field.try_into().ok())
        .ok_or(SourceHoldReadbackErrorV1::NonCanonical)
}

