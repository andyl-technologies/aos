//! Controller-only readback of accepted original-Effect project history.
//!
//! This historical receipt is separate from publisher currentness. The key is
//! the existing Controller-only role, but the signature domain and parser do
//! not overlap AOSCTP03 admission or any Q04 effect receipt. The issuer reads
//! actual protected Original Operation/Effect metadata under its writer.
//!
//! ```text
//! AOSCTP04 | version:u16=4 | terminal-kind:u8 | reserved[5]=0 |
//! signer-generation:u64 | Controller-UID:u32 | journal-sequence:u64 |
//! original-operation:16 | original-sandbox:16 | project:16 |
//! source-commitment:32 | immutable-admission-revision:32 | admission-generation:u64 |
//! accepted-Effect-metadata:32 | Source-reservation:32 | Source-issue:u64 |
//! Root-terminal:32 | Source-challenge:32 or zero | client-nonce:16 |
//! Source-fixed-names[48] | Ed25519-signature:64
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::journal::{Journal, ProtectedJournalNamesV1};
use crate::reconciler::project_admission::accepted_controller_project_terminal_v1;

use super::{
    ControllerProjectAdmissionReadbackErrorV1, PinnedControllerHoldSignerV1,
    RootProjectHistoryTerminalKindV1,
};

const MAGIC: &[u8; 8] = b"AOSCTP04";
const DOMAIN: &[u8] = b"aos.sandbox.controller-project-history-acceptance.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const BODY_BYTES: usize = 356;
/// Bounds the dedicated historical Controller acceptance receipt.
pub const CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Retains only the exact claims independently verified by Root's pinned key.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedControllerProjectTerminalV1 {
    pub operation: OperationId,
    pub sandbox: SandboxId,
    pub project: ProjectId,
    pub source_commitment: ObjectDigest,
    pub admission_revision: ObjectDigest,
    pub admission_generation: u64,
    pub accepted_metadata: ObjectDigest,
    pub reservation: ObjectDigest,
    pub issue: u64,
    pub root_terminal: ObjectDigest,
    pub challenge: ObjectDigest,
    pub client_nonce: [u8; 16],
    pub names: ProtectedJournalNamesV1,
    pub kind: RootProjectHistoryTerminalKindV1,
}

/// Signs an exact accepted original Effect under the existing Controller role.
///
/// The caller retains this writer through Source readback and Root-last floor
/// CAS. Publisher expiry is irrelevant to historical acceptance; the complete
/// immutable original admission and child identity are nevertheless rejoined.
///
/// # Errors
///
/// Rejects non-Controller custody, absent or changed accepted metadata, altered
/// original admission, a zero signer generation, or invalid physical names.
pub fn sign_fixed_controller_project_terminal_readback_v1(
    journal: &Journal,
    operation: OperationId,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    if signer_generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let claims = accepted_controller_project_terminal_v1(journal, operation)
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::Stale)?;
    sign_terminal_claims(
        &claims,
        rustix::process::getuid().as_raw(),
        journal.snapshot_sequence(),
        signer_generation,
        key,
    )
}

fn sign_terminal_claims(
    claims: &crate::reconciler::project_admission::AcceptedControllerProjectTerminalV1,
    controller_uid: u32,
    sequence: u64,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    if controller_uid == 0 || sequence == 0 || signer_generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let mut packet = [0; CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&4_u16.to_be_bytes());
    packet[10] = claims.kind.byte();
    packet[16..24].copy_from_slice(&signer_generation.to_be_bytes());
    packet[24..28].copy_from_slice(&controller_uid.to_be_bytes());
    packet[28..36].copy_from_slice(&sequence.to_be_bytes());
    packet[36..52].copy_from_slice(claims.operation.as_bytes());
    packet[52..68].copy_from_slice(claims.sandbox.as_bytes());
    packet[68..84].copy_from_slice(claims.project.as_bytes());
    packet[84..116].copy_from_slice(claims.source_commitment.as_bytes());
    packet[116..148].copy_from_slice(claims.admission_revision.as_bytes());
    packet[148..156].copy_from_slice(&claims.admission_generation.to_be_bytes());
    packet[156..188].copy_from_slice(claims.accepted_metadata.as_bytes());
    packet[188..220].copy_from_slice(claims.reservation.record_digest().as_bytes());
    packet[220..228].copy_from_slice(&claims.reservation.issue().to_be_bytes());
    packet[228..260].copy_from_slice(claims.root_terminal.as_bytes());
    if let Some(challenge) = claims.challenge {
        packet[260..292].copy_from_slice(challenge.record_digest().as_bytes());
    }
    packet[292..308].copy_from_slice(&claims.reservation.client_nonce());
    packet[308..356].copy_from_slice(&claims.reservation.names().to_bytes());
    let signature = key.sign(&preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(packet)
}

// This fixture-only seam qualifies Root signature/terminal joining, never the
// installed Controller issuer or Source genesis/currentness authority.
#[cfg(test)]
pub(crate) fn sign_synthetic_controller_project_terminal_v1(
    claims: &crate::reconciler::project_admission::AcceptedControllerProjectTerminalV1,
    controller_uid: u32,
    sequence: u64,
    generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    sign_terminal_claims(claims, controller_uid, sequence, generation, key)
}

pub(crate) fn verify_controller_project_terminal_readback_v1(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    expected_uid: u32,
) -> Result<VerifiedControllerProjectTerminalV1, ControllerProjectAdmissionReadbackErrorV1> {
    if packet.len() != CONTROLLER_PROJECT_TERMINAL_READBACK_BYTES_V1
        || packet.get(..8) != Some(MAGIC.as_slice())
        || packet.get(8..10) != Some(4_u16.to_be_bytes().as_slice())
        || packet[11..16] != [0; 5]
        || expected_uid == 0
        || u32::from_be_bytes(take::<4>(packet, 24)?) != expected_uid
        || u64::from_be_bytes(take::<8>(packet, 16)?) != pin.generation()
        || u64::from_be_bytes(take::<8>(packet, 28)?) == 0
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let kind = RootProjectHistoryTerminalKindV1::from_byte(packet[10])
        .ok_or(ControllerProjectAdmissionReadbackErrorV1::NonCanonical)?;
    let field = |start| take::<32>(packet, start).map(ObjectDigest::from_bytes);
    let fields = VerifiedControllerProjectTerminalV1 {
        operation: OperationId::from_bytes(take::<16>(packet, 36)?),
        sandbox: SandboxId::from_bytes(take::<16>(packet, 52)?),
        project: ProjectId::from_bytes(take::<16>(packet, 68)?),
        source_commitment: field(84)?,
        admission_revision: field(116)?,
        admission_generation: u64::from_be_bytes(take::<8>(packet, 148)?),
        accepted_metadata: field(156)?,
        reservation: field(188)?,
        issue: u64::from_be_bytes(take::<8>(packet, 220)?),
        root_terminal: field(228)?,
        challenge: field(260)?,
        client_nonce: take::<16>(packet, 292)?,
        names: ProtectedJournalNamesV1::from_bytes(&packet[308..356])
            .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::NonCanonical)?,
        kind,
    };
    if fields.operation.as_bytes() == &[0; 16]
        || fields.sandbox.as_bytes() == &[0; 16]
        || fields.project.as_bytes() == &[0; 16]
        || fields.client_nonce == [0; 16]
        || fields.issue == 0
        || fields.admission_generation != 1
        || [
            fields.source_commitment,
            fields.admission_revision,
            fields.accepted_metadata,
            fields.reservation,
            fields.root_terminal,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
        || ((kind == RootProjectHistoryTerminalKindV1::CanceledReservation)
            != (fields.challenge.as_bytes() == &[0; 32]))
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let signature = Signature::from_bytes(&take::<64>(packet, BODY_BYTES)?);
    pin.verifying_key()
        .verify_strict(&preimage(&packet[..BODY_BYTES]), &signature)
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::Signature)?;
    Ok(fields)
}

fn preimage(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + body.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

pub(super) fn take<const N: usize>(
    packet: &[u8],
    offset: usize,
) -> Result<[u8; N], ControllerProjectAdmissionReadbackErrorV1> {
    packet
        .get(offset..offset + N)
        .ok_or(ControllerProjectAdmissionReadbackErrorV1::NonCanonical)?
        .try_into()
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::NonCanonical)
}
