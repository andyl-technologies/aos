//! Historical Controller dispatch custody, restricted to negative recovery.
//!
//! The issuer rejoins the actual original Operation/Effect and protected suffix.
//! No publisher, project ancestry, deployment, or positive currentness claim is
//! present. Root independently verifies its retained Controller-only role pin.
//!
//! ```text
//! AOSCTP05 | version:u16=5 | reserved[6]=0 | signer-generation:u64 |
//! Controller-UID:u32 | Controller-journal-sequence:u64 |
//! original-operation:16 | original-sandbox:16 | project:16 |
//! source-commitment:32 | immutable-admission-revision:32 |
//! admission-generation:u64 | DispatchAuthorized-metadata:32 |
//! actual-prospective-Source-reservation:136 | Ed25519-signature:64
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::journal::{Journal, SourceProjectAdmissionReservationV1};
use crate::reconciler::project_admission::{
    ControllerProjectDispatchReadbackV1, controller_project_dispatch_readback_v1,
};

use super::controller_project_terminal_readback::take;
use super::{ControllerProjectAdmissionReadbackErrorV1, PinnedControllerHoldSignerV1};

const MAGIC: &[u8; 8] = b"AOSCTP05";
const DOMAIN: &[u8] = b"aos.sandbox.controller-project-negative-dispatch.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const BODY_BYTES: usize = 324;
/// Bounds the retirement-only original Controller dispatch readback.
pub const CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Signs an actual DispatchAuthorized original Effect for retirement only.
///
/// The retained Controller writer and subsequent actual Source preview recheck
/// are mandatory. This receipt cannot authorize a Root stage or positive commit.
///
/// # Errors
///
/// Rejects changed owner custody, original admission, phase or reserved suffix,
/// absent metadata, or a zero signer generation.
pub fn sign_fixed_controller_project_dispatch_readback_v1(
    journal: &Journal,
    operation: OperationId,
    signer_generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    let claims = controller_project_dispatch_readback_v1(journal, operation)
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::Stale)?;
    sign_claims(
        &claims,
        rustix::process::getuid().as_raw(),
        journal.snapshot_sequence(),
        signer_generation,
        key,
    )
}

fn sign_claims(
    claims: &ControllerProjectDispatchReadbackV1,
    uid: u32,
    sequence: u64,
    generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    if uid == 0 || sequence == 0 || generation == 0 {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let mut packet = [0; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&5_u16.to_be_bytes());
    packet[16..24].copy_from_slice(&generation.to_be_bytes());
    packet[24..28].copy_from_slice(&uid.to_be_bytes());
    packet[28..36].copy_from_slice(&sequence.to_be_bytes());
    packet[36..52].copy_from_slice(claims.operation.as_bytes());
    packet[52..68].copy_from_slice(claims.sandbox.as_bytes());
    packet[68..84].copy_from_slice(claims.project.as_bytes());
    packet[84..116].copy_from_slice(claims.source_commitment.as_bytes());
    packet[116..148].copy_from_slice(claims.admission_revision.as_bytes());
    packet[148..156].copy_from_slice(&claims.admission_generation.to_be_bytes());
    packet[156..188].copy_from_slice(claims.metadata.as_bytes());
    packet[188..324].copy_from_slice(&claims.reservation.record_bytes());
    let signature = key.sign(&preimage(&packet[..BODY_BYTES]));
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(packet)
}

pub(crate) fn verify_controller_project_dispatch_readback_v1(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    uid: u32,
) -> Result<ControllerProjectDispatchReadbackV1, ControllerProjectAdmissionReadbackErrorV1> {
    if packet.len() != CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1
        || packet.get(..8) != Some(MAGIC.as_slice())
        || packet[8..10] != 5_u16.to_be_bytes()
        || packet[10..16] != [0; 6]
        || uid == 0
        || u32::from_be_bytes(take::<4>(packet, 24)?) != uid
        || u64::from_be_bytes(take::<8>(packet, 16)?) != pin.generation()
        || u64::from_be_bytes(take::<8>(packet, 28)?) == 0
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    let claims = ControllerProjectDispatchReadbackV1 {
        operation: OperationId::from_bytes(take::<16>(packet, 36)?),
        sandbox: SandboxId::from_bytes(take::<16>(packet, 52)?),
        project: ProjectId::from_bytes(take::<16>(packet, 68)?),
        source_commitment: ObjectDigest::from_bytes(take::<32>(packet, 84)?),
        admission_revision: ObjectDigest::from_bytes(take::<32>(packet, 116)?),
        admission_generation: u64::from_be_bytes(take::<8>(packet, 148)?),
        metadata: ObjectDigest::from_bytes(take::<32>(packet, 156)?),
        reservation: SourceProjectAdmissionReservationV1::from_record_bytes(&packet[188..324])
            .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::NonCanonical)?,
    };
    if claims.operation.as_bytes() == &[0; 16]
        || claims.sandbox.as_bytes() == &[0; 16]
        || claims.project.as_bytes() == &[0; 16]
        || claims.project != claims.reservation.project()
        || claims.reservation.client_nonce()
            != super::project_admission_client_nonce_v1(claims.operation, claims.source_commitment)
        || claims.admission_generation != 1
        || [
            claims.source_commitment,
            claims.admission_revision,
            claims.metadata,
        ]
        .iter()
        .any(|value| value.as_bytes() == &[0; 32])
    {
        return Err(ControllerProjectAdmissionReadbackErrorV1::NonCanonical);
    }
    pin.verifying_key()
        .verify_strict(
            &preimage(&packet[..BODY_BYTES]),
            &Signature::from_bytes(&take::<64>(packet, BODY_BYTES)?),
        )
        .map_err(|_| ControllerProjectAdmissionReadbackErrorV1::Signature)?;
    Ok(claims)
}

fn preimage(body: &[u8]) -> Vec<u8> {
    [DOMAIN, body].concat()
}

// Tests exercise historical Root joining, not the installed Controller issuer.
#[cfg(test)]
pub(crate) fn sign_synthetic_controller_project_dispatch_v1(
    claims: &ControllerProjectDispatchReadbackV1,
    uid: u32,
    sequence: u64,
    generation: u64,
    key: &SigningKey,
) -> Result<
    [u8; CONTROLLER_PROJECT_DISPATCH_READBACK_BYTES_V1],
    ControllerProjectAdmissionReadbackErrorV1,
> {
    sign_claims(claims, uid, sequence, generation, key)
}
