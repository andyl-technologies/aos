//! Existing Controller-role signatures over actual held genesis acceptance.
//!
//! ```text
//! AOSSGR01 | version:u16=1 | kind:u8 | reserved[5] | signer-generation:u64 |
//! Controller-uid:u32 | Source-uid:u32 | Controller-frame:u64 | Source-frame:u64 |
//! Root-flight-nonce[16] | accepted-input[608] | Controller-names[48] |
//! Source-names[48] | actual-existing-Source-instance[32] or zero |
//! Ed25519-signature[64]
//! ```
//!
//! Current kind=0 is emitted only before genuine new Source mutation; historical
//! kind=1 requires an actual existing immutable Source receipt. Vacant kind=2
//! retains an actual empty target under an already anchored existing instance.
//! Final kind=3 additionally rejoins the actual durable Controller Complete
//! row with the exact anchored Source ACK. Historical kind=1 remains available
//! before that Controller append for crash recovery. All four rejoin real held
//! writers. These signatures are provenance, not a detached Root proof.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1;
use crate::hierarchy::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1, hash, take,
};
use crate::hierarchy::source_genesis::HeldSourceTreeGenesisObservationV1;
use crate::hierarchy::source_genesis::SourceTreeGenesisStateV1;
use crate::journal::ProtectedJournalNamesV1;

use super::super::PinnedControllerHoldSignerV1;

const MAGIC: &[u8; 8] = b"AOSSGR01";
const DOMAIN: &[u8] = b"aos.sandbox.source-genesis.controller-held-readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const BODY_BYTES: usize = 800;
/// Bounds the existing Controller-purpose genesis readback signature packet.
pub const CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

/// Signs the exact actual Controller and Source cuts for one live Root nonce.
///
/// The existing process credential signer supplies the key. This function
/// cannot issue seed/project administration or mint a live Root proof.
///
/// # Errors
/// Rejects changed real owner cuts, foreign input/UID, zero generation/nonce,
/// or noncurrent administrative heads before a genuinely new Source append.
pub fn sign_controller_source_genesis_readback_v1(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    nonce: [u8; 16],
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1> {
    controller.recheck()?;
    source.recheck()?;
    if nonce == [0; 16] || generation == 0 || source.source_uid() == 0 {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let kind = if source.state() == SourceTreeGenesisStateV1::VacantProject {
        if source.project() != Some(controller.acceptance().project())
            || source.instance().is_none()
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        controller.recheck_current_admission()?;
        2
    } else if let Some(receipt) = source.receipt() {
        if receipt.acceptance_digest() != controller.acceptance().digest()
            || &receipt.seed_packet() != controller.acceptance().seed_packet()
            || &receipt.auth_packet() != controller.acceptance().auth_packet()
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        1
    } else {
        if source.state() != SourceTreeGenesisStateV1::Empty {
            return Err(SourceGenesisErrorV1::Stale);
        }
        controller.recheck_current_admission()?;
        0
    };
    sign_readback(controller, source, nonce, generation, key, kind)
}

/// Signs actual durable Controller completion joined to the exact Source ACK.
///
/// This final-only readback cannot be produced merely from an acceptance or
/// anchored Source receipt. Ordinary historical readback remains separate so
/// a crash after Source ACK can recover before Controller completion exists.
/// It creates no detached Root proof or new administrative authority.
///
/// # Errors
/// Rejects missing or mismatched durable completion, changed held owner cuts,
/// foreign receipt/ACK, or zero generation/nonce.
pub fn sign_controller_source_genesis_completion_readback_v1(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    nonce: [u8; 16],
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1> {
    controller.recheck_completed_source_ack(source)?;
    sign_readback(controller, source, nonce, generation, key, 3)
}

fn sign_readback(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    nonce: [u8; 16],
    generation: u64,
    key: &SigningKey,
    kind: u8,
) -> Result<[u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1> {
    if nonce == [0; 16] || generation == 0 || source.source_uid() == 0 {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    let mut packet = [0; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1];
    packet[..8].copy_from_slice(MAGIC);
    packet[8..10].copy_from_slice(&1_u16.to_be_bytes());
    packet[10] = kind;
    packet[16..24].copy_from_slice(&generation.to_be_bytes());
    packet[24..28].copy_from_slice(&controller.uid().to_be_bytes());
    packet[28..32].copy_from_slice(&source.source_uid().to_be_bytes());
    packet[32..40].copy_from_slice(&controller.snapshot_sequence()?.to_be_bytes());
    packet[40..48].copy_from_slice(&source.snapshot_sequence().to_be_bytes());
    packet[48..64].copy_from_slice(&nonce);
    packet[64..672].copy_from_slice(controller.acceptance().record_bytes());
    packet[672..720].copy_from_slice(&controller.names().to_bytes());
    packet[720..768].copy_from_slice(&source.names().to_bytes());
    packet[768..800].copy_from_slice(&source.instance().unwrap_or([0; 32]));
    let signature = key.sign(&[DOMAIN, &packet[..BODY_BYTES]].concat());
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    controller.recheck()?;
    source.recheck()?;
    if kind == 3 {
        controller.recheck_completed_source_ack(source)?;
    } else if kind != 1 {
        controller.recheck_current_admission()?;
    }
    Ok(packet)
}

pub(super) struct VerifiedControllerSourceGenesisReadbackV1 {
    pub(super) acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    pub(super) historical: bool,
    pub(super) completed: bool,
    pub(super) vacant: bool,
    pub(super) source_instance: Option<[u8; 32]>,
    pub(super) source_names: ProtectedJournalNamesV1,
    pub(super) source_sequence: u64,
}

pub(super) fn verify(
    packet: &[u8],
    pin: &PinnedControllerHoldSignerV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
) -> Result<VerifiedControllerSourceGenesisReadbackV1, SourceGenesisErrorV1> {
    if packet.len() != CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
        || packet.get(..8) != Some(MAGIC.as_slice())
        || packet[8..10] != 1_u16.to_be_bytes()
        || packet[10] > 3
        || packet[11..16] != [0; 5]
        || nonce == [0; 16]
        || controller_uid == 0
        || source_uid == 0
        || u64::from_be_bytes(take(packet, 16)?) != pin.generation()
        || u32::from_be_bytes(take(packet, 24)?) != controller_uid
        || u32::from_be_bytes(take(packet, 28)?) != source_uid
        || u64::from_be_bytes(take(packet, 32)?) == 0
        || u64::from_be_bytes(take(packet, 40)?) == 0
        || take::<16>(packet, 48)? != nonce
    {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    ProtectedJournalNamesV1::from_bytes(&packet[672..720])?;
    let source_names = ProtectedJournalNamesV1::from_bytes(&packet[720..768])?;
    let acceptance =
        ControllerSourceGenesisAcceptanceRecordV1::from_record_bytes(&packet[64..672])?;
    let source_instance = take::<32>(packet, 768)?;
    if (packet[10] == 0) != (source_instance == [0; 32]) {
        return Err(SourceGenesisErrorV1::NonCanonical);
    }
    pin.verifying_key()
        .verify_strict(
            &[DOMAIN, &packet[..BODY_BYTES]].concat(),
            &Signature::from_bytes(&take(packet, BODY_BYTES)?),
        )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    Ok(VerifiedControllerSourceGenesisReadbackV1 {
        acceptance,
        historical: matches!(packet[10], 1 | 3),
        completed: packet[10] == 3,
        vacant: packet[10] == 2,
        source_instance: (source_instance != [0; 32]).then_some(source_instance),
        source_names,
        source_sequence: u64::from_be_bytes(take(packet, 40)?),
    })
}

pub(super) fn packet_digest(packet: &[u8]) -> ObjectDigest {
    hash(DOMAIN, packet)
}

#[cfg(test)]
mod tests;
