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
const PROJECT_MAGIC_V3: &[u8; 8] = b"AOSSGR03";
const PROJECT_DOMAIN_V3: &[u8] = b"aos.sandbox.source-genesis.controller-mixed-readback.v3\0/var/lib/aos/sandboxd/controller.journal\0";

#[derive(Clone, Copy)]
enum ControllerGenesisReadbackRecipeV3 { StrictV1, ProjectV3 }
/// Bounds the existing Controller-purpose genesis readback signature packet.
pub const CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

#[derive(Clone, Copy)]
pub(super) enum ProjectGenesisSignatureFailureV3 { Signature, Post(usize), Refused }

// The source loan and original flight stay in the enclosing invocation; this
// signature Result is parked there before any independent post can fail.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_project_genesis_readback_v3(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &crate::hierarchy::source_genesis::HeldSourceProjectGenesisObservationV3<'_>,
    generation: u64,
    key: &SigningKey,
    original: &super::flight::OriginalRootGenesisFlightV1<'_>,
    complete: bool,
    resident: &mut Option<Result<[u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1>>,
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>,
) -> Result<(), ProjectGenesisSignatureFailureV3> {
    if resident.is_some() { return Err(ProjectGenesisSignatureFailureV3::Refused); }
    *resident = Some((|| {
        controller.recheck()?;
        source.recheck()?;
        if generation == 0 || source.project() != controller.acceptance().project()
            || source.source_uid() != original.first_successor_source_uid()?
        { return Err(SourceGenesisErrorV1::Stale); }
        let kind = if complete {
            controller.recheck_completed_project_genesis_v3(source)?;
            3
        } else if let Some(receipt) = source.receipt() {
            if receipt.acceptance_digest() != controller.acceptance().digest()
                || &receipt.seed_packet() != controller.acceptance().seed_packet()
                || &receipt.auth_packet() != controller.acceptance().auth_packet()
            { return Err(SourceGenesisErrorV1::Stale); }
            1
        } else {
            if source.state() != SourceTreeGenesisStateV1::VacantProject || source.instance().is_none() {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            controller.recheck_current_admission()?;
            2
        };
        let mut packet = [0; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1];
        packet[..8].copy_from_slice(PROJECT_MAGIC_V3);
        packet[8..10].copy_from_slice(&3_u16.to_be_bytes());
        packet[10] = kind;
        packet[16..24].copy_from_slice(&generation.to_be_bytes());
        packet[24..28].copy_from_slice(&controller.uid().to_be_bytes());
        packet[28..32].copy_from_slice(&source.source_uid().to_be_bytes());
        packet[32..40].copy_from_slice(&controller.snapshot_sequence()?.to_be_bytes());
        packet[40..48].copy_from_slice(&source.snapshot_sequence().to_be_bytes());
        packet[48..64].copy_from_slice(&original.nonce());
        packet[64..672].copy_from_slice(controller.acceptance().record_bytes());
        packet[672..720].copy_from_slice(&controller.names().to_bytes());
        packet[720..768].copy_from_slice(&source.names().to_bytes());
        packet[768..800].copy_from_slice(&source.instance().ok_or(SourceGenesisErrorV1::Stale)?);
        let preimage = [PROJECT_DOMAIN_V3, &packet[..BODY_BYTES]].concat();
        // Slow owner work follows preparation, then this final genuine pair is
        // sampled immediately before the existing real-key crypto operation.
        controller.recheck()?;
        source.recheck()?;
        if kind == 2 { controller.recheck_current_admission()?; }
        original.first_successor_clock()?;
        Ok(finish_readback(packet, preimage, key))
    })());
    let mut first = resident.as_ref().is_some_and(Result::is_err).then_some(ProjectGenesisSignatureFailureV3::Signature);
    posts.push(controller.recheck());
    if first.is_none() && posts.last().is_some_and(Result::is_err) { first = Some(ProjectGenesisSignatureFailureV3::Post(posts.len() - 1)); }
    posts.push(source.recheck());
    if first.is_none() && posts.last().is_some_and(Result::is_err) { first = Some(ProjectGenesisSignatureFailureV3::Post(posts.len() - 1)); }
    posts.push(original.first_successor_clock().map(|_| ()));
    if first.is_none() && posts.last().is_some_and(Result::is_err) { first = Some(ProjectGenesisSignatureFailureV3::Post(posts.len() - 1)); }
    posts.push(original.observe_first_successor_clock().map(|_| ()));
    if first.is_none() && posts.last().is_some_and(Result::is_err) { first = Some(ProjectGenesisSignatureFailureV3::Post(posts.len() - 1)); }
    match first { Some(site) => Err(site), None => Ok(()) }
}

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
    let kind = prepare_current_readback_kind(controller, source, nonce, generation)?;
    sign_readback(controller, source, nonce, generation, key, kind)
}

fn prepare_current_readback_kind(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    nonce: [u8; 16],
    generation: u64,
) -> Result<u8, SourceGenesisErrorV1> {
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
    Ok(kind)
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
    let packet = prepare_readback(controller, source, nonce, generation, kind)?;
    let preimage = [DOMAIN, &packet[..BODY_BYTES]].concat();
    let packet = finish_readback(packet, preimage, key);
    recheck_readback(controller, source, kind)?;
    Ok(packet)
}

fn prepare_readback(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    nonce: [u8; 16],
    generation: u64,
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
    Ok(packet)
}

fn finish_readback(
    mut packet: [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1],
    preimage: Vec<u8>,
    key: &SigningKey,
) -> [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1] {
    let signature = key.sign(&preimage);
    // Preserve the original temporary's destruction before packet copying.
    drop(preimage);
    packet[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    packet
}

fn recheck_readback(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    kind: u8,
) -> Result<(), SourceGenesisErrorV1> {
    controller.recheck()?;
    source.recheck()?;
    if kind == 3 {
        controller.recheck_completed_source_ack(source)?;
    } else if kind != 1 {
        controller.recheck_current_admission()?;
    }
    Ok(())
}

// These fixed entries use the same kind, body and postcheck engines, but
// retain the actual signature before those postchecks can fail.
#[allow(clippy::too_many_arguments)]
pub(super) fn capture_q04_prepare_readback_v1(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    generation: u64,
    key: &SigningKey,
    original: &super::flight::OriginalRootGenesisFlightV1<'_>,
    resident: &mut Option<Result<
        [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1],
        SourceGenesisErrorV1,
    >>,
    first: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
    debt: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    require_q04_capture_vacant(resident, first, debt)?;
    let kind = prepare_current_readback_kind(
        controller, source, original.nonce(), generation,
    );
    capture_q04_readback(
        controller, source, generation, key, original, resident, first, debt, kind,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn capture_q04_complete_readback_v1(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    generation: u64,
    key: &SigningKey,
    original: &super::flight::OriginalRootGenesisFlightV1<'_>,
    resident: &mut Option<Result<
        [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1],
        SourceGenesisErrorV1,
    >>,
    first: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
    debt: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    require_q04_capture_vacant(resident, first, debt)?;
    let kind = controller.recheck_completed_source_ack(source).map(|()| 3);
    capture_q04_readback(
        controller, source, generation, key, original, resident, first, debt, kind,
    )
}

fn require_q04_capture_vacant(
    resident: &Option<Result<
        [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1],
        SourceGenesisErrorV1,
    >>,
    first: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
    debt: &Option<super::super::create_q04::CreateQ04ErrorV1>,
) -> Result<(), ()> {
    if resident.is_some() || first.is_some() || debt.is_some() {
        if first.is_none() && debt.is_none() {
            *first = Some(super::super::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        return Err(());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn capture_q04_readback(
    controller: &HeldControllerSourceGenesisV1<'_>,
    source: &HeldSourceTreeGenesisObservationV1<'_>,
    generation: u64,
    key: &SigningKey,
    original: &super::flight::OriginalRootGenesisFlightV1<'_>,
    resident: &mut Option<Result<
        [u8; CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1],
        SourceGenesisErrorV1,
    >>,
    first: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
    debt: &mut Option<super::super::create_q04::CreateQ04ErrorV1>,
    kind: Result<u8, SourceGenesisErrorV1>,
) -> Result<(), ()> {
    let mut observed_kind = None;
    *resident = Some((|| {
        let kind = kind?;
        observed_kind = Some(kind);
        let packet = prepare_readback(
            controller, source, original.nonce(), generation, kind,
        )?;
        let preimage = [DOMAIN, &packet[..BODY_BYTES]].concat();

        original.require_q04_signing_boundary()?;
        Ok(finish_readback(packet, preimage, key))
    })());

    // Move an actual error once; a successful signature never leaves its slot
    // on failure. No postcheck can replace or manufacture that original result.
    if matches!(resident, Some(Err(_))) {
        match resident.take() {
            Some(Err(error)) => { *first = Some(error.into()); }
            returned => { *resident = returned; }
        }
    }
    if let Some(kind) = observed_kind {
        if let Err(error) = recheck_readback(controller, source, kind) {
            debt.get_or_insert(error.into());
        }
    }
    if first.is_some() || debt.is_some() {
        Err(())
    } else {
        Ok(())
    }
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
    verify_with_recipe(packet, pin, nonce, controller_uid, source_uid, ControllerGenesisReadbackRecipeV3::StrictV1)
}

pub(super) fn verify_project_genesis_v3(
    packet: &[u8], pin: &PinnedControllerHoldSignerV1, nonce: [u8; 16],
    controller_uid: u32, source_uid: u32,
) -> Result<VerifiedControllerSourceGenesisReadbackV1, SourceGenesisErrorV1> {
    verify_with_recipe(packet, pin, nonce, controller_uid, source_uid, ControllerGenesisReadbackRecipeV3::ProjectV3)
}

fn verify_with_recipe(
    packet: &[u8], pin: &PinnedControllerHoldSignerV1, nonce: [u8; 16],
    controller_uid: u32, source_uid: u32, recipe: ControllerGenesisReadbackRecipeV3,
) -> Result<VerifiedControllerSourceGenesisReadbackV1, SourceGenesisErrorV1> {
    let (magic, version, domain) = match recipe {
        ControllerGenesisReadbackRecipeV3::StrictV1 => (MAGIC, 1_u16, DOMAIN),
        ControllerGenesisReadbackRecipeV3::ProjectV3 => (PROJECT_MAGIC_V3, 3_u16, PROJECT_DOMAIN_V3),
    };
    if packet.len() != CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1
        || packet.get(..8) != Some(magic.as_slice())
        || packet[8..10] != version.to_be_bytes()
        || packet[10] > 3
        || matches!(recipe, ControllerGenesisReadbackRecipeV3::ProjectV3) && packet[10] == 0
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
            &[domain, &packet[..BODY_BYTES]].concat(),
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
