//! Controller-signed readback of a durable V8 owner settlement.
//!
//! ```text
//! AOSCTS08 envelope | canonical AOSQ8S01[312] | Ed25519[64]
//! ```
//!
//! The signer reads only its retained protected Controller journal. Root
//! compares the returned record with its own ACK, terminal, and release row
//! beneath the Root writer before it can replace a settled predecessor.

use std::path::Path;

use ed25519_dalek::SigningKey;

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{ControllerPolicyV8SettlementV1, Journal, RecordNamespace};

use super::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::controller_v8_readback_envelope::{
    ControllerV8ReadbackProtocol, HEADER_BYTES, SIGNATURE_BYTES, sign_packet, verify_packet,
};

const BODY_BYTES: usize = HEADER_BYTES + 312;

/// Bounds the purpose-separated signed Controller settlement packet.
pub const CONTROLLER_V8_SETTLEMENT_READBACK_BYTES_V1: usize = BODY_BYTES + SIGNATURE_BYTES;

/// Signs the exact current AOSQ8S01 row under Controller writer custody.
///
/// # Errors
///
/// Rejects an absent or inconsistent settlement, unsafe journal name,
/// changed writer snapshot, or invalid Controller signer generation.
pub fn sign_fixed_controller_v8_settlement_readback_v1(
    journal: &mut Journal,
    challenge: ControllerEffectAckChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_SETTLEMENT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    sign_at(
        journal,
        Path::new("/var/lib/aos/sandboxd"),
        rustix::process::getuid().as_raw(),
        challenge,
        signer_generation,
        signing_key,
    )
}

fn sign_at(
    journal: &mut Journal,
    directory: &Path,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_SETTLEMENT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1> {
    if uid == 0 || generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    let settlement = journal
        .controller_policy_v8_settlement_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    require_current_settlement(journal, settlement)?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let packet = sign_packet(
        ControllerV8ReadbackProtocol::Settlement,
        &settlement.record_bytes()?,
        uid,
        snapshot.sequence(),
        challenge,
        generation,
        key,
    )?;

    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .validate_snapshot_for_effect(&snapshot)?;
    require_current_settlement(journal, settlement)?;
    Ok(packet)
}

fn require_current_settlement(
    journal: &mut Journal,
    settlement: ControllerPolicyV8SettlementV1,
) -> Result<(), ControllerEffectAckReadbackErrorV1> {
    let hold = journal
        .controller_policy_hold_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    if hold.is_held()
        || hold.binding() != settlement.binding()
        || hold.epoch() != settlement.epoch()
        || journal.controller_policy_v8_settlement_v1()? != Some(settlement)
        || journal.controller_policy_v8_effect_ack_v1()?.is_none()
        || journal.controller_policy_v8_root_receipt_v1()?.is_none()
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(())
}

/// Verifies the Controller-only signature and canonical settlement row.
///
/// The caller must compare every relevant digest with its protected Root
/// predecessor and retain its own writer through the successor transaction.
///
/// # Errors
///
/// Rejects a foreign signer, challenge, UID, protocol, or malformed row.
pub(crate) fn verify_controller_v8_settlement_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
) -> Result<ControllerPolicyV8SettlementV1, ControllerEffectAckReadbackErrorV1> {
    let record = verify_packet(
        ControllerV8ReadbackProtocol::Settlement,
        bytes,
        signer,
        challenge,
        expected_uid,
    )?;
    Ok(ControllerPolicyV8SettlementV1::from_record_bytes(record)?)
}
