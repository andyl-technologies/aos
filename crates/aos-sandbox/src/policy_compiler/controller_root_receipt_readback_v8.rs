//! Controller-signed readback of its durable V8 Root receipt.
//!
//! ```text
//! AOSCTR08 | version:u16=1 | reserved[6]=0 | signer-generation:u64 |
//! Root-nonce[16] | Root-cut[32] | Controller-UID:u32 |
//! journal-sequence:u64 | canonical AOSPC88A[332] | Ed25519[64]
//! ```
//!
//! This packet is distinct from the earlier AOSCTE08 effect ACK. Root checks
//! it while retaining its journal writer; it grants no release by itself.

use std::path::Path;

use ed25519_dalek::SigningKey;

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{Journal, RecordNamespace};

use super::binding_v2::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};
use super::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use super::controller_effect_ack_readback_v8::require_current_ack;
use super::controller_hold_readback::PinnedControllerHoldSignerV1;
use super::controller_v8_readback_envelope::{
    ControllerV8ReadbackProtocol, HEADER_BYTES, SIGNATURE_BYTES, sign_packet, verify_packet,
};

const BODY_BYTES: usize = HEADER_BYTES + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1;

/// Bounds one signed Controller V8 Root receipt.
pub const CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1: usize = BODY_BYTES + SIGNATURE_BYTES;

/// Signs the exact durable Root receipt under the retained Controller writer.
///
/// # Errors
///
/// Rejects an unsafe Controller journal location, changed V8 custody,
/// missing receipt, or invalid signer generation.
pub fn sign_fixed_controller_v8_root_receipt_readback_v1(
    journal: &mut Journal,
    challenge: ControllerEffectAckChallengeV1,
    signer_generation: u64,
    signing_key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1>
{
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
) -> Result<[u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1>
{
    if uid == 0 || generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    journal.require_protected_named_location(
        directory,
        "controller.journal",
        uid,
        production_journal_limits(),
    )?;
    let receipt = current_receipt(journal)?;
    let snapshot = journal
        .claim_protected_authority(RecordNamespace::ControllerPolicyHold)?
        .snapshot()?;
    let packet = sign_fields(
        receipt,
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
    if current_receipt(journal)? != receipt {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(packet)
}

fn current_receipt(
    journal: &mut Journal,
) -> Result<RootV8EffectAckV1, ControllerEffectAckReadbackErrorV1> {
    let receipt = journal
        .controller_policy_v8_root_receipt_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    let ack = journal
        .controller_policy_v8_effect_ack_v1()?
        .ok_or(ControllerEffectAckReadbackErrorV1::Stale)?;
    require_current_ack(journal, ack)?;
    if receipt.controller_ack() != ack.record_digest()? {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    Ok(receipt)
}

/// Verifies a Controller-signed receipt for one fresh Root challenge.
///
/// The caller must compare the returned receipt to the exact protected Root
/// ACK under its journal writer.
///
/// # Errors
///
/// Rejects a foreign signer, stale nonce, cut or UID, malformed receipt, or
/// invalid signature.
pub fn verify_controller_v8_root_receipt_readback_v1(
    bytes: &[u8],
    signer: &PinnedControllerHoldSignerV1,
    challenge: ControllerEffectAckChallengeV1,
    expected_uid: u32,
) -> Result<RootV8EffectAckV1, ControllerEffectAckReadbackErrorV1> {
    let record = verify_packet(
        ControllerV8ReadbackProtocol::RootReceipt,
        bytes,
        signer,
        challenge,
        expected_uid,
    )?;
    RootV8EffectAckV1::from_record_bytes(record)
        .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)
}

fn sign_fields(
    receipt: RootV8EffectAckV1,
    uid: u32,
    sequence: u64,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1>
{
    sign_packet(
        ControllerV8ReadbackProtocol::RootReceipt,
        &receipt
            .record_bytes()
            .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?,
        uid,
        sequence,
        challenge,
        generation,
        key,
    )
}

#[cfg(test)]
pub(crate) fn sign_test_controller_v8_root_receipt_readback_v1(
    receipt: RootV8EffectAckV1,
    uid: u32,
    challenge: ControllerEffectAckChallengeV1,
    generation: u64,
    key: &SigningKey,
) -> Result<[u8; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1], ControllerEffectAckReadbackErrorV1>
{
    sign_fields(receipt, uid, 7, challenge, generation, key)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    #[test]
    fn current_root_receipt_requires_durable_row() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        assert_ne!(uid, 0);
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "controller.journal",
            production_journal_limits(),
            uid,
        )
        .unwrap();
        assert!(matches!(
            current_receipt(&mut journal),
            Err(ControllerEffectAckReadbackErrorV1::Stale)
        ));
    }
}
