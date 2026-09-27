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

use ed25519_dalek::{Signature, Signer as _, SigningKey};

use crate::controller_service::journal::production_journal_limits;
use crate::journal::{Journal, RecordNamespace};

use super::binding_v2::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};
use super::controller_effect_ack_readback::{
    ControllerEffectAckChallengeV1, ControllerEffectAckReadbackErrorV1,
};
use super::controller_effect_ack_readback_v8::require_current_ack;
use super::controller_hold_readback::PinnedControllerHoldSignerV1;

const MAGIC: &[u8; 8] = b"AOSCTR08";
const SIGNATURE_DOMAIN: &[u8] =
    b"aos.sandbox.controller-policy-v8-root-receipt.readback.v1\0/var/lib/aos/sandboxd/controller.journal\0";
const BODY_BYTES: usize = 84 + ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1;

/// Bounds one signed Controller V8 Root receipt.
pub const CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1: usize = BODY_BYTES + 64;

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
    if bytes.len() != CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1
        || bytes[..8] != MAGIC[..]
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[16..24] != signer.generation().to_be_bytes()
        || bytes[24..40] != challenge.nonce()
        || bytes[40..72] != *challenge.cut().as_bytes()
        || bytes[72..76] != expected_uid.to_be_bytes()
        || expected_uid == 0
        || bytes[76..84] == [0; 8]
    {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let receipt = RootV8EffectAckV1::from_record_bytes(&bytes[84..BODY_BYTES])
        .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?;
    let signature = Signature::from_bytes(
        &bytes[BODY_BYTES..]
            .try_into()
            .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?,
    );
    signer
        .verifying_key()
        .verify_strict(
            &[SIGNATURE_DOMAIN, &bytes[..BODY_BYTES]].concat(),
            &signature,
        )
        .map_err(|_| ControllerEffectAckReadbackErrorV1::Signature)?;
    Ok(receipt)
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
    if uid == 0 || sequence == 0 || generation == 0 {
        return Err(ControllerEffectAckReadbackErrorV1::Stale);
    }
    let mut bytes = [0; CONTROLLER_V8_ROOT_RECEIPT_READBACK_BYTES_V1];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..24].copy_from_slice(&generation.to_be_bytes());
    bytes[24..40].copy_from_slice(&challenge.nonce());
    bytes[40..72].copy_from_slice(challenge.cut().as_bytes());
    bytes[72..76].copy_from_slice(&uid.to_be_bytes());
    bytes[76..84].copy_from_slice(&sequence.to_be_bytes());
    bytes[84..BODY_BYTES].copy_from_slice(
        &receipt
            .record_bytes()
            .map_err(|_| ControllerEffectAckReadbackErrorV1::Stale)?,
    );
    let signature = key.sign(&[SIGNATURE_DOMAIN, &bytes[..BODY_BYTES]].concat());
    bytes[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
    Ok(bytes)
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
