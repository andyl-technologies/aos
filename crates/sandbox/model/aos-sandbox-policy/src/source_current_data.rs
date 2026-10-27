//! Authenticates Source reply bytes and compares their captured time interval.
//!
//! These routines operate only on protocol DATA and a supplied public key.
//! Genuine consumers retain their own current pin, original query, native
//! transport and independent clock/peer custody. Success constructs no owner,
//! signed reply, append gate, receiving admission or live Source capability.

use std::mem::size_of;

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    source_current::{
        SourceCurrentReplyFieldsV1, SOURCE_CURRENT_BODY_BYTES_V1,
        SOURCE_CURRENT_REPLY_FRAME_BYTES_V1, SOURCE_CURRENT_SIGNATURE_DOMAIN_V1,
    },
};
use ed25519_dalek::{Signature, SignatureError, VerifyingKey};

/// Verifies the exact existing Source reply signature under a supplied key.
///
/// The supplied key and reply bytes are DATA. A genuine native consumer must
/// derive its key from its own independent current pin and check its actual
/// query, clocks and owed posts before using the result.
///
/// # Errors
/// Retains the signature verifier's error for altered bytes or a foreign key.
pub fn verify_source_current_signature_data_v1(
    frame: &[u8; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1],
    signature: [u8; 64],
    key: &VerifyingKey,
) -> Result<(), SignatureError> {
    let mut message = [0; SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len() + SOURCE_CURRENT_BODY_BYTES_V1];
    message[..SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()]
        .copy_from_slice(SOURCE_CURRENT_SIGNATURE_DOMAIN_V1);
    message[SOURCE_CURRENT_SIGNATURE_DOMAIN_V1.len()..]
        .copy_from_slice(&frame[8..8 + SOURCE_CURRENT_BODY_BYTES_V1]);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
}

/// Compares reply DATA with two original captured clock samples.
///
/// This comparison performs no sampling and grants no currentness. Native
/// consumers must obtain both samples from their genuine same-owner attempts.
///
/// # Errors
/// Reports correlation refusal for another boot, an invalid sample ordering or
/// reply time outside either closed interval.
pub fn require_source_current_interval_data_v1(
    before: &RawPairedClockSample,
    after: &RawPairedClockSample,
    reply: &SourceCurrentReplyFieldsV1,
) -> Result<(), HistoryErrorV1> {
    before.validate_later_sample(*after).map_err(|_| HistoryErrorV1::Correlation)?;
    if reply.boot != before.host_boot_id() || reply.boot != after.host_boot_id()
        || reply.boottime_nanoseconds < before.boottime_nanoseconds()
        || reply.boottime_nanoseconds > after.boottime_nanoseconds()
        || reply.wall_seconds < before.wall_seconds() || reply.wall_seconds > after.wall_seconds()
    {
        return Err(HistoryErrorV1::Correlation);
    }
    Ok(())
}

/// Measures the new concrete DATA call interfaces without decoder backing.
///
/// Actual native consumers add this Memory-only amount before entering their
/// real exchange Stage. It supplies no resource allowance or proof of admission.
#[must_use]
pub fn additional_control_bytes_v1() -> Option<usize> {
    size_of::<(&[u8; SOURCE_CURRENT_REPLY_FRAME_BYTES_V1], [u8; 64], &VerifyingKey)>()
        .checked_mul(3)?
        .checked_add(size_of::<Result<(), SignatureError>>().checked_mul(3)?)?
        .checked_add(size_of::<&VerifyingKey>().checked_mul(3)?)?
        .checked_add(size_of::<(&RawPairedClockSample, &RawPairedClockSample,
            &SourceCurrentReplyFieldsV1)>().checked_mul(3)?)?
        .checked_add(size_of::<Result<(), HistoryErrorV1>>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
}
