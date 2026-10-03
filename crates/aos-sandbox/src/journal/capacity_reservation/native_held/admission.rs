//! Native-specific atomic DATA joins with the actual old dispatch reservation.
//!
//! SourceLedger independently validates complete canonical Applying/Attempt/
//! Session/Requested graphs. This adapter compares that proposal's exported
//! original bindings with the exact old namespace-46 record; it cannot replace
//! the Source graph validator or supply original protected admission provenance.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityV1, native_export_fence::native_dispatch_backend_identity_v2,
};
use sha2::{Digest as _, Sha256};

use super::super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    validate_transaction,
};
use super::super::{GlobalCapacityReservationPurposeV1, decode_capacity_reservation_request_v1};
use super::{
    NativeHeldCapacityAppendV3, NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3,
    NativeHeldCapacitySuffixV3, invalid,
};

const DISPATCH_OWNER_DOMAIN: &[u8] =
    b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0";
// This is the unchanged old six-row owner bound plus the exact one-shot
// capacity deletion and Begin/Commit/record framing, not a new held bound.
const LEGACY_DISPATCH_OWNER_BYTES: u64 = 3_677_574;
const LEGACY_DISPATCH_FLOOR_BYTES: u64 = LEGACY_DISPATCH_OWNER_BYTES + 7 + 72 + 72 * 9 + 40;

/// Carries actual admission comparison fields exported by Source's pure reducer.
///
/// Fields are plain DATA, not an admission token. Before effects, the original
/// Source owner must obtain them from its exact canonical graph reducer and
/// jointly validate the actual old reservation under its retained writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldProviderAdmissionDataV3 {
    /// Original full Provider authority, not an ambient process credential.
    pub provider: SourceProviderAuthorityV1,
    /// Original full holder authority, not a successor session's holder.
    pub holder: SourceProviderAuthorityV1,
    /// Original acquisition identity from the Applying row.
    pub acquisition_id: ObjectDigest,
    /// Original effect operation ID from that same Applying row.
    pub operation_id: [u8; 16],
    /// Digest of the canonical original Applying acquisition before Requested.
    pub reservation_acquisition_digest: ObjectDigest,
    /// Exact original immutable attempt commitment.
    pub attempt_digest: ObjectDigest,
    /// Exact signed original Root request commitment.
    pub root_request_digest: ObjectDigest,
    /// Exact original pending session binding.
    pub session_binding: ObjectDigest,
    /// Exact original signed Provider-to-Storage native request commitment.
    pub native_request_digest: ObjectDigest,
    /// Exact retained signed RootPrepared1 commitment.
    pub root_prepared_digest: ObjectDigest,
    /// Original catalog generation, never a freshly recaptured successor.
    pub catalog_generation: u64,
    /// Exact original catalog head commitment.
    pub catalog_digest: ObjectDigest,
    /// Exact original normalized intent used to derive the dispatch backend.
    pub normalized_intent_digest: ObjectDigest,
    /// Exact original resource namespace commitment.
    pub resource_namespace_digest: ObjectDigest,
    /// Actual dispatch-domain backend identity, never the no-dispatch domain.
    pub backend_id: [u8; 32],
    /// Original AcquirePlan lineage already checked by Source's graph reducer.
    pub backend_lineage_digest: ObjectDigest,
    /// Exact canonical Requested mutation key from that reducer.
    pub requested_key: Vec<u8>,
    /// Exact canonical Requested after-value; Source validates its full codec.
    pub requested_value: Vec<u8>,
}

/// Derives the one atomic old-dispatch-delete, native9-put, Requested transaction.
///
/// The result is an ordinary [`JournalTransaction`], not a preflight token or
/// permission to commit. Existing generic protected routes explicitly reject
/// native capacity. No original-V3 no-dispatch operation is convertible here.
///
/// # Errors
///
/// Rejects a foreign/changed old floor, no-dispatch identity or five-row budget,
/// mismatched original bindings, a late/smaller floor, malformed Requested key,
/// changed transaction/admission ID, or the unchanged journal transaction limits.
pub fn provider_native_capacity_admission_v3(
    data: &NativeHeldProviderAdmissionDataV3,
    old_capacity: &JournalRecord,
    native_capacity: &NativeHeldCapacityRecordV3,
    transaction_id: [u8; 16],
    limits: JournalLimits,
) -> Result<JournalTransaction, JournalError> {
    let (old, _, _) = decode_capacity_reservation_request_v1(old_capacity)?;
    let new = native_capacity.request();
    let mut owner = Sha256::new();
    owner.update(DISPATCH_OWNER_DOMAIN);
    owner.update(data.provider.authority_id());
    owner.update(data.holder.authority_id());
    owner.update(data.acquisition_id.as_bytes());
    let owner_id: [u8; 32] = owner.finalize().into();
    let backend = native_dispatch_backend_identity_v2(
        data.normalized_intent_digest,
        data.catalog_generation,
        data.catalog_digest,
        data.attempt_digest,
    );
    let mut native_key = b"AOSNCK02".to_vec();
    native_key.extend_from_slice(data.acquisition_id.as_bytes());

    let original_digests = [
        data.acquisition_id,
        data.reservation_acquisition_digest,
        data.attempt_digest,
        data.root_request_digest,
        data.session_binding,
        data.native_request_digest,
        data.root_prepared_digest,
        data.catalog_digest,
        data.normalized_intent_digest,
        data.resource_namespace_digest,
        data.backend_lineage_digest,
    ];
    if original_digests
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
        || data.operation_id == [0; 16]
        || data.catalog_generation == 0
        || data.backend_id != backend
        || data.backend_id == [0; 32]
        || data.requested_key != native_key
        || data.requested_value.is_empty()
        || old.purpose != GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
        || old.owner_namespace != RecordNamespace::SourceProviderAuthority
        || old.owner_id != owner_id
        || old.owner_digest != *data.reservation_acquisition_digest.as_bytes()
        || old.operation_id != data.operation_id
        || old.artifact_digest != *data.attempt_digest.as_bytes()
        || old.checkpoint_digest != *data.root_request_digest.as_bytes()
        || old.chain_head_digest != *data.session_binding.as_bytes()
        || old.future_transactions != 1
        || old.terminal_records != 7
        || old.poison_records != 7
        || old.terminal_bytes != LEGACY_DISPATCH_FLOOR_BYTES
        || old.poison_bytes != LEGACY_DISPATCH_FLOOR_BYTES
        || new.purpose != NativeHeldCapacityPurposeV3::Provider
        || new.owner_id != owner_id
        || new.owner_digest != old.owner_digest
        || new.operation_id != data.operation_id
        || new.artifact_digest != *data.native_request_digest.as_bytes()
        || new.checkpoint_digest != *data.root_prepared_digest.as_bytes()
        || new.chain_head_digest != *data.catalog_digest.as_bytes()
        || new.future_transactions != 19
        || new.terminal_records < old.terminal_records
        || new.poison_records < old.poison_records
        || new.terminal_bytes < old.terminal_bytes
        || new.poison_bytes < old.poison_bytes
        || native_capacity.admission_transaction_id() != transaction_id
    {
        return Err(invalid(
            "native Provider admission does not join original dispatch floor",
        ));
    }
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                old_capacity.key().to_vec(),
            ),
            native_capacity.to_journal_record(),
            JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                data.requested_key.clone(),
                data.requested_value.clone(),
            ),
        ],
    )?;
    validate_transaction(&transaction, limits)?;
    Ok(transaction)
}

/// Frames one Provider DATA append with its complete measured successor floor.
///
/// The actual Source owner must derive both the current append and every
/// remaining continuation from its checked original graph. Cleanup remains a
/// distinct final append; Root's terminal proof alone cannot remove this floor.
/// No protected transfer, original admission, currentness or effect is granted.
///
/// # Errors
///
/// Rejects a foreign append/old floor, missing or enlarged continuation, count
/// exhaustion, premature deletion, or an unchanged journal ceiling violation.
pub fn provider_native_capacity_transition_v3(
    append: &NativeHeldCapacityAppendV3,
    old: &NativeHeldCapacityRecordV3,
    remaining: Option<(&NativeHeldCapacitySuffixV3, &NativeHeldCapacitySuffixV3)>,
    limits: JournalLimits,
) -> Result<(JournalTransaction, Option<NativeHeldCapacityRecordV3>), JournalError> {
    if append.purpose() != NativeHeldCapacityPurposeV3::Provider
        || old.request().purpose != NativeHeldCapacityPurposeV3::Provider
        || (append.is_cleanup() && (remaining.is_some() || old.request().future_transactions != 1))
        || (!append.is_cleanup() && remaining.is_none())
    {
        return Err(invalid("native Provider continuation or cleanup floor"));
    }
    let next = remaining
        .map(|(normal, cold)| {
            NativeHeldCapacityRecordV3::from_suffixes(
                old.request(),
                old.admission_transaction_id(),
                normal,
                cold,
                limits,
            )
        })
        .transpose()?;
    if next
        .as_ref()
        .is_some_and(|next| next.request().future_transactions >= old.request().future_transactions)
    {
        return Err(invalid(
            "native Provider continuation count did not decrease",
        ));
    }
    let transaction = super::transfer::frame_transfer(
        append.transaction_id(),
        append.owner_records(),
        old,
        next.as_ref(),
        limits,
        (
            "native Provider consumed records",
            "native Provider complete transferred suffix",
        ),
    )?;
    Ok((transaction, next))
}

#[cfg(test)]
mod tests;
