//! Quotes the fixed schema factories invoked by historical native5 verification.
//!
//! Each factory's actual borrowed schema drives its allocation-free counter.
//! Completed SchemaRefs coexist while the selected Vec is assembled, but full
//! schema DOM/canonical banks are sequential. Owner identity and dynamic
//! provider/realization validation remain the enclosing helper's separate work.

use crate::ProviderError;
use crate::reference_packet::service::{
    complete_restore::{
        PACKET_COMPLETE_RESTORE_FEATURE, PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION, PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        canonical_restore_inputs_contract_storage_data, complete_restore_contract_storage_data,
        input_emitter::PACKET_CANONICAL_RESTORE_INPUTS_FEATURE,
        native_restored_record_contract_storage_data,
        transfer::{
            PacketCompleteRestoreTransferPhase, complete_restore_transfer_contract_storage_data,
        },
    },
    native_snapshot::{SCHEMA, native_owned11_snapshot_contract_storage_data},
};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use crucible_node_format::SchemaRef;
use std::mem::size_of;

/// Quotes the closed maximal schema-factory phase without creating any schema.
///
/// Transfer12 retains the original three restore schemas, six phase schemas,
/// restored-record schema and Owned11 snapshot schema. Owned11 selects a subset.
/// The optional canonical-input schema is constructed after that Vec is dropped;
/// its independent factory peak is compared rather than added as simultaneous.
/// This bound covers both finite enum cases without trusting Source selection.
///
/// # Errors
/// Refuses insufficient independent construction credit or checked layout overflow.
pub(super) fn native5_record_schema_factory_peak_data(
    maximum: usize,
) -> Result<usize, ProviderError> {
    let factory_peak = [
        factory_work(complete_restore_contract_storage_data(maximum)?)?,
        factory_work(complete_restore_transfer_contract_storage_data(maximum)?)?,
        factory_work(native_restored_record_contract_storage_data(maximum)?)?,
        factory_work(native_owned11_snapshot_contract_storage_data(maximum)?)?,
    ]
    .into_iter()
    .max()
    .ok_or_else(invalid)?;
    let ids = selected_schema_ids();
    let schema_backing = ids.iter().try_fold(0usize, |bytes, id| {
        bytes.checked_add(schema_strings(id)?).ok_or_else(invalid)
    })?;

    // The defining vec![three schemas] starts at capacity3. Subsequent pushes
    // request6 then12 SchemaRef slots on the pinned allocator implementation.
    // Summing requests also covers an old bank during a growing reallocation.
    let mut capacity = 3usize;
    let mut vector_requests = capacity;
    while capacity < ids.len() {
        capacity = capacity.checked_mul(2).ok_or_else(invalid)?;
        vector_requests = vector_requests.checked_add(capacity).ok_or_else(invalid)?;
    }
    std::alloc::Layout::array::<SchemaRef>(capacity).map_err(|_| invalid())?;
    let selected_peak = vector_requests
        .checked_mul(size_of::<SchemaRef>())
        .and_then(|bytes| bytes.checked_add(schema_backing))
        .and_then(|bytes| bytes.checked_add(factory_peak))
        .ok_or_else(invalid)?;

    let input_peak = factory_work(canonical_restore_inputs_contract_storage_data(maximum)?)?
        .checked_add(schema_strings(PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)?)
        .ok_or_else(invalid)?;
    let peak = selected_peak.max(input_peak);
    if peak > maximum {
        return Err(invalid());
    }
    Ok(peak)
}

fn factory_work(quote: OriginalSerializationStorageData) -> Result<usize, ProviderError> {
    // These factories serialize their compiled roster directly to Value, then
    // canonical bytes. They run no JSON parser. Counter headers belong to the
    // separate fixed scratch getter, never to an encoded-byte allowance.
    quote
        .dom_and_canonical_scratch_bytes
        .checked_add(quote.canonical_output_requested_bytes)
        .and_then(|bytes| bytes.checked_add(quote.serializer_temporary_requested_bytes))
        .ok_or_else(invalid)
}

fn selected_schema_ids() -> [&'static str; 11] {
    use PacketCompleteRestoreTransferPhase::{Commit, Prepare};

    [
        PACKET_COMPLETE_RESTORE_FEATURE,
        PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        Prepare.request_extension(),
        Prepare.proof_extension(),
        Prepare.receipt_extension(),
        Commit.request_extension(),
        Commit.proof_extension(),
        Commit.receipt_extension(),
        PACKET_NATIVE_RESTORED_RECORD_FEATURE,
        SCHEMA,
    ]
}

fn schema_strings(id: &str) -> Result<usize, ProviderError> {
    // A SchemaRef owns its Id, definition HashRef's three Strings and media type.
    // The digest is the defining BLAKE3 hexadecimal output. No definition bytes
    // remain in the returned SchemaRef and its Extensions map is empty.
    let strings = id
        .len()
        .checked_add("blake3-256".len())
        .and_then(|bytes| bytes.checked_add("cnp.blob.v1".len()))
        .and_then(|bytes| bytes.checked_add(2 * blake3::OUT_LEN))
        .and_then(|bytes| bytes.checked_add("application/json".len()))
        .ok_or_else(invalid)?;
    // Includes cumulative String growth and each of the five minimum banks.
    strings
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(5 * 8))
        .ok_or_else(invalid)
}

/// Names only concrete fixed visitor/factory/roster headers, not compiler frames.
pub(super) fn counter_scratch_data() -> usize {
    crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
        + 2 * size_of::<OriginalSerializationStorageData>()
        + size_of::<[&str; 11]>()
        + size_of::<[usize; 4]>()
        + size_of::<[SchemaRef; 3]>()
        + size_of::<SchemaRef>()
        + size_of::<Vec<SchemaRef>>()
        + size_of::<std::vec::IntoIter<SchemaRef>>()
        + size_of::<Result<usize, ProviderError>>()
        + 10 * size_of::<usize>()
}

fn invalid() -> ProviderError {
    ProviderError::ResourceExhausted("historical native5 schema construction")
}
