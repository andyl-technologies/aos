//! Quotes actual output-pair DTO, model, proof and canonical construction work.
//!
//! These walks borrow the already decoded graph pair and genuine SDK originals.
//! They do not use a postsealed Source-history row or turn scalar limits into
//! heap demand. Formatter quote work is admitted before invoking Serialize.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, actual_serialization_storage_data,
};
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, RetainedProtocolMetadataFacts};
use crucible_node_format::Id;
use std::mem::size_of;

/// Quotes the two real Controller membership comparisons before raw retention.
pub(in super::super) fn sdk_correspondence_data(
    sdk: &crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSettledCapture17,
    controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let parts = controller.parts_data()?.as_object().ok_or_else(invalid)?;
    let journal = parts
        .get("custody")
        .and_then(serde_json::Value::as_array)
        .and_then(|tuple| tuple.get(3))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    let capture = sdk.capture_pair_data();
    let confirmation = sdk.confirmation_pair_data();
    let mut total = 0usize;
    for (original, terminal) in [(capture.0, capture.1), (confirmation.0, confirmation.1)] {
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let identity = journal
            .get(id.as_str())
            .and_then(serde_json::Value::as_object)
            .and_then(|entry| entry.get("identity"))
            .ok_or_else(invalid)?;
        let identity = actual_serialization_storage_data(identity, Default::default(), maximum)?;
        // The comparison holds request and response Values while computing the
        // original's normative hash; read<HashRef> owns its independent clone.
        total = sum(&[
            total,
            value_work(original, maximum)?,
            value_work(terminal, maximum)?,
            value_work(original, maximum)?,
            serialization_work(&identity)?,
            identity.projected_parser_requested_bytes,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
        ])?;
    }
    if total > maximum {
        return Err(invalid());
    }
    Ok(total)
}

pub(in super::super) fn formatter_data(
    before: &NativeCurrentGraph17Data,
    sdk: &OutputPairSdk17Data<'_>,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(before.current_capture_artifact17_data()?)?;
    observer.observe(before.current_capture_context17_data()?)?;
    observer.observe(sdk.capture_original)?;
    observer.observe(sdk.capture_terminal)?;
    observer.observe(sdk.confirmation_original)?;
    observer.observe(sdk.confirmation_request)?;
    let (_, arguments, begin) = before.current_capture_registration17_data()?;
    observer.observe(arguments)?;
    observer.observe(begin)?;
    observer.observe(owner(before)?)?;
    before
        .current_model17_data()?
        .observe_settled_history_metadata_data(&mut observer)?;
    Ok(observer
        .ordinary_bytes_formatter_data()
        .maximum_temporary_requested_bytes_data()?
        .max(20))
}

pub(in super::super) fn quote_data(
    before: &NativeCurrentGraph17Data,
    sdk: &OutputPairSdk17Data<'_>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let (_, arguments, begin) = before.current_capture_registration17_data()?;
    let owner = owner(before)?;
    let model = before
        .current_model17_data()?
        .capture_boundary17_construction_data(maximum)?;
    let mut total = sum(&[
        value_work(before.current_capture_artifact17_data()?, maximum)?,
        value_work(before.current_capture_context17_data()?, maximum)?,
        value_work(owner, maximum)?,
        value_work(begin, maximum)?,
        value_work(arguments, maximum)?,
        value_work(sdk.capture_original, maximum)?,
        value_work(sdk.capture_terminal, maximum)?,
        value_work(sdk.confirmation_original, maximum)?,
        value_work(sdk.confirmation_request, maximum)?,
        model,
        super::super::historical_auth::construction::cold_capture17_decode_window_data(
            sdk.capture_original,
            maximum,
        )?,
    ])?;
    // OwnerBinding::validate materializes its actual node roster beside its
    // cloned IDs. The comparison's sorted-key clones are priced by value_work.
    let roster = owner
        .node_bindings
        .len()
        .checked_mul(size_of::<Id>())
        .ok_or_else(invalid)?;
    let id_backing = owner
        .node_bindings
        .iter()
        .try_fold(0usize, |bytes, binding| {
            bytes
                .checked_add(binding.node_id.as_str().len())
                .ok_or_else(invalid)
        })?;
    total = sum(&[total, roster, id_backing])?;
    // These exact hash domains own three returned Strings after their DOM drops.
    // The model has two closed alternatives; both require the same constructor.
    for domain in [
        "cnp.owner-binding.v1",
        "cnp.request.v1",
        "cnp.request.v1",
        "cnp.request.v1",
        PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
        "source-owned.packet-connected-inventory/4",
    ] {
        let strings = "blake3-256"
            .len()
            .checked_add(domain.len())
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or_else(invalid)?;
        total = sum(&[total, strings])?;
    }
    if total > maximum {
        return Err(invalid());
    }
    Ok(total)
}

fn owner(
    before: &NativeCurrentGraph17Data,
) -> Result<&crucible_node_format::OwnerBinding, ProviderError> {
    before
        .current_control_data()
        .selection_data()
        .realization
        .owner_bindings
        .first()
        .ok_or_else(invalid)
}

pub(in super::super) fn held_formatter_data(
    held: &crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(&held.context_digest)?;
    Ok(observer
        .ordinary_bytes_formatter_data()
        .maximum_temporary_requested_bytes_data()?
        .max(20))
}

pub(in super::super) fn held_quote_data(
    held: &crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
    maximum: usize,
) -> Result<usize, ProviderError> {
    // This defining nonrecursive Hold has only one custom Bytes formatter;
    // every other field is borrowed String/Id/fullref/U64/Position or bool.
    let mut observer = MetadataObserver::new();
    observer.observe(&held.context_digest)?;
    let row = actual_serialization_storage_data(held, observer.finish(), maximum)?;
    let strings = "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len();
    let total = serialization_work(&row)?
        .checked_add(strings)
        .ok_or_else(invalid)?;
    if total > maximum {
        return Err(invalid());
    }
    Ok(total)
}

fn value_work<T: Serialize + ObserveMetadata>(
    value: &T,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    let facts = observer.finish();
    let row = actual_serialization_storage_data(value, facts, maximum)?;
    // Sorted Id validation holds two independently cloned keys. Actual typed
    // string backing bounds each key; this is independent of the DOM quote.
    let sorted_keys = facts
        .string_capacity_bytes
        .checked_add(facts.string_capacity_bytes)
        .ok_or_else(invalid)?;
    sum(&[serialization_work(&row)?, sorted_keys])
}

fn serialization_work(row: &OriginalSerializationStorageData) -> Result<usize, ProviderError> {
    sum(&[
        row.dom_and_canonical_scratch_bytes,
        row.canonical_output_requested_bytes,
        row.serializer_temporary_requested_bytes,
    ])
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |bytes, value| {
        bytes.checked_add(*value).ok_or_else(invalid)
    })
}

pub(in super::super) fn counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<crate::bodies::BeginRequest>()
        + size_of::<crate::bodies::CaptureArguments>()
        + size_of::<PacketRestoredSettledCaptureRequest>()
        + size_of::<PacketRestoredSettledCaptureContext>()
        + size_of::<PacketRestoredSettledCaptureArtifact>()
        + size_of::<PacketRestoredSettledAfterConfirmationRequest>()
        + size_of::<Vec<Id>>()
        + size_of::<[usize; 11]>()
        + size_of::<[&'static str; 6]>()
        + size_of::<std::array::IntoIter<&'static str, 6>>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<[(&'static Envelope, &'static Envelope); 2]>()
        + size_of::<std::array::IntoIter<(&'static Envelope, &'static Envelope), 2>>()
        + size_of::<Option<&'static serde_json::Value>>()
        + size_of::<&'static serde_json::Map<String, serde_json::Value>>()
        + size_of::<&'static crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + crate::reference_packet::continuation_models::settled_reader::PacketSettledModel17Data::capture_boundary17_construction_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}
