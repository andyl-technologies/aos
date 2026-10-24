//! Composes actual endpoint children with the closed future outer12 grammar.
//!
//! Current Hello/pins/records are borrowed from their actual owners. Only the
//! separately proved future Observe record, Capture fields, Control6 and compact
//! before encoding supply prospective data. No future owner/ref/DOM is created.

use super::*;
use crate::reference_packet::control::{
    NativeObserveControlGrowthData, NativeProjectedCaptureRequestData,
};
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
    closed_event_serialization_storage_data, sum_serialization_storage_data,
};
use crate::retained_metadata::{
    RetainedProtocolMetadataFacts, serialization_storage::OriginalSerializationStorageProjection,
};
use serde::{Serialize, ser::SerializeSeq};

type Projection = OriginalSerializationStorageProjection;

pub(super) struct NativeCaptureOuterProjectionData {
    pub(super) snapshot: NativeSerializationStorageData,
    pub(super) endpoint: NativeSerializationStorageData,
    pub(super) protocol_before: NativeSerializationStorageData,
    pub(super) native_before: NativeSerializationStorageData,
}

#[derive(Clone, Copy)]
pub(super) enum NativeCaptureOuterEdition {
    Allocation12,
    Startup13,
    Invocation14,
}

impl NativeCaptureOuterEdition {
    fn endpoint(self) -> &'static str {
        match self {
            Self::Allocation12 => "source-owned.packet-native-endpoint-state/12",
            Self::Startup13 => "source-owned.packet-native-endpoint-state/13",
            Self::Invocation14 => "source-owned.packet-native-endpoint-state/14",
        }
    }
    fn context(self) -> &'static str {
        match self {
            Self::Allocation12 => "same-original-native-protocol-service-context/11",
            Self::Startup13 => "same-original-native-protocol-service-context/14",
            Self::Invocation14 => "same-original-native-protocol-service-context/15",
        }
    }
    fn owner(self) -> &'static str {
        match self {
            Self::Allocation12 => "source-private.native-capture-allocation-owner-reference/12",
            Self::Startup13 => "source-private.native-capture-allocation-owner-reference/13",
            Self::Invocation14 => "source-private.native-capture-allocation-owner-reference/14",
        }
    }
    fn before(self) -> &'static str {
        match self {
            Self::Allocation12 => "source-private.native-before-protocol/12",
            Self::Startup13 => "source-private.native-before-protocol/13",
            Self::Invocation14 => "source-private.native-before-protocol/14",
        }
    }
    fn snapshot(self) -> &'static str {
        match self {
            Self::Allocation12 => "source-owned.packet-native-continuation/12",
            Self::Startup13 => "source-owned.packet-native-continuation/13",
            Self::Invocation14 => "source-owned.packet-native-continuation/14",
        }
    }
}

pub(super) struct NativeCaptureOuterProjectionInput<'a> {
    pub(super) edition: NativeCaptureOuterEdition,
    pub(super) state: &'a complete::CompleteEndpointState,
    pub(super) records: &'a [ExchangeRecord],
    pub(super) record_capacity: usize,
    pub(super) pins: &'a [OperationContentPin],
    pub(super) pin_capacity: usize,
    pub(super) uploads: &'a BlobReceiver,
    pub(super) observed_fields: RetainedProtocolMetadataFacts,
    pub(super) before: &'a crate::connection::NativeOwned12CaptureBeforeEncodingData,
    pub(super) observe_record: &'a crate::connection::OriginalPacketCompletedRecordEncodingData,
    pub(super) control: &'a NativeObserveControlGrowthData,
    pub(super) capture: &'a NativeProjectedCaptureRequestData,
    pub(super) maximum_requested_bytes: usize,
}

pub(super) struct BorrowedOriginalPins<'a> {
    pub(super) pins: &'a [OperationContentPin],
    pub(super) uploads: &'a BlobReceiver,
}

impl Serialize for BorrowedOriginalPins<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.pins.len()))?;
        for pin in self.pins {
            let view = pin
                .original_protocol_view(self.uploads)
                .map_err(|_| serde::ser::Error::custom("original endpoint pin loan refused"))?;
            sequence.serialize_element(&view)?;
        }
        sequence.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native outer12 prospective original owner differs")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native outer12 prospective requested layout")
}

fn reference(out: &mut Projection, media: &str) -> Result<(), ProviderError> {
    out.add_object()?;
    for key in ["hash", "length", "media_type"] {
        out.add_field(key)?;
    }
    out.add_object()?;
    for key in ["algorithm", "domain", "digest"] {
        out.add_field(key)?;
    }
    out.add_string("blake3-256")?;
    out.add_string("cnp.blob.v1")?;
    out.add_unescaped_ascii_extent(64)?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_string(media)
}

fn compact(out: &mut Projection, maximum_raw: usize) -> Result<(), ProviderError> {
    let layout =
        crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::serialization_layout_data(
            maximum_raw,
        )?;
    out.add_array_extent(3)?;
    out.add_string("source-private.compact-bytes/7")?;
    out.add_value(&maximum_raw)?;
    out.add_array_extent(layout.chunk_count)?;
    for _ in 0..layout.full_chunks {
        out.add_unescaped_ascii_extent(4096)?;
    }
    if layout.final_encoded_chunk_bytes != 0 {
        out.add_unescaped_ascii_extent(layout.final_encoded_chunk_bytes)?;
    }
    Ok(())
}

pub(super) fn quote_original_outer12_projection(
    input: NativeCaptureOuterProjectionInput<'_>,
) -> Result<NativeCaptureOuterProjectionData, ProviderError> {
    let NativeCaptureOuterProjectionInput {
        edition,
        state,
        records,
        record_capacity,
        pins,
        pin_capacity,
        uploads,
        observed_fields,
        before,
        observe_record,
        control,
        capture,
        maximum_requested_bytes: maximum,
    } = input;
    state.ensure_origin()?;
    if record_capacity <= records.len() || pin_capacity < pins.len() {
        return Err(refused());
    }
    let events = before.before.serialization_events.ok_or_else(refused)?;
    let native_before = closed_event_serialization_storage_data(
        before.before.maximum_encoded_bytes,
        events.maximum_value_nodes,
        events.maximum_capacity_records,
        events.maximum_serializer_temporary_requested_bytes,
        maximum,
    )?;
    // This is exactly the actual outer endpoint's old fourteen tuple fields.
    // Future sequence/credit are numeric upper grammar, independent of bytes
    // newly retained by the completed Observe record appended below.
    let current_endpoint = actual_serialization_storage_data(
        &(
            edition.endpoint(),
            &state.storage,
            &state.profile,
            state.metadata_limits,
            state.metadata_birth_facts,
            state.hello.protocol_view(),
            edition.context(),
            crate::protocol_snapshot::Sequence(|| {
                records.iter().map(ExchangeRecord::original_protocol_view)
            }),
            record_capacity,
            BorrowedOriginalPins { pins, uploads },
            pin_capacity,
            u64::MAX,
            usize::MAX,
            true,
        ),
        observed_fields,
        maximum,
    )?;
    let record = closed_event_serialization_storage_data(
        observe_record.maximum_encoded_bytes,
        observe_record.maximum_serialized_value_nodes,
        observe_record.maximum_serialized_capacity_records,
        20, // closed decimal formatter; canonical byte banks serialize u8
        maximum,
    )?;
    let mut marker = Projection::new(maximum)?;
    marker.add_array_extent(2)?;
    marker.add_string(edition.owner())?;
    reference(&mut marker,
        crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA)?;
    let marker = marker.finish(maximum)?;
    // Two array/list joins each add a comma. Counting a whole extra two-slot
    // tuple overcounts punctuation and its DOM/parser layout without a fake
    // child value or dependence on whether the old record list was empty.
    let mut joins = Projection::new(maximum)?;
    joins.add_array_extent(2)?;
    let joins = joins.finish(maximum)?;
    let endpoint =
        sum_serialization_storage_data(&[&current_endpoint, &record, &marker, &joins], maximum)?;

    let mut protocol = Projection::new(maximum)?;
    protocol.add_array_extent(4)?;
    protocol.add_string(edition.before())?;
    reference(&mut protocol, "application/json")?;
    // This is the physical preborn encoded bank, distinct from the prospective
    // initialized byte extent which drives compact serialization.
    protocol.add_value(
        &state
            .before
            .as_ref()
            .ok_or_else(refused)?
            .original_allocation_facts()?
            .encoded_capacity,
    )?;
    compact(&mut protocol, before.before.maximum_encoded_bytes)?;
    let protocol_before = protocol.finish(maximum)?;
    let mut root = Projection::new(maximum)?;
    root.add_object()?;
    for key in [
        "capture",
        "capture_request",
        "control",
        "control_reference",
        "endpoint",
        "protocol",
        "schema",
    ] {
        root.add_field(key)?;
    }
    reference(&mut root, "application/json")?;
    root.add_string(edition.snapshot())?;
    let root = root.finish(maximum)?;
    let snapshot = sum_serialization_storage_data(
        &[
            &root,
            &capture.arguments,
            &capture.envelope,
            &control.control_encoding,
            &endpoint,
            &protocol_before,
        ],
        maximum,
    )?;
    if snapshot.maximum_encoded_bytes
        > usize::try_from(state.storage.snapshot_bytes.get()).map_err(|_| credit())?
        || control.maximum_control_encoded_bytes
            > usize::try_from(state.storage.control_snapshot_bytes.get()).map_err(|_| credit())?
    {
        return Err(credit());
    }
    state.ensure_origin()?;
    Ok(NativeCaptureOuterProjectionData {
        snapshot,
        endpoint,
        protocol_before,
        native_before,
    })
}
