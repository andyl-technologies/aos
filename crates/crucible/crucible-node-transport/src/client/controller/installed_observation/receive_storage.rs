//! Projects each named first-Observe host receiver owner before assignment.
//!
//! The actual SDK enters from an idle correlation cut and ACKs each Blob before
//! receiving another. The persistent ClientCustody namespace and ContentStore
//! still retain every original, cached ACK and failed/incomplete transfer. The
//! receiver keeps all existing ceilings, including unexpected provider traffic.

use super::*;
use crate::client::ClientContent;
use crate::retained_metadata::requested_storage::tree_storage_data;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};
use std::mem::{align_of, size_of};

/// Reports independently priced future host receiver axes as inert DATA.
pub struct OriginalObservationReceiveStorageData {
    /// Prices prospective persistent content, original, ACK and failure backing.
    pub(crate) retained: usize,
    /// Prices simultaneous decoder, mutation, serialization and failure work.
    pub(crate) transient: usize,
    /// Prices the defining fixed counters and borrowed views.
    pub(crate) scratch: usize,
}

impl OriginalObservationReceiveStorageData {
    /// Returns prospective content, original, ACK and failure backing.
    pub fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independently priced simultaneous receiver work.
    pub fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining counters and borrowed receiver views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
}

impl CnpController {
    /// Names this exact causal receiver quote's fixed headers before its walk.
    ///
    /// This DATA grants no original, credit, protocol operation or native action.
    pub fn original_observation_receive_counter_scratch_data() -> usize {
        counter_scratch_data()
    }

    /// Quotes the actual finite receiver, persistent provider journals and ACKs.
    ///
    /// This inert DATA authenticates no Source, current checkpoint, World or
    /// native action. The owning construction independently prices this new
    /// component beside its existing census and other operation-specific rows.
    ///
    /// # Errors
    /// Refuses nonidle or changed native codec, checked overflow or total demand
    /// beyond the caller's independently funded complete construction ceiling.
    pub fn original_observation_receive_storage_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalObservationReceiveStorageData, ProviderError> {
        self.observation_receive_storage_for_capture_data(maximum, None)
    }

    pub(in crate::client) fn observation_receive_storage_for_capture_data(
        &self,
        maximum: usize,
        capacity: Option<&crate::client::content::capture_capacity::CaptureContentCapacityData>,
    ) -> Result<OriginalObservationReceiveStorageData, ProviderError> {
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        let limits = self.authority().limits();
        let frame = usize::try_from(limits.frame_bytes.get()).map_err(|_| credit())?;
        // Count the actual receiver's limit, even if its installer selected a
        // larger value than the advertised nominal chunk size. Wire framing is
        // an independent unchanged ceiling; no negotiation-only alias is used.
        let chunk = self
            .custody
            .content()
            .observation_receive_maximum_chunk_data()
            .min(frame);
        let requests = self.custody.maximum_requests();
        let shapes = [
            blob_frame(0, chunk, false, maximum)?,
            blob_frame(1, chunk, false, maximum)?,
            blob_frame(2, chunk, false, maximum)?,
        ];
        let acks = [
            blob_frame(0, chunk, true, maximum)?,
            blob_frame(1, chunk, true, maximum)?,
            blob_frame(2, chunk, true, maximum)?,
        ];
        let request_backing = shapes
            .iter()
            .map(|row| row.retained_value_backing_bytes)
            .max()
            .ok_or_else(credit)?;
        let ack_backing = acks
            .iter()
            .map(|row| row.retained_value_backing_bytes)
            .max()
            .ok_or_else(credit)?;
        let request_work = shapes.iter().try_fold(0usize, |maximum, row| {
            Ok::<_, ProviderError>(maximum.max(row.requested_total()?))
        })?;
        let ack_work = acks.iter().try_fold(0usize, |maximum, row| {
            Ok::<_, ProviderError>(maximum.max(row.requested_total()?))
        })?;
        let reference = reference_projection(maximum)?;
        let content = if let Some(capacity) = capacity {
            self.custody
                .content()
                .observation_receive_capture_content_storage_data(
                    reference.retained_value_backing_bytes,
                    requests,
                    frame,
                    capacity,
                )?
        } else {
            self.custody
                .content()
                .observation_receive_content_storage_data(
                    reference.retained_value_backing_bytes,
                    requests,
                    frame,
                )?
        };
        let raw = original_json_value_storage_extent_data(frame)?;
        // All lifetime provider records can remain in ClientCustody after ACK.
        // Count its full unchanged finite map as a fresh prospective allocation;
        // current nodes are independently retained, with no spare-node credit.
        let journal_tree = tree_storage_data(
            1,
            requests,
            size_of::<Id>() + size_of::<ClientOriginal>(),
            align_of::<(Id, ClientOriginal)>(),
        )?;
        let journal_entry = sum(&[
            request_backing,
            ack_backing,
            // Map ID, request identity HashRef and original literal slot's ID.
            128,
            128 + 64 + "blake3-256".len(),
            128,
        ])?;
        // Only one request/ACK can be active at once. CorrelationGuard retains
        // independent request and response clones until send completes; failure
        // also retains one real incident with that request's complete body.
        let open_guards = tree_storage_data(
            3,
            3,
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<(Id, Envelope)>(),
        )?;
        let containment = sum(&[
            size_of::<crate::connection::ConnectionIncident>(),
            3 * 128,
            8 * size_of::<Envelope>(),
            raw.value_dom_requested_bytes,
        ])?;
        let retained = sum(&[
            content.0,
            journal_tree,
            mul(requests, journal_entry)?,
            open_guards,
            request_backing,
            ack_backing,
            containment,
            // A terminating provider Retire can be retained by ClientCustody
            // before receive_transfer refuses its non-Blob method.
            raw.value_dom_requested_bytes,
            // That terminating non-Blob also remains in the original incoming
            // correlation until containment; a closed Blob shape cannot pay it.
            raw.value_dom_requested_bytes,
        ])?;
        let typed_blob = sum(&[
            size_of::<RequestBody>(),
            size_of::<ResponseBody>(),
            size_of::<NotificationBody>(),
            size_of::<BlobBeginRequest>()
                .max(size_of::<BlobChunkRequest>())
                .max(size_of::<BlobFinishRequest>()),
            size_of::<BlobBeginResult>()
                .max(size_of::<BlobChunkResult>())
                .max(size_of::<BlobFinishResult>()),
            reference.retained_value_backing_bytes,
            128,
            chunk,
        ])?;
        let transient = sum(&[
            content.1,
            request_work,
            ack_work,
            typed_blob,
            // Raw input/parser/canonical error work is one terminating phase,
            // never multiplied into lifetime accepted-journal storage.
            raw.canonical_pass_requested_bytes()?,
            raw.value_dom_requested_bytes,
            frame,
            // Retire's two ID arrays are the only provider-origin non-Blob
            // request decoded before Session rejects it. Keep all typed slots.
            mul(raw.maximum_value_nodes, size_of::<Id>())?,
            // A rejected Notification owns a separate arbitrary details Map;
            // its Validate implementation clones that Map for canonical work.
            raw.value_dom_requested_bytes,
            raw.canonical_pass_requested_bytes()?,
            // An oversized BlobChunk can decode a whole framed byte string
            // before ClientContent rejects the unchanged chunk ceiling.
            mul(frame, 2)?.checked_add(8).ok_or_else(credit)?,
            // bytes serializer base64 buffer coexists with typed Blob bytes.
            mul(chunk.div_ceil(3), 4)?,
        ])?;
        let scratch = counter_scratch_data();
        if sum(&[retained, transient, scratch])? > maximum {
            return Err(credit());
        }
        self.session
            .ensure_original_observation_receiver_idle_data()?;
        Ok(OriginalObservationReceiveStorageData {
            retained,
            transient,
            scratch,
        })
    }
}

fn reference_projection(maximum: usize) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    reference_fields(&mut out)?;
    out.finish(maximum)
}

fn reference_fields(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("hash")?;
    out.add_object()?;
    for (name, value) in [("algorithm", "blake3-256"), ("domain", "cnp.blob.v1")] {
        out.add_field(name)?;
        out.add_string(value)?;
    }
    out.add_field("digest")?;
    out.add_unescaped_ascii_extent(64)?;
    out.add_field("length")?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_field("media_type")?;
    out.add_string_extent(128)
}

fn blob_frame(
    method: usize,
    chunk: usize,
    response: bool,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    for (name, value) in [
        ("protocol", "CNP/1"),
        ("message", if response { "response" } else { "request" }),
    ] {
        out.add_field(name)?;
        out.add_string(value)?;
    }
    for name in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
        "request_id",
    ] {
        out.add_field(name)?;
        out.add_string_extent(128)?;
    }
    out.add_field("sequence")?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_field("method")?;
    out.add_string(match method {
        0 => "blob_begin",
        1 => "blob_chunk",
        _ => "blob_finish",
    })?;
    out.add_field("body")?;
    out.add_object()?;
    if response {
        out.add_field("status")?;
        out.add_string("completed")?;
        out.add_field("operation_state")?;
        out.add_string("completed")?;
        out.add_field("result")?;
        out.add_object()?;
    }
    out.add_field("transfer_id")?;
    out.add_string_extent(128)?;
    if response {
        if method == 2 {
            out.add_field("content")?;
            reference_fields(&mut out)?;
        } else {
            out.add_field("next_offset")?;
            out.add_unescaped_ascii_extent(20)?;
            if method == 0 {
                out.add_field("maximum_chunk_bytes")?;
                out.add_unescaped_ascii_extent(20)?;
            }
        }
        out.add_field("extensions")?;
        out.add_object()?;
    } else {
        match method {
            0 => {
                out.add_field("content")?;
                reference_fields(&mut out)?;
            }
            1 => {
                out.add_field("offset")?;
                out.add_unescaped_ascii_extent(20)?;
                out.add_field("bytes")?;
                out.add_unescaped_ascii_extent(mul(chunk.div_ceil(3), 4)?)?;
            }
            _ => {}
        }
        out.add_field("extensions")?;
        out.add_object()?;
    }
    out.add_field("extensions")?;
    out.add_object()?;
    out.finish(maximum)
}

pub(super) fn counter_scratch_data() -> usize {
    let receiver = size_of::<OriginalObservationReceiveStorageData>()
        + size_of::<Result<OriginalObservationReceiveStorageData, ProviderError>>()
        + size_of::<[OriginalSerializationStorageData; 3]>() * 2
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Projection>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
        >()
        + size_of::<&CnpController>()
        + size_of::<&ClientContent>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<std::slice::Iter<'static, OriginalSerializationStorageData>>()
        + size_of::<Option<usize>>()
        + size_of::<Option<&crate::client::content::capture_capacity::CaptureContentCapacityData>>(
        )
        + size_of::<&crate::client::content::capture_capacity::CaptureContentCapacityData>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[usize; 18]>()
        + 24 * size_of::<usize>()
        + size_of::<RequestBody>()
        + size_of::<ResponseBody>()
        + size_of::<NotificationBody>();

    // Request identity and content verification are receiver work. Keep their
    // own fixed headers instead of borrowing another protocol phase's row.
    let hashing = size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + returned_layout_bytes(|| blake3::Hash::from([0; 32]).to_hex())
        + size_of::<crucible_node_format::HashRef>()
        + size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>()
        + size_of::<Result<crucible_node_format::HashRef, ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&ContentRef>()
        + size_of::<&[u8]>()
        + size_of::<u32>()
        + size_of::<u64>()
        + size_of::<[u8; 4]>()
        + size_of::<[u8; 8]>();

    receiver
        + hashing
        + ClientContent::observation_receive_content_counter_scratch_data()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + crate::client::ClientSession::original_installed_restoration_observation_counter_scratch_data()
}

fn returned_layout_bytes<T>(_: impl FnOnce() -> T) -> usize {
    size_of::<T>()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or_else(credit)
    })
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}
