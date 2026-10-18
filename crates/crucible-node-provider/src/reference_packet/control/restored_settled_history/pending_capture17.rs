//! Projects pending Capture registration without mutating Control or issuing permission.
//!
//! Only the four fields changed by the defining registration are replaced.
//! The complete future Control extent is DATA; its new UNKNOWN map need not
//! reproduce feature-dependent map iteration order to count the exact bytes.
//! Normative request hashing is a separate admitted, retained owning phase.

use super::*;
use crate::envelope::MessageKind;
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
};
use crate::reference_packet::service::restored_settled_capture::RESTORED_SETTLED_CAPTURE_FEATURE;
use crate::retained_metadata::RetainedProtocolMetadataFacts;
use serde::ser::SerializeMap;
use std::io::{self, Write};

fn refused() -> ProviderError {
    ProviderError::Correlation("pending Capture17 Control projection differs")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("pending Capture17 Control demand")
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}

/// Keeps an exact prospective bank extent and separately named metadata growth.
pub(crate) struct NativePendingCapture17ControlStorageData {
    encoded: usize,
    begin: RetainedProtocolMetadataFacts,
    unknown: NativeSerializationStorageData,
}

impl NativePendingCapture17ControlStorageData {
    /// Returns exact emitted extent, excluding any separately retained spare capacity.
    pub(crate) fn encoded_bytes_data(&self) -> usize {
        self.encoded
    }

    /// Returns the concrete cloned Begin's backing upper, including original spare capacity.
    ///
    /// These are prospective clone bounds, not observed future capacities.
    pub(crate) fn begin_clone_metadata_upper_data(&self) -> RetainedProtocolMetadataFacts {
        self.begin
    }

    /// Returns UNKNOWN-body DOM/layout demand from its defining closed projection.
    pub(crate) fn unknown_body_storage_data(&self) -> &NativeSerializationStorageData {
        &self.unknown
    }

    /// Returns exact additional capacity-record count for the known registration grammar.
    ///
    /// The three existing outer-map records change extent, not record count.
    /// New strings are five IDs, three HashRef strings and fourteen UNKNOWN
    /// keys/values; the body adds four maps and the reply one empty evidence Vec.
    /// # Errors
    /// Refuses checked count overflow.
    pub(crate) fn additional_capacity_records_data(&self) -> Result<usize, ProviderError> {
        self.begin
            .capacity_records
            .checked_add(27)
            .ok_or_else(exhausted)
    }

    /// Returns new logical tree entries, including the complete cloned Begin tree.
    /// # Errors
    /// Refuses checked count overflow.
    pub(crate) fn additional_tree_entries_data(&self) -> Result<usize, ProviderError> {
        self.begin
            .tree_entries
            .checked_add(12)
            .ok_or_else(exhausted)
    }
}

pub(super) struct PendingCapture17Fields<'a> {
    id: &'a Id,
    operation: &'a Id,
    begin: &'a BeginRequest,
    hash: &'a HashRef,
}

impl PendingCapture17Fields<'_> {
    pub(super) fn operation_data(&self) -> &Id {
        self.operation
    }
    pub(super) fn originals_data<'a>(&'a self, map: &'a Originals) -> PendingOriginals<'a> {
        PendingOriginals(map, self)
    }
    pub(super) fn begins_data<'a>(
        &'a self,
        map: &'a BTreeMap<Id, BeginRequest>,
    ) -> MergedMap<'a, BeginRequest, BeginRequest> {
        MergedMap {
            map,
            key: self.operation,
            value: self.begin,
        }
    }
    pub(super) fn begin_requests_data<'a>(
        &'a self,
        map: &'a BTreeMap<Id, Id>,
    ) -> MergedMap<'a, Id, Id> {
        MergedMap {
            map,
            key: self.operation,
            value: self.id,
        }
    }
}

// This private generic adapter is instantiated only by the two closed maps
// above. It borrows actual entries and inserts in Id order without sorting or
// allocating a collection of references.
pub(super) struct MergedMap<'a, V, P> {
    map: &'a BTreeMap<Id, V>,
    key: &'a Id,
    value: &'a P,
}
impl<V: Serialize, P: Serialize> Serialize for MergedMap<'_, V, P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_map(Some(self.map.len() + 1))?;
        let mut pending = true;
        for (key, value) in self.map {
            if pending && self.key < key {
                rows.serialize_entry(self.key, self.value)?;
                pending = false;
            }
            rows.serialize_entry(key, value)?;
        }
        if pending {
            rows.serialize_entry(self.key, self.value)?;
        }
        rows.end()
    }
}

pub(super) struct PendingOriginals<'a>(&'a Originals, &'a PendingCapture17Fields<'a>);
impl Serialize for PendingOriginals<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.0.len() + 1))?;
        let mut pending = true;
        for (id, (hash, reply)) in self.0 {
            if pending && self.1.id < id {
                rows.serialize_element(&(
                    self.1.id,
                    self.1.hash,
                    UnknownCapture,
                    &[] as &[(ContentRef, Vec<u8>)],
                ))?;
                pending = false;
            }
            rows.serialize_element(&(id, hash, &reply.body, &reply.evidence))?;
        }
        if pending {
            rows.serialize_element(&(
                self.1.id,
                self.1.hash,
                UnknownCapture,
                &[] as &[(ContentRef, Vec<u8>)],
            ))?;
        }
        rows.end()
    }
}

#[derive(Serialize)]
struct UnknownCaptureError<'a> {
    code: &'a str,
    message: &'a str,
    effect: EffectCertainty,
    retryable: bool,
    details: &'a Map<String, Value>,
}

#[derive(Serialize)]
struct UnknownCaptureBody<'a> {
    status: &'a str,
    operation_state: OperationState,
    error: UnknownCaptureError<'a>,
    extensions: &'a Map<String, Value>,
}

struct UnknownCapture;
impl Serialize for UnknownCapture {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let empty = Map::new();
        UnknownCaptureBody {
            status: "error",
            operation_state: OperationState::Unknown,
            error: UnknownCaptureError {
                code: "OUTCOME_UNKNOWN",
                message: "original native Capture remains unresolved",
                effect: EffectCertainty::Unknown,
                retryable: false,
                details: &empty,
            },
            extensions: &empty,
        }
        .serialize(serializer)
    }
}

struct Count {
    bytes: usize,
}
impl Write for Count {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(input.len())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl PacketControl {
    /// Quotes custom Bytes/decimal formatter demand before the generic history count.
    ///
    /// The actual stopped graph supplies the maximum visited typed Bytes length.
    /// Compact-wrapped typed Bytes may overcount; raw Vec capacity is excluded.
    /// No observed backing becomes construction credit.
    /// # Errors
    /// Refuses foreign/busy actual edges or checked traversal/extent overflow.
    pub(crate) fn pending_capture17_formatter_work_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_restored_settled_history_metadata_data(&mut observer)?;
        Ok(observer
            .ordinary_bytes_formatter_data()
            .maximum_temporary_requested_bytes_data()?
            .max(20))
    }

    /// Counts the actual Control with only the defining pending registration changes.
    ///
    /// Caller must separately prepay fixed traversal and the returned custom
    /// formatter demand BEFORE this count, and retain the genuine Source/native
    /// loan and complete future action. A completed hash DATA prerequisite is
    /// correspondence, never permission. No map or Control state is mutated.
    /// # Errors
    /// Refuses unrelated original/Begin/hash, duplicate IDs, active operation,
    /// foreign history edges, count overflow or the unchanged output maximum.
    pub(crate) fn quote_pending_capture17_history_data(
        &self,
        original: &Envelope,
        begin: &BeginRequest,
        arguments: &CaptureArguments,
        hash: &NativePendingCapture17RequestHashAttempt,
        maximum_encoded: usize,
    ) -> Result<NativePendingCapture17ControlStorageData, ProviderError> {
        self.authenticate_restored_settled_history_edges_data()?;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = original.operation_id.0.as_ref().ok_or_else(refused)?;
        if original.message != MessageKind::Request
            || original.method != Method::Begin
            || begin.kind != BeginKind::Capture
            || self.current_operation.is_some()
            || self.originals.len() >= ORIGINALS
            || self.begins.len() >= 64
            || self.originals.contains_key(id)
            || self.begins.contains_key(operation)
            || self.begin_requests.contains_key(operation)
            || self.begin_requests.len().checked_add(1).is_none()
        {
            return Err(refused());
        }
        authenticate_fields_data(original, begin, arguments)?;
        let hash = hash.completed_data(original)?;
        let fields = PendingCapture17Fields {
            id,
            operation,
            begin,
            hash,
        };
        let mut count = Count { bytes: 0 };
        serde_json::to_writer(&mut count, &ControlHistory(self, false, Some(fields)))
            .map_err(|_| exhausted())?;
        if count.bytes > maximum_encoded {
            return Err(exhausted());
        }
        let mut begin_metadata = MetadataObserver::new();
        begin_metadata.observe(begin)?;
        let mut unknown = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(usize::MAX)?;
        super::super::observe_control_growth::unknown_capture(&mut unknown)?;
        let unknown = unknown.finish(usize::MAX)?;
        Ok(NativePendingCapture17ControlStorageData {
            encoded: count.bytes,
            begin: begin_metadata.finish(),
            unknown,
        })
    }
}

#[path = "pending_capture17/request_hash.rs"]
mod request_hash;
pub(crate) use request_hash::{
    NativePendingCapture17RequestHashAttempt, NativePendingCapture17RequestHashStorageData,
};

fn u64_matches(value: Option<&Value>, expected: U64) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        !value.is_empty()
            && (value == "0" || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && value.parse::<u64>().ok() == Some(expected.get())
    })
}

fn hash_matches(value: Option<&Value>, actual: &HashRef) -> bool {
    let HashRef {
        algorithm,
        domain,
        digest,
    } = actual;
    value.and_then(Value::as_object).is_some_and(|value| {
        value.len() == 3
            && value.get("algorithm").and_then(Value::as_str) == Some(algorithm.as_str())
            && value.get("domain").and_then(Value::as_str) == Some(domain.as_str())
            && value.get("digest").and_then(Value::as_str) == Some(digest.as_str())
    })
}

// The typed protocol map and JSON object can use different map backends.
// Compare exact keys/values without constructing another object or assuming order.
fn extensions_match_data(value: Option<&Value>, expected: &Extensions) -> bool {
    value.and_then(Value::as_object).is_some_and(|actual| {
        actual.len() == expected.len()
            && expected
                .iter()
                .all(|(key, value)| actual.get(key) == Some(value))
    })
}

fn authenticate_fields_data(
    original: &Envelope,
    begin: &BeginRequest,
    arguments: &CaptureArguments,
) -> Result<(), ProviderError> {
    let BeginRequest {
        kind,
        binding_hash,
        owner_generation,
        activation_id,
        world_generation,
        arguments: body_arguments,
        extensions,
    } = begin;
    let body = &original.body;
    let activation_matches = match (&activation_id.0, body.get("activation_id")) {
        (None, Some(Value::Null)) => true,
        (Some(actual), Some(Value::String(value))) => actual.as_str() == value,
        _ => false,
    };
    if original.protocol != "CNP/1"
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_SETTLED_CAPTURE_FEATURE)
        || *kind != BeginKind::Capture
        || body.len() != 7
        || body.get("kind").and_then(Value::as_str) != Some("capture")
        || !hash_matches(body.get("binding_hash"), binding_hash)
        || !u64_matches(body.get("owner_generation"), *owner_generation)
        || !activation_matches
        || !u64_matches(body.get("world_generation"), *world_generation)
        || body.get("arguments").and_then(Value::as_object) != Some(body_arguments)
        || !extensions_match_data(body.get("extensions"), extensions)
    {
        return Err(refused());
    }
    let CaptureArguments {
        capture_id,
        participant_ids,
        cut_id,
        cut,
        event_ordinal,
        ordering_profile,
        preservation_contract,
    } = arguments;
    let body = body_arguments;
    let participants = body
        .get("participant_ids")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if body.len() != 7
        || body.get("capture_id").and_then(Value::as_str) != Some(capture_id.as_str())
        || participants.len() != participant_ids.len()
        || participants
            .iter()
            .zip(participant_ids)
            .any(|(value, id)| value.as_str() != Some(id.as_str()))
        || body.get("cut_id").and_then(Value::as_str) != Some(cut_id.as_str())
        || !u64_matches(body.get("event_ordinal"), *event_ordinal)
        || body.get("ordering_profile").and_then(Value::as_str) != Some(ordering_profile.as_str())
        || body.get("preservation_contract").and_then(Value::as_str)
            != Some(preservation_contract.as_str())
    {
        return Err(refused());
    }
    let Position {
        time_ps,
        microstep,
        phase,
    } = cut;
    let phase = match phase {
        Phase::BoundaryControl => 0,
        Phase::Publication => 1,
        Phase::Delivery => 2,
        Phase::Reaction => 3,
    };
    let cut = body
        .get("cut")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    if cut.len() != 3
        || !u64_matches(cut.get("time_ps"), *time_ps)
        || !u64_matches(cut.get("microstep"), *microstep)
        || cut.get("phase").and_then(Value::as_u64) != Some(phase)
    {
        return Err(refused());
    }
    Ok(())
}

impl PacketControl {
    /// Names the actual future-view/count/merge and complete old history views.
    ///
    /// Custom Bytes banks and compiler/serializer recursion remain separate.
    pub(crate) fn pending_capture17_history_counter_scratch_data() -> usize {
        Self::restored_settled_history_counter_scratch_data()
            + size_of::<PendingCapture17Fields<'static>>()
            + size_of::<NativePendingCapture17ControlStorageData>()
            + size_of::<Result<NativePendingCapture17ControlStorageData, ProviderError>>()
            + size_of::<MergedMap<'static, BeginRequest, BeginRequest>>()
            + size_of::<MergedMap<'static, Id, Id>>()
            + size_of::<PendingOriginals<'static>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Count>()
            + size_of::<serde_json::Serializer<&'static mut Count>>()
            + size_of::<Map<String, Value>>()
            + size_of::<UnknownCapture>()
            + size_of::<UnknownCaptureBody<'static>>()
            + size_of::<UnknownCaptureError<'static>>()
            + size_of::<std::collections::btree_map::Iter<'static, Id, BeginRequest>>()
            + size_of::<std::collections::btree_map::Iter<'static, Id, Id>>()
            + size_of::<bool>()
            + field_view_bytes(|value: &'static BeginRequest| {
                let BeginRequest {
                    kind,
                    binding_hash,
                    owner_generation,
                    activation_id,
                    world_generation,
                    arguments,
                    extensions,
                } = value;

                (
                    kind,
                    binding_hash,
                    owner_generation,
                    activation_id,
                    world_generation,
                    arguments,
                    extensions,
                )
            })
            + field_view_bytes(|value: &'static CaptureArguments| {
                let CaptureArguments {
                    capture_id,
                    participant_ids,
                    cut_id,
                    cut,
                    event_ordinal,
                    ordering_profile,
                    preservation_contract,
                } = value;

                (
                    capture_id,
                    participant_ids,
                    cut_id,
                    cut,
                    event_ordinal,
                    ordering_profile,
                    preservation_contract,
                )
            })
            + field_view_bytes(|value: &'static HashRef| {
                let HashRef {
                    algorithm,
                    domain,
                    digest,
                } = value;

                (
                    algorithm,
                    domain,
                    digest,
                )
            })
            + field_view_bytes(|value: &'static Position| {
                let Position {
                    time_ps,
                    microstep,
                    phase,
                } = value;

                (
                    time_ps,
                    microstep,
                    phase,
                )
            })
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<Option<&Value>>()
            + size_of::<Option<&str>>()
            + size_of::<Option<&Vec<Value>>>()
            + size_of::<Option<&Map<String, Value>>>()
            + size_of::<Option<(&Id, &BeginRequest)>>()
            + size_of::<Option<(&Id, &Id)>>()
            + size_of::<std::collections::btree_map::Iter<'static, String, Value>>()
            + size_of::<Option<(&String, &Value)>>()
            + size_of::<Result<(), serde_json::Error>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<std::iter::Zip<std::slice::Iter<'static, Value>, std::slice::Iter<'static, Id>>>()
            + request_hash::original_identity_counter_scratch_data()
            + crate::retained_metadata::ordinary_bytes_formatter_counter_scratch_data()
            + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
    }
}

#[cfg(test)]
mod tests;

impl PacketControl {
    /// Rechecks exact original/Begin/arguments correspondence without decoding.
    ///
    /// This is a borrowed DATA comparison, not Source or registration authority.
    /// # Errors
    /// Refuses any changed closed body field, extension, coordinate or Id roster.
    pub(in crate::reference_packet::control) fn authenticate_capture17_borrowed_fields_data(
        original: &Envelope,
        begin: &BeginRequest,
        arguments: &CaptureArguments,
    ) -> Result<(), ProviderError> {
        authenticate_fields_data(original, begin, arguments)
    }
}
