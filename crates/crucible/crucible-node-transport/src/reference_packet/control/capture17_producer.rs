//! Defines independently funded Capture phase geometry and retained DATA layouts.
//!
//! Prebirth geometry uses the actual retained phase layouts and closed future
//! shapes. These quotes neither allocate a live phase owner nor register a
//! Capture. Live effects additionally require the same private Source-
//! authenticated occurrence and its complete, independently funded spent action.

use super::*;
use crate::envelope::MessageKind;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::reference_packet::service::restored_settled_capture::{
    PacketRestoredSettledCaptureRequest, RESTORED_SETTLED_CAPTURE_FEATURE,
};
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata, requested_metadata_backing_storage_data,
    requested_storage::tree_storage_data,
    serialization_storage::{
        OriginalSerializationStorageData as Shape,
        OriginalSerializationStorageProjection as Projection, actual_serialization_storage_data,
        original_serialization_counter_scratch_data,
    },
};
use std::{
    io::Write,
    mem::{align_of, size_of},
    rc::Rc,
};

mod confirmation;
mod registration;
mod retained;
mod terminal;

pub(crate) use confirmation::{
    NativeCapture17ConfirmationAttempt, NativeCapture17ConfirmationInputs,
    NativeCapture17ConfirmationStorageData,
};
pub(crate) use registration::{
    NativeCapture17RegistrationAttempt, NativeCapture17RegistrationInputs,
    NativeCapture17RegistrationStorageData,
};
pub(crate) use terminal::{NativeCapture17ReplyAttempt, NativeCapture17TerminalStorageData};

fn refused() -> ProviderError {
    ProviderError::Correlation("same private Capture17 Control producer required")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("independent Capture17 Control phase storage")
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}

fn multiply(count: usize, bytes: usize) -> Result<usize, ProviderError> {
    count.checked_mul(bytes).ok_or_else(exhausted)
}

fn quantity(bytes: usize) -> Result<U64, ProviderError> {
    u64::try_from(bytes).map(U64::new).map_err(|_| exhausted())
}

fn row(
    retained: usize,
    transient: usize,
    scratch: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    };
    if usize::try_from(row.requested_peak_data()?).map_err(|_| exhausted())? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

fn backing(value: &(impl ObserveMetadata + ?Sized)) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    requested_metadata_backing_storage_data(&observer.finish())
}

fn arguments_backing(value: &CaptureArguments) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observe_capture17_arguments_data(value, &mut observer)?;
    requested_metadata_backing_storage_data(&observer.finish())
}

pub(crate) fn observe_capture17_arguments_data(
    value: &CaptureArguments,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let CaptureArguments {
        capture_id,
        participant_ids,
        cut_id,
        cut,
        event_ordinal,
        ordering_profile,
        preservation_contract,
    } = value;
    observer.observe(capture_id)?;
    observer.observe(participant_ids)?;
    observer.observe(cut_id)?;
    observer.observe(cut)?;
    observer.observe(event_ordinal)?;
    observer.observe(ordering_profile)?;
    observer.observe(preservation_contract)
}

// The actual pinned BTree can split one node per occupied level and add a
// root. Binary minimum branching is deliberately weaker than its B=6 layout;
// all new nodes use the defining full internal-node requested layout.
fn insertion<K, V>(entries: usize) -> Result<usize, ProviderError> {
    let length = entries.checked_add(1).ok_or_else(exhausted)?;
    let nodes = (length.checked_ilog2().unwrap_or(0) as usize)
        .checked_add(2)
        .ok_or_else(exhausted)?;
    tree_storage_data(
        0,
        nodes,
        size_of::<K>()
            .checked_add(size_of::<V>())
            .ok_or_else(exhausted)?,
        align_of::<K>().max(align_of::<V>()),
    )
}

fn project_object(out: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    out.add_object()?;
    for field in fields {
        out.add_field(field)?;
    }
    Ok(())
}

fn project_reference(out: &mut Projection) -> Result<(), ProviderError> {
    project_object(out, &["hash", "length", "media_type"])?;
    project_object(out, &["algorithm", "domain", "digest"])?;
    out.add_string("blake3-256")?;
    out.add_string("cnp.blob.v1")?;
    out.add_unescaped_ascii_extent(64)?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_string("application/json")
}

// Leaves body and root extensions to the one defining phase visitor.
fn project_terminal_header(out: &mut Projection, original: &Envelope) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    out.add_value(&original.protocol)?;
    out.add_value(&MessageKind::Response)?;
    out.add_value(&original.session_id)?;
    out.add_value(&original.incarnation_id)?;
    out.add_value(&original.node_id)?;
    out.add_value(&original.execution_owner_id)?;
    out.add_value(&original.capture_owner_id)?;
    out.add_value(&original.request_id)?;
    out.add_value(&original.operation_id)?;
    out.add_unescaped_ascii_extent(20)?;
    out.add_value(&original.method)
}

fn within(actual: &Shape, bound: &Shape) -> Result<(), ProviderError> {
    for (actual, bound) in [
        (
            actual.dom_and_canonical_scratch_bytes,
            bound.dom_and_canonical_scratch_bytes,
        ),
        (
            actual.retained_value_backing_bytes,
            bound.retained_value_backing_bytes,
        ),
        (
            actual.projected_parser_requested_bytes,
            bound.projected_parser_requested_bytes,
        ),
        (
            actual.canonical_output_requested_bytes,
            bound.canonical_output_requested_bytes,
        ),
        (
            actual.serializer_temporary_requested_bytes,
            bound.serializer_temporary_requested_bytes,
        ),
        (
            actual.declared_counter_scratch_bytes,
            bound.declared_counter_scratch_bytes,
        ),
        (actual.maximum_encoded_bytes, bound.maximum_encoded_bytes),
        (actual.sequence_elements, bound.sequence_elements),
        (actual.sequence_containers, bound.sequence_containers),
        (actual.serialized_value_nodes, bound.serialized_value_nodes),
        (
            actual.serialized_capacity_records,
            bound.serialized_capacity_records,
        ),
    ] {
        if actual > bound {
            return Err(exhausted());
        }
    }
    Ok(())
}

struct OriginalIdentity(blake3::Hasher);
impl Write for OriginalIdentity {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// This complete wire transcript is correspondence only. The private native
// scope separately authenticates Source MAC, original literal and same Rc slot.
fn original_identity(original: &Envelope) -> Result<[u8; 32], ProviderError> {
    let mut sink = OriginalIdentity(blake3::Hasher::new_derive_key(
        "source-private.native-capture-phase-original/17",
    ));
    serde_json::to_writer(&mut sink, original).map_err(|_| refused())?;
    Ok(*sink.0.finalize().as_bytes())
}

fn authenticate_owner(
    control: &PacketControl,
    owner: &Rc<()>,
    creator: u32,
) -> Result<(), ProviderError> {
    if creator != std::process::id()
        || control.capture_creator != creator
        || !Rc::ptr_eq(owner, &control.capture_identity)
    {
        return Err(refused());
    }
    Ok(())
}

struct CanonicalBank<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}
impl Write for CanonicalBank<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|length| *length <= self.maximum && *length <= self.bytes.capacity())
            .ok_or(std::io::ErrorKind::OutOfMemory)?;
        self.bytes.extend_from_slice(input);
        debug_assert_eq!(length, self.bytes.len());
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn retain_canonical(
    value: &Envelope,
    storage: &Shape,
    dom: &mut Option<Value>,
    bytes: &mut Vec<u8>,
) -> Result<(), ProviderError> {
    if dom.is_some() || !bytes.is_empty() || bytes.capacity() != 0 {
        return Err(refused());
    }
    bytes
        .try_reserve_exact(storage.maximum_encoded_bytes)
        .map_err(|_| exhausted())?;
    *dom = Some(serde_json::to_value(value).map_err(ContractError::from)?);
    canonical::canonical_json_to_writer(
        dom.as_ref().ok_or_else(refused)?,
        &mut CanonicalBank {
            bytes,
            maximum: storage.maximum_encoded_bytes,
        },
    )?;
    Ok(())
}

impl PacketControl {
    /// Names actual quote formatter work before any generic Serialize traversal.
    ///
    /// The genuine native scope independently admits this demand against its
    /// Source-signed and remaining native axes. This value is neither allocation
    /// credit nor a Control or Capture permission. The request's actual32-byte
    /// digest is separately included even if today's Control has no Bytes fields.
    ///
    /// # Errors
    /// Refuses foreign/busy Control edges, a non32-byte request digest or overflow.
    pub(crate) fn capture17_prequote_work_data(
        &self,
        request: &PacketRestoredSettledCaptureRequest,
    ) -> Result<(usize, usize), ProviderError> {
        let digest = request.scope.restoration.context_digest.as_slice().len();
        if digest != 32 {
            return Err(refused());
        }
        let encoded = digest
            .checked_div(3)
            .and_then(|groups| groups.checked_mul(4))
            .and_then(|bytes| {
                bytes.checked_add(match digest % 3 {
                    0 => 0,
                    1 => 2,
                    _ => 3,
                })
            })
            .ok_or_else(exhausted)?;
        Ok((
            self.pending_capture17_formatter_work_data()?
                .max(encoded)
                .max(20),
            capture17_producer_counter_scratch_data(),
        ))
    }

    /// Names defining fixed prequote controls before the actual Control walk.
    pub(crate) fn capture17_prequote_counter_scratch_data() -> usize {
        capture17_producer_counter_scratch_data()
    }

    /// Lends the real Control allocation identity to its private native scope.
    pub(crate) fn capture17_identity_data(&self) -> &Rc<()> {
        &self.capture_identity
    }
}

/// Names independently prepaid quote and retained producer fixed controls.
pub(crate) fn capture17_producer_counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>()
        + size_of::<Projection>()
        + size_of::<Shape>()
        + size_of::<OriginalIdentity>()
        + size_of::<blake3::Hash>()
        + size_of::<CanonicalBank<'static>>()
        + canonical::canonical_number_counter_scratch_bytes_data()
        + crucible_node_format::Bytes::serialization_counter_scratch_data()
        + size_of::<serde_json::Serializer<&'static mut OriginalIdentity>>()
        + size_of::<[u8; 32]>()
        + size_of::<Option<[u8; 32]>>()
        + size_of::<[u8; 20]>()
        + size_of::<std::alloc::Layout>()
        + size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>()
        + size_of::<[usize; 5]>()
        + size_of::<&PacketControl>()
        + size_of::<&Envelope>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<[&str; 13]>()
        + size_of::<[(usize, usize); 11]>()
        + size_of::<PacketNativeStartupAllocationRow>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(usize, usize), ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<std::ops::Range<usize>>()
        + original_serialization_counter_scratch_data()
        + PacketControl::pending_capture17_history_counter_scratch_data()
        + PacketControl::pending_capture17_request_hash_counter_scratch_data()
        + registration::counter_scratch_data()
        + terminal::counter_scratch_data()
        + confirmation::counter_scratch_data()
}

#[cfg(test)]
mod tests;

mod future;
pub use future::{
    PacketRestoredSettledCaptureControlFutureInputs,
    PacketRestoredSettledCaptureControlFutureStorageData,
    PacketRestoredSettledCaptureControlModelFutureData,
    restored_settled_capture_control_future_from_model_data,
    restored_settled_capture_control_future_prequote_data,
    restored_settled_capture_control_future_storage_data,
    restored_settled_capture_control_model_future_from_initial15_data,
    restored_settled_capture_control_model_future_initial15_prequote_data,
};
