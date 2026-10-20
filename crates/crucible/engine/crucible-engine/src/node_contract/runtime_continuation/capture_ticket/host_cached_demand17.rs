//! Quotes the actual current17 cached Host producer and its exact direct edges.
//!
//! The genuine private capsule, actual attached witness and current Runtime must
//! agree. Original15 preparation and Host2 decoder paths remain separate.

use super::*;
use crate::node_contract::NodeRuntime;
use crate::node_state::CompleteOriginalOwnerCaptureGeometry;
use serde::Serialize;

#[derive(Serialize)]
struct JournalView<'a> {
    schema: &'a str,
    capture_id: &'a Id,
    operation: &'a Id,
    owner: &'a OwnerIdentity,
    participants: &'a [Id],
    cut: Position,
    ordinal: U64,
    runtime: &'a ContentRef,
    snapshot: &'a ContentRef,
    transition: &'a str,
}

pub(super) fn cached_demand_data(
    prepared: &PreparedRestoredHost17Capture,
    runtime: &NodeRuntime,
    witness: &HostSchedulingNodeWitness<'_>,
    activation: &WorldActivation,
    original: &OriginalLineageRuntimeRecord,
    runtime_object: &InputPayload,
    limits: NativeArchiveLimits,
) -> Result<CompleteOriginalOwnerCapturePreflight, RuntimeError> {
    prepared.authenticate_runtime_data(runtime, activation, runtime_object)?;
    let selected = witness.original_capture_source()?;
    prepared.authenticate_host_data(&selected)?;
    let result = prepared.with_snapshot_data(|snapshot| {
        if snapshot.record_data().runtime != *original
            || snapshot.record_data().source != *selected.selection()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let selection = selected.selection();
        let owner = activation
            .record()
            .owners
            .iter()
            .find(|owner| owner.owner == selection.owner.owner.id)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if owner.incarnation != selection.binding.authority.incarnation_id
            || owner.generation != selection.binding.authority.owner_generation
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let key = prepared.key_data().clone();
        let longest_id = Id::new("x".repeat(128)).map_err(|_| RuntimeError::InvalidReceipt)?;
        let journal = JournalView {
            schema: "source-owned.host-scheduling-capture-journal/2",
            capture_id: &longest_id,
            operation: &longest_id,
            owner,
            participants: &selection.owner.owner.participant_ids,
            cut: original.capture_cut,
            ordinal: original.capture_ordinal,
            runtime: &runtime_object.reference,
            snapshot: &snapshot.encoded_data().reference,
            transition: "one original unchanged-cut common snapshot; no native operation, input or acknowledgement submitted",
        };
        // The callback's closed journal has its existing 4096-byte record
        // ceiling. Two full JSON Value passes cover json! and credit/encoding;
        // the same selected record, not a hard snapshot ceiling, is inspected.
        let journal_scratch = NodeRuntime::capture_serialization_storage(
            &journal,
            limits.state.maximum_total_content_bytes,
        )?;
        let record_scratch = NodeRuntime::capture_serialization_storage(
            snapshot.record_data(),
            limits.state.maximum_total_content_bytes,
        )?;
        let decode = NodeRuntime::capture_restored_host17_decode_storage_data(
            &snapshot.encoded_data().bytes,
            limits.state.maximum_total_content_bytes,
        )?;
        let dependency_count = selected
            .restored_complete_capture_dependency_preflight17_data(&runtime_object.reference)?
            .maximum_dependency_count();
        let maximum_record_bytes = snapshot.encoded_data().bytes.len().max(4096);
        let mut retained = storage::add(
            NodeRuntime::capture_restored_host_record_storage_data(snapshot.record_data())?,
            storage::payload(snapshot.encoded_data())?,
        )?;
        // The actual restored node and its retained archive-backed Source are
        // independently present beside this prepared snapshot. This deliberately
        // grants no discount for another observer retaining the same Rc.
        retained = storage::add(
            retained,
            witness.restored17_node_requested_storage_data(limits.native.maximum_total_record_bytes)?,
        )?;
        // The pinned empty-Vec growth can retain twice the closed journal's
        // 4096-byte extent. Cumulative encoding requests are charged separately.
        retained = storage::add(retained, 8192)?;
        retained = storage::add(retained, NodeRuntime::capture_native_key_storage(&key)?)?;
        retained = storage::add(retained, selection.owner.owner.id.allocated_capacity())?;
        retained = storage::add(
            retained,
            selection
                .owner
                .owner
                .participant_ids
                .capacity()
                .checked_mul(std::mem::size_of::<Id>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for id in &selection.owner.owner.participant_ids {
            retained = storage::add(retained, id.allocated_capacity())?;
        }
        // Two independently owned content references accompany the journal.
        retained = storage::add(
            retained,
            NodeRuntime::capture_reference_storage(&runtime_object.reference)?,
        )?;
        retained = storage::add(
            retained,
            NodeRuntime::capture_reference_storage(&snapshot.encoded_data().reference)?,
        )?;
        let journal_encoding = 4usize
            .checked_mul(4096)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or(RuntimeError::ResourceLimit)?;
        let transient = storage::add(
            storage::add(record_scratch, journal_encoding)?,
            storage::add(
                decode,
                journal_scratch
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )?,
        )?;
        if maximum_record_bytes > limits.native.maximum_record_bytes
            || storage::add(retained, transient)? > limits.native.maximum_total_record_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(CompleteOriginalOwnerCapturePreflight {
            key,
            geometry: CompleteOriginalOwnerCaptureGeometry {
                owner: selection.owner.owner.id.clone(),
                participants: selection.owner.owner.participant_ids.clone(),
                maximum_record_bytes,
                maximum_objects: 2,
                maximum_retained_bytes: retained,
                maximum_dependency_edges: dependency_count,
                maximum_transient_bytes: transient,
            },
        })
    });
    prepared.authenticate_runtime_data(runtime, activation, runtime_object)?;
    let current = witness.original_capture_source()?;
    prepared.authenticate_host_data(current.as_ref())?;
    result
}
