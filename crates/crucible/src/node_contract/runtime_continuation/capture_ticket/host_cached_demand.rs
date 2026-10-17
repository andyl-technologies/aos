//! Derives allocation facts from the one genuine cached host producer.
//!
//! No portable record, regenerated snapshot or borrowed capability label can
//! issue this row. The same original runtime/node/source is checked before any
//! private snapshot borrow and after every fallible accounting operation.

use super::*;
use crate::node_contract::{HostSchedulingNodeWitness, NativeStateKey, NodeRuntime};
use crate::node_state::{
    CompleteOriginalOwnerCaptureGeometry, CompleteOriginalOwnerCapturePreflight,
    NativeArchiveLimits,
};
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

impl OriginalHostCapturePreparation {
    pub(crate) fn cached_demand(
        &self,
        runtime: &NodeRuntime,
        witness: &HostSchedulingNodeWitness<'_>,
        activation: &WorldActivation,
        original: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        limits: NativeArchiveLimits,
    ) -> Result<CompleteOriginalOwnerCapturePreflight, RuntimeError> {
        runtime.validate_activation(activation)?;
        self.authenticate_runtime(runtime)?;
        let current = witness.original_capture_source()?;
        let selected = self.source.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        if !Rc::ptr_eq(&current, selected) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let snapshot_guard = self
            .snapshot
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let snapshot = snapshot_guard
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        if !matches!(&snapshot.record().runtime, HostSchedulingRuntimeRecord::OriginalLineage(record) if record.as_ref() == original)
            || snapshot.record().source != *selected.selection()
            || snapshot.record().scheduling.world_binding_hash
                != activation.record().world_binding_hash
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
        let schema = selection
            .binding
            .compatibility
            .implementation
            .formats
            .iter()
            .find(|schema| {
                schema.id.as_str() == "source-owned.host-scheduling-continuation/2"
                    && schema.version == 2
            })
            .ok_or(RuntimeError::UnsupportedFacet)?
            .clone();
        let key = NativeStateKey {
            implementation: selection
                .binding
                .compatibility
                .implementation
                .implementation_id
                .clone(),
            profile: Id::new("source-owned.host-scheduling-original-lineage/2")
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            schema,
        };
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
            snapshot: &snapshot.encoded().reference,
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
            snapshot.record(),
            limits.state.maximum_total_content_bytes,
        )?;
        let decode = NodeRuntime::capture_host_decode_storage(
            &snapshot.encoded().bytes,
            limits.state.maximum_total_content_bytes,
        )?;
        let dependency_count = NodeRuntime::capture_host_dependency_count(
            &snapshot.encoded().bytes,
            limits.state.maximum_dependency_edges,
        )?;
        let maximum_record_bytes = snapshot.encoded().bytes.len().max(4096);
        let mut retained = storage::add(
            NodeRuntime::capture_host_record_storage(snapshot.record())?,
            storage::payload(snapshot.encoded())?,
        )?;
        // Count the actual retained original node (route/activation/readiness,
        // concrete Box; the source observer counts the anchor) independently of this cached snapshot. Source
        // metadata is charged once by the same daemon's original Rc observer.
        retained = storage::add(retained, witness.original_node_requested_storage()?)?;
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
            NodeRuntime::capture_reference_storage(&snapshot.encoded().reference)?,
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
        drop(snapshot_guard);
        self.authenticate_runtime(runtime)?;
        let current = witness.original_capture_source()?;
        if !Rc::ptr_eq(&current, selected) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(CompleteOriginalOwnerCapturePreflight {
            key,
            geometry: CompleteOriginalOwnerCaptureGeometry {
                owner: selection.owner.owner.id.clone(),
                participants: selection.owner.owner.participant_ids.clone(),
                maximum_record_bytes,
                maximum_objects: 2,
                maximum_retained_bytes: retained,
                maximum_dependency_edges: dependency_count
                    .checked_add(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
                maximum_transient_bytes: transient,
            },
        })
    }
}
