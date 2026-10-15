//! Walks the actual original runtime owners under one immutable origin loan.
//!
//! Portable Runtime7/Scheduling records are independent archive owners. This
//! module observes the live maps, retained operations, actual node Boxes and
//! shared activation/custody allocations instead. Requested storage is distinct
//! from allocator residency, native memory, kernel objects and compiler frames.

use std::mem::{size_of, size_of_val};

use super::*;
use crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter;
use crate::node_contract::{condition_debug, terminal};

/// Binds an internal storage requery to the original runtime allocation.
///
/// This process-local weak alias creates no new allocation or live authority.
/// The same runtime's retained observer still checks all actual owning fields.
pub(crate) struct OriginalRuntimeStorageIdentity {
    process: u32,
    thread: std::thread::ThreadId,
    authority: std::rc::Weak<()>,
}

impl OriginalRuntimeStorageIdentity {
    /// Checks the original creator and exact retained runtime allocation.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, released owner or another runtime.
    pub(crate) fn authenticate(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let original = self
            .authority
            .upgrade()
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(&original, &runtime.authority) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl NodeRuntime {
    /// Retains the original allocation identity for an internal storage budget.
    ///
    /// # Errors
    /// Refuses absent scheduling custody, another creator or lost authority.
    pub(crate) fn original_retained_storage_identity(
        &self,
    ) -> Result<OriginalRuntimeStorageIdentity, RuntimeError> {
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)?;
        Ok(OriginalRuntimeStorageIdentity {
            process: std::process::id(),
            thread: std::thread::current().id(),
            authority: Rc::downgrade(&self.authority),
        })
    }

    /// Bounds requested storage of this same original runtime's actual owners.
    ///
    /// This synchronous data observation borrows the original owners and does
    /// not clone a snapshot, submit native work, drop custody or mint permission.
    /// Each independent capacity and ordered-tree backing remains charged. Only
    /// identical live shared-allocation addresses with identical complete widths
    /// deduplicate; equal data in another allocation remains independent. Closed
    /// erased-owner reports conservatively repeat shared banks when their local
    /// observer cannot expose a compatible complete allocation descriptor.
    ///
    /// Erased nodes and supervisor slots require their original typed backing
    /// observers. Unsupported ownership states refuse rather than receive zero
    /// credit. Native/process/compiler/allocator physical terms and the fixed
    /// observer scratch are separate simultaneous terms for the calling factory.
    ///
    /// # Errors
    /// Refuses foreign creator custody, busy originals, unsupported owners,
    /// conflicting shared widths, exhausted traversal storage or the bound.
    pub fn original_retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.retained_requested_storage_inner(maximum, false)
    }

    /// Observes actual owners using only closed typed precredit node callbacks.
    ///
    /// Unknown node implementations refuse, even if their legacy string-error
    /// observer supports a later credited inspection. This method grants no
    /// allocation or execution permission; its fixed scratch must be admitted
    /// separately before the walk.
    ///
    /// # Errors
    /// Refuses unsupported typed owners, foreign origin, busy originals,
    /// conflicting shared widths or the requested bound.
    pub fn original_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original_retained_requested_storage_precredit_scratch_data()?;
        self.retained_requested_storage_inner(maximum, true)
    }

    /// Names simultaneous fixed counters for this closed typed owning walk.
    ///
    /// Child observations are sequential, so their largest explicit term is
    /// live beside the runtime counter. Compiler/recursive frames, native or
    /// kernel storage and physical allocator residency remain separate.
    ///
    /// # Errors
    /// Refuses foreign scheduling custody, unknown node scratch or overflow.
    pub fn original_retained_requested_storage_precredit_scratch_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let scheduler = self
            .scheduler
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?;
        scheduler
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)?;
        let mut child = 0usize;
        for node in self.nodes.values() {
            child = child.max(
                node.retained_requested_storage_precredit_scratch_data()?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            );
        }
        if let Some(slot) = &self.custody_slot {
            child = child.max(
                slot.retained_requested_storage_precredit_scratch_data()?
                    .ok_or(RuntimeError::UnsupportedFacet)?,
            );
        }
        child = child.max(super::opaque_owner_counter_scratch_data());
        scheduler
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)?;
        size_of::<RetainedRuntimeCounter>()
            .checked_add(child)
            .ok_or(RuntimeError::ResourceLimit)
    }

    fn retained_requested_storage_inner(
        &self,
        maximum: usize,
        precredit: bool,
    ) -> Result<usize, RuntimeError> {
        // Authenticate the retained original before following its owner graph.
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)?;
        let Self {
            authority,
            nodes,
            snapshots,
            owners,
            operations,
            input_batches,
            barrier,
            activated: _,
            limits: _,
            scheduler,
            custody_slot,
            terminal,
            condition_stop,
            collecting,
            graceful_retirement: _,
            original_error_site: _,
            original_capture_history: _,
            original_capture_attempts: _,
        } = self;
        let scheduler = scheduler.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.add(size_of::<Self>())?;
        counter.rc(authority)?;
        charge_snapshots(snapshots, &mut counter)?;
        counter.map(owners)?;
        for (key, owner) in owners {
            let OwnerCustody {
                identity,
                lifecycle: _,
                operation,
                domains,
            } = owner;
            counter.owned(key)?;
            counter.owned(identity)?;
            counter.owned(operation)?;
            counter.set(domains)?;
            for domain in domains {
                counter.owned(domain)?;
            }
        }
        counter.map(operations)?;
        for (key, operation) in operations {
            counter.owned(key)?;
            charge_operation(operation, &mut counter)?;
        }
        counter.map(input_batches)?;
        for (key, input) in input_batches {
            counter.owned(key)?;
            charge_input(input, &mut counter)?;
        }
        barrier.charge_original_retained_storage(&mut counter)?;
        scheduler.charge_original_retained_storage(&mut counter)?;
        if let Some(graph) = collecting {
            if counter.rc(graph)? {
                graph.charge_original_retained_storage(&mut counter)?;
            }
        }

        if let Some(terminal) = terminal {
            let terminal::TerminalState { saved } = terminal;
            counter.owned(saved)?;
        }
        if let Some(condition) = condition_stop {
            let condition_debug::ConditionStopState {
                saved,
                publication_verified_for,
            } = condition;
            counter.owned(saved)?;
            counter.owned(publication_verified_for)?;
        }
        let capture = self.retained_original_capture_buffer_bytes()?;
        counter.add(
            capture
                .checked_sub(size_of_val(&self.original_capture_attempts))
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        self.charge_original_capture_activation_backings(&mut counter)?;

        counter.map(nodes)?;
        for (key, node) in nodes {
            counter.owned(key)?;
            counter.add(size_of_val(node.as_ref()))?;
            let backing = if precredit {
                node.retained_requested_storage_precredit_data(maximum)?
            } else {
                node.retained_requested_storage_data(maximum)
                    .map_err(|_| RuntimeError::UnsupportedFacet)?
            }
            .ok_or(RuntimeError::UnsupportedFacet)?;
            counter.add(backing)?;
        }
        if let Some(slot) = custody_slot {
            counter.add(size_of_val(slot.as_ref()))?;
            let backing = slot
                .retained_requested_storage_data(maximum)?
                .ok_or(RuntimeError::UnsupportedFacet)?;
            counter.add(backing)?;
        }
        scheduler.authenticate_retained(authority, &barrier.record().world_binding_hash)?;
        Ok(counter.bytes())
    }

    /// Returns the actual inline identity-bank scratch of the owning walk.
    ///
    /// This is not a compiler stack or recursive traversal bound. The caller
    /// charges it beside all retained owners and separately covers real frames.
    pub fn original_retained_requested_storage_scratch_bytes() -> usize {
        size_of::<RetainedRuntimeCounter>()
    }
}

fn charge_operation(
    value: &RetainedOperation,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let RetainedOperation {
        admission,
        result,
        close_submission,
        submission_effects,
        scheduling_commit,
    } = value;
    let facts = admission.retained_requested_storage_data(counter.maximum())?;
    counter.views(
        facts.independent_bytes(),
        facts
            .shared_allocations()
            .map(|row| (row.identity(), row.requested_bytes())),
    )?;
    match result {
        RetainedResult::Pending => {}
        RetainedResult::Complete(value) | RetainedResult::Acknowledged(value) => {
            counter.owned(value)?
        }
        RetainedResult::Failed(value) => counter.owned(value)?,
    }
    if let Some(submission) = close_submission {
        match submission {
            Submission::Accepted => {}
            Submission::Refused(value) => counter.owned(&value.reason)?,
            Submission::Uncertain(value) => counter.owned(value)?,
        }
    }
    counter.owned(submission_effects)?;
    if let Some(commit) = scheduling_commit {
        let crate::node_scheduling::SchedulingCommit {
            activation,
            node,
            operation,
            retained_outputs,
        } = commit;
        counter.activation(activation)?;
        counter.owned(node)?;
        counter.owned(operation)?;
        counter.owned(retained_outputs)?;
    }
    Ok(())
}

fn charge_input(
    value: &inputs::RetainedInput,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let inputs::RetainedInput {
        batch,
        provenance,
        lineage,
        acknowledgement,
        failure,
        committed: _,
        commit,
    } = value;
    let facts = batch.retained_requested_storage_data(counter.maximum())?;
    counter.views(
        facts.independent_bytes(),
        facts
            .shared_allocations()
            .map(|row| (row.identity(), row.requested_bytes())),
    )?;
    if let Some(provenance) = provenance {
        counter.activation(provenance.activation())?;
        let super::SavedInputProvenance {
            schema_version: _,
            node,
            stage_operation,
            batch,
            inventory,
            roots,
            objects,
        } = provenance.saved();
        counter.owned(node)?;
        counter.owned(stage_operation)?;
        counter.owned(batch)?;
        counter.owned(inventory)?;
        counter.owned(roots)?;
        counter.owned(objects)?;
    }
    if let Some(lineage) = lineage {
        let facts = NodeRuntime::capture_original_lineage_storage_data(lineage, counter.maximum())?;
        counter.views(
            facts.independent_bytes(),
            facts
                .shared_allocations()
                .map(|row| (row.identity(), row.requested_bytes())),
        )?;
    }
    counter.owned(acknowledgement)?;
    counter.owned(failure)?;
    if let Some(commit) = commit {
        let facts = commit.retained_requested_storage_data(counter.maximum())?;
        counter.views(
            facts.independent_bytes(),
            facts
                .shared_allocations()
                .map(|row| (row.identity(), row.requested_bytes())),
        )?;
    }
    Ok(())
}

fn charge_snapshots(
    snapshots: &BTreeMap<crucible_node_contract::NodeId, NodeSnapshot>,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    counter.map(snapshots)?;
    for (key, snapshot) in snapshots {
        let NodeSnapshot {
            descriptor,
            binding,
            route,
            facets,
            thread_affinity: _,
        } = snapshot;
        counter.owned(key)?;
        counter.owned(descriptor)?;
        counter.owned(binding)?;
        counter.owned(route)?;
        counter.slots(facets)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_frozen_snapshot_spare_string_storage_is_observed_without_changing_labels()
    -> Result<(), RuntimeError> {
        let (mut runtime, _) = crate::node_contract::runtime::tests::capture_ticket_fixture();
        let mut first = RetainedRuntimeCounter::new(32 * 1024 * 1024);
        charge_snapshots(&runtime.snapshots, &mut first)?;
        let snapshot = runtime
            .snapshots
            .values_mut()
            .next()
            .ok_or(RuntimeError::UnknownNode)?;
        let original = snapshot.descriptor.id.clone();
        let old_capacity = snapshot.descriptor.id.allocated_capacity();
        let mut spelling = String::with_capacity(65536);
        spelling.push_str(original.as_str());
        snapshot.descriptor.id = Id::new(spelling).map_err(|_| RuntimeError::InvalidReceipt)?;
        assert_eq!(snapshot.descriptor.id, original);
        let difference = snapshot.descriptor.id.allocated_capacity() - old_capacity;

        let mut second = RetainedRuntimeCounter::new(32 * 1024 * 1024);
        charge_snapshots(&runtime.snapshots, &mut second)?;
        assert_eq!(second.bytes() - first.bytes(), difference);
        assert_eq!(runtime.snapshots.len(), runtime.nodes.len());
        Ok(())
    }

    #[test]
    fn real_runtime_retains_original_owners_when_a_backing_observer_refuses()
    -> Result<(), RuntimeError> {
        let (runtime, _) = crate::node_contract::runtime::tests::capture_ticket_fixture();
        let aliases = Rc::strong_count(&runtime.authority);
        let operations = runtime.operations.len();
        assert_eq!(
            runtime.original_retained_requested_storage_data(64 * 1024 * 1024),
            Err(RuntimeError::UnsupportedFacet),
        );
        assert_eq!(Rc::strong_count(&runtime.authority), aliases);
        assert_eq!(runtime.operations.len(), operations);
        assert!(runtime.original_capture_attempts.is_empty());
        Ok(())
    }

    #[test]
    fn terminal_reference_only_encoding_does_not_hide_original_scheduler_or_native_slot_capacity()
    -> Result<(), RuntimeError> {
        let (runtime, source) = crate::node_contract::runtime::tests::capture_ticket_fixture();
        let node = runtime
            .snapshots
            .keys()
            .next()
            .ok_or(RuntimeError::UnknownNode)?
            .clone();
        let mut record = crate::node_contract::WorldTerminalRecord {
            version: 1,
            operation: Id::new("original/terminal-storage")
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            node,
            cut: source.source_activation.boundary,
            source: source.source_activation,
            scheduler: crucible_node_contract::Bytes::default(),
            native: Vec::new(),
        };
        let before = record.owned_storage()?;
        let scheduler = Vec::with_capacity(8192);
        let scheduler_capacity = scheduler.capacity();
        record.scheduler = crucible_node_contract::Bytes::new(scheduler);
        record.native = Vec::with_capacity(7);
        let expected = scheduler_capacity
            + record.native.capacity() * size_of::<crate::node_contract::NativeTerminalInventory>();
        assert_eq!(record.owned_storage()? - before, expected);
        let actual = record.owned_storage()?;
        let mut one_short = RetainedRuntimeCounter::new(actual - 1);
        assert_eq!(one_short.owned(&record), Err(RuntimeError::ResourceLimit));
        assert!(record.scheduler.as_slice().is_empty());
        assert!(record.native.is_empty());
        Ok(())
    }
}
