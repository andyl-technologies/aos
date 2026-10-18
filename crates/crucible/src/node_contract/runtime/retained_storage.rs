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
    pub(crate) fn retained_shared_storage_data(&self) -> Result<usize, RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || self.authority.upgrade().is_none()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(NodeRuntime::capture_shared_allocation_storage::<()>())
    }

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
    pub(crate) fn authenticate_original_restoration_target_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        source.inner.authenticate_birth()?;
        if self.activated
            || !self.barrier.can_arm()
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.terminal.is_some()
            || self.condition_stop.is_some()
            || !self.original_capture_attempts.is_empty()
            || self.barrier.record() != activation
            || activation.owners.len() != 4
            || !self
                .collecting
                .as_ref()
                .is_some_and(|graph| graph.plan().is_same_original_plan_data(plan))
            || !source
                .inner
                .collecting_plan()?
                .is_some_and(|original| original.is_same_original_plan_data(plan))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.scheduler
            .as_ref()
            .ok_or(RuntimeError::UnsupportedFacet)?
            .authenticate(&self.authority, &activation.world_binding_hash)?;
        if let Some(history) = &self.original_capture_history {
            if !Rc::ptr_eq(history, &source.inner) {
                return Err(RuntimeError::ForeignAuthority);
            }
            source.inner.authenticate_target(&self.authority)?;
        }
        Ok(())
    }

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
        self.retained_requested_storage_inner(maximum, false, None)
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
        self.retained_requested_storage_inner(maximum, true, None)
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
        child = child.max(super::coordinator_commitment::counter_scratch_data());
        scheduler
            .authenticate_retained(&self.authority, &self.barrier.record().world_binding_hash)?;
        size_of::<RetainedRuntimeCounter>()
            .checked_add(child)
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Counts the same runtime with an optional actual initial Source roster.
    ///
    /// # Errors
    /// Preserves all scheduler, owner, metadata and requested-bound refusals.
    pub(super) fn retained_requested_storage_inner(
        &self,
        maximum: usize,
        precredit: bool,
        initial_sources: Option<&[Rc<crate::node_adapters::cnp::PacketCompleteSemanticSource>; 3]>,
    ) -> Result<usize, RuntimeError> {
        use crate::node_adapters::cnp::CnpSemanticSource;

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
                // Only the authenticated initial roster uses the distinct
                // initial-lifecycle Source census below. Its graph follows the
                // same precredit authority walk as the pre-runtime graph owner.
                if precredit && initial_sources.is_some() {
                    graph.charge_original_retained_storage_precredit_data(&mut counter)?;
                } else {
                    graph.charge_original_retained_storage(&mut counter)?;
                }
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
                match initial_sources.and_then(|sources| {
                    sources
                        .iter()
                        .find(|source| source.installation().descriptor.id == *key)
                }) {
                    Some(source) => node
                        .retained_original_initial_requested_storage_precredit_data(
                            source, maximum,
                        )?,
                    None => node.retained_requested_storage_precredit_data(maximum)?,
                }
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

impl NodeRuntime {
    pub(crate) fn quote_original_restoration_node_data(
        &self,
        inputs: &crate::node_admission::OriginalRestorationNodeInputs<'_>,
    ) -> Result<crate::node_admission::OriginalRestorationNodeConstructionData, RuntimeError> {
        let owner = inputs.ticket.owner()?;
        let [node_id] = owner.participants.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        self.nodes
            .get(node_id)
            .ok_or(RuntimeError::UnknownNode)?
            .original_restoration_construction_data(inputs)?
            .ok_or(RuntimeError::UnsupportedFacet)
    }

    pub(crate) fn original_restoration_node_counter_scratch_data(
        &self,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
    ) -> Result<usize, RuntimeError> {
        let [node] = ticket.owner()?.participants.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        self.nodes
            .get(node)
            .ok_or(RuntimeError::UnknownNode)?
            .original_restoration_construction_scratch_data()?
            .ok_or(RuntimeError::UnsupportedFacet)
    }
}

impl NodeRuntime {
    pub(crate) fn begin_original_restoration_transaction(
        &mut self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<OriginalRuntimeStorageIdentity, RuntimeError> {
        self.authenticate_original_restoration_target_data(source, plan, activation)?;
        ticket.authenticate_source(source)?;
        // Spend before the first legacy currentness/owning-node callback. The
        // fully admitted caller retains this runtime, source and ticket on error.
        ticket.begin_original_restoration_transaction_data(&self.authority)?;
        if self.original_capture_history.is_none() {
            self.original_capture_history = Some(Rc::clone(&source.inner));
        }

        let checked = (|| {
            self.authenticate_complete_restoration_purpose(Some(plan))?;
            let mut host_seen = false;
            for node in self.nodes.values() {
                if let Some(host) = node.original_host_scheduling_owner() {
                    if host_seen {
                        return Err(RuntimeError::ForeignAuthority);
                    }
                    host.authenticate_archive_target(&source.inner, &self.authority)?;
                    host_seen = true;
                }
            }
            if !host_seen {
                return Err(RuntimeError::UnsupportedFacet);
            }
            self.authenticate_original_restoration_target_data(source, plan, activation)?;
            self.original_retained_storage_identity()
        })();
        if checked.is_err() {
            self.contain_roster(&NodeRoute {
                node: activation.activation_id.clone(),
                owners: activation.owners.clone(),
            });
        }
        checked
    }

    pub(crate) fn authenticate_original_restoration_transaction_data(
        &self,
        source: &crate::node_state::CompleteOriginalRestorationSource,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &ActivationRecord,
        identity: &OriginalRuntimeStorageIdentity,
    ) -> Result<(), RuntimeError> {
        identity.authenticate(self)?;
        self.authenticate_original_restoration_target_data(source, plan, activation)?;
        ticket.authenticate_source(source)?;
        if !self
            .original_capture_history
            .as_ref()
            .is_some_and(|original| Rc::ptr_eq(original, &source.inner))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        ticket.authenticate_original_restoration_transaction_data(&self.authority)
    }
}

#[path = "retained_storage/restoration_identity.rs"]
mod restoration_identity;
pub(crate) use restoration_identity::OriginalRestorationRuntimeMemberIdentity;

impl NodeRuntime {
    pub(crate) fn execute_original_restoration_node_dispatch(
        &mut self,
        dispatch: crate::node_admission::OriginalRestorationNodeDispatch<'_>,
    ) -> Result<(), RuntimeError> {
        let [node] = dispatch.ticket_data()?.owner()?.participants.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        self.nodes
            .get_mut(node)
            .ok_or(RuntimeError::UnknownNode)?
            .execute_original_restoration_transaction(dispatch)
    }
}

impl NodeRuntime {
    pub(crate) fn inspect_original_restoration_node_continuation(
        &self,
        inspection: crate::node_admission::OriginalRestorationNodeContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        let [node] = inspection.ticket_data()?.owner()?.participants.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        self.nodes
            .get(node)
            .ok_or(RuntimeError::UnknownNode)?
            .inspect_original_restoration_continuation(inspection)
    }
}

impl NodeRuntime {
    pub(crate) fn inspect_original_host_restoration_continuation(
        &self,
        inspection: crate::node_admission::OriginalRestorationHostContinuationInspection<'_>,
    ) -> Result<(), RuntimeError> {
        let node = inspection.node_data()?;
        let actual = self.nodes.get(node).ok_or(RuntimeError::UnknownNode)?;
        let snapshot = self.snapshots.get(node).ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(actual.as_ref())?;
        actual.inspect_original_host_restoration_continuation(&inspection)?;
        snapshot.validate_current(actual.as_ref())?;
        inspection.authenticate_current()
    }
}

impl NodeRuntime {
    pub(crate) fn activate_original_installed_restoration_node_world(
        &mut self,
        node: &Id,
        world: &WorldActivation,
    ) -> Result<(), RuntimeError> {
        self.nodes
            .get_mut(node)
            .ok_or(RuntimeError::UnknownNode)?
            .activate_original_installed_restoration_world(world)
    }

    pub(crate) fn original_installed_world_dispatch_counter_scratch_data() -> usize {
        size_of::<&mut Self>()
            + size_of::<&Id>()
            + size_of::<&WorldActivation>()
            + size_of::<Option<&mut Box<dyn SimulationNode>>>()
            + size_of::<Result<&mut Box<dyn SimulationNode>, RuntimeError>>()
            + size_of::<&mut Box<dyn SimulationNode>>()
            + size_of::<&mut dyn SimulationNode>()
            + size_of::<Result<(), RuntimeError>>()
    }
}
