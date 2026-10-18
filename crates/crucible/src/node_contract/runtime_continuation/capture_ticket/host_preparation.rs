//! Retains the same original host closure before native administrative effects.
//!
//! The producer reads the actual runtime and original shared scheduler. No
//! portable body or source label creates this process-local preparation.

use super::*;
use crate::node_contract::{
    HostSchedulingContinuationLimits, HostSchedulingContinuationV2, HostSchedulingObservation,
    HostSchedulingRuntimeRecord, HostSchedulingSource,
};

#[path = "host_preparation_credit.rs"]
mod credit;
#[path = "host_cached_demand.rs"]
mod demand;

pub(crate) struct OriginalHostCapturePreparation {
    source: Option<Rc<HostSchedulingSource>>,
    snapshot: RefCell<Option<HostSchedulingContinuationV2>>,
}

impl crate::node_contract::NodeRuntime {
    pub(crate) fn precharge_original_host_capture(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        original: &OriginalLineageRuntimeRecord,
        scheduling: &crate::node_scheduling::SchedulingSnapshot,
        runtime_object: &InputPayload,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut found = None;
        for id in graph.node_ids() {
            let node = self.nodes.get(id).ok_or(RuntimeError::UnknownNode)?;
            if let Some(witness) = node.original_host_scheduling_owner() {
                if found.is_some() {
                    return Err(RuntimeError::UnsupportedFacet);
                }
                let source = witness.original_capture_source()?;
                self.authenticate_host_scheduling_source(&source)?;
                source
                    .authenticate_complete_preparation_source(source.world())
                    .map_err(|_| RuntimeError::UnsupportedFacet)?;
                let bytes =
                    credit::precharge(self, source.selection(), original, scheduling, maximum)?;
                self.authenticate_host_scheduling_source(&source)?;
                let dependencies =
                    source.precharge_capture_dependency_plan(self, runtime_object, maximum)?;
                let peak = storage::add(bytes, dependencies)?;
                if peak > maximum {
                    return Err(RuntimeError::ResourceLimit);
                }
                found = Some(peak);
            }
        }
        found.ok_or(RuntimeError::UnsupportedFacet)
    }
}

impl OriginalHostCapturePreparation {
    pub(crate) fn authenticate_runtime(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
    ) -> Result<(), RuntimeError> {
        let source = self.source.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        runtime.authenticate_host_scheduling_source(source)?;
        source
            .authenticate_complete_preparation_source(source.world())
            .map_err(|_| RuntimeError::UnsupportedFacet)
    }

    pub(crate) fn owned_snapshot_storage(&self) -> Result<usize, RuntimeError> {
        use super::owned::OwnedStorage;

        let snapshot = self
            .snapshot
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        // The preparation header remains owned after its sole snapshot moves
        // into the host capture result. Consumption never frees that Rc bank.
        let header = storage::shared_allocation::<Self>();
        snapshot.as_ref().map_or(Ok(header), |snapshot| {
            storage::add(
                header,
                storage::add(
                    snapshot.record().owned_storage()?,
                    storage::payload(snapshot.encoded())?,
                )?,
            )
        })
    }

    #[cfg(test)]
    pub(super) fn absent() -> Self {
        Self {
            source: None,
            snapshot: RefCell::new(None),
        }
    }

    pub(crate) fn prepare(
        runtime: &crate::node_contract::NodeRuntime,
        graph: &crate::node_admission::AdmittedGraph,
        original: &OriginalLineageRuntimeRecord,
        runtime_object: &InputPayload,
        lineage: OriginalInputLineageLimits,
        maximum_record_bytes: usize,
        maximum_total_bytes: usize,
    ) -> Result<Self, RuntimeError> {
        let mut host = None;
        for node in graph.node_ids() {
            let binding = graph.binding(node).ok_or(RuntimeError::UnknownNode)?;
            if binding
                .compatibility
                .implementation
                .implementation_id
                .as_str()
                != "source-owned.host-scheduling-owner/2"
            {
                continue;
            }
            if host.is_some() {
                return Err(RuntimeError::UnsupportedFacet);
            }
            let witness = runtime
                .nodes
                .get(node)
                .ok_or(RuntimeError::UnknownNode)?
                .original_host_scheduling_owner()
                .ok_or(RuntimeError::ForeignAuthority)?;
            let source = witness.original_capture_source()?;
            runtime.authenticate_host_scheduling_source(&source)?;
            let snapshot = HostSchedulingObservation::new(runtime, &source)?.continuation_v2(
                original.capture_cut,
                original.capture_ordinal,
                HostSchedulingContinuationLimits {
                    maximum_record_bytes,
                    lineage,
                },
            )?;
            if !matches!(&snapshot.record().runtime,
                HostSchedulingRuntimeRecord::OriginalLineage(record) if record.as_ref() == original)
                || &snapshot.record().source != source.selection()
            {
                return Err(RuntimeError::InvalidReceipt);
            }
            runtime.authenticate_host_scheduling_source(&source)?;
            source.prepare_capture_dependency_plan(
                &snapshot,
                runtime_object,
                maximum_total_bytes,
            )?;
            runtime.authenticate_host_scheduling_source(&source)?;
            host = Some((source, snapshot));
        }
        let (source, snapshot) = host.ok_or(RuntimeError::UnsupportedFacet)?;
        Ok(Self {
            source: Some(source),
            snapshot: RefCell::new(Some(snapshot)),
        })
    }

    /// Lends the original scheduling snapshot before any owner takes it.
    ///
    /// The same host and runtime are checked after callback refusal as well as
    /// success. This loan performs no model work and transfers no custody.
    ///
    /// # Errors
    /// Refuses foreign or inactive host/runtime custody, a consumed preparation,
    /// or changed ownership across the callback.
    pub(super) fn with_original_scheduling_data<R>(
        &self,
        runtime: &crate::node_contract::NodeRuntime,
        activation: &WorldActivation,
        inspect: impl FnOnce(
            &HostSchedulingSource,
            &crate::node_scheduling::SchedulingSnapshot,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.authenticate_runtime(runtime)?;
        runtime.validate_activation(activation)?;
        let source = self.source.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if source.world() != &activation.record().world_binding_hash {
            return Err(RuntimeError::ForeignAuthority);
        }
        let snapshot = self
            .snapshot
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let snapshot = snapshot
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)?;
        if &snapshot.record().source != source.selection() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let result = inspect(source, &snapshot.record().scheduling);
        self.authenticate_runtime(runtime)?;
        runtime.validate_activation(activation)?;
        source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        result
    }

    pub(super) fn take(
        &self,
        source: &HostSchedulingSource,
        owner: &OwnerIdentity,
        activation: &WorldActivation,
    ) -> Result<HostSchedulingContinuationV2, RuntimeError> {
        source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let original = self.source.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        if !std::ptr::eq(original.as_ref(), source)
            || source.selection().owner.owner.id != owner.owner
            || source.selection().binding.authority.incarnation_id != owner.incarnation
            || source.selection().binding.authority.owner_generation != owner.generation
            || source.world() != &activation.record().world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut snapshot = self
            .snapshot
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        source
            .authenticate_current()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        snapshot.take().ok_or(RuntimeError::OutstandingObligations)
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn consumed_preparation_keeps_its_reference_counted_bank_charged() {
        // This absent capsule is inert modeled data, never an original producer.
        let preparation = OriginalHostCapturePreparation::absent();
        assert_eq!(
            preparation.owned_snapshot_storage(),
            Ok(storage::shared_allocation::<OriginalHostCapturePreparation>())
        );
    }
}
