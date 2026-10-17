//! Fences each collecting publication callback with the original current scope.
//!
//! The ordinary runtime publication path remains independent. Callback refusal
//! or revocation retains the original barrier and native owners; a historically
//! committed storage effect cannot mint fresh collecting activation permission.

use crate::node_admission::ConformanceGraph;
use crate::node_scheduling::InputPayload;

use super::*;
use crate::node_contract::{PreparedWorldPublication, PublicationStatus};

struct CurrentPublisher<'a> {
    graph: &'a ConformanceGraph,
    nodes: &'a BTreeMap<NodeId, Box<dyn SimulationNode>>,
    snapshots: &'a BTreeMap<NodeId, NodeSnapshot>,
    publisher: &'a mut dyn ActivationPublisher,
}

impl CurrentPublisher<'_> {
    fn current(&self) -> Result<(), RuntimeError> {
        self.graph
            .reauthenticate()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))?;
        for (id, node) in self.nodes {
            let snapshot = self.snapshots.get(id).ok_or(RuntimeError::UnknownNode)?;
            snapshot.validate_current(node.as_ref())?;
            if !node
                .collection_scope()
                .is_some_and(|plan| plan.same_original(self.graph.plan()))
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            node.validate_collection_scope(self.graph.plan())
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            snapshot.validate_current(node.as_ref())?;
        }
        // Native callbacks can revoke the same installed plan while returning
        // success. Reauthenticate after them, before the next storage effect.
        self.graph
            .reauthenticate()
            .map_err(|error| RuntimeError::SchedulerRefused(error.message))
    }

    fn publication(
        &mut self,
        callback: impl FnOnce(&mut dyn ActivationPublisher) -> PublicationStatus,
    ) -> PublicationStatus {
        if self.current().is_err() {
            return PublicationStatus::Unknown;
        }
        let status = callback(self.publisher);
        if self.current().is_err() {
            // The underlying original may already be durable. Keep its uncertain
            // custody rather than relabeling that effect as a fresh noncommit.
            return PublicationStatus::Unknown;
        }
        status
    }
}

impl ActivationPublisher for CurrentPublisher<'_> {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.current()?;
        let coordinator = self.publisher.prepare_coordinator(record, nodes)?;
        self.current()?;
        Ok(coordinator)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.publication(|publisher| publisher.publish_complete(record, prepared))
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.publication(|publisher| publisher.reconcile_complete(record, prepared))
    }

    fn publish(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.publication(|publisher| publisher.publish(record))
    }

    fn reconcile(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.publication(|publisher| publisher.reconcile(record))
    }
}

impl NodeRuntime {
    pub(in crate::node_contract) fn activate_collection(
        &mut self,
        graph: &ConformanceGraph,
        publisher: &mut dyn ActivationPublisher,
    ) -> Result<WorldActivation, RuntimeError> {
        if !graph.graph.collecting
            || graph.graph.world_binding_hash() != &self.barrier.record().world_binding_hash
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if !self.activated
            && self
                .owners
                .values()
                .any(|owner| owner.lifecycle != Lifecycle::Prepared)
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.validate_all_declarations()?;
        let mut current = CurrentPublisher {
            graph,
            nodes: &self.nodes,
            snapshots: &self.snapshots,
            publisher,
        };
        current.current()?;
        let activation = self.barrier.publish(&self.authority, &mut current)?;
        current.current()?;
        self.finish_activation();
        Ok(activation)
    }
}
