//! Keeps original native capsule publication knowledge aligned with durable CAS.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible::{
    node_contract::{
        ActivationPublisher, ActivationRecord, PreparedWorldPublication, PublicationStatus,
        RuntimeError, ValidatedNodePreparation,
    },
    node_scheduling::InputPayload,
    node_state::PublicationKnowledge,
};

use super::super::StoredWorldActivationPublisher;
use super::custody::Gem5CustodyQueue;

pub(super) struct NativeCustodyPublisher {
    pub(super) stored: StoredWorldActivationPublisher,
    pub(super) queue: Gem5CustodyQueue,
}

impl NativeCustodyPublisher {
    fn record_effect(
        &mut self,
        record: &ActivationRecord,
        action: impl FnOnce(&mut StoredWorldActivationPublisher) -> PublicationStatus,
    ) -> PublicationStatus {
        // Reserve uncertainty before entering the effecting callback. A callback
        // unwind cannot leave original native custody labeled NotAttempted.
        let committed = matches!(
            self.queue.publication_knowledge(record),
            Ok(PublicationKnowledge::Committed)
        );
        if !committed
            && self
                .queue
                .record_publication(record, PublicationKnowledge::Unknown)
                .is_err()
        {
            return PublicationStatus::Unknown;
        }
        let status = catch_unwind(AssertUnwindSafe(|| action(&mut self.stored)))
            .unwrap_or(PublicationStatus::Unknown);
        let knowledge = match status {
            PublicationStatus::Committed => PublicationKnowledge::Committed,
            PublicationStatus::NotCommitted => PublicationKnowledge::NotCommitted,
            PublicationStatus::Unknown => PublicationKnowledge::Unknown,
        };
        if committed && status != PublicationStatus::Committed {
            // Previously committed history cannot become NotAttempted merely
            // because the durable store is now unavailable or corrupt.
            return PublicationStatus::Unknown;
        }
        if self.queue.record_publication(record, knowledge).is_err() {
            return PublicationStatus::Unknown;
        }
        status
    }
}

impl ActivationPublisher for NativeCustodyPublisher {
    fn publish(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.record_effect(record, |stored| stored.publish(record))
    }

    fn reconcile(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.record_effect(record, |stored| stored.reconcile(record))
    }

    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        coordinator: InputPayload,
    ) -> Result<(), RuntimeError> {
        self.stored.retain_initial_coordinator(record, nodes, coordinator)
    }

    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.stored.prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.record_effect(record, |stored| stored.publish_complete(record, prepared))
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.record_effect(record, |stored| stored.reconcile_complete(record, prepared))
    }
}
