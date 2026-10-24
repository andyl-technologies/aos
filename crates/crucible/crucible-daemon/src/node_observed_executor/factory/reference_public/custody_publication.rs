//! Forwards durable complete publication into the same original public peer slot.
//!
//! The original queue records uncertainty before storage can take effect. Its
//! private launch and negotiated journals remain owned on refusal or unwind;
//! positive committed history survives later storage outages.

use std::panic::{AssertUnwindSafe, catch_unwind};

use crucible_engine::{
    node_contract::{
        ActivationPublisher, ActivationRecord, PreparedWorldPublication, PublicationStatus,
        RuntimeError, ValidatedNodePreparation,
    },
    node_scheduling::InputPayload,
};

use super::custody::PublicReferenceCustodyQueue;

pub(super) struct PublicReferenceCustodyPublisher<P> {
    stored: P,
    queue: PublicReferenceCustodyQueue,
}

impl<P> PublicReferenceCustodyPublisher<P> {
    pub(super) fn new(stored: P, queue: PublicReferenceCustodyQueue) -> Self {
        Self { stored, queue }
    }

    fn record_effect(
        &mut self,
        record: &ActivationRecord,
        action: impl FnOnce(&mut P) -> PublicationStatus,
    ) -> PublicationStatus {
        let committed = match self.queue.publication(record) {
            Ok(status) => status == Some(PublicationStatus::Committed),
            Err(_) => return PublicationStatus::Unknown,
        };
        if self
            .queue
            .record_scope_publication(record, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }

        let status = catch_unwind(AssertUnwindSafe(|| action(&mut self.stored)))
            .unwrap_or(PublicationStatus::Unknown);
        if committed && status != PublicationStatus::Committed {
            return PublicationStatus::Unknown;
        }
        if self.queue.record_scope_publication(record, status).is_err() {
            return PublicationStatus::Unknown;
        }
        status
    }
}

impl<P: ActivationPublisher> ActivationPublisher for PublicReferenceCustodyPublisher<P> {
    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        coordinator: InputPayload,
    ) -> Result<(), RuntimeError> {
        self.queue
            .publication(record)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.stored
            .retain_initial_coordinator(record, nodes, coordinator)
    }

    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.queue
            .publication(record)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.stored.prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        if self
            .queue
            .record_publication(record, prepared, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        self.record_effect(record, |stored| stored.publish_complete(record, prepared))
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        if self
            .queue
            .record_publication(record, prepared, PublicationStatus::Unknown)
            .is_err()
        {
            return PublicationStatus::Unknown;
        }
        self.record_effect(record, |stored| stored.reconcile_complete(record, prepared))
    }

    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::NotCommitted
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }
}

#[cfg(test)]
#[path = "custody_publication_tests.rs"]
mod tests;
