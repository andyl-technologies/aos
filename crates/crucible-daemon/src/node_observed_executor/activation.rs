//! Durably records an exact complete-world activation before native RUN.

use std::sync::Arc;

use crucible::node_contract::{
    ActivationPublisher, ActivationRecord, PublicationStatus, SavedRuntimeActivation,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MutableRefBackend, ObjectKind, RefCasOutcome,
    RefName, StoreError,
};
use crucible_node_contract::canonical;

mod complete;

/// Publishes an activation event into durable content and an immutable ref slot.
///
/// The slot is write-once. A repeated exact record reconciles to the same bytes;
/// an existing different generation is refused, never replaced or relabeled.
/// Both `node-world-activations/` and `node-world-coordinators/` belong to the
/// daemon's ordinary authoritative ref inventory and publication/GC fence.
pub struct StoredWorldActivationPublisher {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
    reference: RefName,
    prepared: Option<complete::PreparedCoordinator>,
}

impl StoredWorldActivationPublisher {
    /// Creates a publisher bound to one native execution's write-once slot.
    ///
    /// # Errors
    /// Refuses a malformed activation namespace or nondurable mutable refs.
    /// Publication also fails closed without durable immutable bytes and atomic
    /// reference placement. A memory-only ref never becomes activation authority.
    pub fn new(
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
        reference: RefName,
    ) -> Result<Self, StoreError> {
        // Keep this namespace distinct from campaign dispatch and legacy state.
        if !refs.capabilities().durable {
            return Err(StoreError::Incompatible);
        }
        if !reference.as_str().starts_with("node-world-activations/") {
            return Err(StoreError::InvalidRefName {
                value: reference.as_str().to_owned(),
            });
        }
        Ok(Self {
            blobs,
            refs,
            reference,
            prepared: None,
        })
    }

    fn record_bytes(record: &ActivationRecord) -> Option<Vec<u8>> {
        let value = serde_json::json!({
            "format": "crucible.node-world-activation", "version": 1,
            "activation": SavedRuntimeActivation::from(record),
        });
        canonical::canonical_json(&value).ok()
    }

    fn reconcile_exact(&self, record: &ActivationRecord) -> PublicationStatus {
        let Some(bytes) = Self::record_bytes(record) else {
            return PublicationStatus::NotCommitted;
        };
        let expected = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        match self.refs.read_ref(&self.reference) {
            Ok(None) => PublicationStatus::NotCommitted,
            Ok(Some(actual)) if actual == expected => match self
                .blobs
                .read(actual, None)
                .and_then(|handle| handle.read_all(1024 * 1024))
            {
                Ok(actual_bytes) if actual_bytes == bytes => PublicationStatus::Committed,
                _ => PublicationStatus::Unknown,
            },
            Ok(Some(_)) => PublicationStatus::NotCommitted,
            Err(_) => PublicationStatus::Unknown,
        }
    }
}

impl ActivationPublisher for StoredWorldActivationPublisher {
    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<crucible::node_contract::ValidatedNodePreparation>,
        coordinator: crucible::node_scheduling::InputPayload,
    ) -> Result<(), crucible::node_contract::RuntimeError> {
        self.retain_coordinator(record.clone(), nodes, coordinator)
            .map_err(|_| crucible::node_contract::RuntimeError::PublicationFailed)
    }

    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[crucible::node_contract::ValidatedNodePreparation],
    ) -> Result<crucible::node_scheduling::InputPayload, crucible::node_contract::RuntimeError>
    {
        self.prepare_complete_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &crucible::node_contract::PreparedWorldPublication,
    ) -> PublicationStatus {
        self.publish_complete_record(record, prepared)
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &crucible::node_contract::PreparedWorldPublication,
    ) -> PublicationStatus {
        self.reconcile_complete_record(record, prepared)
    }

    fn publish(&mut self, record: &ActivationRecord) -> PublicationStatus {
        let Some(bytes) = Self::record_bytes(record) else {
            return PublicationStatus::NotCommitted;
        };
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return PublicationStatus::Unknown;
        };
        let receipt = self.blobs.put_if_absent(id, &BlobHandle::from_bytes(bytes));
        if !matches!(receipt, Ok(ref receipt) if receipt.is_durable()) {
            return PublicationStatus::NotCommitted;
        }
        match self.refs.compare_exchange(&self.reference, None, id) {
            Ok(RefCasOutcome::Advanced { next }) if next == id => self.reconcile_exact(record),
            Ok(RefCasOutcome::Conflict {
                current: Some(current),
                ..
            }) if current == id => self.reconcile_exact(record),
            Ok(_) => PublicationStatus::NotCommitted,
            Err(_) => PublicationStatus::Unknown,
        }
    }

    fn reconcile(&mut self, record: &ActivationRecord) -> PublicationStatus {
        self.reconcile_exact(record)
    }
}

#[cfg(test)]
mod tests;
