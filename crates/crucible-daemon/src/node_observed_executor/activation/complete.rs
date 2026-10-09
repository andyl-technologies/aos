//! Durable complete preparation with separately rooted original coordinator bytes.
//!
//! Version 2 activation records bind the original validated node and owner
//! preparations plus the public coordinator reference. Its exact raw bytes have
//! a second write-once root established before the activation root. Both roots
//! and both durable objects must reconcile before execution authority is granted.

use crucible::node_contract::{
    MAXIMUM_ACTIVATION_COORDINATOR_BYTES, PreparedWorldPublication, RuntimeError,
    ValidatedNodePreparation,
};
use crucible::node_scheduling::InputPayload;

use super::*;

const MAXIMUM_PREPARATION_RECORD_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct PreparedCoordinator {
    activation: ActivationRecord,
    nodes: Vec<ValidatedNodePreparation>,
    coordinator: InputPayload,
    reference: RefName,
}

impl StoredWorldActivationPublisher {
    /// Binds actual complete prepared coordinator custody to the original readiness.
    ///
    /// The caller belongs to the trusted coordinator construction boundary. It
    /// supplies the actual complete initial or authenticated restored state,
    /// including clock, graph, scheduling and retained operation/input custody.
    /// The publisher checks exact scope when the runtime requests publication;
    /// this method does not qualify native state or issue execution authority.
    ///
    /// # Errors
    /// Refuses repeated preparation, empty or oversized coordinator bytes, invalid
    /// content identity, incomplete public preparation or oversized ready records.
    pub fn with_prepared_coordinator(
        mut self,
        activation: ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        coordinator: InputPayload,
    ) -> Result<Self, StoreError> {
        if self.prepared.is_some()
            || nodes.is_empty()
            || nodes.iter().any(|node| node.prepared_owners().is_none())
            || coordinator.bytes.is_empty()
            || coordinator.bytes.len() > MAXIMUM_ACTIVATION_COORDINATOR_BYTES
            || coordinator.reference.verify(&coordinator.bytes).is_err()
            || canonical::canonical_json(
                &serde_json::to_value(&nodes).map_err(|_| StoreError::Incompatible)?,
            )
            .map_err(|_| StoreError::Incompatible)?
            .len()
                > MAXIMUM_PREPARATION_RECORD_BYTES
        {
            return Err(StoreError::Incompatible);
        }
        let reference = self.coordinator_reference()?;
        self.prepared = Some(PreparedCoordinator {
            activation,
            nodes,
            coordinator,
            reference,
        });
        Ok(self)
    }

    pub(super) fn prepare_complete_coordinator(
        &self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(RuntimeError::PublicationFailed)?;
        if prepared.activation != *record || prepared.nodes != nodes {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(prepared.coordinator.clone())
    }

    fn coordinator_reference(&self) -> Result<RefName, StoreError> {
        let suffix = self
            .reference
            .as_str()
            .strip_prefix("node-world-activations/")
            .ok_or(StoreError::Incompatible)?;
        // A child ref would turn the legacy activation's file path into a
        // directory on filesystem-backed stores. Keep two disjoint roots.
        RefName::new(format!("node-world-coordinators/{suffix}"))
    }

    fn complete_bytes(
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> Option<Vec<u8>> {
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format": "crucible.node-world-activation", "version": 2,
            "activation": SavedRuntimeActivation::from(record),
            "node_preparations": prepared.nodes(),
            "prepared_owners": prepared.prepared_owners(),
            "coordinator_state_ref": prepared.coordinator_snapshot().reference,
        }))
        .ok()?;
        (bytes.len() <= MAXIMUM_PREPARATION_RECORD_BYTES).then_some(bytes)
    }

    pub(super) fn reconcile_complete_record(
        &self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        let Some(bytes) = Self::complete_bytes(record, prepared) else {
            return PublicationStatus::Unknown;
        };
        let activation_id = ContentId::for_bytes(ObjectKind::Trace, 2, &bytes);
        match self.refs.read_ref(&self.reference) {
            Ok(None) => return PublicationStatus::NotCommitted,
            Ok(Some(actual)) if actual != activation_id => return PublicationStatus::NotCommitted,
            Err(_) => return PublicationStatus::Unknown,
            Ok(Some(_)) => {}
        }

        let Ok(reference) = self.coordinator_reference() else {
            return PublicationStatus::Unknown;
        };
        let coordinator = prepared.coordinator_snapshot();
        let coordinator_id = ContentId::for_bytes(ObjectKind::Trace, 2, &coordinator.bytes);
        if !matches!(self.refs.read_ref(&reference), Ok(Some(actual)) if actual == coordinator_id) {
            return PublicationStatus::Unknown;
        }
        for (id, expected, ceiling) in [
            (
                activation_id,
                bytes.as_slice(),
                MAXIMUM_PREPARATION_RECORD_BYTES,
            ),
            (
                coordinator_id,
                coordinator.bytes.as_slice(),
                MAXIMUM_ACTIVATION_COORDINATOR_BYTES,
            ),
        ] {
            match self
                .blobs
                .read(id, None)
                .and_then(|handle| handle.read_all(ceiling as u64))
            {
                Ok(actual) if actual == expected => {}
                _ => return PublicationStatus::Unknown,
            }
        }
        PublicationStatus::Committed
    }

    pub(super) fn publish_complete_record(
        &self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        let Some(original) = &self.prepared else {
            return PublicationStatus::NotCommitted;
        };
        if original.activation != *record
            || original.nodes != prepared.nodes()
            || original.coordinator != *prepared.coordinator_snapshot()
        {
            return PublicationStatus::NotCommitted;
        }
        match self.reconcile_complete_record(record, prepared) {
            PublicationStatus::NotCommitted => {}
            known => return known,
        }
        let Some(bytes) = Self::complete_bytes(record, prepared) else {
            return PublicationStatus::NotCommitted;
        };
        let coordinator = prepared.coordinator_snapshot();
        let activation_id = ContentId::for_bytes(ObjectKind::Trace, 2, &bytes);
        let coordinator_id = ContentId::for_bytes(ObjectKind::Trace, 2, &coordinator.bytes);
        let Ok(_guard) = self.refs.acquire_publication_guard() else {
            return PublicationStatus::Unknown;
        };

        // Keep both immutable objects protected until their two ordinary GC
        // roots exist. Partial preparation never grants activation authority.
        for (id, value) in [
            (coordinator_id, coordinator.bytes.as_slice()),
            (activation_id, bytes.as_slice()),
        ] {
            let receipt = self
                .blobs
                .put_if_absent(id, &BlobHandle::from_bytes(value.to_vec()));
            if !matches!(receipt, Ok(ref receipt) if receipt.is_durable()) {
                return PublicationStatus::Unknown;
            }
        }
        for (reference, id) in [
            (&original.reference, coordinator_id),
            (&self.reference, activation_id),
        ] {
            match self.refs.compare_exchange(reference, None, id) {
                Ok(RefCasOutcome::Advanced { next }) if next == id => {}
                Ok(RefCasOutcome::Conflict {
                    current: Some(actual),
                    ..
                }) if actual == id => {}
                Ok(_) => return PublicationStatus::NotCommitted,
                Err(_) => return PublicationStatus::Unknown,
            }
        }
        self.reconcile_complete_record(record, prepared)
    }
}
