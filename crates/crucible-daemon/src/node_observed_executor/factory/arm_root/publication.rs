//! Couples complete public publication with the original reserved Root capsule.
//!
//! Unknown is recorded before every durable callback. A callback unwind retains
//! the whole native journal and cannot restore a pre-effect publication label.

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
use super::custody::RootCustodyQueue;

pub(super) struct RootPublisher {
    pub(super) stored: StoredWorldActivationPublisher,
    pub(super) queue: RootCustodyQueue,
    restored: Option<RestoredCoordinator>,
}

impl RootPublisher {
    pub(super) fn for_initial(
        stored: StoredWorldActivationPublisher,
        queue: RootCustodyQueue,
    ) -> Self {
        Self {
            stored,
            queue,
            restored: None,
        }
    }

    pub(super) fn for_restore(
        stored: StoredWorldActivationPublisher,
        queue: RootCustodyQueue,
        archive: &crucible::node_state::NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<Self, super::super::NodeObservedError> {
        let source = archive
            .source_activation()
            .map_err(|error| super::super::refused(&error.to_string()))?;
        if source.world_binding_hash != target.world_binding_hash
            || target.boundary != archive.manifest().cut
            || target.activation_id == source.activation_id
            || target.generation != source.generation.checked_add(1.into())?
            || target.owners.len() != 2
            || source.owners.len() != 2
            || target.owners.iter().any(|fresh| {
                !source.owners.iter().any(|old| {
                    old.owner == fresh.owner
                        && old.incarnation != fresh.incarnation
                        && old.generation.checked_add(1.into()).ok() == Some(fresh.generation)
                })
            })
        {
            return Err(super::super::refused(
                "Root complete publication has another source or fresh owner roster",
            ));
        }
        let reference = archive.manifest().coordinator_state_ref.clone();
        // Original octets expand to at most four JSON bytes each. Leave the
        // remaining bounded record credit for both genuine fresh preparations.
        let bytes = archive
            .object_bytes(&reference, 3 * 1024 * 1024)
            .map_err(|error| super::super::refused(&error.to_string()))?;
        Ok(Self {
            stored,
            queue,
            restored: Some(RestoredCoordinator {
                target: target.clone(),
                source,
                archive: archive.artifact().clone(),
                coordinator: InputPayload { reference, bytes },
            }),
        })
    }

    fn effect(
        &mut self,
        record: &ActivationRecord,
        callback: impl FnOnce(&mut StoredWorldActivationPublisher) -> PublicationStatus,
    ) -> PublicationStatus {
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
        let status = catch_unwind(AssertUnwindSafe(|| callback(&mut self.stored)))
            .unwrap_or(PublicationStatus::Unknown);
        let knowledge = match status {
            PublicationStatus::Committed => PublicationKnowledge::Committed,
            PublicationStatus::NotCommitted => PublicationKnowledge::NotCommitted,
            PublicationStatus::Unknown => PublicationKnowledge::Unknown,
        };
        if (committed && status != PublicationStatus::Committed)
            || self.queue.record_publication(record, knowledge).is_err()
        {
            return PublicationStatus::Unknown;
        }
        status
    }
}

impl ActivationPublisher for RootPublisher {
    fn publish(&mut self, _record: &ActivationRecord) -> PublicationStatus {
        // This distinct public Root profile has no scalar publication path.
        PublicationStatus::NotCommitted
    }

    fn reconcile(&mut self, _record: &ActivationRecord) -> PublicationStatus {
        PublicationStatus::Unknown
    }

    fn retain_initial_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: Vec<ValidatedNodePreparation>,
        coordinator: InputPayload,
    ) -> Result<(), RuntimeError> {
        self.stored
            .retain_initial_coordinator(record, nodes, coordinator)
    }

    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        if let Some(original) = &self.restored {
            if original.target != *record
                || nodes.len() != 2
                || nodes.iter().any(|node| node.prepared_owners().is_none())
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            let body = RestoredCoordinatorBody {
                schema: "crucible/coordinator-restored-public-arm-root/1",
                source_archive: &original.archive,
                source_activation: &original.source,
                source_coordinator_ref: &original.coordinator.reference,
                source_coordinator_bytes: &original.coordinator.bytes,
                target_activation: crucible::node_contract::SavedRuntimeActivation::from(record),
                actual_fresh_preparations: nodes,
            };
            let bytes = super::evidence::metadata_bytes(&body)
                .map_err(|_| RuntimeError::PublicationFailed)?;
            let reference =
                crucible_node_contract::canonical::content_ref(&bytes, "application/json")
                    .map_err(|_| RuntimeError::PublicationFailed)?;
            self.stored.retain_initial_coordinator(
                record,
                nodes.to_vec(),
                InputPayload { reference, bytes },
            )?;
        }
        self.stored.prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.effect(record, |stored| stored.publish_complete(record, prepared))
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.effect(record, |stored| stored.reconcile_complete(record, prepared))
    }
}

/// Owns signed original coordinator bytes separately from genuine fresh Ready.
struct RestoredCoordinator {
    target: ActivationRecord,
    source: crucible::node_contract::SavedRuntimeActivation,
    archive: crucible_node_contract::ContentRef,
    coordinator: InputPayload,
}

#[derive(serde::Serialize)]
struct RestoredCoordinatorBody<'a> {
    schema: &'static str,
    source_archive: &'a crucible_node_contract::ContentRef,
    source_activation: &'a crucible::node_contract::SavedRuntimeActivation,
    source_coordinator_ref: &'a crucible_node_contract::ContentRef,
    source_coordinator_bytes: &'a [u8],
    target_activation: crucible::node_contract::SavedRuntimeActivation,
    actual_fresh_preparations: &'a [ValidatedNodePreparation],
}
