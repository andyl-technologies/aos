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
    pub(super) restored: Option<RestoredCoordinator>,
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
                || nodes.len() != original.expected_nodes
                || nodes.iter().any(|node| node.prepared_owners().is_none())
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            if original.expected_nodes == 4 {
                preflight_group_coordinator(original, record, nodes)?;
            }
            let bytes = crucible_node_contract::canonical::canonical_json(&serde_json::json!({
                "schema":"crucible/coordinator-restored-public-native/1",
                "source_archive":original.archive,
                "source_activation":original.source,
                "source_coordinator_ref":original.coordinator.reference,
                "source_coordinator_bytes":original.coordinator.bytes,
                "target_activation":crucible::node_contract::SavedRuntimeActivation::from(record),
                "actual_fresh_preparations":nodes,
            }))
            .map_err(|_| RuntimeError::PublicationFailed)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(RuntimeError::PublicationFailed);
            }
            let reference =
                crucible_node_contract::canonical::content_ref(&bytes, "application/json")
                    .map_err(|_| RuntimeError::PublicationFailed)?;
            let coordinator = InputPayload { reference, bytes };
            self.stored
                .retain_initial_coordinator(record, nodes.to_vec(), coordinator)?;
        }
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

/// Retains authenticated original coordinator data before fresh publication.
pub(super) struct RestoredCoordinator {
    expected_nodes: usize,
    target: ActivationRecord,
    source: crucible::node_contract::SavedRuntimeActivation,
    archive: crucible_node_contract::ContentRef,
    coordinator: InputPayload,
}

impl NativeCustodyPublisher {
    pub(super) fn for_public_restore(
        stored: StoredWorldActivationPublisher,
        queue: Gem5CustodyQueue,
        archive: &crucible::node_state::NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<Self, super::super::NodeObservedError> {
        let source = archive
            .source_activation()
            .map_err(|error| super::super::refused(&error.to_string()))?;
        if target.world_binding_hash != source.world_binding_hash
            || target.boundary != archive.manifest().cut
            || target.generation <= source.generation
            || target.activation_id == source.activation_id
        {
            return Err(super::super::refused(
                "public restored publication differs from its authenticated source and fresh target",
            ));
        }
        // A byte-array JSON encoding may use four bytes per original octet. This
        // conservative preflight leaves room for the complete fresh roster.
        let coordinator_ref = archive.manifest().coordinator_state_ref.clone();
        let bytes = archive
            .object_bytes(&coordinator_ref, 3 * 1024 * 1024)
            .map_err(|error| super::super::refused(&error.to_string()))?;
        Ok(Self {
            stored,
            queue,
            restored: Some(RestoredCoordinator {
                expected_nodes: 2,
                target: target.clone(),
                source,
                archive: archive.artifact().clone(),
                coordinator: InputPayload {
                    reference: coordinator_ref,
                    bytes,
                },
            }),
        })
    }

    /// Retains the separately selected signed complete four-owner source bridge.
    ///
    /// # Errors
    /// Refuses another roster or native family, an unchanged activation or a
    /// missing source coordinator. Actual restored Ready remains mandatory.
    pub(super) fn for_public_group_restore(
        stored: StoredWorldActivationPublisher,
        queue: Gem5CustodyQueue,
        archive: &crucible::node_state::NativeArchiveRecord,
        target: &ActivationRecord,
    ) -> Result<Self, super::super::NodeObservedError> {
        if archive.owners().len() != 4
            || target.owners.len() != 4
            || archive
                .owners()
                .iter()
                .filter(|owner| {
                    owner.key.schema.id.as_str() == "host/public-owned-model-continuation-v1"
                        && owner.key.schema.version == 1
                })
                .count()
                != 2
            || !archive.owners().iter().any(|owner| {
                owner.key.schema.id.as_str() == "crucible/gem5-public-native-continuation-v1"
            })
            || !archive.owners().iter().any(|owner| {
                owner.key.schema.id.as_str() == "crucible/host-public-clock-continuation-v1"
            })
        {
            return Err(super::super::refused(
                "public group bridge selects another signed native family",
            ));
        }
        let mut publisher = Self::for_public_restore(stored, queue, archive, target)?;
        let original = publisher
            .restored
            .as_mut()
            .ok_or_else(|| super::super::refused("public group original coordinator is absent"))?;
        original.expected_nodes = 4;
        Ok(publisher)
    }
}

fn preflight_group_coordinator(
    original: &RestoredCoordinator,
    record: &ActivationRecord,
    nodes: &[ValidatedNodePreparation],
) -> Result<(), RuntimeError> {
    #[derive(serde::Serialize)]
    struct Target<'a> {
        generation: crucible_node_contract::U64,
        activation_id: &'a crucible_node_contract::Id,
        world_binding_hash: &'a crucible_node_contract::HashRef,
        owners: &'a [crucible::node_contract::OwnerIdentity],
        boundary: crucible_node_contract::Position,
    }

    #[derive(serde::Serialize)]
    struct Wire<'a> {
        schema: &'static str,
        source_archive: &'a crucible_node_contract::ContentRef,
        source_activation: &'a crucible::node_contract::SavedRuntimeActivation,
        source_coordinator_ref: &'a crucible_node_contract::ContentRef,
        source_coordinator_bytes: &'a [u8],
        target_activation: Target<'a>,
        actual_fresh_preparations: &'a [ValidatedNodePreparation],
    }

    struct Credit(usize);

    impl std::io::Write for Credit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.checked_sub(bytes.len()).ok_or_else(|| {
                std::io::Error::other("complete restored group coordinator exceeds credit")
            })?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // The borrowed counter precedes Value, canonical body and owner roster
    // allocation. Source bytes and actual fresh preparations remain untouched.
    serde_json::to_writer(
        Credit(16 * 1024 * 1024),
        &Wire {
            schema: "crucible/coordinator-restored-public-native/1",
            source_archive: &original.archive,
            source_activation: &original.source,
            source_coordinator_ref: &original.coordinator.reference,
            source_coordinator_bytes: &original.coordinator.bytes,
            target_activation: Target {
                generation: record.generation,
                activation_id: &record.activation_id,
                world_binding_hash: &record.world_binding_hash,
                owners: &record.owners,
                boundary: record.boundary,
            },
            actual_fresh_preparations: nodes,
        },
    )
    .map_err(|_| RuntimeError::PublicationFailed)
}
