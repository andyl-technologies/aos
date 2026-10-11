//! Retains the actual complete publication observed by the source publisher.
//!
//! This latch starts empty before Child. The owning installation publisher may
//! fill it only after its concrete durable publisher reports Committed. It never
//! constructs a core preparation, readiness object or activation permission.

use std::cell::RefCell;

use crucible::node_contract::{ActivationRecord, PreparedWorldPublication, PublicationStatus};
use crucible_node_provider::ProviderError;

pub(super) struct SourceLifecycleWorld {
    expected: ActivationRecord,
    committed: RefCell<Option<PreparedWorldPublication>>,
}

impl SourceLifecycleWorld {
    pub(super) fn new(expected: ActivationRecord) -> Self {
        Self {
            expected,
            committed: RefCell::new(None),
        }
    }

    /// Retains the original opaque publication after authentic durable commit.
    ///
    /// # Errors
    /// Refuses changed original scope, incomplete owners/coordinator, noncommit
    /// disposition or replacement of an already retained original preparation.
    pub(super) fn record_committed(
        &self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
        status: PublicationStatus,
    ) -> Result<(), ProviderError> {
        if status != PublicationStatus::Committed
            || record != &self.expected
            || prepared.nodes().len() != record.owners.len()
            || prepared.prepared_owners().len() != record.owners.len()
            || prepared.prepared_owners().iter().any(|owner| {
                !record.owners.iter().any(|original| {
                    owner.owner_id == original.owner
                        && owner.incarnation_id == original.incarnation
                        && owner.owner_generation == original.generation
                })
            })
        {
            return Err(ProviderError::Correlation(
                "source original complete publication differs",
            ));
        }
        let coordinator = prepared.coordinator_snapshot();
        coordinator.reference.verify(&coordinator.bytes)?;
        let mut committed = self.committed.borrow_mut();
        if committed
            .as_ref()
            .is_some_and(|original| original != prepared)
        {
            return Err(ProviderError::Correlation(
                "source original publication cannot be replaced",
            ));
        }
        if committed.is_none() {
            *committed = Some(prepared.clone());
        }
        Ok(())
    }

    /// Authenticates inert manifest data against the original core publication.
    ///
    /// # Errors
    /// Refuses absent durable source publication or exact roster/body drift.
    pub(super) fn verify(
        &self,
        manifest: &crucible_node_contract::ActivationManifest,
        coordinator_bytes: &[u8],
    ) -> Result<(), ProviderError> {
        let committed = self.committed.borrow();
        let prepared = committed.as_ref().ok_or(ProviderError::Correlation(
            "source committed world unavailable",
        ))?;
        if manifest.activation_id != self.expected.activation_id
            || manifest.world_generation != self.expected.generation
            || manifest.world_binding_hash != self.expected.world_binding_hash
            || manifest.owners != prepared.prepared_owners()
            || manifest.coordinator_state_ref != prepared.coordinator_snapshot().reference
            || coordinator_bytes != prepared.coordinator_snapshot().bytes
        {
            return Err(ProviderError::Correlation(
                "source world manifest or coordinator differs",
            ));
        }
        Ok(())
    }
}
