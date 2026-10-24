//! Admits the fourth historical protocol class beside before/host/after owners.
//!
//! The same signed journal names the registry's full encoded reference. Its
//! separate summary/copy banks and actual reconstruction demand participate in
//! the fixed-three source aggregate before any protocol owner is reconstructed.
//! Historical creator data never authenticates a live process or callback.

use super::*;
use crucible_node_transport::protocol_snapshot::owned11::host_registry::{
    SealedHistoricalHostExtensionRegistry, ValidatedHostExtensionRegistry,
};

impl PacketCompleteArchivedOwnerData<'_> {
    pub(super) fn registry_demand_data(&mut self) -> Result<usize, OperationFailure> {
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold registry journal absent"))?;
        let reference = journal.require_complete_registry_data()?;
        let input = self
            .content
            .get(reference)
            .ok_or_else(|| refused("cold registry body absent"))?;
        reference.verify(input).map_err(unknown)?;
        let plan = ValidatedHostExtensionRegistry::validate(
            input,
            self.registry_limits,
            &mut self.registry_aliases,
        )
        .map_err(unknown)?;
        checked_sum(
            [
                protocol_demand(plan.allocation_demand(), self.maximum)?,
                NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
            ],
            self.maximum,
        )
    }

    pub(super) fn reconstruct_registry_data(&mut self) -> Result<(), OperationFailure> {
        self.ensure_origin()?;
        if self.known_requested.is_none() || self.failed {
            return Err(refused("cold registry demand was not admitted"));
        }
        let journal = self
            .journal
            .as_ref()
            .ok_or_else(|| refused("cold registry journal absent"))?;
        let reference = journal.require_complete_registry_data()?;
        let input = self
            .content
            .get(reference)
            .ok_or_else(|| refused("cold registry body absent"))?;
        let mut plan = ValidatedHostExtensionRegistry::validate(
            input,
            self.registry_limits,
            &mut self.registry_aliases,
        )
        .map_err(unknown)?;
        plan.reconstruct_sealed_into(reference, &mut self.registry_encoded, &mut self.registry)
            .map_err(unknown)?;
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| refused("cold sealed registry absent"))?;
        if registry.body_reference() != reference {
            return Err(refused(
                "cold registry sealed reference differs from signed journal",
            ));
        }
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("cold registry host absent"))?
            .historical()
            .map_err(unknown)?;
        registry
            .historical()
            .map_err(unknown)?
            .authenticate_host_data(host)
            .map_err(unknown)?;
        self.ensure_origin()
    }

    /// Borrows the complete body-linked historical registry without live enrollment.
    ///
    /// # Errors
    /// Refuses a foreign creator, incomplete group or absent sealed registry.
    pub fn sealed_host_registry_data(
        &self,
    ) -> Result<&SealedHistoricalHostExtensionRegistry, OperationFailure> {
        self.ensure_complete()?;
        self.registry
            .as_ref()
            .ok_or_else(|| refused("cold sealed registry absent"))
    }
}
