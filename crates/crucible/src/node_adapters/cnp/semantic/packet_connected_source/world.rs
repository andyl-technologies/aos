//! Binds a distinct collecting source to one complete three-owner installation.
//!
//! The static roster supplies correlation data only. Each semantic source still
//! authenticates its own actual original realization and local Ready. The common
//! barrier and independently installed host policy must authenticate all three
//! original native owners before any durable publication or gate opening.

use crucible_node_provider::{
    bodies::RealizeResult,
    reference_packet::{
        control::PacketControlSelection, coordinator::PacketConnectedCoordinatorInstallation,
    },
};

use super::*;

pub(super) struct PacketConnectedWorldScope {
    coordinator: PacketConnectedCoordinatorInstallation,
    local: usize,
    activation: SavedRuntimeActivation,
}

impl PacketConnectedWorldScope {
    pub(super) fn new(
        installation: &CnpSemanticInstallation,
        coordinator: PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        budget::serialized_size(&coordinator, crucible_node_provider::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES)?;
        let mut selected = None;
        for (index, peer) in coordinator.participants.iter().enumerate() {
            if Self::matches_installation(installation, peer) && selected.replace(index).is_some() {
                return Err(refused("packet whole-world local source is duplicated"));
            }
        }
        let local = selected.ok_or_else(|| refused("packet whole-world local source absent"))?;
        coordinator
            .validate(&coordinator.participants[local])
            .map_err(unknown)?;
        let contract =
            crucible_node_provider::reference_packet::contracts::connected_ingress_contract()
                .map_err(unknown)?;
        let definition = canonical::content_ref(&contract, "application/json").map_err(unknown)?;
        let formats = &installation.provider.implementation.formats;
        if formats
            .iter()
            .filter(|format| format.id.as_str() == "source-owned.packet-ingress/4")
            .count()
            != 1
            || formats.iter().any(|format| {
                matches!(
                    format.id.as_str(),
                    "source-owned.packet-ingress/1"
                        | "source-owned.packet-ingress/2"
                        | "source-owned.packet-ingress/3"
                ) || (format.id.as_str() == "source-owned.packet-ingress/4"
                    && (format.version != 4
                        || format.definition != definition
                        || !format.extensions.is_empty()))
            })
        {
            return Err(refused(
                "packet whole-world source requires exact ingress edition4",
            ));
        }
        let activation: SavedRuntimeActivation =
            serde_json::from_value(coordinator.template["activation"].clone()).map_err(unknown)?;
        Ok(Self {
            coordinator,
            local,
            activation,
        })
    }

    pub(super) fn selection(&self) -> &PacketControlSelection {
        &self.coordinator.participants[self.local]
    }

    pub(super) fn coordinator(&self) -> &PacketConnectedCoordinatorInstallation {
        &self.coordinator
    }

    fn matches_installation(
        installation: &CnpSemanticInstallation,
        peer: &PacketControlSelection,
    ) -> bool {
        peer.provider == installation.provider
            && peer.realization.descriptors.as_slice()
                == std::slice::from_ref(&installation.descriptor)
            && peer.realization.bindings.as_slice() == std::slice::from_ref(&installation.binding)
            && peer.realization.owner_bindings.as_slice()
                == std::slice::from_ref(&installation.owner)
            && peer.realization.owners.as_slice() == std::slice::from_ref(&installation.owner.owner)
            && peer.realize == installation.realize
            && peer.admission == installation.admission
            && peer.transaction == installation.transaction
            && peer.gate == installation.gate
            && peer.world == installation.world_binding_hash
            && peer.admission_receipt == installation.admission_receipt
    }

    pub(super) fn authenticate_installation(
        &self,
        coordinator: &PacketConnectedCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        if coordinator != &self.coordinator {
            return Err(refused("packet original whole-world installation changed"));
        }
        Ok(())
    }

    pub(super) fn owners(&self) -> &[OwnerIdentity] {
        &self.activation.owners
    }

    pub(super) fn authenticate_record(
        &self,
        record: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        // These five borrowed fields compare the complete static correlation;
        // the caller's opaque runtime authority remains independently checked.
        if record.generation != self.activation.generation
            || record.activation_id != self.activation.activation_id
            || record.world_binding_hash != self.activation.world_binding_hash
            || record.owners != self.activation.owners
            || record.boundary != self.activation.boundary
        {
            return Err(refused(
                "packet whole-world original activation differs from installation",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_realization(
        &self,
        realization: &RealizeResult,
    ) -> Result<(), OperationFailure> {
        if realization.realization_manifest != self.coordinator.participants[self.local].realization
            || realization.prepared_token
                != self.coordinator.participants[self.local].prepared_token
        {
            return Err(refused(
                "packet whole-world original preparation token changed",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_prepared<'a>(
        &self,
        owners: &'a [PreparedOwner],
        realization: &RealizeResult,
    ) -> Result<&'a PreparedOwner, OperationFailure> {
        self.authenticate_realization(realization)?;
        if owners.len() != self.activation.owners.len() {
            return Err(refused(
                "packet whole-world complete prepared roster absent",
            ));
        }
        for (actual, peer) in owners.iter().zip(&self.coordinator.participants) {
            let binding = &peer.realization.bindings[0];
            let expected = &peer.realization.owners[0];
            if actual.owner_id != expected.id
                || actual.incarnation_id != binding.authority.incarnation_id
                || actual.owner_generation != binding.authority.owner_generation
                || actual.binding_hashes != [binding.identity().map_err(unknown)?]
                || actual.prepared_token != peer.prepared_token
                || !actual.extensions.is_empty()
            {
                return Err(refused(
                    "packet whole-world prepared owner association changed",
                ));
            }
            actual.ready_receipt.validate().map_err(unknown)?;
        }
        let actual = owners
            .get(self.coordinator.participants.len())
            .ok_or_else(|| refused("connected original host prepared row absent"))?;
        let host = &self.coordinator.host;
        if actual.owner_id != host.owner.owner.id
            || actual.incarnation_id != host.binding.authority.incarnation_id
            || actual.owner_generation != host.binding.authority.owner_generation
            || actual.binding_hashes != [host.binding.identity().map_err(unknown)?]
            || actual.prepared_token != host.prepared_token
            || !actual.extensions.is_empty()
        {
            return Err(refused(
                "connected actual original host preparation changed",
            ));
        }
        actual.ready_receipt.validate().map_err(unknown)?;

        // A foreign Ready reference is only correlation here. Runtime barrier
        // validation and the same installed host authority authenticate each
        // original source; THIS source opens only its own actual native gate.
        Ok(&owners[self.local])
    }

    pub(super) fn authenticate_coordinator(&self, bytes: &[u8]) -> Result<(), OperationFailure> {
        self.coordinator.validate_body(bytes).map_err(unknown)
    }
}
