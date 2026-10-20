//! Binds a distinct collecting source to one complete three-owner installation.
//!
//! The static roster supplies correlation data only. Each semantic source still
//! authenticates its own actual original realization and local Ready. The common
//! barrier and independently installed host policy must authenticate all three
//! original native owners before any durable publication or gate opening.

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::{
    bodies::RealizeResult,
    reference_packet::{
        control::PacketControlSelection,
        coordinator::{
            PacketConnectedCoordinatorInstallation, PacketNative5CoordinatorInstallation,
            PacketWorldCoordinatorInstallation,
        },
    },
};

use super::*;

pub(super) struct PacketWorldSourceScope {
    coordinator: InstalledCoordinator,
    local: usize,
    activation: SavedRuntimeActivation,
}

impl PacketWorldSourceScope {
    pub(super) fn new(
        installation: &CnpSemanticInstallation,
        coordinator: PacketWorldCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        budget::serialized_size(&coordinator, 65_536)?;
        Self::new_selected(installation, InstalledCoordinator::OutputOnly(coordinator))
    }

    pub(super) fn new_connected(
        installation: &CnpSemanticInstallation,
        coordinator: PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        budget::serialized_size(
            &coordinator,
            crucible_node_transport::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES,
        )?;
        Self::new_selected(
            installation,
            InstalledCoordinator::Connected(Box::new(coordinator)),
        )
    }

    pub(super) fn new_complete(
        installation: &CnpSemanticInstallation,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        budget::serialized_size(
            &coordinator,
            crucible_node_transport::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
        )?;
        Self::new_selected(
            installation,
            InstalledCoordinator::Complete(Box::new(coordinator)),
        )
    }

    fn new_selected(
        installation: &CnpSemanticInstallation,
        coordinator: InstalledCoordinator,
    ) -> Result<Self, OperationFailure> {
        let mut selected = None;
        for (index, peer) in coordinator.participants().iter().enumerate() {
            if Self::matches_installation(installation, peer) && selected.replace(index).is_some() {
                return Err(refused("packet whole-world local source is duplicated"));
            }
        }
        let local = selected.ok_or_else(|| refused("packet whole-world local source absent"))?;
        coordinator
            .validate(&coordinator.participants()[local])
            .map_err(unknown)?;
        let (identifier, version, contract) = match &coordinator {
            InstalledCoordinator::OutputOnly(_) => (
                "source-owned.packet-ingress/3",
                3,
                crucible_node_transport::reference_packet::contracts::world_ingress_contract()
                    .map_err(unknown)?,
            ),
            InstalledCoordinator::Connected(_) => (
                "source-owned.packet-ingress/4",
                4,
                crucible_node_transport::reference_packet::contracts::connected_ingress_contract()
                    .map_err(unknown)?,
            ),
            InstalledCoordinator::Complete(_) => (
                "source-owned.packet-ingress/5",5,
                crucible_node_transport::reference_packet::continuation_contracts::complete_ingress_contract().map_err(unknown)?,
            ),
        };
        let definition = canonical::content_ref(&contract, "application/json").map_err(unknown)?;
        let formats = &installation.provider.implementation.formats;
        if formats
            .iter()
            .filter(|format| format.id.as_str() == identifier)
            .count()
            != 1
            || formats.iter().any(|format| {
                (matches!(
                    format.id.as_str(),
                    "source-owned.packet-ingress/1"
                        | "source-owned.packet-ingress/2"
                        | "source-owned.packet-ingress/3"
                        | "source-owned.packet-ingress/4"
                        | "source-owned.packet-ingress/5"
                ) && format.id.as_str() != identifier)
                    || (format.id.as_str() == identifier
                        && (format.version != version
                            || format.definition != definition
                            || !format.extensions.is_empty()))
            })
        {
            return Err(refused(
                "packet whole-world source requires its exact original ingress edition",
            ));
        }
        let activation: SavedRuntimeActivation =
            serde_json::from_value(coordinator.template()["activation"].clone())
                .map_err(unknown)?;
        Ok(Self {
            coordinator,
            local,
            activation,
        })
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
        coordinator: &PacketWorldCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        if !matches!(&self.coordinator, InstalledCoordinator::OutputOnly(original) if original == coordinator)
        {
            return Err(refused("packet original whole-world installation changed"));
        }
        Ok(())
    }

    pub(super) fn authenticate_connected_installation(
        &self,
        coordinator: &PacketConnectedCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        if !matches!(&self.coordinator, InstalledCoordinator::Connected(original) if original.as_ref() == coordinator)
        {
            return Err(refused("packet original connected installation changed"));
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        matches!(&self.coordinator, InstalledCoordinator::Complete(_))
    }

    pub(super) fn selection(&self) -> &PacketControlSelection {
        &self.coordinator.participants()[self.local]
    }

    pub(super) fn authenticate_complete_installation(
        &self,
        coordinator: &PacketNative5CoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        if !matches!(&self.coordinator,InstalledCoordinator::Complete(original) if original.as_ref()==coordinator)
        {
            return Err(refused("packet complete original coordinator changed"));
        }
        Ok(())
    }

    pub(super) fn is_connected(&self) -> bool {
        matches!(
            &self.coordinator,
            InstalledCoordinator::Connected(_) | InstalledCoordinator::Complete(_)
        )
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
        if realization.realization_manifest
            != self.coordinator.participants()[self.local].realization
            || realization.prepared_token
                != self.coordinator.participants()[self.local].prepared_token
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
        for (actual, peer) in owners.iter().zip(self.coordinator.participants()) {
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
        if let Some(host) = self.coordinator.host() {
            let actual = &owners[self.coordinator.participants().len()];
            if actual.owner_id != host.owner.owner.id
                || actual.incarnation_id != host.binding.authority.incarnation_id
                || actual.owner_generation != host.binding.authority.owner_generation
                || actual.binding_hashes != [host.binding.identity().map_err(unknown)?]
                || actual.prepared_token != host.prepared_token
                || !actual.extensions.is_empty()
            {
                return Err(refused(
                    "packet connected original host preparation changed",
                ));
            }
            actual.ready_receipt.validate().map_err(unknown)?;
        }
        // A foreign Ready reference is only correlation here. Runtime barrier
        // validation and the same installed host authority authenticate each
        // original source; THIS source opens only its own actual native gate.
        Ok(&owners[self.local])
    }

    pub(super) fn authenticate_coordinator(&self, bytes: &[u8]) -> Result<(), OperationFailure> {
        self.coordinator.validate_body(bytes).map_err(unknown)
    }
}

enum InstalledCoordinator {
    OutputOnly(PacketWorldCoordinatorInstallation),
    Connected(Box<PacketConnectedCoordinatorInstallation>),
    Complete(Box<PacketNative5CoordinatorInstallation>),
}

impl InstalledCoordinator {
    fn host(
        &self,
    ) -> Option<&crucible_node_transport::reference_packet::coordinator::PacketConnectedHostSelection>
    {
        match self {
            Self::OutputOnly(_) => None,
            Self::Connected(scope) => Some(&scope.host),
            Self::Complete(scope) => Some(&scope.host),
        }
    }

    fn participants(&self) -> &[PacketControlSelection] {
        match self {
            Self::OutputOnly(scope) => &scope.participants,
            Self::Connected(scope) => &scope.participants,
            Self::Complete(scope) => &scope.participants,
        }
    }

    fn template(&self) -> &serde_json::Value {
        match self {
            Self::OutputOnly(scope) => &scope.template,
            Self::Connected(scope) => &scope.template,
            Self::Complete(scope) => &scope.template,
        }
    }

    fn validate(
        &self,
        local: &PacketControlSelection,
    ) -> Result<(), crucible_node_transport::ProviderError> {
        match self {
            Self::OutputOnly(scope) => scope.validate(local),
            Self::Connected(scope) => scope.validate(local),
            Self::Complete(scope) => scope.validate(local),
        }
    }

    fn validate_body(&self, bytes: &[u8]) -> Result<(), crucible_node_transport::ProviderError> {
        match self {
            Self::OutputOnly(scope) => scope.validate_body(bytes),
            Self::Connected(scope) => scope.validate_body(bytes),
            Self::Complete(scope) => scope.validate_body(bytes),
        }
    }
}

impl PacketWorldSourceScope {
    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_parts_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<
        (
            &PacketNative5CoordinatorInstallation,
            &SavedRuntimeActivation,
        ),
        E,
    > {
        match &self.coordinator {
            InstalledCoordinator::Complete(coordinator) => {
                Ok((coordinator.as_ref(), &self.activation))
            }
            _ => Err(E::refused("retained complete coordinator absent")),
        }
    }
}

impl PacketWorldSourceScope {
    pub(super) fn complete_template_constructor_transient_data() -> usize {
        // Actual world return, coordinator Clone return/Box input, and saved
        // activation Clone return are named independently of retained backing.
        std::mem::size_of::<Result<Self, RuntimeError>>()
            + std::mem::size_of::<PacketNative5CoordinatorInstallation>()
            + std::mem::size_of::<SavedRuntimeActivation>()
    }

    /// Copies already validated complete-world correlation, without a live grant.
    pub(super) fn cloned_complete_template_data(&self) -> Result<Self, RuntimeError> {
        let InstalledCoordinator::Complete(coordinator) = &self.coordinator else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        Ok(Self {
            coordinator: InstalledCoordinator::Complete(Box::new(coordinator.as_ref().clone())),
            local: self.local,
            activation: self.activation.clone(),
        })
    }
}
