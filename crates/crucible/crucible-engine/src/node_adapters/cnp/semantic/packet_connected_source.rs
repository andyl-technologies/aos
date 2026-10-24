//! Original connected packet semantics beneath independent common acceptance.
//!
//! Edition four retains the complete staged byte cut and its later source
//! consumption separately from Delivery, Reaction and Publication. The source
//! joins actual native journals to the same private child and original common
//! authority. Schema fields and decoded records cannot issue readiness or grants.

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use std::cell::RefCell;

use crucible_node_format::*;
use crucible_node_transport::{
    bodies::*,
    envelope::Method,
    reference_packet::{
        common::{PacketConnectedCommonGrant, PacketConnectedCommonInput},
        connected::{
            PacketCommitRecord, PacketConnectedDefinition, PacketConnectedInventory,
            PacketConnectedNativeRecord, PacketStageRecord,
        },
        coordinator::{
            PacketConnectedCoordinatorInstallation, PacketNative5CoordinatorInstallation,
        },
        input::{PACKET_INPUT_FEATURE, PacketInputContext, PacketInputCut},
    },
};
use serde::Serialize;

use crate::{node_contract::*, node_scheduling::*};

use super::{
    CnpSemanticInstallation, CnpSemanticProcessCustody, CnpSemanticRealizationScope,
    CnpSemanticSource, CnpSemanticTransition, budget, refused, unknown,
};

mod ancestry;
mod complete_static;
mod credit;
mod deferred;
mod evidence;
mod grant;
mod input;
mod input_witness;

pub use input_witness::PacketConnectedInputWitness;
mod lifecycle;
mod lineage;
mod native;
mod world;

/// Validates the source-installed connected packet implementation and originals.
///
/// This source retains one complete independently installed world. Its callbacks
/// supply source facts beneath the common runtime and separate acceptance policy;
/// they do not replace either authority with matching portable fields.
pub struct PacketConnectedSemanticSource {
    installation: CnpSemanticInstallation,
    definition: PacketConnectedDefinition,
    world: world::PacketConnectedWorldScope,
    input_lineage: RefCell<Vec<OriginalInputLineage>>,
    complete_input_static: RefCell<Option<complete_static::CompleteInputStaticRows>>,
    process: u32,
    thread: std::thread::ThreadId,
    current_native: RefCell<Option<super::process::CnpSemanticSourceRead>>,
    pub(super) complete_confirmation_selection: Option<
        Option<
            crucible_node_transport::reference_packet::service::PacketNative5ConfirmationSelection,
        >,
    >,
    pub(super) complete_capture_profile:
        Option<crucible_node_transport::reference_packet::service::PacketNative5CaptureProfile>,
    pub(super) complete_capture_allocation_selection: Option<crucible_node_transport::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
    complete_storage:
        Option<crucible_node_transport::reference_packet::control::PacketNative5StorageSelection>,
}

/// Borrows complete original native edition-four bytes and their checked record.
///
/// Only the installed source constructs a witness after joining original
/// controller requests and current private native custody. A witness is neither
/// behavioral qualification nor common operation permission.
pub struct PacketConnectedNativeWitness<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    record: PacketConnectedNativeRecord,
}

impl PacketConnectedNativeWitness<'_> {
    /// Borrows the exact original source receipt identity.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete retained source-native body.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Borrows the checked original grant and full native inventory.
    pub fn record(&self) -> &PacketConnectedNativeRecord {
        &self.record
    }
}

impl PacketConnectedSemanticSource {
    // Complete-source authorities join the retained original allocation, never
    // only equal installation fields or an independently live foreign child.
    // Immutable selection data; the complete wrapper authenticates origin first.
    pub(super) fn complete_selected_storage(
        &self,
    ) -> Option<&crucible_node_transport::reference_packet::control::PacketNative5StorageSelection>
    {
        self.complete_storage.as_ref()
    }

    pub(super) fn authenticate_complete_native_owner(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        native.authenticate_process().map_err(unknown)?;
        let original = self
            .current_native
            .try_borrow()
            .map_err(|_| refused("complete source original native read is already borrowed"))?;
        let original = original
            .as_ref()
            .ok_or_else(|| refused("complete source original native read is absent"))?;
        if !original.same_native_owner(native) {
            return Err(refused(
                "complete source belongs to another original native owner",
            ));
        }
        original.ensure_current().map_err(unknown)?;
        let supplied = native.original_source_read().map_err(unknown)?;
        if !original.same_original(&supplied) {
            return Err(refused(
                "complete source original registrar allocation changed",
            ));
        }
        supplied.ensure_current().map_err(unknown)?;
        original.ensure_current().map_err(unknown)
    }

    /// Retains an exact connected source and complete original collecting world.
    ///
    /// Construction validates static source selection only. Actual original
    /// realization, all-owner preparation and durable activation remain separate.
    ///
    /// # Errors
    /// Refuses a mismatched implementation, profile, native definition, ports,
    /// unsupported guarantee, incomplete coordinator or unbounded source tuple.
    pub fn new_for_collecting_world(
        installation: CnpSemanticInstallation,
        definition: PacketConnectedDefinition,
        coordinator: PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        Self::new_selected(
            installation,
            definition,
            SelectedConnectedCoordinator::Four(coordinator),
        )
    }

    pub(super) fn complete_preparation_unbound(&self) -> Result<bool, OperationFailure> {
        self.complete_preparation_unbound_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_preparation_unbound_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<bool, E> {
        self.local_owner_with_error::<E>()?;
        self.current_native
            .try_borrow()
            .map(|original| original.is_none())
            .map_err(|_| E::refused("complete source native association is busy"))
    }

    pub(super) fn new_complete_collecting(
        installation: CnpSemanticInstallation,
        definition: PacketConnectedDefinition,
        coordinator: PacketNative5CoordinatorInstallation,
        storage_selection:crucible_node_transport::reference_packet::control::PacketNative5StorageSelection,
    ) -> Result<Self, OperationFailure> {
        storage_selection.validate().map_err(unknown)?;
        let mut source = Self::new_selected(
            installation,
            definition,
            SelectedConnectedCoordinator::Complete(coordinator),
        )?;
        source.complete_storage = Some(storage_selection);
        Ok(source)
    }

    fn new_selected(
        installation: CnpSemanticInstallation,
        definition: PacketConnectedDefinition,
        coordinator: SelectedConnectedCoordinator,
    ) -> Result<Self, OperationFailure> {
        let complete = matches!(&coordinator, SelectedConnectedCoordinator::Complete(_));
        if complete {
            super::preparation::validate_complete_installation(&installation)?;
        } else {
            super::preparation::validate_installation(&installation)?;
        }
        budget::serialized_size(&definition, 8192)?;
        coordinator.precharge()?;
        let contract = if complete {
            crucible_node_transport::reference_packet::continuation_contracts::complete_packet_contract().map_err(unknown)?
        } else {
            crucible_node_transport::reference_packet::contracts::connected_packet_contract()
                .map_err(unknown)?
        };
        let contract = canonical::content_ref(&contract, "application/json").map_err(unknown)?;
        let octets =
            crucible_node_transport::reference_packet::contracts::immediate_packet_contract()
                .map_err(unknown)?;
        let octets = canonical::content_ref(&octets, "application/json").map_err(unknown)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(&definition).map_err(unknown)?)
            .map_err(unknown)?;
        let configuration = canonical::content_ref(&bytes, "application/json").map_err(unknown)?;
        if installation
            .provider
            .implementation
            .implementation_id
            .as_str()
            != if complete {
                "source-owned.packet-native/5"
            } else {
                "source-owned.packet-native/4"
            }
            || installation.profile.profile_id.as_str()
                != if complete {
                    "source-owned.packet-complete-original-lineage/5"
                } else {
                    "source-owned.packet-connected/4"
                }
            || installation.receipt_schema.id.as_str()
                != if complete {
                    "source-owned.packet-receipt/5"
                } else {
                    "source-owned.packet-receipt/4"
                }
            || installation.receipt_schema.version != if complete { 5 } else { 4 }
            || installation.receipt_schema.definition != contract
            || installation.profile.configuration_schema.id.as_str()
                != "source-owned.packet-connected-program/4"
            || installation.profile.configuration_schema.version != 4
            || installation.profile.configuration_schema.definition != contract
            || installation.exact_facet.id.as_str()
                != if complete {
                    "source-owned.packet-exact/5"
                } else {
                    "source-owned.packet-exact/4"
                }
            || installation.exact_facet.version != if complete { 5 } else { 4 }
            || installation.descriptor.roles.as_slice()
                != [Id::new("external_device").map_err(unknown)?]
            || installation.profile.roles != installation.descriptor.roles
            || installation.descriptor.model_ref != configuration
            || installation.binding.compatibility.configuration_ref != configuration
            || installation.realize.configuration != configuration
            || definition.schema != "source-owned.packet-connected-program/4"
            || !(1..=4).contains(&definition.connections.len())
            || installation.guarantees.repeatability
                != if complete {
                    Repeatability::Unqualified
                } else {
                    Repeatability::Nondeterministic
                }
            || installation.guarantees.capture_scope
                != if complete {
                    CaptureScope::CompleteModel
                } else {
                    CaptureScope::None
                }
            || installation.guarantees.continuation
                != if complete {
                    Continuation::Exact
                } else {
                    Continuation::Unsupported
                }
            || installation.guarantees.durable_restart != complete
            || installation.guarantees.isolated_fork
            || installation.guarantees.conditional_replay
            || installation.maximum_operations > 64
            || installation.maximum_result_bytes != 65_536
            || installation.maximum_authorization_bytes < 8192
        {
            return Err(refused("connected packet complete installed source tuple"));
        }
        let ports = &installation.descriptor.ports;
        if ports.len() != 1 + usize::from(definition.output.is_some()) {
            return Err(refused("connected packet original port roster"));
        }
        for port in ports {
            let (name, lane, direction) = if port.id.as_str() == "wire_rx" {
                ("wire_rx", "input", Direction::Input)
            } else if definition.output.is_some() && port.id.as_str() == "wire_tx" {
                ("wire_tx", "output", Direction::Output)
            } else {
                return Err(refused("connected packet undeclared original port"));
            };
            if port.id.as_str() != name
                || port.interface_id.as_str() != "source-owned.packet-octets/1"
                || port.lanes.len() != 1
                || port.lanes[0].id.as_str() != lane
                || port.lanes[0].direction != direction
                || port.lanes[0].payload_schema.id.as_str() != "source-owned.packet-octets/1"
                || port.lanes[0].payload_schema.version != 1
                || port.lanes[0].payload_schema.definition != octets
                || port.lanes[0].maximum_payload_bytes.get() != 32
                || !(1..=32).contains(&port.lanes[0].maximum_pending_events.get())
            {
                return Err(refused("connected packet original octet lane semantics"));
            }
        }
        let input = Endpoint {
            node_id: installation.descriptor.id.clone(),
            port_id: Id::new("wire_rx").map_err(unknown)?,
            lane_id: Id::new("input").map_err(unknown)?,
        };
        let mut connections = std::collections::BTreeSet::new();
        for connection in &definition.connections {
            connection.id.validate().map_err(unknown)?;
            connection.policy.validate().map_err(unknown)?;
            connection.producer.validate().map_err(unknown)?;
            connection.consumer.validate().map_err(unknown)?;
            if connection.consumer != input || !connections.insert(&connection.id) {
                return Err(refused(
                    "connected packet foreign or duplicate original route",
                ));
            }
        }
        if definition.output.as_ref().is_some_and(|output| {
            output.node_id != installation.descriptor.id
                || output.port_id.as_str() != "wire_tx"
                || output.lane_id.as_str() != "output"
        }) {
            return Err(refused("connected packet foreign original output"));
        }
        let selected_world: WorldBinding =
            serde_json::from_value(coordinator.template()["world"].clone()).map_err(unknown)?;
        selected_world.validate().map_err(unknown)?;
        let incoming = selected_world
            .connections
            .iter()
            .filter(|route| route.consumer.node_id == installation.descriptor.id)
            .collect::<Vec<_>>();
        if incoming.len() != definition.connections.len()
            || definition.connections.iter().any(|route| {
                incoming
                    .iter()
                    .find(|original| original.id == route.id)
                    .is_none_or(|original| {
                        original.policy_ref != route.policy
                            || original.producer != route.producer
                            || original.consumer != route.consumer
                            || original.minimum_latency_ps != route.delay_ps
                    })
            })
        {
            return Err(refused(
                "connected native definition differs from original full world routes",
            ));
        }
        let world = coordinator.into_scope(&installation)?;
        // Share immutable runtime-issued lineage allocations in a bounded
        // original Stage roster. All slots exist before native effects.
        let mut input_lineage = Vec::new();
        input_lineage
            .try_reserve_exact(installation.maximum_operations)
            .map_err(|_| refused("connected original lineage preallocation"))?;
        Ok(Self {
            input_lineage: RefCell::new(input_lineage),
            complete_input_static: RefCell::new(None),
            installation,
            definition,
            world,
            process: std::process::id(),
            thread: std::thread::current().id(),
            current_native: RefCell::new(None),
            complete_storage: None,
            complete_capture_profile: None,
            complete_confirmation_selection: None,
            complete_capture_allocation_selection: None,
        })
    }

    /// Checks the complete original static collecting installation as data.
    ///
    /// # Errors
    /// Refuses a copied/foreign source owner or changed complete coordinator.
    pub fn authenticate_collecting_world_scope(
        &self,
        coordinator: &PacketConnectedCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        self.world.authenticate_installation(coordinator)
    }

    /// Reads the surviving exact original native capsule without policy callbacks.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, absent source realization, busy/revoked
    /// ownership, changed registrar or lost original kernel incarnation.
    pub fn authenticate_current_native(&self) -> Result<(), OperationFailure> {
        self.local_owner()?;
        self.current_native
            .try_borrow()
            .map_err(|_| refused("connected packet original source read busy"))?
            .as_ref()
            .ok_or_else(|| refused("connected packet original source read absent"))?
            .ensure_current()
            .map_err(unknown)
    }

    fn local_owner(&self) -> Result<(), OperationFailure> {
        self.local_owner_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn local_owner_with_error<E: StorageError>(
        &self,
    ) -> Result<(), E> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(E::origin(
                "connected packet foreign original source process/thread",
            ));
        }
        Ok(())
    }

    fn owner(&self) -> OwnerIdentity {
        OwnerIdentity {
            owner: self.installation.owner.owner.id.clone(),
            incarnation: self.installation.binding.authority.incarnation_id.clone(),
            generation: self.installation.binding.authority.owner_generation,
        }
    }

    fn payload(
        &self,
        value: &impl Serialize,
        maximum: usize,
    ) -> Result<InputPayload, OperationFailure> {
        budget::serialized_size(value, maximum)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(value).map_err(unknown)?)
            .map_err(unknown)?;
        if bytes.len() > maximum {
            return Err(refused(
                "connected packet complete source body exceeds original credit",
            ));
        }
        Ok(InputPayload {
            reference: canonical::content_ref(&bytes, "application/json").map_err(unknown)?,
            bytes,
        })
    }
}

impl PacketConnectedSemanticSource {
    fn guard(&self, scope: &CnpSemanticRealizationScope<'_>) -> Result<(), OperationFailure> {
        self.local_owner()?;
        if !std::ptr::eq(scope.installation, &self.installation)
            || scope
                .native
                .controller()
                .is_none_or(|controller| !std::ptr::eq(controller, scope.controller))
        {
            return Err(refused("connected packet foreign original scope"));
        }
        self.authenticate_provider(scope.native)
    }

    fn retain_current_native(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        let handle = native.original_source_read().map_err(unknown)?;
        let mut retained = self
            .current_native
            .try_borrow_mut()
            .map_err(|_| refused("connected original source read busy"))?;
        if let Some(original) = retained.as_ref() {
            if !original.same_original(&handle) {
                return Err(refused(
                    "connected original source owner cannot be replaced",
                ));
            }
            original.ensure_current().map_err(unknown)
        } else {
            *retained = Some(handle);
            Ok(())
        }
    }

    fn authenticate_activation_record(
        &self,
        record: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        self.world.authenticate_record(record)
    }

    fn initial(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketConnectedNativeRecord, OperationFailure> {
        let native = self.native_record(scope, root)?;
        if native.inventory != native::initial_inventory() || native.grant.is_some() {
            return Err(refused(
                "connected original gate is not unused source state",
            ));
        }
        Ok(native)
    }

    /// Borrows a complete source-checked original native edition-four record.
    ///
    /// # Errors
    /// Refuses changed custody, unrelated original requests or inconsistent full journals.
    pub fn original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: &ContentRef,
    ) -> Result<PacketConnectedNativeWitness<'a>, OperationFailure> {
        let record = self.native_record(scope, reference)?;
        let bytes = scope.controller.content(reference).map_err(unknown)?;
        self.guard(scope)?;
        Ok(PacketConnectedNativeWitness {
            reference: reference.clone(),
            bytes,
            record,
        })
    }

    /// Borrows the latest original source observation without minting permission.
    ///
    /// # Errors
    /// Refuses absent or changed original native proof and lost source custody.
    pub fn latest_original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
    ) -> Result<PacketConnectedNativeWitness<'a>, OperationFailure> {
        self.original_native_witness(scope, &self.latest_root(scope)?)
    }
}

fn operation_interval(
    original: &OperationAdmission,
) -> Result<(Position, Position), OperationFailure> {
    match original.request() {
        OperationRequest::ExactRun {
            start,
            limit,
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        } if start <= limit => Ok((*start, *limit)),
        OperationRequest::BoundarySettle { start, limit }
            if start <= limit && start.time_ps == limit.time_ps =>
        {
            Ok((*start, *limit))
        }
        _ => Err(refused("connected unsupported original full interval")),
    }
}

// The grant adapter is test-only; complete archive checks share the pure output-bound projection.
#[cfg(test)]
pub(super) fn project_grant(
    initial: &PacketConnectedInventory,
    operation: &Id,
    start: Position,
    limit: Position,
    output: bool,
) -> Result<
    crucible_node_transport::reference_packet::connected::PacketConnectedGrant,
    OperationFailure,
> {
    native::project_grant(initial, operation, start, limit, output)
}

pub(super) fn output_bound(
    inventory: &PacketConnectedInventory,
    output: bool,
) -> Result<NativeOutputBound, OperationFailure> {
    grant::output_bound(inventory, output)
}

fn controller_originals(
    controller: &crucible_node_transport::client::CnpController,
) -> impl Iterator<Item = &crucible_node_transport::client::ClientOriginal> {
    controller.originals_by_origin(crucible_node_transport::envelope::RequestOrigin::Controller)
}

pub(super) fn native_result_root(
    result: Option<&MethodResult>,
) -> Result<Option<ContentRef>, OperationFailure> {
    native::result_root(result)
}

// Only an explicit entry point chooses this closed internal dialect. It keeps
// the actual selected coordinator and never fabricates a four-tuple for five.
enum SelectedConnectedCoordinator {
    Four(PacketConnectedCoordinatorInstallation),
    Complete(PacketNative5CoordinatorInstallation),
}

impl SelectedConnectedCoordinator {
    fn precharge(&self) -> Result<(), OperationFailure> {
        use crucible_node_transport::reference_packet::coordinator::{
            PACKET_CONNECTED_COORDINATOR_BYTES, PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
        };

        match self {
            Self::Four(value) => budget::serialized_size(value, PACKET_CONNECTED_COORDINATOR_BYTES),
            Self::Complete(value) => {
                budget::serialized_size(value, PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES)
            }
        }
        .map(|_| ())
    }

    fn template(&self) -> &serde_json::Value {
        match self {
            Self::Four(value) => &value.template,
            Self::Complete(value) => &value.template,
        }
    }

    fn into_scope(
        self,
        installation: &CnpSemanticInstallation,
    ) -> Result<world::PacketConnectedWorldScope, OperationFailure> {
        match self {
            Self::Four(value) => world::PacketConnectedWorldScope::new(installation, value),
            Self::Complete(value) => {
                world::PacketConnectedWorldScope::new_complete(installation, value)
            }
        }
    }
}

impl PacketConnectedSemanticSource {
    pub(super) fn authenticate_complete_world_scope(
        &self,
        coordinator: &PacketNative5CoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        self.world.authenticate_complete_installation(coordinator)
    }
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_original_definition_data(
        &self,
    ) -> Result<&PacketConnectedDefinition, OperationFailure> {
        self.local_owner()?;
        if !self.world.is_complete() {
            return Err(refused("original complete reactive definition unavailable"));
        }
        Ok(&self.definition)
    }
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_declaration_parts_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<
        (
            &PacketConnectedDefinition,
            &PacketNative5CoordinatorInstallation,
            &SavedRuntimeActivation,
        ),
        E,
    > {
        let (coordinator, activation) = self.world.complete_retained_parts_with_error::<E>()?;
        Ok((&self.definition, coordinator, activation))
    }
}

#[path = "packet_connected_source/retained_lineage.rs"]
mod retained_lineage;

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_native_read_storage_data_with_error<
        E: StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<Option<super::retained_storage::CnpRetainedStorageReport>, E> {
        // The complete outer Source checks its actual creator first. This is
        // retained-data observation, so revoked or reaped reads remain data.
        self.current_native
            .try_borrow()
            .map_err(|_| E::refused("retained source native read already borrowed"))?
            .as_ref()
            .map(|read| E::read(read, maximum))
            .transpose()
    }
}

#[path = "packet_connected_source/complete_template.rs"]
mod complete_template;
