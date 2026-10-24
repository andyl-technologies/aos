//! Installed finite packet-native semantics beneath mandatory common acceptance.
//!
//! This source oracle authenticates actual original native CNP journals and the
//! complete independently selected two-callback program. It is not an acceptance
//! policy: generic preparation still requires the independent complete normative
//! class report before ordinary Admit, and reauthenticates it on every ordinary
//! use. The distinct opaque collecting route instead requires its installed
//! Refused plan and original source custody without issuing class acceptance.
//! Portable records cannot construct common activation, admissions or tokens.

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_format::*;
use crucible_node_transport::{
    bodies::*,
    envelope::Method,
    reference_packet::{PacketProgramDefinition, control::PacketNativeRecord},
};
use serde::Serialize;
use std::cell::RefCell;

use crate::{
    node_contract::*,
    node_scheduling::{
        InputPayload, NativeInputAcknowledgement, NativeOutputBound, NativeProducerBound,
        NativePublication, NativeSchedulingObservation, RuntimeInputBatch,
    },
};

use super::{
    CnpSemanticInstallation, CnpSemanticProcessCustody, CnpSemanticRealizationScope,
    CnpSemanticSource, CnpSemanticTransition, budget, packet_common_grant_authorization, refused,
    unknown,
};

mod credit;
mod lineage;
mod native;
mod world;

/// Authenticates the source-installed finite output-only packet implementation.
///
/// Construction installs semantic validation only. It does not grant behavioral
/// acceptance or native/common readiness. The independently trusted registry and
/// mandatory acceptance policy must both reauthenticate this exact tuple.
pub struct PacketSemanticSource {
    installation: CnpSemanticInstallation,
    program: PacketProgramDefinition,
    world_scope: Option<world::PacketWorldSourceScope>,
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

/// Borrows authentic source-native original bytes without issuing permission.
///
/// Only the selected source validator constructs this view. The host fixture
/// must separately inspect its independent effect oracle and preserve all bytes;
/// decoding a record cannot create this witness or an accepted qualification.
pub struct PacketNativeWitness<'a> {
    reference: ContentRef,
    bytes: &'a [u8],
    record: PacketNativeRecord,
}

impl PacketNativeWitness<'_> {
    /// Borrows the exact original receipt identity verified against current custody.
    pub fn reference(&self) -> &ContentRef {
        &self.reference
    }

    /// Borrows the complete original record body without cloning its buffers.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Borrows the source-validated native request, inventory and original grant.
    pub fn record(&self) -> &PacketNativeRecord {
        &self.record
    }
}

impl PacketSemanticSource {
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

    fn coordinator_byte_limit(&self) -> usize {
        if self
            .world_scope
            .as_ref()
            .is_some_and(world::PacketWorldSourceScope::is_connected)
        {
            crucible_node_transport::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
        } else {
            65_536
        }
    }

    /// Checks this original source's retained collecting-world installation.
    ///
    /// This compares the complete source-owned scope, not portable Ready or an
    /// accepted qualification. Native/current registrar checks remain separate.
    ///
    /// # Errors
    /// Refuses a singleton source, changed full roster or foreign coordinator.
    pub fn authenticate_collecting_world_scope(
        &self,
        coordinator: &crucible_node_transport::reference_packet::coordinator::PacketWorldCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.world_scope
            .as_ref()
            .ok_or_else(|| refused("packet collecting-world source absent"))?
            .authenticate_installation(coordinator)
    }

    /// Checks the complete original connected coordinator of this source-2 producer.
    ///
    /// # Errors
    /// Refuses another collecting topology or a changed full installation.
    pub fn authenticate_collecting_connected_world_scope(
        &self,
        coordinator: &crucible_node_transport::reference_packet::coordinator::PacketConnectedCoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.world_scope
            .as_ref()
            .ok_or_else(|| refused("packet connected producer scope absent"))?
            .authenticate_connected_installation(coordinator)
    }

    /// Borrows one source-validated original native record and its complete body.
    ///
    /// Validation joins the current actual process and peer, the original CNP
    /// request/response association, and the independently installed finite
    /// program. This witness grants no class, common Ready or operation authority.
    ///
    /// # Errors
    /// Refuses unavailable original bytes, changed current process/source,
    /// unrelated receipts, malformed or overwide bodies, or a native inventory
    /// inconsistent with the installed complete program and original grant.
    pub fn original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
        reference: &ContentRef,
    ) -> Result<PacketNativeWitness<'a>, OperationFailure> {
        let record = self.native_record(scope, reference)?;
        let bytes = scope.controller.content(reference).map_err(unknown)?;
        Ok(PacketNativeWitness {
            reference: reference.clone(),
            bytes,
            record,
        })
    }

    /// Borrows the latest authentic original native record beneath current custody.
    ///
    /// Original controller sequence selects the observation; endpoint ordering,
    /// host polling order and portable timestamps cannot replace that identity.
    /// This read issues no grant, native ACK or qualification authority.
    ///
    /// # Errors
    /// Refuses an absent original response, changed current source, missing body,
    /// malformed receipt or inventory inconsistent with the installed programme.
    pub fn latest_original_native_witness<'a>(
        &self,
        scope: &CnpSemanticRealizationScope<'a>,
    ) -> Result<PacketNativeWitness<'a>, OperationFailure> {
        let root = self.latest_root(scope)?;
        self.original_native_witness(scope, &root)
    }

    /// Retains the complete exact installed native program and common role tuple.
    ///
    /// # Errors
    /// Refuses changed program/configuration identity, nonfinite source scope,
    /// non-output ports or optional guarantees absent from this implementation.
    pub fn new(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
    ) -> Result<Self, OperationFailure> {
        Self::new_selected(installation, program, "source-owned.packet-emitter/2")
    }

    fn new_selected(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
        profile: &str,
    ) -> Result<Self, OperationFailure> {
        Self::new_selected_edition(installation, program, profile, false)
    }

    fn new_selected_edition(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
        profile: &str,
        complete: bool,
    ) -> Result<Self, OperationFailure> {
        if complete {
            super::preparation::validate_complete_installation(&installation)?;
        } else {
            super::preparation::validate_installation(&installation)?;
        }
        budget::serialized_size(&program, 8192)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(&program).map_err(unknown)?)
            .map_err(unknown)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(unknown)?;
        let contract_bytes =
            crucible_node_transport::reference_packet::contracts::immediate_packet_contract()
                .map_err(unknown)?;
        let contract =
            canonical::content_ref(&contract_bytes, "application/json").map_err(unknown)?;
        let ports = &installation.descriptor.ports;
        let semantic_contract = if complete {
            let bytes=crucible_node_transport::reference_packet::continuation_contracts::complete_packet_contract().map_err(unknown)?;
            canonical::content_ref(&bytes, "application/json").map_err(unknown)?
        } else {
            contract.clone()
        };
        if installation.receipt_schema.id.as_str()
            != if complete {
                "source-owned.packet-receipt/5"
            } else {
                "source-owned.packet-receipt/2"
            }
            || installation.profile.profile_id.as_str() != profile
            || installation
                .provider
                .implementation
                .implementation_id
                .as_str()
                != if complete {
                    "source-owned.packet-native/5"
                } else {
                    "source-owned.packet-native/2"
                }
            || installation.exact_facet.id.as_str()
                != if complete {
                    "source-owned.packet-exact/5"
                } else {
                    "source-owned.packet-exact/2"
                }
            || installation.descriptor.roles.as_slice()
                != [Id::new("external_device").map_err(unknown)?]
            || installation.profile.roles != installation.descriptor.roles
            || installation.receipt_schema.version != if complete { 5 } else { 2 }
            || installation.receipt_schema.definition != semantic_contract
            || installation.profile.configuration_schema.id.as_str()
                != "source-owned.packet-program/1"
            || installation.profile.configuration_schema.version != 1
            || installation.profile.configuration_schema.definition != semantic_contract
            || installation.exact_facet.version != if complete { 5 } else { 2 }
            || program.schema != "source-owned.packet-program.v1"
            || program.events.len() != 2
            || program.events[0].payload.is_some()
            || program.events[1].payload.is_none()
            || program.events[1]
                .payload
                .as_ref()
                .is_some_and(|payload| payload.as_slice().len() > 32)
            || program.events[0].id == program.events[1].id
            || program.events[0].evaluation != program.events[0].completion
            || program.events[0].evaluation >= program.events[1].evaluation
            || program.events[1].completion <= program.events[1].evaluation
            || program
                .events
                .iter()
                .any(|event| event.evaluation.phase != Phase::Reaction)
            || program.events[1].completion.phase != Phase::Publication
            || installation.descriptor.model_ref != reference
            || installation.realize.configuration != reference
            || installation.binding.compatibility.configuration_ref != reference
            || ports.len() != 1
            || ports[0].lanes.len() != 1
            || ports[0].lanes[0].direction != Direction::Output
            || ports[0].id.as_str() != "wire_tx"
            || ports[0].interface_id.as_str() != "source-owned.packet-octets/1"
            || ports[0].lanes[0].id.as_str() != "output"
            || ports[0].lanes[0].payload_schema.id.as_str() != "source-owned.packet-octets/1"
            || ports[0].lanes[0].payload_schema.version != 1
            || ports[0].lanes[0].payload_schema.definition != contract
            || ports[0].lanes[0].maximum_payload_bytes.get() != 32
            || ports[0].lanes[0].maximum_pending_events.get() != 1
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
            return Err(refused(
                "packet exact source-installed finite program/role selection",
            ));
        }
        for event in &program.events {
            event.id.validate().map_err(unknown)?;
            event.evaluation.validate().map_err(unknown)?;
            event.completion.validate().map_err(unknown)?;
        }
        Ok(Self {
            installation,
            program,
            world_scope: None,
            current_native: RefCell::new(None),
            complete_storage: None,
            complete_capture_profile: None,
            complete_confirmation_selection: None,
            complete_capture_allocation_selection: None,
        })
    }

    /// Installs the distinct packet-emitter-world/3 collecting source roster.
    ///
    /// The static coordinator names all sources before launch and contains no
    /// predicted Ready rows. Native realization, local Arm and the host's three
    /// current original owners must still be authenticated independently. This
    /// constructor grants no ordinary class acceptance or activation authority.
    ///
    /// # Errors
    /// Refuses a foreign or incomplete roster, changed local source selection,
    /// unsupported ingress edition or body exceeding the unchanged finite caps.
    pub fn new_for_collecting_world(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
        coordinator: crucible_node_transport::reference_packet::coordinator::PacketWorldCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        let world_scope = world::PacketWorldSourceScope::new(&installation, coordinator)?;
        let mut source =
            Self::new_selected(installation, program, "source-owned.packet-emitter-world/3")?;
        source.world_scope = Some(world_scope);
        Ok(source)
    }

    /// Retains the unchanged output-only producer inside a connected source world.
    ///
    /// The distinct coordinator4 authenticates complete topology and actual
    /// native-three plus genuine host-owner preparation. This source has no input lane, uses
    /// unchanged source-2 native receipts and grants no ordinary qualification.
    ///
    /// # Errors
    /// Refuses changed source-2 program/profile or an incomplete connected installation.
    pub fn new_for_collecting_connected_world(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
        coordinator: crucible_node_transport::reference_packet::coordinator::PacketConnectedCoordinatorInstallation,
    ) -> Result<Self, OperationFailure> {
        let mut source =
            Self::new_selected(installation, program, "source-owned.packet-emitter-world/3")?;
        source.world_scope = Some(world::PacketWorldSourceScope::new_connected(
            &source.installation,
            coordinator,
        )?);
        Ok(source)
    }

    pub(super) fn complete_preparation_unbound(&self) -> Result<bool, OperationFailure> {
        self.complete_preparation_unbound_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_preparation_unbound_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<bool, E> {
        // The complete outer source authenticates its creator before this loan.
        if self.complete_storage.is_none() {
            return Err(E::refused("source has no complete preparation selection"));
        }
        self.current_native
            .try_borrow()
            .map(|original| original.is_none())
            .map_err(|_| E::refused("complete source native association is busy"))
    }

    pub(super) fn new_complete_collecting(
        installation: CnpSemanticInstallation,
        program: PacketProgramDefinition,
        coordinator: crucible_node_transport::reference_packet::coordinator::PacketNative5CoordinatorInstallation,
        storage_selection:crucible_node_transport::reference_packet::control::PacketNative5StorageSelection,
    ) -> Result<Self, OperationFailure> {
        storage_selection.validate().map_err(unknown)?;
        let mut source = Self::new_selected_edition(
            installation,
            program,
            "source-owned.packet-complete-original-lineage/5",
            true,
        )?;
        source.world_scope = Some(world::PacketWorldSourceScope::new_complete(
            &source.installation,
            coordinator,
        )?);
        source.complete_storage = Some(storage_selection);
        Ok(source)
    }

    pub(super) fn authenticate_complete_world_scope(
        &self,
        coordinator:&crucible_node_transport::reference_packet::coordinator::PacketNative5CoordinatorInstallation,
    ) -> Result<(), OperationFailure> {
        self.world_scope
            .as_ref()
            .ok_or_else(|| refused("complete producer world absent"))?
            .authenticate_complete_installation(coordinator)
    }

    fn authenticate_activation_record(
        &self,
        record: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        if let Some(world) = &self.world_scope {
            world.authenticate_record(record)
        } else if record.world_binding_hash == self.installation.world_binding_hash
            && record.owners == [self.owner()]
        {
            Ok(())
        } else {
            Err(refused("packet original whole-world activation changed"))
        }
    }

    fn grant_authorization(
        &self,
        original: &OperationAdmission,
        watermark: U64,
    ) -> Result<InputPayload, OperationFailure> {
        if let Some(world) = &self.world_scope {
            world.authenticate_record(original.activation().record())?;
            if world.is_complete() {
                super::packet_grant::packet_complete_grant_authorization(
                    &self.installation,
                    original,
                    watermark,
                    world.owners(),
                )
            } else {
                super::packet_grant::packet_world_grant_authorization(
                    &self.installation,
                    original,
                    watermark,
                    world.owners(),
                )
            }
        } else {
            packet_common_grant_authorization(&self.installation, original, watermark)
        }
    }

    /// Reads the first actual source-authenticated native capsule directly.
    ///
    /// No installed, vendor, schema or node callback runs here. The handle is
    /// retained only after complete original native realization authentication;
    /// portable records and source labels cannot install a replacement.
    ///
    /// # Errors
    /// Refuses absent original realization, busy/revoked/transferred ownership,
    /// changed actual process/registrar, or a contended source-handle borrow.
    pub fn authenticate_current_native(&self) -> Result<(), OperationFailure> {
        self.current_native
            .try_borrow()
            .map_err(|_| refused("packet original native read busy"))?
            .as_ref()
            .ok_or_else(|| refused("packet actual native read absent"))?
            .ensure_current()
            .map_err(unknown)
    }

    fn retain_current_native(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        let handle = native.original_source_read().map_err(unknown)?;
        let mut retained = self
            .current_native
            .try_borrow_mut()
            .map_err(|_| refused("packet original native read busy"))?;
        if let Some(original) = retained.as_ref() {
            if !original.same_original(&handle) {
                return Err(refused("packet original native owner cannot be replaced"));
            }
            original.ensure_current().map_err(unknown)
        } else {
            *retained = Some(handle);
            Ok(())
        }
    }

    fn initial(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        root: &ContentRef,
    ) -> Result<PacketNativeRecord, OperationFailure> {
        let record = self.native_record(scope, root)?;
        if !record.inventory.gate_closed
            || record.inventory.reached
                != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
            || record.inventory.pending != self.program.events
            || record.inventory.private_mutations.get() != 0
            || record.inventory.packet_effects.get() != 0
            || !record.inventory.retained_outputs.is_empty()
            || record.grant.is_some()
        {
            return Err(refused(
                "packet native initial gate is not genuine unused source state",
            ));
        }
        Ok(record)
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
            return Err(refused("packet full source body exceeds credit"));
        }
        Ok(InputPayload {
            reference: canonical::content_ref(&bytes, "application/json").map_err(unknown)?,
            bytes,
        })
    }

    fn operation_root(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<ContentRef, OperationFailure> {
        for retained in scope.controller.originals() {
            if !matches!(retained.request.method, Method::Begin | Method::Poll)
                || retained.request.operation_id.0.as_ref() != Some(original.token().operation())
            {
                continue;
            }
            let Some(response) = &retained.response else {
                continue;
            };
            let request =
                decode_request(retained.request.method, &retained.request.body).map_err(unknown)?;
            let decoded = decode_response(&request, &response.body).map_err(unknown)?;
            if let Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) =
                &decoded.result
            {
                return Ok(result.stop_receipt.clone());
            }
            if let Some(MethodResult::Poll(poll)) = decoded.result
                && let Some(outcome) = poll.outcome.0
                && let ResponseShape::Completed { result, .. } = native_shape(outcome)?
            {
                let root = result
                    .get("stop_receipt")
                    .cloned()
                    .ok_or_else(|| refused("packet completed original native root absent"))?;
                return serde_json::from_value(root).map_err(unknown);
            }
        }
        Err(refused(
            "packet original operation has no authentic completed Poll",
        ))
    }

    fn mapped_outcome(
        &self,
        scope: &CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        root: &ContentRef,
    ) -> Result<OperationOutcome, OperationFailure> {
        let native = self.native_record(scope, root)?;
        let grant = native
            .grant
            .as_ref()
            .ok_or_else(|| refused("packet original native grant absent"))?;
        let (start, limit) = match original.request() {
            OperationRequest::ExactRun {
                start,
                limit,
                boundary_policy: ExactBoundaryPolicy::HorizonPark,
            }
            | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
            _ => {
                return Err(refused(
                    "packet native outcome has unsupported original request",
                ));
            }
        };
        if grant.operation != *original.token().operation()
            || grant.start != start
            || grant.limit != limit
            || grant.inventory.reached != limit
        {
            return Err(refused(
                "packet native outcome differs from complete original authorized interval",
            ));
        }
        let observation = self.observation(original.activation(), root, &native)?;
        Ok(OperationOutcome {
            operation: grant.operation.clone(),
            node: original.token().route().node.clone(),
            owners: original.token().route().owners.clone(),
            progress: ProgressEvidence::Exact {
                reached: grant.inventory.reached,
                stop: crate::node_contract::StopReason::HorizonPark,
            },
            retained_outputs: grant.newborn.iter().map(|row| row.event.clone()).collect(),
            scheduling: Some(observation),
        })
    }
}

impl CnpSemanticSource for PacketSemanticSource {
    fn original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        limits: OriginalInputLineageLimits,
    ) -> Result<OriginalPublicationClaim, OperationFailure> {
        self.publication_claim(scope, original, outcome, publication, limits)
    }

    fn validate_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        let expected = self.publication_claim(
            scope,
            original,
            outcome,
            publication,
            OriginalInputLineageLimits::default(),
        )?;
        if &expected != claim {
            return Err(refused(
                "packet complete original publication codec changed",
            ));
        }
        Ok(())
    }

    fn validate_exact_original_publication_lineage(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        publication: &NativePublication,
        claim: &OriginalPublicationClaim,
    ) -> Result<(), OperationFailure> {
        self.validate_original_publication_lineage(scope, original, outcome, publication, claim)
    }

    fn installation(&self) -> &CnpSemanticInstallation {
        &self.installation
    }

    fn authenticate_provider(
        &self,
        native: &CnpSemanticProcessCustody,
    ) -> Result<(), OperationFailure> {
        native.authenticate_process().map_err(unknown)?;
        if self.world_scope.is_some() && native.conformance.is_none() {
            return Err(refused("packet three-owner source is collecting-only"));
        }
        let controller = native
            .controller()
            .ok_or_else(|| refused("packet actual native transport absent"))?;
        if self
            .installation
            .provider
            .implementation
            .formats
            .iter()
            .any(|format| {
                matches!(
                    format.id.as_str(),
                    "source-owned.packet-ingress/2" | "source-owned.packet-ingress/3"
                )
            })
            && !controller.has_packet_transport_schema()
        {
            return Err(refused(
                "packet common ingress requires immutable original transport schema",
            ));
        }
        if self
            .installation
            .provider
            .implementation
            .formats
            .iter()
            .any(|format| format.id.as_str() == "source-owned.packet-ingress/4")
            && !controller.has_connected_packet_transport_schema()
        {
            return Err(refused(
                "packet connected producer requires immutable original transport4",
            ));
        }
        if self.complete_storage.is_some() {
            controller
                .authenticate_native5_source_codec()
                .map_err(crate::node_adapters::cnp::semantic::refused_display)?;
        }

        if !self
            .installation
            .provider
            .implementation
            .artifacts
            .iter()
            .any(|artifact| {
                artifact.role.as_str() == "executable"
                    && artifact.content == *controller.peer_executable()
            })
            || controller.peer_pid() != native.provider_pid()
        {
            return Err(refused(
                "packet actual native executable/peer is not the installed source",
            ));
        }
        Ok(())
    }

    fn preflight_transition(
        &self,
        native: &CnpSemanticProcessCustody,
        transition: CnpSemanticTransition,
    ) -> Result<(), OperationFailure> {
        self.authenticate_provider(native)?;
        let prefix = match transition {
            CnpSemanticTransition::Preparation => credit::Prefix::Preparation,
            CnpSemanticTransition::Readiness => credit::Prefix::Stage,
            CnpSemanticTransition::Observation => credit::Prefix::Observation,
            CnpSemanticTransition::Admission | CnpSemanticTransition::Query => {
                credit::Prefix::Query
            }
            CnpSemanticTransition::Retirement => credit::Prefix::Retirement,
        };
        prefix.preflight(
            native
                .controller()
                .ok_or_else(|| refused("packet source prefix has no original native controller"))?,
        )
    }

    fn authenticate_realization(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), OperationFailure> {
        self.authenticate_provider(scope.native)?;
        if scope.discovery.provider_manifest != self.installation.provider
            || scope.realization.realization_manifest.descriptors
                != [self.installation.descriptor.clone()]
            || scope.realization.realization_manifest.bindings
                != [self.installation.binding.clone()]
            || scope.realization.realization_manifest.owner_bindings
                != [self.installation.owner.clone()]
            || scope.realization.realization_manifest.owners
                != [self.installation.owner.owner.clone()]
            || scope.realization.realization_manifest.realization_id
                != self.installation.realize.realization_id
        {
            return Err(refused(
                "packet complete original realized source selection changed",
            ));
        }
        let native = self.initial(&scope, &scope.realization.closed_gate_receipt)?;
        let request =
            decode_request(native.original.method, &native.original.body).map_err(unknown)?;
        if !matches!(request, RequestBody::Realize(ref request) if request == &self.installation.realize)
        {
            return Err(refused(
                "packet native gate belongs to a different original Realize",
            ));
        }
        if let Some(world) = &self.world_scope {
            world.authenticate_realization(scope.realization)?;
        }
        self.retain_current_native(scope.native)
    }

    fn preflight_operation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<(), OperationFailure> {
        credit::Prefix::Operation.preflight(scope.controller)?;
        self.grant_authorization(original, U64::new(0))?;
        self.authenticate_provider(scope.native)?;
        let current = self.latest(&scope)?;
        let (start, limit) = match original.request() {
            OperationRequest::ExactRun { start, limit, .. }
            | OperationRequest::BoundarySettle { start, limit } => (*start, *limit),
            _ => return Err(refused("packet unsupported original operation")),
        };
        if current.inventory.reached != start
            || current
                .inventory
                .pending
                .iter()
                .any(|event| event.evaluation < limit && event.completion >= limit)
        {
            return Err(refused(
                "packet callback straddles common exclusive cut or start differs from native",
            ));
        }
        // This finite source requires a complete callback. A partial native
        // stop remains a useful component witness, not an invented common stop.
        budget::serialized_size(&current, self.installation.maximum_result_bytes)?;
        Ok(())
    }

    fn status(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<NodeStatus, OperationFailure> {
        let native = self.latest(&scope)?;
        Ok(NodeStatus {
            lifecycle: if native.inventory.gate_closed {
                Lifecycle::Prepared
            } else {
                Lifecycle::Stopped
            },
            physical: PhysicalState::Unknown,
            boundary: Some(native.inventory.reached),
        })
    }

    fn prepared_owner(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<PreparedOwner, OperationFailure> {
        self.validate_readiness(scope, record, ready)?;
        Ok(PreparedOwner {
            owner_id: self.owner().owner,
            incarnation_id: self.owner().incarnation,
            owner_generation: self.owner().generation,
            binding_hashes: vec![self.installation.binding.identity().map_err(unknown)?],
            prepared_token: scope.realization.prepared_token.clone(),
            ready_receipt: ready.ready_receipt.clone(),
            extensions: Extensions::new(),
        })
    }

    fn validate_initial_preparation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.validate_readiness(scope, record, ready)?;
        let current = self.latest(&scope)?;
        if current.inventory != self.initial(&scope, &ready.ready_receipt)?.inventory {
            return Err(refused("packet native preparation has already changed"));
        }
        Ok(())
    }

    fn readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        response: &ActivateResult,
    ) -> Result<ReadyAttestation, OperationFailure> {
        let native = self.initial(&scope, &response.activation_receipt)?;
        let request =
            decode_request(native.original.method, &native.original.body).map_err(unknown)?;
        let RequestBody::Activate(request) = request else {
            return Err(refused("packet readiness has no original Activate"));
        };
        self.authenticate_activation_record(record)?;
        if record.world_binding_hash != self.installation.world_binding_hash
            || record.boundary != native.inventory.reached
            || request.activation_id != record.activation_id
            || request.world_generation != record.generation
            || request.gate_id != self.installation.gate
            || response.staged_owner_ids != [self.owner().owner]
            || !response.staged
        {
            return Err(refused(
                "packet actual original readiness differs from complete common preparation",
            ));
        }
        Ok(ReadyAttestation {
            owners: vec![self.owner()],
            boundary: native.inventory.reached,
            state_inventory: response.activation_receipt.clone(),
            ready_receipt: response.activation_receipt.clone(),
        })
    }

    fn validate_readiness(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        let native = self.initial(&scope, &ready.ready_receipt)?;
        self.authenticate_activation_record(record)?;
        if ready.owners != [self.owner()]
            || ready.boundary != record.boundary
            || ready.boundary != native.inventory.reached
            || ready.state_inventory != ready.ready_receipt
            || record.world_binding_hash != self.installation.world_binding_hash
        {
            return Err(refused(
                "packet retained native readiness/common owner association changed",
            ));
        }
        let RequestBody::Activate(request) =
            decode_request(native.original.method, &native.original.body).map_err(unknown)?
        else {
            return Err(refused("packet readiness original method changed"));
        };
        if request.activation_id != record.activation_id
            || request.world_generation != record.generation
        {
            return Err(refused(
                "packet readiness belongs to a different original activation",
            ));
        }
        Ok(())
    }

    fn preflight_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        credit::Prefix::WorldActivation.preflight(scope.controller)?;
        self.authenticate_provider(scope.native)?;
        let record = activation.record();
        let owners = activation
            .prepared_owners()
            .ok_or_else(|| refused("packet complete original prepared owners absent"))?;
        let coordinator = activation
            .coordinator_snapshot()
            .ok_or_else(|| refused("packet complete original coordinator bytes absent"))?;
        self.authenticate_activation_record(record)?;
        let local = if let Some(world) = &self.world_scope {
            world.authenticate_prepared(owners, scope.realization)?
        } else {
            if owners.len() != 1
                || owners[0].owner_id != self.owner().owner
                || owners[0].incarnation_id != self.owner().incarnation
                || owners[0].owner_generation != self.owner().generation
                || owners[0].binding_hashes
                    != [self.installation.binding.identity().map_err(unknown)?]
                || owners[0].prepared_token != scope.realization.prepared_token
            {
                return Err(refused(
                    "packet complete original common preparation changed",
                ));
            }
            &owners[0]
        };
        let ready = self.initial(&scope, &local.ready_receipt)?;
        let current = self.latest(&scope)?;
        if current.inventory != ready.inventory {
            return Err(refused(
                "packet source state changed before original global gate opening",
            ));
        }
        coordinator
            .reference
            .verify(&coordinator.bytes)
            .map_err(unknown)?;
        if let Some(world) = &self.world_scope {
            world.authenticate_coordinator(&coordinator.bytes)?;
        }
        let data = canonical::parse_json(&coordinator.bytes, self.coordinator_byte_limit())
            .map_err(unknown)?;
        let saved: SavedRuntimeActivation = serde_json::from_value(
            data.get("activation")
                .cloned()
                .ok_or_else(|| refused("packet full original coordinator activation absent"))?,
        )
        .map_err(unknown)?;
        if data.get("schema").and_then(serde_json::Value::as_str)
            != Some("crucible/coordinator-initial/1")
            || saved != SavedRuntimeActivation::from(record)
            || data.get("clock") != Some(&serde_json::to_value(record.boundary).map_err(unknown)?)
            || data
                .get("nodes")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|nodes| nodes.len() != record.owners.len())
            || data
                .get("connections")
                .and_then(serde_json::Value::as_array)
                .is_none_or(|connections| {
                    if self
                        .world_scope
                        .as_ref()
                        .is_some_and(|world| world.is_connected())
                    {
                        connections.is_empty()
                    } else {
                        !connections.is_empty()
                    }
                })
        {
            return Err(refused(
                "packet common gate lacks authentic whole initial coordinator scope",
            ));
        }
        Ok(())
    }

    fn validate_world_activation(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &WorldActivateResult,
    ) -> Result<(), OperationFailure> {
        let native = self.native_record(&scope, &response.activation_receipt)?;
        let RequestBody::WorldActivate(request) =
            decode_request(native.original.method, &native.original.body).map_err(unknown)?
        else {
            return Err(refused("packet global gate lacks original WorldActivate"));
        };
        let coordinator = activation
            .coordinator_snapshot()
            .ok_or_else(|| refused("packet complete common coordinator absent"))?;
        let owners = activation
            .prepared_owners()
            .ok_or_else(|| refused("packet complete original common preparation absent"))?;
        let manifest: ActivationManifest = canonical::decode(
            scope
                .controller
                .content(&request.activation_manifest)
                .map_err(unknown)?,
            65_536,
        )
        .map_err(unknown)?;
        coordinator
            .reference
            .verify(&coordinator.bytes)
            .map_err(unknown)?;
        if let Some(world) = &self.world_scope {
            world.authenticate_coordinator(&coordinator.bytes)?;
        }
        let data = canonical::parse_json(&coordinator.bytes, self.coordinator_byte_limit())
            .map_err(unknown)?;
        let saved: SavedRuntimeActivation = serde_json::from_value(
            data.get("activation")
                .cloned()
                .ok_or_else(|| refused("packet original initial coordinator activation absent"))?,
        )
        .map_err(unknown)?;
        self.authenticate_activation_record(activation.record())?;
        if let Some(world) = &self.world_scope {
            world.authenticate_prepared(owners, scope.realization)?;
        }
        if data.get("schema").and_then(serde_json::Value::as_str)
            != Some("crucible/coordinator-initial/1")
            || saved != SavedRuntimeActivation::from(activation.record())
            || request.activation_id != activation.record().activation_id
            || request.world_generation != activation.record().generation
            || request.transaction_id != self.installation.transaction
            || manifest.owners != owners
            || manifest.coordinator_state_ref != coordinator.reference
            || scope
                .controller
                .content(&coordinator.reference)
                .map_err(unknown)?
                != coordinator.bytes
            || native.inventory.gate_closed
            || !native.inventory.retained_outputs.is_empty()
            || native.inventory.pending != self.program.events
        {
            return Err(refused(
                "packet actual all-owner gate is not bound to original opaque common publication",
            ));
        }
        Ok(())
    }

    fn input_batch(&self, _: &RuntimeInputBatch, _: U64) -> Result<InputBatch, OperationFailure> {
        Err(refused("packet source has no admitted ingress lane"))
    }

    fn input_acknowledgement(
        &self,
        _: CnpSemanticRealizationScope<'_>,
        _: &RuntimeInputBatch,
        _: &InputResult,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        Err(refused("packet source cannot acknowledge ingress"))
    }

    fn boundary_policy(
        &self,
        _: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
    ) -> Result<BoundaryPolicy, OperationFailure> {
        self.grant_authorization(original, U64::new(0))?;
        Ok(BoundaryPolicy::OrdinaryStop)
    }

    fn input_authorization(
        &self,
        _: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        watermark: U64,
    ) -> Result<InputPayload, OperationFailure> {
        self.grant_authorization(original, watermark)
    }

    fn outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        response: &ResponseBody,
    ) -> Result<OperationOutcome, OperationFailure> {
        let Some(MethodResult::ExactRun(result) | MethodResult::BoundarySettle(result)) =
            &response.result
        else {
            return Err(refused(
                "packet common outcome is not exact original completion",
            ));
        };
        let outcome = self.mapped_outcome(&scope, original, &result.stop_receipt)?;
        budget::serialized_size(&outcome, self.installation.maximum_result_bytes)?;
        Ok(outcome)
    }

    fn validate_outcome(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
    ) -> Result<(), OperationFailure> {
        let root = self.operation_root(&scope, original)?;
        if self.mapped_outcome(&scope, original, &root)? != *outcome {
            return Err(refused("packet original native outcome changed"));
        }
        Ok(())
    }

    fn scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        response: &ObserveResult,
    ) -> Result<NativeSchedulingObservation, OperationFailure> {
        if !response.complete || response.observations.len() != 1 {
            return Err(refused(
                "packet complete original native observation absent",
            ));
        }
        let root = &response.observations[0].measurement_ref;
        let native = self.native_record(&scope, root)?;
        self.observation(activation, root, &native)
    }

    fn validate_scheduling(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        observation: &NativeSchedulingObservation,
    ) -> Result<(), OperationFailure> {
        let native = self.native_record(&scope, &observation.proof_ref)?;
        if self.observation(activation, &observation.proof_ref, &native)? != *observation {
            return Err(refused(
                "packet actual original scheduling inventory changed",
            ));
        }
        Ok(())
    }

    fn evidence(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        activation: &WorldActivation,
        original: Option<&OperationAdmission>,
        references: &[ContentRef],
        maximum_bytes: usize,
    ) -> Result<Vec<InputPayload>, OperationFailure> {
        self.authenticate_activation_record(activation.record())?;
        if references.len() > 32 {
            return Err(refused(
                "packet evidence scope or association credit changed",
            ));
        }
        let current = if let Some(original) = original {
            let root = self.operation_root(&scope, original)?;
            self.native_record(&scope, &root)?
        } else {
            self.latest(&scope)?
        };
        let mut total = 0usize;
        let mut planned = Vec::with_capacity(references.len());
        for reference in references {
            let complete = self
                .world_scope
                .as_ref()
                .is_some_and(|world| world.is_complete());
            let retained_payload = if complete {
                current.inventory.retained_outputs.iter().find(|row| {
                    canonical::content_ref(row.payload.as_slice(), "application/octet-stream")
                        .ok()
                        .as_ref()
                        == Some(reference)
                })
            } else {
                None
            };
            let bytes = if let Some(row) = retained_payload {
                reference.verify(row.payload.as_slice()).map_err(unknown)?;
                if let Ok(stored) = scope.controller.content(reference) {
                    if stored != row.payload.as_slice() {
                        return Err(refused("complete producer original raw payload changed"));
                    }
                    stored
                } else {
                    row.payload.as_slice()
                }
            } else if let Ok(bytes) = scope.controller.content(reference) {
                self.authenticate_record_evidence(&scope, reference)?;
                bytes
            } else {
                current
                    .inventory
                    .retained_outputs
                    .iter()
                    .find_map(|row| {
                        reference
                            .verify(row.payload.as_slice())
                            .ok()
                            .map(|()| row.payload.as_slice())
                    })
                    .ok_or_else(|| {
                        refused("packet requested evidence has no native original body")
                    })?
            };
            total = total
                .checked_add(bytes.len())
                .filter(|size| *size <= maximum_bytes)
                .ok_or_else(|| refused("packet full evidence credit exceeds original budget"))?;
            planned.push((reference, bytes));
        }
        Ok(planned
            .into_iter()
            .map(|(reference, bytes)| InputPayload {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            })
            .collect())
    }

    fn consumption(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        outcome: &OperationOutcome,
        outputs: &[Id],
    ) -> Result<InputPayload, OperationFailure> {
        self.validate_outcome(scope, original, outcome)?;
        if outputs != outcome.retained_outputs {
            return Err(refused(
                "packet consumption omits or changes original outputs",
            ));
        }
        self.payload(
            &serde_json::json!({
                "schema": "source-owned.packet-consumption.v1",
                "operation": original.token().operation(),
                "outputs": outputs,
            }),
            self.installation.maximum_authorization_bytes.min(8192),
        )
    }

    fn validate_retirement(
        &self,
        scope: CnpSemanticRealizationScope<'_>,
        original: &OperationAdmission,
        consumption: &InputPayload,
        response: &RetireResult,
    ) -> Result<(), OperationFailure> {
        consumption
            .reference
            .verify(&consumption.bytes)
            .map_err(unknown)?;
        let root = self.operation_root(&scope, original)?;
        let outcome = self.mapped_outcome(&scope, original, &root)?;
        let expected = self.consumption(scope, original, &outcome, &outcome.retained_outputs)?;
        if expected != *consumption
            || response.retired_operation_ids != [original.token().operation().clone()]
        {
            return Err(refused(
                "packet original native consumption/retirement changed",
            ));
        }
        Ok(())
    }

    fn reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        owner: &OwnerIdentity,
    ) -> Result<NativeReclamationReceipt, OperationFailure> {
        if *owner != self.owner() || !native.kernel_resources_reclaimed().map_err(unknown)? {
            return Err(refused(
                "packet original native resources have not been authentically reclaimed",
            ));
        }
        // The installed source owns only process-local sockets/program state.
        // Kernel reaping and original empty-group proof release these handles;
        // output/receipt bodies remain in the common owning capsule separately.
        let proof = self.payload(
            &serde_json::json!({"schema":"source-owned.packet-reclaimed.v1",
            "original_pid":native.provider_pid(),"owner":owner,"actual_kernel_reaped":true,
            "implementation":self.installation.binding.compatibility.implementation}),
            self.installation.maximum_result_bytes,
        )?;
        Ok(NativeReclamationReceipt {
            owner: owner.clone(),
            receipt: proof.reference,
        })
    }

    fn validate_reclamation(
        &self,
        native: &CnpSemanticProcessCustody,
        receipt: &NativeReclamationReceipt,
    ) -> Result<(), OperationFailure> {
        if self.reclamation(native, &receipt.owner)? != *receipt {
            return Err(refused(
                "packet original source reclamation receipt changed",
            ));
        }
        Ok(())
    }
}

fn native_shape(
    body: serde_json::Map<String, serde_json::Value>,
) -> Result<ResponseShape, OperationFailure> {
    let shape: ResponseShape =
        serde_json::from_value(serde_json::Value::Object(body)).map_err(unknown)?;
    shape.validate().map_err(unknown)?;
    Ok(shape)
}

impl PacketSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_retained_declaration_parts_with_error<E: StorageError>(
        &self,
    ) -> Result<(&PacketProgramDefinition, &crucible_node_transport::reference_packet::coordinator::PacketNative5CoordinatorInstallation, &SavedRuntimeActivation), E>{
        let (coordinator, activation) = self
            .world_scope
            .as_ref()
            .ok_or_else(|| E::refused("retained complete producer world absent"))?
            .complete_retained_parts_with_error::<E>()?;
        Ok((&self.program, coordinator, activation))
    }
}

impl PacketSemanticSource {
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

impl PacketSemanticSource {
    // The returned immutable model is a sizing loan, never current native state.
    pub(super) fn original_program_data(&self) -> &PacketProgramDefinition {
        &self.program
    }
}

impl PacketSemanticSource {
    pub(super) fn original_restored_producer_inventory_data(
        &self,
        record: &crucible_node_transport::reference_packet::control::PacketNativeRecord,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        self.inventory(record)
            .map_err(|_| crate::node_contract::RuntimeError::InvalidReceipt)
    }
}

#[path = "packet_source/complete_template.rs"]
mod complete_template;
