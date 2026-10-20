//! Retains the original selected actor across a refused complete-control birth.
//!
//! Validation borrows the same actor and selection before any ownership transfer.
//! A refusal returns that original actor, including its owning effect socket; it
//! never substitutes a reconstructed model or closes the socket to report an error.

use super::*;
use std::rc::Rc;

/// Retains every original birth input together with its refusal reason.
///
/// The actor remains unopened and owned by the caller. This object grants no
/// native dispatch, capture, restoration or retry permission.
pub struct PacketCompleteControlBirthFailure<P> {
    selection: PacketControlSelection,
    program: P,
    coordinator: PacketNative5CoordinatorInstallation,
    error: ProviderError,
}

impl<P> std::fmt::Debug for PacketCompleteControlBirthFailure<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PacketCompleteControlBirthFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<P> PacketCompleteControlBirthFailure<P> {
    /// Borrows the original validation refusal without consuming native custody.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Borrows the exact original unopened actor.
    pub fn program(&self) -> &P {
        &self.program
    }

    /// Returns the unchanged selection, actor, coordinator and refusal reason.
    pub fn into_original_parts(
        self,
    ) -> (
        PacketControlSelection,
        P,
        PacketNative5CoordinatorInstallation,
        ProviderError,
    ) {
        (self.selection, self.program, self.coordinator, self.error)
    }
}

impl PacketControl {
    /// Constructs a complete producer while retaining all inputs on refusal.
    ///
    /// The full selected scope and unopened actor are checked by borrowing the
    /// originals. Successful transfer initializes control custody without another
    /// fallible validation step. The older constructor remains unchanged.
    ///
    /// # Errors
    /// Returns the same owning actor and selected scope when the complete
    /// coordinator, configuration or unopened boot state fails authentication.
    // Refusal retains all original owners inline; allocating a replacement error
    // after Hello would add a new failure path. The service precharges this slot.
    #[allow(clippy::result_large_err)]
    pub fn new_complete_producer_retained(
        selection: PacketControlSelection,
        program: PacketProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, PacketCompleteControlBirthFailure<PacketProgram>> {
        let checked = (|| {
            coordinator.validate(&selection)?;
            validate_configuration(&selection, &program.definition())?;
            let inventory = program.inventory();
            validate_unopened(
                inventory.reached,
                inventory.gate_closed,
                inventory.private_mutations.get(),
                inventory.packet_effects.get(),
                inventory.retained_outputs.is_empty(),
            )
        })();
        if let Err(error) = checked {
            return Err(PacketCompleteControlBirthFailure {
                selection,
                program,
                coordinator,
                error,
            });
        }

        Ok(Self::from_checked_complete_birth(
            selection,
            NativeProgram::OutputOnly(program),
            coordinator,
        ))
    }

    /// Constructs a complete reactive control while retaining its original socket on refusal.
    ///
    /// Exact incoming routes, configuration and unopened inventory are validated
    /// before ownership moves. Historical stage and grant association is not
    /// admitted through this initial-birth route.
    ///
    /// # Errors
    /// Returns the unchanged owning actor and selection for malformed complete
    /// scope, changed routes or an opened, advanced or input-bearing actor.
    // The complete original socket/model/scope stay in the precharged phase slot.
    // No additional error allocation occurs after validation refuses.
    #[allow(clippy::result_large_err)]
    pub fn new_complete_reactive_retained(
        selection: PacketControlSelection,
        program: PacketConnectedProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Result<Self, PacketCompleteControlBirthFailure<PacketConnectedProgram>> {
        let checked = (|| {
            coordinator.validate(&selection)?;
            validate_configuration(&selection, program.definition())?;
            validate_reactive_routes(&selection, &program, &coordinator)?;
            let inventory = program.inventory()?;
            validate_unopened(
                inventory.reached,
                inventory.gate_closed,
                inventory.reactions_completed.get(),
                inventory.packet_effects.get(),
                inventory.retained_outputs.is_empty(),
            )?;
            if !inventory.reactions.is_empty()
                || !inventory.delivered_inputs.is_empty()
                || !inventory.publications.is_empty()
                || !inventory.stages.is_empty()
                || !inventory.commits.is_empty()
            {
                return Err(ProviderError::Correlation(
                    "native5 retained birth contains input history",
                ));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(PacketCompleteControlBirthFailure {
                selection,
                program,
                coordinator,
                error,
            });
        }

        Ok(Self::from_checked_complete_birth(
            selection,
            NativeProgram::Connected(program),
            coordinator,
        ))
    }

    // All validation has completed while the caller still owned each input.
    // This transfer has no fallible model, socket or selected-scope operation.
    fn from_checked_complete_birth(
        selection: PacketControlSelection,
        program: NativeProgram,
        coordinator: PacketNative5CoordinatorInstallation,
    ) -> Self {
        Self {
            selection,
            program,
            capture_creator: std::process::id(),
            capture_identity: Rc::new(()),
            originals: BTreeMap::new(),
            begins: BTreeMap::new(),
            begin_requests: BTreeMap::new(),
            content: BTreeMap::new(),
            content_bytes: 0,
            realized: false,
            admitted: false,
            staged: None,
            active: None,
            fenced: false,
            native_effect_attempted: false,
            immediate: true,
            current_operation: None,
            terminals: BTreeMap::new(),
            common_coordinator: None,
            world_coordinator: None,
            connected_coordinator: None,
            complete_coordinator: Some(coordinator),
            complete_storage: None,
            complete_restored_hold: None,
            restoration_activation_required: false,
            complete_restored_evidence: None,
            complete_capture_profile: None,
            complete_confirmation_selection: None,
            complete_ack_emitter_selection: None,
            complete_restore_selection: None,
            complete_protocol_metadata_limits: None,
            complete_protocol_metadata_birth_facts: None,
            complete_restore_input_emitter_selection: None,
            complete_capture_allocation_selection: None,
        }
    }
}

fn validate_configuration(
    selection: &PacketControlSelection,
    configuration: &impl Serialize,
) -> Result<(), ProviderError> {
    selection.provider.validate()?;
    selection.realization.validate()?;
    selection.realize.validate()?;
    selection.world.validate()?;

    let realization = &selection.realization;
    let actual_configuration = reference(&encode(configuration)?)?;
    if realization.bindings.len() != 1
        || realization.owners.len() != 1
        || realization.descriptors.len() != 1
        || realization.owner_bindings.len() != 1
        || realization.realization_id != selection.realize.realization_id
        || realization.provider_manifest != reference(&encode(&selection.provider)?)?
        || selection.realize.requested_node_ids != [realization.descriptors[0].id.clone()]
        || selection.realize.configuration != actual_configuration
        || realization.bindings[0].compatibility.configuration_ref != actual_configuration
        || realization.descriptors[0].model_ref != actual_configuration
    {
        return Err(ProviderError::Correlation(
            "native5 retained birth selected configuration",
        ));
    }
    Ok(())
}

fn validate_unopened(
    reached: Position,
    gate_closed: bool,
    mutations: u64,
    effects: u64,
    outputs_empty: bool,
) -> Result<(), ProviderError> {
    let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
    if reached != zero || !gate_closed || mutations != 0 || effects != 0 || !outputs_empty {
        return Err(ProviderError::Correlation(
            "native5 retained birth requires unopened boot state",
        ));
    }
    Ok(())
}

fn validate_reactive_routes(
    selection: &PacketControlSelection,
    program: &PacketConnectedProgram,
    coordinator: &PacketNative5CoordinatorInstallation,
) -> Result<(), ProviderError> {
    let world: WorldBinding = serde_json::from_value(coordinator.template["world"].clone())
        .map_err(ContractError::from)?;
    let node = &selection.realization.descriptors[0].id;
    let mut count = 0usize;
    for route in world
        .connections
        .iter()
        .filter(|route| &route.consumer.node_id == node)
    {
        count += 1;
        if !program.definition().connections.iter().any(|native| {
            route.id == native.id
                && route.policy_ref == native.policy
                && route.producer == native.producer
                && route.consumer == native.consumer
                && route.minimum_latency_ps == native.delay_ps
        }) {
            return Err(ProviderError::Correlation(
                "native5 retained birth original reactive routes changed",
            ));
        }
    }
    if count != program.definition().connections.len() {
        return Err(ProviderError::Correlation(
            "native5 retained birth original reactive route population",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "birth_tests.rs"]
mod tests;
