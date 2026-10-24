//! Retains decoded originals and the same fresh socket through model adoption.
//!
//! This data reconstruction grants no Core, Control, activation or restore
//! permission. The enclosing native installer must authenticate its source-signed
//! archive and keep its distinct physical gate held until actual activation.

use super::*;
use serde::Deserialize;

/// Owns one model adoption attempt, including partial allocations and socket.
///
/// A failed attempt remains inspectable and cannot be renewed or overwritten.
pub struct PacketReactiveModelAdoption {
    snapshot: Option<PacketDecodedModelSnapshot>,
    effect_socket: Option<UnixDatagram>,
    state: Option<ConnectedState>,
    reactions: Vec<PacketReaction>,
    delivered_inputs: Vec<PacketDeliveredInput>,
    publications: Vec<PacketPendingPublication>,
    outputs: Vec<PacketConnectedPublication>,
    stages: Vec<OriginalStage>,
    completed: Option<PacketConnectedProgram>,
    ready: bool,
}

impl PacketConnectedProgram {
    /// Retains both inputs before decoding or reserving exact model vectors.
    ///
    /// The caller keeps the attempt slot outside callback/unwind boundaries.
    /// Every refusal leaves original inputs in their slots or in that same
    /// attempt. A socket enters the completed model only after all checks.
    ///
    /// # Errors
    /// Refuses occupied slots, absent inputs, wrong model/definition/history,
    /// incompatible recorded capacities or unavailable allocation credit.
    pub fn adopt_model_state_retained_into(
        snapshot: &mut Option<PacketDecodedModelSnapshot>,
        effect_socket: &mut Option<UnixDatagram>,
        attempt: &mut Option<PacketReactiveModelAdoption>,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || snapshot.is_none() || effect_socket.is_none() {
            return Err(ProviderError::Conflict("model adoption original slots"));
        }
        *attempt = Some(PacketReactiveModelAdoption {
            snapshot: None,
            effect_socket: None,
            state: None,
            reactions: Vec::new(),
            delivered_inputs: Vec::new(),
            publications: Vec::new(),
            outputs: Vec::new(),
            stages: Vec::new(),
            completed: None,
            ready: false,
        });
        let owner = attempt
            .as_mut()
            .ok_or(ProviderError::Conflict("model adoption owner absent"))?;
        owner.snapshot = snapshot.take();
        owner.effect_socket = effect_socket.take();
        owner.prepare_retained_data()?;
        owner.finish_retained_socket()
    }
}

impl PacketReactiveModelAdoption {
    /// Moves a fully reconstructed model into an empty caller-owned slot.
    ///
    /// # Errors
    /// Refuses incomplete reconstruction or an already occupied destination.
    pub fn take_completed_into(
        &mut self,
        completed: &mut Option<PacketConnectedProgram>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() || self.completed.is_none() {
            return Err(ProviderError::Conflict("model adoption completion slots"));
        }
        *completed = self.completed.take();
        Ok(())
    }
}

impl PacketConnectedProgram {
    /// Prepares every model allocation while the original fresh socket stays put.
    pub(crate) fn prepare_model_state_retained_into(
        snapshot: &mut Option<PacketDecodedModelSnapshot>,
        attempt: &mut Option<PacketReactiveModelAdoption>,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || snapshot.is_none() {
            return Err(ProviderError::Conflict("prepared model original slots"));
        }
        *attempt = Some(PacketReactiveModelAdoption {
            snapshot: snapshot.take(),
            effect_socket: None,
            state: None,
            reactions: Vec::new(),
            delivered_inputs: Vec::new(),
            publications: Vec::new(),
            outputs: Vec::new(),
            stages: Vec::new(),
            completed: None,
            ready: false,
        });
        attempt
            .as_mut()
            .ok_or(ProviderError::Conflict("prepared model owner absent"))?
            .prepare_retained_data()
    }
}

impl PacketReactiveModelAdoption {
    fn prepare_retained_data(&mut self) -> Result<(), ProviderError> {
        if self.ready || self.completed.is_some() || self.state.is_some() {
            return Err(ProviderError::Conflict("prepared model already attempted"));
        }
        let record = &self
            .snapshot
            .as_ref()
            .ok_or(ProviderError::Conflict("model snapshot absent"))?
            .record;
        if record.kind != PacketModelKind::Reactive {
            return Err(ProviderError::Correlation("model adoption kind"));
        }
        // Borrow the full raw Value; decode failure cannot consume it.
        self.state = Some(
            ConnectedState::deserialize(&record.state)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let state = self
            .state
            .as_ref()
            .ok_or(ProviderError::Conflict("model typed state absent"))?;
        authenticate_connected_data(record, state)?;
        super::super::validate_connected_program_definition(&state.definition)?;
        self.reactions
            .try_reserve_exact(record.capacities.reactions)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.reactions.capacity() != record.capacities.reactions {
            return Err(ProviderError::ResourceExhausted(
                "retained model exact vector capacity",
            ));
        }
        self.delivered_inputs
            .try_reserve_exact(record.capacities.delivered_inputs)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.delivered_inputs.capacity() != record.capacities.delivered_inputs {
            return Err(ProviderError::ResourceExhausted(
                "retained model exact vector capacity",
            ));
        }
        self.publications
            .try_reserve_exact(record.capacities.publications)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.publications.capacity() != record.capacities.publications {
            return Err(ProviderError::ResourceExhausted(
                "retained model exact vector capacity",
            ));
        }
        self.outputs
            .try_reserve_exact(record.capacities.outputs)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.outputs.capacity() != record.capacities.outputs {
            return Err(ProviderError::ResourceExhausted(
                "retained model exact vector capacity",
            ));
        }
        self.stages
            .try_reserve_exact(record.capacities.stages)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.stages.capacity() != record.capacities.stages {
            return Err(ProviderError::ResourceExhausted(
                "retained model exact vector capacity",
            ));
        }
        let state = self
            .state
            .as_mut()
            .ok_or(ProviderError::Conflict("model typed state absent"))?;
        self.reactions.append(&mut state.reactions);
        self.delivered_inputs.append(&mut state.delivered_inputs);
        self.publications.append(&mut state.publications);
        self.outputs.append(&mut state.outputs);
        self.stages.append(&mut state.stages);
        self.ready = true;
        Ok(())
    }

    /// Authenticates prepared data before any original socket can be moved.
    pub(crate) fn authenticate_prepared_data(
        &self,
        configuration: &crucible_node_format::ContentRef,
    ) -> Result<(), ProviderError> {
        if !self.ready
            || self.state.is_none()
            || self.completed.is_some()
            || self.effect_socket.is_some()
            || self
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| &snapshot.record.configuration != configuration)
        {
            return Err(ProviderError::Correlation(
                "prepared model configuration or phase",
            ));
        }
        Ok(())
    }

    /// Takes the same freshly owned socket only after all model allocation succeeds.
    pub(crate) fn bind_original_socket(
        &mut self,
        socket: &mut Option<UnixDatagram>,
    ) -> Result<(), ProviderError> {
        if !self.ready
            || self.state.is_none()
            || self.completed.is_some()
            || self.effect_socket.is_some()
            || socket.is_none()
        {
            return Err(ProviderError::Conflict("prepared model socket slots"));
        }
        self.effect_socket = socket.take();
        self.finish_retained_socket()
    }

    fn finish_retained_socket(&mut self) -> Result<(), ProviderError> {
        if !self.ready
            || self.state.is_none()
            || self.completed.is_some()
            || self.effect_socket.is_none()
        {
            return Err(ProviderError::Conflict("prepared model completion phase"));
        }
        let state = self
            .state
            .take()
            .ok_or(ProviderError::Conflict("model typed state absent"))?;
        let socket = match self.effect_socket.take() {
            Some(socket) => socket,
            None => {
                self.state = Some(state);
                return Err(ProviderError::Conflict("model original socket absent"));
            }
        };
        // All operations after the socket transfer are infallible field moves.
        self.completed = Some(PacketConnectedProgram {
            effect_socket: socket,
            native_pid: std::process::id(),
            reactions: std::mem::take(&mut self.reactions),
            delivered_inputs: std::mem::take(&mut self.delivered_inputs),
            publications: std::mem::take(&mut self.publications),
            outputs: std::mem::take(&mut self.outputs),
            stages: std::mem::take(&mut self.stages),
            definition: state.definition,
            reached: state.reached,
            gate_closed: state.gate_closed,
            grants: state.grants,
            retired: state.retired,
            reactions_completed: state.reactions_completed,
            packet_effects: state.packet_effects,
            failed: state.failed,
        });
        Ok(())
    }
}

/// Retains every displaced fresh model field while the original socket moves.
pub(crate) struct PacketDisplacedReactiveModel {
    state: ConnectedState,
}

impl PacketDisplacedReactiveModel {
    pub(crate) fn authenticate_fresh_data(&self) -> Result<(), ProviderError> {
        let state = &self.state;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if state.reached != zero
            || state.native_pid != std::process::id()
            || !state.gate_closed
            || !state.reactions.is_empty()
            || !state.delivered_inputs.is_empty()
            || !state.publications.is_empty()
            || !state.outputs.is_empty()
            || !state.stages.is_empty()
            || !state.grants.is_empty()
            || !state.retired.is_empty()
            || state.reactions_completed != 0
            || state.packet_effects != 0
            || state.failed
        {
            return Err(ProviderError::Correlation(
                "displaced original model was not fresh",
            ));
        }
        Ok(())
    }
}

impl PacketConnectedProgram {
    /// Moves all displaced fields and the same socket into preowned empty slots.
    pub(crate) fn displace_original_restore_socket_into(
        original: &mut Option<Self>,
        displaced: &mut Option<PacketDisplacedReactiveModel>,
        socket: &mut Option<UnixDatagram>,
    ) -> Result<(), ProviderError> {
        if original.is_none() || displaced.is_some() || socket.is_some() {
            return Err(ProviderError::Conflict("original model displacement slots"));
        }
        let original = original
            .take()
            .ok_or(ProviderError::Conflict("original model absent"))?;
        let Self {
            effect_socket,
            definition,
            native_pid,
            reached,
            gate_closed,
            reactions,
            delivered_inputs,
            publications,
            outputs,
            stages,
            grants,
            retired,
            reactions_completed,
            packet_effects,
            failed,
        } = original;
        // Every operation after the take is an infallible field move.
        *displaced = Some(PacketDisplacedReactiveModel {
            state: ConnectedState {
                definition,
                native_pid,
                reached,
                gate_closed,
                reactions,
                delivered_inputs,
                publications,
                outputs,
                stages,
                grants,
                retired,
                reactions_completed,
                packet_effects,
                failed,
            },
        });
        *socket = Some(effect_socket);
        Ok(())
    }
}

#[path = "connected_adoption_history.rs"]
mod settled_history;
