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
pub struct PacketProducerModelAdoption {
    snapshot: Option<PacketDecodedModelSnapshot>,
    effect_socket: Option<UnixDatagram>,
    state: Option<ProducerState>,
    events: Vec<PacketEvent>,
    outputs: Vec<PacketPublication>,
    completed: Option<PacketProgram>,
    ready: bool,
}

impl PacketProgram {
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
        attempt: &mut Option<PacketProducerModelAdoption>,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || snapshot.is_none() || effect_socket.is_none() {
            return Err(ProviderError::Conflict("model adoption original slots"));
        }
        *attempt = Some(PacketProducerModelAdoption {
            snapshot: None,
            effect_socket: None,
            state: None,
            events: Vec::new(),
            outputs: Vec::new(),
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

impl PacketProducerModelAdoption {
    /// Moves a fully reconstructed model into an empty caller-owned slot.
    ///
    /// # Errors
    /// Refuses incomplete reconstruction or an already occupied destination.
    pub fn take_completed_into(
        &mut self,
        completed: &mut Option<PacketProgram>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() || self.completed.is_none() {
            return Err(ProviderError::Conflict("model adoption completion slots"));
        }
        *completed = self.completed.take();
        Ok(())
    }
}

impl PacketProgram {
    /// Prepares every model allocation while the original fresh socket stays put.
    pub(crate) fn prepare_model_state_retained_into(
        snapshot: &mut Option<PacketDecodedModelSnapshot>,
        attempt: &mut Option<PacketProducerModelAdoption>,
    ) -> Result<(), ProviderError> {
        if attempt.is_some() || snapshot.is_none() {
            return Err(ProviderError::Conflict("prepared model original slots"));
        }
        *attempt = Some(PacketProducerModelAdoption {
            snapshot: snapshot.take(),
            effect_socket: None,
            state: None,
            events: Vec::new(),
            outputs: Vec::new(),
            completed: None,
            ready: false,
        });
        attempt
            .as_mut()
            .ok_or(ProviderError::Conflict("prepared model owner absent"))?
            .prepare_retained_data()
    }
}

impl PacketProducerModelAdoption {
    fn prepare_retained_data(&mut self) -> Result<(), ProviderError> {
        if self.ready || self.completed.is_some() || self.state.is_some() {
            return Err(ProviderError::Conflict("prepared model already attempted"));
        }
        let record = &self
            .snapshot
            .as_ref()
            .ok_or(ProviderError::Conflict("model snapshot absent"))?
            .record;
        if record.kind != PacketModelKind::Producer {
            return Err(ProviderError::Correlation("model adoption kind"));
        }
        // Borrow the full raw Value; decode failure cannot consume it.
        self.state = Some(
            ProducerState::deserialize(&record.state)
                .map_err(crucible_node_format::ContractError::from)?,
        );
        let state = self
            .state
            .as_ref()
            .ok_or(ProviderError::Conflict("model typed state absent"))?;
        authenticate_producer_data(record, state)?;
        super::super::validate_packet_program_definition(&state.events)?;
        self.events
            .try_reserve_exact(record.capacities.events)
            .map_err(|_| ProviderError::ResourceExhausted("retained model vector allocation"))?;
        if self.events.capacity() != record.capacities.events {
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
        let state = self
            .state
            .as_mut()
            .ok_or(ProviderError::Conflict("model typed state absent"))?;
        self.events.append(&mut state.events);
        self.outputs.append(&mut state.outputs);
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
        self.completed = Some(PacketProgram {
            effect_socket: socket,
            events: std::mem::take(&mut self.events),
            outputs: std::mem::take(&mut self.outputs),
            next_event: state.next_event,
            reached: state.reached,
            gate_closed: state.gate_closed,
            grants: state.grants,
            private_mutations: state.private_mutations,
            packet_effects: state.packet_effects,
            retired: state.retired,
            failed: state.failed,
        });
        Ok(())
    }
}

/// Retains every displaced fresh model field while the original socket moves.
pub(crate) struct PacketDisplacedProducerModel {
    state: ProducerState,
}

impl PacketDisplacedProducerModel {
    pub(crate) fn authenticate_fresh_data(&self) -> Result<(), ProviderError> {
        let state = &self.state;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if state.reached != zero
            || state.next_event != 0
            || !state.gate_closed
            || !state.outputs.is_empty()
            || !state.grants.is_empty()
            || !state.retired.is_empty()
            || state.private_mutations != 0
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

impl PacketProgram {
    /// Moves all displaced fields and the same socket into preowned empty slots.
    pub(crate) fn displace_original_restore_socket_into(
        original: &mut Option<Self>,
        displaced: &mut Option<PacketDisplacedProducerModel>,
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
            events,
            next_event,
            reached,
            gate_closed,
            outputs,
            grants,
            private_mutations,
            packet_effects,
            retired,
            failed,
        } = original;
        // Every operation after the take is an infallible field move.
        *displaced = Some(PacketDisplacedProducerModel {
            state: ProducerState {
                events,
                next_event,
                reached,
                gate_closed,
                outputs,
                grants,
                private_mutations,
                packet_effects,
                retired,
                failed,
            },
        });
        *socket = Some(effect_socket);
        Ok(())
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Actual model/socket custody controls intentionally panic on failed fixture invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn original() -> (PacketProgram, UnixDatagram) {
        let (writer, receiver) = UnixDatagram::pair().unwrap();
        let at = Position::new(U64::new(1), U64::new(0), Phase::Reaction);
        let model = PacketProgram::new(
            vec![PacketEvent {
                id: Id::new("retained-model-event").unwrap(),
                evaluation: at,
                completion: at,
                payload: None,
            }],
            writer,
        )
        .unwrap();
        (model, receiver)
    }

    fn decoded(model: &PacketProgram) -> PacketDecodedModelSnapshot {
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let original = model
            .capture_state(zero, PACKET_MODEL_SNAPSHOT_BYTES)
            .unwrap();
        decode_packet_model_snapshot(
            original.bytes(),
            original.reference(),
            PACKET_MODEL_SNAPSHOT_BYTES,
        )
        .unwrap()
    }

    #[test]
    fn retained_model_adoption_preserves_same_actual_socket_and_inventory() {
        let (source, _source_receiver) = original();
        let expected = source.inventory();
        let mut snapshot = Some(decoded(&source));
        let (writer, _receiver) = UnixDatagram::pair().unwrap();
        let original_fd = writer.as_raw_fd();
        let mut socket = Some(writer);
        let mut attempt = None;

        PacketProgram::adopt_model_state_retained_into(&mut snapshot, &mut socket, &mut attempt)
            .unwrap();
        let mut completed = None;
        attempt
            .as_mut()
            .unwrap()
            .take_completed_into(&mut completed)
            .unwrap();
        let restored = completed.as_ref().unwrap();

        assert!(snapshot.is_none() && socket.is_none());
        assert_eq!(restored.effect_socket.as_raw_fd(), original_fd);
        assert_eq!(restored.inventory(), expected);
        assert!(
            attempt
                .as_mut()
                .unwrap()
                .take_completed_into(&mut completed)
                .is_err()
        );
    }

    #[test]
    fn retained_model_parse_failure_preserves_full_value_and_same_socket() {
        let (source, _source_receiver) = original();
        let mut snapshot = decoded(&source);
        snapshot.record.state["next_event"] = serde_json::json!("invalid-index");
        let expected = snapshot.record.state.clone();
        let mut snapshot = Some(snapshot);
        let (writer, _receiver) = UnixDatagram::pair().unwrap();
        let original_fd = writer.as_raw_fd();
        let mut socket = Some(writer);
        let mut attempt = None;

        assert!(
            PacketProgram::adopt_model_state_retained_into(
                &mut snapshot,
                &mut socket,
                &mut attempt
            )
            .is_err()
        );
        let retained = attempt.as_ref().unwrap();
        assert_eq!(
            retained.effect_socket.as_ref().unwrap().as_raw_fd(),
            original_fd
        );
        assert_eq!(retained.snapshot.as_ref().unwrap().record.state, expected);
        assert!(retained.completed.is_none());
        assert!(snapshot.is_none() && socket.is_none());
        assert!(
            PacketProgram::adopt_model_state_retained_into(
                &mut snapshot,
                &mut socket,
                &mut attempt
            )
            .is_err()
        );
        assert_eq!(
            attempt
                .as_ref()
                .unwrap()
                .effect_socket
                .as_ref()
                .unwrap()
                .as_raw_fd(),
            original_fd
        );
    }

    #[test]
    fn retained_model_exact_original_vector_credit_refuses_one_short() {
        let (source, _source_receiver) = original();
        let mut snapshot = decoded(&source);
        assert_eq!(snapshot.record.capacities.events, 1);
        snapshot.record.capacities.events = 0;
        let mut snapshot = Some(snapshot);
        let (writer, _receiver) = UnixDatagram::pair().unwrap();
        let original_fd = writer.as_raw_fd();
        let mut socket = Some(writer);
        let mut attempt = None;

        assert!(
            PacketProgram::adopt_model_state_retained_into(
                &mut snapshot,
                &mut socket,
                &mut attempt
            )
            .is_err()
        );
        let retained = attempt.as_ref().unwrap();
        assert_eq!(
            retained.effect_socket.as_ref().unwrap().as_raw_fd(),
            original_fd
        );
        assert_eq!(retained.state.as_ref().unwrap().events.len(), 1);
        assert!(retained.completed.is_none());
    }

    #[test]
    fn prepared_model_leaves_original_socket_outside_allocation_until_bind() {
        let (mut source, _source_receiver) = original();
        source.open_gate().unwrap();
        let expected = source.inventory();
        let mut snapshot = Some(decoded(&source));
        let configuration = snapshot.as_ref().unwrap().record.configuration.clone();
        let (writer, receiver) = UnixDatagram::pair().unwrap();
        let descriptor = writer.as_raw_fd();
        receiver.set_nonblocking(true).unwrap();
        let mut socket = Some(writer);
        let mut attempt = None;

        PacketProgram::prepare_model_state_retained_into(&mut snapshot, &mut attempt).unwrap();
        let prepared = attempt.as_mut().unwrap();
        prepared.authenticate_prepared_data(&configuration).unwrap();
        assert_eq!(socket.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(prepared.effect_socket.is_none() && prepared.completed.is_none());
        let mut bytes = [0u8; 1];
        assert_eq!(
            receiver.recv(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        prepared.bind_original_socket(&mut socket).unwrap();
        let mut complete = None;
        prepared.take_completed_into(&mut complete).unwrap();
        assert!(socket.is_none());
        assert_eq!(
            complete.as_ref().unwrap().effect_socket.as_raw_fd(),
            descriptor
        );
        assert_eq!(complete.as_ref().unwrap().inventory(), expected);
        assert!(!complete.as_ref().unwrap().inventory().gate_closed);
        assert!(prepared.bind_original_socket(&mut socket).is_err());
    }

    #[test]
    fn prepared_model_failure_keeps_external_socket_and_full_original() {
        let (source, _source_receiver) = original();
        let mut captured = decoded(&source);
        captured.record.state["next_event"] = serde_json::json!("bad-index");
        let expected = captured.record.state.clone();
        let mut snapshot = Some(captured);
        let (writer, _receiver) = UnixDatagram::pair().unwrap();
        let descriptor = writer.as_raw_fd();
        let mut socket = Some(writer);
        let mut attempt = None;

        assert!(
            PacketProgram::prepare_model_state_retained_into(&mut snapshot, &mut attempt).is_err()
        );
        assert_eq!(socket.as_ref().unwrap().as_raw_fd(), descriptor);
        let retained = attempt.as_mut().unwrap();
        assert_eq!(retained.snapshot.as_ref().unwrap().record.state, expected);
        assert!(retained.effect_socket.is_none() && retained.completed.is_none());
        assert!(retained.bind_original_socket(&mut socket).is_err());
        assert_eq!(socket.as_ref().unwrap().as_raw_fd(), descriptor);
    }
}

#[path = "producer_adoption_history.rs"]
mod settled_history;
