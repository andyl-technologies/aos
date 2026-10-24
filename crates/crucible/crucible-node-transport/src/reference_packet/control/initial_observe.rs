//! Checks the genuine Source14 first-report model before allocating report owners.
//!
//! This defining census is DATA only. The actual private report scope must first
//! authenticate the same Source14 boot and completed baseline. No public state,
//! portable row, imported snapshot or empty-history label can create that scope.

use super::*;
use std::mem::size_of;

impl PacketProgram {
    fn authenticate_original_initial_observation_data(&self) -> Result<(), ProviderError> {
        let Self {
            effect_socket: _,
            events: _,
            next_event,
            reached,
            gate_closed,
            outputs,
            grants,
            private_mutations,
            packet_effects,
            retired,
            failed,
        } = self;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        if *failed
            || *gate_closed
            || *next_event != 0
            || *reached != zero
            || !outputs.is_empty()
            || !grants.is_empty()
            || !retired.is_empty()
            || *private_mutations != 0
            || *packet_effects != 0
        {
            return Err(refused());
        }
        Ok(())
    }
}

impl PacketControl {
    /// Checks a fresh activated Control without constructing an inventory clone.
    ///
    /// The actual first report scope supplies Source/currentness authority.
    /// Arbitrary constructed and imported owners cannot use this census alone.
    ///
    /// # Errors
    /// Refuses unavailable, restored, unfinished or used Control/model state.
    pub(crate) fn authenticate_original_initial_observation_data(
        &self,
    ) -> Result<(), ProviderError> {
        // A new future-affecting Control field must explicitly rejoin this
        // census rather than silently inherit the initial-state projection.
        let Self {
            selection: _,
            program: _,
            complete_restored_evidence: _,
            complete_restored_hold: _,
            restoration_activation_required: _,
            capture_creator: _,
            capture_identity: _,
            originals: _,
            begins: _,
            begin_requests: _,
            content: _,
            content_bytes: _,
            realized: _,
            admitted: _,
            staged: _,
            active: _,
            fenced: _,
            native_effect_attempted: _,
            immediate: _,
            current_operation: _,
            terminals: _,
            common_coordinator: _,
            world_coordinator: _,
            connected_coordinator: _,
            complete_coordinator: _,
            complete_storage: _,
            complete_capture_profile: _,
            complete_confirmation_selection: _,
            complete_ack_emitter_selection: _,
            complete_restore_selection: _,
            complete_protocol_metadata_limits: _,
            complete_protocol_metadata_birth_facts: _,
            complete_restore_input_emitter_selection: _,
            complete_capture_allocation_selection: _,
        } = self;
        if self.capture_creator != std::process::id() || self.fenced
            || !self.immediate || !self.realized || !self.admitted
            || self.staged.is_none() || self.active.is_none()
            || self.complete_restored_evidence.is_some() || self.complete_restored_hold.is_some()
            || self.restoration_activation_required || self.current_operation.is_some()
            // The authenticated boot dispatches Discover/Realize/Admit, then
            // the first activation supplies Activate/WorldActivate. Any extra
            // cached method, including a refused Input/Poll/Retire, is not this
            // closed initial producer and cannot borrow its smaller row.
            || self.originals.len() != 5
            || !self.begins.is_empty() || !self.begin_requests.is_empty() || !self.terminals.is_empty()
            || self.common_coordinator.is_some() || self.world_coordinator.is_some()
            || self.connected_coordinator.is_some() || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_capture_allocation_selection != Some(
                super::super::service::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(refused());
        }
        match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.authenticate_original_initial_observation_data()
            }
            NativeProgram::Connected(program) => {
                program.authenticate_original_initial_observation_data()
            }
            NativeProgram::RestorationInProgress => Err(refused()),
        }
    }

    /// Borrows the actual selection after checking the initial activated owner.
    ///
    /// # Errors
    /// Refuses any noninitial or unavailable Control/model owner.
    pub(crate) fn original_initial_observation_selection_data(
        &self,
    ) -> Result<&PacketControlSelection, ProviderError> {
        self.authenticate_original_initial_observation_data()?;
        Ok(&self.selection)
    }

    /// Names the exact nonallocating census argument, result and scalar views.
    pub(crate) const fn original_initial_observation_counter_scratch_data() -> usize {
        super::super::connected::PacketConnectedProgram::original_initial_observation_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&usize>()
            + size_of::<&Position>()
            + 2 * size_of::<&bool>()
            + size_of::<&Vec<super::super::PacketPublication>>()
            + size_of::<&BTreeMap<Id, PacketGrant>>()
            + size_of::<&BTreeMap<Id, Vec<Id>>>()
            + 2 * size_of::<&u64>()
            + size_of::<&Option<WorldActivateRequest>>()
            + size_of::<&Option<(ActivateRequest, ContentRef)>>()
            + size_of::<&PacketProgram>()
            + size_of::<&super::super::connected::PacketConnectedProgram>()
            + size_of::<&NativeProgram>()
            + size_of::<Position>()
            + size_of::<U64>()
            + size_of::<Phase>()
            + 3 * size_of::<Result<(), ProviderError>>()
            + size_of::<bool>()
            + size_of::<&PacketControlSelection>()
            + size_of::<Result<&PacketControlSelection, ProviderError>>()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original initial Control observation state")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn event() -> Result<super::super::super::PacketEvent, ContractError> {
        let point = Position::new(U64::new(1), U64::new(0), Phase::Reaction);
        Ok(super::super::super::PacketEvent {
            id: Id::new("original-private-callback")?,
            evaluation: point,
            completion: point,
            payload: None,
        })
    }

    #[test]
    fn real_producer_initial_census_refuses_completed_callback_history() -> TestResult {
        let (socket, peer) = UnixDatagram::pair()?;
        let mut model = PacketProgram::new(vec![event()?], socket)?;
        assert!(
            model
                .authenticate_original_initial_observation_data()
                .is_err()
        );
        model.open_gate()?;
        model.authenticate_original_initial_observation_data()?;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let limit = Position::new(U64::new(2), U64::new(0), Phase::BoundaryControl);
        model.execute(Id::new("actual-completed-operation")?, zero, limit)?;

        let mut trace = [255u8; 2];
        assert_eq!(peer.recv(&mut trace)?, 1);
        assert_eq!(trace[0], 0);
        assert_eq!(model.private_mutations, 1);
        assert!(!model.grants.is_empty());
        assert!(
            model
                .authenticate_original_initial_observation_data()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn failed_callback_keeps_same_original_and_cannot_reenter_initial_report() -> TestResult {
        let socket = UnixDatagram::unbound()?;
        let mut model = PacketProgram::new(vec![event()?], socket)?;
        model.open_gate()?;
        model.authenticate_original_initial_observation_data()?;
        let operation = Id::new("actual-failed-operation")?;
        let zero = Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl);
        let limit = Position::new(U64::new(2), U64::new(0), Phase::BoundaryControl);
        assert!(model.execute(operation.clone(), zero, limit).is_err());
        let original = model.original(&operation).ok_or("failed original absent")?;
        assert!(!original.complete);
        let original_identity = original as *const _;

        assert!(
            model
                .authenticate_original_initial_observation_data()
                .is_err()
        );
        assert!(model.execute(operation.clone(), zero, limit).is_err());
        assert_eq!(
            model.original(&operation).map(|v| v as *const _),
            Some(original_identity)
        );
        assert_eq!(model.grants.len(), 1);
        assert!(model.failed);
        Ok(())
    }
}
