//! Genuine native phase registration, stopped sampling and historical slice replies.
//!
//! The source callback owns all native queries. The reader only recovers cached
//! public bytes and cannot assign timer positions or upgrade unknown source arms.

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeCommandError, NativeFrame, NativePhasePreparation, NativePhaseTimerQuery,
};

use super::NativeNodeControl;
use crate::native_node_control::{phase_abi, phase_custody::PhaseProjectionCustody};

impl NativeNodeControl {
    pub(crate) fn with_phase_projection(
        mut self,
        preparation: NativePhasePreparation,
    ) -> Result<Self, NativeCommandError> {
        preparation.validate()?;
        if self.phase_projection.is_some()
            || self.initialization.as_ref().is_none_or(|initialization| {
                initialization.preparation != preparation.initialization
            })
            || preparation
                .initialization
                .preparation
                .scope
                .identity_digest()?
                != self.prepared_scope_hash
        {
            return Err(NativeCommandError::Conflict);
        }
        let query = phase_abi::resolve_query_timer_births().ok_or(NativeCommandError::Invalid(
            "native phase timer source API unavailable",
        ))?;
        self.phase_projection = Some(PhaseProjectionCustody::new(preparation, query)?);
        Ok(self)
    }

    pub(super) fn register_phase_projection(&self) -> Result<(), NativeCommandError> {
        let Some(phase) = &self.phase_projection else {
            return Ok(());
        };
        let register = phase_abi::resolve_register_phase().ok_or(NativeCommandError::Invalid(
            "native phase registration unavailable",
        ))?;
        phase.register(register)
    }

    /// Returns only an actually registered original phase preparation commitment.
    pub(crate) fn registered_phase_commitment(&self) -> Option<[u8; 32]> {
        self.phase_projection.as_ref()?.registered_commitment()
    }

    pub(super) fn observe_phase_timers(&self, sequence: U64) -> Result<(), NativeCommandError> {
        let Some(phase) = &self.phase_projection else {
            return Ok(());
        };
        let (digest, time, generation) = {
            // A stopped callback cannot wait for the administrative reader while
            // owning BQL. Busy custody yields refusal, not a guessed source cut.
            let state = self
                .state
                .try_lock()
                .map_err(|_| NativeCommandError::Conflict)?;
            if state.quarantined {
                return Err(NativeCommandError::Conflict);
            }
            let generation = state
                .writer_generation
                .ok_or(NativeCommandError::Conflict)?;
            let (digest, time) = if sequence.get() == 0 {
                // An idle getter after execution only recovers the historical
                // initial object. It must not sample a new initial cut or make
                // the original session unusable because its journal advanced.
                if !state.journal.is_pristine() {
                    return Ok(());
                }
                (
                    [0; 32],
                    state
                        .cpu_park
                        .as_ref()
                        .ok_or(NativeCommandError::Conflict)?
                        .current_ps,
                )
            } else {
                let stop = state
                    .receipts
                    .get(&sequence.get())
                    .ok_or(NativeCommandError::Conflict)?;
                (stop.grant_hash, U64::new(stop.current_ps))
            };
            (digest, time, generation)
        };
        phase.observe_original(sequence, digest, time, generation)
    }

    pub(super) fn send_phase_timer_chunk(
        &self,
        query: &NativePhaseTimerQuery,
    ) -> Result<(), NativeCommandError> {
        let phase = self
            .phase_projection
            .as_ref()
            .ok_or(NativeCommandError::Conflict)?;
        if let Some(chunk) = phase.chunk(query)? {
            let channel = self.channel.as_ref().ok_or(NativeCommandError::Conflict)?;
            channel
                .send(&NativeFrame::PhaseTimerChunk(Box::new(chunk)))
                .map_err(|_| NativeCommandError::Conflict)?;
        }
        Ok(())
    }
}
