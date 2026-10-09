//! Original phase preparation and checked assembly of source timer-birth evidence.
//!
//! These Apache-side records consume only the versioned process protocol. They
//! compare actual returned bytes with the original command/preparation journals;
//! they never include QEMU headers or infer readiness from a diagnostic timer cut.

use std::collections::BTreeMap;

use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES, NativeCommandError, NativeControlEdition, NativeFrame,
    NativePhasePreparation, NativePhaseTimerChunk, NativePhaseTimerObservation,
    NativePhaseTimerQuery, NativeTimerBirth,
};

use super::{NativeLaunchEndpoint, NativeQemuControlError, NativeQemuControlTransport};

pub(super) struct PhaseAssembly {
    digest: Option<[u8; 32]>,
    total: Option<usize>,
    bytes: Vec<u8>,
    complete: Option<NativePhaseTimerObservation>,
}

#[cfg(test)]
#[path = "phase_tests.rs"]
mod tests;

pub(super) struct PhaseJournal {
    pub(super) preparation: NativePhasePreparation,
    originals: BTreeMap<u64, PhaseAssembly>,
}

impl NativeQemuControlTransport {
    /// Pins the complete original phase and construction preparation before launch.
    ///
    /// The installed launcher must authenticate the original Realize record and
    /// selected policies. Native source registration independently compares the
    /// early authorization; matching these data alone grants no native capability.
    ///
    /// # Errors
    /// Rejects invalid preparation, unbounded framing or socket creation failure.
    pub fn prepare_phase(
        preparation: NativePhasePreparation,
    ) -> Result<(Self, NativeLaunchEndpoint), NativeQemuControlError> {
        preparation.validate()?;
        let (mut transport, mut endpoint) = Self::prepare_channel(
            preparation.initialization.preparation.clone(),
            NativeControlEdition::PhaseProjection,
            NativeFrame::PreparePhase(Box::new(preparation.clone())),
            Some(preparation.initialization.clone()),
        )?;
        transport.phase_projection = Some(PhaseJournal {
            preparation: preparation.clone(),
            originals: BTreeMap::new(),
        });
        endpoint.phase_projection = Some(preparation);
        Ok((transport, endpoint))
    }

    /// Requests only the next bytes of one retained source timer-birth observation.
    ///
    /// Sequence zero selects the original initial source park. Other sequences
    /// require their original native stop facts already held by this transport.
    /// Offset retries preserve the same historical object, not live timer state.
    ///
    /// # Errors
    /// Rejects unprepared phase scope, source faults, unknown stops, exhausted
    /// original retention credit, incompatible edition or physical channel failure.
    pub fn request_phase_timer_observation(
        &mut self,
        sequence: U64,
    ) -> Result<bool, NativeQemuControlError> {
        if self.channel.edition() != NativeControlEdition::PhaseProjection
            || self.source_fault.is_some()
            || (sequence.get() == 0 && self.cpu_park.is_none())
            || (sequence.get() != 0 && !self.facts.contains_key(&sequence.get()))
        {
            return Err(NativeCommandError::Conflict.into());
        }
        let journal = self
            .phase_projection
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        let count = journal.originals.len();
        let original = match journal.originals.entry(sequence.get()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                // Each reserved identity owns the complete independent object cap.
                // No peer size can expand this finite local retention policy.
                if count >= 16 {
                    return Err(NativeCommandError::ResourceLimit.into());
                }
                entry.insert(PhaseAssembly {
                    digest: None,
                    total: None,
                    bytes: Vec::new(),
                    complete: None,
                })
            }
        };
        let offset = if original.complete.is_some() {
            0
        } else {
            original.bytes.len() as u64
        };
        Ok(self
            .channel
            .send(&NativeFrame::QueryPhaseTimers(NativePhaseTimerQuery {
                prepared_scope_hash: self.prepared_scope_hash,
                sequence,
                offset: U64::new(offset),
            }))?)
    }

    /// Returns the original complete observation, retaining unknown births as unknown.
    pub fn phase_timer_observation(&self, sequence: U64) -> Option<&NativePhaseTimerObservation> {
        self.phase_projection
            .as_ref()?
            .originals
            .get(&sequence.get())?
            .complete
            .as_ref()
    }

    pub(super) fn accept_phase_timer_chunk(
        &mut self,
        chunk: &NativePhaseTimerChunk,
    ) -> Result<(), NativeQemuControlError> {
        chunk.validate()?;
        if chunk.prepared_scope_hash != self.prepared_scope_hash || self.source_fault.is_some() {
            return Err(NativeCommandError::Conflict.into());
        }
        let journal = self
            .phase_projection
            .as_mut()
            .ok_or(NativeCommandError::Conflict)?;
        let original = journal
            .originals
            .get_mut(&chunk.sequence.get())
            .ok_or(NativeCommandError::Conflict)?;
        let total = usize::try_from(chunk.total_bytes.get())
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        let offset =
            usize::try_from(chunk.offset.get()).map_err(|_| NativeCommandError::ResourceLimit)?;
        if total > NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES
            || original
                .digest
                .is_some_and(|digest| digest != chunk.object_digest)
            || original.total.is_some_and(|size| size != total)
        {
            return Err(NativeCommandError::Conflict.into());
        }
        let end = offset
            .checked_add(chunk.bytes.len())
            .filter(|end| *end <= total)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if offset < original.bytes.len() {
            if end > original.bytes.len() || original.bytes[offset..end] != chunk.bytes {
                return Err(NativeCommandError::Conflict.into());
            }
            return Ok(());
        }
        if offset != original.bytes.len() {
            return Err(NativeCommandError::Conflict.into());
        }
        let mut candidate = Vec::new();
        candidate
            .try_reserve_exact(end)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        candidate.extend_from_slice(&original.bytes);
        candidate.extend_from_slice(&chunk.bytes);
        let complete = if end == total {
            if blake3::hash(&candidate).as_bytes() != &chunk.object_digest {
                return Err(NativeCommandError::Conflict.into());
            }
            let observation = NativePhaseTimerObservation::decode(&candidate)?;
            observation.validate_against(&journal.preparation)?;
            let (time, digest) = if chunk.sequence.get() == 0 {
                (
                    self.cpu_park
                        .as_ref()
                        .ok_or(NativeCommandError::Conflict)?
                        .current_ps,
                    [0; 32],
                )
            } else {
                let stop = self
                    .facts
                    .get(&chunk.sequence.get())
                    .ok_or(NativeCommandError::Conflict)?;
                (stop.reached.time_ps, stop.command_digest)
            };
            if observation.sequence != chunk.sequence
                || observation.current_ps != time
                || observation.command_digest != digest
            {
                return Err(NativeCommandError::Conflict.into());
            }
            for timer in &observation.timers {
                if let NativeTimerBirth::Reaction {
                    position,
                    sequence,
                    command_digest,
                    ..
                } = &timer.birth
                {
                    let command = self
                        .journal
                        .original(*sequence)
                        .ok_or(NativeCommandError::Conflict)?;
                    if command.identity_digest()? != *command_digest
                        || position.time_ps < command.kind.start().time_ps
                        || position.time_ps >= command.kind.limit().time_ps
                    {
                        return Err(NativeCommandError::Conflict.into());
                    }
                    journal.preparation.policy()?.validate_position(*position)?;
                }
            }
            Some(observation)
        } else {
            None
        };
        original.digest = Some(chunk.object_digest);
        original.total = Some(total);
        original.bytes = candidate;
        original.complete = complete;
        Ok(())
    }
}
