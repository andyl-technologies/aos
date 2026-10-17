//! 9p visibility event feeding and frontier advancement for the production
//! coordinator.
//!
//! The production runtime's emitted events are append-only and checkpointed,
//! and the 9p visibility state records how many of them it has consumed. Each
//! service pass converts and feeds only the emissions appended since then, so
//! its cost is proportional to new emissions rather than to the run's history.
//! A newly committed event-released update scans the consumed prefix once, by
//! exact signal identity, for emissions that already release it.
//!
//! The first pass after construction or a rollback verifies every live latch
//! against the consumed prefix, so a restored 9p continuation that disagrees
//! with the restored runtime fails closed instead of advancing.

use super::*;

use crucible::model::ReferencedSignalEvent;
use crucible_device::NinepEventEmission;

impl ProductionNinepFaultCoordinator {
    /// Feeds the emissions appended since the visibility state's cursor,
    /// first verifying the consumed prefix when it has not been verified.
    pub(super) fn feed_visibility_events(
        &mut self,
        servicer: &mut LiveNinepServicer,
    ) -> Result<(), DeviceRuntimeError> {
        let cursor = servicer.visibility_state().event_cursor();
        let appended = {
            let runtime = self.runtime.lock().map_err(|_| {
                storage_error(
                    "read 9p visibility events",
                    "fault runtime lock is poisoned",
                )
            })?;
            let (consumed, appended) = split_emitted_events(runtime.emitted_events(), cursor)?;
            if self.verified_event_cursor != Some(cursor) {
                servicer
                    .visibility_state()
                    .verify_event_latches(&ninep_event_emissions(consumed)?)
                    .map_err(|error| storage_error("verify 9p visibility events", error))?;
            }
            ninep_event_emissions(appended)?
        };

        servicer
            .observe_visibility_events(&appended)
            .map_err(|error| storage_error("feed 9p visibility events", error))?;
        self.verified_event_cursor = Some(servicer.visibility_state().event_cursor());
        Ok(())
    }

    /// Returns the consumed emissions of `event`, which latch a newly
    /// committed update subscribed to `key`.
    pub(super) fn prior_visibility_emissions(
        &self,
        state: &NinepVisibilityState,
        event: &FaultObjectId,
        key: [u8; 32],
    ) -> Result<Vec<NinepEventEmission>, DeviceRuntimeError> {
        let runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "read 9p visibility events",
                "fault runtime lock is poisoned",
            )
        })?;
        let (consumed, _appended) =
            split_emitted_events(runtime.emitted_events(), state.event_cursor())?;

        // Identifier parsing is the identity on valid text, so comparing the
        // signal text selects exactly the emissions whose event key is `key`.
        Ok(consumed
            .iter()
            .filter(|emitted| emitted.signal.as_str() == event.as_str())
            .map(|emitted| NinepEventEmission {
                event: key,
                coordinate: emission_coordinate(emitted),
            })
            .collect())
    }

    /// Advances the current session's frontiers and records the advance.
    pub(super) fn advance_visibility(
        &self,
        servicer: &mut LiveNinepServicer,
        now_ticks: u64,
    ) -> Result<(), DeviceRuntimeError> {
        let session = servicer.visibility_session();
        let before = servicer.visibility_state().visible_frontier(session);
        let after = servicer
            .advance_visibility(now_ticks)
            .map_err(|error| storage_error("advance 9p visibility", error))?;
        if before == after {
            return Ok(());
        }

        // Updates below the compaction floor survive only as lookup residue.
        // A newly negotiated session passes them as one jump to the floor,
        // which the evidence records instead of enumerating them.
        let state = servicer.visibility_state();
        let floor = state.compacted_frontier();
        let mut updates = BTreeMap::new();
        for (start, end) in [(before.0, after.0), (before.1, after.1)] {
            let advanced = state
                .updates_between(start.max(floor), end)
                .map_err(|error| storage_error("advance 9p visibility", error))?;
            updates.extend(advanced.into_iter().map(|update| (update.sequence, update)));
        }
        let updates = updates.into_values().collect::<Vec<_>>();
        let evidence = ninep_visibility_advance_evidence(
            session,
            before,
            after,
            now_ticks,
            &updates,
            servicer.visibility_state(),
        );

        let mut cursor = self.cursor.lock().map_err(|_| {
            storage_error(
                "sequence 9p visibility advancement",
                "production fault evaluation cursor lock is poisoned",
            )
        })?;
        let cursor_before = *cursor;
        let sequence = cursor
            .next_sequence(now_ticks)
            .map_err(|error| storage_error("sequence 9p visibility advancement", error))?;
        let observation = FaultObservation {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            kind: FaultObservationKind::EffectApplied,
            coordinate: FaultCoordinate {
                virtual_ticks: now_ticks,
                retired_instructions: None,
            },
            binding: None,
            target: Some(self.target.clone()),
            opportunity: None,
            evidence,
        };
        if let Err(error) = self
            .observations
            .lock()
            .map_err(|_| storage_error("record 9p visibility advancement", "journal is poisoned"))?
            .append(sequence.journal, vec![observation])
        {
            *cursor = cursor_before;
            return Err(error);
        }
        Ok(())
    }
}

/// Returns the scheduler coordinate of one emitted signal event.
fn emission_coordinate(event: &ReferencedSignalEvent) -> NinepEventCoordinate {
    NinepEventCoordinate {
        ticks: event.coordinate.virtual_ticks,
        sequence: event.same_coordinate_sequence,
    }
}

/// Converts emitted signal events into the 9p emissions they latch.
fn ninep_event_emissions(
    events: &[ReferencedSignalEvent],
) -> Result<Vec<NinepEventEmission>, DeviceRuntimeError> {
    events
        .iter()
        .map(|event| {
            let signal = FaultObjectId::parse(event.signal.as_str())
                .map_err(|error| storage_error("read 9p visibility events", error))?;
            Ok(NinepEventEmission {
                event: storage_recovery_event_key(&signal),
                coordinate: emission_coordinate(event),
            })
        })
        .collect()
}

/// Splits the emitted events into the prefix a visibility state with
/// `cursor` has consumed and the emissions appended after it.
///
/// A cursor beyond the emitted events fails closed: the 9p continuation does
/// not belong to this runtime continuation.
fn split_emitted_events(
    events: &[ReferencedSignalEvent],
    cursor: u64,
) -> Result<(&[ReferencedSignalEvent], &[ReferencedSignalEvent]), DeviceRuntimeError> {
    usize::try_from(cursor)
        .ok()
        .filter(|cursor| *cursor <= events.len())
        .map(|cursor| events.split_at(cursor))
        .ok_or_else(|| {
            storage_error(
                "read 9p visibility events",
                "9p visibility event cursor exceeds the emitted events",
            )
        })
}
