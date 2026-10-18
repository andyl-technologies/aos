//! 9p visibility event feeding and frontier advancement for the production
//! coordinator.
//!
//! The production runtime counts every referenced event it emits but retains,
//! in its referenced-event window, only the events a live subscription can
//! still use. The 9p visibility state records how many emissions it has
//! consumed. Each service pass feeds the retained emissions appended since
//! then and advances the cursor over retired ones, which release no live
//! update, so its cost is proportional to new retained emissions rather than
//! to the run's history. After the pass the coordinator reports every live
//! event-released update as a subscription, which keeps the emission that
//! releases it until the next pass feeds it.
//!
//! The first pass after construction or a rollback verifies every live latch
//! against the retained consumed emissions, so a restored 9p continuation that
//! disagrees with the restored runtime fails closed instead of advancing.

use super::*;

use crucible_device::NinepEventEmission;

impl ProductionNinepFaultCoordinator {
    /// Feeds the retained emissions appended since the visibility state's
    /// cursor, first verifying the consumed ones when they are unverified.
    pub(super) fn feed_visibility_events(
        &mut self,
        servicer: &mut LiveNinepServicer,
    ) -> Result<(), DeviceRuntimeError> {
        let cursor = servicer.visibility_state().event_cursor();
        let live = ninep_event_subscriptions(servicer.visibility_state());
        let (appended, consumed_through) = {
            let runtime = self.runtime.lock().map_err(|_| {
                storage_error(
                    "read 9p visibility events",
                    "fault runtime lock is poisoned",
                )
            })?;
            runtime
                .verify_referenced_event_subscriptions(self.consumer, &live)
                .map_err(|error| storage_error("verify 9p visibility events", error))?;
            let window = runtime.referenced_events();
            if cursor > window.emitted() {
                return Err(storage_error(
                    "read 9p visibility events",
                    "9p visibility event cursor exceeds the emitted events",
                ));
            }
            if self.verified_event_cursor != Some(cursor) {
                servicer
                    .visibility_state()
                    .verify_event_latches(&ninep_event_emissions(window.retained_before(cursor))?)
                    .map_err(|error| storage_error("verify 9p visibility events", error))?;
            }
            (
                ninep_event_emissions(window.retained_from(cursor))?,
                window.emitted(),
            )
        };

        servicer
            .observe_visibility_events(&appended, consumed_through)
            .map_err(|error| storage_error("feed 9p visibility events", error))?;
        self.verified_event_cursor = Some(servicer.visibility_state().event_cursor());
        Ok(())
    }

    /// Reports every live event-released update so the runtime keeps the
    /// emission that releases it.
    pub(super) fn report_visibility_subscriptions(
        &self,
        servicer: &LiveNinepServicer,
    ) -> Result<(), DeviceRuntimeError> {
        let live = ninep_event_subscriptions(servicer.visibility_state());
        self.runtime
            .lock()
            .map_err(|_| {
                storage_error(
                    "report 9p visibility subscriptions",
                    "fault runtime lock is poisoned",
                )
            })?
            .report_referenced_event_subscriptions(self.consumer, live)
            .map_err(|error| storage_error("report 9p visibility subscriptions", error))
    }

    /// Returns the retained consumed emissions of `event`, which latch a
    /// newly committed update subscribed to `key`.
    ///
    /// The committing evaluation follows every emitted event in scheduler
    /// order, so no consumed emission lies strictly after its subscription;
    /// the device still filters them, which keeps the latch exact even if an
    /// emission were retained out of that order.
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

        // Identifier parsing is the identity on valid text, so comparing the
        // signal text selects exactly the emissions whose event key is `key`.
        Ok(runtime
            .referenced_events()
            .retained_before(state.event_cursor())
            .iter()
            .filter(|retained| retained.event().signal.as_str() == event.as_str())
            .map(|retained| NinepEventEmission {
                event: key,
                coordinate: emission_coordinate(retained),
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

/// Returns the scheduler coordinate of one retained emission.
fn emission_coordinate(retained: &RetainedReferencedEvent) -> NinepEventCoordinate {
    let coordinate = retained.coordinate();
    NinepEventCoordinate {
        ticks: coordinate.ticks,
        sequence: coordinate.sequence,
    }
}

/// Converts retained emissions into the 9p emissions they latch.
fn ninep_event_emissions(
    events: &[RetainedReferencedEvent],
) -> Result<Vec<NinepEventEmission>, DeviceRuntimeError> {
    let mut emissions = Vec::new();
    emissions
        .try_reserve_exact(events.len())
        .map_err(|_| storage_error("read 9p visibility events", "emission allocation failed"))?;
    emissions.extend(events.iter().map(|retained| NinepEventEmission {
        event: retained.key(),
        coordinate: emission_coordinate(retained),
    }));
    Ok(emissions)
}

/// Returns every live event-released update as a referenced-event subscription.
fn ninep_event_subscriptions(state: &NinepVisibilityState) -> Vec<ReferencedEventSubscription> {
    state
        .event_subscriptions()
        .map(|(event, after)| ReferencedEventSubscription {
            event,
            after: ReferencedEventCoordinate {
                ticks: after.ticks,
                sequence: after.sequence,
            },
        })
        .collect()
}
