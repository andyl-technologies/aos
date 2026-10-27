//! Release timing for 9p visibility updates.
//!
//! A time release is fixed when its update commits. An event-released update
//! subscribes at the coordinate of the evaluation that committed it and
//! latches the earliest emission of its event, in scheduler order
//! `(ticks, sequence)`, strictly after that subscription. An emission by the
//! committing evaluation itself therefore never releases it, which is the
//! window rule block recovery applies to retained completions. Once latched, a
//! later re-emission never moves the release coordinate, so visibility is
//! monotone and lagged event releases compact like time releases.
//!
//! The state consumes the fault runtime's emitted events in append order
//! through a checkpointed cursor:
//!
//! ```text
//! emitted events:  e0  e1  e2 | e3  e4
//!                             ^ event_cursor = 3
//! commit:    latch from the matching retained prefix of e0..e2
//! advance:   caller feeds e3, e4; event_cursor = 5
//! restore:   verify every live latch against the retained e0..e2
//! ```
//!
//! The fault runtime retires an emission once it can release no live update,
//! so the caller may feed and verify a subset of each range: one that holds,
//! for every live update, the earliest emission that releases it. A retired
//! emission advances the cursor without latching. Each step costs time in the
//! number of new emissions, and the cursor rolls back and restores with the
//! rest of the 9p continuation.

use super::*;

/// Returns the tick at which an update's metadata becomes visible to a
/// session that does not own it, or `None` while its release event is
/// unlatched.
pub(super) fn release_coordinate(
    update: &NinepVisibilityUpdate,
) -> Result<Option<u64>, DeviceError> {
    match update.release {
        NinepVisibilityRelease::AtNanos(deadline) => Ok(Some(crate::ns_to_tick(deadline)?)),
        NinepVisibilityRelease::AtTicks(deadline) => Ok(Some(deadline)),
        NinepVisibilityRelease::OnEvent { .. } => Ok(update.event_latch.map(|latch| latch.ticks)),
    }
}

/// Returns the tick at which an update's bytes become visible to a session
/// that does not own it, or `None` while its release event is unlatched.
pub(super) fn data_deadline(update: &NinepVisibilityUpdate) -> Result<Option<u64>, DeviceError> {
    let Some(coordinate) = release_coordinate(update)? else {
        return Ok(None);
    };
    let lag_ticks = update
        .data_lag_nanos
        .checked_mul(crucible_qemu_shmem::TICKS_PER_NS)
        .ok_or(invalid(
            "9p data visibility lag exceeds simulation tick range",
        ))?;
    coordinate
        .checked_add(lag_ticks)
        .map(Some)
        .ok_or(invalid("9p data visibility deadline overflow"))
}

/// Returns whether every present and future session would pass `update` at
/// `now_tick` or any later tick, independently of writer-immediate scope.
///
/// Data readiness implies metadata readiness, because the data deadline never
/// precedes the release coordinate. Release coordinates never move later: time
/// releases are fixed at commit and an event latch can only move earlier, so a
/// deadline that has passed stays passed. Range and overflow failures stay
/// live, so the session that reaches them reports the same error it would
/// without compaction.
pub(super) fn released_for_every_session(update: &NinepVisibilityUpdate, now_tick: u64) -> bool {
    data_deadline(update)
        .ok()
        .flatten()
        .is_some_and(|deadline| now_tick >= deadline)
}

/// Exact scheduler order of one signal emission or committing evaluation.
///
/// Coordinates order lexicographically: by simulation tick, then by the
/// evaluation sequence among evaluations at that tick.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct NinepEventCoordinate {
    /// Exact simulation tick.
    pub ticks: u64,
    /// Stable order among evaluations at the same tick.
    pub sequence: u64,
}

/// One emission of a signal event, as consumed in fault-runtime append order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NinepEventEmission {
    /// Content identity of the emitted signal event.
    pub event: [u8; 32],
    /// Scheduler coordinate of the emission.
    pub coordinate: NinepEventCoordinate,
}

impl NinepVisibilityState {
    /// Returns how many fault-runtime emissions the state has consumed.
    ///
    /// The next call to [`NinepVisibilityState::observe_events`] must start
    /// with the emission at this index.
    #[must_use]
    pub const fn event_cursor(&self) -> u64 {
        self.event_cursor
    }

    /// Consumes the emissions appended since the last call and latches every
    /// live update they release.
    ///
    /// Callers pass each fault-runtime emission exactly once, in append order,
    /// starting at [`NinepVisibilityState::event_cursor`].
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutating the state when the cursor would
    /// overflow.
    pub fn observe_events(&mut self, emissions: &[NinepEventEmission]) -> Result<(), DeviceError> {
        let count = u64::try_from(emissions.len())
            .map_err(|_| invalid("9p visibility event cursor overflow"))?;
        self.event_cursor = self
            .event_cursor
            .checked_add(count)
            .ok_or(invalid("9p visibility event cursor overflow"))?;

        for emission in emissions {
            let Some(subscribers) = self.event_subscribers.get(&emission.event) else {
                continue;
            };
            for sequence in subscribers {
                if let Some(update) = self.updates.get_mut(sequence) {
                    latch_emission(update, emission.coordinate);
                }
            }
        }
        Ok(())
    }

    /// Consumes emissions up to fault-runtime index `consumed_through` and
    /// latches every live update that the retained ones release.
    ///
    /// `emissions` are the retained emissions with indexes in
    /// `event_cursor..consumed_through`, in append order. The others retired
    /// because they release no live update, so they only advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] without mutating the state when
    /// `consumed_through` precedes the cursor or cannot hold `emissions`.
    pub fn observe_events_through(
        &mut self,
        emissions: &[NinepEventEmission],
        consumed_through: u64,
    ) -> Result<(), DeviceError> {
        let count = u64::try_from(emissions.len())
            .map_err(|_| invalid("9p visibility event cursor overflow"))?;
        if consumed_through
            .checked_sub(self.event_cursor)
            .is_none_or(|range| range < count)
        {
            return Err(invalid("9p visibility events end before the event cursor"));
        }
        self.observe_events(emissions)?;
        self.event_cursor = consumed_through;
        Ok(())
    }

    /// Returns the event subscription of every live event-released update.
    ///
    /// Each pair is the subscribed event and the coordinate strictly after
    /// which an emission releases the update, whether or not it has latched.
    pub fn event_subscriptions(
        &self,
    ) -> impl Iterator<Item = ([u8; 32], NinepEventCoordinate)> + '_ {
        self.updates.values().filter_map(event_subscription)
    }

    /// Verifies every live latch against the consumed emissions still retained.
    ///
    /// `emissions` are consumed fault-runtime emissions in append order, at
    /// most [`NinepVisibilityState::event_cursor`] of them, and must include
    /// for every live event-released update the earliest consumed emission
    /// that releases it. Each such update must hold that emission as its
    /// latch, or no latch when none exists, so a restored continuation cannot
    /// carry a latch that no emission produced.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when more emissions are supplied than the
    /// cursor consumed or any live latch differs from the one the emissions
    /// determine.
    pub fn verify_event_latches(
        &self,
        emissions: &[NinepEventEmission],
    ) -> Result<(), DeviceError> {
        if !u64::try_from(emissions.len()).is_ok_and(|count| count <= self.event_cursor) {
            return Err(invalid(
                "9p visibility event cursor disagrees with the emitted events",
            ));
        }

        let mut expected = BTreeMap::<u64, NinepEventCoordinate>::new();
        for emission in emissions {
            let Some(subscribers) = self.event_subscribers.get(&emission.event) else {
                continue;
            };
            for sequence in subscribers {
                let releases = self
                    .updates
                    .get(sequence)
                    .and_then(event_subscription)
                    .is_some_and(|(_event, after)| emission.coordinate > after);
                if releases {
                    expected
                        .entry(*sequence)
                        .and_modify(|latched| *latched = (*latched).min(emission.coordinate))
                        .or_insert(emission.coordinate);
                }
            }
        }

        let consistent = self.updates.iter().all(|(sequence, update)| {
            event_subscription(update).is_none()
                || update.event_latch == expected.get(sequence).copied()
        });
        if !consistent {
            return Err(invalid(
                "9p visibility event latch does not match the emitted events",
            ));
        }
        Ok(())
    }

    /// Latches a newly committed event-released update from emissions the
    /// cursor consumed before its commit.
    pub(super) fn latch_prior_emissions(
        &mut self,
        sequence: u64,
        prior_emissions: &[NinepEventEmission],
    ) {
        let Some(update) = self.updates.get_mut(&sequence) else {
            return;
        };
        let Some((event, _after)) = event_subscription(update) else {
            return;
        };
        for emission in prior_emissions
            .iter()
            .filter(|emission| emission.event == event)
        {
            latch_emission(update, emission.coordinate);
        }
    }
}

/// Returns the subscribed event and subscription coordinate of an
/// event-released update.
pub(super) fn event_subscription(
    update: &NinepVisibilityUpdate,
) -> Option<([u8; 32], NinepEventCoordinate)> {
    match update.release {
        NinepVisibilityRelease::OnEvent { event, after } => Some((event, after)),
        NinepVisibilityRelease::AtNanos(_) | NinepVisibilityRelease::AtTicks(_) => None,
    }
}

/// Records `coordinate` when it releases `update` earlier than its current
/// latch.
///
/// Keeping the minimum makes the latch the earliest releasing emission even
/// when emissions are appended out of coordinate order; a later re-emission
/// never replaces it, so its release coordinate never moves later.
fn latch_emission(update: &mut NinepVisibilityUpdate, coordinate: NinepEventCoordinate) {
    let Some((_event, after)) = event_subscription(update) else {
        return;
    };
    if coordinate > after
        && update
            .event_latch
            .is_none_or(|latched| coordinate < latched)
    {
        update.event_latch = Some(coordinate);
    }
}
