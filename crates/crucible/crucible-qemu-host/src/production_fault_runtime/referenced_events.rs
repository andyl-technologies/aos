//! Live window of referenced signal events and their device consumers.
//!
//! The signal runtime emits a referenced event whenever an exported event
//! signal named by a storage recovery contract fires. Every emission is charged
//! once against the cumulative `event_records` and `event_log_bytes` budgets
//! and folded into a history chain digest, so the checkpoint identity commits
//! to the complete emitted history in constant space. Only events that a
//! device consumer can still use stay resident:
//!
//! ```text
//! emitted:   e0  e1  e2  e3  e4  e5  e6     count = 7, history = H(..H(H(0, e0), e1).., e6)
//! retained:          e2          e5  e6     each needed by a live subscription
//!                                           or at the newest emitted tick
//! ```
//!
//! # Retention rules
//!
//! Emissions and subscriptions follow the binding runtime's monotone scheduler
//! cursor `(ticks, sequence)`: an evaluation never precedes an earlier one, so
//! a subscription created by an evaluation is at or after every event already
//! emitted. Consumers release a subscription with the earliest event of its key
//! strictly after it, so no later event of that key can change the outcome.
//! An event is retained while one of these rules needs it:
//!
//! 1. It is the earliest event of key `K` strictly after a subscription
//!    `(K, after)` that a consumer last reported: a retained block completion
//!    or a live event-released 9p visibility update.
//! 2. It has key `K` and either lies at tick `T` or is the earliest event of
//!    `K` after tick `T`, where an active persistent storage action recovers on
//!    `K` and was installed at `T`. A completion that action retains later
//!    subscribes at `(T, s)` for a sequence `s` fixed only then.
//! 3. It lies at the newest emitted tick, where an action installed later
//!    could still subscribe.
//!
//! Without a bound consumer no rule applies and every event retires at once.
//!
//! # Retired-event frontier
//!
//! For every key the window keeps the greatest coordinate of a retired event.
//! A live subscription at or after that frontier cannot be released by a
//! retired event. An earlier one is safe only if its consumer reported it
//! before the events it needs could retire, or rule 2 covers it; consumers
//! verify their live subscriptions on every read, and an uncovered one fails
//! closed instead of observing an incomplete history.

use std::collections::BTreeMap;

use crucible_engine::model::{
    ContentHash, EffectSpecification, FaultExecutionError, FaultObjectId, FaultResourceLimitError,
    FaultResourceLimits, HostFaultActionState, ReferencedSignalEvent, ResolvedFaultTarget,
    StorageEffectSpecification,
};

use super::{ProductionFaultRuntimeError, runtime_collection_reservation};
use crate::storage_recovery_event_key;

/// Fixed record overhead charged per event beyond its signal and value bytes.
const REFERENCED_EVENT_RECORD_OVERHEAD_BYTES: u64 = 81;

/// Exact scheduler order of one referenced event or subscription.
///
/// Coordinates order lexicographically: by simulation tick, then by the
/// evaluation sequence among evaluations at that tick.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ReferencedEventCoordinate {
    /// Exact simulation tick.
    pub ticks: u64,
    /// Stable order among evaluations at the same tick.
    pub sequence: u64,
}

impl ReferencedEventCoordinate {
    /// Returns the scheduler coordinate at which `event` was emitted.
    #[must_use]
    pub const fn of(event: &ReferencedSignalEvent) -> Self {
        Self {
            ticks: event.coordinate.virtual_ticks,
            sequence: event.same_coordinate_sequence,
        }
    }
}

/// Stable identity of one device that consumes referenced events.
///
/// The identity binds the consumer role and its resolved target, so a block
/// device and a 9p export with equal targets remain distinct consumers.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct ReferencedEventConsumer(ContentHash);

impl ReferencedEventConsumer {
    /// Returns the consumer identity of block recovery for one World block target.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the target's canonical
    /// material cannot be reserved or encoded.
    pub fn block_recovery(
        target: &ResolvedFaultTarget,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        Self::derive(
            "crucible.referenced-event-consumer.block-recovery.v1",
            target,
        )
    }

    /// Returns the consumer identity of 9p visibility for one World 9p target.
    ///
    /// # Errors
    ///
    /// Returns [`ProductionFaultRuntimeError`] when the target's canonical
    /// material cannot be reserved or encoded.
    pub fn ninep_visibility(
        target: &ResolvedFaultTarget,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        Self::derive(
            "crucible.referenced-event-consumer.ninep-visibility.v1",
            target,
        )
    }

    /// Returns the content identity that names this consumer in checkpoints.
    #[must_use]
    pub const fn id(self) -> ContentHash {
        self.0
    }

    fn derive(
        domain: &str,
        target: &ResolvedFaultTarget,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        let required = target.canonical_material_length();
        let mut material = Vec::new();
        material.try_reserve_exact(required).map_err(|_| {
            runtime_collection_reservation(
                "event_log_bytes",
                0,
                required,
                FaultResourceLimits::default(),
            )
        })?;
        target
            .append_canonical_material_bytes(&mut material)
            .map_err(|_| FaultExecutionError::CheckpointPresence)?;
        Ok(Self(ContentHash::from_canonical_material_bytes(
            domain, &material,
        )))
    }
}

/// One live consumer subscription that a later referenced event may release.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ReferencedEventSubscription {
    /// Storage recovery-event key of the subscribed signal.
    pub event: [u8; 32],
    /// Coordinate strictly after which an emission releases the subscription.
    pub after: ReferencedEventCoordinate,
}

/// One emitted event that the window still retains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedReferencedEvent {
    index: u64,
    key: [u8; 32],
    log_bytes: u64,
    event: ReferencedSignalEvent,
}

impl RetainedReferencedEvent {
    /// Returns the event's zero-based position among all emitted events.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the storage recovery-event key of the emitted signal.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.key
    }

    /// Returns the scheduler coordinate of the emission.
    #[must_use]
    pub const fn coordinate(&self) -> ReferencedEventCoordinate {
        ReferencedEventCoordinate::of(&self.event)
    }

    /// Returns the complete emitted event.
    #[must_use]
    pub const fn event(&self) -> &ReferencedSignalEvent {
        &self.event
    }
}

/// Observable state of the referenced-event history at one boundary.
///
/// Equal evidence means equal emitted histories: the count and chain digest
/// cover every emission, including those no consumer retains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReferencedEventEvidence {
    /// Number of referenced events emitted since the run began.
    pub emitted: u64,
    /// Chain digest over every emitted event in emission order.
    pub history: ContentHash,
    /// Retained events with their emission indexes, in emission order.
    pub retained: Vec<(u64, ReferencedSignalEvent)>,
}

/// Cumulative referenced-event charge against the authored event budgets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ReferencedEventUsage {
    pub(super) records: u64,
    pub(super) log_bytes: u64,
}

/// Validated, charged events of one evaluation awaiting publication.
#[derive(Debug, Default)]
pub(super) struct ChargedReferencedEvents {
    events: Vec<RetainedReferencedEvent>,
    usage: ReferencedEventUsage,
    history: ContentHash,
    newest: Option<ReferencedEventCoordinate>,
}

impl ChargedReferencedEvents {
    /// Returns the cumulative usage after this batch is published.
    pub(super) const fn usage(&self) -> ReferencedEventUsage {
        self.usage
    }

    /// Returns the number of events in the batch.
    pub(super) fn len(&self) -> usize {
        self.events.len()
    }

    /// Reports whether `events` are exactly the charged events in order.
    pub(super) fn matches(&self, events: &[ReferencedSignalEvent]) -> bool {
        self.events.len() == events.len()
            && self
                .events
                .iter()
                .zip(events)
                .all(|(charged, event)| charged.event == *event)
    }
}

/// Retained referenced events, cumulative charges, and consumer subscriptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReferencedEventWindow {
    /// Retained events in strictly increasing emission index order.
    retained: Vec<RetainedReferencedEvent>,
    /// Number of events emitted since the run began.
    emitted: u64,
    /// Cumulative `event_log_bytes` charged for every emitted event.
    log_bytes: u64,
    /// Chain digest over every emitted event.
    history: ContentHash,
    /// Coordinate of the newest emitted event, retained or not.
    newest: Option<ReferencedEventCoordinate>,
    /// Greatest retired coordinate per key, in key order.
    retired: Vec<([u8; 32], ReferencedEventCoordinate)>,
    /// Last reported live subscriptions per bound consumer, sorted and unique.
    consumers: BTreeMap<ReferencedEventConsumer, Vec<ReferencedEventSubscription>>,
}

impl ReferencedEventWindow {
    /// Returns the number of referenced events emitted since the run began.
    #[must_use]
    pub const fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Returns the chain digest over every emitted event.
    #[must_use]
    pub const fn history(&self) -> ContentHash {
        self.history
    }

    /// Returns the retained events in emission order.
    #[must_use]
    pub fn retained(&self) -> &[RetainedReferencedEvent] {
        &self.retained
    }

    /// Returns the retained events whose emission index is at least `index`.
    #[must_use]
    pub fn retained_from(&self, index: u64) -> &[RetainedReferencedEvent] {
        let start = self.retained.partition_point(|event| event.index < index);
        &self.retained[start..]
    }

    /// Returns the retained events whose emission index is below `index`.
    #[must_use]
    pub fn retained_before(&self, index: u64) -> &[RetainedReferencedEvent] {
        let end = self.retained.partition_point(|event| event.index < index);
        &self.retained[..end]
    }

    /// Returns the greatest retired coordinate of events with `key`.
    #[must_use]
    pub fn retired_frontier(&self, key: [u8; 32]) -> Option<ReferencedEventCoordinate> {
        self.retired
            .binary_search_by(|(candidate, _)| candidate.cmp(&key))
            .ok()
            .map(|position| self.retired[position].1)
    }

    /// Returns the evidence projection of the emitted history.
    #[must_use]
    pub fn evidence(&self) -> ReferencedEventEvidence {
        ReferencedEventEvidence {
            emitted: self.emitted,
            history: self.history,
            retained: self
                .retained
                .iter()
                .map(|retained| (retained.index, retained.event.clone()))
                .collect(),
        }
    }

    pub(super) const fn usage(&self) -> ReferencedEventUsage {
        ReferencedEventUsage {
            records: self.emitted,
            log_bytes: self.log_bytes,
        }
    }

    /// Validates and charges one evaluation's emitted events.
    ///
    /// Each event is charged exactly once, here, in emission order: the
    /// cumulative counters replace a rescan of the history.
    pub(super) fn charge(
        &self,
        events: &[ReferencedSignalEvent],
        limits: FaultResourceLimits,
    ) -> Result<ChargedReferencedEvents, ProductionFaultRuntimeError> {
        let mut charged = Vec::new();
        charged.try_reserve_exact(events.len()).map_err(|_| {
            runtime_collection_reservation("event_records", 0, events.len(), limits)
        })?;
        let mut usage = self.usage();
        let mut history = self.history;
        let mut newest = self.newest;

        for event in events {
            let coordinate = ReferencedEventCoordinate::of(event);
            if newest.is_some_and(|previous| coordinate < previous) {
                return Err(FaultExecutionError::CheckpointPresence.into());
            }

            limits.reserve("event_records", usage.records, 1)?;
            let index = usage.records;
            usage.records =
                usage
                    .records
                    .checked_add(1)
                    .ok_or(FaultResourceLimitError::Representation {
                        field: "event_records",
                        value: u64::MAX,
                    })?;
            let log_bytes = referenced_event_log_bytes(event, limits)?;
            limits.reserve("event_log_bytes", usage.log_bytes, log_bytes)?;
            usage.log_bytes += log_bytes;

            history = chain_history(history, event);
            newest = Some(coordinate);
            charged.push(RetainedReferencedEvent {
                index,
                key: referenced_event_key(event)?,
                log_bytes,
                event: event.clone(),
            });
        }

        Ok(ChargedReferencedEvents {
            events: charged,
            usage,
            history,
            newest,
        })
    }

    /// Reserves retained storage so publication cannot allocate.
    pub(super) fn try_reserve(
        &mut self,
        additional: usize,
        limits: FaultResourceLimits,
    ) -> Result<(), ProductionFaultRuntimeError> {
        self.retained.try_reserve(additional).map_err(|_| {
            runtime_collection_reservation("event_records", self.retained.len(), additional, limits)
        })
    }

    /// Publishes a charged batch into storage reserved by [`Self::try_reserve`].
    ///
    /// Retirement runs before the next evaluation stages, so publication only
    /// moves owned values.
    pub(super) fn publish(&mut self, charged: ChargedReferencedEvents) {
        if charged.events.is_empty() {
            return;
        }
        self.retained.extend(charged.events);
        self.emitted = charged.usage.records;
        self.log_bytes = charged.usage.log_bytes;
        self.history = charged.history;
        self.newest = charged.newest;
    }

    /// Binds exactly `consumers`, keeping reported subscriptions of survivors.
    ///
    /// A newly bound consumer starts without subscriptions; its first read
    /// verifies that any live subscription it already holds is covered.
    pub(super) fn bind_consumers(
        &mut self,
        consumers: &[ReferencedEventConsumer],
        host: &HostFaultActionState,
        limits: FaultResourceLimits,
    ) -> Result<(), ProductionFaultRuntimeError> {
        let mut bound = BTreeMap::new();
        for consumer in consumers {
            let subscriptions = self.consumers.remove(consumer).unwrap_or_default();
            bound.insert(*consumer, subscriptions);
        }
        self.consumers = bound;
        self.retire_unneeded(host, limits)
    }

    /// Verifies that every live subscription of `consumer` saw its history.
    pub(super) fn verify_subscriptions(
        &self,
        consumer: ReferencedEventConsumer,
        live: &[ReferencedEventSubscription],
        host: &HostFaultActionState,
    ) -> Result<(), ProductionFaultRuntimeError> {
        let reported = self
            .consumers
            .get(&consumer)
            .ok_or_else(|| window_error(consumer, "is not bound to the production runtime"))?;
        let persistent = persistent_recovery_subscriptions(host);
        for subscription in live {
            if reported.binary_search(subscription).is_err()
                && !self.covers_unreported(subscription, &persistent)
            {
                return Err(window_error(
                    consumer,
                    "holds a live subscription whose referenced events may have retired",
                ));
            }
        }
        Ok(())
    }

    /// Records the live subscriptions of `consumer` and retires unneeded events.
    pub(super) fn report_subscriptions(
        &mut self,
        consumer: ReferencedEventConsumer,
        mut live: Vec<ReferencedEventSubscription>,
        host: &HostFaultActionState,
        limits: FaultResourceLimits,
    ) -> Result<(), ProductionFaultRuntimeError> {
        live.sort_unstable();
        live.dedup();
        let reported = self
            .consumers
            .get(&consumer)
            .ok_or_else(|| window_error(consumer, "is not bound to the production runtime"))?;
        let persistent = persistent_recovery_subscriptions(host);
        for subscription in &live {
            if reported.binary_search(subscription).is_err()
                && !self.covers_unreported(subscription, &persistent)
            {
                return Err(window_error(
                    consumer,
                    "reported a subscription whose referenced events may have retired",
                ));
            }
        }

        if let Some(reported) = self.consumers.get_mut(&consumer) {
            *reported = live;
        }
        self.retire_unneeded(host, limits)
    }

    /// Reports whether retirement can have skipped no event `subscription` needs.
    fn covers_unreported(
        &self,
        subscription: &ReferencedEventSubscription,
        persistent: &[([u8; 32], u64)],
    ) -> bool {
        self.retired_frontier(subscription.event)
            .is_none_or(|frontier| frontier <= subscription.after)
            || persistent.iter().any(|(key, ticks)| {
                *key == subscription.event && *ticks == subscription.after.ticks
            })
    }

    /// Retires every retained event that no retention rule still needs.
    pub(super) fn retire_unneeded(
        &mut self,
        host: &HostFaultActionState,
        limits: FaultResourceLimits,
    ) -> Result<(), ProductionFaultRuntimeError> {
        if self.retained.is_empty() {
            return Ok(());
        }
        let keep = self.needed(host, limits)?;
        if keep.iter().all(|needed| *needed) {
            return Ok(());
        }

        let retiring = keep.iter().filter(|needed| !**needed).count();
        self.retired.try_reserve(retiring).map_err(|_| {
            runtime_collection_reservation("event_records", self.retired.len(), retiring, limits)
        })?;
        for (event, _needed) in self
            .retained
            .iter()
            .zip(&keep)
            .filter(|(_event, needed)| !**needed)
        {
            let coordinate = event.coordinate();
            match self
                .retired
                .binary_search_by(|(candidate, _)| candidate.cmp(&event.key))
            {
                Ok(position) => {
                    let frontier = &mut self.retired[position].1;
                    *frontier = (*frontier).max(coordinate);
                }
                Err(position) => self.retired.insert(position, (event.key, coordinate)),
            }
        }
        let mut needed = keep.into_iter();
        self.retained
            .retain(|_event| needed.next().unwrap_or(false));
        Ok(())
    }

    /// Marks the retained events that a retention rule needs.
    fn needed(
        &self,
        host: &HostFaultActionState,
        limits: FaultResourceLimits,
    ) -> Result<Vec<bool>, ProductionFaultRuntimeError> {
        let count = self.retained.len();
        let allocation =
            |requested| runtime_collection_reservation("event_records", count, requested, limits);
        let mut keep = Vec::new();
        keep.try_reserve_exact(count)
            .map_err(|_| allocation(count))?;
        keep.resize(count, false);
        if self.consumers.is_empty() {
            return Ok(keep);
        }

        // Rule 3: retained coordinates never decrease, and every retirement
        // keeps the newest tick, so its events form the retained suffix.
        if let Some(newest) = self.newest {
            for (position, event) in self.retained.iter().enumerate().rev() {
                if event.event.coordinate.virtual_ticks != newest.ticks {
                    break;
                }
                keep[position] = true;
            }
        }

        // One (key, coordinate)-sorted index answers "earliest event of K
        // after A" by binary search for every subscription.
        let mut index = Vec::new();
        index
            .try_reserve_exact(count)
            .map_err(|_| allocation(count))?;
        index.extend(
            self.retained
                .iter()
                .enumerate()
                .map(|(position, event)| (event.key, event.coordinate(), position)),
        );
        index.sort_unstable();
        let earliest_after = |key: [u8; 32], after: ReferencedEventCoordinate| {
            let start = index.partition_point(|(candidate, coordinate, _)| {
                (*candidate, *coordinate) <= (key, after)
            });
            index
                .get(start)
                .filter(|(candidate, _, _)| *candidate == key)
                .map(|(_, _, position)| *position)
        };

        // Rule 1: reported consumer subscriptions.
        for subscription in self.consumers.values().flatten() {
            if let Some(position) = earliest_after(subscription.event, subscription.after) {
                keep[position] = true;
            }
        }

        // Rule 2: active persistent actions that can still retain completions.
        for (key, ticks) in persistent_recovery_subscriptions(host) {
            let at_tick = ReferencedEventCoordinate { ticks, sequence: 0 };
            let start = index.partition_point(|(candidate, coordinate, _)| {
                (*candidate, *coordinate) < (key, at_tick)
            });
            for (_, _, position) in
                index[start..]
                    .iter()
                    .take_while(|(candidate, coordinate, _)| {
                        *candidate == key && coordinate.ticks == ticks
                    })
            {
                keep[*position] = true;
            }
            let after_tick = ReferencedEventCoordinate {
                ticks,
                sequence: u64::MAX,
            };
            if let Some(position) = earliest_after(key, after_tick) {
                keep[position] = true;
            }
        }
        Ok(keep)
    }
}

/// Checkpoint-facing parts and restore validation.
impl ReferencedEventWindow {
    pub(super) const fn log_bytes(&self) -> u64 {
        self.log_bytes
    }

    pub(super) const fn newest(&self) -> Option<ReferencedEventCoordinate> {
        self.newest
    }

    pub(super) fn retired_frontiers(&self) -> &[([u8; 32], ReferencedEventCoordinate)] {
        &self.retired
    }

    pub(super) const fn consumer_subscriptions(
        &self,
    ) -> &BTreeMap<ReferencedEventConsumer, Vec<ReferencedEventSubscription>> {
        &self.consumers
    }

    /// Rebuilds a window from decoded checkpoint parts.
    ///
    /// A checkpoint may retain events published after the last retirement:
    /// retirement runs before the next evaluation stages, identically in the
    /// live runtime and every continuation restored from its checkpoint.
    // crucible-lint: allow rust-allow -- restore receives each independently encoded window component explicitly.
    #[allow(
        clippy::too_many_arguments,
        reason = "restore receives each independently encoded window component explicitly"
    )]
    pub(super) fn from_parts(
        emitted: u64,
        log_bytes: u64,
        history: ContentHash,
        newest: Option<ReferencedEventCoordinate>,
        retired: Vec<([u8; 32], ReferencedEventCoordinate)>,
        retained: Vec<(u64, ReferencedSignalEvent)>,
        consumers: Vec<(ReferencedEventConsumer, Vec<ReferencedEventSubscription>)>,
        limits: FaultResourceLimits,
    ) -> Result<Self, ProductionFaultRuntimeError> {
        let invalid = || ProductionFaultRuntimeError::from(FaultExecutionError::CheckpointPresence);
        limits.reserve("event_records", 0, emitted)?;
        limits.reserve("event_log_bytes", 0, log_bytes)?;
        if (emitted == 0) != newest.is_none()
            || (emitted == 0 && (log_bytes != 0 || history != ContentHash::default()))
            || !retired.windows(2).all(|pair| pair[0].0 < pair[1].0)
        {
            return Err(invalid());
        }

        let mut window = Self {
            retained: Vec::new(),
            emitted,
            log_bytes,
            history,
            newest,
            retired,
            consumers: BTreeMap::new(),
        };
        window
            .retained
            .try_reserve_exact(retained.len())
            .map_err(|_| {
                runtime_collection_reservation("event_records", 0, retained.len(), limits)
            })?;
        let mut retained_bytes = 0_u64;
        for (index, event) in retained {
            let coordinate = ReferencedEventCoordinate::of(&event);
            let ordered = window.retained.last().is_none_or(|previous| {
                previous.index < index && previous.coordinate() <= coordinate
            });
            if index >= emitted || !ordered || newest.is_none_or(|newest| coordinate > newest) {
                return Err(invalid());
            }
            let log_bytes = referenced_event_log_bytes(&event, limits)?;
            retained_bytes = retained_bytes.checked_add(log_bytes).ok_or_else(invalid)?;
            window.retained.push(RetainedReferencedEvent {
                index,
                key: referenced_event_key(&event)?,
                log_bytes,
                event,
            });
        }
        if retained_bytes > log_bytes {
            return Err(invalid());
        }

        for (consumer, subscriptions) in consumers {
            let canonical = subscriptions.windows(2).all(|pair| pair[0] < pair[1]);
            let ascending = window
                .consumers
                .last_key_value()
                .is_none_or(|(previous, _)| *previous < consumer);
            if !canonical || !ascending {
                return Err(invalid());
            }
            window.consumers.insert(consumer, subscriptions);
        }
        Ok(window)
    }
}

/// Returns the recovery subscription of every retained block completion.
///
/// A completion subscribes when its directive names a recovery event; the
/// device releases it with the earliest emission of that event strictly after
/// its recovery coordinate and no later than its timeout.
#[must_use]
pub fn retained_recovery_subscriptions(
    state: &crucible_device::block::BlockFaultState,
) -> Vec<ReferencedEventSubscription> {
    state
        .retained_completions()
        .values()
        .filter_map(|completion| {
            let (ticks, sequence) = completion
                .recovery_after_ticks
                .zip(completion.recovery_after_sequence)?;
            Some(ReferencedEventSubscription {
                event: completion.recovery_event?,
                after: ReferencedEventCoordinate { ticks, sequence },
            })
        })
        .collect()
}

/// Returns `(recovery key, installation tick)` for every active persistent
/// storage action whose later retentions subscribe to a recovery event.
///
/// The storage resolver subscribes such a retention at the action's own
/// coordinate tick rather than the retaining opportunity's, so the action's
/// installation tick bounds the events it can still need.
fn persistent_recovery_subscriptions(host: &HostFaultActionState) -> Vec<([u8; 32], u64)> {
    host.active()
        .values()
        .filter_map(|action| {
            let recovery_event = match action.effect.specification() {
                EffectSpecification::Storage(
                    StorageEffectSpecification::StallTimeout { recovery_event, .. }
                    | StorageEffectSpecification::FlushDisposition { recovery_event, .. },
                ) => recovery_event.as_ref()?,
                _ => return None,
            };
            Some((
                storage_recovery_event_key(recovery_event),
                action.coordinate.virtual_ticks,
            ))
        })
        .collect()
}

/// Returns the storage recovery-event key of an emitted signal.
fn referenced_event_key(
    event: &ReferencedSignalEvent,
) -> Result<[u8; 32], ProductionFaultRuntimeError> {
    let signal = FaultObjectId::parse(event.signal.as_str())
        .map_err(|_| FaultExecutionError::CheckpointPresence)?;
    Ok(storage_recovery_event_key(&signal))
}

/// Authenticates one event value and returns its `event_log_bytes` charge.
fn referenced_event_log_bytes(
    event: &ReferencedSignalEvent,
    limits: FaultResourceLimits,
) -> Result<u64, ProductionFaultRuntimeError> {
    let (evidence, bytes) = event
        .canonical_value_identity()
        .map_err(FaultExecutionError::from)?;
    if evidence != event.evidence {
        return Err(FaultExecutionError::CheckpointPresence.into());
    }
    let value_bytes =
        u64::try_from(bytes).map_err(|_| FaultResourceLimitError::Representation {
            field: "event_inline_payload_bytes",
            value: u64::MAX,
        })?;
    limits.reserve("event_inline_payload_bytes", 0, value_bytes)?;
    let signal_bytes = u64::try_from(event.signal.as_str().len()).map_err(|_| {
        FaultResourceLimitError::Representation {
            field: "event_log_bytes",
            value: u64::MAX,
        }
    })?;
    signal_bytes
        .checked_add(value_bytes)
        .and_then(|value| value.checked_add(REFERENCED_EVENT_RECORD_OVERHEAD_BYTES))
        .ok_or_else(|| {
            FaultResourceLimitError::Representation {
                field: "event_log_bytes",
                value: u64::MAX,
            }
            .into()
        })
}

/// Appends the identity material of one emitted event.
pub(super) fn event_identity_material(event: &ReferencedSignalEvent, material: &mut Vec<u8>) {
    material.extend_from_slice(event.signal.as_str().as_bytes());
    material.push(0);
    material.extend_from_slice(&event.coordinate.virtual_ticks.to_be_bytes());
    material.extend_from_slice(
        &event
            .coordinate
            .retired_instructions
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(&event.same_coordinate_sequence.to_be_bytes());
    material.extend_from_slice(&event.evidence.bytes);
}

/// Extends the history chain digest by one emitted event.
fn chain_history(history: ContentHash, event: &ReferencedSignalEvent) -> ContentHash {
    let mut material = Vec::with_capacity(32 + event.signal.as_str().len() + 1 + 24 + 32);
    material.extend_from_slice(&history.bytes);
    event_identity_material(event, &mut material);
    ContentHash::from_canonical_material_bytes("crucible.referenced-event-history.v1", &material)
}

fn window_error(
    consumer: ReferencedEventConsumer,
    reason: &'static str,
) -> ProductionFaultRuntimeError {
    ProductionFaultRuntimeError::ReferencedEventWindow {
        consumer: consumer.0.to_hex(),
        reason,
    }
}

#[cfg(test)]
#[path = "referenced_events/tests.rs"]
mod tests;
