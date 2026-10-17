//! Committed-versus-visible 9p namespace and object state.
//!
//! Host-authored object updates commit at a dense, monotone sequence and become
//! visible to a negotiated session only through a contiguous ready prefix. The
//! state keeps three bounded parts:
//!
//! - **Live window.** Updates at or above the compaction floor
//!   (`base_sequence`) keep their full release policy, because some session can
//!   still observe them as not yet visible. A per-path index makes lookups
//!   logarithmic in the window instead of scanning every update.
//! - **Compacted base.** Updates below the floor are visible to the current
//!   session and released for every future session. Only their effect on
//!   lookups survives: per path, the newest version and, when that version is
//!   a deletion, the newest earlier live version whose bytes remain readable.
//! - **One session.** Each `Tversion` starts a new monotone session epoch and
//!   only the current epoch is ever queried, so frontiers of earlier sessions
//!   are retired instead of retained.
//!
//! Update identities are keyed by an authored slot. A slot names the binding,
//! phase, target, and update object that install visibility updates; its
//! generation advances with every new installing action, so a superseded
//! action can never recur and only the newest identity per slot is retained.
//!
//! Release timing lives in the `release` submodule: time deadlines, data lag,
//! and the latch through which an event-released update records the first
//! emission of its event after its commit.

use std::collections::BTreeSet;

use super::*;

#[path = "visibility_release.rs"]
mod release;

pub use release::{NinepEventCoordinate, NinepEventEmission};
use release::{data_deadline, event_subscription, release_coordinate, released_for_every_session};

/// Visibility scope for a committed object update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NinepVisibilityScope {
    /// All sessions advance together.
    Global,
    /// Each session advances in its own request order.
    PerSession,
    /// The writer sees its update immediately; other sessions wait.
    WriterImmediate,
}

/// Complete namespace/data visibility policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepVisibilityPolicy {
    /// Visibility scope.
    pub scope: NinepVisibilityScope,
    /// Whether metadata and data advance atomically.
    pub atomic_metadata_and_data: bool,
    /// Whether deleted objects remain readable before visibility advances.
    pub retain_deleted_objects: bool,
}

/// Release condition for one committed update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NinepVisibilityRelease {
    /// Becomes visible at this absolute virtual-nanosecond boundary.
    AtNanos(u64),
    /// Becomes visible at this exact simulation tick.
    AtTicks(u64),
    /// Becomes visible at the first emission of `event` strictly after
    /// `after`, the coordinate of the committing evaluation. A re-emission
    /// never moves that release coordinate.
    OnEvent {
        /// Content identity of the subscribed signal event.
        event: [u8; 32],
        /// Coordinate of the committing evaluation.
        ///
        /// The first commit of an update fixes it. Recommitting the same
        /// identity from a later opportunity carries a later coordinate, so
        /// it is excluded from the committed content digest.
        after: NinepEventCoordinate,
    },
}

/// Authored identity under which one action commits a visibility update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepVisibilityUpdateKey {
    /// Stable authored source of the update: binding, phase, target, and
    /// update object. One slot installs at most one update per generation.
    pub slot: [u8; 32],
    /// Exact identity of the installing action and its update object.
    pub update_id: [u8; 32],
    /// Monotone generation of the installing action within `slot`.
    ///
    /// A new installing action for the same slot must carry a strictly greater
    /// generation, which lets the state retire superseded identities.
    pub generation: u64,
}

/// One committed object update retained in checkpoint state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepVisibilityUpdate {
    /// Stable authored update identity.
    pub key: NinepVisibilityUpdateKey,
    /// Monotone committed sequence.
    pub sequence: u64,
    /// Immutable object version.
    pub object: NinepObjectVersion,
    /// Scope and atomicity policy.
    pub policy: NinepVisibilityPolicy,
    /// Exact release condition.
    pub release: NinepVisibilityRelease,
    /// Session that authored the update for writer-immediate semantics.
    pub writer_session: u64,
    /// Additional delay between metadata and data visibility.
    pub data_lag_nanos: u64,
    /// Emission that releases an event-released update, once observed.
    ///
    /// It is the earliest emission of the subscribed event strictly after the
    /// subscription coordinate, and it is always absent for time releases.
    pub event_latch: Option<NinepEventCoordinate>,
}

impl NinepVisibilityUpdate {
    fn content_digest(&self) -> [u8; 32] {
        update_content_digest(
            &self.object,
            self.policy,
            self.release,
            self.writer_session,
            self.data_lag_nanos,
        )
    }
}

/// Checkpointed committed-versus-visible 9p object continuation.
///
/// The derived per-path index is rebuilt on decode and never serialized, so
/// the checkpoint carries only canonical state.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(try_from = "NinepVisibilityStateWire")]
pub struct NinepVisibilityState {
    next_sequence: u64,
    base_sequence: u64,
    release_tick: u64,
    event_cursor: u64,
    session: Option<NinepVisibilitySession>,
    updates: BTreeMap<u64, NinepVisibilityUpdate>,
    compacted: BTreeMap<String, NinepCompactedPath>,
    identities: BTreeMap<[u8; 32], NinepSlotIdentity>,
    live_paths: BTreeMap<String, BTreeSet<u64>>,
    /// Live event-released update sequences by subscribed event.
    event_subscribers: BTreeMap<[u8; 32], BTreeSet<u64>>,
}

/// Metadata and data frontiers of the only retained session.
///
/// Frontiers are either both zero, for a session that has committed but not
/// yet advanced, or both at or above the compaction floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepVisibilitySession {
    session: u64,
    metadata: u64,
    data: u64,
}

/// One compacted version that still determines lookups for its path.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepCompactedVersion {
    sequence: u64,
    object: NinepObjectVersion,
    retain_deleted_objects: bool,
}

/// Lookup-relevant residue of every compacted update for one path.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepCompactedPath {
    /// Newest compacted version, live or deleted.
    newest: NinepCompactedVersion,
    /// Newest earlier non-deleted version, present only when `newest` is a
    /// deletion, because data lookups skip deletions.
    newest_live: Option<NinepCompactedVersion>,
}

impl NinepCompactedPath {
    fn version_count(&self) -> usize {
        1 + usize::from(self.newest_live.is_some())
    }

    fn newest_live_object(&self) -> Option<&NinepObjectVersion> {
        if self.newest.object.deleted {
            self.newest_live.as_ref().map(|version| &version.object)
        } else {
            Some(&self.newest.object)
        }
    }
}

/// Newest committed identity of one authored slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepSlotIdentity {
    update_id: [u8; 32],
    generation: u64,
    sequence: u64,
    /// Digest of every committed field, so an idempotent recommit is still
    /// checked byte for byte after its update has been compacted.
    content: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NinepVisibilityStateWire {
    next_sequence: u64,
    base_sequence: u64,
    release_tick: u64,
    event_cursor: u64,
    session: Option<NinepVisibilitySession>,
    updates: BTreeMap<u64, NinepVisibilityUpdate>,
    compacted: BTreeMap<String, NinepCompactedPath>,
    identities: BTreeMap<[u8; 32], NinepSlotIdentity>,
}

#[derive(serde::Serialize)]
struct NinepVisibilityStateRef<'a> {
    next_sequence: u64,
    base_sequence: u64,
    release_tick: u64,
    event_cursor: u64,
    session: &'a Option<NinepVisibilitySession>,
    updates: &'a BTreeMap<u64, NinepVisibilityUpdate>,
    compacted: &'a BTreeMap<String, NinepCompactedPath>,
    identities: &'a BTreeMap<[u8; 32], NinepSlotIdentity>,
}

impl serde::Serialize for NinepVisibilityState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        NinepVisibilityStateRef {
            next_sequence: self.next_sequence,
            base_sequence: self.base_sequence,
            release_tick: self.release_tick,
            event_cursor: self.event_cursor,
            session: &self.session,
            updates: &self.updates,
            compacted: &self.compacted,
            identities: &self.identities,
        }
        .serialize(serializer)
    }
}

impl TryFrom<NinepVisibilityStateWire> for NinepVisibilityState {
    type Error = DeviceError;

    fn try_from(wire: NinepVisibilityStateWire) -> Result<Self, Self::Error> {
        let mut live_paths = BTreeMap::<String, BTreeSet<u64>>::new();
        let mut event_subscribers = BTreeMap::<[u8; 32], BTreeSet<u64>>::new();
        for (sequence, update) in &wire.updates {
            live_paths
                .entry(update.object.path.clone())
                .or_default()
                .insert(*sequence);
            if let Some((event, _after)) = event_subscription(update) {
                event_subscribers
                    .entry(event)
                    .or_default()
                    .insert(*sequence);
            }
        }
        let state = Self {
            next_sequence: wire.next_sequence,
            base_sequence: wire.base_sequence,
            release_tick: wire.release_tick,
            event_cursor: wire.event_cursor,
            session: wire.session,
            updates: wire.updates,
            compacted: wire.compacted,
            identities: wire.identities,
            live_paths,
            event_subscribers,
        };
        state.validate()?;
        Ok(state)
    }
}

/// Layered visibility result for one canonical absolute path.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NinepVisibilityLookup {
    /// No visible update overrides the immutable base tree.
    Base,
    /// A committed policy hides the path or a visible tombstone deletes it.
    Deleted,
    /// This exact object version overrides the immutable base tree.
    Object(NinepObjectVersion),
}

fn invalid(reason: &'static str) -> DeviceError {
    DeviceError::InvalidNinepFaultDirective { reason }
}

impl NinepVisibilityState {
    /// Returns the number of retained session-frontier pairs, at most one.
    #[must_use]
    pub fn session_count(&self) -> usize {
        usize::from(self.session.is_some())
    }

    /// Returns whether one session already owns retained visibility state.
    #[must_use]
    pub fn contains_session(&self, session: u64) -> bool {
        self.session
            .is_some_and(|retained| retained.session == session)
    }

    /// Returns the number of retained object versions: every live update plus
    /// the compacted versions that still determine lookups.
    #[must_use]
    pub fn object_version_count(&self) -> usize {
        self.compacted
            .values()
            .map(NinepCompactedPath::version_count)
            .fold(self.updates.len(), usize::saturating_add)
    }

    /// Returns whether an authenticated update identity is already committed.
    #[must_use]
    pub fn contains_update(&self, key: &NinepVisibilityUpdateKey) -> bool {
        self.identities
            .get(&key.slot)
            .is_some_and(|identity| identity.update_id == key.update_id)
    }

    /// Returns collection sizes needed for bounded checkpoint admission.
    pub(crate) fn checkpoint_collection_counts(&self) -> [usize; 3] {
        [
            self.updates.len(),
            self.compacted.len(),
            self.identities.len(),
        ]
    }

    /// Returns the retained session's metadata and data frontiers.
    ///
    /// At most one session is retained, so the result has zero or one entry.
    #[must_use]
    pub fn session_frontiers(&self) -> Vec<(u64, u64, u64)> {
        self.session
            .iter()
            .map(|retained| (retained.session, retained.metadata, retained.data))
            .collect()
    }

    /// Retires retained frontiers that do not belong to `current`.
    ///
    /// A version negotiation starts a new session epoch, and only the current
    /// epoch is ever queried, so earlier frontiers carry no future meaning.
    pub(crate) fn retire_sessions_except(&mut self, current: u64) {
        if !self.contains_session(current) {
            self.session = None;
        }
    }

    /// Validates all checkpoint indexes, bounds, frontiers, and object records.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when retained state is non-canonical or internally
    /// inconsistent.
    pub fn validate(&self) -> Result<(), DeviceError> {
        if self.object_version_count() > HARD_NINEP_OBJECT_VERSIONS
            || self.identities.len() > HARD_NINEP_OBJECT_VERSIONS
            || self.base_sequence > self.next_sequence
            || self
                .updates
                .keys()
                .copied()
                .ne(self.base_sequence..self.next_sequence)
            || (self.base_sequence == 0 && (self.release_tick != 0 || !self.compacted.is_empty()))
        {
            return Err(invalid("9p visibility checkpoint indexes are inconsistent"));
        }

        self.validate_live_updates()?;
        self.validate_compacted()?;
        self.validate_identities()?;

        if let Some(retained) = self.session {
            let unadvanced = retained.metadata == 0 && retained.data == 0;
            if !unadvanced
                && (retained.data < self.base_sequence
                    || retained.data > retained.metadata
                    || retained.metadata > self.next_sequence)
            {
                return Err(invalid("9p visibility checkpoint frontier is invalid"));
            }
        }
        Ok(())
    }

    fn validate_live_updates(&self) -> Result<(), DeviceError> {
        let mut update_ids = BTreeSet::new();
        let mut slot_generations = BTreeMap::<[u8; 32], u64>::new();
        let mut event_released = 0_usize;
        for (sequence, update) in &self.updates {
            update.object.validate()?;
            if *sequence != update.sequence
                || update.policy.atomic_metadata_and_data != (update.data_lag_nanos == 0)
                || !update_ids.insert(update.key.update_id)
                || !self
                    .live_paths
                    .get(&update.object.path)
                    .is_some_and(|sequences| sequences.contains(sequence))
            {
                return Err(invalid("9p visibility checkpoint update is inconsistent"));
            }
            // A latch must lie strictly after its commit. Whether an emission
            // really produced it is checked against the emitted events by
            // `verify_event_latches`, which this state cannot see.
            match event_subscription(update) {
                Some((event, after)) => {
                    event_released += 1;
                    if update.event_latch.is_some_and(|latched| latched <= after)
                        || !self
                            .event_subscribers
                            .get(&event)
                            .is_some_and(|sequences| sequences.contains(sequence))
                    {
                        return Err(invalid(
                            "9p visibility checkpoint event latch precedes its commit",
                        ));
                    }
                }
                None if update.event_latch.is_some() => {
                    return Err(invalid(
                        "9p visibility checkpoint latches a time-released update",
                    ));
                }
                None => {}
            }
            let previous = slot_generations.insert(update.key.slot, update.key.generation);
            if previous.is_some_and(|generation| generation >= update.key.generation) {
                return Err(invalid(
                    "9p visibility checkpoint slot generations do not increase",
                ));
            }
            let newest = self.identities.get(&update.key.slot).ok_or(invalid(
                "9p visibility checkpoint update lacks its slot identity",
            ))?;
            if newest.sequence < *sequence {
                return Err(invalid(
                    "9p visibility checkpoint slot identity is not the newest",
                ));
            }
        }
        let indexed = self.live_paths.values().map(BTreeSet::len).sum::<usize>();
        let subscribed = self
            .event_subscribers
            .values()
            .map(BTreeSet::len)
            .sum::<usize>();
        if indexed != self.updates.len() || subscribed != event_released {
            return Err(invalid("9p visibility path index is inconsistent"));
        }
        Ok(())
    }

    fn validate_compacted(&self) -> Result<(), DeviceError> {
        for (path, entry) in &self.compacted {
            let newest = &entry.newest;
            newest.object.validate()?;
            if newest.object.path != *path || newest.sequence >= self.base_sequence {
                return Err(invalid("9p compacted visibility version is inconsistent"));
            }
            match &entry.newest_live {
                None => {}
                Some(live) => {
                    live.object.validate()?;
                    if !newest.object.deleted
                        || live.object.deleted
                        || live.object.path != *path
                        || live.sequence >= newest.sequence
                    {
                        return Err(invalid(
                            "9p compacted live visibility version is inconsistent",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_identities(&self) -> Result<(), DeviceError> {
        for (slot, identity) in &self.identities {
            if identity.sequence >= self.next_sequence {
                return Err(invalid(
                    "9p visibility identity is beyond the commit frontier",
                ));
            }
            if identity.sequence < self.base_sequence {
                continue;
            }
            let update = self
                .updates
                .get(&identity.sequence)
                .ok_or(invalid("9p visibility identity index is inconsistent"))?;
            if update.key.slot != *slot
                || update.key.update_id != identity.update_id
                || update.key.generation != identity.generation
                || update.content_digest() != identity.content
            {
                return Err(invalid("9p visibility identity index is inconsistent"));
            }
        }
        Ok(())
    }

    /// Commits one authenticated update exactly once.
    ///
    /// Recommitting the newest identity of a slot with byte-identical content
    /// returns its original sequence, even after that update was compacted.
    ///
    /// A new event-released update latches from `prior_emissions`, which must
    /// hold every retained emission of its event among the first
    /// [`NinepVisibilityState::event_cursor`] fault-runtime emissions; other
    /// emissions are ignored. Later emissions reach it through
    /// [`NinepVisibilityState::observe_events_through`].
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for malformed objects, a reused identity with
    /// differing content, a slot generation that does not advance, more prior
    /// emissions than the cursor consumed, sequence overflow, or the hard
    /// retained-version bound.
    // crucible-lint: allow rust-allow -- one commit validates identity, object, policy, release, writer, lag, and prior emissions atomically.
    #[allow(
        clippy::too_many_arguments,
        reason = "one commit validates identity, object, policy, release, writer, lag, and prior emissions atomically"
    )]
    pub fn commit(
        &mut self,
        key: NinepVisibilityUpdateKey,
        object: NinepObjectVersion,
        policy: NinepVisibilityPolicy,
        release: NinepVisibilityRelease,
        writer_session: u64,
        data_lag_nanos: u64,
        prior_emissions: &[NinepEventEmission],
    ) -> Result<u64, DeviceError> {
        object.validate()?;
        if policy.atomic_metadata_and_data != (data_lag_nanos == 0) {
            return Err(invalid(
                "9p metadata/data atomicity disagrees with data lag",
            ));
        }
        if !u64::try_from(prior_emissions.len()).is_ok_and(|count| count <= self.event_cursor) {
            return Err(invalid(
                "9p visibility prior emissions exceed the event cursor",
            ));
        }
        let content =
            update_content_digest(&object, policy, release, writer_session, data_lag_nanos);

        if let Some(newest) = self.identities.get(&key.slot) {
            if newest.update_id == key.update_id {
                if newest.generation == key.generation && newest.content == content {
                    return Ok(newest.sequence);
                }
                return Err(invalid("9p visibility update identity was reused"));
            }
            // Retained identities are only the newest per slot. An older
            // generation would be a superseded action that the state can no
            // longer recognize, so it fails closed instead of committing twice.
            if key.generation <= newest.generation {
                return Err(invalid(
                    "9p visibility update slot generation did not advance",
                ));
            }
        } else if self.identities.len() == HARD_NINEP_OBJECT_VERSIONS {
            return Err(DeviceError::NinepFaultStateLimit {
                field: "ninep_visibility_slots",
                hard: HARD_NINEP_OBJECT_VERSIONS,
            });
        }
        if self.object_version_count() >= HARD_NINEP_OBJECT_VERSIONS {
            return Err(DeviceError::NinepFaultStateLimit {
                field: "ninep_object_versions",
                hard: HARD_NINEP_OBJECT_VERSIONS,
            });
        }

        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(invalid("9p visibility sequence overflow"))?;
        self.identities.insert(
            key.slot,
            NinepSlotIdentity {
                update_id: key.update_id,
                generation: key.generation,
                sequence,
                content,
            },
        );
        self.live_paths
            .entry(object.path.clone())
            .or_default()
            .insert(sequence);
        self.updates.insert(
            sequence,
            NinepVisibilityUpdate {
                key,
                sequence,
                object,
                policy,
                release,
                writer_session,
                data_lag_nanos,
                event_latch: None,
            },
        );
        if let NinepVisibilityRelease::OnEvent { event, .. } = release {
            self.event_subscribers
                .entry(event)
                .or_default()
                .insert(sequence);
            self.latch_prior_emissions(sequence, prior_emissions);
        }
        if !self.contains_session(writer_session) {
            self.session = Some(NinepVisibilitySession {
                session: writer_session,
                metadata: 0,
                data: 0,
            });
        }
        Ok(sequence)
    }

    /// Advances the contiguous visible frontier at an exact simulation tick.
    /// Latched event coordinates are exact ticks; absolute nanosecond release
    /// boundaries and data-lag durations are scaled before comparison.
    ///
    /// Advancing a session other than the retained one retires the retained
    /// session's frontiers. Before advancing, updates below both the session's
    /// prior data frontier and the globally released prefix are compacted.
    /// Callers supply a non-decreasing `now_tick` and feed new emissions
    /// through [`NinepVisibilityState::observe_events`] first. The compaction
    /// proof relies on that clock and on release coordinates never moving
    /// later.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if checkpoint state is inconsistent, `now_tick`
    /// precedes the tick that proved the current compaction floor, or a release
    /// deadline exceeds the simulation tick range.
    pub fn advance_visibility(
        &mut self,
        session: u64,
        now_tick: u64,
    ) -> Result<(u64, u64), DeviceError> {
        if now_tick < self.release_tick {
            return Err(invalid("9p visibility clock precedes its compaction proof"));
        }
        self.retire_sessions_except(session);
        self.compact(now_tick);

        // A session below the floor has not advanced yet. Every compacted
        // update is released for every session, so it starts at the floor.
        let (metadata_before, data_before) = self.visible_frontier(session);
        let mut metadata = metadata_before.max(self.base_sequence);
        while metadata < self.next_sequence {
            let update = self.updates.get(&metadata).ok_or(invalid(
                "9p visibility frontier references a missing update",
            ))?;
            let ready = update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
                || release_coordinate(update)?.is_some_and(|coordinate| now_tick >= coordinate);
            if !ready {
                break;
            }
            metadata += 1;
        }

        let mut data = data_before.max(self.base_sequence);
        while data < self.next_sequence {
            let update = self
                .updates
                .get(&data)
                .ok_or(invalid("9p data frontier references a missing update"))?;
            let ready = if update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
            {
                true
            } else {
                data_deadline(update)?.is_some_and(|deadline| now_tick >= deadline)
            };
            if !ready {
                break;
            }
            data += 1;
        }

        self.session = Some(NinepVisibilitySession {
            session,
            metadata,
            data,
        });
        Ok((metadata, data))
    }

    /// Folds every update below the compaction floor into the compacted base.
    ///
    /// The floor is the smaller of the retained session's data frontier and
    /// the longest prefix released for every session at `now_tick`. Updates
    /// below it are visible to the current session and would be passed by
    /// any later session's first advance, so only their lookup residue
    /// matters.
    fn compact(&mut self, now_tick: u64) {
        let data_frontier = self.session.map_or(0, |retained| retained.data);
        let mut floor = self.base_sequence;
        while floor < data_frontier {
            let released = self
                .updates
                .get(&floor)
                .is_some_and(|update| released_for_every_session(update, now_tick));
            if !released {
                break;
            }
            floor += 1;
        }
        if floor == self.base_sequence {
            return;
        }

        let folded = self.updates.split_off(&floor);
        let compacted = std::mem::replace(&mut self.updates, folded);
        for (sequence, update) in compacted {
            if let Some(sequences) = self.live_paths.get_mut(&update.object.path) {
                sequences.remove(&sequence);
                if sequences.is_empty() {
                    self.live_paths.remove(&update.object.path);
                }
            }
            if let Some((event, _after)) = event_subscription(&update)
                && let Some(sequences) = self.event_subscribers.get_mut(&event)
            {
                sequences.remove(&sequence);
                if sequences.is_empty() {
                    self.event_subscribers.remove(&event);
                }
            }
            let version = NinepCompactedVersion {
                sequence,
                retain_deleted_objects: update.policy.retain_deleted_objects,
                object: update.object,
            };
            let previous = self.compacted.remove(&version.object.path);
            let newest_live = if version.object.deleted {
                previous.and_then(|entry| {
                    if entry.newest.object.deleted {
                        entry.newest_live
                    } else {
                        Some(entry.newest)
                    }
                })
            } else {
                None
            };
            self.compacted.insert(
                version.object.path.clone(),
                NinepCompactedPath {
                    newest: version,
                    newest_live,
                },
            );
        }
        self.base_sequence = floor;
        self.release_tick = now_tick;
    }

    /// Resolves one path against the visibility overlay without losing deletion
    /// information needed to suppress immutable-base fallback.
    #[must_use]
    pub fn lookup_object(&self, session: u64, path: &str) -> NinepVisibilityLookup {
        let (metadata_frontier, data_frontier) = self.visible_frontier(session);
        let live = self.live_paths.get(path);
        let compacted = self.compacted.get(path);

        let newest_committed = live
            .and_then(|sequences| sequences.last())
            .and_then(|sequence| self.updates.get(sequence))
            .map(|update| {
                (
                    update.sequence,
                    update.object.deleted,
                    update.policy.retain_deleted_objects,
                )
            })
            .or_else(|| {
                compacted.map(|entry| {
                    (
                        entry.newest.sequence,
                        entry.newest.object.deleted,
                        entry.newest.retain_deleted_objects,
                    )
                })
            });
        if newest_committed.is_some_and(|(sequence, deleted, retain)| {
            deleted && !retain && sequence >= metadata_frontier
        }) {
            return NinepVisibilityLookup::Deleted;
        }

        let Some(metadata) = self
            .newest_visible(live, metadata_frontier, |_| true)
            .or_else(|| {
                self.compacted_visible(metadata_frontier)
                    .then_some(compacted.map(|entry| &entry.newest.object))
                    .flatten()
            })
        else {
            return NinepVisibilityLookup::Base;
        };
        if metadata.deleted {
            return NinepVisibilityLookup::Deleted;
        }

        let data = self
            .newest_visible(live, data_frontier, |object| !object.deleted)
            .or_else(|| {
                self.compacted_visible(data_frontier)
                    .then_some(compacted.and_then(NinepCompactedPath::newest_live_object))
                    .flatten()
            })
            .map(|object| object.data.clone())
            .unwrap_or_default();
        let mut visible = metadata.clone();
        visible.data = data;
        NinepVisibilityLookup::Object(visible)
    }

    /// Returns the newest live version below `frontier` accepted by `filter`.
    fn newest_visible(
        &self,
        live: Option<&BTreeSet<u64>>,
        frontier: u64,
        filter: impl Fn(&NinepObjectVersion) -> bool,
    ) -> Option<&NinepObjectVersion> {
        live?
            .range(..frontier)
            .rev()
            .filter_map(|sequence| self.updates.get(sequence))
            .map(|update| &update.object)
            .find(|object| filter(object))
    }

    /// Returns whether compacted versions lie below `frontier`.
    ///
    /// A retained frontier is zero or at least the floor, so the compacted
    /// base is either entirely visible or, before a session's first advance,
    /// entirely invisible.
    fn compacted_visible(&self, frontier: u64) -> bool {
        self.base_sequence > 0 && frontier >= self.base_sequence
    }

    /// Returns the newest visible object, excluding base-tree and deleted paths.
    #[must_use]
    pub fn visible_object(&self, session: u64, path: &str) -> Option<NinepObjectVersion> {
        match self.lookup_object(session, path) {
            NinepVisibilityLookup::Object(object) => Some(object),
            NinepVisibilityLookup::Base | NinepVisibilityLookup::Deleted => None,
        }
    }

    /// Returns the committed frontier.
    #[must_use]
    pub const fn committed_frontier(&self) -> u64 {
        self.next_sequence
    }

    /// Returns the compaction floor: updates below it survive only as their
    /// per-path lookup residue.
    #[must_use]
    pub const fn compacted_frontier(&self) -> u64 {
        self.base_sequence
    }

    /// Returns one session's visible metadata and data frontiers.
    ///
    /// A session without retained frontiers has not advanced and sees `(0, 0)`.
    #[must_use]
    pub fn visible_frontier(&self, session: u64) -> (u64, u64) {
        self.session
            .filter(|retained| retained.session == session)
            .map_or((0, 0), |retained| (retained.metadata, retained.data))
    }

    /// Returns committed live updates in the half-open sequence interval.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidNinepFaultDirective`] when `start` lies
    /// below the compaction floor, because those updates no longer exist
    /// individually.
    pub fn updates_between(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<NinepVisibilityUpdate>, DeviceError> {
        if start < self.base_sequence {
            return Err(invalid(
                "9p visibility updates below the compaction floor were folded",
            ));
        }
        Ok(self
            .updates
            .range(start..end.max(start))
            .map(|(_sequence, update)| update.clone())
            .collect())
    }
}

/// Digests every committed field that idempotent recommits must reproduce.
fn update_content_digest(
    object: &NinepObjectVersion,
    policy: NinepVisibilityPolicy,
    release: NinepVisibilityRelease,
    writer_session: u64,
    data_lag_nanos: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.ninep-visibility-content.v1\0");
    hasher.update(
        &u64::try_from(object.path.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(object.path.as_bytes());
    hasher.update(&object.version.to_le_bytes());
    hasher.update(&object.mode.to_le_bytes());
    hasher.update(
        &u64::try_from(object.data.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&object.data);
    hasher.update(&[u8::from(object.deleted)]);
    let scope = match policy.scope {
        NinepVisibilityScope::Global => 0_u8,
        NinepVisibilityScope::PerSession => 1,
        NinepVisibilityScope::WriterImmediate => 2,
    };
    hasher.update(&[
        scope,
        u8::from(policy.atomic_metadata_and_data),
        u8::from(policy.retain_deleted_objects),
    ]);
    match release {
        NinepVisibilityRelease::AtNanos(nanos) => {
            hasher.update(&[0]);
            hasher.update(&nanos.to_le_bytes());
        }
        NinepVisibilityRelease::AtTicks(ticks) => {
            hasher.update(&[1]);
            hasher.update(&ticks.to_le_bytes());
        }
        // The first commit fixes the subscription coordinate, so it is not
        // content: an idempotent recommit from a later opportunity must match.
        NinepVisibilityRelease::OnEvent { event, after: _ } => {
            hasher.update(&[2]);
            hasher.update(&event);
        }
    }
    hasher.update(&writer_session.to_le_bytes());
    hasher.update(&data_lag_nanos.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
#[path = "visibility_test_support.rs"]
mod test_support;

#[cfg(test)]
#[path = "visibility_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "visibility_release_tests.rs"]
mod release_tests;
