//! Committed-versus-visible 9p namespace and object state.

use super::*;

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
    /// Becomes visible at this exact virtual-nanosecond coordinate.
    AtNanos(u64),
    /// Becomes visible after this signal event identity is observed.
    OnEvent([u8; 32]),
}

/// One committed object update retained in checkpoint state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepVisibilityUpdate {
    /// Stable authored update identity.
    pub update_id: [u8; 32],
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
}

/// Checkpointed committed-versus-visible 9p object continuation.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepVisibilityState {
    next_sequence: u64,
    session_metadata_frontiers: BTreeMap<u64, u64>,
    session_data_frontiers: BTreeMap<u64, u64>,
    updates: BTreeMap<u64, NinepVisibilityUpdate>,
    identities: BTreeMap<[u8; 32], u64>,
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

impl NinepVisibilityState {
    /// Returns every session's metadata and data frontiers in session order.
    #[must_use]
    pub fn session_frontiers(&self) -> Vec<(u64, u64, u64)> {
        self.session_metadata_frontiers
            .iter()
            .map(|(session, metadata)| {
                (
                    *session,
                    *metadata,
                    self.session_data_frontiers
                        .get(session)
                        .copied()
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    /// Validates all checkpoint indexes, bounds, frontiers, and object records.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when retained state is non-canonical or internally
    /// inconsistent.
    pub fn validate(&self) -> Result<(), DeviceError> {
        if self.updates.len() > HARD_NINEP_OBJECT_VERSIONS
            || self.updates.len() != self.identities.len()
            || self.next_sequence != u64::try_from(self.updates.len()).unwrap_or(u64::MAX)
            || self.updates.keys().copied().ne(0..self.next_sequence)
        {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p visibility checkpoint indexes are inconsistent",
            });
        }
        for (sequence, update) in &self.updates {
            update.object.validate()?;
            if *sequence != update.sequence
                || self.identities.get(&update.update_id) != Some(sequence)
                || update.policy.atomic_metadata_and_data != (update.data_lag_nanos == 0)
            {
                return Err(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p visibility checkpoint update is inconsistent",
                });
            }
        }
        for (session, metadata) in &self.session_metadata_frontiers {
            let data = self.session_data_frontiers.get(session).copied().ok_or(
                DeviceError::InvalidNinepFaultDirective {
                    reason: "9p visibility checkpoint lacks a data frontier",
                },
            )?;
            if data > *metadata || *metadata > self.next_sequence {
                return Err(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p visibility checkpoint frontier is invalid",
                });
            }
        }
        if self.session_data_frontiers.len() != self.session_metadata_frontiers.len() {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p visibility checkpoint session indexes differ",
            });
        }
        Ok(())
    }

    /// Commits one authenticated update exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for malformed objects, conflicting identities,
    /// sequence overflow, or the hard retained-version bound.
    pub fn commit(
        &mut self,
        update_id: [u8; 32],
        object: NinepObjectVersion,
        policy: NinepVisibilityPolicy,
        release: NinepVisibilityRelease,
        writer_session: u64,
        data_lag_nanos: u64,
    ) -> Result<u64, DeviceError> {
        object.validate()?;
        if policy.atomic_metadata_and_data != (data_lag_nanos == 0) {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p metadata/data atomicity disagrees with data lag",
            });
        }
        if let Some(sequence) = self.identities.get(&update_id).copied() {
            let existing =
                self.updates
                    .get(&sequence)
                    .ok_or(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p visibility identity index is inconsistent",
                    })?;
            if existing.object == object
                && existing.policy == policy
                && existing.release == release
                && existing.writer_session == writer_session
                && existing.data_lag_nanos == data_lag_nanos
            {
                return Ok(sequence);
            }
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p visibility update identity was reused",
            });
        }
        if self.updates.len() == HARD_NINEP_OBJECT_VERSIONS {
            return Err(DeviceError::NinepFaultStateLimit {
                field: "ninep_object_versions",
                hard: HARD_NINEP_OBJECT_VERSIONS,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence =
            self.next_sequence
                .checked_add(1)
                .ok_or(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p visibility sequence overflow",
                })?;
        self.identities.insert(update_id, sequence);
        self.updates.insert(
            sequence,
            NinepVisibilityUpdate {
                update_id,
                sequence,
                object,
                policy,
                release,
                writer_session,
                data_lag_nanos,
            },
        );
        self.session_metadata_frontiers
            .entry(writer_session)
            .or_default();
        self.session_data_frontiers
            .entry(writer_session)
            .or_default();
        Ok(sequence)
    }

    /// Advances the contiguous visible frontier at an exact coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if checkpoint state is inconsistent.
    pub fn advance_visibility(
        &mut self,
        session: u64,
        now_nanos: u64,
        observed_events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(u64, u64), DeviceError> {
        let mut metadata = self
            .session_metadata_frontiers
            .get(&session)
            .copied()
            .unwrap_or_default();
        while metadata < self.next_sequence {
            let update =
                self.updates
                    .get(&metadata)
                    .ok_or(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p visibility frontier references a missing update",
                    })?;
            let ready = update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
                || release_coordinate(update.release, observed_events)
                    .is_some_and(|coordinate| now_nanos >= coordinate);
            if !ready {
                break;
            }
            metadata += 1;
        }
        self.session_metadata_frontiers.insert(session, metadata);
        let mut data = self
            .session_data_frontiers
            .get(&session)
            .copied()
            .unwrap_or_default();
        while data < self.next_sequence {
            let update =
                self.updates
                    .get(&data)
                    .ok_or(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p data frontier references a missing update",
                    })?;
            let ready = if update.policy.scope == NinepVisibilityScope::WriterImmediate
                && update.writer_session == session
            {
                true
            } else if let Some(coordinate) = release_coordinate(update.release, observed_events) {
                let deadline = coordinate.checked_add(update.data_lag_nanos).ok_or(
                    DeviceError::InvalidNinepFaultDirective {
                        reason: "9p data visibility deadline overflow",
                    },
                )?;
                now_nanos >= deadline
            } else {
                false
            };
            if !ready {
                break;
            }
            data += 1;
        }
        self.session_data_frontiers.insert(session, data);
        Ok((metadata, data))
    }

    /// Resolves one path against the visibility overlay without losing deletion
    /// information needed to suppress immutable-base fallback.
    #[must_use]
    pub fn lookup_object(&self, session: u64, path: &str) -> NinepVisibilityLookup {
        let metadata_frontier = self
            .session_metadata_frontiers
            .get(&session)
            .copied()
            .unwrap_or_default();
        let newest_committed = self
            .updates
            .values()
            .rev()
            .find(|update| update.object.path == path);
        if newest_committed.is_some_and(|update| {
            update.object.deleted
                && !update.policy.retain_deleted_objects
                && update.sequence >= metadata_frontier
        }) {
            return NinepVisibilityLookup::Deleted;
        }
        let Some(metadata) = self
            .updates
            .range(..metadata_frontier)
            .rev()
            .find_map(|(_, update)| (update.object.path == path).then_some(&update.object))
        else {
            return NinepVisibilityLookup::Base;
        };
        if metadata.deleted {
            return NinepVisibilityLookup::Deleted;
        }
        let data_frontier = self
            .session_data_frontiers
            .get(&session)
            .copied()
            .unwrap_or_default();
        let data = self
            .updates
            .range(..data_frontier)
            .rev()
            .find_map(|(_, update)| {
                (update.object.path == path && !update.object.deleted)
                    .then_some(update.object.data.clone())
            })
            .unwrap_or_default();
        let mut visible = metadata.clone();
        visible.data = data;
        NinepVisibilityLookup::Object(visible)
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

    /// Returns the globally visible frontier.
    #[must_use]
    pub fn visible_frontier(&self, session: u64) -> (u64, u64) {
        (
            self.session_metadata_frontiers
                .get(&session)
                .copied()
                .unwrap_or_default(),
            self.session_data_frontiers
                .get(&session)
                .copied()
                .unwrap_or_default(),
        )
    }

    /// Returns committed updates in the half-open sequence interval.
    #[must_use]
    pub fn updates_between(&self, start: u64, end: u64) -> Vec<NinepVisibilityUpdate> {
        self.updates
            .range(start..end)
            .map(|(_sequence, update)| update.clone())
            .collect()
    }
}

fn release_coordinate(
    release: NinepVisibilityRelease,
    observed_events: &BTreeMap<[u8; 32], u64>,
) -> Option<u64> {
    match release {
        NinepVisibilityRelease::AtNanos(deadline) => Some(deadline),
        NinepVisibilityRelease::OnEvent(event) => observed_events.get(&event).copied(),
    }
}
