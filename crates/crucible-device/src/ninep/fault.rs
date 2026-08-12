//! Signal-driven 9p request results and committed-versus-visible object state.
//!
//! The production coordinator resolves authored effects into these exact values;
//! the device validates and applies them without consulting host state.

use std::collections::BTreeMap;

use crate::DeviceError;

use super::codec::{Message, TMessage};

/// Maximum committed 9p object versions retained by one device continuation.
pub const HARD_NINEP_OBJECT_VERSIONS: usize = 1_048_576;

/// Stable identity of one exact 9p request frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct NinepRequestIdentity {
    /// Exact request coordinate, which distinguishes repeated identical frames.
    pub request_icount: u64,
    /// Shared-memory producer sequence for this exact request.
    pub transport_sequence: u32,
    /// Protocol request tag.
    pub tag: u16,
    /// BLAKE3 digest of the complete encoded request frame.
    pub digest: [u8; 32],
}

/// Closed operation class used by 9p signal bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub enum NinepOperation {
    /// Reads regular-file bytes.
    Read,
    /// Enumerates or queries namespace and metadata state.
    Enumerate,
    /// Negotiates, attaches, or opens protocol state.
    Admit,
    /// Executes a read-only flush or fsync.
    Flush,
    /// Completes or releases protocol state.
    Complete,
    /// Attempts a mutation against the read-only export.
    Write,
}

impl NinepOperation {
    /// Classifies a decoded request into the closed signal operation vocabulary.
    #[must_use]
    pub const fn from_message(message: &TMessage) -> Self {
        match message {
            TMessage::Read { .. } => Self::Read,
            TMessage::Walk { .. }
            | TMessage::Readdir { .. }
            | TMessage::Getattr { .. }
            | TMessage::Readlink { .. }
            | TMessage::Statfs { .. }
            | TMessage::Xattrwalk { .. } => Self::Enumerate,
            TMessage::Version { .. } | TMessage::Attach { .. } | TMessage::Lopen { .. } => {
                Self::Admit
            }
            TMessage::Flush { .. } | TMessage::Fsync { .. } => Self::Flush,
            TMessage::Clunk { .. } | TMessage::Unknown { .. } => Self::Complete,
            TMessage::Mutating { .. } => Self::Write,
        }
    }
}

/// One immutable object version supplied by a scenario artifact.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepObjectVersion {
    /// Absolute canonical slash-separated path.
    pub path: String,
    /// Stable object version sequence exposed in the 9p QID.
    pub version: u32,
    /// Exact Linux mode bits.
    pub mode: u32,
    /// Exact regular-file or symlink bytes; empty for a directory.
    pub data: Vec<u8>,
    /// Whether this version removes the path when its metadata becomes visible.
    pub deleted: bool,
}

impl NinepObjectVersion {
    /// Validates the object independently of any request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidNinepFaultDirective`] for malformed paths,
    /// unsupported kinds, directory bytes, or invalid symlink text.
    pub fn validate(&self) -> Result<(), DeviceError> {
        if !self.path.starts_with('/')
            || self.path.contains("//")
            || self
                .path
                .split('/')
                .any(|component| component == "." || component == "..")
        {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p object path is not absolute and canonical",
            });
        }
        if self.deleted {
            if self.mode != 0 || !self.data.is_empty() {
                return Err(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p deleted object must have zero mode and empty data",
                });
            }
            return Ok(());
        }
        let kind = self.mode & 0o170_000;
        if !matches!(kind, 0o040_000 | 0o100_000 | 0o120_000) {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p object mode has an unsupported file kind",
            });
        }
        if kind == 0o040_000 && !self.data.is_empty() {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p directory object carries data bytes",
            });
        }
        if kind == 0o120_000 && std::str::from_utf8(&self.data).is_err() {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p symlink target is not UTF-8",
            });
        }
        Ok(())
    }

    /// Returns the path as canonical components within the export.
    #[must_use]
    pub fn components(&self) -> Vec<String> {
        if self.path == "/" {
            return Vec::new();
        }
        self.path
            .trim_start_matches('/')
            .split('/')
            .map(str::to_owned)
            .collect()
    }
}

/// Resolved result mutation for one exact request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NinepResultDirective {
    /// Executes the ordinary server result against the visible view.
    Normal,
    /// Returns a positive Linux errno without server-side mutation.
    Errno(u32),
    /// Executes against a retained prior object version.
    Stale(NinepObjectVersion),
    /// Executes against another declared object.
    Misdirected(NinepObjectVersion),
}

/// Complete resolve-phase decision for one exact 9p request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedNinepRequestDirective {
    /// Exact request identity.
    pub identity: NinepRequestIdentity,
    /// Expected operation class.
    pub operation: NinepOperation,
    /// Result mutation selected by composition.
    pub result: NinepResultDirective,
}

impl ResolvedNinepRequestDirective {
    /// Builds an explicit fault-free directive for one request frame.
    ///
    /// Malformed protocol bodies are classified as [`NinepOperation::Complete`]
    /// so the ordinary server path can return its deterministic `Rlerror`
    /// response. Frames shorter than the 9p header use tag zero, matching the
    /// device's ordinary request-correlation fallback.
    ///
    /// # Errors
    ///
    /// This constructor currently has no error case. Its fallible signature is
    /// retained so callers can uniformly propagate request classification
    /// failures if the closed operation vocabulary gains stricter validation.
    pub fn fault_free(
        request_icount: u64,
        transport_sequence: u32,
        frame: &[u8],
    ) -> Result<Self, DeviceError> {
        let decoded = Message::decode(frame).ok();
        let tag = decoded
            .as_ref()
            .map(|message| message.tag)
            .unwrap_or_else(|| {
                frame
                    .get(5..7)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                    .unwrap_or_default()
            });
        Ok(Self {
            identity: NinepRequestIdentity {
                request_icount,
                transport_sequence,
                tag,
                digest: *blake3::hash(frame).as_bytes(),
            },
            operation: decoded
                .as_ref()
                .map(|message| NinepOperation::from_message(&message.body))
                .unwrap_or(NinepOperation::Complete),
            result: NinepResultDirective::Normal,
        })
    }

    /// Validates this directive against the exact encoded request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::InvalidNinepFaultDirective`] when identity,
    /// operation, errno, or object semantics disagree with the request.
    pub fn validate_for(
        &self,
        request_icount: u64,
        transport_sequence: u32,
        frame: &[u8],
    ) -> Result<(), DeviceError> {
        let expected = Self::fault_free(request_icount, transport_sequence, frame)?;
        if self.identity != expected.identity || self.operation != expected.operation {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p directive identity or operation differs from request",
            });
        }
        match &self.result {
            NinepResultDirective::Normal => Ok(()),
            NinepResultDirective::Errno(0) => Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p errno directive must be positive",
            }),
            NinepResultDirective::Errno(_) => Ok(()),
            NinepResultDirective::Stale(object) | NinepResultDirective::Misdirected(object) => {
                if !matches!(
                    self.operation,
                    NinepOperation::Read | NinepOperation::Enumerate
                ) {
                    return Err(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p object result requires read or enumeration",
                    });
                }
                object.validate()?;
                match Message::decode(frame)?.body {
                    TMessage::Walk { ref wnames, .. } if wnames.len() <= 1 => Ok(()),
                    TMessage::Lopen { .. }
                    | TMessage::Read { .. }
                    | TMessage::Readdir { .. }
                    | TMessage::Getattr { .. }
                    | TMessage::Readlink { .. }
                    | TMessage::Xattrwalk { .. } => Ok(()),
                    _ => Err(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p object result does not support this request shape",
                    }),
                }
            }
        }
    }
}

/// Exact request opportunity pinned from the request-ring head.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NinepRequestOpportunity {
    /// Exact request identity.
    pub identity: NinepRequestIdentity,
    /// Request coordinate in guest icount units.
    pub request_icount: u64,
    /// Classified operation.
    pub operation: NinepOperation,
    /// Complete encoded request frame.
    pub frame: Vec<u8>,
}

impl NinepRequestOpportunity {
    /// Decodes an opportunity from one exact ring-head frame.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the payload is not valid 9p.
    pub fn from_frame(
        request_icount: u64,
        transport_sequence: u32,
        frame: Vec<u8>,
    ) -> Result<Self, DeviceError> {
        let directive =
            ResolvedNinepRequestDirective::fault_free(request_icount, transport_sequence, &frame)?;
        Ok(Self {
            identity: directive.identity,
            request_icount,
            operation: directive.operation,
            frame,
        })
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn object(path: &str, version: u32, data: &[u8]) -> NinepObjectVersion {
        NinepObjectVersion {
            path: path.to_owned(),
            version,
            mode: 0o100_644,
            data: data.to_vec(),
            deleted: false,
        }
    }

    fn atomic(scope: NinepVisibilityScope, retain_deleted_objects: bool) -> NinepVisibilityPolicy {
        NinepVisibilityPolicy {
            scope,
            atomic_metadata_and_data: true,
            retain_deleted_objects,
        }
    }

    #[test]
    fn transport_sequence_distinguishes_identical_requests_at_one_coordinate() {
        let frame = [7, 0, 0, 0, 12, 9, 0];
        let first = ResolvedNinepRequestDirective::fault_free(44, 10, &frame)
            .unwrap_or_else(|error| panic!("valid frame: {error}"));
        let second = ResolvedNinepRequestDirective::fault_free(44, 11, &frame)
            .unwrap_or_else(|error| panic!("valid frame: {error}"));
        assert_ne!(first.identity, second.identity);
        assert_eq!(first.identity.digest, second.identity.digest);
    }

    #[test]
    fn delayed_and_event_releases_advance_only_a_contiguous_prefix() {
        let mut state = NinepVisibilityState::default();
        state
            .commit(
                [1; 32],
                object("/a", 1, b"one"),
                atomic(NinepVisibilityScope::Global, false),
                NinepVisibilityRelease::AtNanos(10),
                0,
                0,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));
        state
            .commit(
                [2; 32],
                object("/b", 1, b"two"),
                atomic(NinepVisibilityScope::Global, false),
                NinepVisibilityRelease::OnEvent([9; 32]),
                0,
                0,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));

        assert_eq!(
            state
                .advance_visibility(7, 9, &BTreeMap::new())
                .unwrap_or_else(|error| panic!("advance: {error}")),
            (0, 0)
        );
        assert_eq!(
            state
                .advance_visibility(7, 10, &BTreeMap::new())
                .unwrap_or_else(|error| panic!("advance: {error}")),
            (1, 1)
        );
        let events = BTreeMap::from([([9; 32], 12)]);
        assert_eq!(
            state
                .advance_visibility(7, 12, &events)
                .unwrap_or_else(|error| panic!("advance: {error}")),
            (2, 2)
        );
    }

    #[test]
    fn non_atomic_policy_exposes_metadata_before_new_data() {
        let mut state = NinepVisibilityState::default();
        state
            .commit(
                [1; 32],
                object("/a", 1, b"old"),
                atomic(NinepVisibilityScope::Global, false),
                NinepVisibilityRelease::AtNanos(0),
                0,
                0,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));
        state
            .commit(
                [2; 32],
                object("/a", 2, b"new"),
                NinepVisibilityPolicy {
                    scope: NinepVisibilityScope::Global,
                    atomic_metadata_and_data: false,
                    retain_deleted_objects: false,
                },
                NinepVisibilityRelease::AtNanos(10),
                0,
                5,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));

        state
            .advance_visibility(3, 10, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("advance: {error}"));
        let split = state
            .visible_object(3, "/a")
            .unwrap_or_else(|| panic!("object is visible"));
        assert_eq!(split.version, 2);
        assert_eq!(split.data, b"old");
        state
            .advance_visibility(3, 15, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("advance: {error}"));
        assert_eq!(
            state
                .visible_object(3, "/a")
                .unwrap_or_else(|| panic!("object is visible"))
                .data,
            b"new"
        );
    }

    #[test]
    fn writer_immediate_and_delete_retention_are_explicit() {
        let mut state = NinepVisibilityState::default();
        state
            .commit(
                [1; 32],
                object("/a", 1, b"old"),
                atomic(NinepVisibilityScope::Global, true),
                NinepVisibilityRelease::AtNanos(0),
                4,
                0,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));
        state
            .advance_visibility(4, 0, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("advance: {error}"));
        let mut deletion = object("/a", 2, b"");
        deletion.mode = 0;
        deletion.deleted = true;
        state
            .commit(
                [2; 32],
                deletion,
                atomic(NinepVisibilityScope::WriterImmediate, true),
                NinepVisibilityRelease::AtNanos(100),
                4,
                0,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));

        state
            .advance_visibility(4, 1, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("advance: {error}"));
        assert!(state.visible_object(4, "/a").is_none());
        state
            .advance_visibility(5, 1, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("advance: {error}"));
        assert_eq!(
            state
                .visible_object(5, "/a")
                .unwrap_or_else(|| panic!("retained version remains visible"))
                .data,
            b"old"
        );
    }

    #[test]
    fn data_deadline_overflow_fails_closed() {
        let mut state = NinepVisibilityState::default();
        state
            .commit(
                [1; 32],
                object("/a", 1, b"new"),
                NinepVisibilityPolicy {
                    scope: NinepVisibilityScope::Global,
                    atomic_metadata_and_data: false,
                    retain_deleted_objects: false,
                },
                NinepVisibilityRelease::AtNanos(u64::MAX),
                0,
                1,
            )
            .unwrap_or_else(|error| panic!("commit: {error}"));
        assert!(
            state
                .advance_visibility(1, u64::MAX, &BTreeMap::new())
                .is_err()
        );
    }
}
