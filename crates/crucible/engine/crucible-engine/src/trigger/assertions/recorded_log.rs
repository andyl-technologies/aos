//! Shared immutable recorded histories with original entry and table custody.

use super::*;
use crate::owned_decode::DecodeCustody;
use std::sync::Arc;

/// Retained assertion-checking view of a recorded scheduler event log.
///
/// Custom host predicate oracles can inspect [`ObservedState::event_log_offset`].
/// To make those predicates byte-identical online and offline, this value stores
/// the scheduler entries plus offsets reconstructed from retained event-log
/// segments using the scheduler's canonical segment and prefix hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAssertionLog {
    body: Arc<RecordedAssertionBody>,
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedAssertionBody {
    entries: Vec<SchedulerEventLogEntry>,
    prefix_offsets: BTreeMap<u64, EventLogOffset>,
    _input: DecodeCustody,
    _array_custody: DecodeCustody,
    custody: DecodeCustody,
}

impl RecordedAssertionLog {
    pub(super) fn enter_original_decode(&self) -> Option<crate::owned_decode::DecodeScope> {
        self.body.custody.enter()
    }

    pub(super) fn prefix_offsets(&self) -> &BTreeMap<u64, EventLogOffset> {
        &self.body.prefix_offsets
    }

    /// Builds a recorded log from scheduler entries without segment offsets.
    ///
    /// This is sufficient for [`OfflineAssertionChecker::check_run`], whose
    /// default black-box oracle cannot inspect event-log offsets. Custom host
    /// oracles should use [`Self::from_segments`] so evaluated prefixes carry the
    /// same offsets the scheduler observed online.
    ///
    /// # Errors
    /// Refuses missing original authority or exhausted metadata before publication.
    pub fn from_entries(entries: Vec<SchedulerEventLogEntry>) -> Result<Self, EngineError> {
        let input = crate::owned_decode::require_current_custody().map_err(admission)?;
        let bank = crate::owned_decode::require_current_child_budget().map_err(admission)?;
        let _scope = bank.enter();
        owned_storage::reserve_arc::<RecordedAssertionBody>()?;
        Ok(Self {
            body: Arc::new(RecordedAssertionBody {
                entries,
                prefix_offsets: BTreeMap::new(),
                _input: input,
                _array_custody: DecodeCustody::default(),
                custody: bank.custody(),
            }),
        })
    }

    /// Builds a recorded log and appends one terminal quantum evaluation boundary.
    ///
    /// # Errors
    /// Returns the original metadata or canonical rendering refusal.
    pub fn from_entries_with_quantum_evaluation_boundary(
        mut entries: Vec<SchedulerEventLogEntry>,
        sequence: u64,
        at: VirtualTime,
    ) -> Result<Self, EngineError> {
        crate::owned_decode::reserve_vec(&mut entries, 1).map_err(admission)?;
        entries.push(SchedulerEventLogEntry::evaluation_boundary(
            sequence,
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        )?);
        Self::from_entries(entries)
    }

    /// Builds a recorded log from retained scheduler event-log segments.
    ///
    /// Each segment is folded in order with the same canonical segment bytes and
    /// prefix hash material used by scheduler EMIT. Offsets are recorded at every
    /// segment boundary, including the zero-entry genesis prefix.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::EventLogSegmentLengthOverflow`] when
    /// a segment byte length cannot fit in `u64`,
    /// [`OfflineAssertionCheckError::EventLogByteOffsetOverflow`] when cumulative
    /// bytes overflow, or [`OfflineAssertionCheckError::EventLogEventCountOverflow`]
    /// when cumulative event count overflows.
    pub fn from_segments(
        segments: impl IntoIterator<Item = Vec<SchedulerEventLogEntry>>,
    ) -> Result<Self, OfflineAssertionCheckError> {
        let input = crate::owned_decode::require_current_custody()
            .map_err(|source| offline(admission(source)))?;
        let bank = crate::owned_decode::require_current_child_budget()
            .map_err(|source| offline(admission(source)))?;
        let _scope = bank.enter();
        let mut array_custody = DecodeCustody::default();
        let mut entries = Vec::new();
        let mut prefix_offsets = BTreeMap::new();
        let mut prefix = scheduler_event_log_empty_prefix();
        let mut bytes = 0_u64;
        let mut events = 0_u64;
        crate::owned_decode::charge_btree_entry::<u64, EventLogOffset>()
            .map_err(|source| offline(admission(source)))?;
        prefix_offsets.insert(events, EventLogOffset::new(prefix, bytes, events));

        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let segment_identity =
                crate::scheduler::scheduler_event_log_segment_identity(prefix, &segment)
                    .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
            let segment_hash = segment_identity.content_hash();
            let previous_prefix = prefix;
            let appended_bytes =
                u64::try_from(segment_identity.canonical_bytes()).map_err(|_| {
                    OfflineAssertionCheckError::EventLogSegmentLengthOverflow {
                        segment_len: segment_identity.canonical_bytes(),
                    }
                })?;
            bytes = bytes.checked_add(appended_bytes).ok_or(
                OfflineAssertionCheckError::EventLogByteOffsetOverflow {
                    bytes,
                    appended_bytes,
                },
            )?;
            let appended_events = u64::try_from(segment.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events: u64::MAX,
                }
            })?;
            events = events.checked_add(appended_events).ok_or(
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events,
                },
            )?;
            prefix = crate::scheduler::scheduler_event_log_prefix_hash(
                previous_prefix,
                segment_hash,
                bytes,
                events,
            );
            crate::owned_decode::charge_btree_entry::<u64, EventLogOffset>()
                .map_err(|source| offline(admission(source)))?;
            prefix_offsets.insert(
                events,
                EventLogOffset::with_appended_segment(previous_prefix, bytes, events, segment_hash),
            );
            crate::owned_decode::grow_retained_vec(&mut entries, segment.len(), &mut array_custody)
                .map_err(|source| offline(admission(source)))?;
            entries.extend(segment);
        }

        owned_storage::reserve_arc::<RecordedAssertionBody>().map_err(offline)?;
        Ok(Self {
            body: Arc::new(RecordedAssertionBody {
                entries,
                prefix_offsets,
                _input: input,
                _array_custody: array_custody,
                custody: bank.custody(),
            }),
        })
    }

    /// Returns retained scheduler event-log entries.
    #[must_use]
    pub fn entries(&self) -> &[SchedulerEventLogEntry] {
        &self.body.entries
    }

    /// Returns the reconstructed event-log offset for `prefix_len`, if retained.
    #[must_use]
    pub fn event_log_offset(&self, prefix_len: u64) -> Option<EventLogOffset> {
        self.body.prefix_offsets.get(&prefix_len).copied()
    }
}

fn admission(source: crate::owned_decode::DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

fn offline(source: EngineError) -> OfflineAssertionCheckError {
    OfflineAssertionCheckError::Engine(Box::new(source))
}
