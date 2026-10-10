//! Incremental reconstruction of recorded event-log prefixes for offline checks.
//!
//! The offline checker observes every valid prefix of a retained log. Building
//! each prefix from scratch clones and re-authenticates the whole history,
//! which is quadratic in the log length. A [`RecordedPrefixCursor`] instead
//! extends one authenticated prefix with only the entries after its last
//! successful length.

use super::*;

/// Extends one authenticated condition prefix through a recorded log.
///
/// [`ConditionEventLogPrefix::append_scheduler_entries`] validates a suffix
/// with the same density, hash, black-box ordering, and future-entry rules as
/// whole-prefix construction, so each cursor result equals the prefix that
/// [`condition_prefix_from_recorded_log`] would build. A refused suffix leaves
/// the retained prefix unchanged; the next request retries those entries
/// together with its own, exactly as a rebuilt longer prefix would.
pub(super) struct RecordedPrefixCursor<'log> {
    recorded_log: &'log RecordedAssertionLog,
    prefix: ConditionEventLogPrefix,
    appended: usize,
}

impl<'log> RecordedPrefixCursor<'log> {
    /// Starts a cursor at the empty prefix of `recorded_log`.
    pub(super) fn new(recorded_log: &'log RecordedAssertionLog) -> Self {
        Self {
            recorded_log,
            prefix: ConditionEventLogPrefix::genesis()
                .with_prefix_offsets(recorded_log.prefix_offsets.clone()),
            appended: 0,
        }
    }

    /// Returns the checked prefix holding the first `prefix_len` entries.
    ///
    /// Requests must strictly increase across successful calls.
    ///
    /// # Errors
    ///
    /// Returns the same validation and offset errors as
    /// [`condition_prefix_from_recorded_log`]. A request that does not extend
    /// the last successful prefix is refused as a non-prefix sequence.
    pub(super) fn prefix(
        &mut self,
        prefix_len: usize,
        require_recorded_offset: bool,
    ) -> Result<&ConditionEventLogPrefix, OfflineAssertionCheckError> {
        if prefix_len <= self.appended || prefix_len > self.recorded_log.entries().len() {
            return Err(ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::try_from(self.appended).unwrap_or(u64::MAX),
                actual: u64::try_from(prefix_len).unwrap_or(u64::MAX),
            }
            .into());
        }

        let suffix = self.recorded_log.entries()[self.appended..prefix_len].to_vec();
        // Appending clears segment-relative offsets; the recorded whole-log
        // offsets stay bound to this cursor's prefix.
        let prefix_offsets = std::mem::take(&mut self.prefix.prefix_offsets);
        let appended = self.prefix.append_scheduler_entries(suffix);
        self.prefix.prefix_offsets = prefix_offsets;
        appended?;
        self.appended = prefix_len;

        let prefix_len = u64::try_from(prefix_len)
            .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len })?;
        let Some(offset) = self.recorded_log.event_log_offset(prefix_len) else {
            return if require_recorded_offset {
                Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len })
            } else {
                Ok(&self.prefix)
            };
        };
        if offset.events != prefix_len {
            return Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
                prefix_len,
                offset_events: offset.events,
            });
        }
        self.prefix.set_event_log_offset(offset);
        Ok(&self.prefix)
    }
}
