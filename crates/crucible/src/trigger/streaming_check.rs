//! Offline assertion checking over a streamed scheduler event log.
//!
//! The seal-time assertion check consumes a retained log once, in order, so a
//! segmented log is graded without materializing it (RFC-0020 CMEAS-21). An
//! [`AssertionLogCheck`] receives entries one at a time and produces the same
//! report, and the same first error, as grading the complete log:
//!
//! - **Validation.** Every entry is checked exactly as the terminal prefix
//!   would check it, against the declared final entry's time. A terminal
//!   validation error therefore wins over any evaluation error, wherever the
//!   two occur in the log.
//! - **Evaluation.** Each intermediate prefix is appended to one condition
//!   prefix and observed. A prefix refused because an entry precedes an
//!   earlier point is deferred only when its atomic batch closes with an
//!   evaluation boundary. Deciding that needs the entries up to the batch's
//!   first entry of another kind, so the check holds at most one atomic batch
//!   of lookahead.
//! - **Finalization.** The terminal prefix is the evaluated prefix extended
//!   with the remaining entries. The reproduction trace hash is computed from
//!   the same streamed entries.

use std::collections::VecDeque;
use std::sync::Arc;

use super::*;

/// Count and final time of the log an [`AssertionLogCheck`] will receive.
///
/// The terminal prefix's validity depends on its final entry's time, so the
/// check needs it before the first entry arrives. A segmented log knows both
/// from its manifest and tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedLogShape {
    entries: u64,
    final_at: Option<VirtualTime>,
}

impl RecordedLogShape {
    /// Describes a log of `entries` entries whose last entry is `last`.
    ///
    /// `last` is `None` exactly when the log is empty.
    #[must_use]
    pub fn new(entries: u64, last: Option<&SchedulerEventLogEntry>) -> Self {
        Self {
            entries,
            final_at: last.map(SchedulerEventLogEntry::at),
        }
    }

    /// Describes a log of `entries` entries whose last entry is stamped
    /// `final_at`, for callers that stream the log and keep only its tail time.
    #[must_use]
    pub const fn with_final_time(entries: u64, final_at: Option<VirtualTime>) -> Self {
        Self { entries, final_at }
    }

    /// Describes a complete in-memory log.
    #[must_use]
    pub fn of(entries: &[SchedulerEventLogEntry]) -> Self {
        Self::new(entries.len() as u64, entries.last())
    }

    /// Returns the number of entries the log holds.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }
}

/// A seal-time assertion check fed one scheduler entry at a time.
///
/// Start one with [`OfflineAssertionChecker::start_check`], pass every entry
/// in log order to [`Self::push`], then call [`Self::finish`]. The oracle must
/// be the same for every call.
pub struct AssertionLogCheck {
    evaluator: HostAssertionEvaluator,
    prefix_end: AssertionPrefixEnd,
    shape: RecordedLogShape,
    offsets: Arc<BTreeMap<u64, EventLogOffset>>,
    require_offsets: bool,
    validation: TerminalValidation,
    trace: ExternalFormalTraceHash,
    received: u64,
    last_received_at: Option<VirtualTime>,
    evaluation: Evaluation,
}

/// Evaluation state for intermediate prefixes.
struct Evaluation {
    prefix: ConditionEventLogPrefix,
    // Entries not yet appended to `prefix`: a refused suffix is retried
    // together with the next entry, exactly as a rebuilt longer prefix would
    // check them.
    pending: Vec<SchedulerEventLogEntry>,
    evaluated: u64,
    deferred: Option<DeferredPrefix>,
    lookahead: VecDeque<SchedulerEventLogEntry>,
    failure: Option<OfflineAssertionCheckError>,
}

/// A refused prefix awaiting its atomic batch's closing entry.
struct DeferredPrefix {
    batch: AtomicBatch,
    error: OfflineAssertionCheckError,
    // Lookahead entries already found to continue the batch.
    scanned: usize,
}

/// Entry kinds an atomic batch may contain before its closing entry.
#[derive(Clone, Copy)]
enum AtomicBatch {
    /// Observations published with their evaluation boundary.
    Observable,
    /// Causal entries and observations published with their boundary.
    Causal,
}

impl AtomicBatch {
    /// Returns the batch a refused prefix ending in `entry` may belong to.
    fn ending_in(entry: &SchedulerEventLogEntry) -> Option<Self> {
        match entry.payload() {
            SchedulerEventLogPayload::Observable(_) => Some(Self::Observable),
            // Quantum EMIT publishes causal entries and their evaluation
            // boundary in one segment. A physical delivery can precede the
            // prior point, but no reader can observe its intermediate prefix.
            SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Decision(_) => Some(Self::Causal),
            _ => None,
        }
    }

    /// Returns whether `entry` closes the batch, and if so whether with an
    /// evaluation boundary.
    fn closed_by(self, entry: &SchedulerEventLogEntry) -> Option<bool> {
        let continues = match self {
            Self::Observable => matches!(entry.payload(), SchedulerEventLogPayload::Observable(_)),
            Self::Causal => matches!(
                entry.payload(),
                SchedulerEventLogPayload::ResolvedHappening(_)
                    | SchedulerEventLogPayload::Decision(_)
                    | SchedulerEventLogPayload::Observable(_)
            ),
        };
        (!continues).then(|| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::EvaluationBoundary(_)
            )
        })
    }
}

/// Streaming form of the terminal prefix's validation.
struct TerminalValidation {
    check: AppendedEntryCheck,
    observable_events: Vec<ObservableEvent>,
    black_box_observation_kinds: BTreeSet<BlackBoxObservationKind>,
    ordering_facts: Vec<ObservedOrderingFact>,
    error: Option<ConditionEvaluationError>,
}

impl TerminalValidation {
    fn new(final_at: Option<VirtualTime>) -> Self {
        Self {
            check: AppendedEntryCheck::new(Some(0), final_at.unwrap_or_default(), None),
            observable_events: Vec::new(),
            black_box_observation_kinds: BTreeSet::new(),
            ordering_facts: Vec::new(),
            error: None,
        }
    }

    /// Checks one entry; only the first refusal is kept.
    fn observe(&mut self, entry: &SchedulerEventLogEntry) {
        if self.error.is_some() {
            return;
        }
        self.observable_events.clear();
        self.black_box_observation_kinds.clear();
        self.ordering_facts.clear();
        if let Err(error) = self.check.check(
            entry,
            &mut self.observable_events,
            &mut self.black_box_observation_kinds,
            &mut self.ordering_facts,
        ) {
            self.error = Some(error);
        }
    }
}

impl OfflineAssertionChecker {
    /// Starts a streaming check of a black-box log with the given shape.
    ///
    /// This is the streaming form of [`Self::check_run`].
    #[must_use]
    pub fn start_check(
        &self,
        properties: &Properties,
        shape: RecordedLogShape,
    ) -> AssertionLogCheck {
        AssertionLogCheck::new(self, properties, shape, Arc::default(), false)
    }

    pub(super) fn build_evaluator(&self, properties: &Properties) -> HostAssertionEvaluator {
        let mut evaluator = HostAssertionEvaluator::new(properties)
            .with_white_box_policies(self.white_box_policies.clone())
            .with_guest_assertion_catalog(self.guest_assertion_catalog.clone())
            .with_resolved_code_points(
                self.code_points
                    .iter()
                    .map(|(key, value)| ((key.0.clone(), key.1.clone()), *value)),
            )
            .with_resolved_mem_places(
                self.mem_places
                    .iter()
                    .map(|(key, value)| ((key.0.clone(), key.1.clone()), value.clone())),
            );
        if let Some(quiescence) = self.terminal_quiescence.clone() {
            evaluator = evaluator.with_terminal_scheduler_quiescence(quiescence);
        }
        evaluator
    }
}

impl AssertionLogCheck {
    pub(super) fn new(
        checker: &OfflineAssertionChecker,
        properties: &Properties,
        shape: RecordedLogShape,
        offsets: Arc<BTreeMap<u64, EventLogOffset>>,
        require_offsets: bool,
    ) -> Self {
        // Property console matchers live in the evaluator's own fold, so the
        // replayed prefix declares none.
        let prefix = ConditionEventLogPrefix::genesis().with_prefix_offsets(Arc::clone(&offsets));
        Self {
            evaluator: checker.build_evaluator(properties),
            prefix_end: checker.prefix_end,
            shape,
            offsets,
            require_offsets,
            validation: TerminalValidation::new(shape.final_at),
            trace: ExternalFormalTraceHash::new(shape.entries),
            received: 0,
            last_received_at: None,
            evaluation: Evaluation {
                prefix,
                pending: Vec::new(),
                evaluated: 0,
                deferred: None,
                lookahead: VecDeque::new(),
                failure: None,
            },
        }
    }

    /// Consumes the next entry of the log.
    ///
    /// Entries beyond the declared count are counted and refused by
    /// [`Self::finish`].
    pub fn push<O>(&mut self, entry: SchedulerEventLogEntry, oracle: &mut O)
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.received = self.received.saturating_add(1);
        self.last_received_at = Some(entry.at());
        if self.received > self.shape.entries {
            return;
        }
        self.validation.observe(&entry);
        self.trace.update(&entry);
        if self.evaluation.failure.is_some() {
            return;
        }

        self.evaluation.lookahead.push_back(entry);
        self.pump(oracle);
    }

    /// Grades the terminal prefix and returns the report.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::RecordedLogShapeMismatch`] when
    /// the entries differ from the declared shape, then, in this order, the
    /// terminal prefix's validation or offset error, the first
    /// intermediate-prefix error, or an assertion fold that failed closed,
    /// including a property console pattern that did not compile.
    pub fn finish<O>(
        mut self,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        if self.received != self.shape.entries || self.last_received_at != self.shape.final_at {
            return Err(OfflineAssertionCheckError::RecordedLogShapeMismatch);
        }
        if let Some(error) = self.validation.error.take() {
            return Err(error.into());
        }
        let terminal_offset = self.recorded_offset(self.shape.entries)?;

        // A batch still open at the end never reached its boundary.
        let evaluation = &mut self.evaluation;
        if let Some(deferred) = evaluation.deferred.take() {
            evaluation.failure.get_or_insert(deferred.error);
        }
        if let Some(failure) = evaluation.failure.take() {
            return Err(failure);
        }

        if !evaluation.pending.is_empty() {
            evaluation.append_pending()?;
        }
        if let Some(offset) = terminal_offset {
            evaluation.prefix.set_event_log_offset(offset);
        }
        let report = self.evaluator.finalize_prefix_with_trace(
            &evaluation.prefix,
            oracle,
            self.prefix_end,
            self.trace.finish(),
        );
        match self.evaluator.assertion_fold_failure() {
            Some(failure) => Err(OfflineAssertionCheckError::Fold(failure.clone())),
            None => Ok(report),
        }
    }

    /// Appends and observes the intermediate prefix ending in `entry`.
    fn evaluate<O>(&mut self, entry: SchedulerEventLogEntry, oracle: &mut O)
    where
        O: HostAssertionOracle + ?Sized,
    {
        let evaluation = &mut self.evaluation;
        let batch = AtomicBatch::ending_in(&entry);
        evaluation.pending.push(entry);
        evaluation.evaluated += 1;
        let prefix_len = evaluation.evaluated;
        // The terminal prefix is observed once, by finalization.
        if prefix_len == self.shape.entries {
            return;
        }

        let recorded_offset = self.offsets.get(&prefix_len).copied();
        if self.require_offsets && recorded_offset.is_none() {
            return;
        }
        let appended = evaluation
            .append_pending()
            .and_then(|()| match recorded_offset {
                Some(offset) if offset.events != prefix_len => {
                    Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
                        prefix_len,
                        offset_events: offset.events,
                    })
                }
                Some(offset) => {
                    evaluation.prefix.set_event_log_offset(offset);
                    Ok(())
                }
                None => Ok(()),
            });
        match appended {
            Ok(()) => {
                self.evaluator.observe_prefix(&evaluation.prefix, oracle);
            }
            Err(
                error @ OfflineAssertionCheckError::ConditionEvaluation(
                    ConditionEvaluationError::FutureEventLogEntry { .. },
                ),
            ) if !self.require_offsets => match batch {
                Some(batch) => {
                    evaluation.deferred = Some(DeferredPrefix {
                        batch,
                        error,
                        scanned: 0,
                    });
                }
                None => evaluation.failure = Some(error),
            },
            Err(error) => evaluation.failure = Some(error),
        }
    }

    /// Evaluates buffered entries until one more entry is needed.
    ///
    /// While a refused prefix is deferred, entries stay buffered until its
    /// batch closes; a batch closed by an evaluation boundary skips the
    /// refused prefix and evaluation resumes with the buffered entries.
    fn pump<O>(&mut self, oracle: &mut O)
    where
        O: HostAssertionOracle + ?Sized,
    {
        loop {
            let evaluation = &mut self.evaluation;
            if evaluation.failure.is_some() {
                evaluation.lookahead.clear();
                return;
            }
            if let Some(deferred) = &mut evaluation.deferred {
                let closing = evaluation
                    .lookahead
                    .iter()
                    .skip(deferred.scanned)
                    .find_map(|entry| deferred.batch.closed_by(entry));
                match closing {
                    None => {
                        deferred.scanned = evaluation.lookahead.len();
                        return;
                    }
                    Some(true) => evaluation.deferred = None,
                    Some(false) => {
                        if let Some(deferred) = evaluation.deferred.take() {
                            evaluation.failure = Some(deferred.error);
                        }
                        continue;
                    }
                }
            }
            let Some(entry) = evaluation.lookahead.pop_front() else {
                return;
            };
            self.evaluate(entry, oracle);
        }
    }

    /// Returns the recorded offset for `prefix_len`, checked against it.
    fn recorded_offset(
        &self,
        prefix_len: u64,
    ) -> Result<Option<EventLogOffset>, OfflineAssertionCheckError> {
        match self.offsets.get(&prefix_len).copied() {
            None if self.require_offsets => {
                Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len })
            }
            None => Ok(None),
            Some(offset) if offset.events != prefix_len => {
                Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
                    prefix_len,
                    offset_events: offset.events,
                })
            }
            Some(offset) => Ok(Some(offset)),
        }
    }
}

impl Evaluation {
    /// Appends the pending entries, keeping them pending when refused.
    fn append_pending(&mut self) -> Result<(), OfflineAssertionCheckError> {
        // Appending clears segment-relative offsets; the recorded whole-log
        // offsets stay bound to the evaluated prefix.
        let offsets = std::mem::take(&mut self.prefix.prefix_offsets);
        let appended = self.prefix.append_scheduler_entries(self.pending.clone());
        self.prefix.prefix_offsets = offsets;
        appended?;
        self.pending.clear();
        Ok(())
    }
}
