//! Assertion outcomes, replay, offline checking, evaluation, and lifecycle state.

use super::*;
/// Terminal kind for one host-side assertion outcome.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum HostAssertionOutcomeKind {
    /// The assertion completed with its safety-style obligation intact.
    Passed,
    /// The assertion discharged an existential or liveness obligation.
    Satisfied,
    /// The assertion failed and contributes to the run verdict.
    Violated,
    /// The assertion produced a non-failing diagnostic outcome.
    Warning,
    /// The assertion had no evaluation point in its declared scope.
    NeverEvaluated,
    /// The assertion's trigger never fired during the run.
    NeverTriggered,
    /// A warn-disposition reachability marker was never reached.
    NeverReachedWarn,
    /// A fail-disposition reachability marker was never reached.
    NeverReachedFail,
}

/// Assertion quantifier or marker flavor attached to outcomes and violations.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AssertionQuantifierKind {
    /// Host-side invariant over every evaluated point.
    Always,
    /// Host-side existential over the whole run.
    Sometimes,
    /// Host-side deadline-bound liveness assertion.
    Eventually,
    /// Host-side terminal quiescence assertion.
    AfterQuiescence,
    /// Host-side reachability or unreachability assertion.
    Reachable,
    /// Guest-side invariant marker.
    GuestAlways,
    /// Guest-side existential marker.
    GuestSometimes,
    /// Guest-side reachability marker.
    GuestReachable,
    /// Guest-side unreachability marker.
    GuestUnreachable,
}

/// Lifecycle state of one declared property during deterministic evaluation.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum PropertyLifecycleState {
    /// The property is registered but has not yet been evaluated.
    Declared,
    /// The property has been evaluated without a broken obligation.
    Passing,
    /// The property discharged an existential or liveness obligation.
    Satisfied,
    /// The property has an open failing-in-progress obligation.
    Failing,
    /// The property reached a terminal failing state.
    Violated,
}

/// Current lifecycle state for one assertion in the unified outcome engine.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionLifecycle {
    /// Assertion whose lifecycle state is reported.
    pub assertion: AssertionId,
    /// Current deterministic lifecycle state.
    pub state: PropertyLifecycleState,
}

/// Terminal result for one host-side assertion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionOutcome {
    /// Assertion that produced the outcome.
    pub assertion: AssertionId,
    /// Assertion quantifier or guest marker flavor that produced the outcome.
    pub quantifier: AssertionQuantifierKind,
    /// Deterministic virtual time where the outcome was recorded.
    pub at: VirtualTime,
    /// Terminal outcome kind.
    pub kind: HostAssertionOutcomeKind,
    /// Terminal lifecycle state.
    pub lifecycle: PropertyLifecycleState,
    /// Human-readable assertion message from the properties bundle.
    pub message: String,
    /// Stable assertion-layer reason.
    pub reason: String,
    evidence: Option<HostAssertionViolationEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(super) struct HostAssertionViolationEvidence {
    pub(super) at_icount: Option<Icount>,
    pub(super) node: Option<NodeId>,
    pub(super) observed: String,
}

/// Deterministic violation record derived from the retained event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionViolation {
    /// Assertion that failed.
    pub assertion: AssertionId,
    /// Author-facing assertion message.
    pub message: String,
    /// Assertion quantifier or guest marker flavor that failed.
    pub quantifier: AssertionQuantifierKind,
    /// Catalog event kind for the event-log site that produced the violation.
    pub event_kind: String,
    /// Exact guest instruction count when the site is icount-stamped.
    pub at_icount: Option<Icount>,
    /// Exact virtual-time site where the violation was attributed.
    pub at_virtual_time: VirtualTime,
    /// Node-local site owner when the deterministic log identifies one.
    pub node: Option<NodeId>,
    /// Expected-vs-observed detail drawn from assertion outcome and observed state.
    pub detail: String,
    /// Content-addressed reproduction artifact for this run.
    pub reproduction_artifact: ContentHash,
}

/// Assertion event log produced while replaying one reproduction artifact.
///
/// This value binds the retained assertion log to the reduction-oracle replay of
/// the same self-contained `(seed, scenario, schedule)` artifact. Callers cannot
/// construct it from raw fields; they must reduce a [`ReproductionArtifact`] and
/// supply the assertion log emitted by that replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationArtifactReplay {
    replay: ReproductionReplay,
    assertion_log: RecordedAssertionLog,
}

impl AssertionViolationArtifactReplay {
    /// Binds `assertion_log` to a replay of `artifact`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the artifact's embedded scenario and schedule
    /// cannot be reduced by the replay oracle.
    pub fn from_artifact(
        artifact: &ReproductionArtifact,
        assertion_log: RecordedAssertionLog,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            replay: artifact.replay()?,
            assertion_log,
        })
    }

    /// Returns the reduction-oracle replay that produced this assertion log.
    #[must_use]
    pub fn replay(&self) -> &ReproductionReplay {
        &self.replay
    }

    /// Returns the retained assertion log emitted by the artifact replay.
    #[must_use]
    pub fn assertion_log(&self) -> &RecordedAssertionLog {
        &self.assertion_log
    }
}

/// Bisection handoff requested for a non-reproduced assertion violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationBisectionRequest {
    /// Self-contained reproduction artifact whose replay diverged.
    pub artifact: ContentHash,
    /// Last event-log prefix length known to be identical.
    pub last_matching_event_prefix_len: usize,
    /// First event-log prefix length known to differ, or the terminal prefix for
    /// report-only divergences where event logs match but assertion reports do not.
    pub first_different_event_prefix_len: usize,
    /// Number of decisions in the replayed artifact schedule.
    pub schedule_decision_count: usize,
    /// First differing schedule-decision prefix length, when the logs expose one.
    pub first_different_decision_prefix_len: Option<usize>,
    /// First differing causal event-log entry reported to `gate:divergence-bisect`.
    pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>,
    /// Stable reason for invoking `gate:divergence-bisect`.
    pub reason: &'static str,
}

/// Successful replay check for a violation-bearing assertion report.
///
/// The `expected` and `reproduced` reports have all violation artifact links
/// rebound to [`Self::artifact`], not to the retained-log trace hash used while
/// a live run is still being folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationReplayReport {
    /// Self-contained `(seed, scenario, schedule)` artifact that was replayed.
    pub artifact: ContentHash,
    /// Result of replaying the artifact through the reduction oracle.
    pub replay: ReproductionReplay,
    /// Assertion report produced from the originally recorded deterministic log.
    pub expected: HostAssertionReport,
    /// Assertion report produced from the replayed deterministic log.
    pub reproduced: HostAssertionReport,
}

/// Localized mismatch between a recorded assertion violation and its replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationDivergence {
    /// Self-contained reproduction artifact whose replay diverged.
    pub artifact: ContentHash,
    /// First deterministic event-log prefix length whose replay no longer matches.
    pub first_different_prefix_len: usize,
    /// Icount associated with the first differing event or violation, when known.
    pub first_different_icount: Option<Icount>,
    /// First differing causal event-log entry, when the event log differs.
    pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>,
    /// Recorded event-log entry at the first differing prefix position.
    pub expected_event: Option<SchedulerEventLogEntry>,
    /// Replayed event-log entry at the first differing prefix position.
    pub reproduced_event: Option<SchedulerEventLogEntry>,
    /// Recorded violation at the first differing violation slot.
    pub expected_violation: Option<HostAssertionViolation>,
    /// Replayed violation at the first differing violation slot.
    pub reproduced_violation: Option<HostAssertionViolation>,
    /// Required `gate:divergence-bisect` handoff for this non-reproduction.
    pub bisection: AssertionViolationBisectionRequest,
}

/// Error returned when assertion violation reproduction fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssertionViolationReplayError {
    /// The artifact's embedded scenario and schedule could not be reduced.
    ArtifactReplay {
        /// Artifact whose reduction failed.
        artifact: ContentHash,
        /// Stable error text from the reduction oracle.
        reason: String,
    },
    /// Replay evidence was reduced from a different artifact tuple.
    ReplayArtifactMismatch {
        /// Artifact replay expected from the checked reproduction artifact.
        expected: Box<ReproductionReplay>,
        /// Artifact replay supplied with the reproduced assertion log.
        reproduced: Box<ReproductionReplay>,
    },
    /// The original retained log did not contain an assertion violation.
    MissingRecordedViolation {
        /// Artifact checked for a violation reproduction.
        artifact: ContentHash,
    },
    /// The original retained log could not be assertion-checked.
    RecordedAssertionCheck(OfflineAssertionCheckError),
    /// The replayed retained log could not be assertion-checked.
    ReproducedAssertionCheck(OfflineAssertionCheckError),
    /// The replay completed but did not reproduce the same violation report.
    Divergence {
        /// Localized assertion-replay divergence.
        divergence: Box<AssertionViolationDivergence>,
    },
}

impl fmt::Display for AssertionViolationReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactReplay { reason, .. } => {
                write!(
                    formatter,
                    "assertion violation artifact replay failed: {reason}"
                )
            }
            Self::ReplayArtifactMismatch {
                expected,
                reproduced,
            } => write!(
                formatter,
                "assertion violation replay artifact mismatch: expected state {} reproduced state {}",
                expected.state.to_hex(),
                reproduced.state.to_hex()
            ),
            Self::MissingRecordedViolation { .. } => {
                write!(
                    formatter,
                    "recorded assertion log did not contain a violation"
                )
            }
            Self::RecordedAssertionCheck(error) => {
                write!(
                    formatter,
                    "recorded assertion log could not be checked: {error}"
                )
            }
            Self::ReproducedAssertionCheck(error) => {
                write!(
                    formatter,
                    "reproduced assertion log could not be checked: {error}"
                )
            }
            Self::Divergence { divergence } => write!(
                formatter,
                "assertion violation replay diverged at prefix {}",
                divergence.first_different_prefix_len
            ),
        }
    }
}

impl Error for AssertionViolationReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RecordedAssertionCheck(error) | Self::ReproducedAssertionCheck(error) => {
                Some(error)
            }
            Self::ArtifactReplay { .. }
            | Self::ReplayArtifactMismatch { .. }
            | Self::MissingRecordedViolation { .. }
            | Self::Divergence { .. } => None,
        }
    }
}

/// Final host-side assertion report for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionReport {
    outcomes: Vec<HostAssertionOutcome>,
    violations: Vec<HostAssertionViolation>,
    proximities: Vec<HostAssertionProximity>,
    verdict: AssertionRunVerdict,
}

impl HostAssertionReport {
    /// Returns terminal assertion outcomes in canonical assertion order.
    #[must_use]
    pub fn outcomes(&self) -> &[HostAssertionOutcome] {
        &self.outcomes
    }

    /// Returns deterministic violation records in canonical assertion order.
    #[must_use]
    pub fn violations(&self) -> &[HostAssertionViolation] {
        &self.violations
    }

    /// Returns steering-only assertion proximity projections in canonical order.
    ///
    /// These distances are pure projections of the retained event log. They do
    /// not contribute to assertion outcomes, run verdicts, or reproduction
    /// fingerprints.
    #[must_use]
    pub fn proximities(&self) -> &[HostAssertionProximity] {
        &self.proximities
    }

    /// Returns the assertion-layer pass/fail verdict.
    #[must_use]
    pub fn verdict(&self) -> &AssertionRunVerdict {
        &self.verdict
    }
}

/// Steering-only distance-to-satisfaction for one unsatisfied assertion.
///
/// A proximity record is produced only for unsatisfied liveness/existential
/// properties whose predicates have a useful guidance signal: unsatisfied
/// `Sometimes`, armed-but-undischarged `Eventually`, and expected-reachable
/// properties that were never reached. The distance is the minimum value observed
/// along the checked event-log trajectory.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionProximity {
    /// Assertion whose predicate produced this distance.
    pub assertion: AssertionId,
    /// Assertion quantifier that owns the steering obligation.
    pub quantifier: AssertionQuantifierKind,
    /// Non-negative structural distance; zero means the predicate was satisfied.
    pub distance: u128,
    /// Evaluation time where the minimum distance was observed.
    pub at: VirtualTime,
    /// Event-log prefix that produced the minimum distance.
    pub event_log_offset: EventLogOffset,
}

/// Replays an assertion violation artifact and verifies bit-identical violations.
///
/// `reproduced` is the execution-layer bridge: it carries the deterministic
/// assertion event log emitted by replaying `artifact`, plus the reduction-oracle
/// replay that proves the same embedded scenario and schedule were reduced. This
/// function verifies the artifact with the reduction oracle, re-grades the
/// original and reproduced logs against the scenario's embedded properties, and
/// treats any event-log or assertion-report mismatch as a localized divergence.
///
/// # Errors
///
/// Returns [`AssertionViolationReplayError`] when artifact reduction fails, the
/// reproduced log was not reduced from the same artifact tuple, the recorded log
/// contains no violation, either retained assertion log is invalid, or the replay
/// does not reproduce the same assertion report.
pub fn check_assertion_violation_reproduction(
    artifact: &ReproductionArtifact,
    recorded_log: &RecordedAssertionLog,
    reproduced: &AssertionViolationArtifactReplay,
) -> Result<AssertionViolationReplayReport, AssertionViolationReplayError> {
    let mut expected_oracle = BlackBoxHostOracle;
    let mut reproduced_oracle = BlackBoxHostOracle;
    check_assertion_violation_reproduction_with_oracles(
        artifact,
        recorded_log,
        reproduced,
        &mut expected_oracle,
        &mut reproduced_oracle,
    )
}

/// Replays an assertion violation artifact with caller-supplied host oracles.
///
/// This is the offset-preserving variant for linted named host predicates. The
/// supplied oracles grade the recorded and reproduced retained logs respectively;
/// both logs must carry exact segment offsets for every observed prefix the
/// oracle can inspect.
///
/// # Errors
///
/// Returns [`AssertionViolationReplayError`] when artifact reduction fails, the
/// reproduced log was not reduced from the same artifact tuple, the recorded log
/// contains no violation, either retained assertion log is invalid for its oracle,
/// or the replay does not reproduce the same assertion report.
pub fn check_assertion_violation_reproduction_with_oracles<ExpectedOracle, ReproducedOracle>(
    artifact: &ReproductionArtifact,
    recorded_log: &RecordedAssertionLog,
    reproduced: &AssertionViolationArtifactReplay,
    expected_oracle: &mut ExpectedOracle,
    reproduced_oracle: &mut ReproducedOracle,
) -> Result<AssertionViolationReplayReport, AssertionViolationReplayError>
where
    ExpectedOracle: HostAssertionOracle + ?Sized,
    ReproducedOracle: HostAssertionOracle + ?Sized,
{
    let artifact_id = artifact.id();
    let replay =
        artifact
            .replay()
            .map_err(|source| AssertionViolationReplayError::ArtifactReplay {
                artifact: artifact_id,
                reason: engine_error_message(&source),
            })?;
    if reproduced.replay() != &replay {
        return Err(AssertionViolationReplayError::ReplayArtifactMismatch {
            expected: Box::new(replay),
            reproduced: Box::new(reproduced.replay().clone()),
        });
    }
    let properties = artifact.scenario_form().properties();
    let world = artifact.scenario_form().world();
    let expected = assertion_replay_report_for_log_with_oracle(
        artifact_id,
        properties,
        world,
        recorded_log,
        expected_oracle,
    )
    .map_err(AssertionViolationReplayError::RecordedAssertionCheck)?;
    if expected.violations().is_empty() {
        return Err(AssertionViolationReplayError::MissingRecordedViolation {
            artifact: artifact_id,
        });
    }

    let reproduced_log = reproduced.assertion_log();
    let reproduced = assertion_replay_report_for_log_with_oracle(
        artifact_id,
        properties,
        world,
        reproduced_log,
        reproduced_oracle,
    )
    .map_err(AssertionViolationReplayError::ReproducedAssertionCheck)?;

    let event_logs_differ =
        !event_log_causal_projections_match(recorded_log.entries(), reproduced_log.entries());
    if event_logs_differ || expected != reproduced {
        return Err(AssertionViolationReplayError::Divergence {
            divergence: Box::new(assertion_violation_replay_divergence(
                artifact_id,
                artifact.schedule(),
                properties,
                world,
                recorded_log,
                reproduced_log,
                &expected,
                &reproduced,
            )),
        });
    }

    Ok(AssertionViolationReplayReport {
        artifact: artifact_id,
        replay,
        expected,
        reproduced,
    })
}

/// Deterministic trace artifact intended for external formal tooling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFormalTraceExport {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    entry_count: u64,
}

impl ExternalFormalTraceExport {
    /// Returns the stable export format label.
    #[must_use]
    pub fn format(&self) -> &'static str {
        "crucible.external-formal-trace.v1"
    }

    /// Returns deterministic trace bytes for external consumers.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content address of [`Self::bytes`].
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of scheduler event-log entries exported.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// Exporter for external formal trace consumers.
///
/// This type only serializes a retained scheduler event log. It does not load,
/// interpret, or evaluate an external specification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExternalFormalTraceExporter;

impl ExternalFormalTraceExporter {
    /// Exports a retained scheduler event log as deterministic trace bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the entries are not a dense,
    /// hash-valid scheduler log prefix.
    pub fn export_event_log(
        entries: &[SchedulerEventLogEntry],
    ) -> Result<ExternalFormalTraceExport, ConditionEvaluationError> {
        validate_recorded_event_log_entries(entries)?;
        let entry_count = u64::try_from(entries.len()).map_err(|_| {
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        let bytes = external_formal_trace_bytes(entries);
        let content_hash = ContentHash::from_bytes(&bytes);
        Ok(ExternalFormalTraceExport {
            bytes,
            content_hash,
            entry_count,
        })
    }
}

/// Offline assertion checker for a retained scheduler event log.
///
/// The checker never drives guests or scheduler state. It reconstructs checked
/// [`ConditionEventLogPrefix`] values from recorded [`SchedulerEventLogEntry`]
/// values and feeds them through [`HostAssertionEvaluator`], so amended property
/// sets can be graded against retained runs.
#[derive(Clone, Debug, Default)]
pub struct OfflineAssertionChecker {
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    guest_assertion_catalog: Vec<GuestAssertionMarker>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<SchedulerQuiescence>,
}

impl OfflineAssertionChecker {
    /// Builds an offline checker with no white-box marker policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .vm_nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers for offline finalization.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        self.guest_assertion_catalog = catalog.into_iter().collect();
        self
    }

    /// Adds host-side code point resolutions visible to coverage predicates.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Adds terminal scheduler-quiescence evidence for after-quiescence checks.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Grades `properties` against a retained event log using the black-box oracle.
    ///
    /// This entry point is for built-in black-box predicates and guest markers.
    /// Named host predicates that inspect [`ObservedState::event_log_offset`]
    /// should use [`Self::check_run_with_oracle`] with a [`RecordedAssertionLog`]
    /// carrying the exact recorded prefix offsets.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix.
    pub fn check_run(
        &self,
        properties: &Properties,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
        let mut oracle = BlackBoxHostOracle;
        let recorded = RecordedAssertionLog::from_entries(event_log.to_vec());
        self.check_run_internal(properties, &recorded, &mut oracle, false)
    }

    /// Grades `properties` against a retained event log using `oracle`.
    ///
    /// The event log is read-only input. Evaluation observes every recorded
    /// event-log prefix except the terminal prefix, then lets
    /// [`HostAssertionEvaluator::finalize_prefix`] observe that terminal prefix
    /// exactly once before applying end-of-run policies. Each observed point is
    /// reconstructed as a [`ConditionEventLogPrefix`] before evaluation. The
    /// supplied [`RecordedAssertionLog`] should carry exact event-log offsets for
    /// every prefix that can be observed by a named host predicate. Intermediate
    /// prefixes without retained offsets are skipped for custom-oracle checks;
    /// the terminal prefix must always have an exact offset.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix,
    /// [`OfflineAssertionCheckError::MissingEventLogOffset`] when the terminal
    /// prefix has no recorded offset, or
    /// [`OfflineAssertionCheckError::EventLogOffsetMismatch`] when a supplied
    /// offset's event count does not match the evaluated prefix length.
    pub fn check_run_with_oracle<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.check_run_internal(properties, recorded_log, oracle, true)
    }

    fn check_run_internal<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
        require_recorded_offsets: bool,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
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
        let event_log = recorded_log.entries();
        let terminal_prefix_len = event_log.len();

        for index in 0..event_log.len() {
            let prefix_len = index + 1;
            if prefix_len == terminal_prefix_len {
                continue;
            }
            if require_recorded_offsets
                && recorded_log
                    .event_log_offset(u64::try_from(prefix_len).map_err(|_| {
                        OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len }
                    })?)
                    .is_none()
            {
                continue;
            }
            let prefix = condition_prefix_from_recorded_log(
                recorded_log,
                prefix_len,
                require_recorded_offsets,
            )?;
            evaluator.observe_prefix(&prefix, oracle);
        }

        let terminal_prefix = condition_prefix_from_recorded_log(
            recorded_log,
            terminal_prefix_len,
            require_recorded_offsets,
        )?;
        Ok(evaluator.finalize_prefix(&terminal_prefix, oracle))
    }
}

/// Retained assertion-checking view of a recorded scheduler event log.
///
/// Custom host predicate oracles can inspect [`ObservedState::event_log_offset`].
/// To make those predicates byte-identical online and offline, this value stores
/// the scheduler entries plus offsets reconstructed from retained event-log
/// segments using the scheduler's canonical segment and prefix hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAssertionLog {
    pub(super) entries: Vec<SchedulerEventLogEntry>,
    pub(super) prefix_offsets: BTreeMap<u64, EventLogOffset>,
}

impl RecordedAssertionLog {
    /// Builds a recorded log from scheduler entries without segment offsets.
    ///
    /// This is sufficient for [`OfflineAssertionChecker::check_run`], whose
    /// default black-box oracle cannot inspect event-log offsets. Custom host
    /// oracles should use [`Self::from_segments`] so evaluated prefixes carry the
    /// same offsets the scheduler observed online.
    #[must_use]
    pub fn from_entries(entries: Vec<SchedulerEventLogEntry>) -> Self {
        Self {
            entries,
            prefix_offsets: BTreeMap::new(),
        }
    }

    /// Builds a recorded log and appends one terminal quantum evaluation boundary.
    #[must_use]
    pub fn from_entries_with_quantum_evaluation_boundary(
        mut entries: Vec<SchedulerEventLogEntry>,
        sequence: u64,
        at: VirtualTime,
    ) -> Self {
        entries.push(SchedulerEventLogEntry::evaluation_boundary(
            sequence,
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        ));
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
        let mut entries = Vec::new();
        let mut prefix_offsets = BTreeMap::new();
        let mut prefix = scheduler_event_log_empty_prefix();
        let mut bytes = 0_u64;
        let mut events = 0_u64;
        prefix_offsets.insert(events, EventLogOffset::new(prefix, bytes, events));

        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let segment_bytes = scheduler_event_log_segment_bytes(prefix, &segment);
            let segment_hash = ContentHash::from_bytes(&segment_bytes);
            let previous_prefix = prefix;
            let appended_bytes = u64::try_from(segment_bytes.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogSegmentLengthOverflow {
                    segment_len: segment_bytes.len(),
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
            let prefix_material = format!(
                "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
                previous_prefix.to_hex(),
                segment_hash.to_hex(),
            );
            prefix = ContentHash::from_canonical_material(
                "crucible.scheduler.event-log.prefix.v1",
                &prefix_material,
            );
            prefix_offsets.insert(
                events,
                EventLogOffset::with_appended_segment(previous_prefix, bytes, events, segment_hash),
            );
            entries.extend(segment);
        }

        Ok(Self {
            entries,
            prefix_offsets,
        })
    }

    /// Returns retained scheduler event-log entries.
    #[must_use]
    pub fn entries(&self) -> &[SchedulerEventLogEntry] {
        &self.entries
    }

    /// Returns the reconstructed event-log offset for `prefix_len`, if retained.
    #[must_use]
    pub fn event_log_offset(&self, prefix_len: u64) -> Option<EventLogOffset> {
        self.prefix_offsets.get(&prefix_len).copied()
    }
}

/// Error returned by offline assertion checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineAssertionCheckError {
    /// A recorded scheduler prefix failed condition-prefix validation.
    ConditionEvaluation(ConditionEvaluationError),
    /// A custom-oracle check lacks the exact event-log offset for a prefix.
    MissingEventLogOffset {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
    },
    /// A supplied event-log offset does not describe the evaluated prefix.
    EventLogOffsetMismatch {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
        /// Event count stored in the supplied offset.
        offset_events: u64,
    },
    /// The platform prefix length could not be represented in the recorded format.
    PrefixLengthOverflow {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: usize,
    },
    /// A retained event-log segment's canonical byte length exceeded `u64`.
    EventLogSegmentLengthOverflow {
        /// Segment byte length that could not be represented.
        segment_len: usize,
    },
    /// Cumulative event-log byte offsets overflowed.
    EventLogByteOffsetOverflow {
        /// Cumulative bytes before the segment was folded.
        bytes: u64,
        /// Bytes appended by the segment.
        appended_bytes: u64,
    },
    /// Cumulative event-log event counts overflowed.
    EventLogEventCountOverflow {
        /// Cumulative events before the segment was folded.
        events: u64,
        /// Events appended by the segment.
        appended_events: u64,
    },
}

impl fmt::Display for OfflineAssertionCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConditionEvaluation(error) => write!(formatter, "{error}"),
            Self::MissingEventLogOffset { prefix_len } => write!(
                formatter,
                "offline assertion log is missing event-log offset for prefix length {prefix_len}"
            ),
            Self::EventLogOffsetMismatch {
                prefix_len,
                offset_events,
            } => write!(
                formatter,
                "offline assertion log offset for prefix length {prefix_len} carries event count {offset_events}"
            ),
            Self::PrefixLengthOverflow { prefix_len } => write!(
                formatter,
                "offline assertion log prefix length {prefix_len} does not fit in u64"
            ),
            Self::EventLogSegmentLengthOverflow { segment_len } => write!(
                formatter,
                "offline assertion log segment length {segment_len} does not fit in u64"
            ),
            Self::EventLogByteOffsetOverflow {
                bytes,
                appended_bytes,
            } => write!(
                formatter,
                "offline assertion log byte offset overflow: bytes={bytes} appended_bytes={appended_bytes}"
            ),
            Self::EventLogEventCountOverflow {
                events,
                appended_events,
            } => write!(
                formatter,
                "offline assertion log event count overflow: events={events} appended_events={appended_events}"
            ),
        }
    }
}

impl Error for OfflineAssertionCheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConditionEvaluation(error) => Some(error),
            Self::MissingEventLogOffset { .. }
            | Self::EventLogOffsetMismatch { .. }
            | Self::PrefixLengthOverflow { .. }
            | Self::EventLogSegmentLengthOverflow { .. }
            | Self::EventLogByteOffsetOverflow { .. }
            | Self::EventLogEventCountOverflow { .. } => None,
        }
    }
}

impl From<ConditionEvaluationError> for OfflineAssertionCheckError {
    fn from(error: ConditionEvaluationError) -> Self {
        Self::ConditionEvaluation(error)
    }
}

/// Streaming host-side assertion evaluator over checked observable state.
#[derive(Clone, Debug)]
pub struct HostAssertionEvaluator {
    states: Vec<HostAssertionState>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Condition>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    last_prefix: Option<ConditionEventLogPrefix>,
}

const HOST_ASSERTION_CHECKPOINT_MAGIC: &[u8] = b"crucible.host-assertion-continuation.v1\0";
const HOST_ASSERTION_CHECKPOINT_MAX_BYTES: usize = 268_435_456;

/// Process-independent continuation of the streaming host assertion evaluator.
#[derive(Clone, Debug)]
pub struct HostAssertionEvaluatorCheckpoint {
    wire: HostAssertionEvaluatorWire,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAssertionEvaluatorWire {
    states: Vec<HostAssertionStateWire>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Vec<u8>>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    last_prefix: Option<EventLogOffset>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAssertionStateWire {
    assertion: AssertionId,
    lifecycle: PropertyLifecycleState,
    terminal: Option<HostAssertionTerminal>,
    evaluated: bool,
    eventually_triggered: bool,
    eventually_satisfied_at: Option<VirtualTime>,
    pending_eventually: Vec<EventuallyObligation>,
    proximity: Option<HostAssertionProximityMinimum>,
}

impl HostAssertionEvaluator {
    /// Captures every mutable assertion-evaluation field at the current prefix.
    #[must_use]
    pub fn checkpoint(&self) -> HostAssertionEvaluatorCheckpoint {
        HostAssertionEvaluatorCheckpoint {
            wire: HostAssertionEvaluatorWire {
                states: self
                    .states
                    .iter()
                    .map(|state| HostAssertionStateWire {
                        assertion: state.assertion.id.clone(),
                        lifecycle: state.lifecycle,
                        terminal: state.terminal.clone(),
                        evaluated: state.evaluated,
                        eventually_triggered: state.eventually_triggered,
                        eventually_satisfied_at: state.eventually_satisfied_at,
                        pending_eventually: state.pending_eventually.clone(),
                        proximity: state.proximity.clone(),
                    })
                    .collect(),
                guest_marker_states: self.guest_marker_states.clone(),
                once_latches: self
                    .once_latches
                    .iter()
                    .map(Predicate::to_compact_binary)
                    .collect(),
                terminal_quiescence: self.terminal_quiescence.clone(),
                last_prefix: self
                    .last_prefix
                    .as_ref()
                    .map(ConditionEventLogPrefix::event_log_offset),
            },
        }
    }
}

impl HostAssertionEvaluatorCheckpoint {
    /// Encodes the complete assertion continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`HostAssertionCheckpointError`] when the checkpoint is malformed
    /// or exceeds its hard encoded-size ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HostAssertionCheckpointError> {
        validate_host_assertion_wire(&self.wire)?;
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&self.wire, &mut payload)
            .map_err(|_| HostAssertionCheckpointError::Malformed)?;
        if payload.len() > HOST_ASSERTION_CHECKPOINT_MAX_BYTES {
            return Err(HostAssertionCheckpointError::Limit);
        }
        let mut bytes = Vec::with_capacity(HOST_ASSERTION_CHECKPOINT_MAGIC.len() + payload.len());
        bytes.extend_from_slice(HOST_ASSERTION_CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes and validates one canonical assertion continuation.
    ///
    /// # Errors
    ///
    /// Returns [`HostAssertionCheckpointError`] for unsupported, malformed,
    /// noncanonical, or over-limit input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HostAssertionCheckpointError> {
        let payload = bytes
            .strip_prefix(HOST_ASSERTION_CHECKPOINT_MAGIC)
            .ok_or(HostAssertionCheckpointError::Version)?;
        if payload.len() > HOST_ASSERTION_CHECKPOINT_MAX_BYTES {
            return Err(HostAssertionCheckpointError::Limit);
        }
        let wire: HostAssertionEvaluatorWire = ciborium::de::from_reader(payload)
            .map_err(|_| HostAssertionCheckpointError::Malformed)?;
        let checkpoint = Self { wire };
        if checkpoint.canonical_bytes()?.as_slice() != bytes {
            return Err(HostAssertionCheckpointError::Noncanonical);
        }
        Ok(checkpoint)
    }

    /// Restores this continuation into an evaluator built from the same properties.
    ///
    /// # Errors
    ///
    /// Returns [`HostAssertionCheckpointError`] when assertion identities or the
    /// current event-log prefix do not match the checkpoint.
    pub fn restore_into(
        &self,
        evaluator: &mut HostAssertionEvaluator,
        current_prefix: &ConditionEventLogPrefix,
    ) -> Result<(), HostAssertionCheckpointError> {
        validate_host_assertion_wire(&self.wire)?;
        if self.wire.states.len() != evaluator.states.len()
            || self
                .wire
                .states
                .iter()
                .zip(&evaluator.states)
                .any(|(wire, state)| wire.assertion != state.assertion.id)
            || self.wire.last_prefix.is_some()
                && self.wire.last_prefix != Some(current_prefix.event_log_offset())
        {
            return Err(HostAssertionCheckpointError::Binding);
        }
        let once_latches = self
            .wire
            .once_latches
            .iter()
            .map(|bytes| Predicate::from_compact_binary(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| HostAssertionCheckpointError::Malformed)?;
        let mut staged = evaluator.clone();
        for (state, wire) in staged.states.iter_mut().zip(&self.wire.states) {
            state.lifecycle = wire.lifecycle;
            state.terminal = wire.terminal.clone();
            state.evaluated = wire.evaluated;
            state.eventually_triggered = wire.eventually_triggered;
            state.eventually_satisfied_at = wire.eventually_satisfied_at;
            state.pending_eventually = wire.pending_eventually.clone();
            state.proximity = wire.proximity.clone();
        }
        staged.guest_marker_states = self.wire.guest_marker_states.clone();
        staged.once_latches = once_latches;
        staged.terminal_quiescence = self.wire.terminal_quiescence.clone();
        staged.last_prefix = self.wire.last_prefix.map(|_| current_prefix.clone());
        *evaluator = staged;
        Ok(())
    }
}

fn validate_host_assertion_wire(
    wire: &HostAssertionEvaluatorWire,
) -> Result<(), HostAssertionCheckpointError> {
    if !wire
        .states
        .windows(2)
        .all(|pair| pair[0].assertion < pair[1].assertion)
        || !wire
            .guest_marker_states
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(HostAssertionCheckpointError::Noncanonical);
    }
    for predicate in &wire.once_latches {
        Predicate::from_compact_binary(predicate)
            .map_err(|_| HostAssertionCheckpointError::Malformed)?;
    }
    Ok(())
}

/// Error returned by host-assertion continuation encoding and restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAssertionCheckpointError {
    /// The envelope semantic version is unsupported.
    Version,
    /// The payload is malformed.
    Malformed,
    /// The payload is valid but not canonical.
    Noncanonical,
    /// The payload exceeds its hard bound.
    Limit,
    /// The continuation does not bind to the admitted properties or log prefix.
    Binding,
}

impl fmt::Display for HostAssertionCheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Version => formatter.write_str("unsupported host-assertion checkpoint version"),
            Self::Malformed => formatter.write_str("malformed host-assertion checkpoint"),
            Self::Noncanonical => formatter.write_str("noncanonical host-assertion checkpoint"),
            Self::Limit => formatter.write_str("host-assertion checkpoint exceeds its size limit"),
            Self::Binding => formatter.write_str("host-assertion checkpoint binding mismatch"),
        }
    }
}

impl Error for HostAssertionCheckpointError {}

impl HostAssertionEvaluator {
    /// Builds an evaluator for the assertions in canonical property order.
    #[must_use]
    pub fn new(properties: &Properties) -> Self {
        let (states, guest_marker_states) = partition_declared_assertions(properties);
        Self {
            states,
            guest_marker_states,
            once_latches: Vec::new(),
            white_box_policies: BTreeMap::new(),
            code_points: BTreeMap::new(),
            mem_places: BTreeMap::new(),
            terminal_quiescence: None,
            last_prefix: None,
        }
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .vm_nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers before event-log evaluation.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        for marker in catalog {
            let _ = guest_marker_assertion_state_for(&mut self.guest_marker_states, &marker);
        }
        self
    }

    /// Adds host-side code point resolutions visible to coverage predicates.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Adds terminal scheduler-quiescence evidence for after-quiescence checks.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Observes one checked event-log prefix and returns newly terminal outcomes.
    pub fn observe_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut outcomes = Vec::new();
        outcomes.extend(self.observe_due_eventually_deadlines(prefix, oracle));
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            if let Some(outcome) = observe_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
                &self.code_points,
                &self.mem_places,
            ) {
                outcomes.push(outcome);
            }
        }
        outcomes.extend(observe_guest_marker_assertions(
            &mut self.guest_marker_states,
            prefix,
            &self.white_box_policies,
        ));
        self.last_prefix = Some(prefix.clone());
        sort_host_assertion_outcomes(&mut outcomes);
        outcomes
    }

    /// Returns current lifecycle states in canonical assertion order.
    #[must_use]
    pub fn lifecycle_states(&self) -> Vec<HostAssertionLifecycle> {
        let mut states = self
            .states
            .iter()
            .map(HostAssertionState::lifecycle)
            .chain(
                self.guest_marker_states
                    .iter()
                    .map(GuestMarkerAssertionState::lifecycle),
            )
            .collect::<Vec<_>>();
        states.sort_by(|left, right| {
            left.assertion
                .cmp(&right.assertion)
                .then_with(|| left.state.cmp(&right.state))
        });
        states
    }

    fn observe_due_eventually_deadlines<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let Some(previous_prefix) = self.last_prefix.clone() else {
            return Vec::new();
        };
        let previous_at = previous_prefix.point().at().ticks;
        let next_at = prefix.point().at().ticks;
        if next_at <= previous_at {
            return Vec::new();
        }

        let mut deadlines = BTreeSet::new();
        for state in &self.states {
            if state.terminal.is_some() {
                continue;
            }
            for obligation in &state.pending_eventually {
                if obligation.deadline.ticks > previous_at && obligation.deadline.ticks < next_at {
                    deadlines.insert(obligation.deadline);
                }
            }
        }

        let mut outcomes = Vec::new();
        for deadline in deadlines {
            let Some(deadline_prefix) =
                prefix.with_facts_through_point(EventEvaluationPoint::assertion_deadline(deadline))
            else {
                continue;
            };
            let once_latches = &mut self.once_latches;
            for state in &mut self.states {
                if let Some(outcome) = observe_eventually_deadline_state(
                    state,
                    &deadline_prefix,
                    oracle,
                    once_latches,
                    &self.white_box_policies,
                    &self.code_points,
                    &self.mem_places,
                ) {
                    outcomes.push(outcome);
                }
            }
        }
        outcomes
    }

    /// Finalizes all assertions at the supplied terminal event-log prefix.
    pub fn finalize_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> HostAssertionReport
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.observe_prefix(prefix, oracle);
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            finalize_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
                &self.code_points,
                &self.mem_places,
                self.terminal_quiescence.as_ref(),
            );
        }
        for state in &mut self.guest_marker_states {
            finalize_guest_marker_assertion_state(state, prefix.point().at());
        }
        let outcomes = self
            .states
            .iter()
            .filter_map(HostAssertionState::outcome)
            .chain(
                self.guest_marker_states
                    .iter()
                    .filter_map(GuestMarkerAssertionState::outcome),
            )
            .collect::<Vec<_>>();
        let mut outcomes = outcomes;
        sort_host_assertion_outcomes(&mut outcomes);
        let failures = outcomes
            .iter()
            .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
            .map(|outcome| {
                AssertionVerdictFailure::new(
                    outcome.assertion.clone(),
                    outcome.at,
                    outcome.reason.clone(),
                )
            })
            .collect::<Vec<_>>();
        let reproduction_artifact = assertion_reproduction_artifact_from_prefix(prefix);
        let violations =
            host_assertion_violations_from_outcomes(&outcomes, prefix, reproduction_artifact);
        let mut proximities = self
            .states
            .iter()
            .filter_map(HostAssertionState::proximity)
            .collect::<Vec<_>>();
        sort_host_assertion_proximities(&mut proximities);
        HostAssertionReport {
            outcomes,
            violations,
            proximities,
            verdict: AssertionRunVerdict::failed(failures),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct HostAssertionState {
    assertion: AssertionDef,
    lifecycle: PropertyLifecycleState,
    terminal: Option<HostAssertionTerminal>,
    evaluated: bool,
    eventually_triggered: bool,
    eventually_satisfied_at: Option<VirtualTime>,
    pending_eventually: Vec<EventuallyObligation>,
    proximity: Option<HostAssertionProximityMinimum>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct GuestMarkerAssertionState {
    pub(super) id: AssertionId,
    pub(super) lifecycle: PropertyLifecycleState,
    pub(super) message: String,
    pub(super) kind: GuestAssertionKind,
    pub(super) must_hit: bool,
    pub(super) details: Vec<GuestAssertionDetail>,
    pub(super) location: String,
    pub(super) observed_true: bool,
    pub(super) last_icount: Option<Icount>,
    pub(super) last_node: Option<NodeId>,
    pub(super) terminal: Option<HostAssertionTerminal>,
    pub(super) declared_message: Option<String>,
}

impl GuestMarkerAssertionState {
    pub(super) fn new(marker: &GuestAssertionMarker) -> Self {
        Self {
            id: marker.id.clone(),
            lifecycle: PropertyLifecycleState::Declared,
            message: marker.message.clone(),
            kind: marker.kind,
            must_hit: marker.must_hit,
            details: marker.details.clone(),
            location: marker.location.clone(),
            observed_true: false,
            last_icount: None,
            last_node: None,
            terminal: None,
            declared_message: None,
        }
    }

    fn lifecycle(&self) -> HostAssertionLifecycle {
        HostAssertionLifecycle {
            assertion: self.id.clone(),
            state: self.lifecycle,
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.id.clone(),
            quantifier: guest_assertion_quantifier_kind(self.kind),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: self.message.clone(),
            reason: terminal.reason.clone(),
            evidence: terminal.evidence.clone(),
        })
    }

    pub(super) fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    pub(super) fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason: reason.into(),
            evidence,
        });
        self.outcome()
    }
}

impl HostAssertionState {
    pub(super) fn new(assertion: &AssertionDef) -> Self {
        Self {
            assertion: assertion.clone(),
            lifecycle: PropertyLifecycleState::Declared,
            terminal: None,
            evaluated: false,
            eventually_triggered: false,
            eventually_satisfied_at: None,
            pending_eventually: Vec::new(),
            proximity: None,
        }
    }

    fn lifecycle(&self) -> HostAssertionLifecycle {
        HostAssertionLifecycle {
            assertion: self.assertion.id.clone(),
            state: self.lifecycle,
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.assertion.id.clone(),
            quantifier: property_quantifier_kind(&self.assertion.property),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: self.assertion.message.clone(),
            reason: terminal.reason.clone(),
            evidence: terminal.evidence.clone(),
        })
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason: reason.into(),
            evidence,
        });
        self.outcome()
    }

    fn observe_proximity(&mut self, prefix: &ConditionEventLogPrefix, distance: u128) {
        let candidate = HostAssertionProximityMinimum {
            distance,
            at: prefix.point().at(),
            event_log_offset: prefix.event_log_offset(),
        };
        let should_replace = match self.proximity.as_ref() {
            Some(current) => candidate.is_better_than(current),
            None => true,
        };
        if should_replace {
            self.proximity = Some(candidate);
        }
    }

    fn proximity(&self) -> Option<HostAssertionProximity> {
        let terminal = self.terminal.as_ref()?;
        if !property_proximity_is_reportable(
            &self.assertion.property,
            terminal.kind,
            self.eventually_triggered,
        ) {
            return None;
        }
        let minimum = self.proximity.as_ref()?;
        Some(HostAssertionProximity {
            assertion: self.assertion.id.clone(),
            quantifier: property_quantifier_kind(&self.assertion.property),
            distance: minimum.distance,
            at: minimum.at,
            event_log_offset: minimum.event_log_offset,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HostAssertionTerminal {
    kind: HostAssertionOutcomeKind,
    lifecycle: PropertyLifecycleState,
    at: VirtualTime,
    reason: String,
    evidence: Option<HostAssertionViolationEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HostAssertionProximityMinimum {
    distance: u128,
    at: VirtualTime,
    event_log_offset: EventLogOffset,
}

impl HostAssertionProximityMinimum {
    fn is_better_than(&self, current: &Self) -> bool {
        self.distance
            .cmp(&current.distance)
            .then_with(|| self.at.ticks.cmp(&current.at.ticks))
            .then_with(|| {
                self.event_log_offset
                    .events
                    .cmp(&current.event_log_offset.events)
            })
            .then_with(|| {
                self.event_log_offset
                    .bytes
                    .cmp(&current.event_log_offset.bytes)
            })
            .is_lt()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct EventuallyObligation {
    triggered_at: VirtualTime,
    deadline: VirtualTime,
}

pub(super) fn observe_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return None;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { predicate } => {
            if prefix.event_log_offset().events == 0 {
                return None;
            }
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            if host_condition_is_true(
                prefix,
                &predicate,
                oracle,
                once_latches,
                white_box_policies,
                code_points,
                mem_places,
                None,
            ) {
                None
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "always predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        &predicate,
                        false,
                        white_box_policies,
                    )),
                )
            }
        }
        Property::Sometimes { predicate } => {
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            let mut leaf_cache = HostConditionEvaluationCache::new();
            let satisfied = host_condition_is_true_with_cache(
                prefix,
                &predicate,
                oracle,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            );
            let distance = host_condition_distance_to_satisfaction(
                prefix,
                &predicate,
                oracle,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            );
            state.observe_proximity(prefix, distance);
            if satisfied {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "sometimes predicate became true",
                )
            } else {
                None
            }
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            let mut leaf_cache = HostConditionEvaluationCache::new();
            observe_eventually_assertion(
                state,
                prefix,
                oracle,
                &trigger,
                &property,
                deadline,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
            )
        }
        Property::AfterQuiescence { .. } => None,
        Property::Reachable {
            predicate,
            expectation,
        } => observe_reachability_assertion(
            state,
            prefix,
            oracle,
            once_latches,
            white_box_policies,
            code_points,
            mem_places,
            &predicate,
            expectation,
        ),
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn observe_eventually_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    trigger: &Condition,
    property: &Condition,
    deadline: VirtualTime,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    let at = prefix.point().at();
    state.evaluated = true;
    if state.lifecycle == PropertyLifecycleState::Declared {
        state.lifecycle = PropertyLifecycleState::Passing;
    }
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    }

    if !state.eventually_triggered
        && host_condition_is_true_with_cache(
            prefix,
            trigger,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        )
    {
        state.eventually_triggered = true;
        state.lifecycle = PropertyLifecycleState::Failing;
        state.pending_eventually.push(EventuallyObligation {
            triggered_at: at,
            deadline: eventually_deadline(at, deadline),
        });
    }

    let property_satisfied = !state.pending_eventually.is_empty()
        && host_condition_is_true_with_cache(
            prefix,
            property,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
    if !state.pending_eventually.is_empty() {
        let distance = host_condition_distance_to_satisfaction(
            prefix,
            property,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
        state.observe_proximity(prefix, distance);
    }
    if property_satisfied {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
        return state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            "eventually predicate became true",
        );
    } else if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)
    {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    }

    None
}

pub(super) fn observe_eventually_deadline_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() || state.pending_eventually.is_empty() {
        return None;
    }

    let Property::Eventually { property, .. } = state.assertion.property.clone() else {
        return None;
    };
    let at = prefix.point().at();
    state.lifecycle = PropertyLifecycleState::Failing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    if host_condition_is_true_with_cache(
        prefix,
        &property,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    ) {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
        return state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            "eventually predicate became true",
        );
    }
    let distance = host_condition_distance_to_satisfaction(
        prefix,
        &property,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    );
    state.observe_proximity(prefix, distance);

    let expired = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)?;
    state.terminal_with_evidence(
        HostAssertionOutcomeKind::Violated,
        expired.deadline,
        format!(
            "eventually deadline expired after trigger at {}",
            expired.triggered_at.ticks
        ),
        Some(condition_violation_evidence(
            prefix,
            &property,
            false,
            white_box_policies,
        )),
    )
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn observe_reachability_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    predicate: &Condition,
    expectation: ReachabilityExpectation,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    state.evaluated = true;
    state.lifecycle = PropertyLifecycleState::Passing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    let reached = host_condition_is_true_with_cache(
        prefix,
        predicate,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    );
    if matches!(expectation, ReachabilityExpectation::Reachable { .. }) {
        let distance = host_condition_distance_to_satisfaction(
            prefix,
            predicate,
            oracle,
            once_latches,
            &mut leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
        state.observe_proximity(prefix, distance);
    }
    match (expectation, reached) {
        (ReachabilityExpectation::Reachable { .. }, true) => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            prefix.point().at(),
            "reachable predicate became true",
        ),
        (ReachabilityExpectation::Unreachable, true) => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            prefix.point().at(),
            "unreachable predicate became true",
            Some(condition_violation_evidence(
                prefix,
                predicate,
                true,
                white_box_policies,
            )),
        ),
        (
            ReachabilityExpectation::Reachable { .. } | ReachabilityExpectation::Unreachable,
            false,
        ) => None,
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<&SchedulerQuiescence>,
) where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { .. } => {
            if state.evaluated {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "always predicate stayed true",
                );
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::NeverEvaluated,
                    at,
                    "always predicate scope was never evaluated",
                );
            }
        }
        Property::Sometimes { predicate } => {
            state.terminal_with_evidence(
                HostAssertionOutcomeKind::Violated,
                at,
                "sometimes predicate never became true",
                Some(condition_violation_evidence(
                    prefix,
                    &predicate,
                    false,
                    white_box_policies,
                )),
            );
        }
        Property::Eventually {
            trigger, property, ..
        } => {
            finalize_eventually_assertion(state, prefix, &trigger, &property, white_box_policies);
        }
        Property::AfterQuiescence { predicate } => {
            if host_condition_is_true(
                prefix,
                &predicate,
                oracle,
                once_latches,
                white_box_policies,
                code_points,
                mem_places,
                terminal_quiescence,
            ) {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "after-quiescence predicate was true",
                );
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "after-quiescence predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        &predicate,
                        false,
                        white_box_policies,
                    )),
                );
            }
        }
        Property::Reachable {
            predicate,
            expectation,
        } => match expectation {
            ReachabilityExpectation::Reachable { on_unreached } => match on_unreached {
                ReachableDisposition::Warn => {
                    state.terminal(
                        HostAssertionOutcomeKind::NeverReachedWarn,
                        at,
                        "reachable predicate was never reached",
                    );
                }
                ReachableDisposition::Fail => {
                    state.terminal_with_evidence(
                        HostAssertionOutcomeKind::NeverReachedFail,
                        at,
                        "reachable predicate was never reached",
                        Some(condition_violation_evidence(
                            prefix,
                            &predicate,
                            false,
                            white_box_policies,
                        )),
                    );
                }
            },
            ReachabilityExpectation::Unreachable => {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "unreachable predicate stayed false",
                );
            }
        },
    }
}

pub(super) fn finalize_eventually_assertion(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    trigger: &Condition,
    property: &Condition,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) {
    let at = prefix.point().at();
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    } else if !state.pending_eventually.is_empty() {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually run ended while triggered",
            Some(condition_violation_evidence(
                prefix,
                property,
                false,
                white_box_policies,
            )),
        );
    } else if let Some(satisfied_at) = state.eventually_satisfied_at {
        state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            satisfied_at,
            "eventually predicate became true",
        );
    } else if state.eventually_triggered {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually trigger fired without a satisfiable obligation",
            Some(condition_violation_evidence(
                prefix,
                trigger,
                true,
                white_box_policies,
            )),
        );
    } else {
        state.terminal(
            HostAssertionOutcomeKind::NeverTriggered,
            at,
            "eventually trigger never fired",
        );
    }
}

pub(super) fn property_quantifier_kind(property: &Property) -> AssertionQuantifierKind {
    match property {
        Property::Always { .. } => AssertionQuantifierKind::Always,
        Property::Sometimes { .. } => AssertionQuantifierKind::Sometimes,
        Property::Eventually { .. } => AssertionQuantifierKind::Eventually,
        Property::AfterQuiescence { .. } => AssertionQuantifierKind::AfterQuiescence,
        Property::Reachable { .. } => AssertionQuantifierKind::Reachable,
    }
}

pub(super) fn guest_assertion_quantifier_kind(kind: GuestAssertionKind) -> AssertionQuantifierKind {
    match kind {
        GuestAssertionKind::Always => AssertionQuantifierKind::GuestAlways,
        GuestAssertionKind::Sometimes => AssertionQuantifierKind::GuestSometimes,
        GuestAssertionKind::Reachable => AssertionQuantifierKind::GuestReachable,
        GuestAssertionKind::Unreachable => AssertionQuantifierKind::GuestUnreachable,
    }
}

pub(super) fn host_assertion_violations_from_outcomes(
    outcomes: &[HostAssertionOutcome],
    prefix: &ConditionEventLogPrefix,
    reproduction_artifact: ContentHash,
) -> Vec<HostAssertionViolation> {
    let mut violations = outcomes
        .iter()
        .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
        .map(|outcome| {
            let evidence = outcome
                .evidence
                .clone()
                .unwrap_or_else(|| outcome_point_evidence(prefix, outcome));
            HostAssertionViolation {
                assertion: outcome.assertion.clone(),
                message: outcome.message.clone(),
                quantifier: outcome.quantifier,
                event_kind: String::from("assertion_state_changed"),
                at_icount: evidence.at_icount,
                at_virtual_time: outcome.at,
                node: evidence.node.clone(),
                detail: violation_detail(outcome, &evidence),
                reproduction_artifact,
            }
        })
        .collect::<Vec<_>>();
    violations.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.quantifier.cmp(&right.quantifier))
            .then_with(|| left.event_kind.cmp(&right.event_kind))
            .then_with(|| left.at_virtual_time.cmp(&right.at_virtual_time))
            .then_with(|| left.node.cmp(&right.node))
            .then_with(|| left.detail.cmp(&right.detail))
            .then_with(|| left.reproduction_artifact.cmp(&right.reproduction_artifact))
    });
    violations
}

pub(super) fn assertion_replay_report_for_log_with_oracle<O>(
    artifact: ContentHash,
    properties: &Properties,
    world: &World,
    recorded_log: &RecordedAssertionLog,
    oracle: &mut O,
) -> Result<HostAssertionReport, OfflineAssertionCheckError>
where
    O: HostAssertionOracle + ?Sized,
{
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(world)
        .check_run_with_oracle(properties, recorded_log, oracle)?;
    Ok(host_assertion_report_with_reproduction_artifact(
        report, artifact,
    ))
}

pub(super) fn host_assertion_report_with_reproduction_artifact(
    mut report: HostAssertionReport,
    artifact: ContentHash,
) -> HostAssertionReport {
    for violation in &mut report.violations {
        violation.reproduction_artifact = artifact;
    }
    report
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn assertion_violation_replay_divergence(
    artifact: ContentHash,
    schedule: &Schedule,
    properties: &Properties,
    world: &World,
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
    expected_report: &HostAssertionReport,
    reproduced_report: &HostAssertionReport,
) -> AssertionViolationDivergence {
    let event_log_comparison =
        compare_event_log_determinism(expected_log.entries(), reproduced_log.entries());
    let event_logs_differ = !event_log_comparison.passes();
    let event_mismatch = event_log_comparison.mismatch().cloned();
    let first_different_causal_entry = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.first_location().cloned());
    let event_prefix = if event_logs_differ {
        first_different_assertion_replay_prefix(expected_log, reproduced_log)
    } else {
        CausalEventLogPrefixDivergence::terminal(expected_log, reproduced_log)
    };
    let bisection = AssertionViolationBisectionRequest {
        artifact,
        last_matching_event_prefix_len: event_prefix.expected_last_matching_event_prefix_len,
        first_different_event_prefix_len: event_prefix.expected_first_different_event_prefix_len,
        schedule_decision_count: schedule.len(),
        first_different_decision_prefix_len: first_different_decision_prefix_len(
            expected_log,
            reproduced_log,
        ),
        first_different_causal_entry: first_different_causal_entry.clone(),
        reason: "assertion violation did not reproduce bit-identically",
    };
    let expected_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        expected_log,
        event_prefix.expected_first_different_event_prefix_len,
    )
    .unwrap_or_else(|_| expected_report.clone());
    let reproduced_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        reproduced_log,
        event_prefix.reproduced_first_different_event_prefix_len,
    )
    .unwrap_or_else(|_| reproduced_report.clone());
    let (expected_violation, reproduced_violation) = first_differing_violation(
        expected_prefix_report.violations(),
        reproduced_prefix_report.violations(),
    )
    .unwrap_or_else(|| {
        first_differing_violation(expected_report.violations(), reproduced_report.violations())
            .unwrap_or((None, None))
    });
    let expected_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.expected_raw_index)
        .and_then(|raw_index| expected_log.entries().get(raw_index))
        .cloned();
    let reproduced_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.reproduced_raw_index)
        .and_then(|raw_index| reproduced_log.entries().get(raw_index))
        .cloned();
    let first_different_icount = first_different_causal_entry
        .as_ref()
        .map(|entry| entry.at.icount)
        .or_else(|| {
            expected_violation
                .as_ref()
                .and_then(|violation| violation.at_icount)
        })
        .or_else(|| {
            reproduced_violation
                .as_ref()
                .and_then(|violation| violation.at_icount)
        });

    AssertionViolationDivergence {
        artifact,
        first_different_prefix_len: event_prefix.expected_first_different_event_prefix_len,
        first_different_icount,
        first_different_causal_entry,
        expected_event,
        reproduced_event,
        expected_violation,
        reproduced_violation,
        bisection,
    }
}
