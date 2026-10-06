//! Assertion outcomes, replay, offline checking, evaluation, and lifecycle state.

use super::*;

mod admitted_pass;
mod checkpoint;
mod output_copy;
pub use checkpoint::{
    HostAssertionCheckpointBytes, HostAssertionCheckpointError, HostAssertionEvaluatorCheckpoint,
};
pub(super) mod owned_storage;
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
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionLifecycle {
    /// Assertion whose lifecycle state is reported.
    pub assertion: AssertionId,
    /// Current deterministic lifecycle state.
    pub state: PropertyLifecycleState,
    _decode_custody: crate::owned_decode::DecodeCustody,
}

/// Terminal result for one host-side assertion.
#[derive(Debug, PartialEq, Eq, Hash)]
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
    _decode_custody: crate::owned_decode::DecodeCustody,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(super) struct HostAssertionViolationEvidence {
    pub(super) at_icount: Option<Icount>,
    pub(super) node: Option<NodeId>,
    pub(super) observed: String,
}

/// Deterministic violation record derived from the retained event log.
#[derive(Debug, PartialEq, Eq, Hash)]
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
    _decode_custody: crate::owned_decode::DecodeCustody,
}

/// Owning violation fields whose allocations were admitted by their producer.
///
/// The fields move into a retained violation without copying. Producers must
/// reserve their original resource credits before constructing these values.
#[derive(Debug)]
pub struct HostAssertionViolationFields {
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

impl HostAssertionViolation {
    /// Retains original allocation custody for already admitted owning fields.
    ///
    /// # Errors
    /// Returns a pending original admission refusal without publishing a record.
    pub fn from_owned_fields(fields: HostAssertionViolationFields) -> Result<Self, EngineError> {
        owned_storage::check()?;
        let HostAssertionViolationFields {
            assertion,
            message,
            quantifier,
            event_kind,
            at_icount,
            at_virtual_time,
            node,
            detail,
            reproduction_artifact,
        } = fields;
        Ok(Self {
            assertion,
            message,
            quantifier,
            event_kind,
            at_icount,
            at_virtual_time,
            node,
            detail,
            reproduction_artifact,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }
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
#[derive(Debug, PartialEq, Eq)]
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
    _decode_custody: crate::owned_decode::DecodeCustody,
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
    pub expected: std::sync::Arc<HostAssertionReport>,
    /// Assertion report produced from the replayed deterministic log.
    pub reproduced: std::sync::Arc<HostAssertionReport>,
}

/// Localized mismatch between a recorded assertion violation and its replay.
#[derive(Debug, PartialEq, Eq)]
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
    pub expected_violation: Option<std::sync::Arc<HostAssertionViolation>>,
    /// Replayed violation at the first differing violation slot.
    pub reproduced_violation: Option<std::sync::Arc<HostAssertionViolation>>,
    /// Required `gate:divergence-bisect` handoff for this non-reproduction.
    pub bisection: AssertionViolationBisectionRequest,
    _decode_custody: crate::owned_decode::DecodeCustody,
}

/// Retains a typed reduction failure and its original diagnostic allocation credit.
#[derive(Debug, PartialEq, Eq)]
pub struct AssertionArtifactReplayFailure {
    source: EngineError,
    _decode_custody: crate::owned_decode::DecodeCustody,
}

impl fmt::Display for AssertionArtifactReplayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl Error for AssertionArtifactReplayFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Shares scalar replay evidence with its original diagnostic allocation credit.
#[derive(Debug, PartialEq, Eq)]
pub struct AssertionReplayEvidence {
    replay: ReproductionReplay,
    _decode_custody: crate::owned_decode::DecodeCustody,
}

impl std::ops::Deref for AssertionReplayEvidence {
    type Target = ReproductionReplay;

    fn deref(&self) -> &Self::Target {
        &self.replay
    }
}

/// Error returned when assertion violation reproduction fails.
#[derive(Debug, PartialEq, Eq)]
pub enum AssertionViolationReplayError {
    /// The artifact's embedded scenario and schedule could not be reduced.
    ArtifactReplay {
        /// Artifact whose reduction failed.
        artifact: ContentHash,
        /// Original typed reduction failure with retained diagnostic custody.
        source: std::sync::Arc<AssertionArtifactReplayFailure>,
    },
    /// Replay evidence was reduced from a different artifact tuple.
    ReplayArtifactMismatch {
        /// Artifact replay expected from the checked reproduction artifact.
        expected: std::sync::Arc<AssertionReplayEvidence>,
        /// Artifact replay supplied with the reproduced assertion log.
        reproduced: std::sync::Arc<AssertionReplayEvidence>,
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
        divergence: std::sync::Arc<AssertionViolationDivergence>,
    },
}

impl fmt::Display for AssertionViolationReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactReplay { source, .. } => {
                write!(
                    formatter,
                    "assertion violation artifact replay failed: {source}"
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
            Self::ArtifactReplay { source, .. } => Some(source.as_ref()),
            Self::ReplayArtifactMismatch { .. }
            | Self::MissingRecordedViolation { .. }
            | Self::Divergence { .. } => None,
        }
    }
}

/// Final host-side assertion report for one run.
#[derive(Debug, PartialEq, Eq)]
pub struct HostAssertionReport {
    outcomes: Vec<HostAssertionOutcome>,
    violations: Vec<HostAssertionViolation>,
    proximities: Vec<HostAssertionProximity>,
    verdict: AssertionRunVerdict,
    _decode_custody: crate::owned_decode::DecodeCustody,
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
#[derive(Debug, PartialEq, Eq, Hash)]
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
    _decode_custody: crate::owned_decode::DecodeCustody,
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
    // Reserve the fixed shared error envelope before reduction can exhaust its
    // account. Failure moves its typed cause; formatting creates no owned text.
    let diagnostic = crate::owned_decode::require_current_child_budget().map_err(|source| {
        AssertionViolationReplayError::RecordedAssertionCheck(OfflineAssertionCheckError::Engine(
            Box::new(owned_storage::admission(source)),
        ))
    })?;
    let replay = {
        let _scope = diagnostic.enter();
        owned_storage::reserve_arc::<AssertionArtifactReplayFailure>().map_err(|source| {
            AssertionViolationReplayError::RecordedAssertionCheck(
                OfflineAssertionCheckError::Engine(Box::new(source)),
            )
        })?;
        for _ in 0..2 {
            owned_storage::reserve_arc::<AssertionReplayEvidence>().map_err(|source| {
                AssertionViolationReplayError::RecordedAssertionCheck(
                    OfflineAssertionCheckError::Engine(Box::new(source)),
                )
            })?;
        }
        artifact
            .replay()
            .map_err(|source| AssertionViolationReplayError::ArtifactReplay {
                artifact: artifact_id,
                source: std::sync::Arc::new(AssertionArtifactReplayFailure {
                    source,
                    _decode_custody: diagnostic.custody(),
                }),
            })?
    };
    if reproduced.replay() != &replay {
        return Err(AssertionViolationReplayError::ReplayArtifactMismatch {
            expected: std::sync::Arc::new(AssertionReplayEvidence {
                replay,
                _decode_custody: diagnostic.custody(),
            }),
            reproduced: std::sync::Arc::new(AssertionReplayEvidence {
                replay: reproduced.replay().clone(),
                _decode_custody: diagnostic.custody(),
            }),
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
            divergence: std::sync::Arc::new(
                assertion_violation_replay_divergence(
                    artifact_id,
                    artifact.schedule(),
                    properties,
                    world,
                    recorded_log,
                    reproduced_log,
                    &expected,
                    &reproduced,
                )
                .map_err(AssertionViolationReplayError::ReproducedAssertionCheck)?,
            ),
        });
    }

    Ok(AssertionViolationReplayReport {
        artifact: artifact_id,
        replay,
        expected: expected.into_shared().map_err(|source| {
            AssertionViolationReplayError::RecordedAssertionCheck(
                OfflineAssertionCheckError::Engine(Box::new(source)),
            )
        })?,
        reproduced: reproduced.into_shared().map_err(|source| {
            AssertionViolationReplayError::ReproducedAssertionCheck(
                OfflineAssertionCheckError::Engine(Box::new(source)),
            )
        })?,
    })
}

/// Deterministic trace artifact intended for external formal tooling.
#[derive(Debug, PartialEq, Eq)]
pub struct ExternalFormalTraceExport {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    entry_count: u64,
    _decode_custody: crate::owned_decode::DecodeCustody,
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
    ) -> Result<ExternalFormalTraceExport, OfflineAssertionCheckError> {
        let child = crate::owned_decode::require_current_child_budget().map_err(|source| {
            OfflineAssertionCheckError::Engine(Box::new(owned_storage::admission(source)))
        })?;
        let _scope = child.enter();
        validate_recorded_event_log_entries(entries)?;
        let entry_count = u64::try_from(entries.len()).map_err(|_| {
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        let bytes = external_formal_trace_bytes(entries)
            .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
        let content_hash = ContentHash::from_bytes(&bytes);
        Ok(ExternalFormalTraceExport {
            bytes,
            content_hash,
            entry_count,
            _decode_custody: crate::owned_decode::require_current_custody().map_err(|source| {
                OfflineAssertionCheckError::Engine(Box::new(owned_storage::admission(source)))
            })?,
        })
    }
}

/// Offline assertion checker for a retained scheduler event log.
///
/// The checker never drives guests or scheduler state. It reconstructs checked
/// [`ConditionEventLogPrefix`] values from recorded [`SchedulerEventLogEntry`]
/// values and feeds them through [`HostAssertionEvaluator`], so amended property
/// sets can be graded against retained runs.
#[derive(Debug, Default)]
pub struct OfflineAssertionChecker {
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    guest_assertion_catalog: Vec<GuestAssertionMarker>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    _decode_custody: crate::owned_decode::DecodeCustody,
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
        let offsets = BTreeMap::new();
        let recorded = RecordedAssertionLogRef {
            entries: event_log,
            prefix_offsets: &offsets,
        };
        self.check_run_internal(properties, &recorded, &mut oracle, false)
    }

    /// Grades `properties` against a retained event log using `oracle`.
    ///
    /// The event log is read-only input. Evaluation observes every valid
    /// recorded prefix except the terminal prefix. An observable prefix that
    /// falls behind an earlier evaluation point is deferred only when a trailing
    /// scheduler evaluation boundary proves it belongs to an atomic batch. The
    /// checker then lets
    /// [`HostAssertionEvaluator::finalize_prefix`] observe that terminal prefix
    /// exactly once before applying end-of-run policies. Each observed point is
    /// reconstructed as a [`ConditionEventLogPrefix`] before evaluation. The
    /// supplied [`RecordedAssertionLog`] should carry exact event-log offsets for
    /// every prefix that can be observed by a named host predicate. A retained
    /// offset makes its prefix an authoritative published boundary even when it
    /// ends in an observable entry. Intermediate prefixes without retained
    /// offsets are skipped for custom-oracle checks; the terminal prefix must
    /// always have an exact offset.
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
        let _original = recorded_log.enter_original_decode();
        let recorded = RecordedAssertionLogRef {
            entries: recorded_log.entries(),
            prefix_offsets: recorded_log.prefix_offsets(),
        };
        self.check_run_internal(properties, &recorded, oracle, true)
    }

    fn check_run_internal<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLogRef<'_>,
        oracle: &mut O,
        require_recorded_offsets: bool,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let _original = self._decode_custody.enter();
        let mut evaluator = HostAssertionEvaluator::new(properties)
            .and_then(|evaluator| evaluator.with_white_box_policies(&self.white_box_policies))
            .and_then(|evaluator| {
                evaluator.with_guest_assertion_catalog(&self.guest_assertion_catalog)
            })
            .and_then(|evaluator| evaluator.with_resolved_code_points(&self.code_points))
            .and_then(|evaluator| evaluator.with_resolved_mem_places(&self.mem_places))
            .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
        if let Some(quiescence) = &self.terminal_quiescence {
            evaluator = evaluator
                .with_terminal_scheduler_quiescence(quiescence)
                .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
        }
        let event_log = recorded_log.entries();
        let terminal_prefix_len = event_log.len();
        let terminal_prefix = condition_prefix_from_recorded_log(
            recorded_log,
            terminal_prefix_len,
            require_recorded_offsets,
        )?;

        // With no host or declared guest states, only new enabled markers can
        // change intermediate outcomes. Reapplying retained marker payloads is
        // idempotent; guest marker states have no deadlines or lifecycle triggers.
        // Prove temporal eligibility first, retaining the original loop
        // for offsets, catalogs, and invalid or unsupported atomic histories.
        let observe_new_markers_only = !require_recorded_offsets
            && recorded_log.prefix_offsets.is_empty()
            && evaluator.states.is_empty()
            && evaluator.guest_marker_states.is_empty()
            && self.guest_assertion_catalog.is_empty()
            && intermediate_prefix_times_are_visible_or_atomic(event_log);
        let mut pending_enabled_marker = false;
        let mut latest_entry_ticks = 0;

        for index in 0..event_log.len() {
            let prefix_len = index + 1;
            if prefix_len == terminal_prefix_len {
                continue;
            }
            if observe_new_markers_only {
                let entry = &event_log[index];
                latest_entry_ticks = latest_entry_ticks.max(entry.at().ticks);
                pending_enabled_marker |= matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::GuestAssertionMarker { node, .. }
                    ) if self.white_box_policies.get(node) == Some(&WhiteBoxPolicy::Enabled)
                );
                // An atomic batch can hide a marker until a later visible entry.
                // Observe its first valid original prefix, even before the batch's
                // closing boundary, so violation coordinates remain unchanged.
                if !pending_enabled_marker
                    || latest_entry_ticks > EventEvaluationPoint::event_log_entry(entry).at().ticks
                {
                    continue;
                }
            }

            let prefix_len_u64 = u64::try_from(prefix_len)
                .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len })?;
            let recorded_offset = recorded_log.event_log_offset(prefix_len_u64);
            if require_recorded_offsets && recorded_offset.is_none() {
                continue;
            }
            let prefix = match condition_prefix_from_recorded_log(
                recorded_log,
                prefix_len,
                require_recorded_offsets,
            ) {
                Ok(prefix) => prefix,
                Err(OfflineAssertionCheckError::ConditionEvaluation(
                    ConditionEvaluationError::FutureEventLogEntry { .. },
                )) if entry_awaits_atomic_evaluation_boundary(event_log, index)
                    && (!require_recorded_offsets || recorded_offset.is_none()) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            evaluator
                .observe_prefix(&prefix, oracle)
                .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
            pending_enabled_marker = false;
        }

        evaluator
            .finalize_prefix(&terminal_prefix, oracle)
            .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))
    }
}

/// Proves that intermediate prefixes are visible or deferred by the original atomic rule.
///
/// A hidden observable prefix requires its first non-observable successor to be
/// an evaluation boundary. A hidden causal prefix permits causal and observable
/// successors until that boundary. Resolve these obligations at their first
/// incompatible payload, even if later entries are temporally visible. This
/// authenticates no new facts and visits each already authenticated entry once.
fn intermediate_prefix_times_are_visible_or_atomic(event_log: &[SchedulerEventLogEntry]) -> bool {
    let mut latest_entry_ticks = 0;
    let mut awaiting_observable_boundary = false;
    let mut awaiting_causal_boundary = false;

    for entry in event_log {
        match entry.payload() {
            SchedulerEventLogPayload::EvaluationBoundary(_) => {
                awaiting_observable_boundary = false;
                awaiting_causal_boundary = false;
            }
            SchedulerEventLogPayload::Observable(_) => {}
            SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Decision(_) => {
                if awaiting_observable_boundary {
                    return false;
                }
            }
            _ => {
                if awaiting_observable_boundary || awaiting_causal_boundary {
                    return false;
                }
            }
        }

        latest_entry_ticks = latest_entry_ticks.max(entry.at().ticks);
        if latest_entry_ticks > EventEvaluationPoint::event_log_entry(entry).at().ticks {
            match entry.payload() {
                SchedulerEventLogPayload::Observable(_) => awaiting_observable_boundary = true,
                SchedulerEventLogPayload::ResolvedHappening(_)
                | SchedulerEventLogPayload::Decision(_) => {
                    awaiting_causal_boundary = true;
                }
                _ => return false,
            }
        }
    }

    !awaiting_observable_boundary && !awaiting_causal_boundary
}

/// Reports whether an unpublished entry belongs to a completed atomic batch.
fn entry_awaits_atomic_evaluation_boundary(
    event_log: &[SchedulerEventLogEntry],
    index: usize,
) -> bool {
    let trailing_batch = &event_log[index + 1..];
    match event_log[index].payload() {
        SchedulerEventLogPayload::Observable(_) => trailing_batch
            .iter()
            .find(|entry| !matches!(entry.payload(), SchedulerEventLogPayload::Observable(_)))
            .is_some_and(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::EvaluationBoundary(_)
                )
            }),
        SchedulerEventLogPayload::ResolvedHappening(_) | SchedulerEventLogPayload::Decision(_) => {
            // Quantum EMIT publishes causal entries and their evaluation boundary
            // in one segment. A physical delivery can precede the prior point,
            // but no reader can observe its intermediate flat prefix.
            trailing_batch
                .iter()
                .find(|entry| {
                    !matches!(
                        entry.payload(),
                        SchedulerEventLogPayload::ResolvedHappening(_)
                            | SchedulerEventLogPayload::Decision(_)
                            | SchedulerEventLogPayload::Observable(_)
                    )
                })
                .is_some_and(|entry| {
                    matches!(
                        entry.payload(),
                        SchedulerEventLogPayload::EvaluationBoundary(_)
                    )
                })
        }
        _ => false,
    }
}

/// Borrows an existing log and its offsets without making an owning raw-log copy.
pub(super) struct RecordedAssertionLogRef<'a> {
    entries: &'a [SchedulerEventLogEntry],
    pub(super) prefix_offsets: &'a BTreeMap<u64, EventLogOffset>,
}

impl RecordedAssertionLogRef<'_> {
    pub(super) fn entries(&self) -> &[SchedulerEventLogEntry] {
        self.entries
    }
    pub(super) fn event_log_offset(&self, prefix_len: u64) -> Option<EventLogOffset> {
        self.prefix_offsets.get(&prefix_len).copied()
    }
}

mod recorded_log;
pub use recorded_log::RecordedAssertionLog;

/// Error returned by offline assertion checking.
#[derive(Debug, PartialEq, Eq)]
pub enum OfflineAssertionCheckError {
    /// An original resource or predicate evaluation refused the assertion pass.
    Engine(Box<EngineError>),
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
            Self::Engine(source) => fmt::Display::fmt(source, formatter),
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
            Self::Engine(source) => Some(source.as_ref()),
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
#[derive(Debug)]
pub struct HostAssertionEvaluator {
    states: Vec<HostAssertionState>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Condition>,
    white_box_policies: std::sync::Arc<BTreeMap<NodeId, WhiteBoxPolicy>>,
    code_points: std::sync::Arc<BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>>,
    mem_places: std::sync::Arc<BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>>,
    terminal_quiescence: Option<std::sync::Arc<SchedulerQuiescence>>,
    last_position: Option<HostAssertionPrefixPosition>,
    _definition_custody: crate::owned_decode::DecodeCustody,
    _mutable_custody: crate::owned_decode::DecodeCustody,
    evaluation_failure: Option<EngineError>,
}

// Deadline crossing needs only the prior point; checkpoint binding needs its
// offset. Retaining the full checked history here would copy it on every live
// observation even though evaluation uses the newly supplied prefix's facts.
#[derive(Clone, Copy, Debug)]
struct HostAssertionPrefixPosition {
    point: EventEvaluationPoint,
    offset: EventLogOffset,
}

impl HostAssertionPrefixPosition {
    fn from_prefix(prefix: &ConditionEventLogPrefix) -> Self {
        Self {
            point: prefix.point(),
            offset: prefix.event_log_offset(),
        }
    }
}

impl HostAssertionEvaluator {
    fn observe_prefix_inner<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Result<Vec<HostAssertionOutcome>, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut outcomes = self.observe_due_eventually_deadlines(prefix, oracle)?;
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            if let Some(outcome) = observe_host_assertion_state(
                state,
                AssertionObservationSources {
                    prefix,
                    white_box_policies: &self.white_box_policies,
                    code_points: &self.code_points,
                    mem_places: &self.mem_places,
                },
                oracle,
                once_latches,
                &mut self.evaluation_failure,
            )? {
                owned_storage::reserve_slot(&mut outcomes)?;
                outcomes.push(outcome);
            }
        }
        for outcome in observe_guest_marker_assertions(
            &mut self.guest_marker_states,
            prefix,
            &self.white_box_policies,
        )? {
            owned_storage::reserve_slot(&mut outcomes)?;
            outcomes.push(outcome);
        }
        self.last_position = Some(HostAssertionPrefixPosition::from_prefix(prefix));
        let _sort = crate::owned_decode::current_budget()
            .map(|budget| budget.reserve_scratch_array::<HostAssertionOutcome>(outcomes.len()))
            .transpose()
            .map_err(owned_storage::admission)?;
        sort_host_assertion_outcomes(&mut outcomes);
        Ok(outcomes)
    }

    /// Returns current lifecycle states in canonical assertion order.
    ///
    /// # Errors
    /// Returns the original resource refusal before publishing copied states.
    pub fn lifecycle_states(&self) -> Result<Vec<HostAssertionLifecycle>, EngineError> {
        let _original = self._definition_custody.enter();
        let child = crate::owned_decode::require_current_child_budget()
            .map_err(owned_storage::admission)?;
        let _scope = child.enter();
        let mut states = Vec::new();
        for state in &self.states {
            owned_storage::reserve_slot(&mut states)?;
            states.push(state.lifecycle()?);
        }
        for state in &self.guest_marker_states {
            owned_storage::reserve_slot(&mut states)?;
            states.push(state.lifecycle()?);
        }
        owned_storage::sort(&mut states, |left, right| {
            left.assertion
                .cmp(&right.assertion)
                .then_with(|| left.state.cmp(&right.state))
        })?;
        owned_storage::check()?;
        Ok(states)
    }

    fn observe_due_eventually_deadlines<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Result<Vec<HostAssertionOutcome>, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let Some(previous_position) = self.last_position else {
            return Ok(Vec::new());
        };
        let previous_at = previous_position.point.at().ticks;
        let next_at = prefix.point().at().ticks;
        if next_at <= previous_at {
            return Ok(Vec::new());
        }
        let mut deadlines = BTreeSet::new();
        for state in &self.states {
            if state.terminal.is_some() {
                continue;
            }
            for obligation in &state.pending_eventually {
                if obligation.deadline.ticks > previous_at
                    && obligation.deadline.ticks < next_at
                    && !deadlines.contains(&obligation.deadline)
                {
                    crate::owned_decode::charge_btree_set_entry::<VirtualTime>()
                        .map_err(owned_storage::admission)?;
                    deadlines.insert(obligation.deadline);
                }
            }
        }
        let mut outcomes = Vec::new();
        for deadline in deadlines {
            let Some(deadline_prefix) =
                prefix.observed_state_at(EventEvaluationPoint::assertion_deadline(deadline))
            else {
                continue;
            };
            let once_latches = &mut self.once_latches;
            for state in &mut self.states {
                if let Some(outcome) = observe_eventually_deadline_state(
                    state,
                    deadline_prefix,
                    AssertionObservationSources {
                        prefix,
                        white_box_policies: &self.white_box_policies,
                        code_points: &self.code_points,
                        mem_places: &self.mem_places,
                    },
                    oracle,
                    once_latches,
                    &mut self.evaluation_failure,
                )? {
                    owned_storage::reserve_slot(&mut outcomes)?;
                    outcomes.push(outcome);
                }
            }
        }
        Ok(outcomes)
    }

    fn finalize_prefix_inner<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.observe_prefix_inner(prefix, oracle)?;
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
                self.terminal_quiescence.as_deref(),
                &mut self.evaluation_failure,
            )?;
        }
        for state in &mut self.guest_marker_states {
            finalize_guest_marker_assertion_state(state, prefix.point().at())?;
        }
        let mut outcomes = Vec::new();
        for state in &self.states {
            if let Some(outcome) = state.outcome()? {
                owned_storage::reserve_slot(&mut outcomes)?;
                outcomes.push(outcome);
            }
        }
        for state in &self.guest_marker_states {
            if let Some(outcome) = state.outcome()? {
                owned_storage::reserve_slot(&mut outcomes)?;
                outcomes.push(outcome);
            }
        }
        let _sort_outcomes = crate::owned_decode::current_budget()
            .map(|budget| budget.reserve_scratch_array::<HostAssertionOutcome>(outcomes.len()))
            .transpose()
            .map_err(owned_storage::admission)?;
        sort_host_assertion_outcomes(&mut outcomes);
        let mut failures = Vec::new();
        for outcome in outcomes
            .iter()
            .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
        {
            owned_storage::reserve_slot(&mut failures)?;
            failures.push(AssertionVerdictFailure::new(
                owned_storage::copy_assertion_id(&outcome.assertion)?,
                outcome.at,
                owned_storage::copy_string(&outcome.reason)?,
            ));
        }
        let reproduction_artifact = assertion_reproduction_artifact_from_prefix(prefix)?;
        let violations =
            host_assertion_violations_from_outcomes(&outcomes, prefix, reproduction_artifact)?;
        let mut proximities = Vec::new();
        for state in &self.states {
            if let Some(proximity) = state.proximity()? {
                owned_storage::reserve_slot(&mut proximities)?;
                proximities.push(proximity);
            }
        }
        let _sort_proximities = crate::owned_decode::current_budget()
            .map(|budget| budget.reserve_scratch_array::<HostAssertionProximity>(proximities.len()))
            .transpose()
            .map_err(owned_storage::admission)?;
        sort_host_assertion_proximities(&mut proximities);
        let _sort_failures = crate::owned_decode::current_budget()
            .map(|budget| budget.reserve_scratch_array::<AssertionVerdictFailure>(failures.len()))
            .transpose()
            .map_err(owned_storage::admission)?;
        owned_storage::check()?;
        Ok(HostAssertionReport {
            outcomes,
            violations,
            proximities,
            verdict: AssertionRunVerdict::failed(failures),
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct HostAssertionState {
    assertion: std::sync::Arc<AssertionDef>,
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
    pub(super) fn new(marker: &GuestAssertionMarker) -> Result<Self, EngineError> {
        Ok(Self {
            id: owned_storage::copy_assertion_id(&marker.id)?,
            lifecycle: PropertyLifecycleState::Declared,
            message: owned_storage::copy_string(&marker.message)?,
            kind: marker.kind,
            must_hit: marker.must_hit,
            details: owned_storage::copy_json(&marker.details)?,
            location: owned_storage::copy_string(&marker.location)?,
            observed_true: false,
            last_icount: None,
            last_node: None,
            terminal: None,
            declared_message: None,
        })
    }

    fn lifecycle(&self) -> Result<HostAssertionLifecycle, EngineError> {
        Ok(HostAssertionLifecycle {
            assertion: owned_storage::copy_assertion_id(&self.id)?,
            state: self.lifecycle,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }

    fn outcome(&self) -> Result<Option<HostAssertionOutcome>, EngineError> {
        let Some(terminal) = &self.terminal else {
            return Ok(None);
        };
        Ok(Some(HostAssertionOutcome {
            assertion: owned_storage::copy_assertion_id(&self.id)?,
            quantifier: guest_assertion_quantifier_kind(self.kind),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: owned_storage::copy_string(&self.message)?,
            reason: owned_storage::copy_string(&terminal.reason)?,
            evidence: owned_storage::copy_json(&terminal.evidence)?,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        }))
    }

    pub(super) fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl fmt::Display,
    ) -> Result<Option<HostAssertionOutcome>, EngineError> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    pub(super) fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl fmt::Display,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Result<Option<HostAssertionOutcome>, EngineError> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        let reason =
            crate::owned_decode::display_string(&reason).map_err(owned_storage::admission)?;
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason,
            evidence,
        });
        self.outcome()
    }
}

impl HostAssertionState {
    pub(super) fn new(assertion: &AssertionDef) -> Result<Self, EngineError> {
        owned_storage::reserve_arc::<AssertionDef>()?;
        Ok(Self {
            assertion: std::sync::Arc::new(assertion.try_clone_admitted()?),
            lifecycle: PropertyLifecycleState::Declared,
            terminal: None,
            evaluated: false,
            eventually_triggered: false,
            eventually_satisfied_at: None,
            pending_eventually: Vec::new(),
            proximity: None,
        })
    }

    fn lifecycle(&self) -> Result<HostAssertionLifecycle, EngineError> {
        Ok(HostAssertionLifecycle {
            assertion: owned_storage::copy_assertion_id(&self.assertion.id)?,
            state: self.lifecycle,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }

    fn outcome(&self) -> Result<Option<HostAssertionOutcome>, EngineError> {
        let Some(terminal) = &self.terminal else {
            return Ok(None);
        };
        Ok(Some(HostAssertionOutcome {
            assertion: owned_storage::copy_assertion_id(&self.assertion.id)?,
            quantifier: property_quantifier_kind(&self.assertion.property),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: owned_storage::copy_string(&self.assertion.message)?,
            reason: owned_storage::copy_string(&terminal.reason)?,
            evidence: owned_storage::copy_json(&terminal.evidence)?,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        }))
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl fmt::Display,
    ) -> Result<Option<HostAssertionOutcome>, EngineError> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl fmt::Display,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Result<Option<HostAssertionOutcome>, EngineError> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        let reason =
            crate::owned_decode::display_string(&reason).map_err(owned_storage::admission)?;
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason,
            evidence,
        });
        self.outcome()
    }

    fn observe_proximity(&mut self, prefix: &ConditionEventLogPrefix, distance: u128) {
        self.observe_proximity_at(prefix.observed_state(), distance);
    }

    fn observe_proximity_at(&mut self, observed: ObservedState<'_>, distance: u128) {
        let candidate = HostAssertionProximityMinimum {
            distance,
            at: observed.point().at(),
            event_log_offset: observed.event_log_offset(),
        };
        let should_replace = match self.proximity.as_ref() {
            Some(current) => candidate.is_better_than(current),
            None => true,
        };
        if should_replace {
            self.proximity = Some(candidate);
        }
    }

    fn proximity(&self) -> Result<Option<HostAssertionProximity>, EngineError> {
        let Some(terminal) = self.terminal.as_ref() else {
            return Ok(None);
        };
        if !property_proximity_is_reportable(
            &self.assertion.property,
            terminal.kind,
            self.eventually_triggered,
        ) {
            return Ok(None);
        }
        let Some(minimum) = self.proximity.as_ref() else {
            return Ok(None);
        };
        Ok(Some(HostAssertionProximity {
            assertion: owned_storage::copy_assertion_id(&self.assertion.id)?,
            quantifier: property_quantifier_kind(&self.assertion.property),
            distance: minimum.distance,
            at: minimum.at,
            event_log_offset: minimum.event_log_offset,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        }))
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

/// Borrows immutable observation inputs while a pass stages mutable verdict state.
struct AssertionObservationSources<'a> {
    prefix: &'a ConditionEventLogPrefix,
    white_box_policies: &'a BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &'a BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &'a BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

fn observe_host_assertion_state<O>(
    state: &mut HostAssertionState,
    sources: AssertionObservationSources<'_>,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    failure: &mut Option<EngineError>,
) -> Result<Option<HostAssertionOutcome>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let AssertionObservationSources {
        prefix,
        white_box_policies,
        code_points,
        mem_places,
    } = sources;

    if state.terminal.is_some() {
        return Ok(None);
    }

    let at = prefix.point().at();
    let assertion = std::sync::Arc::clone(&state.assertion);
    let property = &assertion.property;
    match property {
        Property::Always { predicate } => {
            if prefix.event_log_offset().events == 0 {
                return Ok(None);
            }
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            if admitted_pass::condition_result(
                host_condition_is_true(
                    prefix,
                    predicate,
                    oracle,
                    once_latches,
                    white_box_policies,
                    code_points,
                    mem_places,
                    None,
                ),
                failure,
            ) {
                Ok(None)
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "always predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        predicate,
                        false,
                        white_box_policies,
                    )?),
                )
            }
        }
        Property::Sometimes { predicate } => {
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            let mut leaf_cache = HostConditionEvaluationCache::new();
            let satisfied = admitted_pass::condition_result(
                host_condition_is_true_with_cache(
                    prefix,
                    predicate,
                    oracle,
                    once_latches,
                    &mut leaf_cache,
                    white_box_policies,
                    code_points,
                    mem_places,
                    None,
                ),
                failure,
            );
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
            if satisfied {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "sometimes predicate became true",
                )
            } else {
                Ok(None)
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
                trigger,
                property,
                *deadline,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                failure,
            )
        }
        Property::AfterQuiescence { .. } => Ok(None),
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
            predicate,
            *expectation,
            failure,
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
    failure: &mut Option<EngineError>,
) -> Result<Option<HostAssertionOutcome>, EngineError>
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
            format_args!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )?),
        );
    }

    if !state.eventually_triggered
        && admitted_pass::condition_result(
            host_condition_is_true_with_cache(
                prefix,
                trigger,
                oracle,
                once_latches,
                leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            ),
            failure,
        )
    {
        state.eventually_triggered = true;
        state.lifecycle = PropertyLifecycleState::Failing;
        owned_storage::reserve_slot(&mut state.pending_eventually)?;
        state.pending_eventually.push(EventuallyObligation {
            triggered_at: at,
            deadline: eventually_deadline(at, deadline),
        });
    }

    let property_satisfied = !state.pending_eventually.is_empty()
        && admitted_pass::condition_result(
            host_condition_is_true_with_cache(
                prefix,
                property,
                oracle,
                once_latches,
                leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            ),
            failure,
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
            format_args!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )?),
        );
    }

    Ok(None)
}

fn observe_eventually_deadline_state<O>(
    state: &mut HostAssertionState,
    observed: ObservedState<'_>,
    sources: AssertionObservationSources<'_>,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    failure: &mut Option<EngineError>,
) -> Result<Option<HostAssertionOutcome>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let AssertionObservationSources {
        prefix,
        white_box_policies,
        code_points,
        mem_places,
    } = sources;

    if state.terminal.is_some() || state.pending_eventually.is_empty() {
        return Ok(None);
    }

    let assertion = std::sync::Arc::clone(&state.assertion);
    let Property::Eventually { property, .. } = &assertion.property else {
        return Ok(None);
    };
    let at = observed.point().at();
    state.lifecycle = PropertyLifecycleState::Failing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    if admitted_pass::condition_result(
        host_condition_is_true_with_cache(
            &observed,
            property,
            oracle,
            once_latches,
            &mut leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        ),
        failure,
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
        &observed,
        property,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    );
    state.observe_proximity_at(observed, distance);

    let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)
    else {
        return Ok(None);
    };
    state.terminal_with_evidence(
        HostAssertionOutcomeKind::Violated,
        expired.deadline,
        format_args!(
            "eventually deadline expired after trigger at {}",
            expired.triggered_at.ticks
        ),
        Some(condition_violation_evidence_at(
            prefix,
            observed.point(),
            property,
            false,
            white_box_policies,
        )?),
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
    failure: &mut Option<EngineError>,
) -> Result<Option<HostAssertionOutcome>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    state.evaluated = true;
    state.lifecycle = PropertyLifecycleState::Passing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    let reached = admitted_pass::condition_result(
        host_condition_is_true_with_cache(
            prefix,
            predicate,
            oracle,
            once_latches,
            &mut leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        ),
        failure,
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
            )?),
        ),
        (
            ReachabilityExpectation::Reachable { .. } | ReachabilityExpectation::Unreachable,
            false,
        ) => Ok(None),
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
    failure: &mut Option<EngineError>,
) -> Result<(), EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return Ok(());
    }

    let at = prefix.point().at();
    let assertion = std::sync::Arc::clone(&state.assertion);
    let property = &assertion.property;
    match property {
        Property::Always { .. } => {
            if state.evaluated {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "always predicate stayed true",
                )?;
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::NeverEvaluated,
                    at,
                    "always predicate scope was never evaluated",
                )?;
            }
        }
        Property::Sometimes { predicate } => {
            state.terminal_with_evidence(
                HostAssertionOutcomeKind::Violated,
                at,
                "sometimes predicate never became true",
                Some(condition_violation_evidence(
                    prefix,
                    predicate,
                    false,
                    white_box_policies,
                )?),
            )?;
        }
        Property::Eventually {
            trigger, property, ..
        } => {
            finalize_eventually_assertion(state, prefix, trigger, property, white_box_policies)?;
        }
        Property::AfterQuiescence { predicate } => {
            if admitted_pass::condition_result(
                host_condition_is_true(
                    prefix,
                    predicate,
                    oracle,
                    once_latches,
                    white_box_policies,
                    code_points,
                    mem_places,
                    terminal_quiescence,
                ),
                failure,
            ) {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "after-quiescence predicate was true",
                )?;
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "after-quiescence predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        predicate,
                        false,
                        white_box_policies,
                    )?),
                )?;
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
                    )?;
                }
                ReachableDisposition::Fail => {
                    state.terminal_with_evidence(
                        HostAssertionOutcomeKind::NeverReachedFail,
                        at,
                        "reachable predicate was never reached",
                        Some(condition_violation_evidence(
                            prefix,
                            predicate,
                            false,
                            white_box_policies,
                        )?),
                    )?;
                }
            },
            ReachabilityExpectation::Unreachable => {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "unreachable predicate stayed false",
                )?;
            }
        },
    }
    Ok(())
}

pub(super) fn finalize_eventually_assertion(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    trigger: &Condition,
    property: &Condition,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Result<(), EngineError> {
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
            format_args!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )?),
        )?;
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
            )?),
        )?;
    } else if let Some(satisfied_at) = state.eventually_satisfied_at {
        state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            satisfied_at,
            "eventually predicate became true",
        )?;
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
            )?),
        )?;
    } else {
        state.terminal(
            HostAssertionOutcomeKind::NeverTriggered,
            at,
            "eventually trigger never fired",
        )?;
    }
    Ok(())
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
) -> Result<Vec<HostAssertionViolation>, EngineError> {
    let mut violations = Vec::new();
    for outcome in outcomes
        .iter()
        .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
    {
        let fallback;
        let evidence = match &outcome.evidence {
            Some(evidence) => evidence,
            None => {
                fallback = outcome_point_evidence(prefix, outcome)?;
                &fallback
            }
        };
        owned_storage::reserve_slot(&mut violations)?;
        violations.push(HostAssertionViolation {
            assertion: owned_storage::copy_assertion_id(&outcome.assertion)?,
            message: owned_storage::copy_string(&outcome.message)?,
            quantifier: outcome.quantifier,
            event_kind: owned_storage::copy_string("assertion_state_changed")?,
            at_icount: evidence.at_icount,
            at_virtual_time: outcome.at,
            node: evidence
                .node
                .as_ref()
                .map(owned_storage::copy_node)
                .transpose()?,
            detail: violation_detail(outcome, evidence)?,
            reproduction_artifact,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        });
    }
    owned_storage::sort(&mut violations, |left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.quantifier.cmp(&right.quantifier))
            .then_with(|| left.event_kind.cmp(&right.event_kind))
            .then_with(|| left.at_virtual_time.cmp(&right.at_virtual_time))
            .then_with(|| left.node.cmp(&right.node))
            .then_with(|| left.detail.cmp(&right.detail))
            .then_with(|| left.reproduction_artifact.cmp(&right.reproduction_artifact))
    })?;
    Ok(violations)
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
    let checker = admitted_offline_checker(world)
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let report = checker.check_run_with_oracle(properties, recorded_log, oracle)?;
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
) -> Result<AssertionViolationDivergence, OfflineAssertionCheckError> {
    let _original = expected_report._decode_custody.enter();
    let child = crate::owned_decode::require_current_child_budget().map_err(|source| {
        OfflineAssertionCheckError::Engine(Box::new(owned_storage::admission(source)))
    })?;
    let _scope = child.enter();
    owned_storage::reserve_arc::<AssertionViolationDivergence>()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let event_mismatch = first_causal_mismatch(expected_log.entries(), reproduced_log.entries());
    let event_logs_differ = event_mismatch.is_some();
    let first_different_causal_entry = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.expected.or(mismatch.reproduced))
        .map(|(index, entry)| admitted_causal_point(index, entry))
        .transpose()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
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
        first_different_causal_entry: first_different_causal_entry
            .as_ref()
            .map(admitted_causal_point_copy)
            .transpose()
            .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?,
        reason: "assertion violation did not reproduce bit-identically",
        _decode_custody: child.custody(),
    };
    let expected_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        expected_log,
        event_prefix.expected_first_different_event_prefix_len,
    )?;
    let reproduced_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        reproduced_log,
        event_prefix.reproduced_first_different_event_prefix_len,
    )?;
    let (expected_violation, reproduced_violation) = first_differing_violation(
        expected_prefix_report.violations(),
        reproduced_prefix_report.violations(),
    )
    .or_else(|| {
        first_differing_violation(expected_report.violations(), reproduced_report.violations())
    })
    .unwrap_or((None, None));
    let expected_violation = expected_violation
        .map(|value| value.try_clone_admitted()?.into_shared())
        .transpose()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let reproduced_violation = reproduced_violation
        .map(|value| value.try_clone_admitted()?.into_shared())
        .transpose()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let expected_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.expected)
        .map(|(_, entry)| crate::scheduler::copy_entry_admitted(entry))
        .transpose()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let reproduced_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.reproduced)
        .map(|(_, entry)| crate::scheduler::copy_entry_admitted(entry))
        .transpose()
        .map_err(|source| OfflineAssertionCheckError::Engine(Box::new(source)))?;
    let first_different_icount = first_different_causal_entry
        .as_ref()
        .and_then(|entry| entry.at.retired)
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

    Ok(AssertionViolationDivergence {
        artifact,
        first_different_prefix_len: event_prefix.expected_first_different_event_prefix_len,
        first_different_icount,
        first_different_causal_entry,
        expected_event,
        reproduced_event,
        expected_violation,
        reproduced_violation,
        bisection,
        _decode_custody: child.custody(),
    })
}

fn admitted_causal_point(
    index: usize,
    entry: &SchedulerEventLogEntry,
) -> Result<EventLogCausalDivergencePoint, EngineError> {
    Ok(EventLogCausalDivergencePoint {
        raw_index: index,
        at: owned_storage::copy_json(&entry.time().stamp)?,
        source: owned_storage::copy_json(entry.source())?,
        kind: owned_storage::copy_string(entry.event_payload().kind())?,
    })
}

fn admitted_causal_point_copy(
    point: &EventLogCausalDivergencePoint,
) -> Result<EventLogCausalDivergencePoint, EngineError> {
    Ok(EventLogCausalDivergencePoint {
        raw_index: point.raw_index,
        at: owned_storage::copy_json(&point.at)?,
        source: owned_storage::copy_json(&point.source)?,
        kind: owned_storage::copy_string(&point.kind)?,
    })
}

/// Builds the replay checker's sole copied policy table under a retained bank.
pub(super) fn admitted_offline_checker(
    world: &World,
) -> Result<OfflineAssertionChecker, EngineError> {
    let child =
        crate::owned_decode::require_current_child_budget().map_err(owned_storage::admission)?;
    let _scope = child.enter();
    let mut white_box_policies = BTreeMap::new();
    for node in world.vm_nodes() {
        crate::owned_decode::charge_btree_entry::<NodeId, WhiteBoxPolicy>()
            .map_err(owned_storage::admission)?;
        white_box_policies.insert(owned_storage::copy_node(&node.id)?, node.white_box);
    }
    child.check().map_err(owned_storage::admission)?;
    Ok(OfflineAssertionChecker {
        white_box_policies,
        _decode_custody: child.custody(),
        ..OfflineAssertionChecker::new()
    })
}
