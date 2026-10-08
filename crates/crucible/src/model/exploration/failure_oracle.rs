//! Retained-log predicate resolution and deterministic search failure oracles.

use super::*;

/// Host-resolution facts used by retained-log search assertion lowering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchRetainedLogPredicateResolutions {
    pub(in crate::model) code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    pub(in crate::model) mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl SearchRetainedLogPredicateResolutions {
    /// Builds an empty retained-log predicate resolution table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a host-resolved coverage code point for one node and predicate leaf.
    #[must_use]
    pub fn with_code_point(
        mut self,
        node: NodeId,
        point: CodePoint,
        resolved: ResolvedCodePoint,
    ) -> Self {
        self.code_points.insert((node, point), resolved);
        self
    }

    /// Adds a host-resolved memory place for one node and predicate leaf.
    #[must_use]
    pub fn with_mem_place(
        mut self,
        node: NodeId,
        place: MemPlace,
        resolved: ResolvedMemPlace,
    ) -> Self {
        self.mem_places.insert((node, place), resolved);
        self
    }

    pub(in crate::model) fn resolves_code_point(&self, node: &NodeId, point: &CodePoint) -> bool {
        self.code_points
            .contains_key(&(node.clone(), point.clone()))
    }

    pub(in crate::model) fn resolves_mem_place(&self, node: &NodeId, place: &MemPlace) -> bool {
        self.mem_places.contains_key(&(node.clone(), place.clone()))
    }
}

/// Configuration-bound retained-log assertion evidence for search lowering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRetainedLogAssertionEvidence {
    pub(in crate::model) recorded_log: RecordedAssertionLog,
    pub(in crate::model) resolutions: SearchRetainedLogPredicateResolutions,
    pub(in crate::model) terminal_quiescence: Option<SchedulerQuiescence>,
}

impl SearchRetainedLogAssertionEvidence {
    /// Builds retained-log evidence with no host-resolution table.
    #[must_use]
    pub fn new(recorded_log: RecordedAssertionLog) -> Self {
        Self {
            recorded_log,
            resolutions: SearchRetainedLogPredicateResolutions::new(),
            terminal_quiescence: None,
        }
    }

    /// Adds host-resolution facts to this retained-log evidence.
    #[must_use]
    pub fn with_resolutions(mut self, resolutions: SearchRetainedLogPredicateResolutions) -> Self {
        self.resolutions = resolutions;
        self
    }

    /// Adds terminal scheduler-quiescence evidence to this retained-log evidence.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Returns the retained assertion log bound to one configuration.
    #[must_use]
    pub const fn recorded_log(&self) -> &RecordedAssertionLog {
        &self.recorded_log
    }

    /// Returns host-resolution facts bound to the retained assertion log.
    #[must_use]
    pub const fn resolutions(&self) -> &SearchRetainedLogPredicateResolutions {
        &self.resolutions
    }

    /// Returns terminal scheduler-quiescence evidence, if supplied.
    #[must_use]
    pub const fn terminal_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.terminal_quiescence.as_ref()
    }
}

/// Read-only failure input for strategy-driven graph search.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SearchFailureOracle {
    pub(in crate::model) failures: BTreeMap<ContentHash, ContentHash>,
}

/// One prefix-safe assertion finding evaluated for an exact search configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchAssertionFinding {
    pub(in crate::model) fingerprint: ContentHash,
    pub(in crate::model) violation: HostAssertionViolation,
}

impl SearchAssertionFinding {
    /// Returns the canonical failure fingerprint used by search deduplication.
    #[must_use]
    pub const fn fingerprint(&self) -> ContentHash {
        self.fingerprint
    }

    /// Returns the assertion violation that produced the finding.
    #[must_use]
    pub const fn violation(&self) -> &HostAssertionViolation {
        &self.violation
    }

    /// Consumes the finding and returns its assertion violation.
    #[must_use]
    pub fn into_violation(self) -> HostAssertionViolation {
        self.violation
    }
}

impl SearchFailureOracle {
    /// Builds an oracle that reports no failures.
    #[must_use]
    pub fn none() -> Self {
        Self {
            failures: BTreeMap::new(),
        }
    }

    /// Adds a deterministic failure fingerprint for one configuration id.
    #[must_use]
    pub fn with_failure(mut self, configuration: ContentHash, fingerprint: ContentHash) -> Self {
        self.failures.insert(configuration, fingerprint);
        self
    }

    /// Evaluates schedule and named-truth assertions for one configuration.
    ///
    /// A finding is withheld when any named predicate needed by the selected
    /// assertion is absent from `named_predicates`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// and `configuration` disagree, or a scenario-serialization error when
    /// the schedule log cannot be reconstructed or checked.
    pub fn evaluate_configuration_with_named_predicates(
        scenario: &ScenarioDefForm,
        configuration: &Configuration,
        named_predicates: &SearchScheduleNamedPredicateTruths,
    ) -> Result<Option<SearchAssertionFinding>, EngineError> {
        validate_search_configuration_scenario(scenario, configuration)?;
        let mut oracle = SearchScheduleNamedPredicateHostOracle::new(named_predicates);
        oracle.clear_missing_truths();
        let finding = search_assertion_finding(
            scenario,
            configuration,
            &mut oracle,
            SearchAssertionPredicateScope::ScheduleAndNamedTruths,
        )?;
        if oracle.has_missing_truths() {
            return Ok(None);
        }
        Ok(finding)
    }

    /// Evaluates prefix-safe assertions from retained configuration evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// and `configuration` disagree, or a scenario-serialization error when
    /// retained evidence cannot be checked.
    pub fn evaluate_configuration_with_retained_log_evidence(
        scenario: &ScenarioDefForm,
        configuration: &Configuration,
        evidence: &SearchRetainedLogAssertionEvidence,
    ) -> Result<Option<SearchAssertionFinding>, EngineError> {
        validate_search_configuration_scenario(scenario, configuration)?;
        search_assertion_finding_from_retained_log(
            scenario,
            configuration,
            evidence.recorded_log(),
            evidence.resolutions(),
            evidence.terminal_quiescence(),
        )
    }

    /// Builds an oracle from prefix-safe assertion violations found by a search run.
    ///
    /// This constructor grades each reached configuration schedule against
    /// `scenario` with the offline assertion checker and lowers only assertion
    /// outcomes that are safe to treat as prefix failures from schedule-only
    /// evidence: host `always` and unreachable violations whose predicates are
    /// composed only from fault-active facts and boolean combinators. It
    /// deliberately does not lower absence-based existential/liveness failures,
    /// time/timer/quiescence predicates, observable-event predicates, guest
    /// marker predicates, or named host predicates, because this path does not
    /// replay a backend-retained event log or a harness oracle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when the retained assertion log
    /// cannot be reconstructed or checked.
    pub fn from_search_assertion_violations(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
    ) -> Result<Self, EngineError> {
        let mut oracle = BlackBoxHostOracle;
        Self::from_search_assertion_violations_internal(
            scenario,
            root,
            run,
            &mut oracle,
            SearchAssertionPredicateScope::ScheduleOnly,
        )
    }

    /// Builds an oracle from prefix-safe assertion violations using named truths.
    ///
    /// This opt-in path admits named assertion predicates only through a
    /// data-only [`SearchScheduleNamedPredicateTruths`] table keyed by the named
    /// leaf and schedule-derived active signal bindings. The retained log is still
    /// reconstructed from search schedules, so this constructor lowers only
    /// prefix-safe safety/unreachability outcomes whose predicates are composed
    /// from binding-active schedule facts, declared named truths, and boolean
    /// combinators.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when the retained assertion log
    /// cannot be reconstructed or checked.
    pub fn from_search_assertion_violations_with_named_predicates(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        named_predicates: &SearchScheduleNamedPredicateTruths,
    ) -> Result<Self, EngineError> {
        let mut oracle = SearchScheduleNamedPredicateHostOracle::new(named_predicates);
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            if let Some(fingerprint) = search_assertion_failure_fingerprint_with_named_truths(
                scenario,
                &configuration,
                &mut oracle,
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    /// Builds an oracle from assertion violations backed by retained logs.
    ///
    /// `retained_log_for` is consulted for every configuration reached by
    /// `run`. Configurations without a retained log are skipped. This is a
    /// trusted internal boundary: the provider must return the retained log that
    /// belongs to the supplied configuration. Supplied logs are graded with the
    /// offline black-box assertion checker, so this constructor can lower
    /// prefix-safe safety/unreachability violations over retained-log predicates
    /// whose evidence is carried by scheduler event-log entries: time/timer
    /// facts, observable network/console/I/O/node/assertion-state facts, raw
    /// guest-address coverage, physical-address/register memory samples, guest
    /// markers, and schedule fault-active facts. Named host predicates still
    /// require a separate explicit oracle path; host-resolution-dependent
    /// coverage or memory predicates require
    /// [`Self::from_search_assertion_violations_with_retained_logs_and_resolutions`].
    /// For backend integrations that have both logs and host-resolution facts,
    /// prefer
    /// [`Self::from_search_assertion_violations_with_retained_log_evidence`]
    /// so each reached configuration carries its own evidence bundle.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_logs<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        mut retained_log_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<RecordedAssertionLog>,
    {
        Self::from_search_assertion_violations_with_retained_log_evidence(
            scenario,
            root,
            run,
            move |configuration| {
                retained_log_for(configuration).map(SearchRetainedLogAssertionEvidence::new)
            },
        )
    }

    /// Builds a retained-log assertion oracle using explicit host resolutions.
    ///
    /// This extends [`Self::from_search_assertion_violations_with_retained_logs`]
    /// by admitting symbolic coverage and virtual/symbolic memory predicates
    /// only when `resolutions` contains an exact leaf resolution for the
    /// predicate's node and host-side reference. Use
    /// [`Self::from_search_assertion_violations_with_retained_log_evidence`]
    /// when those resolutions differ by reached configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_logs_and_resolutions<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        resolutions: &SearchRetainedLogPredicateResolutions,
        mut retained_log_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<RecordedAssertionLog>,
    {
        let resolutions = resolutions.clone();
        Self::from_search_assertion_violations_with_retained_log_evidence(
            scenario,
            root,
            run,
            move |configuration| {
                retained_log_for(configuration).map(|recorded_log| {
                    SearchRetainedLogAssertionEvidence::new(recorded_log)
                        .with_resolutions(resolutions.clone())
                })
            },
        )
    }

    /// Builds a retained-log assertion oracle from configuration-bound evidence.
    ///
    /// `evidence_for` is consulted for every configuration reached by `run`.
    /// Configurations without evidence are skipped. This is the backend-facing
    /// retained-log boundary: every returned [`SearchRetainedLogAssertionEvidence`]
    /// must contain the exact retained log for that configuration and any
    /// host-resolution facts that were valid when the log was captured.
    /// Terminal scheduler-quiescence evidence is used for retained
    /// `after-quiescence` assertions, terminal retained `sometimes`/
    /// `eventually` violations, terminal retained expected-reachable failures,
    /// and guest assertion marker outcomes only when their retained-log evidence
    /// is complete enough for the marker flavor; it does not make quiescence
    /// predicates admissible for prefix, reachability, or terminal
    /// `sometimes`/`eventually` properties.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ReproductionScenarioMismatch`] when `scenario`
    /// does not match `root` or a reached configuration. Returns
    /// [`EngineError::ScenarioSerialization`] when a supplied retained assertion
    /// log cannot be checked.
    pub fn from_search_assertion_violations_with_retained_log_evidence<F>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        mut evidence_for: F,
    ) -> Result<Self, EngineError>
    where
        F: FnMut(&Configuration) -> Option<SearchRetainedLogAssertionEvidence>,
    {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            let Some(evidence) = evidence_for(&configuration) else {
                continue;
            };
            if let Some(fingerprint) = search_assertion_failure_fingerprint_from_retained_log(
                scenario,
                &configuration,
                evidence.recorded_log(),
                evidence.resolutions(),
                evidence.terminal_quiescence(),
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    fn from_search_assertion_violations_internal<O>(
        scenario: &ScenarioDefForm,
        root: &Configuration,
        run: &TemporalGraphSearchRun,
        oracle: &mut O,
        predicate_scope: SearchAssertionPredicateScope,
    ) -> Result<Self, EngineError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let scenario_def = scenario.scenario_def();
        if scenario_def.id != root.def.id {
            return Err(EngineError::ReproductionScenarioMismatch {
                expected: root.def.id,
                actual: scenario_def.id,
            });
        }

        let mut failure_oracle = Self::none();
        for configuration in search_run_reached_configurations(root, run) {
            if configuration.def.id != scenario_def.id {
                return Err(EngineError::ReproductionScenarioMismatch {
                    expected: scenario_def.id,
                    actual: configuration.def.id,
                });
            }
            if let Some(fingerprint) = search_assertion_failure_fingerprint(
                scenario,
                &configuration,
                oracle,
                predicate_scope,
            )? {
                failure_oracle = failure_oracle.with_failure(configuration.id(), fingerprint);
            }
        }
        Ok(failure_oracle)
    }

    /// Returns the configured failure fingerprint for `configuration`, if any.
    #[must_use]
    pub fn failure_for(&self, configuration: ContentHash) -> Option<ContentHash> {
        self.failures.get(&configuration).copied()
    }

    /// Returns whether this oracle contains no failure entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}
