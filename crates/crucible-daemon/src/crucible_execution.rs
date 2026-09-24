//! Typed Crucible execution boundary for repository-resolved campaign attempts.
//!
//! This adapter consumes the language-neutral campaign contract, strictly
//! translates its nested artifacts through [`crate::crucible_artifact`], and
//! gives a concrete runner only authenticated Crucible values. Placement,
//! hot-fork, exact-restore, and thin-replay selection remain operational runner
//! policy and cannot alter the canonical attempt.

use crucible::{
    Configuration, Decision, NetworkFaultSelectable, ScenarioDefForm, SelectionDecision,
    SignalFaultCampaignReplayPlan, SignalFaultSelectable, try_step,
};
use crucible_campaign::{
    Attempt, AttemptContinuationInput, AttemptResourceLimits, AttemptStart, BranchPath,
    CampaignCodecError, CampaignExecutorStore, CampaignLineage, ChoiceSource,
    ConfigurationArtifactId, ExecutorRejection, ResolvedSelection, StopOutcome,
};
use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::executor_worker::ResolvedAttemptOrigins;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionInput,
    AttemptExecutionModel, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleArtifactError, ResolvedAttemptStart,
    decode_crucible_scenario_artifact,
};

mod decode_budget;

use decode_budget::{
    MAX_SELECTED_ORIGIN_DECODE_BYTES, SelectedOriginDecodeBudget,
    decode_selected_origin_configuration,
};

/// Authenticated Crucible discovery or typed branch start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrucibleResolvedAttemptStart {
    /// Continues one exact existing Crucible configuration.
    Discover {
        /// Decoded and identity-verified starting configuration.
        configuration: Configuration,
    },
    /// Applies one campaign selection at an exact parent configuration.
    Branch {
        /// Decoded and identity-verified parent configuration.
        parent: Configuration,
        /// Campaign selection, opportunity, and effective domain authenticated together.
        selection: Box<ResolvedSelection>,
        /// Exact canonical prefix after recording the branch selection and any
        /// producer-specific decision certified by the typed bridge.
        selected: Configuration,
    },
    /// Replays origin attempts from an authenticated base to a selected boundary.
    AfterAttempt {
        /// Oldest decoded discovery or branch start.
        base: Box<CrucibleResolvedAttemptStart>,
        /// Promoted signal-fault replay state at the decoded base start.
        base_signal_fault_replay: SignalFaultCampaignReplayPlan,
        /// Origin stops and their exact claimed reached configurations.
        origins: Box<CrucibleAttemptOrigins>,
    },
}

impl CrucibleResolvedAttemptStart {
    /// Returns the decoded configuration at the semantic execution boundary.
    #[must_use]
    pub fn configuration(&self) -> &Configuration {
        match self {
            Self::Discover { configuration } => configuration,
            Self::Branch { selected, .. } => selected,
            Self::AfterAttempt { origins, .. } => origins.last().reached(),
        }
    }

    /// Returns selected-continuation origin boundaries, when present.
    #[must_use]
    pub const fn origins(&self) -> Option<&CrucibleAttemptOrigins> {
        match self {
            Self::AfterAttempt { origins, .. } => Some(origins),
            Self::Discover { .. } | Self::Branch { .. } => None,
        }
    }

    /// Returns authenticated choice records for a retained branch decision.
    pub(crate) fn replay_selection(&self, decision_index: usize) -> Option<&ResolvedSelection> {
        match self {
            Self::Branch {
                parent, selection, ..
            } if parent.schedule.len() == decision_index => Some(selection),
            Self::AfterAttempt { base, .. } => base.replay_selection(decision_index),
            Self::Discover { .. } | Self::Branch { .. } => None,
        }
    }
}

/// One decoded origin attempt and its claimed post-stop replay boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptOrigin {
    attempt: Attempt,
    reached: Configuration,
    signal_fault_replay: SignalFaultCampaignReplayPlan,
    source_stop: Option<StopOutcome>,
}

/// Nonempty decoded ancestry for one selected continuation boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptOrigins {
    first: CrucibleAttemptOrigin,
    rest: Vec<CrucibleAttemptOrigin>,
}

impl CrucibleAttemptOrigins {
    /// Binds one required origin and any later descendants.
    #[must_use]
    pub fn new(first: CrucibleAttemptOrigin, rest: Vec<CrucibleAttemptOrigin>) -> Self {
        Self { first, rest }
    }

    /// Returns the final origin that establishes the semantic start boundary.
    #[must_use]
    pub fn last(&self) -> &CrucibleAttemptOrigin {
        self.rest.last().unwrap_or(&self.first)
    }

    /// Iterates from the authenticated base toward the selected boundary.
    pub fn iter(&self) -> impl Iterator<Item = &CrucibleAttemptOrigin> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }

    /// Returns the number of decoded origin attempts.
    #[must_use]
    pub fn len(&self) -> usize {
        1 + self.rest.len()
    }

    /// Returns false because a selected continuation always has an origin.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl CrucibleAttemptOrigin {
    /// Binds one immutable origin attempt to its authenticated reached boundary.
    #[must_use]
    pub fn new(
        attempt: Attempt,
        reached: Configuration,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
    ) -> Self {
        Self {
            attempt,
            reached,
            signal_fault_replay,
            source_stop: None,
        }
    }

    /// Binds a controlled origin to its authenticated final stop outcome.
    #[must_use]
    pub fn new_with_source_stop(
        attempt: Attempt,
        reached: Configuration,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
        source_stop: StopOutcome,
    ) -> Self {
        Self {
            attempt,
            reached,
            signal_fault_replay,
            source_stop: Some(source_stop),
        }
    }

    /// Returns the immutable origin attempt whose stop is replayed.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the exact configuration required at the origin stop.
    #[must_use]
    pub const fn reached(&self) -> &Configuration {
        &self.reached
    }

    /// Returns the promoted signal-fault replay plan for the reached boundary.
    #[must_use]
    pub const fn signal_fault_replay(&self) -> &SignalFaultCampaignReplayPlan {
        &self.signal_fault_replay
    }

    /// Returns the authenticated final stop outcome for controlled continuation.
    #[must_use]
    pub const fn source_stop(&self) -> Option<&StopOutcome> {
        self.source_stop.as_ref()
    }
}

/// Operational realization tier used for one local Crucible attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrucibleMaterializationTier {
    /// A QEMU-owned immutable fork template produced a copy-on-write child.
    HotFork,
    /// An authenticated exact checkpoint restored the requested configuration.
    ExactRestore,
    /// Deterministic replay reconstructed the requested configuration.
    ThinReplay,
}

const MAX_MATERIALIZATION_DIAGNOSTIC_EVENTS: usize = 256;
// This process-local limit is opt-in and never enters campaign facts or artifacts.
static MATERIALIZATION_DIAGNOSTIC_LIMIT: OnceLock<usize> = OnceLock::new();
static MATERIALIZATION_DIAGNOSTIC_COUNT: AtomicUsize = AtomicUsize::new(0);

fn record_materialization_diagnostic(
    input: &AttemptExecutionInput,
    materialization: CrucibleMaterializationTier,
) {
    let limit = *MATERIALIZATION_DIAGNOSTIC_LIMIT.get_or_init(|| {
        std::env::var("CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| (1..=MAX_MATERIALIZATION_DIAGNOSTIC_EVENTS).contains(value))
            .unwrap_or(0)
    });
    if limit == 0
        || MATERIALIZATION_DIAGNOSTIC_COUNT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < limit).then_some(count + 1)
            })
            .is_err()
    {
        return;
    }

    if let Ok(attempt) = input.attempt().id() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "CRUCIBLE-MATERIALIZATION-V1 attempt={attempt} tier={materialization:?}"
        );
    }
}

/// Complete runner result with non-canonical materialization telemetry.
#[derive(Debug)]
pub struct CrucibleExecutionOutcome {
    product: AttemptExecutionProduct,
    materialization: CrucibleMaterializationTier,
}

impl CrucibleExecutionOutcome {
    /// Binds one canonical candidate to the operational tier that realized it.
    #[must_use]
    pub const fn new(
        product: AttemptExecutionProduct,
        materialization: CrucibleMaterializationTier,
    ) -> Self {
        Self {
            product,
            materialization,
        }
    }

    /// Returns the modeled completion or exact-checkpoint product.
    #[must_use]
    pub const fn product(&self) -> &AttemptExecutionProduct {
        &self.product
    }

    /// Returns the operational realization tier.
    #[must_use]
    pub const fn materialization(&self) -> CrucibleMaterializationTier {
        self.materialization
    }

    /// Consumes the outcome into its result product and operational tier.
    #[must_use]
    pub fn into_parts(self) -> (AttemptExecutionProduct, CrucibleMaterializationTier) {
        (self.product, self.materialization)
    }
}

/// Fully decoded input supplied to a concrete Crucible execution runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptExecution {
    lineage: CampaignLineage,
    scenario: ScenarioDefForm,
    attempt: Attempt,
    path: BranchPath,
    start: CrucibleResolvedAttemptStart,
    signal_fault_replay: SignalFaultCampaignReplayPlan,
    replay_continuation_basis: Option<(
        Box<CrucibleAttemptOrigins>,
        Option<AttemptContinuationInput>,
    )>,
}

impl CrucibleAttemptExecution {
    /// Reconstructs a private fresh replay from a self-contained finding candidate.
    ///
    /// The candidate retains the complete scenario and schedule. Its attempt
    /// reuses the original semantic path, stop, and controlled continuation
    /// boundaries without carrying physical checkpoint authority.
    pub(crate) fn for_finding_replay(
        &self,
        scenario: ScenarioDefForm,
        configuration_artifact: ConfigurationArtifactId,
        configuration: Configuration,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
    ) -> Result<Self, CampaignCodecError> {
        if scenario.scenario_def().id() != configuration.def.id()
            || signal_fault_replay.target() != &configuration
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finding replay scenario or signal-fault plan differs from candidate",
            });
        }
        if let Some((origins, _terminal)) = self.continuation_replay_basis() {
            for origin in origins.iter() {
                let reached = origin.reached();
                let prefix = configuration
                    .schedule
                    .prefix(reached.schedule.len())
                    .map_err(|_| CampaignCodecError::InvalidValue {
                        reason: "finding replay candidate ends before a controlled source boundary",
                    })?;
                if prefix != reached.schedule {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "finding replay candidate diverges before a controlled source boundary",
                    });
                }
            }
        }
        let attempt = Attempt::new(
            AttemptStart::Discover {
                configuration: configuration_artifact,
            },
            self.path.id()?,
            self.attempt.stop().clone(),
        )?;
        let replay = Self {
            lineage: self.lineage.clone(),
            scenario,
            attempt,
            path: self.path.clone(),
            start: CrucibleResolvedAttemptStart::Discover { configuration },
            signal_fault_replay,
            replay_continuation_basis: None,
        };
        Ok(replay.with_replay_continuation_basis_from(self))
    }

    pub(crate) fn for_origin_replay(
        &self,
        attempt: Attempt,
        start: CrucibleResolvedAttemptStart,
        signal_fault_replay: SignalFaultCampaignReplayPlan,
    ) -> Self {
        Self {
            lineage: self.lineage.clone(),
            scenario: self.scenario.clone(),
            attempt,
            path: self.path.clone(),
            start,
            signal_fault_replay,
            replay_continuation_basis: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        lineage: CampaignLineage,
        scenario: ScenarioDefForm,
        attempt: Attempt,
        path: BranchPath,
        start: CrucibleResolvedAttemptStart,
    ) -> Self {
        let target = match &start {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration.clone(),
            CrucibleResolvedAttemptStart::Branch { selected, .. } => selected.clone(),
            CrucibleResolvedAttemptStart::AfterAttempt { origins, .. } => {
                origins.last().reached().clone()
            }
        };
        Self {
            lineage,
            scenario,
            attempt,
            path,
            start,
            signal_fault_replay: SignalFaultCampaignReplayPlan::empty(target),
            replay_continuation_basis: None,
        }
    }

    /// Preserves controlled source boundaries while a private replay uses a fresh start.
    pub(crate) fn with_replay_continuation_basis_from(mut self, source: &Self) -> Self {
        self.replay_continuation_basis = source
            .continuation_replay_basis()
            .map(|(origins, terminal)| (Box::new(origins.clone()), terminal.cloned()));
        self
    }

    pub(crate) fn continuation_replay_basis(
        &self,
    ) -> Option<(&CrucibleAttemptOrigins, Option<&AttemptContinuationInput>)> {
        match &self.start {
            CrucibleResolvedAttemptStart::AfterAttempt { origins, .. } => {
                Some((origins, self.attempt.continuation_input()))
            }
            CrucibleResolvedAttemptStart::Discover { .. }
            | CrucibleResolvedAttemptStart::Branch { .. } => self
                .replay_continuation_basis
                .as_ref()
                .map(|(origins, terminal)| (origins.as_ref(), terminal.as_ref())),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_signal_fault_replay(
        mut self,
        replay: SignalFaultCampaignReplayPlan,
    ) -> Self {
        let target = match &self.start {
            CrucibleResolvedAttemptStart::Discover { configuration } => configuration,
            CrucibleResolvedAttemptStart::Branch { selected, .. } => selected,
            CrucibleResolvedAttemptStart::AfterAttempt { origins, .. } => origins.last().reached(),
        };
        assert_eq!(replay.target(), target);
        self.signal_fault_replay = replay;
        self
    }

    /// Returns the exact campaign lineage admitted for this execution.
    #[must_use]
    pub const fn lineage(&self) -> &CampaignLineage {
        &self.lineage
    }

    /// Returns the decoded canonical Crucible scenario form.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioDefForm {
        &self.scenario
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    /// Returns the authenticated semantic edge path.
    #[must_use]
    pub const fn path(&self) -> &BranchPath {
        &self.path
    }

    /// Returns the decoded discovery or typed branch start.
    #[must_use]
    pub const fn start(&self) -> &CrucibleResolvedAttemptStart {
        &self.start
    }

    /// Returns the authenticated promoted signal-fault replay for this start.
    #[must_use]
    pub const fn signal_fault_replay(&self) -> &SignalFaultCampaignReplayPlan {
        &self.signal_fault_replay
    }
}

/// Strictly decodes one repository-resolved input into Crucible model values.
///
/// Selection-bearing schedules are resolved against the same narrow executor
/// store and branch selections are replay-validated before a concrete runner
/// receives them. The function performs no writes.
///
/// # Errors
///
/// Returns [`CrucibleArtifactError`] when the scenario or configuration bytes
/// are malformed, carry a different identity, contain unresolved selections,
/// or the branch selection does not replay at the authenticated parent.
pub fn decode_crucible_attempt_execution(
    store: &CampaignExecutorStore,
    input: &AttemptExecutionInput,
) -> Result<CrucibleAttemptExecution, CrucibleArtifactError> {
    decode_crucible_attempt_execution_with_origin_limit(
        store,
        input,
        MAX_SELECTED_ORIGIN_DECODE_BYTES,
    )
}

/// Strictly decodes one input within its selected-continuation memory ceiling.
///
/// # Errors
///
/// Returns the same errors as [`decode_crucible_attempt_execution`] and rejects
/// an ancestry whose encoded artifacts, decoded schedules, or replay-plan
/// prefixes exceed the admitted logical resident-byte budget.
pub fn decode_crucible_attempt_execution_with_resources(
    store: &CampaignExecutorStore,
    input: &AttemptExecutionInput,
    resources: AttemptResourceLimits,
) -> Result<CrucibleAttemptExecution, CrucibleArtifactError> {
    decode_crucible_attempt_execution_with_origin_limit(
        store,
        input,
        resources.maximum_resident_bytes(),
    )
}

fn decode_crucible_attempt_execution_with_origin_limit(
    store: &CampaignExecutorStore,
    input: &AttemptExecutionInput,
    maximum_resident_bytes: u64,
) -> Result<CrucibleAttemptExecution, CrucibleArtifactError> {
    let mut origin_budget = match input.start() {
        ResolvedAttemptStart::AfterAttempt { base, origins } => {
            Some(SelectedOriginDecodeBudget::new(
                input,
                base,
                origins,
                maximum_resident_bytes.min(MAX_SELECTED_ORIGIN_DECODE_BYTES),
            )?)
        }
        ResolvedAttemptStart::Discover { .. } | ResolvedAttemptStart::Branch { .. } => None,
    };
    let scenario = decode_crucible_scenario_artifact(input.scenario())?;
    let (start, signal_fault_replay) = match input.start() {
        start @ (ResolvedAttemptStart::Discover { .. } | ResolvedAttemptStart::Branch { .. }) => {
            decode_base_crucible_start(store, &scenario, input.scenario(), start, None)?
        }
        ResolvedAttemptStart::AfterAttempt { base, origins } => {
            let (base, base_signal_fault_replay) = decode_base_crucible_start(
                store,
                &scenario,
                input.scenario(),
                base,
                origin_budget.as_mut(),
            )?;
            let mut decoded_origins = Vec::with_capacity(origins.len());
            let mut terminal_replay = None;
            for origin in origins.iter() {
                let (reached, replay) = decode_selected_origin_configuration(
                    store,
                    &scenario,
                    input.scenario(),
                    origin.reached(),
                    origin_budget
                        .as_mut()
                        .ok_or(CrucibleArtifactError::ResourceLimit {
                            resource: "selected-origin-decoded-resident-bytes",
                        })?,
                )?;
                terminal_replay = Some(replay.clone());
                decoded_origins.push(CrucibleAttemptOrigin {
                    attempt: origin.attempt().clone(),
                    reached,
                    signal_fault_replay: replay,
                    source_stop: origin.source_stop().cloned(),
                });
            }
            let replay = terminal_replay.ok_or(CrucibleArtifactError::Campaign(
                crucible_campaign::CampaignCodecError::InvalidValue {
                    reason: "attempt continuation has no origin boundary",
                },
            ))?;
            let mut decoded_origins = decoded_origins.into_iter();
            let first = decoded_origins
                .next()
                .ok_or(CrucibleArtifactError::Campaign(
                    crucible_campaign::CampaignCodecError::InvalidValue {
                        reason: "attempt continuation has no origin boundary",
                    },
                ))?;
            (
                CrucibleResolvedAttemptStart::AfterAttempt {
                    base: Box::new(base),
                    base_signal_fault_replay,
                    origins: Box::new(CrucibleAttemptOrigins::new(
                        first,
                        decoded_origins.collect(),
                    )),
                },
                replay,
            )
        }
    };

    Ok(CrucibleAttemptExecution {
        lineage: input.lineage().clone(),
        scenario,
        attempt: input.attempt().clone(),
        path: input.path().clone(),
        start,
        signal_fault_replay,
        replay_continuation_basis: None,
    })
}

fn decode_base_crucible_start(
    store: &CampaignExecutorStore,
    scenario: &ScenarioDefForm,
    scenario_artifact: &crucible_campaign::ScenarioArtifact,
    start: &ResolvedAttemptStart,
    mut origin_budget: Option<&mut SelectedOriginDecodeBudget>,
) -> Result<(CrucibleResolvedAttemptStart, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    match start {
        ResolvedAttemptStart::Discover { configuration } => {
            let (configuration, replay) = match origin_budget.as_deref_mut() {
                Some(budget) => decode_selected_origin_configuration(
                    store,
                    scenario,
                    scenario_artifact,
                    configuration,
                    budget,
                )?,
                None => crate::decode_crucible_configuration_artifact_with_signal_fault_replay(
                    scenario,
                    scenario_artifact,
                    configuration,
                    store,
                )?,
            };
            Ok((
                CrucibleResolvedAttemptStart::Discover { configuration },
                replay,
            ))
        }
        ResolvedAttemptStart::Branch { parent, selection } => {
            let (parent, parent_replay) = match origin_budget.as_deref_mut() {
                Some(budget) => decode_selected_origin_configuration(
                    store,
                    scenario,
                    scenario_artifact,
                    parent,
                    budget,
                )?,
                None => crate::decode_crucible_configuration_artifact_with_signal_fault_replay(
                    scenario,
                    scenario_artifact,
                    parent,
                    store,
                )?,
            };
            let recorded = selection.selection();
            recorded
                .validate_branch_replay(
                    selection.opportunity(),
                    selection.domain(),
                    selection.opportunity().branch_point_id(
                        crucible_campaign::ConfigurationId::from_hash(
                            crucible_campaign::CampaignHash::from_bytes(parent.id().bytes),
                        ),
                    ),
                )
                .map_err(CrucibleArtifactError::Campaign)?;
            let signal_fault = match selection.opportunity().source() {
                ChoiceSource::Environment { adapter, .. }
                    if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER =>
                {
                    let selectable = SignalFaultSelectable::from_records(
                        &parent,
                        selection.declaration(),
                        selection.opportunity(),
                        selection.domain(),
                    )?;
                    Some(Box::new(selectable.resolve_branch(recorded)?))
                }
                _ => None,
            };
            let network_fault = match selection.opportunity().source() {
                ChoiceSource::Environment { adapter, .. }
                    if adapter == crucible::NETWORK_FAULT_CAMPAIGN_ADAPTER =>
                {
                    let selectable = NetworkFaultSelectable::from_records(
                        scenario,
                        &parent,
                        selection.declaration(),
                        selection.opportunity(),
                        selection.domain(),
                    )?;
                    Some(selectable.resolve_branch(recorded)?)
                }
                _ => None,
            };
            let selected = if let Some(branch) = signal_fault.as_ref() {
                branch.selected().clone()
            } else if let Some(branch) = network_fault.as_ref() {
                branch.selected().clone()
            } else {
                try_step(
                    &parent,
                    Decision::Selection(SelectionDecision::new(recorded)),
                )
                .map_err(|source| CrucibleArtifactError::InvalidPayload {
                    artifact: "selected branch configuration",
                    source: Box::new(source),
                })?
            };
            if let Some(budget) = origin_budget {
                budget.charge_branch_start(&selected)?;
            }
            let (_, mut branches, mut network_branches) = parent_replay.into_parts();
            if let Some(branch) = signal_fault.as_deref() {
                branches.push(branch.clone());
            }
            if let Some(branch) = network_fault {
                network_branches.push(branch);
            }
            let replay = SignalFaultCampaignReplayPlan::new(selected.clone(), branches)?
                .with_network_branches(network_branches)?;
            Ok((
                CrucibleResolvedAttemptStart::Branch {
                    parent,
                    selection: selection.clone(),
                    selected,
                },
                replay,
            ))
        }
        ResolvedAttemptStart::AfterAttempt { .. } => Err(CrucibleArtifactError::Campaign(
            crucible_campaign::CampaignCodecError::InvalidValue {
                reason: "attempt continuation has nested base",
            },
        )),
    }
}

/// Concrete Crucible lifecycle runner behind the campaign execution contract.
pub trait CrucibleExecutionRunner {
    /// Runner-specific process, materialization, or modeled-execution failure.
    type Error;

    /// Executes one strictly decoded Crucible attempt.
    ///
    /// Implementations choose hot fork, exact restore, or thin replay without
    /// changing the returned canonical candidate.
    ///
    /// # Errors
    ///
    /// Returns a classified runner error for retryable infrastructure failure,
    /// observed cancellation, or stable incompatibility.
    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>>;

    /// Reconciles operational authority retained after one successful result.
    ///
    /// Runners without a retained process or template use the default no-op.
    /// Hot-fork runners use this callback to bind source/target cleanup to the
    /// repository and supervisor's durable semantic disposition.
    /// Attempt-charged execution resources must already be stopped before the
    /// successful result is returned; this callback owns only cleanup whose
    /// release is ordered after semantic publication.
    /// A runner returning an execution error must finish or quarantine its
    /// operational owner before returning so a retry cannot overlap it.
    ///
    /// # Errors
    ///
    /// Returns a classified operational failure while retaining retry or
    /// quarantine authority according to the failure class.
    fn reconcile_execution(
        &mut self,
        _disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    /// Quarantines authority retained by a successful execution immediately.
    ///
    /// An outer runner must call this when its own result preparation fails
    /// after the wrapped execution succeeded, because no durable semantic
    /// disposition exists for ordinary reconciliation. The default is valid
    /// only for runners whose successful execution retains no operational
    /// authority. A wrapper over an arbitrary runner must forward this call.
    fn quarantine_pending_execution(&mut self) {}
}

/// Execution-model adapter that authenticates artifacts before invoking a runner.
pub struct CrucibleExecutionModel<R> {
    store: CampaignExecutorStore,
    runner: R,
    last_materialization: Option<CrucibleMaterializationTier>,
}

impl<R> CrucibleExecutionModel<R> {
    /// Creates the strict Crucible adapter over one concrete runner.
    #[must_use]
    pub const fn new(store: CampaignExecutorStore, runner: R) -> Self {
        Self {
            store,
            runner,
            last_materialization: None,
        }
    }

    /// Returns the concrete runner for diagnostics and configuration.
    #[must_use]
    pub const fn runner(&self) -> &R {
        &self.runner
    }

    /// Returns the last successful operational materialization tier.
    #[must_use]
    pub const fn last_materialization(&self) -> Option<CrucibleMaterializationTier> {
        self.last_materialization
    }
}

/// Failure from artifact authentication or the concrete Crucible runner.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleExecutionModelError<E> {
    /// Nested execution-model bytes failed strict authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The concrete Crucible runner failed after authentication.
    #[error("Crucible execution runner failed")]
    Runner(#[source] E),
}

impl<R> AttemptExecutionModel for CrucibleExecutionModel<R>
where
    R: CrucibleExecutionRunner,
{
    type Error = CrucibleExecutionModelError<R::Error>;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        self.last_materialization = None;
        let decoded = decode_crucible_attempt_execution_with_resources(
            &self.store,
            input,
            context.resources(),
        )
        .map_err(map_artifact_failure)?;
        let outcome = self
            .runner
            .execute(&decoded, context)
            .map_err(map_runner_failure)?;
        let (product, materialization) = outcome.into_parts();
        self.last_materialization = Some(materialization);
        record_materialization_diagnostic(input, materialization);
        Ok(product)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.runner
            .reconcile_execution(disposition)
            .map_err(map_runner_failure)
    }
}

fn map_artifact_failure<E>(
    error: CrucibleArtifactError,
) -> AttemptWorkerFailure<CrucibleExecutionModelError<E>> {
    let retryable = matches!(
        &error,
        CrucibleArtifactError::SelectionRepository(repository)
            if repository.executor_rejection() == ExecutorRejection::UnavailableInput
    );
    let error = CrucibleExecutionModelError::Artifact(error);
    if retryable {
        AttemptWorkerFailure::Retryable(error)
    } else {
        AttemptWorkerFailure::Terminal(error)
    }
}

fn map_runner_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<CrucibleExecutionModelError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(CrucibleExecutionModelError::Runner(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(CrucibleExecutionModelError::Runner(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(CrucibleExecutionModelError::Runner(error))
        }
    }
}
