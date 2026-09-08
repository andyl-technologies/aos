//! Typed Crucible execution boundary for repository-resolved campaign attempts.
//!
//! This adapter consumes the language-neutral campaign contract, strictly
//! translates its nested artifacts through [`crate::crucible_artifact`], and
//! gives a concrete runner only authenticated Crucible values. Placement,
//! hot-fork, exact-restore, and thin-replay selection remain operational runner
//! policy and cannot alter the canonical attempt.

use crucible::{
    Configuration, Decision, ScenarioDefForm, SelectionDecision, SignalFaultCampaignReplayPlan,
    SignalFaultSelectable, step,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, BranchPath, CampaignExecutorStore, CampaignLineage,
    ChoiceSource, ExecutorRejection, ResolvedSelection,
};

use crate::executor_worker::ResolvedAttemptOrigins;
use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionInput,
    AttemptExecutionModel, AttemptExecutionProduct, AttemptExecutionReconciliationStep,
    AttemptWorkerFailure, CrucibleArtifactError, ResolvedAttemptStart,
    decode_crucible_scenario_artifact,
};

const MAX_SELECTED_ORIGIN_DECODE_BYTES: u64 = 256 * 1024 * 1024;
const SCENARIO_DECODE_EXPANSION: u64 = 256;
const CONFIGURATION_DECODE_PREFLIGHT_EXPANSION: u64 = 256;
const SELECTION_RESOLUTION_EXPANSION: u64 = 256;
const RETAINED_ALLOCATION_OVERHEAD: u64 = 64;

struct SelectedOriginDecodeBudget {
    maximum: u64,
    retained: u64,
}

impl SelectedOriginDecodeBudget {
    fn new(
        input: &AttemptExecutionInput,
        base: &ResolvedAttemptStart,
        origins: &ResolvedAttemptOrigins,
        maximum: u64,
    ) -> Result<Self, CrucibleArtifactError> {
        let mut budget = Self {
            maximum,
            retained: 0,
        };
        let scenario_bytes = u64::try_from(input.scenario().payload().len())
            .map_err(|_| selected_origin_memory_error())?;
        let decoded_scenario_bytes = scenario_bytes
            .checked_mul(SCENARIO_DECODE_EXPANSION)
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(selected_origin_memory_error)?;
        budget.charge(
            scenario_bytes
                .checked_add(decoded_scenario_bytes)
                .ok_or_else(selected_origin_memory_error)?,
        )?;

        budget.charge_encoded_configuration(base_configuration_artifact(base)?)?;
        for origin in origins.iter() {
            budget.charge_encoded_configuration(origin.reached())?;
        }
        let origin_slots = u64::try_from(origins.len())
            .ok()
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<CrucibleAttemptOrigin>() as u64)
            })
            .ok_or_else(selected_origin_memory_error)?;
        budget.charge(origin_slots)?;
        Ok(budget)
    }

    fn charge_encoded_configuration(
        &mut self,
        artifact: &crucible_campaign::ConfigurationArtifact,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes =
            u64::try_from(artifact.payload().len()).map_err(|_| selected_origin_memory_error())?;
        self.charge(bytes)
    }

    fn preflight_configuration(
        &self,
        artifact: &crucible_campaign::ConfigurationArtifact,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes = u64::try_from(artifact.payload().len())
            .ok()
            .and_then(|bytes| bytes.checked_mul(CONFIGURATION_DECODE_PREFLIGHT_EXPANSION))
            .ok_or_else(selected_origin_memory_error)?;
        self.retained
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .map(|_| ())
            .ok_or_else(selected_origin_memory_error)
    }

    fn charge_decoded_configuration(
        &mut self,
        configuration: &Configuration,
        campaign_branch_count: usize,
    ) -> Result<(), CrucibleArtifactError> {
        let schedule_bytes = decoded_configuration_logical_bytes(configuration)
            .ok_or_else(selected_origin_memory_error)?;
        let branches =
            u64::try_from(campaign_branch_count).map_err(|_| selected_origin_memory_error())?;
        // Each retained branch owns parent, selected, and decision-prefix
        // schedules. The terminal replay plan and final pending observation can
        // each clone that graph, so charge their exact worst-case multiplicity.
        let configuration_instances = branches
            .checked_mul(12)
            .and_then(|instances| instances.checked_add(6))
            .ok_or_else(selected_origin_memory_error)?;
        let configuration_bytes = schedule_bytes
            .checked_mul(configuration_instances)
            .ok_or_else(selected_origin_memory_error)?;
        let branch_bytes = branches
            .checked_mul(4)
            .and_then(|count| {
                count.checked_mul(std::mem::size_of::<crucible::SignalFaultCampaignBranch>() as u64)
            })
            .ok_or_else(selected_origin_memory_error)?;
        self.charge(
            configuration_bytes
                .checked_add(branch_bytes)
                .ok_or_else(selected_origin_memory_error)?,
        )
    }

    fn selection_resolution_canonical_limit(&self) -> Result<usize, CrucibleArtifactError> {
        let remaining = self
            .maximum
            .checked_sub(self.retained)
            .ok_or_else(selected_origin_memory_error)?;
        usize::try_from(remaining / SELECTION_RESOLUTION_EXPANSION)
            .map_err(|_| selected_origin_memory_error())
    }

    fn charge_branch_start(
        &mut self,
        selected: &Configuration,
    ) -> Result<(), CrucibleArtifactError> {
        let bytes = decoded_configuration_logical_bytes(selected)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or_else(selected_origin_memory_error)?;
        self.charge(bytes)
    }

    fn charge(&mut self, bytes: u64) -> Result<(), CrucibleArtifactError> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .filter(|total| *total <= self.maximum)
            .ok_or_else(selected_origin_memory_error)?;
        Ok(())
    }
}

fn selected_origin_memory_error() -> CrucibleArtifactError {
    CrucibleArtifactError::ResourceLimit {
        resource: "selected-origin-decoded-resident-bytes",
    }
}

fn base_configuration_artifact(
    base: &ResolvedAttemptStart,
) -> Result<&crucible_campaign::ConfigurationArtifact, CrucibleArtifactError> {
    match base {
        ResolvedAttemptStart::Discover { configuration } => Ok(configuration),
        ResolvedAttemptStart::Branch { parent, .. } => Ok(parent),
        ResolvedAttemptStart::AfterAttempt { .. } => Err(CrucibleArtifactError::Campaign(
            crucible_campaign::CampaignCodecError::InvalidValue {
                reason: "attempt continuation has nested base",
            },
        )),
    }
}

fn decode_selected_origin_configuration(
    store: &CampaignExecutorStore,
    scenario: &ScenarioDefForm,
    scenario_artifact: &crucible_campaign::ScenarioArtifact,
    artifact: &crucible_campaign::ConfigurationArtifact,
    budget: &mut SelectedOriginDecodeBudget,
) -> Result<(Configuration, SignalFaultCampaignReplayPlan), CrucibleArtifactError> {
    budget.preflight_configuration(artifact)?;
    let mut guard = |configuration: &Configuration, campaign_branch_count: usize| {
        budget.charge_decoded_configuration(configuration, campaign_branch_count)?;
        budget.selection_resolution_canonical_limit()
    };
    crate::crucible_artifact::decode_crucible_configuration_artifact_with_signal_fault_replay_guarded(
        scenario,
        scenario_artifact,
        artifact,
        store,
        Some(&mut guard),
    )
}

fn decoded_configuration_logical_bytes(configuration: &Configuration) -> Option<u64> {
    let mut bytes = u64::try_from(std::mem::size_of::<Configuration>()).ok()?;
    bytes = bytes.checked_add(
        u64::try_from(configuration.schedule.len())
            .ok()?
            .checked_mul(std::mem::size_of::<Decision>() as u64)?,
    )?;
    bytes = bytes.checked_add(RETAINED_ALLOCATION_OVERHEAD)?;

    for decision in configuration.schedule.decisions() {
        let variable = match decision {
            Decision::DeliveryOrder(decision) => {
                let mut retained = u64::try_from(decision.order.len())
                    .ok()?
                    .checked_mul(std::mem::size_of::<crucible::EventKey>() as u64)?;
                retained = retained.checked_add(RETAINED_ALLOCATION_OVERHEAD)?;
                for event in &decision.order {
                    retained = retained
                        .checked_add(u64::try_from(event.consumer.node.name.len()).ok()?)?
                        .checked_add(u64::try_from(event.producer.node.name.len()).ok()?)?
                        .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?;
                }
                retained
            }
            Decision::RngDraw(decision) => {
                u64::try_from(decision.stream.domain.len() + decision.stream.name.len())
                    .ok()?
                    .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?
            }
            Decision::Override(decision) => {
                u64::try_from(decision.point.key.len() + decision.choice.name.len())
                    .ok()?
                    .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(2)?)?
            }
            Decision::Preemption(decision) => u64::try_from(decision.node.name.len())
                .ok()?
                .checked_add(RETAINED_ALLOCATION_OVERHEAD)?,
            Decision::AppRandom(decision) => u64::try_from(
                decision.node.name.len()
                    + decision.stream.domain.len()
                    + decision.stream.name.len(),
            )
            .ok()?
            .checked_add(RETAINED_ALLOCATION_OVERHEAD.checked_mul(3)?)?,
            Decision::Selection(decision) => u64::try_from(decision.canonical_bytes().len())
                .ok()?
                .checked_add(RETAINED_ALLOCATION_OVERHEAD)?,
        };
        bytes = bytes.checked_add(variable)?;
    }
    Some(bytes)
}

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
}

/// One decoded origin attempt and its claimed post-stop replay boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleAttemptOrigin {
    attempt: Attempt,
    reached: Configuration,
    signal_fault_replay: SignalFaultCampaignReplayPlan,
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
}

impl CrucibleAttemptExecution {
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

    /// Returns the exact compatibility lineage admitted for this execution.
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
            let selected = signal_fault.as_ref().map_or_else(
                || {
                    step(
                        &parent,
                        Decision::Selection(SelectionDecision::new(recorded)),
                    )
                },
                |branch| branch.selected().clone(),
            );
            if let Some(budget) = origin_budget {
                budget.charge_branch_start(&selected)?;
            }
            let (_, mut branches) = parent_replay.into_parts();
            if let Some(branch) = signal_fault.as_deref() {
                branches.push(branch.clone());
            }
            let replay = SignalFaultCampaignReplayPlan::new(selected.clone(), branches)?;
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

    /// Returns mutable access to the concrete runner.
    #[must_use]
    pub const fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    /// Returns the owned runner after worker shutdown.
    #[must_use]
    pub fn into_runner(self) -> R {
        self.runner
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crucible::{Decision, DeliveryOrderDecision, Schedule, VirtualTime};

    use super::*;

    #[test]
    fn many_branch_prefixes_exhaust_the_aggregate_decode_budget() {
        let fixture = crucible::happy_path_scenario().expect("scenario fixture");
        let decisions = (0..256).map(|tick| {
            Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: tick },
                order: Vec::new(),
            })
        });
        let configuration = Configuration {
            def: fixture.scenario.scenario_def(),
            schedule: Schedule::from_decisions(decisions),
        };
        let mut budget = SelectedOriginDecodeBudget {
            maximum: 256 * 1024,
            retained: 0,
        };

        let error = budget
            .charge_decoded_configuration(&configuration, 256)
            .expect_err("retained branch prefixes must be charged before plan construction");

        assert!(matches!(
            error,
            CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            }
        ));
        assert_eq!(budget.retained, 0);
    }

    #[test]
    fn repeated_origin_plans_exhaust_one_aggregate_budget() {
        let fixture = crucible::happy_path_scenario().expect("scenario fixture");
        let configuration = Configuration {
            def: fixture.scenario.scenario_def(),
            schedule: Schedule::from_decisions([Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            })]),
        };
        let one_plan_bytes = decoded_configuration_logical_bytes(&configuration)
            .expect("logical configuration bytes")
            .checked_mul(6)
            .expect("empty replay-plan multiplicity");
        let mut budget = SelectedOriginDecodeBudget {
            maximum: one_plan_bytes
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_sub(1))
                .expect("test budget"),
            retained: 0,
        };

        budget
            .charge_decoded_configuration(&configuration, 0)
            .expect("one origin fits independently");
        let retained_after_one = budget.retained;
        let error = budget
            .charge_decoded_configuration(&configuration, 0)
            .expect_err("repeated retained origins must share one aggregate budget");

        assert!(matches!(
            error,
            CrucibleArtifactError::ResourceLimit {
                resource: "selected-origin-decoded-resident-bytes"
            }
        ));
        assert_eq!(retained_after_one, one_plan_bytes);
        assert_eq!(budget.retained, retained_after_one);
    }
}
