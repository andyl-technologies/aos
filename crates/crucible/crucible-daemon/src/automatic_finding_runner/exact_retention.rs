//! Exact-checkpoint retention selection for automatic findings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use crucible_campaign::{
    AttemptRetentionPolicyBasis, AuthenticatedFindingExactCheckpoint, CampaignCodecError,
    CampaignExecutorStore, CampaignHash, CampaignName, CampaignRepositoryError,
    CampaignRepositoryGcExclusionGuard, ConfigurationId, ExactCheckpointId,
    ExecutorExactCatalogAllocationCustody, ExecutorExactRetentionCatalog,
    ExecutorExactRetentionCatalogCustody, ExecutorExactRetentionOwnerLease,
    FindingAssertionFailureBoundary, FindingExactCheckpointAuthenticationError,
    FindingExactCheckpointAuthenticator, FindingExactPins, FindingExactRetention,
    FindingExactRetentionCandidate, FindingExactRetentionDisposition,
    FindingExactRetentionEvidence, FindingExactRetentionIncomplete, PropertyVerdict,
    ScenarioArtifactId, ScenarioDefId, StopOutcome,
};
#[cfg(test)]
use crucible_engine::{AssertionPhase, SchedulerEventLogEntry};

use crate::crucible_artifact::{PreparedFindingExactRetention, PreparedSemanticAttemptResult};
use crate::crucible_measurement::CrucibleMeasurementStopEvidence;
use crate::crucible_measurement::verified_assertion_transition;
use crate::exact_checkpoint_store::ExactFindingCheckpointAuthenticator;
use crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot;
use crate::{
    AttemptExecutionContext, CapturedAttemptCheckpoint, CrucibleAttemptExecution,
    ExactCheckpointStore, ExecutionCancellation,
};

pub(crate) const MAX_FINDING_EXACT_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAMPAIGN_RUN_EXACT_CHECKPOINTS: usize = 65_536;

pub(crate) fn synchronous_exact_retention_owner(
    campaign: &CampaignName,
    writer_namespace: Option<CampaignHash>,
) -> CampaignHash {
    let mut material = Vec::with_capacity(32 + campaign.as_str().len());
    if let Some(writer_namespace) = writer_namespace {
        material.extend_from_slice(&writer_namespace.as_bytes());
    }
    material.extend_from_slice(campaign.as_str().as_bytes());
    CampaignHash::derive(
        "crucible.executor.synchronous-exact-retention-owner.v2",
        &material,
    )
}

struct FindingExactBoundary {
    failure_events: u64,
    measurement_events: Option<u64>,
    assertion: Option<(
        FindingAssertionFailureBoundary,
        crate::CrucibleMeasurementEvidenceBytes,
    )>,
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum FindingExactCandidateInventoryError {
    #[error("exact finding candidate inventory is unavailable")]
    Unavailable,
    #[error("exact finding candidate inventory exceeds its bounded limit")]
    LimitExceeded,
}

pub(crate) struct FindingExactCandidateInventory {
    roots: Vec<ExactCheckpointId>,
    // Declared after the vector so its allocation credit closes last.
    _scratch: Option<crucible_store::owned_decode::DecodeScratch>,
}

impl std::fmt::Debug for FindingExactCandidateInventory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingExactCandidateInventory")
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

impl PartialEq for FindingExactCandidateInventory {
    fn eq(&self, other: &Self) -> bool {
        self.roots == other.roots
    }
}

impl Eq for FindingExactCandidateInventory {}

#[cfg(test)]
impl PartialEq<Vec<ExactCheckpointId>> for FindingExactCandidateInventory {
    fn eq(&self, other: &Vec<ExactCheckpointId>) -> bool {
        self.roots == *other
    }
}

impl FindingExactCandidateInventory {
    pub(crate) fn admitted(
        roots: Vec<ExactCheckpointId>,
        scratch: crucible_store::owned_decode::DecodeScratch,
    ) -> Self {
        Self {
            roots,
            _scratch: Some(scratch),
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            roots: Vec::new(),
            _scratch: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(roots: Vec<ExactCheckpointId>) -> Self {
        Self {
            roots,
            _scratch: None,
        }
    }

    pub(crate) fn roots(&self) -> &[ExactCheckpointId] {
        &self.roots
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    fn len(&self) -> usize {
        self.roots.len()
    }
}

pub(crate) trait FindingExactRetentionSource: FindingExactCheckpointAuthenticator {
    fn candidate_checkpoints(
        &self,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError>;

    /// Authenticates the admitted attempt's exact-findings policy before capture.
    fn exact_findings_enabled(
        &self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> bool;

    /// Publishes and catalogs a failed observation's exact terminal root.
    fn retain_terminal_checkpoint(
        &self,
        capture: &CapturedAttemptCheckpoint,
        context: &AttemptExecutionContext,
        identity: FindingTerminalCheckpointIdentity,
    ) -> Result<(), FindingExactCandidateInventoryError>;

    /// Installs catalog and selected-result ownership before execution releases GC exclusion.
    fn retain_execution_result(
        &self,
        _input: &CrucibleAttemptExecution,
        _context: &AttemptExecutionContext,
        _result: &PreparedSemanticAttemptResult,
        _gc_exclusion: &CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        Ok(())
    }

    /// Persists catalog ownership when execution fails after publishing a candidate.
    fn retain_execution_catalog(
        &self,
        _gc_exclusion: &CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        Ok(())
    }

    /// Stops advertising candidates whose durable handoff failed.
    fn abandon_unretained_candidates(&self) {}
}

/// Semantic basis and completed event count required of an auxiliary root.
#[derive(Clone, Copy)]
pub(crate) struct FindingTerminalCheckpointIdentity {
    pub(crate) scenario: ScenarioDefId,
    pub(crate) scenario_artifact: ScenarioArtifactId,
    pub(crate) configuration: ConfigurationId,
    pub(crate) event_count: u64,
}

pub(crate) fn exact_findings_enabled(
    store: &CampaignExecutorStore,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
) -> bool {
    let crucible_campaign::AttemptRetentionPolicyDisposition::Required(basis) =
        context.retention_policy()
    else {
        return false;
    };
    let Ok(lineage) = input.lineage().id() else {
        return false;
    };
    let Ok(attempt) = input.attempt().id() else {
        return false;
    };
    store
        .validate_attempt_retention_policy_basis(lineage, attempt, basis)
        .is_ok_and(|policy| policy.exact_findings())
}

pub(crate) fn publish_authenticated_terminal_checkpoint(
    source: &dyn FindingExactCheckpointAuthenticator,
    checkpoints: &ExactCheckpointStore,
    capture: &CapturedAttemptCheckpoint,
    cancellation: &ExecutionCancellation,
    identity: FindingTerminalCheckpointIdentity,
) -> Result<ExactCheckpointId, FindingExactCandidateInventoryError> {
    // The root is published before catalog insertion, so a failed count or
    // canceled publication can only leave an unselected durable orphan.
    let prepared = checkpoints
        .prepare_attempt_checkpoint_with_cancellation(capture, cancellation)
        .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
    if cancellation.is_canceled() {
        return Err(FindingExactCandidateInventoryError::Unavailable);
    }
    let root = prepared.root();
    let publication = checkpoints
        .publish_attempt_checkpoint(&prepared)
        .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
    if publication.root() != root {
        return Err(FindingExactCandidateInventoryError::Unavailable);
    }
    let authenticated = source
        .authenticate_finding_exact_checkpoint(
            root,
            identity.scenario,
            identity.scenario_artifact,
            identity.configuration,
            MAX_FINDING_EXACT_METADATA_BYTES,
        )
        .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
    if authenticated.event_count() != identity.event_count {
        return Err(FindingExactCandidateInventoryError::Unavailable);
    }
    if cancellation.is_canceled() {
        return Err(FindingExactCandidateInventoryError::Unavailable);
    }
    Ok(root)
}

pub(crate) struct CampaignRunFindingExactRetentionSource {
    campaign: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    owner: CampaignHash,
    // Field order keeps map allocation credit and owner custody through teardown.
    candidates: Mutex<CampaignRunExactCheckpointCatalog>,
    _owner_lease: ExecutorExactRetentionOwnerLease,
    _durable_catalog_custody: ExecutorExactRetentionCatalogCustody,
}

struct CampaignRunExactCheckpointCatalog {
    maximum_roots: usize,
    maximum_roots_per_configuration: usize,
    roots: BTreeMap<ExactCheckpointId, ConfigurationId>,
    insertion_order: VecDeque<ExactCheckpointId>,
    by_configuration: BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    incomplete_configurations: BTreeSet<ConfigurationId>,
    globally_incomplete: bool,
    // Declared last so allocation credit outlives every producer-controlled map.
    _allocation_custody: Option<ExecutorExactCatalogAllocationCustody>,
}

impl CampaignRunExactCheckpointCatalog {
    fn new(maximum_roots: usize) -> Self {
        let maximum_roots = maximum_roots.max(1);
        Self {
            maximum_roots,
            maximum_roots_per_configuration: maximum_roots
                .min(crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize),
            roots: BTreeMap::new(),
            insertion_order: VecDeque::new(),
            by_configuration: BTreeMap::new(),
            incomplete_configurations: BTreeSet::new(),
            globally_incomplete: false,
            _allocation_custody: None,
        }
    }

    fn from_durable(
        maximum_roots: usize,
        checkpoints: &ExactCheckpointStore,
        durable: Option<&ExecutorExactRetentionCatalog>,
        allocation_custody: Option<ExecutorExactCatalogAllocationCustody>,
    ) -> Result<Self, CampaignRepositoryError> {
        let mut catalog = Self::new(maximum_roots);
        catalog._allocation_custody = allocation_custody;
        let Some(durable) = durable else {
            return Ok(catalog);
        };
        catalog.globally_incomplete = durable.globally_incomplete();
        catalog.incomplete_configurations = durable.incomplete_configurations().clone();
        for (root, configuration) in durable.entries() {
            let loaded = checkpoints.load_attempt_checkpoint(*root).map_err(|_| {
                CampaignRepositoryError::Integrity {
                    reason: "durable exact-retention catalog root failed authentication",
                }
            })?;
            let authenticated_configuration =
                ConfigurationId::from_hash(CampaignHash::from_bytes(loaded.configuration().bytes));
            if authenticated_configuration != *configuration {
                return Err(CampaignRepositoryError::Integrity {
                    reason: "durable exact-retention catalog configuration changed",
                });
            }
            if catalog.roots.len() >= catalog.maximum_roots
                || catalog.roots.insert(*root, *configuration).is_some()
            {
                return Err(CampaignRepositoryError::Integrity {
                    reason: "durable exact-retention catalog exceeds runtime bounds",
                });
            }
            catalog.insertion_order.push_back(*root);
            catalog
                .by_configuration
                .entry(*configuration)
                .or_default()
                .insert(*root);
        }
        Ok(catalog)
    }

    fn retain(
        &mut self,
        checkpoint: ExactCheckpointId,
        configuration: ConfigurationId,
    ) -> Result<(), FindingExactCandidateInventoryError> {
        if self.roots.contains_key(&checkpoint) {
            return Ok(());
        }
        if self.globally_incomplete || self.incomplete_configurations.contains(&configuration) {
            return Ok(());
        }
        if self
            .by_configuration
            .get(&configuration)
            .is_some_and(|roots| roots.len() == self.maximum_roots_per_configuration)
        {
            self.mark_incomplete(configuration);
            return Ok(());
        }
        if self.roots.len() == self.maximum_roots {
            let retired = self
                .insertion_order
                .pop_front()
                .ok_or(FindingExactCandidateInventoryError::Unavailable)?;
            let retired_configuration = self
                .roots
                .remove(&retired)
                .ok_or(FindingExactCandidateInventoryError::Unavailable)?;
            let retained = self
                .by_configuration
                .get_mut(&retired_configuration)
                .ok_or(FindingExactCandidateInventoryError::Unavailable)?;
            retained.remove(&retired);
            if retained.is_empty() {
                self.by_configuration.remove(&retired_configuration);
            }
            self.mark_incomplete(retired_configuration);
        }
        self.roots.insert(checkpoint, configuration);
        self.insertion_order.push_back(checkpoint);
        self.by_configuration
            .entry(configuration)
            .or_default()
            .insert(checkpoint);
        Ok(())
    }

    fn required_allocation_entries(
        &self,
        checkpoint: ExactCheckpointId,
        configuration: ConfigurationId,
    ) -> Option<usize> {
        if self.roots.contains_key(&checkpoint)
            || self.globally_incomplete
            || self.incomplete_configurations.contains(&configuration)
        {
            return None;
        }
        self.roots
            .len()
            .checked_add(self.incomplete_configurations.len())
            .and_then(|entries| entries.checked_add(1))
    }

    fn mark_incomplete(&mut self, configuration: ConfigurationId) {
        if self.globally_incomplete || self.incomplete_configurations.contains(&configuration) {
            return;
        }
        if self.incomplete_configurations.len() == self.maximum_roots {
            self.incomplete_configurations.clear();
            self.globally_incomplete = true;
            return;
        }
        self.incomplete_configurations.insert(configuration);
    }

    fn candidates(
        &self,
        campaign: &CampaignExecutorStore,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError> {
        if self.globally_incomplete || self.incomplete_configurations.contains(&configuration) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        let candidates = self.by_configuration.get(&configuration);
        if candidates.is_some_and(|candidates| candidates.len() > maximum_candidates) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        let Some(candidates) = candidates else {
            return Ok(FindingExactCandidateInventory::empty());
        };
        let scratch = campaign
            .reserve_exact_candidate_inventory(candidates.len())
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(candidates.len())
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        roots.extend(candidates.iter().copied());
        Ok(FindingExactCandidateInventory::admitted(roots, scratch))
    }

    fn durable_projection(&self) -> Result<ExecutorExactRetentionCatalog, CampaignCodecError> {
        let entries = self
            .insertion_order
            .iter()
            .map(|root| {
                self.roots
                    .get(root)
                    .copied()
                    .map(|configuration| (*root, configuration))
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "exact-retention insertion order is inconsistent",
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        ExecutorExactRetentionCatalog::new(
            entries,
            self.incomplete_configurations.clone(),
            self.globally_incomplete,
        )
    }

    fn projection_entries(&self) -> Result<usize, CampaignRepositoryError> {
        1_usize
            .checked_add(self.roots.len())
            .and_then(|count| count.checked_add(self.incomplete_configurations.len()))
            .ok_or(CampaignRepositoryError::Integrity {
                reason: "campaign exact-retention catalog entry count overflowed",
            })
    }

    fn abandon_unretained(&mut self) {
        self.roots.clear();
        self.insertion_order.clear();
        self.by_configuration.clear();
        self.incomplete_configurations.clear();
        self.globally_incomplete = true;
    }
}

impl CampaignRunFindingExactRetentionSource {
    pub(crate) fn new(
        campaign: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
        owner: CampaignHash,
    ) -> Result<Self, CampaignRepositoryError> {
        let owner_lease = campaign.claim_exact_catalog_owner(owner)?;
        let durable_catalog_custody = campaign.load_exact_catalog(owner)?;
        let mut allocation_custody = None;
        if let Some(catalog) = durable_catalog_custody.catalog() {
            let entries = catalog
                .entries()
                .len()
                .checked_add(catalog.incomplete_configurations().len())
                .ok_or(CampaignRepositoryError::Integrity {
                    reason: "durable exact-retention catalog entry count overflowed",
                })?;
            if entries != 0 {
                campaign.ensure_exact_catalog_custody(&mut allocation_custody, entries)?;
            }
        }
        let candidates = CampaignRunExactCheckpointCatalog::from_durable(
            MAX_CAMPAIGN_RUN_EXACT_CHECKPOINTS,
            &checkpoints,
            durable_catalog_custody.catalog(),
            allocation_custody,
        )?;
        Ok(Self {
            campaign,
            checkpoints,
            owner,
            _owner_lease: owner_lease,
            _durable_catalog_custody: durable_catalog_custody,
            candidates: Mutex::new(candidates),
        })
    }

    pub(crate) fn retain_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
    ) -> Result<(), FindingExactCandidateInventoryError> {
        let loaded = self
            .checkpoints
            .load_attempt_checkpoint(checkpoint)
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        let configuration =
            ConfigurationId::from_hash(CampaignHash::from_bytes(loaded.configuration().bytes));
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        if let Some(entries) = candidates.required_allocation_entries(checkpoint, configuration) {
            self.campaign
                .ensure_exact_catalog_custody(&mut candidates._allocation_custody, entries)
                .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?;
        }
        candidates.retain(checkpoint, configuration)
    }

    pub(crate) fn retire_catalog(&self) -> Result<(), CampaignRepositoryError> {
        self.campaign.retire_exact_catalog(self.owner)
    }
}

impl FindingExactRetentionSource for CampaignRunFindingExactRetentionSource {
    fn candidate_checkpoints(
        &self,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError> {
        self.candidates
            .lock()
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?
            .candidates(&self.campaign, configuration, maximum_candidates)
    }

    fn exact_findings_enabled(
        &self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> bool {
        exact_findings_enabled(&self.campaign, input, context)
    }

    fn retain_terminal_checkpoint(
        &self,
        capture: &CapturedAttemptCheckpoint,
        context: &AttemptExecutionContext,
        identity: FindingTerminalCheckpointIdentity,
    ) -> Result<(), FindingExactCandidateInventoryError> {
        let root = publish_authenticated_terminal_checkpoint(
            self,
            &self.checkpoints,
            capture,
            context.cancellation(),
            identity,
        )?;
        self.retain_checkpoint(root)
    }

    fn retain_execution_result(
        &self,
        _input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        result: &PreparedSemanticAttemptResult,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        let roots = result
            .finding()
            .map(|finding| finding.bundle().exact_pins().all());
        let candidates =
            self.candidates
                .lock()
                .map_err(|_| CampaignRepositoryError::Integrity {
                    reason: "campaign exact-retention catalog lock is poisoned",
                })?;
        if roots.is_none_or(BTreeSet::is_empty)
            && candidates.roots.is_empty()
            && candidates.incomplete_configurations.is_empty()
            && !candidates.globally_incomplete
        {
            return Ok(());
        }
        let _projection_scratch = self
            .campaign
            .reserve_exact_catalog_projection(candidates.projection_entries()?)?;
        let catalog = candidates.durable_projection()?;
        // Keep the source catalog locked through publication. A later call
        // must not publish an older projection after this handoff completes.
        match (context.diagnostic_execution_id(), roots) {
            (Some(execution), Some(roots)) if !roots.is_empty() => self
                .campaign
                .retain_exact_result_under(gc_exclusion, self.owner, catalog, execution, roots),
            _ => self
                .campaign
                .replace_exact_catalog_under(gc_exclusion, self.owner, catalog),
        }
    }

    fn retain_execution_catalog(
        &self,
        gc_exclusion: &CampaignRepositoryGcExclusionGuard,
    ) -> Result<(), CampaignRepositoryError> {
        let candidates =
            self.candidates
                .lock()
                .map_err(|_| CampaignRepositoryError::Integrity {
                    reason: "campaign exact-retention catalog lock is poisoned",
                })?;
        if candidates.roots.is_empty()
            && candidates.incomplete_configurations.is_empty()
            && !candidates.globally_incomplete
        {
            return Ok(());
        }
        let _projection_scratch = self
            .campaign
            .reserve_exact_catalog_projection(candidates.projection_entries()?)?;
        let catalog = candidates.durable_projection()?;
        // Serialize projection and publication for the shared synchronous
        // source so concurrent failure handoffs cannot overwrite newer roots.
        self.campaign
            .replace_exact_catalog_under(gc_exclusion, self.owner, catalog)
    }

    fn abandon_unretained_candidates(&self) {
        if let Ok(mut candidates) = self.candidates.lock() {
            candidates.abandon_unretained();
        }
    }
}

impl FindingExactCheckpointAuthenticator for CampaignRunFindingExactRetentionSource {
    fn authenticate_finding_assertion_boundary(
        &self,
        checkpoint: ExactCheckpointId,
        boundary: &FindingAssertionFailureBoundary,
        trace_bytes: &[u8],
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
    ) -> Result<(), FindingExactCheckpointAuthenticationError> {
        ExactFindingCheckpointAuthenticator::new(&self.campaign, &self.checkpoints)
            .authenticate_finding_assertion_boundary(
                checkpoint,
                boundary,
                trace_bytes,
                scenario,
                scenario_artifact,
                configuration,
            )
    }

    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        ExactFindingCheckpointAuthenticator::new(&self.campaign, &self.checkpoints)
            .authenticate_finding_exact_checkpoint(
                checkpoint,
                scenario,
                scenario_artifact,
                configuration,
                maximum_metadata_bytes,
            )
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: crucible_store::content_store::ContentId,
    ) -> Result<crucible_store::content_store::BlobHandle, FindingExactCheckpointAuthenticationError>
    {
        ExactFindingCheckpointAuthenticator::new(&self.campaign, &self.checkpoints)
            .read_finding_exact_checkpoint_object(object)
    }
}

pub(super) fn prepare_finding_exact_retention(
    store: &CampaignExecutorStore,
    source: &dyn FindingExactRetentionSource,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    result: &PreparedSemanticAttemptResult,
    execution: Option<&QemuAttemptExecutionEvidenceSnapshot>,
) -> Result<(FindingExactPins, PreparedFindingExactRetention), CampaignCodecError> {
    let observation = result.observation();
    let crucible_campaign::AttemptRetentionPolicyDisposition::Required(basis) =
        context.retention_policy()
    else {
        return Err(CampaignCodecError::InvalidValue {
            reason: "automatic finding execution omits its retention policy basis",
        });
    };
    let retention_policy = store
        .validate_attempt_retention_policy_basis(
            input.lineage().id()?,
            input.attempt().id()?,
            basis,
        )
        .map_err(|_| CampaignCodecError::InvalidValue {
            reason: "finding retention policy basis failed executor authentication",
        })?;
    let boundary = match observation.observation().stop() {
        StopOutcome::ObservationReached(proof) => Some(FindingExactBoundary {
            failure_events: proof.event_log().events(),
            measurement_events: Some(proof.boundary().start_events()),
            assertion: None,
        }),
        StopOutcome::AssertionFailure(property) => match execution {
            Some(execution) => assertion_failure_boundary(input, result, execution, property)?,
            None => None,
        }
        .map(|(witness, bytes)| FindingExactBoundary {
            failure_events: witness.terminal_events(),
            measurement_events: Some(witness.quantum_start_events()),
            assertion: Some((witness, bytes)),
        }),
        _ => None,
    };
    select_finding_exact_retention(
        basis,
        retention_policy.exact_findings(),
        source,
        input.lineage().scenario(),
        input.lineage().scenario_content(),
        observation.child().configuration(),
        boundary,
    )
}

fn assertion_failure_boundary(
    input: &CrucibleAttemptExecution,
    result: &PreparedSemanticAttemptResult,
    execution: &QemuAttemptExecutionEvidenceSnapshot,
    property: &str,
) -> Result<
    Option<(
        FindingAssertionFailureBoundary,
        crate::CrucibleMeasurementEvidenceBytes,
    )>,
    CampaignCodecError,
> {
    let selected = (|| {
        let observation = result.observation();
        if observation.observation().attempt() != input.attempt().id().ok()?
            || observation
                .properties()
                .properties()
                .get(property)?
                .verdict()
                != PropertyVerdict::Failed
        {
            return None;
        }

        let terminal_events = execution.semantic_stop_events()?;
        let quantum_start_events = execution.latest_quantum_start_events()?;
        let terminal_len = usize::try_from(terminal_events).ok()?;
        let entries = execution.event_log_entries().get(..terminal_len)?;
        if quantum_start_events >= terminal_events {
            return None;
        }

        let measurement_ids = observation.measurements().evaluation().evidence();
        let mut matching = result
            .measurement_replay_evidence()
            .iter()
            .filter_map(|leaf| {
                let id = leaf.id().ok()?;
                (measurement_ids.contains(&id)
                    && leaf.scenario() == input.lineage().scenario()
                    && leaf.configuration() == observation.child().configuration()
                    && leaf.stop() == CrucibleMeasurementStopEvidence::Campaign
                    && leaf.entries() == entries)
                    .then_some((id, leaf))
            });
        let (trace, leaf) = matching.next()?;
        if matching.next().is_some() || measurement_ids.len() != 1 {
            return None;
        }

        Some((trace, leaf, entries, terminal_events, quantum_start_events))
    })();
    let Some((trace, leaf, entries, terminal_events, quantum_start_events)) = selected else {
        return Ok(None);
    };
    let engine_custody =
        crate::crucible_measurement::boundary_error::admit::<crucible_engine::EngineError>()?;
    let measurement_custody =
        crate::crucible_measurement::boundary_error::admit::<crate::CrucibleMeasurementError>()?;
    let Some(transition) = verified_assertion_transition(entries, quantum_start_events, property)
        .map_err(|source| match source {
        crucible_engine::EngineError::ArtifactDecodeAdmission { source } => {
            CampaignCodecError::DecodeAdmission(source)
        }
        source => crate::crucible_measurement::boundary_error::campaign(source, engine_custody),
    })?
    else {
        return Ok(None);
    };

    let boundary = FindingAssertionFailureBoundary::new(
        trace,
        crate::crucible_measurement::observation_event_prefix_digest(entries),
        terminal_events,
        quantum_start_events,
        transition.sequence(),
        CampaignHash::from_bytes(transition.content_hash().bytes),
        crucible_engine::owned_decode::display_string(property)
            .map_err(CampaignCodecError::DecodeAdmission)?,
    )
    .ok();
    let Some(boundary) = boundary else {
        return Ok(None);
    };
    let bytes = leaf.canonical_bytes().map_err(|source| {
        crate::crucible_measurement::boundary_error::campaign(source, measurement_custody)
    })?;
    Ok(Some((boundary, bytes)))
}

fn select_finding_exact_retention(
    basis: AttemptRetentionPolicyBasis,
    exact_findings: bool,
    source: &dyn FindingExactRetentionSource,
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    boundary: Option<FindingExactBoundary>,
) -> Result<(FindingExactPins, PreparedFindingExactRetention), CampaignCodecError> {
    if !exact_findings {
        let retention = FindingExactRetention::new(
            basis.snapshot(),
            basis.policy(),
            basis.admission(),
            0,
            FindingExactRetentionDisposition::Disabled,
        )?;
        return Ok((
            FindingExactPins::default(),
            PreparedFindingExactRetention {
                retention,
                evidence: None,
            },
        ));
    }

    let incomplete = |reason| {
        FindingExactRetention::new(
            basis.snapshot(),
            basis.policy(),
            basis.admission(),
            0,
            FindingExactRetentionDisposition::Incomplete(reason),
        )
        .map(|retention| {
            (
                FindingExactPins::default(),
                PreparedFindingExactRetention {
                    retention,
                    evidence: None,
                },
            )
        })
    };
    let roots = match source.candidate_checkpoints(
        configuration,
        crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize,
    ) {
        Ok(roots) if !roots.is_empty() => roots,
        Ok(_) => return incomplete(FindingExactRetentionIncomplete::MissingSafeBoundaryCapture),
        Err(FindingExactCandidateInventoryError::Unavailable) => {
            return incomplete(FindingExactRetentionIncomplete::CandidateInventoryUnavailable);
        }
        Err(FindingExactCandidateInventoryError::LimitExceeded) => {
            return incomplete(FindingExactRetentionIncomplete::CandidateLimitExceeded);
        }
    };
    let boundary = match boundary {
        Some(boundary) => boundary,
        None => return incomplete(FindingExactRetentionIncomplete::MissingSafeBoundaryCapture),
    };
    let failure_events = boundary.failure_events;
    let measurement_events = boundary.measurement_events;

    let mut candidates = Vec::with_capacity(roots.len());
    let mut remaining_metadata = MAX_FINDING_EXACT_METADATA_BYTES;
    for root in roots.roots().iter().copied() {
        let authenticated = match source.authenticate_finding_exact_checkpoint(
            root,
            scenario,
            scenario_artifact,
            configuration,
            remaining_metadata,
        ) {
            Ok(authenticated) => authenticated,
            Err(_) => {
                return incomplete(FindingExactRetentionIncomplete::CandidateAuthenticationFailed);
            }
        };
        remaining_metadata = match remaining_metadata.checked_sub(authenticated.metadata_bytes()) {
            Some(remaining) => remaining,
            None => {
                return incomplete(FindingExactRetentionIncomplete::CandidateAuthenticationFailed);
            }
        };
        candidates.push(FindingExactRetentionCandidate::new(
            root,
            authenticated.event_count(),
        ));
    }
    candidates.sort_by_key(|candidate| candidate.checkpoint());
    if let Some((boundary, trace_bytes)) = boundary.assertion.as_ref() {
        candidates.retain(|candidate| {
            source
                .authenticate_finding_assertion_boundary(
                    candidate.checkpoint(),
                    boundary,
                    trace_bytes,
                    scenario,
                    scenario_artifact,
                    configuration,
                )
                .is_ok()
        });
    }
    let Some(captured_failure) = candidates
        .iter()
        .filter(|candidate| candidate.event_count() == failure_events)
        .map(|candidate| candidate.checkpoint())
        .min()
    else {
        return incomplete(FindingExactRetentionIncomplete::MissingSafeBoundaryCapture);
    };
    let evidence = match FindingExactRetentionEvidence::select(
        candidates,
        captured_failure,
        failure_events,
        measurement_events,
    ) {
        Ok(evidence) => evidence,
        Err(_) => return incomplete(FindingExactRetentionIncomplete::SelectionFailed),
    };
    let evidence = match boundary.assertion {
        Some((boundary, _)) => match evidence.with_assertion_boundary(boundary) {
            Ok(evidence) => evidence,
            Err(_) => return incomplete(FindingExactRetentionIncomplete::SelectionFailed),
        },
        None => evidence,
    };
    let authenticated_candidates = u32::try_from(evidence.candidates().len()).map_err(|_| {
        CampaignCodecError::LimitExceeded {
            limit: "finding-exact-retention-candidate-count",
        }
    })?;
    let pins = evidence.selected().clone();
    let retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        authenticated_candidates,
        FindingExactRetentionDisposition::Complete,
    )?;
    Ok((
        pins,
        PreparedFindingExactRetention {
            retention,
            evidence: Some(evidence),
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io;

    use crucible_engine::{AssertionId, VirtualTime};
    use crucible_store::content_store::{ContentId, ObjectKind};

    use super::*;
    use crucible_campaign::{
        AttemptAdmissionId, CampaignHash, CampaignPolicyId, CampaignRepository, CampaignSnapshotId,
    };

    #[derive(Clone)]
    enum TestInventory {
        Roots(Vec<ExactCheckpointId>),
        Failure(FindingExactCandidateInventoryError),
    }

    struct TestSource {
        inventory: TestInventory,
        events: BTreeMap<ExactCheckpointId, u64>,
        authentication_fails: bool,
    }

    impl FindingExactRetentionSource for TestSource {
        fn candidate_checkpoints(
            &self,
            _configuration: ConfigurationId,
            _maximum_candidates: usize,
        ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError> {
            match &self.inventory {
                TestInventory::Roots(roots) => {
                    Ok(FindingExactCandidateInventory::fixture(roots.clone()))
                }
                TestInventory::Failure(error) => Err(*error),
            }
        }

        fn exact_findings_enabled(
            &self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
        ) -> bool {
            false
        }

        fn retain_terminal_checkpoint(
            &self,
            _capture: &CapturedAttemptCheckpoint,
            _context: &AttemptExecutionContext,
            _identity: FindingTerminalCheckpointIdentity,
        ) -> Result<(), FindingExactCandidateInventoryError> {
            Err(FindingExactCandidateInventoryError::Unavailable)
        }
    }

    impl FindingExactCheckpointAuthenticator for TestSource {
        fn authenticate_finding_exact_checkpoint(
            &self,
            checkpoint: ExactCheckpointId,
            scenario: ScenarioDefId,
            _scenario_artifact: ScenarioArtifactId,
            configuration: ConfigurationId,
            _maximum_metadata_bytes: u64,
        ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
        {
            if self.authentication_fails {
                return Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed);
            }
            let event_count = self
                .events
                .get(&checkpoint)
                .copied()
                .ok_or(FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
            Ok(AuthenticatedFindingExactCheckpoint::new(
                scenario,
                configuration,
                event_count,
                128,
            ))
        }
    }

    struct PrefixSource {
        inner: TestSource,
        prefixes: BTreeMap<ExactCheckpointId, Vec<SchedulerEventLogEntry>>,
    }

    impl FindingExactRetentionSource for PrefixSource {
        fn candidate_checkpoints(
            &self,
            configuration: ConfigurationId,
            maximum_candidates: usize,
        ) -> Result<FindingExactCandidateInventory, FindingExactCandidateInventoryError> {
            self.inner
                .candidate_checkpoints(configuration, maximum_candidates)
        }

        fn exact_findings_enabled(
            &self,
            _input: &CrucibleAttemptExecution,
            _context: &AttemptExecutionContext,
        ) -> bool {
            false
        }

        fn retain_terminal_checkpoint(
            &self,
            _capture: &CapturedAttemptCheckpoint,
            _context: &AttemptExecutionContext,
            _identity: FindingTerminalCheckpointIdentity,
        ) -> Result<(), FindingExactCandidateInventoryError> {
            Err(FindingExactCandidateInventoryError::Unavailable)
        }
    }

    impl FindingExactCheckpointAuthenticator for PrefixSource {
        fn authenticate_finding_assertion_boundary(
            &self,
            checkpoint: ExactCheckpointId,
            boundary: &FindingAssertionFailureBoundary,
            trace_bytes: &[u8],
            _scenario: ScenarioDefId,
            _scenario_artifact: ScenarioArtifactId,
            _configuration: ConfigurationId,
        ) -> Result<(), FindingExactCheckpointAuthenticationError> {
            (ContentId::for_bytes(ObjectKind::Trace, 2, trace_bytes) == boundary.trace())
                .then_some(())
                .ok_or(FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
            self.prefixes
                .get(&checkpoint)
                .filter(|entries| {
                    entries.len() as u64 == boundary.terminal_events()
                        && crate::crucible_measurement::observation_event_prefix_digest(entries)
                            == boundary.prefix_digest()
                })
                .map(|_| ())
                .ok_or(FindingExactCheckpointAuthenticationError::AuthenticationFailed)
        }

        fn authenticate_finding_exact_checkpoint(
            &self,
            checkpoint: ExactCheckpointId,
            scenario: ScenarioDefId,
            scenario_artifact: ScenarioArtifactId,
            configuration: ConfigurationId,
            maximum_metadata_bytes: u64,
        ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
        {
            self.inner.authenticate_finding_exact_checkpoint(
                checkpoint,
                scenario,
                scenario_artifact,
                configuration,
                maximum_metadata_bytes,
            )
        }
    }

    fn checkpoint(label: &[u8]) -> Result<ExactCheckpointId, Box<dyn Error>> {
        Ok(ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            6,
            label,
        ))?)
    }

    #[test]
    fn candidate_inventory_credit_refuses_bounded_outstanding_and_recovers_after_drop()
    -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = crucible_engine::owned_decode::DecodeBudget::for_store(resources)?;
        // Existing metadata consumes the same original account. The remaining
        // headroom must bound held responses across the admitted worker count.
        let _other_metadata = original.reserve_scratch_bytes(240 * 1024 * 1024)?;
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(crucible_store::content_store::MemoryBlobBackend::new(
                "candidate-inventory-credit",
                1024,
            )),
            Arc::new(crucible_store::content_store::MemoryRefBackend::new()),
            crucible_campaign::CampaignRamAdmission::Available(original),
        ));
        let store = CampaignExecutorStore::new(repository);
        let root = checkpoint(b"candidate-inventory-credit")?;
        let count = crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize;
        let released = store.reserve_exact_candidate_inventory(count)?;
        drop(FindingExactCandidateInventory::admitted(
            vec![root; count],
            released,
        ));
        let returned = store.reserve_exact_candidate_inventory(count)?;
        drop(returned);

        let mut outstanding = Vec::new();
        let mut refused = false;

        for _ in 0..=crate::MAX_LOCAL_EXECUTOR_WORKERS {
            let scratch = match store.reserve_exact_candidate_inventory(count) {
                Ok(scratch) => scratch,
                Err(_) => {
                    refused = true;
                    break;
                }
            };
            let mut roots = Vec::new();
            roots.try_reserve_exact(count)?;
            roots.resize(count, root);
            outstanding.push(FindingExactCandidateInventory::admitted(roots, scratch));
        }
        assert!(refused, "finite fixture original must eventually refuse");
        assert!(!outstanding.is_empty());
        assert!(outstanding.len() <= crate::MAX_LOCAL_EXECUTOR_WORKERS);

        drop(outstanding);
        Ok(())
    }

    #[test]
    fn candidate_inventory_rejects_excessive_count_before_original_authority() {
        let repository = Arc::new(CampaignRepository::new(
            Arc::new(crucible_store::content_store::MemoryBlobBackend::new(
                "candidate-inventory-limit",
                1,
            )),
            Arc::new(crucible_store::content_store::MemoryRefBackend::new()),
            crucible_campaign::CampaignRamAdmission::Unavailable,
        ));
        let store = CampaignExecutorStore::new(repository);
        let excessive = crucible_campaign::MAX_FINDING_EXACT_RETENTION_CANDIDATES as usize + 1;

        assert!(matches!(
            store.reserve_exact_candidate_inventory(excessive),
            Err(CampaignRepositoryError::Codec(
                CampaignCodecError::LimitExceeded {
                    limit: "executor-exact-retention"
                }
            ))
        ));
    }

    #[test]
    fn campaign_catalog_bounds_matching_roots_after_configuration_partitioning()
    -> Result<(), Box<dyn Error>> {
        let resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = crucible_engine::owned_decode::DecodeBudget::for_store(resources)?;
        let store = CampaignExecutorStore::new(Arc::new(CampaignRepository::new(
            Arc::new(crucible_store::content_store::MemoryBlobBackend::new(
                "candidate-partition-credit",
                1024,
            )),
            Arc::new(crucible_store::content_store::MemoryRefBackend::new()),
            crucible_campaign::CampaignRamAdmission::Available(original),
        )));

        let matching = ConfigurationId::from_hash(CampaignHash::derive(
            "exact-retention-test.matching-configuration",
            b"matching",
        ));
        let unrelated = ConfigurationId::from_hash(CampaignHash::derive(
            "exact-retention-test.unrelated-configuration",
            b"unrelated",
        ));
        let mut catalog = CampaignRunExactCheckpointCatalog::new(4_100);
        for index in 0_u32..4_097 {
            catalog.retain(checkpoint(&index.to_be_bytes())?, unrelated)?;
        }
        let retained = checkpoint(b"matching-root")?;
        catalog.retain(retained, matching)?;

        assert_eq!(catalog.roots.len(), 4_097);
        assert_eq!(catalog.by_configuration[&unrelated].len(), 4_096);
        assert_eq!(catalog.candidates(&store, matching, 4_096)?, vec![retained]);
        assert_eq!(
            catalog.candidates(&store, unrelated, 4_096),
            Err(FindingExactCandidateInventoryError::LimitExceeded),
        );

        let mut bounded = CampaignRunExactCheckpointCatalog::new(2);
        let retired = checkpoint(b"bounded-1")?;
        let retained = checkpoint(b"bounded-2")?;
        let admitted = checkpoint(b"bounded-3")?;
        bounded.retain(retired, unrelated)?;
        bounded.retain(retained, matching)?;
        bounded.retain(admitted, matching)?;
        assert_eq!(
            bounded.candidates(&store, unrelated, 4_096),
            Err(FindingExactCandidateInventoryError::LimitExceeded),
        );
        let mut expected = vec![retained, admitted];
        expected.sort();
        assert_eq!(bounded.candidates(&store, matching, 4_096)?, expected);

        let mut globally_bounded = CampaignRunExactCheckpointCatalog::new(2);
        let mut last_configuration = matching;
        for index in 0_u8..5 {
            let configuration = ConfigurationId::from_hash(CampaignHash::derive(
                "exact-retention-test.bounded-configuration",
                &[index],
            ));
            globally_bounded.retain(checkpoint(&[0x80, index])?, configuration)?;
            last_configuration = configuration;
        }
        assert!(globally_bounded.globally_incomplete);
        assert!(globally_bounded.incomplete_configurations.is_empty());
        assert_eq!(
            globally_bounded.candidates(&store, last_configuration, 4_096),
            Err(FindingExactCandidateInventoryError::LimitExceeded),
        );
        Ok(())
    }

    fn basis() -> Result<AttemptRetentionPolicyBasis, Box<dyn Error>> {
        let snapshot = ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"exact-retention-test-snapshot",
        );
        let admission = ContentId::for_bytes(
            ObjectKind::CampaignFact,
            3,
            b"exact-retention-test-admission",
        );
        let policy = ContentId::for_bytes(ObjectKind::Policy, 5, b"exact-retention-test-policy");
        Ok(AttemptRetentionPolicyBasis::new(
            CampaignSnapshotId::parse(&format!("crucible.campaign.snapshot@{snapshot}"))?,
            AttemptAdmissionId::parse(&format!("crucible.campaign.attempt-admission@{admission}"))?,
            CampaignPolicyId::parse(&format!("crucible.campaign.policy@{policy}"))?,
        ))
    }

    fn identities() -> Result<(ScenarioDefId, ScenarioArtifactId, ConfigurationId), Box<dyn Error>>
    {
        let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
            "exact-retention-test.scenario",
            b"scenario",
        ));
        let scenario_content = ContentId::for_bytes(
            ObjectKind::Scenario,
            1,
            b"exact-retention-test-scenario-artifact",
        );
        let scenario_artifact = ScenarioArtifactId::parse(&format!(
            "crucible.campaign.scenario-artifact@{scenario_content}"
        ))?;
        let configuration = ConfigurationId::from_hash(CampaignHash::derive(
            "exact-retention-test.configuration",
            b"configuration",
        ));
        Ok((scenario, scenario_artifact, configuration))
    }

    fn disposition(
        prepared: &PreparedFindingExactRetention,
    ) -> Result<FindingExactRetentionDisposition, Box<dyn Error>> {
        Ok(prepared.retention.disposition())
    }

    #[test]
    fn assertion_boundary_requires_one_dense_violated_transition_in_terminal_quantum()
    -> Result<(), Box<dyn Error>> {
        let _scope = crucible_engine::test_support::fixture_decode_scope(16 << 20)?;
        let unrelated = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            AssertionId::from_name("unrelated"),
            AssertionPhase::Violated,
        )?;
        let target = SchedulerEventLogEntry::assertion_state_observation(
            1,
            VirtualTime { ticks: 2 },
            AssertionId::from_name("target"),
            AssertionPhase::Violated,
        )?;
        let entries = vec![unrelated.clone(), target.clone()];

        assert_eq!(
            verified_assertion_transition(&entries, 1, "target")?,
            Some(&target),
        );
        assert!(verified_assertion_transition(&entries, 1, "unrelated")?.is_none());
        assert!(verified_assertion_transition(&entries, 2, "target")?.is_none());

        let duplicate = SchedulerEventLogEntry::assertion_state_observation(
            2,
            VirtualTime { ticks: 2 },
            AssertionId::from_name("target"),
            AssertionPhase::Violated,
        )?;
        assert!(
            verified_assertion_transition(&[unrelated, target, duplicate], 1, "target")?.is_none()
        );
        assert!(verified_assertion_transition(&[entries[1].clone()], 0, "target")?.is_none());
        Ok(())
    }

    #[test]
    fn assertion_retention_uses_unpublished_trace_and_excludes_divergent_root()
    -> Result<(), Box<dyn Error>> {
        let _original_fixture_scope =
            crate::exact_checkpoint_store::test_support::fixture_decode_scope();

        let mut roots = [checkpoint(b"first")?, checkpoint(b"second")?];
        roots.sort();
        let divergent = roots[0];
        let matching = roots[1];
        let matching_log = (0_u64..5)
            .map(|sequence| {
                SchedulerEventLogEntry::assertion_state_observation(
                    sequence,
                    VirtualTime {
                        ticks: sequence + 1,
                    },
                    AssertionId::from_name(if sequence == 3 { "target" } else { "noise" }),
                    if sequence == 3 {
                        AssertionPhase::Violated
                    } else {
                        AssertionPhase::Satisfied
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut divergent_log = matching_log.clone();
        divergent_log[0] = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            AssertionId::from_name("foreign"),
            AssertionPhase::Satisfied,
        )?;
        let source = PrefixSource {
            inner: TestSource {
                inventory: TestInventory::Roots(roots.to_vec()),
                events: BTreeMap::from([(divergent, 5), (matching, 5)]),
                authentication_fails: false,
            },
            prefixes: BTreeMap::from([
                (divergent, divergent_log),
                (matching, matching_log.clone()),
            ]),
        };
        let (scenario, scenario_artifact, configuration) = identities()?;
        let boundary = FindingAssertionFailureBoundary::new(
            ContentId::for_bytes(ObjectKind::Trace, 2, b"matching"),
            crate::crucible_measurement::observation_event_prefix_digest(&matching_log),
            5,
            2,
            3,
            CampaignHash::from_bytes(matching_log[3].content_hash().bytes),
            String::from("target"),
        )?;

        // The source has no durable Trace store; selection uses the prepared bytes.
        let (pins, prepared) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario,
            scenario_artifact,
            configuration,
            Some(FindingExactBoundary {
                failure_events: 5,
                measurement_events: Some(2),
                assertion: Some((
                    boundary.clone(),
                    crate::CrucibleMeasurementEvidenceBytes::fixture(b"matching")?,
                )),
            }),
        )?;

        assert_eq!(
            disposition(&prepared)?,
            FindingExactRetentionDisposition::Complete
        );
        assert_eq!(pins.post_failure(), &BTreeSet::from([matching]));
        let evidence = prepared.evidence.ok_or("missing selected evidence")?;
        assert_eq!(evidence.captured_failure(), matching);
        assert_eq!(evidence.candidates().len(), 1);

        let (invalid_pins, invalid) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario,
            scenario_artifact,
            configuration,
            Some(FindingExactBoundary {
                failure_events: 5,
                measurement_events: Some(2),
                assertion: Some((
                    boundary,
                    crate::CrucibleMeasurementEvidenceBytes::fixture(b"forged")?,
                )),
            }),
        )?;
        assert_eq!(invalid_pins, FindingExactPins::default());
        assert_eq!(
            disposition(&invalid)?,
            FindingExactRetentionDisposition::Incomplete(
                FindingExactRetentionIncomplete::MissingSafeBoundaryCapture
            )
        );
        Ok(())
    }

    #[test]
    fn matching_authenticated_roots_produce_complete_exact_pins() -> Result<(), Box<dyn Error>> {
        let first = checkpoint(b"first")?;
        let failure = checkpoint(b"failure")?;
        let source = TestSource {
            inventory: TestInventory::Roots(vec![failure, first]),
            events: BTreeMap::from([(first, 3), (failure, 5)]),
            authentication_fails: false,
        };
        let (scenario, scenario_artifact, configuration) = identities()?;

        let (pins, prepared) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario,
            scenario_artifact,
            configuration,
            Some(FindingExactBoundary {
                failure_events: 5,
                measurement_events: Some(4),
                assertion: None,
            }),
        )?;

        assert_eq!(
            disposition(&prepared)?,
            FindingExactRetentionDisposition::Complete
        );
        assert_eq!(
            prepared
                .evidence
                .map(|evidence| evidence.candidates().len()),
            Some(2)
        );
        assert!(pins.all().contains(&first));
        assert!(pins.all().contains(&failure));
        Ok(())
    }

    #[test]
    fn retained_production_checkpoint_authenticates_into_complete_evidence()
    -> Result<(), Box<dyn Error>> {
        let _original_fixture_scope =
            crate::exact_checkpoint_store::test_support::fixture_decode_scope();

        let directory = tempfile::tempdir()?;
        let fixture = crate::build_exact_ram_production_checkpoint_codec_fixture(directory.path())?;
        let repository_backend = Arc::new(crucible_store::content_store::MemoryBlobBackend::new(
            "campaign-run-exact-retention-integration",
            u64::MAX,
        ));
        let metadata = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()?;
        let original = crucible_engine::owned_decode::DecodeBudget::for_store(metadata.clone())?;
        let repository = Arc::new(CampaignRepository::new(
            repository_backend,
            Arc::new(crucible_store::content_store::MemoryRefBackend::new()),
            crucible_campaign::CampaignRamAdmission::Available(original),
        ));
        let scenario = fixture.source().scenario_def();
        let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
        let encoded_scenario = crate::encode_crucible_scenario_artifact(fixture.source())?;
        let scenario_artifact = repository.publish_scenario_artifact(
            scenario_id,
            encoded_scenario.payload_schema(),
            encoded_scenario.payload().to_vec(),
        )?;
        let configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
            fixture.configuration().id().bytes,
        ));
        let checkpoint_directory = tempfile::tempdir()?;
        let checkpoint_backend =
            Arc::new(crucible_store::content_store::DirectoryBlobBackend::new(
                "campaign-run-exact-retention-checkpoints",
                checkpoint_directory.path(),
            ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(
                checkpoint_backend,
                u64::MAX,
                repository.ram_retention_authority(),
            )?
            .with_ram_root_resources(metadata),
        );
        let prepared = checkpoints.prepare_production_closure(fixture.closure().clone())?;
        let checkpoint = checkpoints.publish_production_closure(&prepared)?.root();
        let store = CampaignExecutorStore::new(repository);
        let owner = CampaignHash::derive(
            "crucible.executor.test-exact-retention-owner.v1",
            b"exact-retention-unit",
        );
        let source =
            CampaignRunFindingExactRetentionSource::new(store.clone(), checkpoints.clone(), owner)
                .expect("open test exact-retention catalog");
        assert!(
            CampaignRunFindingExactRetentionSource::new(store.clone(), checkpoints.clone(), owner,)
                .is_err(),
            "a second live source must not appropriate the same catalog owner",
        );
        let loaded = Arc::new(source.checkpoints.load_attempt_checkpoint(checkpoint)?);
        let stored_scenario = source.campaign.load_scenario_artifact(scenario_artifact)?;
        let decoded_source = crate::decode_crucible_scenario_artifact(&stored_scenario)?;
        let decoded_checkpoint = source.checkpoints.decode_semantic_checkpoint(
            &loaded,
            &decoded_source,
            &crate::ExecutionCancellation::default(),
        )?;
        assert_eq!(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(loaded.scenario().bytes)),
            scenario_id,
        );
        assert_eq!(
            ConfigurationId::from_hash(CampaignHash::from_bytes(
                decoded_checkpoint.configuration().id().bytes,
            )),
            configuration,
        );
        let authenticated = source
            .authenticate_finding_exact_checkpoint(
                checkpoint,
                scenario_id,
                scenario_artifact,
                configuration,
                MAX_FINDING_EXACT_METADATA_BYTES,
            )
            .map_err(|error| io::Error::other(format!("checkpoint authentication: {error:?}")))?;

        let context = AttemptExecutionContext::new(
            crucible_campaign::AttemptResourceLimits::new(
                2,
                64 * 1024 * 1024,
                128 * 1024 * 1024,
                4,
            )?,
            crucible_campaign::ExecutionRetentionIntent::RetainOnFailure,
            ExecutionCancellation::default(),
            crate::ExecutionCheckpointRequest::default(),
            crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
        );
        let capture = CapturedAttemptCheckpoint::from_production_closure(fixture.closure().clone());
        let identity = FindingTerminalCheckpointIdentity {
            scenario: scenario_id,
            scenario_artifact,
            configuration,
            event_count: authenticated.event_count(),
        };
        assert!(source.candidate_checkpoints(configuration, 2)?.is_empty());
        source.retain_terminal_checkpoint(&capture, &context, identity)?;
        source.retain_terminal_checkpoint(&capture, &context, identity)?;
        assert_eq!(
            source.candidate_checkpoints(configuration, 2)?,
            vec![checkpoint]
        );
        let stale = FindingTerminalCheckpointIdentity {
            event_count: identity.event_count + 1,
            ..identity
        };
        assert_eq!(
            source.retain_terminal_checkpoint(&capture, &context, stale),
            Err(FindingExactCandidateInventoryError::Unavailable)
        );
        assert_eq!(
            source.candidate_checkpoints(configuration, 2)?,
            vec![checkpoint]
        );

        let (pins, prepared) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario_id,
            scenario_artifact,
            configuration,
            Some(FindingExactBoundary {
                failure_events: authenticated.event_count(),
                measurement_events: None,
                assertion: None,
            }),
        )?;

        assert_eq!(
            disposition(&prepared)?,
            FindingExactRetentionDisposition::Complete
        );
        assert_eq!(pins.post_failure().len(), 1);
        assert!(pins.post_failure().contains(&checkpoint));
        drop(source);
        CampaignRunFindingExactRetentionSource::new(store, checkpoints, owner)
            .expect("stopped predecessor releases its exact catalog owner");
        Ok(())
    }

    #[test]
    fn producer_records_disabled_and_truthful_incomplete_dispositions() -> Result<(), Box<dyn Error>>
    {
        let root = checkpoint(b"candidate")?;
        let (scenario, scenario_artifact, configuration) = identities()?;
        let cases = [
            (
                false,
                TestSource {
                    inventory: TestInventory::Roots(vec![root]),
                    events: BTreeMap::from([(root, 5)]),
                    authentication_fails: false,
                },
                Some((5, Some(4))),
                FindingExactRetentionDisposition::Disabled,
            ),
            (
                true,
                TestSource {
                    inventory: TestInventory::Roots(Vec::new()),
                    events: BTreeMap::new(),
                    authentication_fails: false,
                },
                Some((5, Some(4))),
                FindingExactRetentionDisposition::Incomplete(
                    FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                ),
            ),
            (
                true,
                TestSource {
                    inventory: TestInventory::Failure(
                        FindingExactCandidateInventoryError::Unavailable,
                    ),
                    events: BTreeMap::new(),
                    authentication_fails: false,
                },
                Some((5, Some(4))),
                FindingExactRetentionDisposition::Incomplete(
                    FindingExactRetentionIncomplete::CandidateInventoryUnavailable,
                ),
            ),
            (
                true,
                TestSource {
                    inventory: TestInventory::Failure(
                        FindingExactCandidateInventoryError::LimitExceeded,
                    ),
                    events: BTreeMap::new(),
                    authentication_fails: false,
                },
                Some((5, Some(4))),
                FindingExactRetentionDisposition::Incomplete(
                    FindingExactRetentionIncomplete::CandidateLimitExceeded,
                ),
            ),
            (
                true,
                TestSource {
                    inventory: TestInventory::Roots(vec![root]),
                    events: BTreeMap::from([(root, 5)]),
                    authentication_fails: true,
                },
                Some((5, Some(4))),
                FindingExactRetentionDisposition::Incomplete(
                    FindingExactRetentionIncomplete::CandidateAuthenticationFailed,
                ),
            ),
            (
                true,
                TestSource {
                    inventory: TestInventory::Roots(vec![root]),
                    events: BTreeMap::from([(root, 5)]),
                    authentication_fails: false,
                },
                None,
                FindingExactRetentionDisposition::Incomplete(
                    FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
                ),
            ),
        ];

        for (exact_findings, source, boundary, expected) in cases {
            let (_, prepared) = select_finding_exact_retention(
                basis()?,
                exact_findings,
                &source,
                scenario,
                scenario_artifact,
                configuration,
                boundary.map(
                    |(failure_events, measurement_events)| FindingExactBoundary {
                        failure_events,
                        measurement_events,
                        assertion: None,
                    },
                ),
            )?;
            assert_eq!(disposition(&prepared)?, expected);
        }
        Ok(())
    }
}
