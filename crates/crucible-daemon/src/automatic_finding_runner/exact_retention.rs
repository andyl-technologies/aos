//! Exact-checkpoint retention selection for automatic findings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use crucible::{AssertionPhase, SchedulerEventLogEntry};
use crucible_campaign::{
    AttemptRetentionPolicyBasis, AuthenticatedFindingExactCheckpoint, CampaignCodecError,
    CampaignExecutorStore, CampaignHash, ConfigurationId, ExactCheckpointId,
    FindingAssertionFailureBoundary, FindingExactCheckpointAuthenticationError,
    FindingExactCheckpointAuthenticator, FindingExactPins, FindingExactRetention,
    FindingExactRetentionCandidate, FindingExactRetentionDisposition,
    FindingExactRetentionEvidence, FindingExactRetentionIncomplete, PropertyVerdict,
    ScenarioArtifactId, ScenarioDefId, StopOutcome,
};

use crate::crucible_artifact::{PreparedFindingExactRetention, PreparedSemanticAttemptResult};
use crate::crucible_measurement::CrucibleMeasurementStopEvidence;
use crate::crucible_measurement::verified_assertion_transition;
use crate::exact_checkpoint_store::ExactFindingCheckpointAuthenticator;
use crate::qemu_campaign_lifecycle::QemuAttemptExecutionEvidenceSnapshot;
use crate::{AttemptExecutionContext, CrucibleAttemptExecution, ExactCheckpointStore};

const MAX_FINDING_EXACT_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAMPAIGN_RUN_EXACT_CHECKPOINTS: usize = 65_536;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum FindingExactCandidateInventoryError {
    #[error("exact finding candidate inventory is unavailable")]
    Unavailable,
    #[error("exact finding candidate inventory exceeds its bounded limit")]
    LimitExceeded,
}

pub(crate) trait FindingExactRetentionSource: FindingExactCheckpointAuthenticator {
    fn candidate_checkpoints(
        &self,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<Vec<ExactCheckpointId>, FindingExactCandidateInventoryError>;
}

pub(crate) struct CampaignRunFindingExactRetentionSource {
    campaign: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    candidates: Mutex<CampaignRunExactCheckpointCatalog>,
}

struct CampaignRunExactCheckpointCatalog {
    maximum_roots: usize,
    maximum_roots_per_configuration: usize,
    roots: BTreeMap<ExactCheckpointId, ConfigurationId>,
    insertion_order: VecDeque<ExactCheckpointId>,
    by_configuration: BTreeMap<ConfigurationId, BTreeSet<ExactCheckpointId>>,
    incomplete_configurations: BTreeSet<ConfigurationId>,
    globally_incomplete: bool,
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
        }
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
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<Vec<ExactCheckpointId>, FindingExactCandidateInventoryError> {
        if self.globally_incomplete || self.incomplete_configurations.contains(&configuration) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        let candidates = self.by_configuration.get(&configuration);
        if candidates.is_some_and(|candidates| candidates.len() > maximum_candidates) {
            return Err(FindingExactCandidateInventoryError::LimitExceeded);
        }
        Ok(candidates.into_iter().flatten().copied().collect())
    }
}

impl CampaignRunFindingExactRetentionSource {
    pub(crate) fn new(
        campaign: CampaignExecutorStore,
        checkpoints: Arc<ExactCheckpointStore>,
    ) -> Self {
        Self {
            campaign,
            checkpoints,
            candidates: Mutex::new(CampaignRunExactCheckpointCatalog::new(
                MAX_CAMPAIGN_RUN_EXACT_CHECKPOINTS,
            )),
        }
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
        self.candidates
            .lock()
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?
            .retain(checkpoint, configuration)
    }
}

impl FindingExactRetentionSource for CampaignRunFindingExactRetentionSource {
    fn candidate_checkpoints(
        &self,
        configuration: ConfigurationId,
        maximum_candidates: usize,
    ) -> Result<Vec<ExactCheckpointId>, FindingExactCandidateInventoryError> {
        self.candidates
            .lock()
            .map_err(|_| FindingExactCandidateInventoryError::Unavailable)?
            .candidates(configuration, maximum_candidates)
    }
}

impl FindingExactCheckpointAuthenticator for CampaignRunFindingExactRetentionSource {
    fn authenticate_finding_assertion_boundary(
        &self,
        checkpoint: ExactCheckpointId,
        boundary: &FindingAssertionFailureBoundary,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
    ) -> Result<(), FindingExactCheckpointAuthenticationError> {
        ExactFindingCheckpointAuthenticator::new(&self.campaign, &self.checkpoints)
            .authenticate_finding_assertion_boundary(
                checkpoint,
                boundary,
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
        object: crucible_cas::content_store::ContentId,
    ) -> Result<crucible_cas::content_store::BlobHandle, FindingExactCheckpointAuthenticationError>
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
    let (boundary, assertion_boundary) = match observation.observation().stop() {
        StopOutcome::ObservationReached(proof) => (
            Some((
                proof.event_log().events(),
                Some(proof.boundary().start_events()),
            )),
            None,
        ),
        StopOutcome::AssertionFailure(property) => {
            let witness = execution.and_then(|execution| {
                assertion_failure_boundary(input, result, execution, property)
            });
            let boundary = witness.as_ref().map(|witness| {
                (
                    witness.terminal_events(),
                    Some(witness.quantum_start_events()),
                )
            });
            (boundary, witness)
        }
        _ => (None, None),
    };
    select_finding_exact_retention(
        basis,
        retention_policy.exact_findings(),
        source,
        input.lineage().scenario(),
        input.lineage().scenario_content(),
        observation.child().configuration(),
        boundary,
        assertion_boundary,
    )
}

fn assertion_failure_boundary(
    input: &CrucibleAttemptExecution,
    result: &PreparedSemanticAttemptResult,
    execution: &QemuAttemptExecutionEvidenceSnapshot,
    property: &str,
) -> Option<FindingAssertionFailureBoundary> {
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
    let (trace, _) = matching.next()?;
    if matching.next().is_some() || measurement_ids.len() != 1 {
        return None;
    }

    let transition = verified_assertion_transition(entries, quantum_start_events, property)?;

    FindingAssertionFailureBoundary::new(
        trace,
        crate::crucible_measurement::observation_event_prefix_digest(entries),
        terminal_events,
        quantum_start_events,
        transition.sequence(),
        CampaignHash::from_bytes(transition.content_hash().bytes),
        property.to_owned(),
    )
    .ok()
}

fn select_finding_exact_retention(
    basis: AttemptRetentionPolicyBasis,
    exact_findings: bool,
    source: &dyn FindingExactRetentionSource,
    scenario: ScenarioDefId,
    scenario_artifact: ScenarioArtifactId,
    configuration: ConfigurationId,
    boundary: Option<(u64, Option<u64>)>,
    assertion_boundary: Option<FindingAssertionFailureBoundary>,
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
    let (failure_events, measurement_events) = match boundary {
        Some(boundary) => boundary,
        None => return incomplete(FindingExactRetentionIncomplete::MissingSafeBoundaryCapture),
    };

    let mut candidates = Vec::with_capacity(roots.len());
    let mut remaining_metadata = MAX_FINDING_EXACT_METADATA_BYTES;
    for root in roots {
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
    if let Some(boundary) = assertion_boundary.as_ref() {
        candidates.retain(|candidate| {
            source
                .authenticate_finding_assertion_boundary(
                    candidate.checkpoint(),
                    boundary,
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
    let evidence = match assertion_boundary {
        Some(boundary) => match evidence.with_assertion_boundary(boundary) {
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

    use crucible::{AssertionId, VirtualTime};
    use crucible_cas::content_store::{ContentId, ObjectKind};

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
        ) -> Result<Vec<ExactCheckpointId>, FindingExactCandidateInventoryError> {
            match &self.inventory {
                TestInventory::Roots(roots) => Ok(roots.clone()),
                TestInventory::Failure(error) => Err(*error),
            }
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
        ) -> Result<Vec<ExactCheckpointId>, FindingExactCandidateInventoryError> {
            self.inner
                .candidate_checkpoints(configuration, maximum_candidates)
        }
    }

    impl FindingExactCheckpointAuthenticator for PrefixSource {
        fn authenticate_finding_assertion_boundary(
            &self,
            checkpoint: ExactCheckpointId,
            boundary: &FindingAssertionFailureBoundary,
            _scenario: ScenarioDefId,
            _scenario_artifact: ScenarioArtifactId,
            _configuration: ConfigurationId,
        ) -> Result<(), FindingExactCheckpointAuthenticationError> {
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
            5,
            label,
        ))?)
    }

    #[test]
    fn campaign_catalog_bounds_matching_roots_after_configuration_partitioning()
    -> Result<(), Box<dyn Error>> {
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
        assert_eq!(catalog.candidates(matching, 4_096)?, vec![retained]);
        assert_eq!(
            catalog.candidates(unrelated, 4_096),
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
            bounded.candidates(unrelated, 4_096),
            Err(FindingExactCandidateInventoryError::LimitExceeded),
        );
        let mut expected = vec![retained, admitted];
        expected.sort();
        assert_eq!(bounded.candidates(matching, 4_096)?, expected);

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
            globally_bounded.candidates(last_configuration, 4_096),
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
    fn assertion_boundary_requires_one_dense_violated_transition_in_terminal_quantum() {
        let unrelated = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            AssertionId::from_name("unrelated"),
            AssertionPhase::Violated,
        );
        let target = SchedulerEventLogEntry::assertion_state_observation(
            1,
            VirtualTime { ticks: 2 },
            AssertionId::from_name("target"),
            AssertionPhase::Violated,
        );
        let entries = vec![unrelated.clone(), target.clone()];

        assert_eq!(
            verified_assertion_transition(&entries, 1, "target"),
            Some(&target),
        );
        assert!(verified_assertion_transition(&entries, 1, "unrelated").is_none());
        assert!(verified_assertion_transition(&entries, 2, "target").is_none());

        let duplicate = SchedulerEventLogEntry::assertion_state_observation(
            2,
            VirtualTime { ticks: 2 },
            AssertionId::from_name("target"),
            AssertionPhase::Violated,
        );
        assert!(
            verified_assertion_transition(&[unrelated, target, duplicate], 1, "target").is_none()
        );
        assert!(verified_assertion_transition(&[entries[1].clone()], 0, "target").is_none());
    }

    #[test]
    fn assertion_retention_excludes_lower_id_divergent_same_count_root()
    -> Result<(), Box<dyn Error>> {
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
            .collect::<Vec<_>>();
        let mut divergent_log = matching_log.clone();
        divergent_log[0] = SchedulerEventLogEntry::assertion_state_observation(
            0,
            VirtualTime { ticks: 1 },
            AssertionId::from_name("foreign"),
            AssertionPhase::Satisfied,
        );
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

        let (pins, prepared) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario,
            scenario_artifact,
            configuration,
            Some((5, Some(2))),
            Some(boundary),
        )?;

        assert_eq!(
            disposition(&prepared)?,
            FindingExactRetentionDisposition::Complete
        );
        assert_eq!(pins.post_failure(), &BTreeSet::from([matching]));
        let evidence = prepared.evidence.ok_or("missing selected evidence")?;
        assert_eq!(evidence.captured_failure(), matching);
        assert_eq!(evidence.candidates().len(), 1);
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
            Some((5, Some(4))),
            None,
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
        let directory = tempfile::tempdir()?;
        let fixture =
            crucible_api::build_exact_ram_production_checkpoint_codec_fixture(directory.path())?;
        let repository_backend = Arc::new(crucible_cas::content_store::MemoryBlobBackend::new(
            "campaign-run-exact-retention-integration",
            u64::MAX,
        ));
        let repository = Arc::new(CampaignRepository::new(
            repository_backend,
            Arc::new(crucible_cas::content_store::MemoryRefBackend::new()),
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
        let checkpoint_backend = Arc::new(crucible_cas::content_store::DirectoryBlobBackend::new(
            "campaign-run-exact-retention-checkpoints",
            checkpoint_directory.path(),
        ));
        let checkpoints = Arc::new(ExactCheckpointStore::new(checkpoint_backend, u64::MAX)?);
        let prepared = checkpoints.prepare_production_closure(fixture.closure().clone())?;
        let checkpoint = checkpoints.publish_production_closure(&prepared)?.root();
        let source = CampaignRunFindingExactRetentionSource::new(
            CampaignExecutorStore::new(repository),
            checkpoints,
        );
        source.retain_checkpoint(checkpoint)?;
        let loaded = Arc::new(source.checkpoints.load_attempt_checkpoint(checkpoint)?);
        let stored_scenario = source.campaign.load_scenario_artifact(scenario_artifact)?;
        let decoded_source = crate::decode_crucible_scenario_artifact(&stored_scenario)?;
        let decoded_checkpoint = loaded.decode_semantic_checkpoint(
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

        let (pins, prepared) = select_finding_exact_retention(
            basis()?,
            true,
            &source,
            scenario_id,
            scenario_artifact,
            configuration,
            Some((authenticated.event_count(), None)),
            None,
        )?;

        assert_eq!(
            disposition(&prepared)?,
            FindingExactRetentionDisposition::Complete
        );
        assert_eq!(pins.post_failure().len(), 1);
        assert!(pins.post_failure().contains(&checkpoint));
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
                boundary,
                None,
            )?;
            assert_eq!(disposition(&prepared)?, expected);
        }
        Ok(())
    }
}
