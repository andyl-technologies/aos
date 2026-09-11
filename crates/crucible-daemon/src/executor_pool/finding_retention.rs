//! Authenticated exact-checkpoint inventory and finding-retention selection.

use super::*;

pub(super) fn select_finding_exact_retention<L, V>(
    shared: &SharedExecutor<L, V>,
    prepared: &PreparedAttemptResult,
    captured: ExactCheckpointId,
) -> Result<
    (
        FindingExactPins,
        u32,
        crucible_campaign::FindingExactRetentionEvidence,
    ),
    FindingExactRetentionIncomplete,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let finding = prepared
        .result()
        .finding()
        .ok_or(FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let scenario = crate::decode_crucible_scenario_artifact(finding.scenario())
        .map_err(|_| FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let configuration = finding.original_configuration().configuration();

    let candidates = collect_finding_exact_candidates(shared, &scenario, configuration, captured)?;

    select_finding_exact_retention_from_candidates(prepared.result(), captured, &candidates)
}

/// Selects policy-bound exact pins from an authenticated candidate inventory.
pub(crate) fn select_finding_exact_retention_from_candidates(
    result: &crate::PreparedSemanticAttemptResult,
    captured: ExactCheckpointId,
    candidates: &BTreeMap<ExactCheckpointId, u64>,
) -> Result<
    (
        FindingExactPins,
        u32,
        crucible_campaign::FindingExactRetentionEvidence,
    ),
    FindingExactRetentionIncomplete,
> {
    let failure_events = candidates
        .get(&captured)
        .copied()
        .ok_or(FindingExactRetentionIncomplete::CandidateAuthenticationFailed)?;
    let measurement_events = match result.observation().observation().stop() {
        crucible_campaign::StopOutcome::ObservationReached(proof) => {
            Some(proof.boundary().start_events())
        }
        _ => None,
    };
    let boundaries = crate::FindingExactPinBoundaries::new(failure_events, measurement_events)
        .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    let pins = crate::exact_pin_retention::select_finding_exact_pins_from_event_counts(
        boundaries, candidates,
    )
    .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    let authenticated_candidates = u32::try_from(candidates.len())
        .map_err(|_| FindingExactRetentionIncomplete::CandidateLimitExceeded)?;
    let evidence = crucible_campaign::FindingExactRetentionEvidence::new(
        candidates
            .iter()
            .map(|(checkpoint, events)| {
                crucible_campaign::FindingExactRetentionCandidate::new(*checkpoint, *events)
            })
            .collect(),
        captured,
        failure_events,
        measurement_events,
        pins.clone(),
    )
    .map_err(|_| FindingExactRetentionIncomplete::SelectionFailed)?;
    Ok((pins, authenticated_candidates, evidence))
}

fn collect_finding_exact_candidates<L, V>(
    shared: &SharedExecutor<L, V>,
    scenario: &crucible::ScenarioDefForm,
    configuration: crucible_campaign::ConfigurationId,
    captured: ExactCheckpointId,
) -> Result<BTreeMap<ExactCheckpointId, u64>, FindingExactRetentionIncomplete>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let mut candidates =
        FindingExactCandidateAccumulator::new(&shared.checkpoints, scenario, configuration);
    candidates.consider(captured);

    let executor = shared
        .lock_executor()
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    executor
        .supervisor()
        .ledger()
        .visit_checkpoint_roots(&mut |checkpoint| {
            candidates.consider(checkpoint);
        })
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;

    // Destructive campaign GC fences the assignment ledger before the hot
    // fallback catalog. Keep that global order here, and retain the executor
    // lock until the hot inventory is complete so no coupled path can invert it.
    let hot_retention = shared.hot_checkpoint_retention.as_ref().map(Arc::clone);
    let mut hot_fence = hot_retention
        .as_ref()
        .map(|retention| retention.acquire_hot_checkpoint_retention_fence())
        .transpose()
        .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    if let Some(fence) = hot_fence.as_mut() {
        fence
            .visit_fallbacks(&mut |_slot, record| {
                if let HotCheckpointFallback::Exact(checkpoint) = record.fallback() {
                    candidates.consider(checkpoint);
                }
                Ok(())
            })
            .map_err(|_| FindingExactRetentionIncomplete::CandidateInventoryUnavailable)?;
    }

    drop(hot_fence);
    drop(executor);
    candidates.finish()
}

/// Authenticates and bounds exact checkpoints considered for finding retention.
pub(crate) struct FindingExactCandidateAccumulator<'a> {
    checkpoints: &'a ExactCheckpointStore,
    scenario: &'a crucible::ScenarioDefForm,
    configuration: crucible_campaign::ConfigurationId,
    examined: BTreeSet<ExactCheckpointId>,
    examined_root_bytes: u64,
    candidates: BTreeMap<ExactCheckpointId, u64>,
    candidate_limit: bool,
    candidate_authentication_failed: bool,
}

impl<'a> FindingExactCandidateAccumulator<'a> {
    /// Creates an empty candidate inventory bound to one finding configuration.
    pub(crate) fn new(
        checkpoints: &'a ExactCheckpointStore,
        scenario: &'a crucible::ScenarioDefForm,
        configuration: crucible_campaign::ConfigurationId,
    ) -> Self {
        Self {
            checkpoints,
            scenario,
            configuration,
            examined: BTreeSet::new(),
            examined_root_bytes: 0,
            candidates: BTreeMap::new(),
            candidate_limit: false,
            candidate_authentication_failed: false,
        }
    }

    /// Authenticates one checkpoint and retains it when it belongs to this finding.
    pub(crate) fn consider(&mut self, checkpoint: ExactCheckpointId) {
        // New finding evidence is independently verifiable only for the
        // manifest/index production representation.
        if checkpoint.content_id().schema_version() != crate::EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION {
            return;
        }
        if self.examined.contains(&checkpoint) {
            return;
        }
        if self.examined.len() == crate::MAX_FINDING_EXACT_PIN_CANDIDATES {
            self.candidate_limit = true;
            return;
        }
        self.examined.insert(checkpoint);

        let remaining = crate::MAX_FINDING_EXACT_PIN_CANDIDATE_ROOT_BYTES
            .saturating_sub(self.examined_root_bytes);
        let metadata_bytes = match self
            .checkpoints
            .finding_authentication_metadata_bytes(checkpoint, remaining)
        {
            Ok(metadata_bytes) => metadata_bytes,
            Err(crate::ExactCheckpointStoreError::ArtifactLimit { .. }) => {
                self.candidate_limit = true;
                return;
            }
            Err(_) => {
                self.candidate_authentication_failed = true;
                return;
            }
        };
        let Some(examined_root_bytes) = self.examined_root_bytes.checked_add(metadata_bytes) else {
            self.candidate_limit = true;
            return;
        };
        if examined_root_bytes > crate::MAX_FINDING_EXACT_PIN_CANDIDATE_ROOT_BYTES {
            self.candidate_limit = true;
            return;
        }
        self.examined_root_bytes = examined_root_bytes;

        let events = match crate::exact_pin_retention::authenticate_finding_exact_checkpoint(
            self.checkpoints,
            self.scenario,
            self.configuration,
            checkpoint,
        ) {
            Ok(events) => events,
            Err(
                crate::ExactPinRetentionError::CheckpointConfigurationMismatch { .. }
                | crate::ExactPinRetentionError::CheckpointScenarioMismatch { .. },
            ) => return,
            Err(_) => {
                self.candidate_authentication_failed = true;
                return;
            }
        };
        self.candidates.insert(checkpoint, events);
    }

    /// Returns the bounded authenticated inventory or its stable incomplete reason.
    pub(crate) fn finish(
        self,
    ) -> Result<BTreeMap<ExactCheckpointId, u64>, FindingExactRetentionIncomplete> {
        if self.candidate_limit {
            return Err(FindingExactRetentionIncomplete::CandidateLimitExceeded);
        }
        if self.candidate_authentication_failed {
            return Err(FindingExactRetentionIncomplete::CandidateAuthenticationFailed);
        }
        Ok(self.candidates)
    }
}
