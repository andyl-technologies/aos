//! Snapshot ancestry replay, command lookup, and lifecycle projection.

use super::*;

impl CampaignRepository {
    pub(super) fn find_derivation_result(
        &self,
        content_id: ContentId,
        derivation: CampaignDerivation,
    ) -> Result<Option<CampaignDerivationResult>, CampaignRepositoryError> {
        let checkpoint = self.load_validation_checkpoint(content_id)?;
        let Some(found) = checkpoint.derived_branch else {
            return Ok(None);
        };
        if found.derivation != derivation {
            return Ok(None);
        }
        Ok(Some(CampaignDerivationResult {
            source_snapshot: derivation.source(),
            new_snapshot: CampaignSnapshotId::from_content_id(found.snapshot)?,
            active_policy: derivation.active_policy(),
            replayed: true,
        }))
    }

    pub(super) fn find_choice_discovery_result(
        &self,
        content_id: ContentId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
    ) -> Result<Option<ChoiceDiscoveryResult>, CampaignRepositoryError> {
        let key = choice_discovery_result_key(parent, opportunity);
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        let CampaignFact::ChoiceOpportunityDiscovered {
            parent: fact_parent,
            branch_point,
            opportunity: fact_opportunity,
        } = fact
        else {
            return Err(integrity("choice-discovery-result-index-type-mismatch"));
        };
        if fact_parent != parent || fact_opportunity != opportunity {
            return Err(integrity("choice-discovery-result-index-input-mismatch"));
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("choice-discovery-transition-has-no-parent"))?;
        Ok(Some(ChoiceDiscoveryResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            parent,
            branch_point,
            opportunity,
            replayed: true,
        }))
    }

    pub(super) fn insert_fact(
        &self,
        root: MerkleMapRoot,
        fact: &CampaignFact,
        content: ContentId,
    ) -> Result<MerkleMapRoot, CampaignRepositoryError> {
        self.merkle
            .insert(
                root.content_id(),
                map_key_content("accounting.fact", fact.id()?.content_id()),
                content,
            )
            .map_err(CampaignRepositoryError::from)
    }

    pub(super) fn find_command_result(
        &self,
        content_id: ContentId,
        request: &ControlRequest,
        replayed: bool,
    ) -> Result<CampaignCommandResult, CampaignRepositoryError> {
        let key = mutation_result_hash_key("control", request.command.as_hash());
        let (result_content, loaded, fact) = self.mutation_result_snapshot(content_id, key)?;
        let CampaignFact::ControlRequested(candidate) = fact else {
            return Err(integrity("control-result-index-type-mismatch"));
        };
        if candidate != *request {
            return Err(CampaignRepositoryError::CommandReuse);
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("control-result-has-no-parent"))?;
        Ok(CampaignCommandResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            replayed,
        })
    }

    pub(super) fn find_branch_request_result(
        &self,
        content_id: ContentId,
        request: BranchRequestId,
    ) -> Result<Option<BranchRequestResult>, CampaignRepositoryError> {
        let key = mutation_result_content_key("branch-request", request.content_id());
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        if fact != CampaignFact::BranchRequestIssued(request) {
            return Err(integrity("branch-request-result-index-type-mismatch"));
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("branch-request-transition-has-no-parent"))?;
        Ok(Some(BranchRequestResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            request,
            replayed: true,
        }))
    }

    pub(super) fn find_proposal_result(
        &self,
        content_id: ContentId,
        proposal: ProposalId,
    ) -> Result<Option<ProposalResult>, CampaignRepositoryError> {
        let key = mutation_result_content_key("proposal", proposal.content_id());
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        if fact != CampaignFact::ProposalIssued(proposal) {
            return Err(integrity("proposal-result-index-type-mismatch"));
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("proposal-transition-has-no-parent"))?;
        Ok(Some(ProposalResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            proposal,
            replayed: true,
        }))
    }

    pub(super) fn find_attempt_admission_result(
        &self,
        content_id: ContentId,
        proposal: ProposalId,
    ) -> Result<Option<AttemptAdmissionResult>, CampaignRepositoryError> {
        let key = mutation_result_content_key("admission", proposal.content_id());
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        let CampaignFact::AttemptAdmitted(admission_id) = fact else {
            return Err(integrity("admission-result-index-type-mismatch"));
        };
        let admission = self.read_attempt_admission(admission_id.content_id())?;
        let candidate = match admission.role() {
            AttemptAdmissionRole::ExecutionBasis { proposal, .. } => proposal,
            AttemptAdmissionRole::AdditionalCause { proposal } => Some(proposal),
        };
        if candidate != Some(proposal) {
            return Err(integrity("admission-result-index-proposal-mismatch"));
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("attempt-admission-transition-has-no-parent"))?;
        Ok(Some(AttemptAdmissionResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            proposal,
            attempt: admission.attempt(),
            admission: admission_id,
            replayed: true,
        }))
    }

    pub(super) fn find_planner_step_result(
        &self,
        content_id: ContentId,
        invocation: PlannerInvocationId,
    ) -> Result<Option<PlannerStepResult>, CampaignRepositoryError> {
        let key = mutation_result_content_key("planner", invocation.content_id());
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        let CampaignFact::PlannerAdvanced(step_id) = fact else {
            return Err(integrity("planner-result-index-type-mismatch"));
        };
        let step = self.read_planner_step(step_id.content_id())?;
        if step.invocation() != invocation {
            return Err(integrity("planner-result-index-invocation-mismatch"));
        }
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("planner-step-transition-has-no-parent"))?;
        Ok(Some(PlannerStepResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            step: step_id,
            replayed: true,
        }))
    }

    pub(super) fn find_observation_result(
        &self,
        content_id: ContentId,
        observation: ObservationId,
    ) -> Result<Option<ObservationResult>, CampaignRepositoryError> {
        let key = mutation_result_content_key("observation", observation.content_id());
        let Ok((result_content, loaded, fact)) = self.mutation_result_snapshot(content_id, key)
        else {
            return Ok(None);
        };
        if fact != CampaignFact::ObservationPublished(observation)
            && fact != CampaignFact::ObservationCredited(observation)
        {
            return Err(integrity("observation-result-index-type-mismatch"));
        }
        let record = self.read_observation(observation.content_id())?;
        let canonical_content = self
            .merkle
            .get(
                loaded.snapshot.roots().observations,
                map_key_content("observations.attempt", record.attempt().content_id()),
            )?
            .ok_or_else(|| integrity("observation-result-has-no-canonical-attempt-index"))?;
        let disposition = if canonical_content == observation.content_id() {
            ObservationDisposition::Canonical
        } else {
            ObservationDisposition::DeterminismConflict {
                canonical: ObservationId::from_content_id(canonical_content)?,
            }
        };
        let prior_snapshot = loaded
            .snapshot
            .parent()
            .ok_or_else(|| integrity("observation-transition-has-no-parent"))?;
        Ok(Some(ObservationResult {
            prior_snapshot,
            new_snapshot: CampaignSnapshotId::from_content_id(result_content)?,
            observation,
            disposition,
            replayed: true,
        }))
    }

    pub(super) fn parent_result_upsert(
        &self,
        content_id: ContentId,
        loaded: &LoadedSnapshot,
    ) -> Result<Option<(CampaignHash, ContentId)>, CampaignRepositoryError> {
        let Some(transition_content) = optional_child(&loaded.envelope, "transition") else {
            return Ok(None);
        };
        let fact = self.read_fact(transition_content)?;
        Ok(self
            .mutation_result_key(&fact)?
            .map(|key| (key, content_id)))
    }

    pub(super) fn coordination_with_parent_result(
        &self,
        content_id: ContentId,
        loaded: &LoadedSnapshot,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let root = loaded.snapshot.roots().coordination;
        let Some((key, value)) = self.parent_result_upsert(content_id, loaded)? else {
            return Ok(root);
        };
        Ok(self.merkle.insert(root, key, value)?.content_id())
    }

    pub(super) fn coordination_matches_parent_result(
        &self,
        parent: &LoadedSnapshot,
        next: ContentId,
    ) -> Result<bool, CampaignRepositoryError> {
        let parent_content = parent.envelope.content_id();
        let upserts = self
            .parent_result_upsert(parent_content, parent)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        self.merkle
            .equals_after_upserts(parent.snapshot.roots().coordination, next, &upserts)
            .map_err(CampaignRepositoryError::from)
    }

    fn mutation_result_snapshot(
        &self,
        current_content: ContentId,
        key: CampaignHash,
    ) -> Result<(ContentId, LoadedSnapshot, CampaignFact), CampaignRepositoryError> {
        let current = self.read_snapshot(current_content)?;
        if let Some(transition_content) = optional_child(&current.envelope, "transition") {
            let fact = self.read_fact(transition_content)?;
            if self.mutation_result_key(&fact)? == Some(key) {
                return Ok((current_content, current, fact));
            }
        }

        let result_content = self
            .merkle
            .get(current.snapshot.roots().coordination, key)?
            .ok_or_else(|| integrity("mutation-result-index-missing"))?;
        let loaded = self.read_snapshot(result_content)?;
        let transition_content = optional_child(&loaded.envelope, "transition")
            .ok_or_else(|| integrity("mutation-result-index-target-has-no-transition"))?;
        let fact = self.read_fact(transition_content)?;
        if self.mutation_result_key(&fact)? != Some(key) {
            return Err(integrity("mutation-result-index-key-mismatch"));
        }
        Ok((result_content, loaded, fact))
    }

    fn mutation_result_key(
        &self,
        fact: &CampaignFact,
    ) -> Result<Option<CampaignHash>, CampaignRepositoryError> {
        let key = match fact {
            CampaignFact::CampaignDerived(derivation) => {
                mutation_result_hash_key("derivation", derivation.basis_digest())
            }
            CampaignFact::ControlRequested(request) => {
                mutation_result_hash_key("control", request.command.as_hash())
            }
            CampaignFact::BranchRequestIssued(request) => {
                mutation_result_content_key("branch-request", request.content_id())
            }
            CampaignFact::ProposalIssued(proposal) => {
                mutation_result_content_key("proposal", proposal.content_id())
            }
            CampaignFact::AttemptAdmitted(admission) => {
                let admission = self.read_attempt_admission(admission.content_id())?;
                let proposal = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => return Ok(None),
                };
                mutation_result_content_key("admission", proposal.content_id())
            }
            CampaignFact::PlannerAdvanced(step) => {
                let step = self.read_planner_step(step.content_id())?;
                mutation_result_content_key("planner", step.invocation().content_id())
            }
            CampaignFact::ObservationPublished(observation)
            | CampaignFact::ObservationCredited(observation) => {
                mutation_result_content_key("observation", observation.content_id())
            }
            CampaignFact::ChoiceOpportunityDiscovered {
                parent,
                opportunity,
                ..
            } => choice_discovery_result_key(*parent, *opportunity),
            _ => return Ok(None),
        };
        Ok(Some(key))
    }
}
