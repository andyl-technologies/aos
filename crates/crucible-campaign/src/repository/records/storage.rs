//! Low-level immutable campaign record storage and decoding.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn put_lineage(
        &self,
        lineage: &CampaignLineage,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_lineage(lineage)?)
    }

    pub(in crate::repository) fn put_policy(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_policy(policy)?)
    }

    pub(in crate::repository) fn put_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_branch_request(
        &self,
        request: &BranchRequest,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::BranchRequest,
            request.schema_version(),
            crate::object::content_children(request.content_children())?,
            request.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_continuation_projection(
        &self,
        projection: &ContinuationProjection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ContinuationProjection,
            crate::object::content_children(projection.content_children())?,
            projection.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_expansion_credit(
        &self,
        credit: &ExpansionCredit,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ExpansionCredit,
            crate::object::content_children(credit.content_children())?,
            credit.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_proposal(
        &self,
        proposal: &Proposal,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Proposal,
            proposal.schema_version(),
            crate::object::content_children(proposal.content_children())?,
            proposal.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_selection(
        &self,
        selection: &Selection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(selection.content_children())?,
            selection.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_branch_path(
        &self,
        path: &BranchPath,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_branch_path(path)?)
    }

    pub(in crate::repository) fn put_attempt(
        &self,
        attempt: &Attempt,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Attempt,
            attempt.schema_version(),
            crate::object::content_children(attempt.content_children())?,
            attempt.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_attempt_admission(
        &self,
        admission: &AttemptAdmission,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::AttemptAdmission,
            admission.schema_version(),
            crate::object::content_children(admission.content_children())?,
            admission.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_measurement_set(
        &self,
        value: &MeasurementSet,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_measurement_set(value)?)
    }

    pub(in crate::repository) fn put_property_verdict_set(
        &self,
        value: &PropertyVerdictSet,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PropertyVerdictSet,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_coverage_projection(
        &self,
        value: &CoverageProjection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CoverageProjection,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_observation(
        &self,
        value: &Observation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Observation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_objective_evaluation(
        &self,
        value: &ObjectiveEvaluation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::ObjectiveEvaluation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_ranking_explanation(
        &self,
        value: &RankingExplanation,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::RankingExplanation,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_survivor_selection(
        &self,
        value: &SurvivorSelection,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SurvivorSelection,
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_reproduction_artifact(
        &self,
        value: &ReproductionArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::ReproductionArtifact,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_finding(
        &self,
        value: &Finding,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::Finding,
            value.schema_version(),
            crate::object::content_children(value.content_children())?,
            value.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_scenario_artifact(
        &self,
        artifact: &ScenarioArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ScenarioArtifact,
            BTreeSet::new(),
            artifact.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_configuration_artifact(
        &self,
        artifact: &ConfigurationArtifact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ConfigurationArtifact,
            crate::object::content_children(artifact.content_children())?,
            artifact.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_planner_candidate_guidance(
        &self,
        guidance: &crate::PlannerCandidateGuidance,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::PlannerCandidateGuidance,
            guidance.schema_version(),
            crate::object::content_children(guidance.content_children())?,
            guidance.canonical_bytes(),
        )?)
    }

    pub(in crate::repository) fn put_fact(
        &self,
        fact: &CampaignFact,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_fact(fact)?)
    }

    pub(in crate::repository) fn put_snapshot(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let envelope = ObjectEnvelope::for_snapshot(snapshot)?;
        self.put_envelope(envelope)
    }

    pub(in crate::repository) fn put_envelope(
        &self,
        envelope: ObjectEnvelope,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let id = envelope.content_id();
        let receipt = self
            .blobs
            .put_if_absent(id, &BlobHandle::from_bytes(envelope.canonical_bytes()))?;
        if receipt.id != id {
            return Err(integrity("store-receipt-id-mismatch"));
        }
        Ok(id)
    }

    pub(in crate::repository) fn read_envelope(
        &self,
        id: ContentId,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let bytes = self.blobs.read(id, None)?.read_all(MAX_ENVELOPE_BYTES)?;
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        if envelope.content_id() != id {
            return Err(integrity("envelope-content-id-mismatch"));
        }
        Ok(envelope)
    }

    pub(in crate::repository) fn read_snapshot(
        &self,
        id: ContentId,
    ) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        if id.kind() != ObjectKind::CampaignSnapshot {
            return Err(integrity("snapshot-content-kind"));
        }
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Snapshot {
            return Err(integrity("snapshot-record-kind"));
        }
        let snapshot = CampaignSnapshot::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_snapshot(&snapshot)? != envelope || snapshot.id()?.content_id() != id
        {
            return Err(integrity("snapshot-child-table-mismatch"));
        }
        Ok(LoadedSnapshot { envelope, snapshot })
    }

    pub(in crate::repository) fn read_lineage(
        &self,
        id: ContentId,
    ) -> Result<CampaignLineage, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Lineage {
            return Err(integrity("lineage-envelope-shape"));
        }
        let lineage = CampaignLineage::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_lineage(&lineage)? != envelope || lineage.id()?.content_id() != id {
            return Err(integrity("lineage-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(lineage.scenario_content().content_id())?;
        let genesis = self.read_configuration_artifact(lineage.genesis_content().content_id())?;
        if scenario.scenario() != lineage.scenario()
            || scenario.payload_schema() != lineage.scenario_schema()
            || genesis.scenario() != lineage.scenario()
            || genesis.scenario_artifact() != lineage.scenario_content()
            || genesis.configuration() != lineage.genesis()
        {
            return Err(integrity("lineage-execution-model-artifact-mismatch"));
        }
        Ok(lineage)
    }

    pub(in crate::repository) fn read_scenario_artifact(
        &self,
        id: ContentId,
    ) -> Result<ScenarioArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ScenarioArtifact {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        let artifact = ScenarioArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("scenario-artifact-envelope-shape"));
        }
        Ok(artifact)
    }

    pub(in crate::repository) fn read_configuration_artifact(
        &self,
        id: ContentId,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ConfigurationArtifact {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let artifact = ConfigurationArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("configuration-artifact-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(artifact.scenario_artifact().content_id())?;
        if scenario.scenario() != artifact.scenario() {
            return Err(integrity("configuration-scenario-artifact-mismatch"));
        }
        Ok(artifact)
    }

    pub(crate) fn read_reproduction_artifact(
        &self,
        id: ContentId,
    ) -> Result<ReproductionArtifact, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::ReproductionArtifact)?;
        let artifact = ReproductionArtifact::from_canonical_bytes(envelope.body())?;
        if artifact.id()?.content_id() != id {
            return Err(integrity("finding-reproduction-envelope-shape"));
        }
        let scenario = self.read_scenario_artifact(artifact.scenario_artifact().content_id())?;
        let configuration =
            self.read_configuration_artifact(artifact.configuration_artifact().content_id())?;
        if scenario.scenario() != artifact.scenario()
            || configuration.scenario() != artifact.scenario()
            || configuration.scenario_artifact() != artifact.scenario_artifact()
            || configuration.configuration() != artifact.configuration()
        {
            return Err(integrity("finding-reproduction-artifact-basis-mismatch"));
        }
        Ok(artifact)
    }

    pub(crate) fn read_finding(&self, id: ContentId) -> Result<Finding, CampaignRepositoryError> {
        self.read_finding_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn decode_finding(
        &self,
        id: ContentId,
    ) -> Result<Finding, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Finding)?;
        let finding = Finding::from_canonical_bytes(envelope.body())?;
        if finding.id()?.content_id() != id {
            return Err(integrity("finding-envelope-shape"));
        }
        Ok(finding)
    }

    pub(in crate::repository) fn read_finding_cached(
        &self,
        id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<Finding, CampaignRepositoryError> {
        let finding = self.decode_finding(id)?;
        self.validate_finding_references_cached(&finding, choice_cache)?;
        Ok(finding)
    }

    pub(in crate::repository) fn validate_finding_references_cached(
        &self,
        finding: &Finding,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let observation = self.decode_observation(finding.observation().content_id())?;
        self.validate_observation_references_cached(&observation, choice_cache)?;
        let observation_child =
            self.read_configuration_artifact(observation.child_content().content_id())?;
        let occurrences = self.merkle.inspect_shallow(finding.occurrences())?;
        if occurrences.entry_count() != u64::from(finding.occurrence_count())
            || self.merkle.get(
                finding.occurrences(),
                finding_occurrence_key(finding.observation()),
            )? != Some(finding.observation().content_id())
            || self.merkle.get(
                finding.occurrences(),
                finding_occurrence_key(finding.latest_occurrence()),
            )? != Some(finding.latest_occurrence().content_id())
        {
            return Err(integrity("finding-occurrence-root-mismatch"));
        }
        let reproduction = self.read_reproduction_artifact(finding.reproduction().content_id())?;
        self.read_snapshot(finding.first_seen_snapshot().content_id())?;
        if reproduction.finding_fingerprint() != finding.signature().fingerprint()
            || reproduction.scenario() != observation_child.scenario()
            || reproduction.configuration_artifact() != observation.child_content()
        {
            return Err(integrity("finding-reproduction-observation-basis-mismatch"));
        }
        if finding.latest_occurrence() != finding.observation() {
            let latest = self.decode_observation(finding.latest_occurrence().content_id())?;
            self.validate_observation_references_cached(&latest, choice_cache)?;
            let latest_child =
                self.read_configuration_artifact(latest.child_content().content_id())?;
            if latest_child.scenario() != observation_child.scenario() {
                return Err(integrity("finding-occurrence-scenario-mismatch"));
            }
        }
        if let Some(minimized) = finding.minimized() {
            let minimized = self.read_reproduction_artifact(minimized.content_id())?;
            if minimized.finding_fingerprint() != finding.signature().fingerprint()
                || minimized.scenario() != observation_child.scenario()
            {
                return Err(integrity("finding-minimized-reproduction-basis-mismatch"));
            }
            if finding.schema_version() >= 2 {
                let minimization = minimized
                    .minimization()
                    .ok_or_else(|| integrity("finding-minimized-reproduction-has-no-trace"))?;
                if minimization.original() != finding.reproduction() {
                    return Err(integrity("finding-minimization-original-mismatch"));
                }
            }
        }
        for pin in finding.exact_pins() {
            let handle = self.blobs.read(pin.content_id(), None)?;
            handle.copy_to(&mut std::io::sink())?;
        }
        Ok(())
    }

    pub(in crate::repository) fn read_policy(
        &self,
        id: ContentId,
    ) -> Result<CampaignPolicy, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Policy {
            return Err(integrity("policy-envelope-shape"));
        }
        let policy = CampaignPolicy::from_canonical_bytes(envelope.body())?;
        if ObjectEnvelope::for_policy(&policy)? != envelope || policy.id()?.content_id() != id {
            return Err(integrity("policy-envelope-shape"));
        }
        for (role, child) in policy.content_children() {
            let kind = if role.starts_with("choice-generator.") {
                crate::CampaignRecordKind::CandidateGeneratorSpec
            } else if role.starts_with("statistical-opportunity.") {
                crate::CampaignRecordKind::ChoiceOpportunity
            } else if role.starts_with("statistical-domain.") {
                crate::CampaignRecordKind::ChoiceDomain
            } else {
                return Err(integrity("policy-child-role-is-unknown"));
            };
            self.require_record_kind(child, kind)?;
        }
        Ok(policy)
    }

    pub(in crate::repository) fn read_generator(
        &self,
        id: ContentId,
    ) -> Result<CandidateGeneratorSpec, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::CandidateGeneratorSpec {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        let generator = CandidateGeneratorSpec::from_canonical_bytes(envelope.body())?;
        let expected = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())?,
            generator.canonical_bytes(),
        )?;
        if expected != envelope || generator.id()?.content_id() != id {
            return Err(integrity("candidate-generator-envelope-shape"));
        }
        for (_, child) in generator.content_children() {
            self.require_record_kind(child, crate::CampaignRecordKind::CandidateGeneratorSpec)?;
        }
        Ok(generator)
    }

    pub(in crate::repository) fn read_fact(
        &self,
        id: ContentId,
    ) -> Result<CampaignFact, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::Fact {
            return Err(integrity("fact-envelope-shape"));
        }
        let fact = CampaignFact::from_canonical_bytes(envelope.body())?;
        self.validate_fact_references(&fact)?;
        Ok(fact)
    }

    pub(in crate::repository) fn validate_fact_references(
        &self,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        match fact {
            CampaignFact::CampaignDerived(derivation) => {
                self.require_record_kind(
                    derivation.source().content_id(),
                    crate::CampaignRecordKind::Snapshot,
                )?;
                self.require_record_kind(
                    derivation.active_policy().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
            }
            CampaignFact::ChoiceOpportunityDiscovered {
                parent,
                opportunity,
                ..
            } => {
                self.require_record_kind(
                    parent.content_id(),
                    crate::CampaignRecordKind::ConfigurationArtifact,
                )?;
                self.require_record_kind(
                    opportunity.content_id(),
                    crate::CampaignRecordKind::ChoiceOpportunity,
                )?;
            }
            CampaignFact::PolicyActivated(activation) => {
                self.require_record_kind(
                    activation.prior().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
                self.require_record_kind(
                    activation.next().content_id(),
                    crate::CampaignRecordKind::Policy,
                )?;
            }
            CampaignFact::ControlRequested(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_)
            | CampaignFact::SavepointCaptureRequested(_)
            | CampaignFact::SavepointCaptureResolved(_)
            | CampaignFact::SavepointContinuationSelected(_) => {
                self.validate_command_fact_references(fact)?
            }
            CampaignFact::BranchRequestIssued(id)
            | CampaignFact::BranchRequestAccepted { request: id, .. } => {
                self.read_branch_request(id.content_id())?;
            }
            CampaignFact::PlannerAdvanced(id) => {
                self.read_planner_step(id.content_id())?;
            }
            CampaignFact::ProposalIssued(id) => {
                self.read_proposal(id.content_id())?;
            }
            CampaignFact::AttemptAdmitted(admission) => {
                self.read_attempt_admission(admission.content_id())?;
            }
            CampaignFact::AttemptClosed { attempt, .. } => {
                self.require_record_kind(attempt.content_id(), crate::CampaignRecordKind::Attempt)?;
            }
            CampaignFact::ObservationPublished(id) | CampaignFact::ObservationCredited(id) => {
                self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Observation)?;
            }
            CampaignFact::FindingPublished(id) => {
                self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Finding)?;
            }
            CampaignFact::ObjectiveEvaluationPublished(id) => {
                self.read_objective_evaluation(id.content_id())?;
            }
            CampaignFact::BudgetGranted(_) | CampaignFact::PinChanged(_) => {}
        }
        Ok(())
    }
}
