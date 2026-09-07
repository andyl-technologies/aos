//! Immutable campaign record publication transactions.

use super::*;

impl CampaignRepository {
    /// Publishes a policy object so a later activation command can name it.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the policy cannot be placed.
    pub fn publish_policy(
        &self,
        policy: &CampaignPolicy,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let content = self.put_policy(policy)?;
        self.verify_campaign_closure(content)?;
        Ok(content)
    }

    /// Publishes a closed candidate-generator specification.
    ///
    /// Child specifications named by an ordered mixture must already exist;
    /// callers normally publish a dependency-ordered set before a policy.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or closure error if the specification cannot
    /// be authenticated and placed.
    pub fn publish_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, CampaignRepositoryError> {
        self.validate_generator_closure_before_publication(generator)?;
        let content = self.put_generator(generator)?;
        self.verify_campaign_closure(content)?;
        CandidateGeneratorSpecId::from_content_id(content).map_err(Into::into)
    }

    /// Authenticates a generator's complete dependency closure before the
    /// immutable parent is written. This keeps a rejected import failure-atomic
    /// while retaining the same count and byte bounds used by campaign creation.
    fn validate_generator_closure_before_publication(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<(), CampaignRepositoryError> {
        let root = generator.id()?;
        let mut visited = BTreeSet::from([root]);
        let mut canonical_bytes = 0_usize;
        charge_creation_generator_bytes(&mut canonical_bytes, generator.canonical_bytes().len())?;
        let mut pending: Vec<_> = generator
            .content_children()
            .into_iter()
            .map(|(_, child)| CandidateGeneratorSpecId::from_content_id(child))
            .collect::<Result<_, _>>()?;

        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            if visited.len() > crate::MAX_CREATE_CAMPAIGN_GENERATORS {
                return Err(integrity("campaign-generator-count-limit"));
            }
            let child = self.read_generator(id.content_id())?;
            charge_creation_generator_bytes(&mut canonical_bytes, child.canonical_bytes().len())?;
            for (_, grandchild) in child.content_children() {
                pending.push(CandidateGeneratorSpecId::from_content_id(grandchild)?);
            }
        }
        Ok(())
    }

    /// Publishes exact canonical scenario bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ScenarioDefId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_scenario_artifact(
        &self,
        scenario: ScenarioDefId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ScenarioArtifactId, CampaignRepositoryError> {
        let artifact = ScenarioArtifact::new(scenario, payload_schema, bytes)?;
        let content = self.put_scenario_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ScenarioArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes exact canonical configuration bytes for use by a lineage.
    ///
    /// The execution-model adapter remains responsible for proving that these
    /// bytes produce the lineage's semantic [`crate::ConfigurationId`].
    ///
    /// # Errors
    ///
    /// Returns a store error if the artifact cannot be authenticated and placed.
    pub fn publish_configuration_artifact(
        &self,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ConfigurationArtifactId, CampaignRepositoryError> {
        let artifact = ConfigurationArtifact::new(
            scenario,
            scenario_artifact,
            configuration,
            payload_schema,
            bytes,
        )?;
        let content = self.put_configuration_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ConfigurationArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes verifier-backed self-contained finding reproduction bytes.
    ///
    /// The execution-model adapter remains responsible for replaying the
    /// payload and proving its semantic identities and failure fingerprint.
    /// This repository boundary authenticates the already-published exact
    /// scenario/configuration basis before the first write.
    ///
    /// # Errors
    ///
    /// Returns a canonical, integrity, or store error when the payload is
    /// invalid, its exact artifact basis is absent or inconsistent, or the
    /// resulting reproduction cannot be placed and authenticated.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_reproduction_artifact(
        &self,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
        payload_schema: u32,
        bytes: Vec<u8>,
    ) -> Result<ReproductionArtifactId, CampaignRepositoryError> {
        let artifact = ReproductionArtifact::new(
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            bytes,
        )?;
        let stored_scenario = self.read_scenario_artifact(scenario_artifact.content_id())?;
        let stored_configuration =
            self.read_configuration_artifact(configuration_artifact.content_id())?;
        if stored_scenario.scenario() != scenario
            || stored_configuration.scenario() != scenario
            || stored_configuration.scenario_artifact() != scenario_artifact
            || stored_configuration.configuration() != configuration
        {
            return Err(integrity("finding-reproduction-artifact-basis-mismatch"));
        }

        let content = self.put_reproduction_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ReproductionArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a minimized reproduction with verifier-retained history.
    ///
    /// The execution-model adapter must have replayed the original, every
    /// candidate, and the final minimized payload before calling this method.
    /// This boundary authenticates the original reproduction and exact artifact
    /// basis before its first write.
    ///
    /// # Errors
    ///
    /// Returns a canonical, integrity, or store error when the trace is
    /// inconsistent, its original or artifact basis is unavailable, or the
    /// resulting record cannot be placed and authenticated.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_minimized_reproduction_artifact(
        &self,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        configuration_artifact: ConfigurationArtifactId,
        finding_fingerprint: CampaignHash,
        payload_schema: u32,
        bytes: Vec<u8>,
        minimization: FindingMinimizationEvidence,
    ) -> Result<ReproductionArtifactId, CampaignRepositoryError> {
        let artifact = ReproductionArtifact::new_minimized(
            scenario,
            scenario_artifact,
            configuration,
            configuration_artifact,
            finding_fingerprint,
            payload_schema,
            bytes,
            minimization,
        )?;
        let original = self.read_reproduction_artifact(
            artifact
                .minimization()
                .ok_or_else(|| integrity("finding-minimization-trace-missing"))?
                .original()
                .content_id(),
        )?;
        let stored_scenario = self.read_scenario_artifact(scenario_artifact.content_id())?;
        let stored_configuration =
            self.read_configuration_artifact(configuration_artifact.content_id())?;
        let minimization = artifact
            .minimization()
            .ok_or_else(|| integrity("finding-minimization-trace-missing"))?;
        let accepted_candidate = minimization
            .attempts()
            .iter()
            .any(|attempt| attempt.accepted());
        if original.minimization().is_some()
            || original.finding_fingerprint() != finding_fingerprint
            || original.scenario() != scenario
            || stored_scenario.scenario() != scenario
            || stored_configuration.scenario() != scenario
            || stored_configuration.scenario_artifact() != scenario_artifact
            || stored_configuration.configuration() != configuration
            || !accepted_candidate
                && (artifact.configuration() != original.configuration()
                    || artifact.configuration_artifact() != original.configuration_artifact()
                    || artifact.payload_schema() != original.payload_schema()
                    || artifact.payload() != original.payload())
        {
            return Err(integrity("finding-minimization-artifact-basis-mismatch"));
        }

        self.verify_campaign_closures_anchored_cached(
            artifact.content_children().into_iter().map(|(_, id)| id),
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        let content = self.put_reproduction_artifact(&artifact)?;
        self.verify_campaign_closure(content)?;
        ReproductionArtifactId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact choice domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the domain cannot be placed and
    /// authenticated.
    pub fn publish_choice_domain(
        &self,
        domain: &ChoiceDomain,
    ) -> Result<ChoiceDomainId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceDomain,
            BTreeSet::new(),
            domain.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceDomainId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes an exact selectable declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical or store error if the declaration cannot be placed
    /// and authenticated.
    pub fn publish_selectable(
        &self,
        selectable: &SelectableDeclaration,
    ) -> Result<SelectableId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::SelectableDeclaration,
            BTreeSet::new(),
            selectable.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectableId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a choice opportunity after resolving its declaration/domain.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if either dependency is
    /// absent or the opportunity's copied semantic fields disagree.
    pub fn publish_choice_opportunity(
        &self,
        opportunity: &ChoiceOpportunity,
    ) -> Result<ChoiceOpportunityId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(opportunity.content_children())?,
            crate::codec::encode(opportunity),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceOpportunityId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a simultaneous choice group after resolving every declaration.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error if a declaration is
    /// absent or disagrees with the group's effective domain.
    pub fn publish_choice_group(
        &self,
        group: &ChoiceGroup,
    ) -> Result<ChoiceGroupId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceGroup,
            crate::object::content_children(group.content_children())?,
            crate::codec::encode(group),
        )?)?;
        self.verify_campaign_closure(content)?;
        ChoiceGroupId::from_content_id(content).map_err(Into::into)
    }

    /// Publishes a selection after validating its opportunity and legal domain.
    ///
    /// Model-sampled selections remain subject to their pure model verifier at
    /// execution time; their self-contained model identity is checked here.
    ///
    /// # Errors
    ///
    /// Returns a canonical, store, or integrity error for an absent dependency,
    /// illegal value, or invalid origin evidence.
    pub fn publish_selection(
        &self,
        selection: &Selection,
    ) -> Result<SelectionId, CampaignRepositoryError> {
        let content = self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::Selection,
            crate::object::content_children(selection.content_children())?,
            selection.canonical_bytes(),
        )?)?;
        self.verify_campaign_closure(content)?;
        SelectionId::from_content_id(content).map_err(Into::into)
    }
}
