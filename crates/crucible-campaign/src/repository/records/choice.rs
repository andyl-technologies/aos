//! Envelope, policy, and choice-reference authentication.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn require_record_kind(
        &self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
    ) -> Result<ObjectEnvelope, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok(envelope)
    }

    pub(super) fn require_record_kind_with_canonical_byte_limit(
        &self,
        id: ContentId,
        expected: crate::CampaignRecordKind,
        remaining_canonical_bytes: usize,
        maximum_canonical_bytes: usize,
    ) -> Result<(ObjectEnvelope, usize), CampaignRepositoryError> {
        let source = self.blobs.read(id, None)?;
        let source_bytes = usize::try_from(source.logical_length()).map_err(|_| {
            CampaignRepositoryError::SelectionResolutionBudgetExceeded {
                maximum_canonical_bytes,
            }
        })?;
        if source.logical_length() > MAX_ENVELOPE_BYTES {
            return Err(StoreError::Quota.into());
        }
        if source_bytes > remaining_canonical_bytes {
            return Err(CampaignRepositoryError::SelectionResolutionBudgetExceeded {
                maximum_canonical_bytes,
            });
        }
        let bytes = source.read_all(source.logical_length())?;
        let envelope = ObjectEnvelope::from_canonical_bytes(&bytes)?;
        if envelope.content_id() != id {
            return Err(integrity("envelope-content-id-mismatch"));
        }
        if envelope.record_kind() != expected {
            return Err(integrity("campaign-child-record-kind-mismatch"));
        }
        Ok((envelope, source_bytes))
    }

    pub(in crate::repository) fn validate_policy_artifact_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let artifact = crate::codec::decode::<PolicyArtifact>(envelope.body())?;
        self.require_record_kind(
            artifact.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_state_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let state = crate::codec::decode::<PlannerState>(envelope.body())?;
        self.require_record_kind(
            state.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        Ok(())
    }

    pub(in crate::repository) fn validate_planner_invocation_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let invocation = crate::codec::decode::<PlannerInvocation>(envelope.body())?;
        self.require_record_kind(
            invocation.engine().content_id(),
            crate::CampaignRecordKind::PlannerEngine,
        )?;
        let artifact_envelope = self.require_record_kind(
            invocation.policy_artifact().content_id(),
            crate::CampaignRecordKind::PolicyArtifact,
        )?;
        let artifact = crate::codec::decode::<PolicyArtifact>(artifact_envelope.body())?;
        self.require_record_kind(
            invocation.policy().content_id(),
            crate::CampaignRecordKind::Policy,
        )?;
        let state_envelope = self.require_record_kind(
            invocation.planner_state().content_id(),
            crate::CampaignRecordKind::PlannerState,
        )?;
        let state = crate::codec::decode::<PlannerState>(state_envelope.body())?;
        self.require_record_kind(
            invocation.input_view().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if artifact.engine() != invocation.engine() || state.engine() != invocation.engine() {
            return Err(integrity("planner-invocation-engine-mismatch"));
        }
        for position in invocation
            .scan_page()
            .after()
            .into_iter()
            .chain(invocation.scan_page().positions().iter().copied())
        {
            let request = self.decode_branch_request(position.source().content_id())?;
            if request.branch_point() != position.branch_point() {
                return Err(integrity(
                    "planner-invocation-scan-position-branch-point-mismatch",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn read_selectable(
        &self,
        id: ContentId,
    ) -> Result<SelectableDeclaration, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::SelectableDeclaration {
            return Err(integrity("selectable-envelope-shape"));
        }
        let selectable = SelectableDeclaration::from_canonical_bytes(envelope.body())?;
        if selectable.id()?.content_id() != id {
            return Err(integrity("selectable-envelope-shape"));
        }
        Ok(selectable)
    }

    pub(in crate::repository) fn read_choice_domain(
        &self,
        id: ContentId,
    ) -> Result<ChoiceDomain, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceDomain {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        let domain = ChoiceDomain::from_canonical_bytes(envelope.body())?;
        if domain.id()?.content_id() != id {
            return Err(integrity("choice-domain-envelope-shape"));
        }
        Ok(domain)
    }

    pub(in crate::repository) fn validate_group_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        let mut declarations = BTreeMap::new();
        for id in group.members() {
            declarations.insert(*id, self.read_selectable(id.content_id())?);
        }
        group.validate_declarations(&declarations)?;
        Ok(())
    }

    pub(in crate::repository) fn read_group(
        &self,
        id: ContentId,
    ) -> Result<ChoiceGroup, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::ChoiceGroup)?;
        let group = crate::codec::decode::<ChoiceGroup>(envelope.body())?;
        if group.id()?.content_id() != id {
            return Err(integrity("choice-group-envelope-shape"));
        }
        self.validate_group_references(&envelope)?;
        Ok(group)
    }

    pub(in crate::repository) fn read_opportunity(
        &self,
        id: ContentId,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        self.read_opportunity_cached(id, &mut ChoiceValidationCache::default())
    }

    pub(in crate::repository) fn read_opportunity_cached(
        &self,
        id: ContentId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        let envelope = self.read_envelope(id)?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        self.validate_opportunity_references_cached(&envelope, cache)
    }

    /// Loads one opportunity and each exact dependency once for a bounded read.
    pub(crate) fn load_choice_opportunity_dependencies(
        &self,
        id: ChoiceOpportunityId,
    ) -> Result<(ChoiceOpportunity, SelectableDeclaration, ChoiceDomain), CampaignRepositoryError>
    {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()? != id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let declaration = self.read_selectable(opportunity.declaration().content_id())?;
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok((opportunity, declaration, domain))
    }

    pub(in crate::repository) fn validate_opportunity_references_cached(
        &self,
        envelope: &ObjectEnvelope,
        cache: &mut ChoiceValidationCache,
    ) -> Result<ChoiceOpportunity, CampaignRepositoryError> {
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()?.content_id() != envelope.content_id() {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let key = (
            opportunity.declaration().content_id(),
            opportunity.domain().content_id(),
        );
        let contract = opportunity.reference_contract_hash();
        if let Some(validated) = cache.get(&key) {
            if validated != contract {
                return Err(integrity("choice-opportunity-cached-reference-mismatch"));
            }
            return Ok(opportunity);
        }

        let declaration = self.read_selectable(key.0)?;
        let domain = self.read_choice_domain(key.1)?;
        opportunity.validate_references(&declaration, &domain)?;
        cache.insert(key, contract);
        Ok(opportunity)
    }

    pub(in crate::repository) fn validate_selection_references(
        &self,
        envelope: &ObjectEnvelope,
    ) -> Result<(), CampaignRepositoryError> {
        let selection = Selection::from_canonical_bytes(envelope.body())?;
        let opportunity = self.read_opportunity(required_child(envelope, "opportunity")?)?;
        let domain = self.read_choice_domain(required_child(envelope, "domain")?)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok(())
    }

    pub(in crate::repository) fn lock_mutation(
        &self,
    ) -> Result<RepositoryMutationGuard<'_>, CampaignRepositoryError> {
        let local = self
            .mutation_lock
            .lock()
            .map_err(|_| CampaignRepositoryError::Poisoned)?;
        let publication = self.refs.acquire_publication_guard()?;
        Ok(RepositoryMutationGuard {
            _local: local,
            _publication: publication,
        })
    }
}
