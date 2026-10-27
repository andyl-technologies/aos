//! Savepoint successor validation over explicit checked or compatibility reads.

use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(super) fn savepoint_capture_request_in_loaded_cached(
        &mut self,
        loaded: &LoadedSnapshot,
        capture: CampaignFactId,
        cache: &mut ChoiceValidationCache,
    ) -> Result<Option<SavepointCaptureRequest>, CampaignRepositoryError> {
        let Some(content) = self.merkle_get(
            loaded.snapshot.roots().accounting,
            savepoint_capture_request_key(capture),
        )?
        else {
            return Ok(None);
        };
        let CampaignFact::SavepointCaptureRequested(request) = self.read_fact(content)? else {
            return Err(integrity(
                "savepoint-capture-index-value-is-not-capture-request",
            ));
        };
        if content != capture.content_id() {
            return Err(integrity("savepoint-capture-request-index-mismatch"));
        }
        self.validate_persisted_savepoint_capture_cached(loaded, content, &request, cache)?;
        Ok(Some(request))
    }

    pub(super) fn validate_savepoint_capture_basis_cached(
        &mut self,
        parent: &LoadedSnapshot,
        request: &SavepointCaptureRequest,
        cache: &mut ChoiceValidationCache,
    ) -> Result<Attempt, CampaignRepositoryError> {
        let roots = parent.snapshot.roots();
        let artifact = self.read_configuration_artifact(request.configuration.content_id())?;
        if artifact.configuration() != request.semantic_configuration
            || self.merkle_get(
                roots.graph,
                map_key_hash(
                    "graph.configuration",
                    request.semantic_configuration.as_hash(),
                ),
            )? != Some(request.configuration.content_id())
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-configuration-is-not-authoritative",
            });
        }
        request.stop.validate()?;
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if let StopCondition::NamedBoundary(name) = &request.stop
            && !policy.stop_conditions().contains(name)
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-stop-boundary-is-not-in-active-policy",
            });
        }

        let attempt = self.read_attempt_cached(request.attempt.content_id(), cache)?;
        let start_configuration = match attempt.start() {
            AttemptStart::Discover { configuration } => configuration,
            AttemptStart::Branch { parent, .. } => parent,
            AttemptStart::AfterAttempt { reached, .. } => reached,
        };
        if start_configuration != request.configuration || attempt.stop() != &request.stop {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-capture-attempt-does-not-match-request",
            });
        }
        Ok(attempt)
    }

    pub(super) fn validate_savepoint_continuation_basis_cached(
        &mut self,
        parent: &LoadedSnapshot,
        selection: &SavepointContinuationSelection,
        continuation: &Attempt,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if selection.expected_snapshot != parent.snapshot.id()? {
            return Err(integrity(
                "savepoint-continuation-precondition-parent-mismatch",
            ));
        }
        if selection.continuation != continuation.id()? {
            return Err(integrity("savepoint-continuation-id-mismatch"));
        }
        let capture = self
            .savepoint_capture_request_in_loaded_cached(parent, selection.request, cache)?
            .ok_or_else(|| integrity("savepoint-continuation-capture-is-not-in-history"))?;
        if self.merkle_get(
            parent.snapshot.roots().accounting,
            savepoint_capture_resolution_key(selection.request),
        )? != Some(selection.ready.content_id())
        {
            return Err(integrity("savepoint-continuation-ready-is-not-current"));
        }
        let CampaignFact::SavepointCaptureResolved(ready) =
            self.read_fact(selection.ready.content_id())?
        else {
            return Err(integrity("savepoint-continuation-ready-fact-type-mismatch"));
        };
        if ready.request != selection.request || ready.outcome != SavepointCaptureOutcome::Ready {
            return Err(integrity("savepoint-continuation-ready-fact-mismatch"));
        }

        let AttemptStart::AfterAttempt { origin, reached } = continuation.start() else {
            return Err(integrity("savepoint-continuation-attempt-start-mismatch"));
        };
        if origin != capture.attempt {
            return Err(integrity("savepoint-continuation-origin-mismatch"));
        }
        let origin = self.read_attempt_cached(origin.content_id(), cache)?;
        if origin.path() != continuation.path() {
            return Err(integrity("savepoint-continuation-path-mismatch"));
        }

        let lineage = self.read_lineage(parent.snapshot.lineage().content_id())?;
        let reached = self.read_configuration_artifact(reached.content_id())?;
        if reached.scenario() != lineage.scenario()
            || reached.scenario_artifact() != lineage.scenario_content()
        {
            return Err(integrity("savepoint-continuation-reached-lineage-mismatch"));
        }
        continuation.stop().validate()?;
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if let StopCondition::NamedBoundary(name) = continuation.stop()
            && !policy.stop_conditions().contains(name)
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "savepoint-continuation-stop-boundary-is-not-in-active-policy",
            });
        }
        Ok(())
    }

    pub(super) fn validate_persisted_savepoint_capture_cached(
        &mut self,
        snapshot: &LoadedSnapshot,
        transition_content: ContentId,
        request: &SavepointCaptureRequest,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        if self.merkle_get(
            roots.accounting,
            savepoint_capture_request_key(CampaignFactId::from_content_id(transition_content)?),
        )? != Some(transition_content)
        {
            return Err(integrity("savepoint-capture-persisted-index-mismatch"));
        }
        let attempt = self.read_attempt_cached(request.attempt.content_id(), cache)?;
        let start_configuration = match attempt.start() {
            AttemptStart::Discover { configuration } => configuration,
            AttemptStart::Branch { parent, .. } => parent,
            AttemptStart::AfterAttempt { reached, .. } => reached,
        };
        if start_configuration != request.configuration || attempt.stop() != &request.stop {
            return Err(integrity("savepoint-capture-persisted-attempt-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_savepoint_capture_successor(
        &mut self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &SavepointCaptureRequest,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("savepoint-capture-changed-lineage-or-policy"));
        }
        self.validate_savepoint_capture_basis_cached(parent, request, cache)?;

        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity("savepoint-capture-changed-unrelated-root"));
        }
        let transition_id = CampaignFactId::from_content_id(transition_content)?;
        let accounting_entries = [
            (
                map_key_hash("accounting.command", request.command.as_hash()),
                transition_content,
            ),
            (
                savepoint_capture_request_key(transition_id),
                transition_content,
            ),
        ];
        let mut accounting_upserts = BTreeMap::new();
        for (key, value) in accounting_entries {
            self.insert_map(&mut accounting_upserts, key, value)?;
        }
        if !self.merkle_equals_after_upserts(
            prior.accounting,
            next.accounting,
            &accounting_upserts,
        )? {
            return Err(integrity("savepoint-capture-accounting-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("savepoint-capture-coordination-root-mismatch"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_savepoint_capture_resolution_successor(
        &mut self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        resolution: &SavepointCaptureResolution,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "savepoint-capture-resolution-changed-lineage-or-policy",
            ));
        }
        if resolution.expected_snapshot != parent.snapshot.id()? {
            return Err(integrity(
                "savepoint-capture-resolution-precondition-parent-mismatch",
            ));
        }
        self.savepoint_capture_request_in_loaded_cached(parent, resolution.request, cache)?
            .ok_or_else(|| {
                integrity("savepoint-capture-resolution-request-is-not-in-parent-history")
            })?;
        let prior_resolution = self.merkle_get(
            parent.snapshot.roots().accounting,
            savepoint_capture_resolution_key(resolution.request),
        )?;
        validate_resolution_predecessor(prior_resolution)
            .map_err(|_| integrity("savepoint-capture-resolution-predecessor-mismatch"))?;
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity(
                "savepoint-capture-resolution-changed-unrelated-root",
            ));
        }
        let accounting_entries = [
            (
                map_key_hash("accounting.command", resolution.command.as_hash()),
                transition_content,
            ),
            (
                savepoint_capture_resolution_key(resolution.request),
                transition_content,
            ),
        ];
        let mut accounting_upserts = BTreeMap::new();
        for (key, value) in accounting_entries {
            self.insert_map(&mut accounting_upserts, key, value)?;
        }
        if !self.merkle_equals_after_upserts(
            prior.accounting,
            next.accounting,
            &accounting_upserts,
        )? {
            return Err(integrity(
                "savepoint-capture-resolution-accounting-root-mismatch",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "savepoint-capture-resolution-coordination-root-mismatch",
            ));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_savepoint_continuation_successor(
        &mut self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        selection: &SavepointContinuationSelection,
        cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "savepoint-continuation-changed-lineage-or-policy",
            ));
        }
        let continuation = self.read_attempt_cached(selection.continuation.content_id(), cache)?;
        self.validate_savepoint_continuation_basis_cached(parent, selection, &continuation, cache)?;

        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity("savepoint-continuation-changed-unrelated-root"));
        }

        let basis_key = attempt_execution_basis_key(selection.continuation);
        let source_key = savepoint_continuation_source_key(selection.continuation);
        let indexed_basis = self.merkle_get(prior.accounting, basis_key)?;
        let indexed_source = self.merkle_get(prior.accounting, source_key)?;
        let upsert_entries = [(
            map_key_hash("accounting.command", selection.command.as_hash()),
            transition_content,
        )];
        let mut upserts = BTreeMap::new();
        for (key, value) in upsert_entries {
            self.insert_map(&mut upserts, key, value)?;
        }
        match (indexed_basis, indexed_source) {
            (None, None) => {
                let expected_admission = AttemptAdmission::new(
                    selection.continuation,
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: None,
                        cause: BranchRequestCause::Operator(selection.command),
                        admission_ordinal: self.next_admission_ordinal(prior.accounting)?,
                    },
                    parent.snapshot.active_policy(),
                );
                let admission_content = self
                    .merkle_get(next.accounting, basis_key)?
                    .ok_or_else(|| integrity("savepoint-continuation-admission-is-missing"))?;
                let admission = self.read_attempt_admission_cached(admission_content, cache)?;
                if admission != expected_admission {
                    return Err(integrity("savepoint-continuation-admission-owner-mismatch"));
                }
                for (key, value) in self.attempt_admission_upserts(admission_content, admission)? {
                    self.insert_map(&mut upserts, key, value)?;
                }
                self.insert_map(&mut upserts, source_key, transition_content)?;
            }
            (Some(admission), Some(source)) => {
                let admission = self.read_attempt_admission_cached(admission, cache)?;
                if admission.attempt() != selection.continuation
                    || !matches!(
                        admission.role(),
                        AttemptAdmissionRole::ExecutionBasis { proposal: None, .. }
                    )
                {
                    return Err(integrity("savepoint-continuation-basis-index-mismatch"));
                }
                let CampaignFact::SavepointContinuationSelected(first) = self.read_fact(source)?
                else {
                    return Err(integrity(
                        "savepoint-continuation-source-index-type-mismatch",
                    ));
                };
                if first.continuation != selection.continuation {
                    return Err(integrity("savepoint-continuation-source-index-mismatch"));
                }
            }
            _ => return Err(integrity("savepoint-continuation-index-shape")),
        }
        if !self.merkle_equals_after_upserts(prior.accounting, next.accounting, &upserts)? {
            return Err(integrity("savepoint-continuation-accounting-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "savepoint-continuation-coordination-root-mismatch",
            ));
        }
        Ok(())
    }
}
