//! Durable first-choice discovery for an otherwise empty campaign frontier.
//!
//! The coordinator creates at most one initial discovery execution basis. It
//! consumes the first granted attempt, executes an exact campaign-owned
//! configuration along the empty authenticated branch path, and stops at the
//! requested boundary or modeled terminal outcome. Restart observes the same
//! admission sequence rather than manufacturing another job.

use super::*;

const DISCOVERY_ACCOUNTING_PAGE_ITEMS: usize = 128;
const MAX_DISCOVERY_ACCOUNTING_PAGES: usize = 512;

impl CampaignRepository {
    /// Admits one explicit, idempotent discovery of a campaign-owned configuration.
    ///
    /// Command lookup precedes snapshot and policy validation so an exact
    /// replay returns the snapshot that first accepted the request after later
    /// campaign mutations.
    ///
    /// # Errors
    ///
    /// Returns an error for command-ID reuse, stale input, an inactive or
    /// nonempty campaign, a configuration outside its graph, an undeclared named
    /// boundary, exhausted attempt budget, publication failure, or ref conflict.
    pub fn submit_discovery_request(
        &self,
        name: &str,
        request: &DiscoveryRequest,
    ) -> Result<CampaignDiscoveryResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if let Some(fact_content) = self
            .merkle
            .get(current.snapshot.roots().accounting, command_key)?
        {
            let fact = self.read_fact(fact_content)?;
            match fact {
                CampaignFact::DiscoveryRequested(prior_request) if prior_request == *request => {
                    return self.find_discovery_result(current_content, request, true);
                }
                CampaignFact::ControlRequested(_)
                | CampaignFact::BranchRequestIssued(_)
                | CampaignFact::BranchRequestAccepted { .. }
                | CampaignFact::PinCommandAccepted(_)
                | CampaignFact::DiscoveryRequested(_) => {
                    return Err(CampaignRepositoryError::CommandReuse);
                }
                _ => return Err(integrity("command-index-value-is-not-mutation-fact")),
            }
        }

        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        if request.expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: request.expected_snapshot,
                current: current_id,
            });
        }
        let (path, attempt, admission) = self.discovery_request_basis(&current, request)?;
        self.ensure_budget_available(&current, 0, 1)?;

        let path_content = self.put_branch_path(&path)?;
        if path_content != path.id()?.content_id() {
            return Err(integrity("discovery-path-publication-id-mismatch"));
        }
        let attempt_content = self.put_attempt(&attempt)?;
        if attempt_content != attempt.id()?.content_id() {
            return Err(integrity("discovery-attempt-publication-id-mismatch"));
        }
        let admission_content = self.put_attempt_admission(&admission)?;
        if admission_content != admission.id()?.content_id() {
            return Err(integrity("discovery-admission-publication-id-mismatch"));
        }

        let discovery_fact = CampaignFact::DiscoveryRequested(request.clone());
        let transition_content = self.put_fact(&discovery_fact)?;
        let mut upserts = attempt_admission_upserts(admission_content, admission)?;
        upserts.insert(command_key, transition_content);
        let mut accounting = current.snapshot.roots().accounting;
        for (key, value) in upserts {
            accounting = self.merkle.insert(accounting, key, value)?.content_id();
        }

        let mut roots = current.snapshot.roots();
        roots.accounting = accounting;
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition_content)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(CampaignDiscoveryResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    attempt: attempt.id()?,
                    admission: admission.id()?,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Admits initial discovery when a running campaign has no existing work.
    ///
    /// Returns `None` when the campaign is inactive, already has an execution
    /// basis or frontier source, or has no positive attempt grant. A successful
    /// admission returns its immutable identity; subsequent calls are no-ops.
    /// The coordinator invokes this only after an idle executor scan.
    ///
    /// # Errors
    ///
    /// Returns an integrity, bounded accounting-scan, storage, or ref-conflict
    /// error without publishing a campaign head on failure.
    pub fn admit_initial_discovery_if_ready(
        &self,
        name: &str,
    ) -> Result<Option<AttemptId>, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        self.validate_complete_head(current_content)?;
        if self.current_lifecycle(current_content)?.visible != CampaignState::Running {
            return Ok(None);
        }
        let current = self.read_snapshot(current_content)?;
        let Some((path, attempt, admission)) = self.initial_discovery_basis(&current)? else {
            return Ok(None);
        };

        self.put_branch_path(&path)?;
        self.put_attempt(&attempt)?;
        let admission_content = self.put_attempt_admission(&admission)?;
        let mut roots = current.snapshot.roots();
        for (key, value) in attempt_admission_upserts(admission_content, admission)? {
            roots.accounting = self
                .merkle
                .insert(roots.accounting, key, value)?
                .content_id();
        }
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let fact = CampaignFact::AttemptAdmitted(admission.id()?);
        let transition = self.put_fact(&fact)?;
        let next = self.budgeted_successor(
            current.snapshot.id()?,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;
        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(Some(attempt.id()?))
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    /// Recomputes the unique initial basis without publishing any objects.
    pub(super) fn initial_discovery_basis(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<Option<(BranchPath, Attempt, AttemptAdmission)>, CampaignRepositoryError> {
        let roots = parent.snapshot.roots();
        if self
            .merkle
            .get(roots.accounting, admission_sequence_key())?
            .is_some()
        {
            return Ok(None);
        }
        // Recheck durable intent during cold import as well as local admission.
        // This parent has no admission sequence, so validating its lifecycle
        // cannot recursively encounter the discovery successor being checked.
        if self
            .current_lifecycle(parent.envelope.content_id())?
            .visible
            != CampaignState::Running
        {
            return Ok(None);
        }
        // Explicitly seeded campaigns already have authoritative planning work.
        // Do not inject an unrelated discovery ahead of those sources.
        let frontier = self
            .merkle
            .get(roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("initial-discovery-frontier-index-missing"))?;
        let has_budget = if parent.snapshot.budget_ledger().is_some() {
            self.project_campaign_budget(parent)?.remaining_attempts() > 0
        } else {
            self.initial_discovery_has_budget(roots.accounting)?
        };
        if !self.merkle.scan(frontier, None, 1)?.entries().is_empty() || !has_budget {
            return Ok(None);
        }
        let lineage = self.read_lineage(parent.snapshot.lineage().content_id())?;
        let path = BranchPath::new(Vec::new())?;
        let attempt = Attempt::new(
            AttemptStart::Discover {
                configuration: lineage.genesis_content(),
            },
            path.id()?,
            StopCondition::NextChoice,
        )?;
        let admission = AttemptAdmission::new(
            attempt.id()?,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::ExhaustivePolicy(parent.snapshot.active_policy()),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        );
        Ok(Some((path, attempt, admission)))
    }

    pub(super) fn discovery_request_basis(
        &self,
        parent: &LoadedSnapshot,
        request: &DiscoveryRequest,
    ) -> Result<(BranchPath, Attempt, AttemptAdmission), CampaignRepositoryError> {
        let current = parent.snapshot.id()?;
        if request.expected_snapshot != current {
            return Err(integrity("discovery-request-precondition-parent-mismatch"));
        }
        let state = self
            .current_lifecycle(parent.envelope.content_id())?
            .visible;
        if state != CampaignState::Running {
            return Err(CampaignRepositoryError::InvalidTransition { state });
        }

        let roots = parent.snapshot.roots();
        if self
            .merkle
            .get(roots.accounting, admission_sequence_key())?
            .is_some()
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "explicit-discovery-requires-empty-admission-sequence",
            });
        }
        let frontier = self
            .merkle
            .get(roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("discovery-frontier-index-missing"))?;
        if !self.merkle.scan(frontier, None, 1)?.entries().is_empty() {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "explicit-discovery-requires-empty-frontier",
            });
        }

        let lineage = self.read_lineage(parent.snapshot.lineage().content_id())?;
        let configuration = self.read_configuration_artifact(request.configuration.content_id())?;
        if configuration.scenario() != lineage.scenario()
            || configuration.scenario_artifact() != lineage.scenario_content()
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "explicit-discovery-configuration-is-outside-lineage",
            });
        }
        if self.merkle.get(
            roots.graph,
            map_key_hash(
                "graph.configuration",
                configuration.configuration().as_hash(),
            ),
        )? != Some(request.configuration.content_id())
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "explicit-discovery-configuration-is-not-in-campaign-graph",
            });
        }

        request.stop.validate()?;
        let policy = self.read_policy(parent.snapshot.active_policy().content_id())?;
        if let StopCondition::NamedBoundary(name) = &request.stop
            && !policy.stop_conditions().contains(name)
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "explicit-discovery-stop-boundary-is-not-in-active-policy",
            });
        }

        let path = BranchPath::new(Vec::new())?;
        let attempt = Attempt::new(
            AttemptStart::Discover {
                configuration: request.configuration,
            },
            path.id()?,
            request.stop.clone(),
        )?;
        let admission = AttemptAdmission::new(
            attempt.id()?,
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause: BranchRequestCause::Operator(request.command),
                admission_ordinal: AdmissionOrdinal::new(1),
            },
        );
        Ok((path, attempt, admission))
    }

    fn initial_discovery_has_budget(
        &self,
        accounting: ContentId,
    ) -> Result<bool, CampaignRepositoryError> {
        let mut after = None;
        for _ in 0..MAX_DISCOVERY_ACCOUNTING_PAGES {
            let page = self
                .merkle
                .scan(accounting, after, DISCOVERY_ACCOUNTING_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                let envelope = self.read_envelope(*content)?;
                if envelope.record_kind() != crate::CampaignRecordKind::Fact {
                    continue;
                }
                let CampaignFact::ControlRequested(request) = self.read_fact(*content)? else {
                    continue;
                };
                // Grants also have deduplicated auxiliary fact entries. Only
                // the authenticated command key represents an additive grant.
                if *key == map_key_hash("accounting.command", request.command.as_hash())
                    && matches!(request.action, CampaignControlAction::GrantBudget(grant) if grant.attempts() > 0)
                {
                    return Ok(true);
                }
            }
            let Some(next) = page.next_after() else {
                return Ok(false);
            };
            after = Some(next);
        }
        Err(integrity("initial-discovery-accounting-scan-limit"))
    }

    pub(super) fn validate_initial_discovery_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        admission: AttemptAdmission,
    ) -> Result<(), CampaignRepositoryError> {
        let Some((_, _, expected)) = self.initial_discovery_basis(parent)? else {
            return Err(integrity("initial-discovery-is-not-admissible"));
        };
        if admission != expected {
            return Err(integrity("initial-discovery-owner-recomputation-mismatch"));
        }
        let mut expected_roots = parent.snapshot.roots();
        expected_roots.accounting = child.snapshot.roots().accounting;
        expected_roots.coordination = child.snapshot.roots().coordination;
        if expected_roots != child.snapshot.roots()
            || !self.merkle.equals_after_upserts(
                parent.snapshot.roots().accounting,
                child.snapshot.roots().accounting,
                &attempt_admission_upserts(admission.id()?.content_id(), admission)?,
            )?
            || !self
                .coordination_matches_parent_result(parent, child.snapshot.roots().coordination)?
        {
            return Err(integrity("initial-discovery-successor-root-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_discovery_request_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        transition_content: ContentId,
        request: &DiscoveryRequest,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity("discovery-request-changed-lineage-or-policy"));
        }
        let (_, _, admission) = self.discovery_request_basis(parent, request)?;
        self.ensure_budget_available(parent, 0, 1)?;

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
            return Err(integrity("discovery-request-changed-unrelated-root"));
        }

        let command_key = map_key_hash("accounting.command", request.command.as_hash());
        if self.merkle.get(prior.accounting, command_key)?.is_some() {
            return Err(integrity("discovery-request-reused-command"));
        }
        let mut upserts = attempt_admission_upserts(admission.id()?.content_id(), admission)?;
        upserts.insert(command_key, transition_content);
        if !self
            .merkle
            .equals_after_upserts(prior.accounting, next.accounting, &upserts)?
        {
            return Err(integrity("discovery-request-accounting-root-mismatch"));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity("discovery-request-coordination-root-mismatch"));
        }
        Ok(())
    }
}
