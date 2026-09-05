//! Durable first-choice discovery for an otherwise empty campaign frontier.
//!
//! The coordinator creates at most one genesis discovery execution basis. It
//! consumes the first granted attempt, uses the empty authenticated branch
//! path, and stops at the next choice or modeled terminal outcome. Restart
//! observes the same admission sequence rather than manufacturing another job.

use super::*;

const DISCOVERY_ACCOUNTING_PAGE_ITEMS: usize = 128;
const MAX_DISCOVERY_ACCOUNTING_PAGES: usize = 512;

impl CampaignRepository {
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
}
