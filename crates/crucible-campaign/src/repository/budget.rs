//! Snapshot-bound projection of additive campaign grants and canonical spending.
//!
//! Command keys count grants, proposal keys count planning work, and the dense
//! admission sequence counts unique semantic attempts. Auxiliary indexes never
//! spend or grant budget a second time. Version-3 snapshots authenticate an
//! indexed ledger against every causal transition. Legacy projection preserves
//! historical overspending during upgrade without invalidating old snapshots.

use super::*;
use crate::{CampaignBudgetLedger, CampaignBudgetLedgerId, CampaignRoots};

const BUDGET_PAGE_ITEMS: usize = 128;
const MAX_BUDGET_PAGES: usize = 512;

/// Reports campaign grants and spending at one authenticated snapshot.
///
/// Totals use `u128` so distinct valid `u64` grants add exactly without wrapping
/// or silently saturating. Spending may exceed grants in historical snapshots;
/// callers must not infer admission permission from a nonzero grant alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignBudgetProjection {
    /// Immutable snapshot whose grants and spending were projected.
    pub snapshot: CampaignSnapshotId,
    /// Sum of proposal allowances from distinct canonical control commands.
    pub granted_proposals: u128,
    /// Sum of attempt allowances from distinct canonical control commands.
    pub granted_attempts: u128,
    /// Number of canonical proposals, including convergent proposals.
    pub spent_proposals: u64,
    /// Number of unique execution bases, excluding additional causes.
    pub spent_attempts: u64,
}

impl CampaignBudgetProjection {
    /// Returns the unspent proposal allowance, or zero for historical debt.
    #[must_use]
    pub const fn remaining_proposals(self) -> u128 {
        self.granted_proposals
            .saturating_sub(self.spent_proposals as u128)
    }

    /// Returns the unspent unique-attempt allowance, or zero for historical debt.
    #[must_use]
    pub const fn remaining_attempts(self) -> u128 {
        self.granted_attempts
            .saturating_sub(self.spent_attempts as u128)
    }
}

impl CampaignRepository {
    /// Projects additive grants and canonical spending at the current head.
    ///
    /// The result names the immutable snapshot read at entry; a concurrent head
    /// change does not mix grants and spending from different snapshots.
    /// This query does not grant permission or mutate the campaign.
    ///
    /// # Errors
    ///
    /// Returns a repository error for an absent campaign, invalid authenticated
    /// head, unreadable record, or legacy accounting/exploration index exceeding
    /// the bounded 65,536-entry scan per index. Version-3 snapshots read one
    /// indexed ledger after head authentication. A limit never yields partial totals.
    pub fn budget_projection(
        &self,
        name: &str,
    ) -> Result<CampaignBudgetProjection, CampaignRepositoryError> {
        let head = self.head(name)?;
        let snapshot = self.read_snapshot(head.content_id())?;
        self.project_campaign_budget(&snapshot)
    }

    pub(super) fn project_campaign_budget(
        &self,
        snapshot: &LoadedSnapshot,
    ) -> Result<CampaignBudgetProjection, CampaignRepositoryError> {
        if let Some(id) = snapshot.snapshot.budget_ledger() {
            let ledger = self.read_budget_ledger(id)?;
            return Ok(CampaignBudgetProjection {
                snapshot: snapshot.snapshot.id()?,
                granted_proposals: ledger.granted_proposals(),
                granted_attempts: ledger.granted_attempts(),
                spent_proposals: ledger.spent_proposals(),
                spent_attempts: ledger.spent_attempts(),
            });
        }
        self.project_legacy_campaign_budget(snapshot)
    }

    fn project_legacy_campaign_budget(
        &self,
        snapshot: &LoadedSnapshot,
    ) -> Result<CampaignBudgetProjection, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let mut result = CampaignBudgetProjection {
            snapshot: snapshot.snapshot.id()?,
            granted_proposals: 0,
            granted_attempts: 0,
            spent_proposals: 0,
            spent_attempts: 0,
        };
        self.visit_budget_index(roots.accounting, |key, content| {
            let envelope = self.read_envelope(content)?;
            if envelope.record_kind() != crate::CampaignRecordKind::Fact {
                return Ok(());
            }
            let CampaignFact::ControlRequested(request) = self.read_fact(content)? else {
                return Ok(());
            };
            if key == map_key_hash("accounting.command", request.command.as_hash())
                && let CampaignControlAction::GrantBudget(grant) = request.action
            {
                // The bounded number of u64 grants fits exactly in u128.
                result.granted_proposals += u128::from(grant.proposals());
                result.granted_attempts += u128::from(grant.attempts());
            }
            Ok(())
        })?;

        self.visit_budget_index(roots.exploration, |key, content| {
            if key == map_key_content("exploration.proposal", content) {
                self.decode_proposal(content)?;
                result.spent_proposals += 1;
            }
            Ok(())
        })?;
        if let Some(content) = self
            .merkle
            .get(roots.accounting, admission_sequence_key())?
        {
            let admission = self.decode_attempt_admission(content)?;
            let AttemptAdmissionRole::ExecutionBasis {
                admission_ordinal, ..
            } = admission.role()
            else {
                return Err(integrity(
                    "admission-sequence-does-not-name-execution-basis",
                ));
            };
            // Complete-head validation proves dense, one-based ordinals. Other
            // admission indexes and AdditionalCause records do not add attempts.
            result.spent_attempts = admission_ordinal.value();
        }
        Ok(result)
    }

    pub(super) fn put_budget_ledger(
        &self,
        ledger: CampaignBudgetLedger,
    ) -> Result<CampaignBudgetLedgerId, CampaignRepositoryError> {
        let envelope = ObjectEnvelope::for_budget_ledger(&ledger)?;
        Ok(CampaignBudgetLedgerId::from_content_id(
            self.put_envelope(envelope)?,
        )?)
    }

    fn read_budget_ledger(
        &self,
        id: CampaignBudgetLedgerId,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::BudgetLedger {
            return Err(integrity("campaign-budget-ledger-kind-mismatch"));
        }
        Ok(CampaignBudgetLedger::from_canonical_bytes(envelope.body())?)
    }

    fn parent_budget_ledger(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        if let Some(id) = parent.snapshot.budget_ledger() {
            return self.read_budget_ledger(id);
        }
        // A legacy history upgrades on its next new transition. Reconstruct its
        // exact debt once; do not forgive previous spending at the version edge.
        let projected = self.project_legacy_campaign_budget(parent)?;
        Ok(CampaignBudgetLedger::from_accounted_totals(
            projected.granted_proposals,
            projected.granted_attempts,
            projected.spent_proposals,
            projected.spent_attempts,
        ))
    }

    pub(super) fn ensure_budget_available(
        &self,
        parent: &LoadedSnapshot,
        proposals: u64,
        attempts: u64,
    ) -> Result<(), CampaignRepositoryError> {
        self.parent_budget_ledger(parent)?
            .with_spending(proposals, attempts)?;
        Ok(())
    }

    fn accounted_attempts(&self, accounting: ContentId) -> Result<u64, CampaignRepositoryError> {
        let Some(content) = self.merkle.get(accounting, admission_sequence_key())? else {
            return Ok(0);
        };
        match self.decode_attempt_admission(content)?.role() {
            AttemptAdmissionRole::ExecutionBasis {
                admission_ordinal, ..
            } => Ok(admission_ordinal.value()),
            AttemptAdmissionRole::AdditionalCause { .. } => Err(integrity(
                "admission-sequence-does-not-name-execution-basis",
            )),
        }
    }

    fn successor_budget_ledger(
        &self,
        parent: &LoadedSnapshot,
        roots: CampaignRoots,
        fact: &CampaignFact,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let mut ledger = self.parent_budget_ledger(parent)?;
        let proposals = match fact {
            CampaignFact::ControlRequested(request) => {
                if let CampaignControlAction::GrantBudget(grant) = request.action {
                    ledger = ledger.with_grant(grant)?;
                }
                0
            }
            CampaignFact::ProposalIssued(_) => 1,
            CampaignFact::PlannerAdvanced(step) => {
                match self.read_planner_step(step.content_id())?.disposition() {
                    PlannerDisposition::Issue {
                        issued_proposals, ..
                    } => u64::try_from(issued_proposals.len())
                        .map_err(|_| integrity("campaign-budget-proposal-count-overflow"))?,
                    PlannerDisposition::ContinueScan { .. } | PlannerDisposition::NoWork => 0,
                }
            }
            CampaignFact::CampaignDerived(_)
            | CampaignFact::ChoiceOpportunityDiscovered { .. }
            | CampaignFact::BranchRequestIssued(_)
            | CampaignFact::AttemptAdmitted(_)
            | CampaignFact::AttemptClosed { .. }
            | CampaignFact::ObservationPublished(_)
            | CampaignFact::ObservationCredited(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::ObjectiveEvaluationPublished(_)
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_) => 0,
        };
        let prior_attempts = self.accounted_attempts(parent.snapshot.roots().accounting)?;
        let attempts = self
            .accounted_attempts(roots.accounting)?
            .checked_sub(prior_attempts)
            .ok_or_else(|| integrity("campaign-budget-admission-sequence-regressed"))?;
        Ok(ledger.with_spending(proposals, attempts)?)
    }

    /// Publishes the ledger required by every newly written successor.
    pub(super) fn budgeted_successor(
        &self,
        parent: CampaignSnapshotId,
        lineage: CampaignLineageId,
        policy: CampaignPolicyId,
        roots: CampaignRoots,
        transition: CampaignFactId,
    ) -> Result<CampaignSnapshot, CampaignRepositoryError> {
        let loaded = self.read_snapshot(parent.content_id())?;
        let fact = self.read_fact(transition.content_id())?;
        let ledger = self.successor_budget_ledger(&loaded, roots, &fact)?;
        Ok(
            CampaignSnapshot::successor(parent, lineage, policy, roots, transition)?
                .with_budget_ledger(self.put_budget_ledger(ledger)?),
        )
    }

    pub(super) fn validate_budget_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        match child.snapshot.budget_ledger() {
            Some(id) => {
                let expected =
                    self.successor_budget_ledger(parent, child.snapshot.roots(), fact)?;
                if self.read_budget_ledger(id)? != expected {
                    return Err(integrity("campaign-budget-successor-mismatch"));
                }
                Ok(())
            }
            None if parent.snapshot.budget_ledger().is_none() => Ok(()),
            None => Err(integrity("campaign-budget-contract-downgrade")),
        }
    }

    pub(super) fn validate_genesis_budget(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        if let Some(id) = snapshot.budget_ledger()
            && self.read_budget_ledger(id)? != CampaignBudgetLedger::empty()
        {
            return Err(integrity("campaign-genesis-budget-is-not-empty"));
        }
        Ok(())
    }

    fn visit_budget_index(
        &self,
        root: ContentId,
        mut visit: impl FnMut(CampaignHash, ContentId) -> Result<(), CampaignRepositoryError>,
    ) -> Result<(), CampaignRepositoryError> {
        let mut after = None;
        for _ in 0..MAX_BUDGET_PAGES {
            let page = self.merkle.scan(root, after, BUDGET_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                visit(*key, *content)?;
            }
            let Some(next) = page.next_after() else {
                return Ok(());
            };
            after = Some(next);
        }
        Err(integrity("campaign-budget-projection-scan-limit"))
    }
}
