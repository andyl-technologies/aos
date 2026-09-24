//! Snapshot-bound projection of additive campaign grants and canonical spending.
//!
//! Command keys count grants, proposal keys count planning work, and the dense
//! admission sequence counts unique semantic attempts. Auxiliary indexes never
//! spend or grant budget a second time. Version-3 snapshots authenticate an
//! indexed ledger against every causal transition.

use super::*;
use crate::{CampaignBudgetLedger, CampaignBudgetLedgerId, CampaignRoots};

pub(super) const MAX_PLANNER_REQUEST_BUDGET_PROPOSALS: usize = 65_536;

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
    /// Reads authenticated request-local spending from the current ledger index.
    pub(super) fn remaining_request_attempts_before(
        &self,
        snapshot: &LoadedSnapshot,
        request: BranchRequestId,
        _ordinal: u64,
        maximum: u64,
        _work: &mut usize,
    ) -> Result<u64, CampaignRepositoryError> {
        let count =
            self.indexed_request_execution_bases(self.parent_budget_ledger(snapshot)?, request)?;
        Ok(maximum.saturating_sub(count))
    }

    /// Projects additive grants and canonical spending at the current head.
    ///
    /// The result names the immutable snapshot read at entry; a concurrent head
    /// change does not mix grants and spending from different snapshots.
    /// This query does not grant permission or mutate the campaign.
    ///
    /// # Errors
    ///
    /// Returns a repository error for an absent campaign, invalid authenticated
    /// head, or unreadable ledger. A failure never yields partial totals.
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
        let ledger = self.read_budget_ledger(snapshot.snapshot.budget_ledger())?;
        Ok(CampaignBudgetProjection {
            snapshot: snapshot.snapshot.id()?,
            granted_proposals: ledger.granted_proposals(),
            granted_attempts: ledger.granted_attempts(),
            spent_proposals: ledger.spent_proposals(),
            spent_attempts: ledger.spent_attempts(),
        })
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

    pub(crate) fn read_budget_ledger(
        &self,
        id: CampaignBudgetLedgerId,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::BudgetLedger {
            return Err(integrity("campaign-budget-ledger-kind-mismatch"));
        }
        Ok(CampaignBudgetLedger::from_canonical_bytes(envelope.body())?)
    }

    pub(super) fn parent_budget_ledger(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        self.read_budget_ledger(parent.snapshot.budget_ledger())
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

    pub(super) fn accounted_attempts(
        &self,
        accounting: ContentId,
    ) -> Result<u64, CampaignRepositoryError> {
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
        publish: bool,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let prior_ledger = self.parent_budget_ledger(parent)?;
        let mut ledger = prior_ledger;
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
            | CampaignFact::BranchRequestAccepted { .. }
            | CampaignFact::AttemptAdmitted(_)
            | CampaignFact::AttemptClosed { .. }
            | CampaignFact::ObservationCredited(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::ObjectiveEvaluationPublished(_)
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_)
            | CampaignFact::SavepointCaptureRequested(_)
            | CampaignFact::SavepointCaptureResolved(_)
            | CampaignFact::SavepointContinuationSelected(_) => 0,
        };
        let prior_attempts = self.accounted_attempts(parent.snapshot.roots().accounting)?;
        let attempts = self
            .accounted_attempts(roots.accounting)?
            .checked_sub(prior_attempts)
            .ok_or_else(|| integrity("campaign-budget-admission-sequence-regressed"))?;
        let ledger = ledger.with_spending(proposals, attempts)?;
        let root = self.request_spending_root_after(prior_ledger, roots.accounting, publish)?;
        let admissions =
            self.request_admissions_root_after(prior_ledger, roots.accounting, fact, publish)?;
        Ok(CampaignBudgetLedger::from_accounted_totals(
            ledger.granted_proposals(),
            ledger.granted_attempts(),
            ledger.spent_proposals(),
            ledger.spent_attempts(),
            root,
            admissions,
        )?)
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
        let ledger = self.successor_budget_ledger(&loaded, roots, &fact, true)?;
        let ledger = self.put_budget_ledger(ledger)?;
        Ok(CampaignSnapshot::successor(
            parent, lineage, policy, roots, transition, ledger,
        )?)
    }

    pub(super) fn validate_budget_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<(), CampaignRepositoryError> {
        let actual = self.read_budget_ledger(child.snapshot.budget_ledger())?;
        let expected = self.successor_budget_ledger(parent, child.snapshot.roots(), fact, false)?;
        if actual != expected {
            return Err(integrity("campaign-budget-successor-mismatch"));
        }
        Ok(())
    }

    pub(super) fn validate_genesis_budget(
        &self,
        snapshot: &CampaignSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        let actual = self.read_budget_ledger(snapshot.budget_ledger())?;
        let expected = CampaignBudgetLedger::empty(MerkleMap::empty_content_id()?)?;
        if actual != expected {
            return Err(integrity("campaign-genesis-budget-is-not-empty"));
        }
        Ok(())
    }
}
