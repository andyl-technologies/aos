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
    /// Reads indexed request spending, falling back to legacy dense proposal pairs.
    ///
    /// Version-2 ledgers require one outer trie lookup and one nested root read.
    /// Legacy ledgers share one work counter across every offer in the bundle;
    /// domain cardinality and unrelated accounting do not affect that traversal.
    /// Reaching the cap establishes zero remaining allowance, so historical debt
    /// cannot wrap or restore permission.
    pub(super) fn remaining_request_attempts_before(
        &self,
        snapshot: &LoadedSnapshot,
        request: BranchRequestId,
        ordinal: u64,
        maximum: u64,
        work: &mut usize,
    ) -> Result<u64, CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        if let Some(count) =
            self.indexed_request_execution_bases(self.parent_budget_ledger(snapshot)?, request)?
        {
            return Ok(maximum.saturating_sub(count));
        }
        let mut remaining = maximum;
        for previous in 1..ordinal {
            if remaining == 0 {
                break;
            }
            *work = work
                .checked_sub(1)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "planner-request-budget-prior-proposals",
                })?;
            let content = self
                .merkle
                .get(roots.exploration, proposal_ordinal_key(request, previous))?
                .ok_or_else(|| integrity("planner-request-budget-missing-proposal"))?;
            let proposal = self.decode_proposal(content)?;
            if proposal.request() != request || proposal.ordinal() != previous {
                return Err(integrity("planner-request-budget-proposal-index-mismatch"));
            }
            let content = self
                .merkle
                .get(
                    roots.accounting,
                    map_key_content("accounting.proposal-admission", content),
                )?
                .ok_or_else(|| integrity("planner-request-budget-missing-admission"))?;
            let admission = self.decode_attempt_admission(content)?;
            match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(source),
                    ..
                } if source == proposal.id()? => remaining -= 1,
                AttemptAdmissionRole::AdditionalCause { proposal: source }
                    if source == proposal.id()? => {}
                _ => return Err(integrity("planner-request-budget-admission-mismatch")),
            }
        }
        Ok(remaining)
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

    pub(super) fn read_budget_ledger(
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
        indexed: bool,
        publish: bool,
    ) -> Result<CampaignBudgetLedger, CampaignRepositoryError> {
        let prior_ledger = self.parent_budget_ledger(parent)?;
        let mut ledger = prior_ledger;
        if !indexed && ledger.request_spending().is_some() {
            return Err(integrity("campaign-request-budget-contract-downgrade"));
        }
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
            | CampaignFact::BranchRequestAccepted { .. }
            | CampaignFact::AttemptAdmitted(_)
            | CampaignFact::AttemptClosed { .. }
            | CampaignFact::ObservationPublished(_)
            | CampaignFact::ObservationCredited(_)
            | CampaignFact::FindingPublished(_)
            | CampaignFact::ObjectiveEvaluationPublished(_)
            | CampaignFact::PolicyActivated(_)
            | CampaignFact::BudgetGranted(_)
            | CampaignFact::PinChanged(_)
            | CampaignFact::PinCommandAccepted(_)
            | CampaignFact::DiscoveryRequested(_) => 0,
        };
        let prior_attempts = self.accounted_attempts(parent.snapshot.roots().accounting)?;
        let attempts = self
            .accounted_attempts(roots.accounting)?
            .checked_sub(prior_attempts)
            .ok_or_else(|| integrity("campaign-budget-admission-sequence-regressed"))?;
        let ledger = ledger.with_spending(proposals, attempts)?;
        if indexed {
            let root = self.request_spending_root_after(prior_ledger, roots.accounting, publish)?;
            Ok(ledger.with_request_spending(root)?)
        } else {
            Ok(ledger)
        }
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
        let ledger = self.successor_budget_ledger(&loaded, roots, &fact, true, true)?;
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
                let actual = self.read_budget_ledger(id)?;
                let expected = self.successor_budget_ledger(
                    parent,
                    child.snapshot.roots(),
                    fact,
                    actual.request_spending().is_some(),
                    false,
                )?;
                if actual != expected {
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
        if let Some(id) = snapshot.budget_ledger() {
            let actual = self.read_budget_ledger(id)?;
            let expected = if actual.request_spending().is_some() {
                CampaignBudgetLedger::empty()
                    .with_request_spending(MerkleMap::empty_content_id()?)?
            } else {
                CampaignBudgetLedger::empty()
            };
            if actual != expected {
                return Err(integrity("campaign-genesis-budget-is-not-empty"));
            }
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
