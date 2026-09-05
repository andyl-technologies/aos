//! Snapshot-bound projection of additive campaign grants and canonical spending.
//!
//! Command keys count grants, proposal keys count planning work, and the dense
//! admission sequence counts unique semantic attempts. Auxiliary indexes never
//! spend or grant budget a second time. This read-only projection also reports
//! historical overspending without changing the validity of old snapshots.

use super::*;

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
    /// head, unreadable record, or accounting/exploration index exceeding the
    /// bounded 65,536-entry scan per index. A limit never produces partial totals.
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
