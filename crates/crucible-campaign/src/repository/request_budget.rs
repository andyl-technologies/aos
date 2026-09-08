//! Authenticated request-local execution-basis indexes inside version-2 ledgers.
//!
//! The outer Merkle map names one nested map per request. Each nested entry
//! names an execution-basis admission, never an additional cause. Its exact
//! authenticated entry count is therefore the request's spent attempt allowance.
//! ```text
//! ledger.request_spending -> request_key -> attempt_key -> execution_basis_admission
//! ```

use super::*;
use crate::CampaignBudgetLedger;

impl CampaignRepository {
    pub(super) fn indexed_request_execution_bases(
        &self,
        ledger: CampaignBudgetLedger,
        request: BranchRequestId,
    ) -> Result<Option<u64>, CampaignRepositoryError> {
        let Some(root) = ledger.request_spending() else {
            return Ok(None);
        };
        let Some(request_root) = self.merkle.get(root, request_spending_key(request))? else {
            return Ok(Some(0));
        };
        Ok(Some(
            self.merkle.inspect_shallow(request_root)?.entry_count(),
        ))
    }

    pub(super) fn request_execution_bases_at(
        &self,
        snapshot: &LoadedSnapshot,
        request: BranchRequestId,
    ) -> Result<u64, CampaignRepositoryError> {
        if let Some(count) =
            self.indexed_request_execution_bases(self.parent_budget_ledger(snapshot)?, request)?
        {
            return Ok(count);
        }
        self.count_request_execution_bases(snapshot.snapshot.roots().accounting, request)
    }

    /// Recomputes only new dense global admissions, or rebuilds a legacy index once.
    pub(super) fn request_spending_root_after(
        &self,
        ledger: CampaignBudgetLedger,
        accounting: ContentId,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let final_ordinal = self.accounted_attempts(accounting)?;
        if final_ordinal < ledger.spent_attempts() {
            return Err(integrity("request-budget-admission-sequence-regressed"));
        }
        if final_ordinal > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(integrity("request-budget-admission-index-limit"));
        }
        let empty = MerkleMap::empty_content_id()?;
        let prior = ledger.request_spending().unwrap_or(empty);
        let first = if ledger.request_spending().is_some() {
            ledger
                .spent_attempts()
                .checked_add(1)
                .ok_or_else(|| integrity("request-budget-admission-ordinal-overflow"))?
        } else {
            1
        };
        let mut requests = BTreeMap::<BranchRequestId, BTreeMap<CampaignHash, ContentId>>::new();
        for ordinal in first..=final_ordinal {
            let content = self
                .merkle
                .get(
                    accounting,
                    admission_ordinal_key(AdmissionOrdinal::new(ordinal)),
                )?
                .ok_or_else(|| integrity("request-budget-missing-dense-admission"))?;
            let admission = self.decode_attempt_admission(content)?;
            let AttemptAdmissionRole::ExecutionBasis {
                proposal,
                admission_ordinal,
                ..
            } = admission.role()
            else {
                return Err(integrity(
                    "request-budget-dense-index-is-not-execution-basis",
                ));
            };
            if admission_ordinal.value() != ordinal {
                return Err(integrity("request-budget-dense-admission-ordinal-mismatch"));
            }
            let Some(proposal) = proposal else {
                continue;
            };
            let request = self.decode_proposal(proposal.content_id())?.request();
            let key = map_key_content("budget.request-attempt", admission.attempt().content_id());
            if requests
                .entry(request)
                .or_default()
                .insert(key, content)
                .is_some()
            {
                return Err(integrity("request-budget-repeated-execution-basis"));
            }
        }

        let mut outer = BTreeMap::new();
        for (request, admissions) in requests {
            let key = request_spending_key(request);
            let request_root = self.merkle.get(prior, key)?.unwrap_or(empty);
            for attempt in admissions.keys() {
                if self.merkle.get(request_root, *attempt)?.is_some() {
                    return Err(integrity("request-budget-reused-execution-basis-slot"));
                }
            }
            outer.insert(
                key,
                self.update_request_spending_map(request_root, &admissions, publish)?,
            );
        }
        self.update_request_spending_map(prior, &outer, publish)
    }

    fn update_request_spending_map(
        &self,
        prior: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !publish {
            return Ok(self.merkle.root_after_upserts(prior, upserts)?);
        }
        let mut root = prior;
        for (key, content) in upserts {
            root = self.merkle.insert(root, *key, *content)?.content_id();
        }
        Ok(root)
    }

    /// Charges the ledger and the maximum two trie paths per indexed admission.
    pub(super) fn request_budget_closure_growth(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
    ) -> Result<usize, CampaignRepositoryError> {
        let prior = self.parent_budget_ledger(parent)?;
        let next = self.parent_budget_ledger(child)?;
        let indexed = if next.request_spending().is_none() {
            0
        } else if prior.request_spending().is_none() {
            next.spent_attempts()
        } else {
            next.spent_attempts()
                .checked_sub(prior.spent_attempts())
                .ok_or_else(|| integrity("request-budget-spending-regressed"))?
        };
        usize::try_from(indexed)
            .ok()
            .and_then(|count| count.checked_mul(2 * MERKLE_UPDATE_NODE_UPPER))
            .and_then(|nodes| nodes.checked_add(1))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }
}

fn request_spending_key(request: BranchRequestId) -> CampaignHash {
    map_key_content("budget.request-spending", request.content_id())
}
