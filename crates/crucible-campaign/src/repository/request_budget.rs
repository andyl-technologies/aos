//! Authenticated request-local indexes inside version-3 ledgers.
//!
//! Each outer Merkle map names one nested map per request. Spending entries
//! name only execution bases, so their exact count is the request's spent
//! attempt allowance. The admissions map includes additional causes.
//! ```text
//! ledger.request_spending -> request_key -> attempt_key -> execution_basis_admission
//! ledger.request_admissions -> request_key -> proposal_key -> admission
//! ```

use super::*;
use crate::CampaignBudgetLedger;

impl CampaignRepository {
    /// Indexes each newly admitted proposal, including convergent causes.
    pub(super) fn request_admissions_root_after(
        &self,
        ledger: CampaignBudgetLedger,
        accounting: ContentId,
        fact: &CampaignFact,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let proposals = self.new_request_admission_proposals(fact)?;

        let prior = ledger.request_admissions();
        let empty = MerkleMap::empty_content_id()?;
        let mut by_request = BTreeMap::<BranchRequestId, BTreeMap<CampaignHash, ContentId>>::new();
        for proposal in proposals {
            let admission_content = self
                .merkle
                .get(
                    accounting,
                    map_key_content("accounting.proposal-admission", proposal.content_id()),
                )?
                .ok_or_else(|| integrity("request-admissions-proposal-has-no-admission"))?;
            let admission = self.decode_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity("request-admissions-unbacked-admission"));
                }
            };
            if admitted_proposal != proposal {
                return Err(integrity("request-admissions-proposal-mismatch"));
            }
            let request = self.decode_proposal(proposal.content_id())?.request();
            let key = request_proposal_key(proposal);
            if by_request
                .entry(request)
                .or_default()
                .insert(key, admission_content)
                .is_some()
            {
                return Err(integrity("request-admissions-duplicate-proposal"));
            }
        }

        let mut outer = BTreeMap::new();
        for (request, admissions) in by_request {
            let key = request_admissions_key(request);
            let request_root = self.merkle.get(prior, key)?.unwrap_or(empty);
            for proposal in admissions.keys() {
                if self.merkle.get(request_root, *proposal)?.is_some() {
                    return Err(integrity("request-admissions-reused-proposal"));
                }
            }
            outer.insert(
                key,
                self.update_request_spending_map(request_root, &admissions, publish)?,
            );
        }
        self.update_request_spending_map(prior, &outer, publish)
    }

    fn new_request_admission_proposals(
        &self,
        fact: &CampaignFact,
    ) -> Result<Vec<ProposalId>, CampaignRepositoryError> {
        Ok(match fact {
            CampaignFact::AttemptAdmitted(id) => {
                let admission = self.decode_attempt_admission(id.content_id())?;
                match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => vec![proposal],
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => Vec::new(),
                }
            }
            CampaignFact::PlannerAdvanced(step) => self
                .read_planner_step(step.content_id())?
                .disposition()
                .issued_proposals()
                .to_vec(),
            _ => Vec::new(),
        })
    }

    pub(super) fn indexed_request_execution_bases(
        &self,
        ledger: CampaignBudgetLedger,
        request: BranchRequestId,
    ) -> Result<u64, CampaignRepositoryError> {
        let root = ledger.request_spending();
        let Some(request_root) = self.merkle.get(root, request_spending_key(request))? else {
            return Ok(0);
        };
        Ok(self.merkle.inspect_shallow(request_root)?.entry_count())
    }

    pub(super) fn request_execution_bases_at(
        &self,
        snapshot: &LoadedSnapshot,
        request: BranchRequestId,
    ) -> Result<u64, CampaignRepositoryError> {
        self.indexed_request_execution_bases(self.parent_budget_ledger(snapshot)?, request)
    }

    /// Adds newly dense global admissions to the authenticated request index.
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
        let prior = ledger.request_spending();
        let first = ledger
            .spent_attempts()
            .checked_add(1)
            .ok_or_else(|| integrity("request-budget-admission-ordinal-overflow"))?;
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
            let key = request_attempt_key(admission.attempt());
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

    pub(crate) fn scan_request_attempt_page(
        &self,
        ledger: CampaignBudgetLedger,
        request: BranchRequestId,
        after: Option<ProposalId>,
        limit: usize,
    ) -> Result<
        (
            Vec<(Proposal, AttemptAdmission)>,
            Option<ProposalId>,
            MerkleMapLookupProof,
            MerkleMapPageProof,
        ),
        CampaignRepositoryError,
    > {
        let (index, index_proof) = self
            .merkle
            .get_with_proof(ledger.request_admissions(), request_admissions_key(request))?;
        let index = index.unwrap_or(MerkleMap::empty_content_id()?);
        let (page, page_proof) =
            self.merkle
                .scan_with_proof(index, after.map(request_proposal_key), limit)?;
        let entries = page
            .entries()
            .iter()
            .map(|(_, content)| {
                let admission = self.read_attempt_admission(*content)?;
                let proposal = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    }
                    | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                        return Err(integrity("request-admissions-unbacked-admission"));
                    }
                };
                Ok((self.read_proposal(proposal.content_id())?, admission))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = if page.next_after().is_some() {
            Some(
                entries
                    .last()
                    .ok_or_else(|| integrity("request-admissions-cursor-without-entry"))?
                    .0
                    .id()?,
            )
        } else {
            None
        };
        Ok((entries, next_after, index_proof, page_proof))
    }

    /// Charges the ledger and the maximum two trie paths per indexed admission.
    pub(super) fn request_budget_closure_growth(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
    ) -> Result<usize, CampaignRepositoryError> {
        let prior = self.parent_budget_ledger(parent)?;
        let next = self.parent_budget_ledger(child)?;
        let fact = child
            .snapshot
            .transition()
            .ok_or_else(|| integrity("request-budget-successor-has-no-transition"))?;
        let fact = self.read_fact(fact.content_id())?;
        let indexed = self.new_request_admission_proposals(&fact)?.len();
        indexed
            .checked_mul(2 * MERKLE_UPDATE_NODE_UPPER)
            .and_then(|nodes| {
                next.spent_attempts()
                    .checked_sub(prior.spent_attempts())
                    .and_then(|attempts| usize::try_from(attempts).ok())
                    .and_then(|attempts| attempts.checked_mul(2 * MERKLE_UPDATE_NODE_UPPER))
                    .and_then(|spending_nodes| nodes.checked_add(spending_nodes))
            })
            .and_then(|nodes| nodes.checked_add(1))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }
}

pub(crate) fn request_spending_key(request: BranchRequestId) -> CampaignHash {
    map_key_content("budget.request-spending", request.content_id())
}

pub(crate) fn request_attempt_key(attempt: AttemptId) -> CampaignHash {
    map_key_content("budget.request-attempt", attempt.content_id())
}

pub(crate) fn request_admissions_key(request: BranchRequestId) -> CampaignHash {
    map_key_content("budget.request-admissions", request.content_id())
}

pub(crate) fn request_proposal_key(proposal: ProposalId) -> CampaignHash {
    map_key_content("budget.request-proposal", proposal.content_id())
}
