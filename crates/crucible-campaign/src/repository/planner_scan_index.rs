//! Ordered, authenticated positions whose immutable request cap is unspent.
//!
//! Campaign genesis owns an empty index. Request transitions extend it and an
//! issue retires its selected request at the final proposal ordinal. Historical
//! request membership remains in exploration. Cold replay checks each delta.
//! ```text
//! exploration[planner-scan-index.v3]
//!   -> branch_point_hash -> request_digest -> request
//! ```
//! [`BranchRequestId`] admits only the current exact wire schema, so its digest
//! is the complete stable ordering key within one branch point.

use super::*;

pub(super) fn planner_scan_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign.planner-scan-index.v3", b"root")
}

impl CampaignRepository {
    pub(super) fn planner_scan_closure_growth(
        &self,
        child: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<usize, CampaignRepositoryError> {
        self.merkle
            .get(
                child.snapshot.roots().exploration,
                planner_scan_index_anchor_key(),
            )?
            .ok_or_else(|| integrity("current-campaign-planner-scan-index-is-missing"))?;
        let updates = match fact {
            CampaignFact::BranchRequestAccepted { .. } => 1,
            CampaignFact::PlannerAdvanced(step) => {
                match self.read_planner_step(step.content_id())?.disposition() {
                    PlannerDisposition::Issue {
                        selected,
                        issued_branch_requests,
                        issued_proposals,
                        ..
                    } => {
                        let retired = match issued_proposals.last() {
                            Some(last) => {
                                let request =
                                    self.read_branch_request(selected.source().content_id())?;
                                let proposal = self.read_proposal(last.content_id())?;
                                usize::from(
                                    proposal.ordinal() == request.budget().maximum_proposals(),
                                )
                            }
                            None => 0,
                        };
                        issued_branch_requests
                            .len()
                            .checked_add(retired)
                            .ok_or_else(|| integrity("campaign-closure-object-limit"))?
                    }
                    _ => 0,
                }
            }
            _ => 0,
        };
        if updates == 0 {
            return Ok(0);
        }
        updates
            .checked_mul(2 * MERKLE_UPDATE_NODE_UPPER)
            .and_then(|nodes| nodes.checked_add(MERKLE_UPDATE_NODE_UPPER))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }

    pub(super) fn planner_scan_index_after(
        &self,
        exploration: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
        retired: Option<(BranchRequestId, crate::BranchPointId)>,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let index = self
            .merkle
            .get(exploration, planner_scan_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-planner-scan-index-is-missing"))?;
        let empty = MerkleMap::empty_content_id()?;
        let mut grouped =
            BTreeMap::<crate::BranchPointId, BTreeMap<CampaignHash, Option<ContentId>>>::new();
        for (request, branch) in requests {
            let content = request.content_id();
            if grouped
                .entry(*branch)
                .or_default()
                .insert(CampaignHash::from_bytes(content.digest()), Some(content))
                .is_some()
            {
                return Err(integrity("planner-scan-index-repeated-request"));
            }
        }
        if let Some((request, branch)) = retired {
            let content = request.content_id();
            if grouped
                .entry(branch)
                .or_default()
                .insert(CampaignHash::from_bytes(content.digest()), None)
                .is_some()
            {
                return Err(integrity("planner-scan-index-repeated-request"));
            }
        }
        let retired_content = retired.map(|(request, _)| request.content_id());
        let mut branches = BTreeMap::new();
        for (branch, edits) in grouped {
            let key = branch.as_hash();
            let request_root = self.merkle.get(index, key)?.unwrap_or(empty);
            for (request, expected) in &edits {
                let existing = self.merkle.get(request_root, *request)?;
                match (expected, existing) {
                    (Some(_), Some(_)) => {
                        return Err(integrity("planner-scan-index-reused-request"));
                    }
                    (None, None) => {
                        return Err(integrity("planner-scan-index-retired-request-missing"));
                    }
                    (None, Some(content)) if Some(content) != retired_content => {
                        return Err(integrity("planner-scan-index-retired-request-mismatch"));
                    }
                    _ => {}
                }
            }
            let root = self.update_planner_scan_index(request_root, &edits, publish)?;
            let value = (root != empty).then_some(root);
            branches.insert(key, value);
        }
        self.update_planner_scan_index(index, &branches, publish)
    }

    fn update_planner_scan_index(
        &self,
        root: ContentId,
        entries: &BTreeMap<CampaignHash, Option<ContentId>>,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !publish {
            return Ok(self.merkle.root_after_edits(root, entries)?);
        }
        Ok(self.merkle.edit_many(root, entries)?.content_id())
    }

    /// Reads at most `limit` positions in exact semantic/digest order.
    pub(super) fn indexed_planner_scan_positions(
        &self,
        exploration: ContentId,
        after: Option<PlanningScanPosition>,
        limit: usize,
    ) -> Result<BTreeMap<PlanningScanPosition, u64>, CampaignRepositoryError> {
        let index = self
            .merkle
            .get(exploration, planner_scan_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-planner-scan-index-is-missing"))?;
        let mut positions = BTreeMap::new();
        let mut branch_after = after.map(|position| position.branch_point().as_hash());
        if let Some(after) = after {
            let root = self
                .merkle
                .get(index, after.branch_point().as_hash())?
                .ok_or_else(|| integrity("planner-scan-index-cursor-branch-missing"))?;
            self.append_planner_scan_branch(
                root,
                after.branch_point(),
                Some(after.source()),
                limit,
                &mut positions,
            )?;
        }
        while positions.len() < limit {
            let page = self
                .merkle
                .scan(index, branch_after, limit - positions.len())?;
            for (key, root) in page.entries() {
                self.append_planner_scan_branch(
                    *root,
                    crate::BranchPointId::from_hash(*key),
                    None,
                    limit,
                    &mut positions,
                )?;
                if positions.len() == limit {
                    return Ok(positions);
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            branch_after = Some(next);
        }
        Ok(positions)
    }

    fn append_planner_scan_branch(
        &self,
        root: ContentId,
        branch: crate::BranchPointId,
        after: Option<BranchRequestId>,
        limit: usize,
        positions: &mut BTreeMap<PlanningScanPosition, u64>,
    ) -> Result<(), CampaignRepositoryError> {
        if self.merkle.inspect_shallow(root)?.entry_count() == 0 {
            return Err(integrity("planner-scan-index-empty-branch"));
        }
        let cursor = after.map(|request| CampaignHash::from_bytes(request.content_id().digest()));
        if let Some(after) = after {
            let content = after.content_id();
            let cursor_key = CampaignHash::from_bytes(content.digest());
            if self.merkle.get(root, cursor_key)? != Some(content) {
                return Err(integrity("planner-scan-index-cursor-request-missing"));
            }
            let request = self.read_branch_request(content)?;
            if request.branch_point() != branch || request.id()? != after {
                return Err(integrity("planner-scan-index-cursor-request-mismatch"));
            }
        }

        let page = self.merkle.scan(root, cursor, limit - positions.len())?;
        for (key, content) in page.entries() {
            let request = self.read_branch_request(*content)?;
            if *key != CampaignHash::from_bytes(content.digest())
                || request.branch_point() != branch
                || request.id()?.content_id() != *content
            {
                return Err(integrity("planner-scan-index-position-mismatch"));
            }
            let position = PlanningScanPosition::new(branch, request.id()?);
            let bytes = u64::try_from(request.canonical_bytes().len())
                .map_err(|_| integrity("planner-scan-page-input-byte-overflow"))?;
            positions.insert(position, bytes);
        }
        Ok(())
    }
}
