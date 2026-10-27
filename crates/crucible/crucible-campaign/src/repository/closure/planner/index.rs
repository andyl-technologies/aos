//! Read-only reconstruction of exact planner scan-index edits.

use super::*;

type ScanEdits = BTreeMap<CampaignHash, Option<ContentId>>;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn planner_scan_index_after(
        &mut self,
        exploration: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
        retired: Option<(BranchRequestId, crate::BranchPointId)>,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let index = self
            .merkle_get(exploration, planner_scan_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-planner-scan-index-is-missing"))?;
        let empty = MerkleMap::empty_content_id()?;
        let mut grouped = BTreeMap::new();
        for (request, branch) in requests {
            self.poll()?;
            let content = request.content_id();
            self.insert_planner_scan_edit(&mut grouped, *branch, content, Some(content))?;
        }
        if let Some((request, branch)) = retired {
            self.insert_planner_scan_edit(&mut grouped, branch, request.content_id(), None)?;
        }

        let retired_content = retired.map(|(request, _)| request.content_id());
        let mut branches = BTreeMap::new();
        for (branch, edits) in grouped {
            self.poll()?;
            let key = branch.as_hash();
            let request_root = self.merkle_get(index, key)?.unwrap_or(empty);
            for (request, expected) in &edits {
                let existing = self.merkle_get(request_root, *request)?;
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
            let root = self.merkle_root_after_edits(request_root, &edits)?;
            self.insert_map(&mut branches, key, (root != empty).then_some(root))?;
        }
        self.merkle_root_after_edits(index, &branches)
    }

    pub(in crate::repository) fn branch_request_index_after(
        &mut self,
        exploration: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
    ) -> Result<ContentId, CampaignRepositoryError> {
        let index = self
            .merkle_get(exploration, branch_request_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-branch-request-index-is-missing"))?;
        let mut projected_entry_count =
            usize::try_from(self.merkle_inspect_shallow(index)?.entry_count())
                .map_err(|_| integrity("feedback-branch-request-index-limit"))?;
        let mut grouped = BTreeMap::<crate::BranchPointId, Vec<BranchRequestId>>::new();
        for (request, branch) in requests {
            self.poll()?;
            if !grouped.contains_key(branch) {
                self.insert_map(&mut grouped, *branch, Vec::new())?;
            }
            let branch_requests = grouped
                .get_mut(branch)
                .ok_or_else(|| integrity("branch-request-index-branch-is-missing"))?;
            self.push(branch_requests, *request)?;
        }

        let mut index_upserts = BTreeMap::new();
        for (branch, branch_requests) in grouped {
            self.poll()?;
            let branch_key = branch_request_index_branch_key(branch);
            let existing_branch_root = self.merkle_get(index, branch_key)?;
            let branch_root = existing_branch_root.unwrap_or(MerkleMap::empty_content_id()?);
            if existing_branch_root.is_none() {
                projected_entry_count = projected_entry_count
                    .checked_add(1)
                    .ok_or_else(|| integrity("feedback-branch-request-index-limit"))?;
            }
            let mut upserts = BTreeMap::new();
            for request in branch_requests {
                self.insert_map(
                    &mut upserts,
                    frontier_index_order_key(request),
                    request.content_id(),
                )?;
            }
            for (key, value) in &upserts {
                self.poll()?;
                if let Some(existing) = self.merkle_get(branch_root, *key)?
                    && existing != *value
                {
                    return Err(integrity("branch-request-point-index-conflict"));
                }
                let request = BranchRequestId::from_content_id(*value)?;
                let membership_key = branch_request_index_membership_key(request);
                if let Some(existing) = self.merkle_get(index, membership_key)? {
                    if existing != *value {
                        return Err(integrity("feedback-branch-request-index-conflict"));
                    }
                } else {
                    projected_entry_count = projected_entry_count
                        .checked_add(1)
                        .ok_or_else(|| integrity("feedback-branch-request-index-limit"))?;
                }
                self.insert_map(&mut index_upserts, membership_key, *value)?;
            }
            let branch_root = self.merkle_root_after_upserts(branch_root, &upserts)?;
            self.insert_map(&mut index_upserts, branch_key, branch_root)?;
        }
        if projected_entry_count > MAX_FEEDBACK_FRONTIER_UPDATES {
            return Err(integrity("feedback-branch-request-index-limit"));
        }
        self.merkle_root_after_upserts(index, &index_upserts)
    }

    fn insert_planner_scan_edit(
        &self,
        grouped: &mut BTreeMap<crate::BranchPointId, ScanEdits>,
        branch: crate::BranchPointId,
        content: ContentId,
        replacement: Option<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        if !grouped.contains_key(&branch) {
            self.insert_map(grouped, branch, BTreeMap::new())?;
        }
        let edits = grouped
            .get_mut(&branch)
            .ok_or_else(|| integrity("planner-scan-index-branch-is-missing"))?;
        if self
            .insert_map(
                edits,
                CampaignHash::from_bytes(content.digest()),
                replacement,
            )?
            .is_some()
        {
            return Err(integrity("planner-scan-index-repeated-request"));
        }
        Ok(())
    }
}
