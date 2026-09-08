//! Ordered, authenticated planner positions independent of exploration history.
//!
//! New campaign genesis owns an empty index. Request transitions extend it;
//! proposals, admissions, and coordination steps preserve it. Legacy histories
//! without the anchor retain their original scan semantics.
//! ```text
//! exploration[planner-scan-index.v1]
//!   -> branch_point_hash -> request_schema_version -> request_digest -> request
//! ```
//! The schema level preserves `BranchRequestId` ordering across retained wire
//! versions; sorting only request digests would silently change planner replay.

use super::*;

pub(super) fn planner_scan_index_anchor_key() -> CampaignHash {
    CampaignHash::derive("crucible.campaign.planner-scan-index.v1", b"root")
}

impl CampaignRepository {
    pub(super) fn planner_scan_closure_growth(
        &self,
        child: &LoadedSnapshot,
        fact: &CampaignFact,
    ) -> Result<usize, CampaignRepositoryError> {
        if self
            .merkle
            .get(
                child.snapshot.roots().exploration,
                planner_scan_index_anchor_key(),
            )?
            .is_none()
        {
            return Ok(0);
        }
        let requests = match fact {
            CampaignFact::BranchRequestIssued(_) | CampaignFact::BranchRequestAccepted { .. } => 1,
            CampaignFact::PlannerAdvanced(step) => {
                match self.read_planner_step(step.content_id())?.disposition() {
                    PlannerDisposition::Issue {
                        issued_branch_requests,
                        ..
                    } => issued_branch_requests.len(),
                    _ => 0,
                }
            }
            _ => 0,
        };
        if requests == 0 {
            return Ok(0);
        }
        requests
            .checked_mul(3 * MERKLE_UPDATE_NODE_UPPER)
            .and_then(|nodes| nodes.checked_add(MERKLE_UPDATE_NODE_UPPER))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }

    pub(super) fn planner_scan_index_after(
        &self,
        exploration: ContentId,
        requests: &[(BranchRequestId, crate::BranchPointId)],
        publish: bool,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        let Some(index) = self
            .merkle
            .get(exploration, planner_scan_index_anchor_key())?
        else {
            return Ok(None);
        };
        let empty = MerkleMap::empty_content_id()?;
        let mut grouped = BTreeMap::<
            crate::BranchPointId,
            BTreeMap<u32, BTreeMap<CampaignHash, ContentId>>,
        >::new();
        for (request, branch) in requests {
            let content = request.content_id();
            if grouped
                .entry(*branch)
                .or_default()
                .entry(content.schema_version())
                .or_default()
                .insert(CampaignHash::from_bytes(content.digest()), content)
                .is_some()
            {
                return Err(integrity("planner-scan-index-repeated-request"));
            }
        }
        let mut branches = BTreeMap::new();
        for (branch, schemas) in grouped {
            let key = branch.as_hash();
            let branch_root = self.merkle.get(index, key)?.unwrap_or(empty);
            let mut versions = BTreeMap::new();
            for (schema, requests) in schemas {
                let key = schema_key(schema);
                let request_root = self.merkle.get(branch_root, key)?.unwrap_or(empty);
                for request in requests.keys() {
                    if self.merkle.get(request_root, *request)?.is_some() {
                        return Err(integrity("planner-scan-index-reused-request"));
                    }
                }
                versions.insert(
                    key,
                    self.update_planner_scan_index(request_root, &requests, publish)?,
                );
            }
            branches.insert(
                key,
                self.update_planner_scan_index(branch_root, &versions, publish)?,
            );
        }
        self.update_planner_scan_index(index, &branches, publish)
            .map(Some)
    }

    fn update_planner_scan_index(
        &self,
        root: ContentId,
        entries: &BTreeMap<CampaignHash, ContentId>,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        if !publish {
            return Ok(self.merkle.root_after_upserts(root, entries)?);
        }
        let mut root = root;
        for (key, content) in entries {
            root = self.merkle.insert(root, *key, *content)?.content_id();
        }
        Ok(root)
    }

    /// Reads at most `limit` positions in exact semantic/schema/digest order.
    pub(super) fn indexed_planner_scan_positions(
        &self,
        exploration: ContentId,
        after: Option<PlanningScanPosition>,
        limit: usize,
    ) -> Result<Option<BTreeMap<PlanningScanPosition, u64>>, CampaignRepositoryError> {
        let Some(index) = self
            .merkle
            .get(exploration, planner_scan_index_anchor_key())?
        else {
            return Ok(None);
        };
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
                    return Ok(Some(positions));
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            branch_after = Some(next);
        }
        Ok(Some(positions))
    }

    fn append_planner_scan_branch(
        &self,
        root: ContentId,
        branch: crate::BranchPointId,
        after: Option<BranchRequestId>,
        limit: usize,
        positions: &mut BTreeMap<PlanningScanPosition, u64>,
    ) -> Result<(), CampaignRepositoryError> {
        let versions = self.merkle.scan(
            root,
            None,
            crate::exploration::BRANCH_REQUEST_SCHEMA_VERSION as usize,
        )?;
        if versions.entries().is_empty() || versions.next_after().is_some() {
            return Err(integrity("planner-scan-index-schema-set"));
        }
        for (key, requests) in versions.entries() {
            let schema = schema_from_key(*key)?;
            let cursor = match after {
                Some(after) if schema < after.content_id().schema_version() => continue,
                Some(after) if schema == after.content_id().schema_version() => {
                    Some(CampaignHash::from_bytes(after.content_id().digest()))
                }
                _ => None,
            };
            if positions.len() == limit {
                break;
            }
            let page = self
                .merkle
                .scan(*requests, cursor, limit - positions.len())?;
            if self.merkle.inspect_shallow(*requests)?.entry_count() == 0 {
                return Err(integrity("planner-scan-index-empty-schema"));
            }
            for (key, content) in page.entries() {
                let request = self.read_branch_request(*content)?;
                if content.schema_version() != schema
                    || *key != CampaignHash::from_bytes(content.digest())
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
        }
        Ok(())
    }
}

fn schema_key(version: u32) -> CampaignHash {
    let mut key = [0; 32];
    key[..4].copy_from_slice(&version.to_be_bytes());
    CampaignHash::from_bytes(key)
}

fn schema_from_key(key: CampaignHash) -> Result<u32, CampaignRepositoryError> {
    for version in 1..=crate::exploration::BRANCH_REQUEST_SCHEMA_VERSION {
        if key == schema_key(version) {
            return Ok(version);
        }
    }
    Err(integrity("planner-scan-index-unknown-request-schema"))
}
