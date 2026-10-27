//! Direct integer-selection index maintained with each canonical observation.
//!
//! Corpus mutation needs the integer values selected by direct children of
//! one branch point. The branch-point credit index cannot answer that
//! cheaply: it credits every descendant observation, and most of those
//! descend through deeper branch points. This index records only the
//! observation that first realized each direct branch selection, ordered by
//! value, so readers stream anchors in canonical order and stop early.
//!
//! ```text
//! observations[direct-selection anchor]
//!   -> map { H(branch point) -> map { order(value, selection) -> observation } }
//! ```
//!
//! Genesis publishes the anchor empty. The nested key layout is documented on
//! [`direct_selection_index_order_key`]. An entry is written once: a later
//! observation of the same selection leaves the earlier entry in place, which
//! keeps the index a pure function of the parent snapshot and the observation.

use super::*;

/// One nested direct-selection insertion projected for an observation.
pub(super) struct DirectSelectionIndexEntry {
    branch_key: CampaignHash,
    order_key: CampaignHash,
    observation: ContentId,
}

impl CampaignRepository {
    /// Projects the direct-selection entry contributed by one canonical observation.
    ///
    /// Only branch attempts with an integer selection contribute. The result
    /// is `None` when the attempt is not a branch, the value is not an integer,
    /// or the same selection already has an entry at its branch point.
    pub(super) fn direct_selection_index_entry(
        &self,
        observations_root: ContentId,
        attempt: &Attempt,
        observation: ContentId,
    ) -> Result<Option<DirectSelectionIndexEntry>, CampaignRepositoryError> {
        let AttemptStart::Branch { selection, .. } = attempt.start() else {
            return Ok(None);
        };
        let resolved = self.resolve_selection(selection)?;

        // Branch attempts are admitted only with a replay-valid campaign-branch
        // selection, so any other origin is a corrupt record.
        let crate::SelectionOrigin::CampaignBranch { branch_point, .. } =
            resolved.selection().origin()
        else {
            return Err(integrity("observation-branch-selection-origin-mismatch"));
        };
        let crate::ChoiceValue::Integer(value) = resolved.selection().value() else {
            return Ok(None);
        };

        let index = self
            .merkle
            .get(observations_root, direct_selection_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-direct-selection-index-is-missing"))?;
        let branch_key = direct_selection_index_branch_key(branch_point);
        let order_key = direct_selection_index_order_key(*value, selection);
        if let Some(branch_root) = self.merkle.get(index, branch_key)?
            && self.merkle.get(branch_root, order_key)?.is_some()
        {
            return Ok(None);
        }

        Ok(Some(DirectSelectionIndexEntry {
            branch_key,
            order_key,
            observation,
        }))
    }

    /// Returns the direct-selection anchor root after one nested insertion.
    ///
    /// Projection computes the root without storing nodes. Publication stores
    /// both nested levels and must reproduce the projected root exactly.
    pub(super) fn direct_selection_index_after(
        &self,
        observations_root: ContentId,
        entry: &DirectSelectionIndexEntry,
        publish: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        let index = self
            .merkle
            .get(observations_root, direct_selection_index_anchor_key())?
            .ok_or_else(|| integrity("current-campaign-direct-selection-index-is-missing"))?;
        let branch_root = self
            .merkle
            .get(index, entry.branch_key)?
            .unwrap_or(MerkleMap::empty_content_id()?);

        let branch_upserts = BTreeMap::from([(entry.order_key, entry.observation)]);
        let next_branch_root = if publish {
            self.insert_upserts(branch_root, &branch_upserts)?
        } else {
            self.merkle
                .root_after_upserts(branch_root, &branch_upserts)?
        };

        let index_upserts = BTreeMap::from([(entry.branch_key, next_branch_root)]);
        if publish {
            self.insert_upserts(index, &index_upserts)
        } else {
            self.merkle
                .root_after_upserts(index, &index_upserts)
                .map_err(Into::into)
        }
    }
}
