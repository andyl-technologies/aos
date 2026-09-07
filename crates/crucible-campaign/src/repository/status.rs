//! Bounded snapshot-derived campaign status projection.

use super::*;
use crate::{
    AttemptId, CampaignContinuationStatus, CampaignLineageId, CampaignSemanticStatus,
    ContinuationState, MAX_CAMPAIGN_STATUS_CONTINUATION_BYTES, MAX_CAMPAIGN_STATUS_CONTINUATIONS,
};

const STATUS_FRONTIER_PAGE_ITEMS: usize = 10_000;

impl CampaignRepository {
    /// Tests bounded lineage-qualified attempt membership at one campaign snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when the snapshot or its accounting
    /// index is missing or corrupt.
    pub fn attempt_membership_at(
        &self,
        snapshot: CampaignSnapshotId,
        attempts: &[(CampaignLineageId, AttemptId)],
    ) -> Result<Vec<bool>, CampaignRepositoryError> {
        if attempts.len() > usize::try_from(MAX_CAMPAIGN_STATUS_CONTINUATIONS).unwrap_or(usize::MAX)
        {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "campaign-status-attempt-membership-limit",
            });
        }
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let lineage = loaded.snapshot.lineage();
        let accounting = loaded.snapshot.roots().accounting;
        attempts
            .iter()
            .map(|(candidate_lineage, attempt)| {
                if *candidate_lineage != lineage {
                    return Ok(false);
                }
                Ok(self.merkle.get(accounting, attempt_index_key(*attempt))?
                    == Some(attempt.content_id()))
            })
            .collect()
    }

    /// Derives exact semantic status from one authenticated campaign snapshot.
    ///
    /// The configuration-only corpus index supplies the stored graph-node
    /// count. The admission sequence supplies the cumulative admitted-attempt
    /// count. Continuation state requires a complete bounded scan of the
    /// snapshot's nested frontier index.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRepositoryError`] when snapshot closure or a
    /// projection is invalid, a count overflows, or the registered frontier
    /// record or byte bound would be exceeded.
    pub fn semantic_status_at(
        &self,
        snapshot: CampaignSnapshotId,
    ) -> Result<CampaignSemanticStatus, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        let roots = loaded.snapshot.roots();
        let stored_graph_nodes = self.merkle.inspect_shallow(roots.corpus)?.entry_count();
        let admitted_attempts = self.accounted_attempts(roots.accounting)?;
        let frontier = self
            .merkle
            .get(roots.exploration, frontier_index_anchor_key())?
            .ok_or_else(|| integrity("campaign-status-frontier-index-is-missing"))?;

        let mut counts = CampaignContinuationStatus::default();
        let mut records = 0_u64;
        let mut bytes = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(frontier, after, STATUS_FRONTIER_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                records = records
                    .checked_add(1)
                    .ok_or_else(|| integrity("campaign-status-continuation-count-overflow"))?;
                if records > MAX_CAMPAIGN_STATUS_CONTINUATIONS {
                    return Err(CampaignRepositoryError::InvalidRequest {
                        reason: "campaign-status-continuation-record-limit",
                    });
                }
                let projection = self.read_continuation_projection(*content)?;
                if *key != frontier_index_order_key(projection.request()) {
                    return Err(integrity("campaign-status-frontier-key-mismatch"));
                }
                bytes = bytes
                    .checked_add(u64::try_from(projection.canonical_bytes().len()).map_err(
                        |_| integrity("campaign-status-continuation-byte-count-overflow"),
                    )?)
                    .ok_or_else(|| integrity("campaign-status-continuation-byte-count-overflow"))?;
                if bytes > MAX_CAMPAIGN_STATUS_CONTINUATION_BYTES {
                    return Err(CampaignRepositoryError::InvalidRequest {
                        reason: "campaign-status-continuation-byte-limit",
                    });
                }
                counts = increment_continuation_status(counts, projection.state())?;
            }

            let Some(next) = page.next_after() else {
                break;
            };
            if after.is_some_and(|current| next <= current) {
                return Err(integrity("campaign-status-frontier-cursor-did-not-advance"));
            }
            after = Some(next);
        }

        CampaignSemanticStatus::new(
            counts,
            admitted_attempts,
            stored_graph_nodes,
            records,
            bytes,
        )
        .map_err(CampaignRepositoryError::from)
    }
}

fn increment_continuation_status(
    counts: CampaignContinuationStatus,
    state: ContinuationState,
) -> Result<CampaignContinuationStatus, CampaignRepositoryError> {
    let increment = |value: u64| {
        value
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-status-continuation-count-overflow"))
    };
    match state {
        ContinuationState::Ready => Ok(CampaignContinuationStatus::new(
            increment(counts.ready())?,
            counts.waiting_for_feedback(),
            counts.open(),
            counts.exhausted(),
            counts.closed(),
        )),
        ContinuationState::WaitingForFeedback(_) => Ok(CampaignContinuationStatus::new(
            counts.ready(),
            increment(counts.waiting_for_feedback())?,
            counts.open(),
            counts.exhausted(),
            counts.closed(),
        )),
        ContinuationState::Open => Ok(CampaignContinuationStatus::new(
            counts.ready(),
            counts.waiting_for_feedback(),
            increment(counts.open())?,
            counts.exhausted(),
            counts.closed(),
        )),
        ContinuationState::Exhausted => Ok(CampaignContinuationStatus::new(
            counts.ready(),
            counts.waiting_for_feedback(),
            counts.open(),
            increment(counts.exhausted())?,
            counts.closed(),
        )),
        ContinuationState::Closed => Ok(CampaignContinuationStatus::new(
            counts.ready(),
            counts.waiting_for_feedback(),
            counts.open(),
            counts.exhausted(),
            increment(counts.closed())?,
        )),
    }
}
