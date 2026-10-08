//! Authenticated planner scan-page construction.

use super::*;

impl CampaignRepository {
    pub(in crate::repository) fn planner_scan_page(
        &self,
        view: &CampaignPlanningView,
        after: Option<PlanningScanPosition>,
        limit: u32,
    ) -> Result<PlanningScanPage, CampaignRepositoryError> {
        let limit_usize =
            usize::try_from(limit).map_err(|_| integrity("planner-scan-page-limit-is-invalid"))?;
        if limit == 0 || limit > MAX_PLANNER_SCAN_PAGE_ITEMS {
            return Err(integrity("planner-scan-page-limit-is-invalid"));
        }
        if let Some(after) = after {
            let source_content = after.source().content_id();
            if self.merkle.get(
                view.exploration(),
                map_key_content("exploration.branch-request", source_content),
            )? != Some(source_content)
                || self.read_branch_request(source_content)?.branch_point() != after.branch_point()
            {
                return Err(integrity("planner-scan-page-after-is-not-authoritative"));
            }
        }

        let retained_limit = limit_usize
            .checked_add(1)
            .ok_or_else(|| integrity("planner-scan-page-limit-is-invalid"))?;
        let mut retained =
            self.indexed_planner_scan_positions(view.exploration(), after, retained_limit)?;
        let complete = retained.len() <= limit_usize;
        if !complete {
            retained.pop_last();
        }
        let input_bytes = retained.values().try_fold(0_u64, |total, bytes| {
            total
                .checked_add(*bytes)
                .ok_or_else(|| integrity("planner-scan-page-input-byte-overflow"))
        })?;
        PlanningScanPage::new(
            after,
            limit,
            retained.into_keys().collect(),
            complete,
            input_bytes,
        )
        .map_err(Into::into)
    }
}
