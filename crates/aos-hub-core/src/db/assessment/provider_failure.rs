//! Projects failure events only from an exact retained physical source plan.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::events::{AssessmentEventPayload, SourceFailureV1};
use aos_assessment_runtime::provider::ProviderWorkPlanV1;
use aos_assessment_runtime::scan::TaskClaim;

use crate::backend::CheckedStatement;
use crate::db::Database;

use super::objects::encode;

impl Database {
    pub(super) async fn assessment_execution_failure_event_statements(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
        now: &Timestamp,
    ) -> Result<Vec<CheckedStatement>> {
        let row = self
            .backend
            .query_opt(
                "SELECT plan_digest, plan_json FROM assessment_tasks
             WHERE scan_id = ?1 AND task_id = ?2
               AND (plan_json IS NULL OR length(plan_json) <= 262144)",
                &vals![@slice claim.scan_id, claim.task_id],
            )
            .await?
            .context("failed source task has no bounded retained plan row")?;
        let Some(bytes) = row.get::<Option<Vec<u8>>>(1)? else {
            // A reservation alone does not assert that a typed source plan was issued.
            return Ok(Vec::new());
        };
        let plan: ProviderWorkPlanV1 = serde_json::from_slice(&bytes)?;
        ensure!(
            plan.claim == *claim
                && encode(&plan)? == bytes
                && row.get::<Option<String>>(0)?.as_deref()
                    == Some(plan.digest()?.to_string().as_str()),
            "failed source task differs from its immutable issued plan"
        );
        // The child may have expired during uncertain execution. The settlement
        // transaction still requires current parent authority and the exact child.
        self.assessment_event_statements(
            registry_id,
            vec![AssessmentEventPayload::SourceFailed {
                failure: Box::new(SourceFailureV1::from_failed_execution(&plan)?),
            }],
            now,
        )
        .await
    }
}
