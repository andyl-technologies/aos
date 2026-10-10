//! Exact provider-plan admission and fenced compact-result retention.
//!
//! Provider authentication and byte custody are checked by the service's runtime
//! ports before result admission. A plan cannot change its durable quota or
//! request scope, and a late result cannot publish an observation head.

use anyhow::{bail, Context as _, Result};
use aos_assessment_runtime::provider::{
    NormalizedObject, ProviderWorkPlanV1, ProviderWorkResultV1, WorkOutcome,
};
use aos_assessment_runtime::scan::ScanUsage;
use aos_contract::Sha256Digest;

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

use super::objects::encode;
use super::scans::claim_values;
use super::AssessmentObjectKind;

/// Reuses an already settled physical question within the same logical scan.
#[derive(Clone, Debug)]
pub enum AssessmentProviderReplay {
    /// Previously admitted compact evidence, including explicitly partial results.
    Admitted(Box<ProviderWorkResultV1>),
    /// A settled failure that must remain an incomplete source in this scan.
    Failed,
}

impl Database {
    /// Reads one exact admitted question under a current coordinator claim.
    ///
    /// Admission time, rather than the old plan's expired execution window,
    /// validates retained evidence. Reuse never dispatches source work, extends
    /// authority or changes consumed quota. Unsettled attempts are not evidence.
    ///
    /// # Errors
    /// Returns an error for lost claims, ambiguous questions, changed retained
    /// commitments, conflicting scope, malformed evidence or persistence failure.
    pub async fn assessment_provider_replay(
        &self,
        registry_id: i64,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        operation: &aos_assessment_runtime::provider::ProviderOperation,
        previous: Option<&aos_assessment_runtime::provider::ProviderPageV1>,
    ) -> Result<Option<AssessmentProviderReplay>> {
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("assessment replay scan is absent")?;
        let rows = self
            .backend
            .query(
                "SELECT state, plan_digest, plan_json, result_digest, result_json
             FROM assessment_tasks WHERE scan_id = ?1 AND operation_digest = ?2
               AND generation = ?3 AND state IN ('succeeded', 'partial', 'failed')
               AND (plan_json IS NULL OR length(plan_json) <= 262144)
               AND (result_json IS NULL OR length(result_json) <= 262144) LIMIT 2",
                &vals![@slice claim.scan_id, operation.digest()?.to_string(), claim.generation],
            )
            .await?;
        if rows.len() > 1 {
            bail!("assessment question has ambiguous retained attempts");
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let Some(result_bytes) = row.get::<Option<Vec<u8>>>(4)? else {
            if row.get::<String>(0)? != "failed" {
                bail!("settled provider evidence is absent");
            }
            self.check_assessment_scan_claim(registry_id, claim).await?;
            return Ok(Some(AssessmentProviderReplay::Failed));
        };
        let plan_bytes = row
            .get::<Option<Vec<u8>>>(2)?
            .context("replay plan is absent")?;
        let plan: ProviderWorkPlanV1 = serde_json::from_slice(&plan_bytes)?;
        let result: ProviderWorkResultV1 = serde_json::from_slice(&result_bytes)?;
        if encode(&plan)? != plan_bytes
            || encode(&result)? != result_bytes
            || row.get::<Option<String>>(1)?.as_deref() != Some(plan.digest()?.to_string().as_str())
            || row.get::<Option<String>>(3)?.as_deref()
                != Some(
                    Sha256Digest::separated("aos.provider-work-result/v1", &result_bytes)
                        .to_string()
                        .as_str(),
                )
            || plan.operation != *operation
            || plan.claim.scan_id != claim.scan_id
            || plan.claim.request_digest != claim.request_digest
            || plan.claim.generation != claim.generation
            || plan.claim.inventory_revision != claim.inventory_revision
            || plan.inventory_digest != scan.request.inventory_digest
            || plan.policy_digest != scan.request.policy_digest
            || plan.authorization_partition != scan.request.authorization_partition
            || plan.continuation != previous.map(|page| page.digest()).transpose()?
            || plan.continuation_ref.as_ref() != previous
        {
            bail!("assessment replay differs from its admitted question or scope");
        }
        result.validate_for(&plan, &result.completed_at)?;
        self.check_assessment_scan_claim(registry_id, claim).await?;
        Ok(Some(AssessmentProviderReplay::Admitted(Box::new(result))))
    }

    /// Retains an incomplete pre-dispatch question without inventing a reservation.
    ///
    /// A missing route, unavailable capability or refused quota is stable for
    /// this logical scan. Later quanta skip it; a new explicitly admitted scan
    /// can ask again. Existing physical attempts are preserved, including unknown
    /// outcomes. At most 8192 settled questions fit one bounded acquisition plan.
    ///
    /// # Errors
    /// Returns an error for revoked or lost authority, excessive question count,
    /// conflicting work or unavailable persistence.
    pub async fn refuse_assessment_provider_question_fenced(
        &self,
        registry_id: i64,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        operation: &aos_assessment_runtime::provider::ProviderOperation,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment question refusal exceeds its authority ceiling");
        }
        operation.validate()?;
        self.check_assessment_scan_claim(registry_id, claim).await?;
        let scan = self
            .assessment_scan(registry_id, &claim.scan_id)
            .await?
            .context("refused question scan is absent")?;
        let existing = self.backend.query_opt(
            "SELECT 1 FROM assessment_tasks WHERE scan_id = ?1 AND operation_digest = ?2 LIMIT 1",
            &vals![@slice claim.scan_id, operation.digest()?.to_string()],
        ).await?.is_some();
        let usage = if existing {
            scan.usage.clone()
        } else {
            scan.usage.consume(
                &ScanUsage {
                    tasks: 1,
                    ..Default::default()
                },
                &scan.request.limits,
            )?
        };
        let mut values = claim_values(registry_id, claim);
        values.extend(vals![
            operation.digest()?.hex(),
            operation.digest()?.to_string()
        ]);
        let mut statements = authority_fences.to_vec();
        statements.push(
            Statement::new(
                format!(
                    "UPDATE assessment_scans SET resource_version = resource_version + 1, usage_json = ?9
             WHERE {} AND resource_version = ?10 AND (SELECT count(*) FROM assessment_tasks WHERE scan_id = ?2) < 8192",
                    self.assessment_claim_guard()
                ),
                { let mut usage_values = claim_values(registry_id, claim);
                    usage_values.extend(vals![encode(&usage)?, scan.resource_version]); usage_values },
            )
            .expecting(1),
        );
        statements.push(
            Statement::new(
                format!(
                    "INSERT INTO assessment_tasks(scan_id, task_id, operation_digest, generation,
                 state, attempt, not_before, last_error_code, resource_version)
             SELECT ?2, ?9, ?10, ?4, 'failed', ?7, 0, 'source-question-refused', 1
             WHERE EXISTS(SELECT 1 FROM assessment_scans WHERE {})
               AND NOT EXISTS(SELECT 1 FROM assessment_tasks WHERE scan_id = ?2
                 AND operation_digest = ?10)",
                    self.assessment_claim_guard()
                ),
                values,
            )
            .unchecked(),
        );
        self.backend.checked_batch(&statements).await
    }

    /// Settles a failed physical attempt without refunding its reserved allowance.
    ///
    /// A response deadline may already have elapsed. Settlement still requires
    /// the current parent lease and exact child attempt; it grants no result or
    /// observation admission authority and cannot revive cancelled work.
    ///
    /// # Errors
    /// Returns an error for an invalid diagnostic, stale parent/child authority
    /// or unavailable persistence.
    pub async fn fail_assessment_provider_work(
        &self,
        registry_id: i64,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        code: &str,
    ) -> Result<()> {
        self.fail_assessment_provider_work_fenced(registry_id, claim, code, &[])
            .await
    }

    /// Settles an uncertain physical attempt under current principal and job guards.
    ///
    /// The exact attempt settlement and installed source backoff share the
    /// authority transaction. Failed guards preserve both prior states.
    ///
    /// # Errors
    /// Returns an error for invalid diagnostic, excessive/revoked authority,
    /// stale parent/child claim or unavailable persistence.
    pub async fn fail_assessment_provider_work_fenced(
        &self,
        registry_id: i64,
        claim: &aos_assessment_runtime::scan::TaskClaim,
        code: &str,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment failure settlement exceeds its authority ceiling");
        }
        if code.is_empty()
            || code.len() > 128
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || claim.task_id == "coordinator"
        {
            bail!("provider failure settlement has an invalid bounded diagnostic or task");
        }
        let mut parent = claim.clone();
        parent.task_id = "coordinator".into();
        self.check_assessment_scan_claim(registry_id, &parent)
            .await?;
        let mut values = claim_values(registry_id, &parent);
        values.extend(vals![claim.task_id, code]);
        let mut statements = authority_fences.to_vec();
        statements.extend([
            Statement::new(
                format!(
                    "UPDATE assessment_tasks SET state = 'failed', last_error_code = ?10,
                 lease_expires_at = NULL, resource_version = resource_version + 1
             WHERE scan_id = ?2 AND task_id = ?9 AND claim_token = ?3 AND attempt = ?7
               AND generation = ?4 AND state = 'leased'
               AND EXISTS(SELECT 1 FROM assessment_scans WHERE {})",
                    self.assessment_claim_guard()
                ),
                values,
            )
            .expecting(1),
            self.assessment_provider_failure_budget_statement(claim, None)?,
        ]);
        self.backend.checked_batch(&statements).await
    }

    /// Binds an installed typed plan to its already consumed exact reservation.
    ///
    /// The planner independently authorizes source, credential and evidence
    /// scope. Identical retries preserve the issued plan; replacements require a
    /// new attempt and reservation, rather than renewing the same allowance.
    ///
    /// # Errors
    /// Returns an error for changed operation/partition/budget, stale parent or
    /// child claims, conflicting plans or unavailable persistence.
    pub async fn admit_assessment_provider_plan(
        &self,
        registry_id: i64,
        plan: &ProviderWorkPlanV1,
    ) -> Result<()> {
        self.admit_assessment_provider_plan_fenced(registry_id, plan, &[])
            .await
    }

    /// Admits an issued plan while holding current principal and job authority.
    ///
    /// # Errors
    /// Returns plan admission failures or invalid/revoked current authority guards.
    pub async fn admit_assessment_provider_plan_fenced(
        &self,
        registry_id: i64,
        plan: &ProviderWorkPlanV1,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment plan authority exceeds its ceiling");
        }
        plan.validate_at(&self.assessment_database_time().await?)?;
        self.check_assessment_provider_claim(registry_id, &plan.claim)
            .await?;
        let scan = self
            .assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .context("provider scan is absent")?;
        if plan.authorization_partition != scan.request.authorization_partition
            || plan.inventory_digest != scan.request.inventory_digest
            || plan.policy_digest != scan.request.policy_digest
        {
            bail!("provider plan differs from the operation's exact scope");
        }
        let digest = plan.digest()?;
        let bytes = encode(plan)?;
        if bytes.len() > 256 * 1024 {
            bail!("provider plan exceeds its compact journal bound");
        }
        let row = self.backend.query_opt(
            "SELECT task.plan_digest, task.plan_json, task.operation_digest, reservation.budget_key,
                reservation.request_allowance, reservation.deadline, task.reservation_id
             FROM assessment_tasks AS task JOIN assessment_budget_reservations AS reservation
               ON reservation.reservation_id = task.reservation_id AND reservation.attempt = task.attempt
             WHERE task.scan_id = ?1 AND task.task_id = ?2", &vals![@slice plan.claim.scan_id, plan.claim.task_id],
        ).await?.context("provider reservation is absent")?;
        if row.get::<String>(2)? != plan.operation.digest()?.to_string()
            || row.get::<String>(3)? != plan.budget_reservation.source_budget
            || row.get::<u32>(4)? != plan.budget_reservation.requests
            || row.get::<u64>(5)? != plan.budget_reservation.deadline.unix_seconds()
            || row.get::<String>(6)? != plan.budget_reservation.reservation_id
        {
            bail!("provider plan changed its durable operation or reservation");
        }
        if let Some(prior) = row.get::<Option<String>>(0)? {
            if prior != digest.to_string()
                || row.get::<Option<Vec<u8>>>(1)?.as_deref() != Some(bytes.as_slice())
            {
                bail!("current provider attempt already has a different immutable plan");
            }
            self.check_assessment_provider_claim(registry_id, &plan.claim)
                .await?;
            self.backend.checked_batch(authority_fences).await?;
            return Ok(());
        }
        let mut values = claim_values(registry_id, &plan.claim);
        values.extend(vals![
            plan.claim.task_id,
            digest.to_string(),
            bytes,
            plan.budget_reservation.reservation_id
        ]);
        let clock = self.backend.dialect().unix_time_expression();
        let mut statements = authority_fences.to_vec();
        statements.push(Statement::new(format!(
            "UPDATE assessment_tasks SET plan_digest = ?10, plan_json = ?11, resource_version = resource_version + 1
             WHERE scan_id = ?2 AND task_id = ?9 AND claim_token = ?3 AND attempt = ?7
               AND generation = ?4 AND state = 'leased' AND lease_expires_at > {clock}
               AND plan_digest IS NULL AND reservation_id = ?12
               AND EXISTS(SELECT 1 FROM assessment_scans WHERE {})
               AND EXISTS(SELECT 1 FROM assessment_budget_reservations WHERE reservation_id = ?12 AND deadline > {clock})",
            self.assessment_claim_guard()), values).expecting(1));
        self.backend.checked_batch(&statements).await?;
        Ok(())
    }

    /// Admits a verified compact result under its exact stored plan and live claim.
    ///
    /// The caller authenticates the paired executor and verifies custody for
    /// every raw source reference before admission. Unknown or partial outcomes
    /// remain explicit; a successful SQL transaction never implies clean risk.
    ///
    /// # Errors
    /// Returns an error for stale work, changed plans/results, malformed projections,
    /// exhausted operation allowance or unavailable immutable object custody.
    pub async fn admit_assessment_provider_result(
        &self,
        registry_id: i64,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
    ) -> Result<()> {
        self.admit_assessment_provider_result_fenced(registry_id, plan, result, &[])
            .await
    }

    /// Publishes compact provider evidence while holding current IAM and job guards.
    ///
    /// Immutable retained objects confer no authority until this transaction
    /// accepts the exact result and its index rows under the current actor.
    ///
    /// # Errors
    /// Returns result admission failures or invalid/revoked current authority guards.
    pub async fn admit_assessment_provider_result_fenced(
        &self,
        registry_id: i64,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
        authority_fences: &[CheckedStatement],
    ) -> Result<()> {
        if authority_fences.len() > 32 {
            bail!("assessment source result authority exceeds its ceiling");
        }
        let result_bytes = encode(result)?;
        if result_bytes.len() > 256 * 1024 {
            bail!("provider result exceeds its compact journal bound");
        }
        let result_digest = Sha256Digest::separated("aos.provider-work-result/v1", &result_bytes);
        let row = self
            .backend
            .query_opt(
                "SELECT plan_digest, plan_json, result_digest, result_json FROM assessment_tasks
             WHERE scan_id = ?1 AND task_id = ?2 AND length(plan_json) <= 262144",
                &vals![@slice plan.claim.scan_id, plan.claim.task_id],
            )
            .await?
            .context("admitted provider plan is absent")?;
        if row.get::<Option<String>>(0)?.as_deref() != Some(plan.digest()?.to_string().as_str())
            || row.get::<Option<Vec<u8>>>(1)?.as_deref() != Some(encode(plan)?.as_slice())
        {
            bail!("provider result does not belong to the exact retained plan");
        }
        if let Some(prior) = row.get::<Option<String>>(2)? {
            if prior == result_digest.to_string()
                && row.get::<Option<Vec<u8>>>(3)?.as_deref() == Some(result_bytes.as_slice())
            {
                self.backend.checked_batch(authority_fences).await?;
                return Ok(());
            }
            bail!("provider attempt already admitted a different immutable result");
        }
        let now = self.assessment_database_time().await?;
        result.validate_for(plan, &now)?;
        self.check_assessment_provider_claim(registry_id, &plan.claim)
            .await?;
        let scan = self
            .assessment_scan(registry_id, &plan.claim.scan_id)
            .await?
            .context("provider scan is absent")?;
        let mut normalized_bytes = result_bytes.len() as u64;
        let mut objects = Vec::with_capacity(result.normalized_objects.len());
        for projection in &result.normalized_objects {
            let (kind, bytes) = match &projection.object {
                NormalizedObject::Observation(value) => {
                    (AssessmentObjectKind::Observation, encode(value)?)
                }
                NormalizedObject::Advisory(value) => {
                    (AssessmentObjectKind::AdvisoryRecord, encode(value)?)
                }
                NormalizedObject::Upstream(value) => {
                    (AssessmentObjectKind::Upstream, encode(value)?)
                }
                NormalizedObject::KnownExploit(value) => {
                    (AssessmentObjectKind::KnownExploit, encode(value)?)
                }
                NormalizedObject::Page(value) => {
                    (AssessmentObjectKind::ProviderPage, encode(value)?)
                }
            };
            normalized_bytes = normalized_bytes
                .checked_add(bytes.len() as u64)
                .context("provider normalized-byte usage overflow")?;
            objects.push((kind, projection.digest, bytes));
        }
        let usage = scan.usage.consume(
            &ScanUsage {
                normalized_bytes,
                ..Default::default()
            },
            &scan.request.limits,
        )?;
        for (kind, digest, bytes) in objects {
            self.put_assessment_object(
                &plan.authorization_partition,
                kind,
                digest,
                &bytes,
                now.unix_seconds() as i64,
            )
            .await?;
        }
        let mut values = claim_values(registry_id, &plan.claim);
        values.extend(vals![encode(&usage)?, scan.resource_version]);
        let mut statements = authority_fences.to_vec();
        statements.extend([Statement::new(
            format!(
            "UPDATE assessment_scans SET usage_json = ?9, resource_version = resource_version + 1
             WHERE {} AND resource_version = ?10", self.assessment_claim_guard()),
            values,
        )
        .expecting(1)]);
        let state = match result.outcome {
            WorkOutcome::Observed | WorkOutcome::NotModified => "succeeded",
            WorkOutcome::Partial => "partial",
            WorkOutcome::Failed => "failed",
        };
        let clock = self.backend.dialect().unix_time_expression();
        statements.push(Statement::new(format!(
            "UPDATE assessment_tasks SET state = ?6, result_digest = ?7, result_json = ?8,
                 continuation_digest = ?9, claim_token = NULL, lease_expires_at = NULL, resource_version = resource_version + 1
             WHERE scan_id = ?1 AND task_id = ?2 AND claim_token = ?3 AND attempt = ?4
               AND plan_digest = ?5 AND state = 'leased' AND lease_expires_at > {clock}
               AND EXISTS(SELECT 1 FROM assessment_budget_reservations WHERE reservation_id = ?10 AND deadline > {clock})"),
            vals![plan.claim.scan_id, plan.claim.task_id, plan.claim.claim_token, plan.claim.attempt, plan.digest()?.to_string(),
                state, result_digest.to_string(), result_bytes, result.continuation.map(|digest| digest.to_string()), plan.budget_reservation.reservation_id],
        ).expecting(1));
        if super::source_health::indicates_outage(result) {
            statements.push(self.assessment_provider_failure_budget_statement(
                &plan.claim,
                result.retry.as_ref().map(|retry| &retry.not_before),
            )?);
        } else if matches!(
            result.outcome,
            WorkOutcome::Observed | WorkOutcome::NotModified
        ) {
            statements.push(self.assessment_provider_success_budget_statement(&plan.claim));
        }
        // Index rows convey the same admitted authority as the result receipt;
        // retention alone must not publish current query or history heads.
        statements.extend(
            self.assessment_provider_index_statements(plan, result, now.unix_seconds())?
                .into_iter()
                .map(Statement::unchecked),
        );
        self.backend.checked_batch(&statements).await?;
        Ok(())
    }
}
