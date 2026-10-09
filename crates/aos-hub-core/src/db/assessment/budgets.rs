//! Shared database-clock provider quotas reserved atomically before dispatch.
//!
//! Failed or uncertain dispatch never refunds allowance. Horizontal executors
//! use the same row, so adding Workers cannot multiply an installed source budget.

use anyhow::{Context as _, Result, bail};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::provider::BudgetReservation;
use aos_assessment_runtime::scan::{ScanUsage, TaskClaim};
use aos_contract::Sha256Digest;

use crate::backend::Statement;
use crate::db::Database;

/// Defines an installed shared quota, independently of package metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessmentSourceBudget {
    /// Installed provider/account quota identity shared by all executors.
    pub key: String,
    /// Fixed UTC quota window, at most one day.
    pub window_seconds: u32,
    /// Maximum requests per window.
    pub allowance: u32,
    /// Minimum spacing between reservations; spaced profiles reserve one request.
    pub min_interval_seconds: u32,
}

/// Binds one conservative quota reservation to its exact durable child claim.
#[derive(Clone, Debug)]
pub struct AssessmentProviderReservation {
    /// Current child identity, fenced by the coordinator's attempt token.
    pub claim: TaskClaim,
    /// Exact shared source allowance and exclusive dispatch deadline.
    pub budget: BudgetReservation,
}

/// Selects one bounded task and its installed source quota before dispatch.
#[derive(Clone, Debug)]
pub struct AssessmentProviderWork {
    /// Stable child reference across coordinator attempts.
    pub task_id: String,
    /// Exact typed operation identity chosen by the planner.
    pub operation_digest: Sha256Digest,
    /// Installed provider/account quota key.
    pub budget_key: String,
    /// Conservatively consumed source calls, at most ten.
    pub requests: u32,
    /// Exclusive reservation lifetime, at most sixty seconds.
    pub deadline_seconds: u32,
}

impl Database {
    /// Installs an exact source budget without resetting consumed allowance.
    ///
    /// # Errors
    /// Returns an error for invalid ceilings, different existing configuration,
    /// or unavailable persistence. Runtime callers cannot enlarge existing quotas.
    pub async fn install_assessment_source_budget(
        &self,
        budget: &AssessmentSourceBudget,
    ) -> Result<()> {
        if budget.key.is_empty()
            || budget.key.len() > 128
            || budget.key.chars().any(char::is_control)
            || budget.window_seconds == 0
            || budget.window_seconds > 86400
            || budget.allowance == 0
            || budget.allowance > 1_000_000
            || budget.min_interval_seconds > 3600
        {
            bail!("installed assessment source budget is invalid");
        }
        let now = self.assessment_database_time().await?.unix_seconds();
        let start = now / u64::from(budget.window_seconds) * u64::from(budget.window_seconds);
        self.backend.execute(
            "INSERT INTO assessment_source_budgets
                (budget_key, window_start, window_seconds, allowance, consumed, min_interval_seconds,
                 next_eligible_at, circuit_until, failure_count, resource_version)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, 0, 0, 0, 1) ON CONFLICT(budget_key) DO NOTHING",
            &vals![@slice budget.key, start, budget.window_seconds, budget.allowance, budget.min_interval_seconds],
        ).await?;
        let row = self.backend.query_opt(
            "SELECT window_seconds, allowance, min_interval_seconds FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice budget.key],
        ).await?.context("installed source budget is absent")?;
        if row.get::<u32>(0)? != budget.window_seconds
            || row.get::<u32>(1)? != budget.allowance
            || row.get::<u32>(2)? != budget.min_interval_seconds
        {
            bail!("source budget conflicts with its installed immutable quota");
        }
        Ok(())
    }

    /// Reserves source and operation-wide allowance before issuing typed provider work.
    ///
    /// The service chooses installed source/task identities and operation digest;
    /// package declarations cannot choose arbitrary budgets or enlarge allowance.
    /// The entire reservation, child lease and monotonic usage commit together.
    ///
    /// # Errors
    /// Returns an error for stale claims, exhausted quotas/limits, duplicate live
    /// child attempts, invalid scope/deadline or unavailable persistence.
    pub async fn reserve_assessment_provider_work(
        &self,
        registry_id: i64,
        coordinator: &TaskClaim,
        work: &AssessmentProviderWork,
    ) -> Result<AssessmentProviderReservation> {
        let task_id = work.task_id.as_str();
        let operation_digest = work.operation_digest;
        let budget_key = work.budget_key.as_str();
        let requests = work.requests;
        let deadline_seconds = work.deadline_seconds;
        self.check_assessment_scan_claim(registry_id, coordinator)
            .await?;
        if task_id.is_empty()
            || task_id == "coordinator"
            || task_id.len() > 128
            || task_id.chars().any(char::is_control)
            || budget_key.is_empty()
            || budget_key.len() > 128
            || budget_key.chars().any(char::is_control)
            || !(1..=10).contains(&requests)
            || !(1..=60).contains(&deadline_seconds)
        {
            bail!("provider reservation scope, allowance or deadline is invalid");
        }
        let scan = self
            .assessment_scan(registry_id, &coordinator.scan_id)
            .await?
            .context("provider scan is absent")?;
        let usage = scan.usage.consume(
            &ScanUsage {
                provider_requests: requests,
                tasks: 1,
                normalized_bytes: 0,
            },
            &scan.request.limits,
        )?;
        let row = self.backend.query_opt(
            "SELECT window_seconds, min_interval_seconds FROM assessment_source_budgets WHERE budget_key = ?1",
            &vals![@slice budget_key],
        ).await?.context("provider source budget is not installed")?;
        let window_seconds: u64 = row.get(0)?;
        let min_interval: u32 = row.get(1)?;
        if window_seconds == 0 || (min_interval > 0 && requests != 1) {
            bail!("spaced provider budget requires one request per reservation");
        }
        let now = self.assessment_database_time().await?;
        let deadline =
            Timestamp::from_unix_seconds(now.unix_seconds() + u64::from(deadline_seconds))?;
        if deadline > coordinator.expires_at {
            bail!("provider deadline exceeds the coordinator lease");
        }
        let window_start = now.unix_seconds() / window_seconds * window_seconds;
        let reservation_id = uuid::Uuid::new_v4().simple().to_string();
        let clock = self.backend.dialect().unix_time_expression();
        let mut scan_values = super::scans::claim_values(registry_id, coordinator);
        scan_values.extend(vals![serde_json::to_vec(&usage)?, scan.resource_version]);
        let commit = vec![
            Statement::new(format!(
                "UPDATE assessment_scans SET usage_json = ?9, resource_version = resource_version + 1, updated_at = {clock}
                 WHERE {} AND resource_version = ?10", self.assessment_claim_guard()), scan_values).expecting(1),
            Statement::new(format!(
                "UPDATE assessment_source_budgets
                 SET consumed = CASE WHEN window_start + window_seconds <= {clock} THEN ?2 ELSE consumed + ?2 END,
                     next_eligible_at = {clock} + min_interval_seconds,
                     resource_version = resource_version + 1, window_start = ?3
                 WHERE budget_key = ?1 AND circuit_until <= {clock} AND next_eligible_at <= {clock}
                   AND window_seconds = ?4 AND {clock} >= ?3 AND {clock} < ?3 + window_seconds
                   AND ?2 <= allowance
                   AND (window_start + window_seconds <= {clock} OR consumed + ?2 <= allowance)"
            ), vals![budget_key, requests, window_start, window_seconds]).expecting(1),
            Statement::new(
                "INSERT INTO assessment_tasks
                    (scan_id, task_id, operation_digest, generation, state, attempt, not_before, resource_version)
                 VALUES (?1, ?2, ?3, ?4, 'pending', 0, 0, 1)
                 ON CONFLICT(scan_id, task_id) DO NOTHING",
                vals![coordinator.scan_id, task_id, operation_digest.to_string(), coordinator.generation],
            ).unchecked(),
            Statement::new(format!(
                "UPDATE assessment_tasks SET state = 'leased', claim_token = ?3, attempt = ?4,
                     plan_digest = NULL, plan_json = NULL, result_digest = NULL, result_json = NULL,
                     continuation_digest = NULL, last_error_code = NULL,
                     lease_expires_at = ?5, reservation_id = ?6, resource_version = resource_version + 1
                 WHERE scan_id = ?1 AND task_id = ?2 AND operation_digest = ?7 AND generation = ?8
                   AND (state = 'pending' OR (state IN('leased', 'waiting', 'failed') AND attempt < ?4
                        AND (lease_expires_at IS NULL OR lease_expires_at <= {clock})))"
            ), vals![coordinator.scan_id, task_id, coordinator.claim_token, coordinator.attempt,
                coordinator.expires_at.unix_seconds(), reservation_id, operation_digest.to_string(), coordinator.generation]).expecting(1),
            Statement::new(
                "INSERT INTO assessment_budget_reservations
                    (reservation_id, budget_key, scan_id, task_id, attempt, request_allowance, deadline, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vals![reservation_id, budget_key, coordinator.scan_id, task_id, coordinator.attempt,
                    requests, deadline.unix_seconds(), now.unix_seconds()],
            ).expecting(1),
        ];
        self.backend.checked_batch(&commit).await?;
        let mut claim = coordinator.clone();
        claim.task_id = task_id.into();
        Ok(AssessmentProviderReservation {
            claim,
            budget: BudgetReservation {
                source_budget: budget_key.into(),
                reservation_id,
                requests,
                deadline,
            },
        })
    }

    /// Checks a child against its current parent, lease and unexpired reservation.
    ///
    /// # Errors
    /// Returns an error for revoked/expired parent or child, superseded attempts,
    /// missing reservations or SQL failure.
    pub async fn check_assessment_provider_claim(
        &self,
        registry_id: i64,
        claim: &TaskClaim,
    ) -> Result<()> {
        let mut parent = claim.clone();
        parent.task_id = "coordinator".into();
        parent.validate_at(&self.assessment_database_time().await?)?;
        let clock = self.backend.dialect().unix_time_expression();
        let guard = self.assessment_claim_guard();
        let mut values = super::scans::claim_values(registry_id, &parent);
        values.extend(vals![claim.task_id]);
        let row = self.backend.query_opt(&format!(
            "SELECT 1 FROM assessment_scans WHERE {guard}
             AND EXISTS(SELECT 1 FROM assessment_tasks AS task JOIN assessment_budget_reservations AS reservation
                 ON reservation.reservation_id = task.reservation_id AND reservation.scan_id = task.scan_id
                    AND reservation.task_id = task.task_id AND reservation.attempt = task.attempt
                 WHERE task.scan_id = ?2 AND task.task_id = ?9 AND task.claim_token = ?3 AND task.attempt = ?7
                   AND task.generation = ?4 AND task.state = 'leased' AND task.lease_expires_at > {clock}
                   AND reservation.deadline > {clock})"
        ), &values).await?;
        if row.is_none() {
            bail!("provider child lost its current reservation fence");
        }
        Ok(())
    }
}
