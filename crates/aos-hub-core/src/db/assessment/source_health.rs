//! Persisted provider outage backoff shared by every installed executor.
//!
//! Physical settlement updates the installed budget in the same transaction as
//! the attempt receipt. Replays never add failures or refund quota. A successful
//! response cannot shorten a cooldown imposed by another concurrent attempt.

use anyhow::Result;
pub(super) use aos_assessment_runtime::provider::provider_result_indicates_outage as indicates_outage;
use aos_assessment_runtime::provider::{
    provider_backoff_jitter, MAX_PROVIDER_BACKOFF_SECONDS, PROVIDER_BACKOFF_STEPS,
};
use aos_assessment_runtime::scan::TaskClaim;

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod retry_tests;

impl Database {
    /// Records one settled uncertain or retryable outage under its reservation.
    ///
    /// # Errors
    /// Returns an error if the exact claim commitment cannot be serialized.
    pub(super) fn assessment_provider_failure_budget_statement(
        &self,
        claim: &TaskClaim,
        retry_not_before: Option<&aos_assessment::time::Timestamp>,
    ) -> Result<CheckedStatement> {
        let clock = self.backend.dialect().unix_time_expression();
        let jitter = provider_backoff_jitter(claim)?;
        // The locked row supplies the count, preventing lost concurrent
        // increments. Both SQL stores and local custody use the same delays.
        let mut delay = String::from("CASE failure_count");
        for (failures, seconds) in PROVIDER_BACKOFF_STEPS.iter().enumerate() {
            delay.push_str(&format!(" WHEN {failures} THEN {}", seconds + jitter));
        }
        delay.push_str(&format!(" ELSE {MAX_PROVIDER_BACKOFF_SECONDS} END"));
        let circuit_delay = format!("CASE WHEN ({delay}) < 300 THEN 300 ELSE ({delay}) END");
        let eligible =
            format!("CASE WHEN ?5 > {clock} + ({delay}) THEN ?5 ELSE {clock} + ({delay}) END");
        let circuit = format!("CASE WHEN ?5 > {clock} + ({circuit_delay}) THEN ?5 ELSE {clock} + ({circuit_delay}) END");
        Ok(Statement::new(
            format!(
                "UPDATE assessment_source_budgets SET
                 next_eligible_at = CASE WHEN next_eligible_at > ({eligible})
                    THEN next_eligible_at ELSE ({eligible}) END,
                 circuit_until = CASE WHEN failure_count >= 4 THEN
                    CASE WHEN circuit_until > ({circuit})
                         THEN circuit_until ELSE ({circuit}) END
                    ELSE circuit_until END,
                 failure_count = CASE WHEN failure_count < 20 THEN failure_count + 1 ELSE 20 END,
                 resource_version = resource_version + 1
             WHERE budget_key = (
                 SELECT reservation.budget_key FROM assessment_budget_reservations reservation
                 JOIN assessment_tasks task ON task.reservation_id = reservation.reservation_id
                    AND task.scan_id = reservation.scan_id AND task.task_id = reservation.task_id
                    AND task.attempt = reservation.attempt
                 WHERE reservation.scan_id = ?1 AND reservation.task_id = ?2
                    AND reservation.attempt = ?3 AND task.generation = ?4)"
            ),
            vals![
                claim.scan_id,
                claim.task_id,
                claim.attempt,
                claim.generation,
                retry_not_before.map_or(0, aos_assessment::time::Timestamp::unix_seconds)
            ],
        )
        .expecting(1))
    }

    /// Clears consecutive failures while preserving concurrent cooldown authority.
    pub(super) fn assessment_provider_success_budget_statement(
        &self,
        claim: &TaskClaim,
    ) -> CheckedStatement {
        let clock = self.backend.dialect().unix_time_expression();
        Statement::new(
            format!(
                "UPDATE assessment_source_budgets SET failure_count = 0,
                 circuit_until = CASE WHEN circuit_until <= {clock} THEN 0 ELSE circuit_until END,
                 resource_version = resource_version + 1
             WHERE budget_key = (
                 SELECT reservation.budget_key FROM assessment_budget_reservations reservation
                 JOIN assessment_tasks task ON task.reservation_id = reservation.reservation_id
                    AND task.scan_id = reservation.scan_id AND task.task_id = reservation.task_id
                    AND task.attempt = reservation.attempt
                 WHERE reservation.scan_id = ?1 AND reservation.task_id = ?2
                    AND reservation.attempt = ?3 AND task.generation = ?4)"
            ),
            vals![
                claim.scan_id,
                claim.task_id,
                claim.attempt,
                claim.generation
            ],
        )
        .expecting(1)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::super::provider_state_tests::{failure, planned};
    use super::super::{AssessmentProviderWork, AssessmentSourceBudget};
    use super::*;
    use anyhow::Context as _;
    use aos_assessment_runtime::provider::WorkOutcome;
    use aos_contract::Sha256Digest;

    #[tokio::test]
    async fn question_errors_and_pagination_limits_do_not_open_global_circuits() -> Result<()> {
        let (_, _, plan) = planned().await?;
        let mut result = failure(&plan)?;
        for code in [
            "source-http-400",
            "source-http-401",
            "source-http-403",
            "source-http-404",
            "source-http-5000",
            "source-http-5xx",
            "source-byte-budget-exhausted",
            "provider-pagination-required",
        ] {
            result.diagnostics = vec![code.into()];
            assert!(!indicates_outage(&result), "{code}");
        }
        for code in [
            "source-http-429",
            "source-http-500",
            "source-http-503",
            "source-http-599",
            "source-request-incomplete",
        ] {
            result.diagnostics = vec![code.into()];
            assert!(indicates_outage(&result), "{code}");
            result.outcome = WorkOutcome::Observed;
            assert!(!indicates_outage(&result));
            result.outcome = WorkOutcome::Partial;
            assert!(indicates_outage(&result));
            result.outcome = WorkOutcome::Failed;
        }
        Ok(())
    }

    #[tokio::test]
    async fn admitted_outage_penalizes_once_and_refused_admission_changes_no_budget() -> Result<()>
    {
        qualify_admitted_outage(Database::open_in_memory().await?).await
    }

    async fn qualify_admitted_outage(db: Database) -> Result<()> {
        let (db, registry, plan) = super::super::provider_state_tests::planned_database(
            db,
            aos_assessment_runtime::provider::ProviderOperation::ObserveReleases {
                repository: "example/fixture".into(),
                tag_prefix: "v".into(),
                page: 1,
            },
        )
        .await?;
        db.admit_assessment_provider_plan(registry, &plan).await?;
        let mut result = failure(&plan)?;
        result.diagnostics = vec!["source-http-503".into()];
        let denial = Statement::new(
            "UPDATE registries SET scope_key = scope_key WHERE id = -1",
            vec![],
        )
        .expecting(1);
        assert!(db
            .admit_assessment_provider_result_fenced(registry, &plan, &result, &[denial])
            .await
            .is_err());
        let key = &plan.budget_reservation.source_budget;
        let before = db.backend.query_opt("SELECT failure_count, consumed, resource_version FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("shared budget")?;
        assert_eq!(before.get::<u32>(0)?, 0);
        assert_eq!(before.get::<u64>(1)?, 1);
        let now = db.assessment_database_time().await?.unix_seconds();
        db.admit_assessment_provider_result(registry, &plan, &result)
            .await?;
        let first = db.backend.query_opt("SELECT failure_count, consumed, resource_version, next_eligible_at FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("shared budget")?;
        assert_eq!(first.get::<u32>(0)?, 1);
        assert_eq!(first.get::<u64>(1)?, 1);
        assert_eq!(first.get::<u64>(2)?, before.get::<u64>(2)? + 1);
        let settled_at = db.assessment_database_time().await?.unix_seconds();
        assert!((now + 20..=settled_at + 40).contains(&first.get::<u64>(3)?));
        db.admit_assessment_provider_result(registry, &plan, &result)
            .await?;
        let replay = db.backend.query_opt("SELECT failure_count, resource_version FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("replayed budget")?;
        assert_eq!(replay.get::<u32>(0)?, 1);
        assert_eq!(replay.get::<u64>(1)?, first.get::<u64>(2)?);
        Ok(())
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
    async fn outage_receipt_and_budget_health_are_atomic_on_postgresql() -> Result<()> {
        let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
            .context("disposable PostgreSQL URL file required")?;
        let url = std::fs::read_to_string(path)?;
        let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
        qualify_admitted_outage(Database::with_backend(Box::new(backend)).await?).await
    }

    #[tokio::test]
    async fn revoked_settlement_authority_preserves_attempt_and_shared_budget() -> Result<()> {
        let (db, registry, plan) = planned().await?;
        let denial = Statement::new(
            "UPDATE registries SET scope_key = scope_key WHERE id = -1",
            vec![],
        )
        .expecting(1);
        assert!(db
            .fail_assessment_provider_work_fenced(
                registry,
                &plan.claim,
                "source-transport-failed",
                &[denial]
            )
            .await
            .is_err());
        db.check_assessment_provider_claim(registry, &plan.claim)
            .await?;
        let row = db.backend.query_opt("SELECT failure_count, consumed FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice plan.budget_reservation.source_budget]).await?.context("preserved budget")?;
        assert_eq!(row.get::<u32>(0)?, 0);
        assert_eq!(row.get::<u64>(1)?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_uncertain_calls_open_persisted_circuit_without_refund_or_retry_extension(
    ) -> Result<()> {
        let (db, registry, plan) = planned().await?;
        let mut parent = plan.claim.clone();
        parent.task_id = "coordinator".into();
        let key = &plan.budget_reservation.source_budget;
        let started_at = db.assessment_database_time().await?.unix_seconds();
        for index in 0..5 {
            let child = if index == 0 {
                plan.claim.clone()
            } else {
                // Expire only the fixture's operational cooldown; real request
                // claims remain unchanged and the database clock stays real.
                db.backend.execute("UPDATE assessment_source_budgets SET next_eligible_at = 0, circuit_until = 0 WHERE budget_key = ?1", &vals![@slice key]).await?;
                db.reserve_assessment_provider_work(
                    registry,
                    &parent,
                    &AssessmentProviderWork {
                        task_id: format!("outage-{index}"),
                        operation_digest: Sha256Digest::of_bytes(format!("question-{index}")),
                        budget_key: key.clone(),
                        requests: 1,
                        deadline_seconds: 30,
                    },
                )
                .await?
                .claim
            };
            db.fail_assessment_provider_work(registry, &child, "source-transport-failed")
                .await?;
            assert!(db
                .fail_assessment_provider_work(registry, &child, "source-transport-failed")
                .await
                .is_err());
        }
        let row = db.backend.query_opt("SELECT failure_count, consumed, circuit_until, next_eligible_at FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("open circuit")?;
        assert_eq!(row.get::<u32>(0)?, 5);
        assert_eq!(row.get::<u64>(1)?, 5);
        assert!(row.get::<u64>(2)? >= started_at + 320);
        assert_eq!(row.get::<u64>(2)?, row.get::<u64>(3)?);
        let blocked = AssessmentProviderWork {
            task_id: "blocked".into(),
            operation_digest: Sha256Digest::of_bytes("blocked"),
            budget_key: key.clone(),
            requests: 1,
            deadline_seconds: 30,
        };
        assert!(db
            .reserve_assessment_provider_work(registry, &parent, &blocked)
            .await
            .is_err());
        db.install_assessment_source_budget(&AssessmentSourceBudget {
            key: key.clone(),
            window_seconds: 3600,
            allowance: 10,
            min_interval_seconds: 0,
        })
        .await?;
        let retained = db.backend.query_opt("SELECT failure_count, consumed, circuit_until FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("reinstalled circuit")?;
        assert_eq!(retained.get::<u32>(0)?, 5);
        assert_eq!(retained.get::<u64>(1)?, 5);
        assert_eq!(retained.get::<u64>(2)?, row.get::<u64>(2)?);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_executor_settlements_cannot_lose_shared_failure_increments() -> Result<()> {
        let (db, registry, plan) = planned().await?;
        let mut parent = plan.claim.clone();
        parent.task_id = "coordinator".into();
        let key = &plan.budget_reservation.source_budget;
        let mut children = vec![plan.claim.clone()];
        for index in 1..3 {
            children.push(
                db.reserve_assessment_provider_work(
                    registry,
                    &parent,
                    &AssessmentProviderWork {
                        task_id: format!("concurrent-{index}"),
                        operation_digest: Sha256Digest::of_bytes(format!(
                            "concurrent-question-{index}"
                        )),
                        budget_key: key.clone(),
                        requests: 1,
                        deadline_seconds: 30,
                    },
                )
                .await?
                .claim,
            );
        }
        let (one, two, three) = tokio::join!(
            db.fail_assessment_provider_work(registry, &children[0], "source-transport-failed"),
            db.fail_assessment_provider_work(registry, &children[1], "source-transport-failed"),
            db.fail_assessment_provider_work(registry, &children[2], "source-transport-failed"),
        );
        one?;
        two?;
        three?;
        let row = db.backend.query_opt("SELECT failure_count, consumed FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("concurrent budget")?;
        assert_eq!(row.get::<u32>(0)?, 3);
        assert_eq!(row.get::<u64>(1)?, 3);
        Ok(())
    }

    #[tokio::test]
    async fn failure_escalation_has_a_portable_hard_one_hour_ceiling() -> Result<()> {
        let (db, registry, plan) = planned().await?;
        let key = &plan.budget_reservation.source_budget;
        db.backend
            .execute(
                "UPDATE assessment_source_budgets SET failure_count = 20 WHERE budget_key = ?1",
                &vals![@slice key],
            )
            .await?;
        let now = db.assessment_database_time().await?.unix_seconds();
        db.fail_assessment_provider_work(registry, &plan.claim, "source-transport-failed")
            .await?;
        let row = db.backend.query_opt("SELECT failure_count, circuit_until, next_eligible_at, consumed FROM assessment_source_budgets WHERE budget_key = ?1", &vals![@slice key]).await?.context("bounded circuit")?;
        assert_eq!(row.get::<u32>(0)?, 20);
        let settled_at = db.assessment_database_time().await?.unix_seconds();
        assert!((now + 3600..=settled_at + 3600).contains(&row.get::<u64>(1)?));
        assert_eq!(row.get::<u64>(1)?, row.get::<u64>(2)?);
        assert_eq!(row.get::<u64>(3)?, 1);
        Ok(())
    }
}
