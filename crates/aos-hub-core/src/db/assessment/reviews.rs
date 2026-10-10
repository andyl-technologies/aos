//! Atomic completion receipts for exact reviewed assessment configuration.
//!
//! The immutable plan fence and retained public response commit with configuration,
//! event allocation and notification intent. A crash cannot leave a committed
//! configuration behind an unconsumed plan or cause a retry to renew authority.

use anyhow::{ensure, Result};

use crate::backend::{CheckedStatement, Statement};
use crate::db::TopologyPlanRecord;

/// Completes one previously reserved immutable plan in the domain transaction.
pub(crate) struct AssessmentReviewCompletion {
    plan: TopologyPlanRecord,
    idempotency_key: String,
}

impl AssessmentReviewCompletion {
    /// Binds completion to an exact reserved, actor-bound review plan.
    ///
    /// # Errors
    /// Returns an error for missing actor/confirmation or a conflicting reservation.
    pub(crate) fn new(plan: TopologyPlanRecord, idempotency_key: String) -> Result<Self> {
        ensure!(
            matches!(
                plan.plan_kind.as_str(),
                "assessment_schedule_review" | "assessment_subscription_review"
            ) && plan.actor_id.is_some()
                && plan.actor_incarnation.is_some()
                && plan.confirmation_hash.is_some()
                && plan.applied_at.is_none()
                && plan.apply_idempotency_key.as_deref() == Some(idempotency_key.as_str()),
            "assessment review requires an exact actor-bound reserved plan"
        );
        Ok(Self {
            plan,
            idempotency_key,
        })
    }

    /// Requires the mutation family retained by this exact plan.
    ///
    /// # Errors
    /// Returns an error for a different configuration family.
    pub(crate) fn require_kind(&self, kind: &str) -> Result<()> {
        ensure!(
            self.plan.plan_kind == kind,
            "assessment review kind differs from the mutation"
        );
        Ok(())
    }

    /// Commits the original public receipt under the complete immutable plan fence.
    ///
    /// # Errors
    /// Returns an error if response serialization fails.
    pub(crate) fn statement(
        &self,
        document_json: Vec<u8>,
        clock: &str,
    ) -> Result<CheckedStatement> {
        let response = aos_proto_types::AssessmentDocumentResponse { document_json };
        let result = serde_json::to_string(&response)?;
        let plan = &self.plan;
        Ok(Statement::new(
            format!(
                "UPDATE topology_plans SET applied_at = {clock}, apply_result_json = ?10
             WHERE plan_id = ?1 AND plan_kind = ?2 AND scope = ?3 AND actor_kind = ?4
             AND actor_id = ?5 AND actor_incarnation = ?6 AND confirmation_hash = ?7
             AND input_versions_json = ?8 AND apply_idempotency_key = ?9
             AND applied_at IS NULL AND expires_at > {clock}"
            ),
            vals![
                plan.plan_id,
                plan.plan_kind,
                plan.scope,
                plan.actor_kind,
                plan.actor_id,
                plan.actor_incarnation,
                plan.confirmation_hash,
                plan.input_versions_json,
                self.idempotency_key,
                result
            ],
        )
        .expecting(1))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::auth::jwt::Claims;
    use crate::db::{Database, NewTopologyPlan};
    use anyhow::Context as _;
    use aos_assessment::input::{FreshnessMode, Profile};
    use aos_assessment_runtime::scan::ScanLimits;
    use aos_assessment_runtime::schedules::{ScheduleConfigurationV1, ScheduleWriteV1};

    async fn reserve(
        db: &Database,
        claims: &Claims,
        scope: &str,
        kind: &str,
    ) -> Result<TopologyPlanRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        db.create_topology_plan(&NewTopologyPlan {
            plan_id: id.clone(),
            plan_kind: kind.into(),
            actor_kind: claims.owner_kind.clone(),
            actor_id: Some(claims.owner_id),
            actor_incarnation: claims.owner_incarnation.clone(),
            actor_label: claims.sub.clone(),
            scope: scope.into(),
            input_versions_json: "{\"review\":1}".into(),
            effects_json: "[]".into(),
            warnings_json: "[]".into(),
            confirmation_hash: Some("a".repeat(64)),
            request_idempotency_key: Some(id.clone()),
            expires_at: i64::try_from(db.assessment_database_time().await?.unix_seconds())? + 300,
        })
        .await?;
        db.begin_topology_plan_apply(&id, "exact-apply").await?;
        db.topology_plan(&id).await?.context("reserved plan")
    }

    #[tokio::test]
    async fn subscription_receipt_and_event_commit_with_plan_and_replay_cannot_mutate() -> Result<()>
    {
        qualify_subscription(Database::open_in_memory().await?).await
    }

    async fn qualify_subscription(db: Database) -> Result<()> {
        let (db, registry, request, claims, fences) =
            super::super::notifications_tests::fixture_database(db).await?;
        let plan = reserve(
            &db,
            &claims,
            &request.resource_scope,
            "assessment_subscription_review",
        )
        .await?;
        let completion = AssessmentReviewCompletion::new(plan.clone(), "exact-apply".into())?;
        let admitted = db
            .write_assessment_subscription_with_plan_fenced(
                registry,
                &request,
                &claims,
                &fences,
                Some(&completion),
            )
            .await?;
        let retained = db
            .topology_plan(&plan.plan_id)
            .await?
            .context("consumed plan")?;
        assert!(retained.applied_at.is_some());
        let receipt: aos_proto_types::AssessmentDocumentResponse = serde_json::from_str(
            retained
                .apply_result_json
                .as_deref()
                .context("atomic receipt")?,
        )?;
        assert_eq!(receipt.document_json, admitted.to_bytes()?);
        assert_eq!(db.assessment_event_page(registry, 0, 10).await?.len(), 1);
        assert!(db
            .write_assessment_subscription_with_plan_fenced(
                registry,
                &request,
                &claims,
                &fences,
                Some(&completion)
            )
            .await
            .is_err());
        assert_eq!(
            db.assessment_subscription(registry, &request.subscription_id)
                .await?,
            Some(admitted)
        );
        assert_eq!(db.assessment_event_page(registry, 0, 10).await?.len(), 1);
        assert!(AssessmentReviewCompletion::new(retained, "exact-apply".into()).is_err());
        Ok(())
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
    async fn subscription_review_receipt_is_atomic_on_postgresql() -> Result<()> {
        let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
            .context("disposable PostgreSQL URL file required")?;
        let url = std::fs::read_to_string(path)?;
        let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
        qualify_subscription(Database::with_backend(Box::new(backend)).await?).await
    }

    #[tokio::test]
    async fn stale_plan_fields_roll_back_configuration_events_and_completion() -> Result<()> {
        let (db, registry, request, claims, fences) =
            super::super::notifications_tests::fixture().await?;
        let plan = reserve(
            &db,
            &claims,
            &request.resource_scope,
            "assessment_subscription_review",
        )
        .await?;
        let mut variants = Vec::new();
        let mut wrong = plan.clone();
        wrong.plan_kind = "assessment_schedule_review".into();
        variants.push(wrong);
        let mut wrong = plan.clone();
        wrong.scope.push_str("-replaced");
        variants.push(wrong);
        let mut wrong = plan.clone();
        wrong.actor_id = Some(claims.owner_id + 1);
        variants.push(wrong);
        let mut wrong = plan.clone();
        wrong.actor_incarnation = Some(uuid::Uuid::new_v4().to_string());
        variants.push(wrong);
        let mut wrong = plan.clone();
        wrong.confirmation_hash = Some("b".repeat(64));
        variants.push(wrong);
        let mut wrong = plan.clone();
        wrong.input_versions_json = "{\"review\":2}".into();
        variants.push(wrong);
        for wrong in variants {
            let completion = AssessmentReviewCompletion::new(wrong, "exact-apply".into())?;
            assert!(db
                .write_assessment_subscription_with_plan_fenced(
                    registry,
                    &request,
                    &claims,
                    &fences,
                    Some(&completion)
                )
                .await
                .is_err());
            assert!(db
                .assessment_subscription(registry, &request.subscription_id)
                .await?
                .is_none());
            assert!(db.assessment_event_page(registry, 0, 10).await?.is_empty());
            assert!(db
                .topology_plan(&plan.plan_id)
                .await?
                .context("unused plan")?
                .applied_at
                .is_none());
        }
        assert!(AssessmentReviewCompletion::new(plan.clone(), "different-apply".into()).is_err());
        let completion = AssessmentReviewCompletion::new(plan.clone(), "exact-apply".into())?;
        db.backend.execute("UPDATE topology_plans SET created_at = ?2 - 1, expires_at = ?2 WHERE plan_id = ?1", &vals![@slice plan.plan_id, db.assessment_database_time().await?.unix_seconds() - 1]).await?;
        assert!(db
            .write_assessment_subscription_with_plan_fenced(
                registry,
                &request,
                &claims,
                &fences,
                Some(&completion)
            )
            .await
            .is_err());
        assert!(db
            .assessment_subscription(registry, &request.subscription_id)
            .await?
            .is_none());
        assert!(db.assessment_event_page(registry, 0, 10).await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn schedule_configuration_and_original_authority_share_atomic_receipt() -> Result<()> {
        let (db, registry, subscription, claims, fences) =
            super::super::notifications_tests::fixture().await?;
        let request = ScheduleWriteV1 {
            service_credential_id: None,
            schema: "aos.assessment-schedule-write/v1".into(),
            resource_scope: subscription.resource_scope,
            schedule_id: "reviewed-updates".into(),
            expected_revision: 0,
            enabled: true,
            configuration: ScheduleConfigurationV1 {
                continuous: false,
                schema: "aos.assessment-schedule-configuration/v1".into(),
                packages: vec!["fixture/example".into()],
                profiles: vec![Profile::Updates],
                freshness: FreshnessMode::Offline,
                cadence_seconds: 60,
                review_expires_at: subscription.configuration.review_expires_at,
                limits: ScanLimits::default(),
            },
        };
        let plan = reserve(
            &db,
            &claims,
            &request.resource_scope,
            "assessment_schedule_review",
        )
        .await?;
        let completion = AssessmentReviewCompletion::new(plan.clone(), "exact-apply".into())?;
        let admitted = db
            .write_assessment_schedule_with_plan_fenced(
                registry,
                &request,
                &claims,
                &fences,
                Some(&completion),
            )
            .await?;
        let retained = db
            .topology_plan(&plan.plan_id)
            .await?
            .context("consumed plan")?;
        let receipt: aos_proto_types::AssessmentDocumentResponse = serde_json::from_str(
            retained
                .apply_result_json
                .as_deref()
                .context("atomic receipt")?,
        )?;
        assert_eq!(receipt.document_json, admitted.to_bytes()?);
        assert_eq!(
            admitted.authority_expires_at.unix_seconds(),
            u64::try_from(claims.exp)?
        );
        assert!(db
            .write_assessment_schedule_with_plan_fenced(
                registry,
                &request,
                &claims,
                &fences,
                Some(&completion)
            )
            .await
            .is_err());
        assert_eq!(
            db.assessment_schedule(registry, &request.schedule_id)
                .await?,
            Some(admitted)
        );
        assert_eq!(db.assessment_event_page(registry, 0, 10).await?.len(), 1);
        Ok(())
    }
}
