//! Public recurring-review controls with private authenticated provenance.

use aos_assessment_runtime::schedules::{SchedulePageV1, ScheduleQueryV1, ScheduleWriteV1};

use super::{pb, RpcError, RpcService};

impl RpcService {
    /// Creates, replaces or disables an explicitly reviewed recurring scan.
    ///
    /// Scheduling and scan permissions are held through admission. An explicit
    /// service review additionally locks its existing execution credential;
    /// public output excludes private principal and credential metadata.
    ///
    /// # Errors
    /// Returns an error for invalid review, stale revision, revoked authority,
    /// excessive lock scope or unavailable persistence.
    pub(super) async fn commit_assessment_schedule_review(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
        completion: &crate::db::AssessmentReviewCompletion,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let request = ScheduleWriteV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.schedule.manage")
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.scan")
            .await?;
        let mut fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.schedule.manage")
            .await?;
        fences.extend(
            self.assessment_mutation_fences(&claims, &registry, "assessment.scan")
                .await?,
        );

        fences.extend(
            self.assessment_mutation_fences(&claims, &registry, "assessment.read")
                .await?,
        );
        let schedule = self
            .db
            .write_assessment_schedule_with_plan_fenced(
                registry.id,
                &request,
                &claims,
                &fences,
                Some(completion),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let document_json = schedule.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.schedule.manage")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Reads schedule detail or a finite page without triggering scans.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, revoked read authority, absent
    /// selected schedule or unavailable persistence.
    pub async fn list_assessment_schedules(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = ScheduleQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        if query
            .resource_scope
            .as_ref()
            .is_some_and(|scope| scope != &registry.scope_key)
        {
            return Err(RpcError::not_found(
                "assessment schedule resource was replaced",
            ));
        }
        let page = if let Some(identity) = &query.schedule_id {
            let schedule = self
                .db
                .assessment_schedule(registry.id, identity)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("assessment schedule"))?;
            SchedulePageV1 {
                schema: "aos.assessment-schedule-page/v1".into(),
                resource_scope: registry.scope_key.clone(),
                as_of: self
                    .db
                    .assessment_database_time()
                    .await
                    .map_err(RpcError::internal)?,
                schedules: vec![schedule],
                next_schedule: None,
            }
        } else {
            self.db
                .assessment_retained_schedule_page(
                    registry.id,
                    &registry.scope_key,
                    query.limit,
                    query.after_schedule.as_deref(),
                )
                .await
                .map_err(super::assessment_notifications::retained_page_error)?
        };
        let document_json = page.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}
