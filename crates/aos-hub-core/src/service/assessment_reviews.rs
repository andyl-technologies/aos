//! Immutable configuration review plans and fenced assessment plan application.
//!
//! Planning retains exact closed schedule/subscription documents without changing
//! their configuration. Apply accepts a plan and confirmation commitment only;
//! current IAM, registry incarnation, configuration CAS and the live plan fence
//! share the configuration mutation transaction.

use aos_assessment_runtime::notifications::SubscriptionWriteV1;
use aos_assessment_runtime::schedules::ScheduleWriteV1;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::{pb, Permission, RpcError, RpcService};
use crate::db::AssessmentReviewCompletion;

#[derive(Clone, Copy)]
enum ReviewKind {
    Schedule,
    Subscription,
}

impl ReviewKind {
    fn plan_kind(self) -> &'static str {
        match self {
            Self::Schedule => "assessment_schedule_review",
            Self::Subscription => "assessment_subscription_review",
        }
    }

    fn permission(self) -> &'static str {
        match self {
            Self::Schedule => "assessment.schedule.manage",
            Self::Subscription => "assessment.subscription.manage",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum ReviewDocument {
    Schedule(ScheduleWriteV1),
    Subscription(SubscriptionWriteV1),
}

impl ReviewDocument {
    fn kind(&self) -> ReviewKind {
        match self {
            Self::Schedule(_) => ReviewKind::Schedule,
            Self::Subscription(_) => ReviewKind::Subscription,
        }
    }

    fn resource_scope(&self) -> &str {
        match self {
            Self::Schedule(request) => &request.resource_scope,
            Self::Subscription(request) => &request.resource_scope,
        }
    }

    fn expected_revision(&self) -> u64 {
        match self {
            Self::Schedule(request) => request.expected_revision,
            Self::Subscription(request) => request.expected_revision,
        }
    }

    fn bytes(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Schedule(request) => {
                request.validate()?;
                aos_contract::canonical::to_vec(request)
            }
            Self::Subscription(request) => {
                request.validate()?;
                aos_contract::canonical::to_vec(request)
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewInput {
    registry_id: i64,
    registry_slug: String,
    document: ReviewDocument,
}

impl ReviewInput {
    fn confirmation_hash(&self) -> anyhow::Result<String> {
        self.document.bytes()?;
        Ok(Sha256Digest::of_canonical("aos.assessment-reviewed-configuration/v1", self)?.hex())
    }
}

impl RpcService {
    /// Retains an immutable proposed recurring scan review without enabling execution.
    ///
    /// # Errors
    /// Returns an error for malformed selection, unavailable current permissions,
    /// changed registry incarnation or conflicting planning identity.
    pub async fn plan_write_assessment_schedule(
        &self,
        auth: Option<&str>,
        req: pb::PlanAssessmentReviewRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_assessment_review(auth, req, ReviewKind::Schedule)
            .await
    }

    /// Retains an immutable proposed subscription review without enqueueing callbacks.
    ///
    /// # Errors
    /// Returns an error for malformed selection, unavailable current permissions,
    /// changed registry incarnation or conflicting planning identity.
    pub async fn plan_write_assessment_subscription(
        &self,
        auth: Option<&str>,
        req: pb::PlanAssessmentReviewRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_assessment_review(auth, req, ReviewKind::Subscription)
            .await
    }

    /// Applies only the exact retained schedule plan under current authority.
    ///
    /// # Errors
    /// Returns an error for mismatched confirmation, stale plan/configuration,
    /// replaced resource, unavailable current permissions or persistence failure.
    pub async fn write_assessment_schedule(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        self.apply_assessment_review(auth, req, ReviewKind::Schedule)
            .await
    }

    /// Applies only the exact retained subscription plan under current authority.
    ///
    /// # Errors
    /// Returns an error for mismatched confirmation, stale plan/destination,
    /// replaced resource, unavailable current permissions or persistence failure.
    pub async fn write_assessment_subscription(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        self.apply_assessment_review(auth, req, ReviewKind::Subscription)
            .await
    }

    async fn plan_assessment_review(
        &self,
        auth: Option<&str>,
        req: pb::PlanAssessmentReviewRequest,
        kind: ReviewKind,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let document = match kind {
            ReviewKind::Schedule => ReviewDocument::Schedule(
                ScheduleWriteV1::from_slice(&req.document_json)
                    .map_err(|error| RpcError::invalid(error.to_string()))?,
            ),
            ReviewKind::Subscription => ReviewDocument::Subscription(
                SubscriptionWriteV1::from_slice(&req.document_json)
                    .map_err(|error| RpcError::invalid(error.to_string()))?,
            ),
        };
        if req.expected_resource_version != document.expected_revision().to_string() {
            return Err(RpcError::invalid(
                "expected resource version differs from the closed review document",
            ));
        }
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, kind.permission())
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        if matches!(kind, ReviewKind::Schedule) {
            self.recheck_assessment(&claims, &registry, "assessment.scan")
                .await?;
        }
        if document.resource_scope() != registry.scope_key {
            return Err(RpcError::not_found(
                "assessment configuration resource was replaced",
            ));
        }
        let effects = vec![format!(
            "Retain the exact {} configuration at expected revision {}: {}",
            kind.plan_kind(),
            document.expected_revision(),
            String::from_utf8(document.bytes().map_err(RpcError::internal)?)
                .map_err(RpcError::internal)?
        )];
        let input = ReviewInput {
            registry_id: registry.id,
            registry_slug: registry.slug.clone(),
            document,
        };
        let confirmation = input.confirmation_hash().map_err(RpcError::internal)?;
        let response = self.create_control_plan(
            &claims, kind.plan_kind(), self.registry_scope(&registry).await?.as_str(),
            &input, &req.idempotency_key, effects,
            vec!["Apply changes only the exact reviewed configuration. Background execution uses the applying credential unless an existing service credential is explicitly selected; it remains expiry-bounded and rechecks current permissions before effects.".into()],
            Some(confirmation),
        ).await?;
        self.recheck_assessment(&claims, &registry, kind.permission())
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(response)
    }

    async fn apply_assessment_review(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRegistryMutationRequest,
        kind: ReviewKind,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let permission = Permission::parse(kind.permission()).ok_or_else(|| {
            RpcError::PermissionDenied("assessment permission policy is unavailable".into())
        })?;
        self.require_control_plan_permission(auth, &req.plan_id, permission)
            .await?;
        let plan = self
            .db
            .topology_plan(&req.plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment review plan"))?;
        let input: ReviewInput =
            serde_json::from_str(&plan.input_versions_json).map_err(RpcError::internal)?;
        if plan.plan_kind != kind.plan_kind()
            || input.document.kind().plan_kind() != kind.plan_kind()
            || input.confirmation_hash().map_err(RpcError::internal)? != req.confirmation_hash
        {
            return Err(RpcError::FailedPrecondition(
                "assessment confirmation differs from its exact review".into(),
            ));
        }
        let registry = self.registry_or_not_found(&input.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, kind.permission())
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        if matches!(kind, ReviewKind::Schedule) {
            self.recheck_assessment(&claims, &registry, "assessment.scan")
                .await?;
        }
        if registry.id != input.registry_id
            || registry.scope_key != input.document.resource_scope()
            || self.registry_scope(&registry).await?.as_str() != plan.scope
        {
            return Err(RpcError::not_found(
                "assessment review resource was replaced",
            ));
        }
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                kind.plan_kind(),
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            self.recheck_assessment(&claims, &registry, kind.permission())
                .await?;
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            kind.plan_kind(),
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, retained): (_, ReviewInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                kind.plan_kind(),
                Some(&req.confirmation_hash),
            )
            .await?;
        if retained.confirmation_hash().map_err(RpcError::internal)? != req.confirmation_hash {
            return Err(RpcError::FailedPrecondition(
                "retained assessment review changed".into(),
            ));
        }
        let reserved = self
            .db
            .topology_plan(&req.plan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment review plan"))?;
        if reserved.input_versions_json != plan.input_versions_json
            || reserved.confirmation_hash != plan.confirmation_hash
            || reserved.actor_incarnation != plan.actor_incarnation
            || reserved.scope != plan.scope
        {
            return Err(RpcError::FailedPrecondition(
                "reserved assessment review changed".into(),
            ));
        }
        let completion = AssessmentReviewCompletion::new(reserved, req.idempotency_key.clone())
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let control = pb::AssessmentControlRequest {
            registry_slug: input.registry_slug,
            document_json: retained.document.bytes().map_err(RpcError::internal)?,
        };
        let response = match kind {
            ReviewKind::Schedule => {
                self.commit_assessment_schedule_review(auth, control, &completion)
                    .await?
            }
            ReviewKind::Subscription => {
                self.commit_assessment_subscription_review(auth, control, &completion)
                    .await?
            }
        };

        self.recheck_assessment(&claims, &registry, kind.permission())
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(response)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aos_assessment::input::{FreshnessMode, Profile};
    use aos_assessment::time::Timestamp;
    use aos_assessment_runtime::scan::ScanLimits;
    use aos_assessment_runtime::schedules::ScheduleConfigurationV1;

    #[test]
    fn confirmation_commits_every_configuration_field_and_registry_identity() -> anyhow::Result<()>
    {
        let request = ScheduleWriteV1 {
            service_credential_id: None,
            schema: "aos.assessment-schedule-write/v1".into(),
            resource_scope: "registry-instance-1".into(),
            schedule_id: "security-updates".into(),
            expected_revision: 1,
            enabled: true,
            configuration: ScheduleConfigurationV1 {
                continuous: false,
                schema: "aos.assessment-schedule-configuration/v1".into(),
                packages: vec!["fixture/example".into()],
                profiles: vec![Profile::Updates],
                freshness: FreshnessMode::Offline,
                cadence_seconds: 60,
                review_expires_at: Timestamp::parse("2027-01-01T00:00:00Z")?,
                limits: ScanLimits::default(),
            },
        };
        let original = ReviewInput {
            registry_id: 1,
            registry_slug: "packages".into(),
            document: ReviewDocument::Schedule(request.clone()),
        };
        let expected = original.confirmation_hash()?;
        let mut variants = Vec::new();
        let mut value = original.clone();
        value.registry_id = 2;
        variants.push(value);
        let mut value = original.clone();
        value.registry_slug = "other-packages".into();
        variants.push(value);
        let mut requests = Vec::new();
        let mut value = request.clone();
        value.service_credential_id = Some("af738afb-8b2f-4b58-a835-c20b7f6b2d51".into());
        requests.push(value);
        let mut value = request.clone();
        value.resource_scope = "registry-instance-2".into();
        requests.push(value);
        let mut value = request.clone();
        value.schedule_id = "other-schedule".into();
        requests.push(value);
        let mut value = request.clone();
        value.expected_revision = 2;
        requests.push(value);
        let mut value = request.clone();
        value.enabled = false;
        requests.push(value);
        let mut value = request.clone();
        value.configuration.packages = vec!["fixture/other".into()];
        requests.push(value);
        let mut value = request.clone();
        value.configuration.profiles = vec![Profile::Vulnerabilities];
        requests.push(value);
        let mut value = request.clone();
        value.configuration.freshness = FreshnessMode::RefreshStale;
        requests.push(value);
        let mut value = request.clone();
        value.configuration.cadence_seconds = 120;
        requests.push(value);
        let mut value = request.clone();
        value.configuration.review_expires_at = Timestamp::parse("2027-01-02T00:00:00Z")?;
        requests.push(value);
        let mut value = request;
        value.configuration.limits.subjects = 100;
        requests.push(value);
        for request in requests {
            variants.push(ReviewInput {
                registry_id: 1,
                registry_slug: "packages".into(),
                document: ReviewDocument::Schedule(request),
            });
        }
        for value in variants {
            assert_ne!(value.confirmation_hash()?, expected);
        }
        let roundtrip: ReviewInput =
            serde_json::from_slice(&aos_contract::canonical::to_vec(&original)?)?;
        assert_eq!(roundtrip.confirmation_hash()?, expected);
        Ok(())
    }
}
