//! Explicit notification review controls with current IAM checks and closed documents.

use aos_assessment_runtime::notifications::{
    DestinationReviewQueryV1, SubscriptionPageV1, SubscriptionQueryV1, SubscriptionWriteV1,
};

use super::{pb, RpcError, RpcService};

impl RpcService {
    /// Creates, replaces or disables a reviewed notification subscription.
    ///
    /// # Errors
    /// Returns an error for unknown fields, stale destination/review, missing current
    /// authority or unavailable persistence. Enabling additionally requires read authority.
    pub async fn write_assessment_subscription(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let request = SubscriptionWriteV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.subscription.manage")
            .await?;
        let mut fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.subscription.manage")
            .await?;
        if request.enabled {
            self.recheck_assessment(&claims, &registry, "assessment.read")
                .await?;
            fences.extend(
                self.assessment_mutation_fences(&claims, &registry, "assessment.read")
                    .await?,
            );
        }
        let subscription = self
            .db
            .write_assessment_subscription_fenced(registry.id, &request, &claims, &fences)
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let document_json = subscription.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.subscription.manage")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Reads finite public notification reviews without triggering delivery.
    ///
    /// # Errors
    /// Returns an error for invalid selectors, replaced resource scope, revoked read
    /// authority, absent selected subscription or unavailable persistence.
    pub async fn list_assessment_subscriptions(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = SubscriptionQueryV1::from_slice(&req.document_json)
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
                "assessment notification resource was replaced",
            ));
        }
        let (subscriptions, next_subscription) = if let Some(identity) = &query.subscription_id {
            let subscription = self
                .db
                .assessment_subscription(registry.id, identity)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("assessment subscription"))?;
            (vec![subscription], None)
        } else {
            let subscriptions = self
                .db
                .assessment_subscription_page(
                    registry.id,
                    query.after_subscription.as_deref().unwrap_or(""),
                    query.limit,
                )
                .await
                .map_err(RpcError::internal)?;
            let next = if let Some(last) = subscriptions.last() {
                let more = self
                    .db
                    .assessment_subscription_page(registry.id, &last.subscription_id, 1)
                    .await
                    .map_err(RpcError::internal)?;
                (!more.is_empty()).then(|| last.subscription_id.clone())
            } else {
                None
            };
            (subscriptions, next)
        };
        let page = SubscriptionPageV1 {
            schema: "aos.assessment-subscription-page/v1".into(),
            resource_scope: registry.scope_key.clone(),
            as_of: self
                .db
                .assessment_database_time()
                .await
                .map_err(RpcError::internal)?,
            subscriptions,
            next_subscription,
        };
        let document_json = page.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Reads the exact registered destination commitment for an independent subscription review.
    ///
    /// # Errors
    /// Returns an error for invalid query, unavailable review/read permissions,
    /// changed resource scope, expired review or inactive/cross-organization destination.
    pub async fn review_assessment_notification_destination(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = DestinationReviewQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.subscription.manage")
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        if query.resource_scope != registry.scope_key {
            return Err(RpcError::not_found(
                "assessment destination review resource was replaced",
            ));
        }
        let now = self
            .db
            .assessment_database_time()
            .await
            .map_err(RpcError::internal)?;
        if query.review_expires_at <= now {
            return Err(RpcError::invalid(
                "notification destination review is expired",
            ));
        }
        let destination = self
            .db
            .assessment_notification_destination(
                registry.id,
                &query.destination_reference,
                &query.review_expires_at,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let document_json =
            aos_contract::canonical::to_vec(&destination).map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.subscription.manage")
            .await?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}
