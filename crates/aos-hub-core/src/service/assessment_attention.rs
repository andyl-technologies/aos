//! Resource-authorized attention pages, exact acknowledgements and event replay.
//!
//! Reads reauthorize after asynchronous work. Acknowledgements hold current IAM
//! and resource fences with the mutation and committed replay event.

use aos_assessment_runtime::alerts::Acknowledgement;
use aos_assessment_runtime::attention_control::{
    AlertAcknowledgementV1, AlertPageV1, AlertQueryV1, EventQueryV1,
};

use super::{pb, RpcError, RpcService};

impl RpcService {
    /// Reads a bounded attention page without acquiring provider evidence.
    ///
    /// # Errors
    /// Returns an error for invalid scope/cursors, revoked authority or persistence.
    pub async fn list_assessment_alerts(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = AlertQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        require_scope(query.resource_scope.as_deref(), &registry.scope_key)?;
        let page = self
            .db
            .assessment_retained_alert_page(
                registry.id,
                &registry.scope_key,
                query.limit,
                query.after_issue.as_deref(),
            )
            .await
            .map_err(super::assessment_notifications::retained_page_error)?;
        let document_json = page.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Replays committed events with a resource-bound reconnect position.
    ///
    /// Empty pages carry database time as a heartbeat. Every poll checks current
    /// principal authority, including while an event stream is otherwise idle.
    ///
    /// # Errors
    /// Returns an error for invalid/replaced scope, revoked access or persistence.
    pub async fn list_assessment_events(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = EventQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        require_scope(query.resource_scope.as_deref(), &registry.scope_key)?;
        let page = self
            .db
            .assessment_event_replay_page(
                registry.id,
                &registry.scope_key,
                query.after_sequence,
                query.limit,
            )
            .await
            .map_err(super::assessment_notifications::retained_page_error)?;
        let document_json = page.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Acknowledges an exact issue episode without resolving its findings.
    ///
    /// # Errors
    /// Returns an error for stale authority, episode/revision conflicts, changed
    /// idempotent content, invalid requests or persistence failures.
    pub async fn acknowledge_package_alert(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let request = AlertAcknowledgementV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.alert.acknowledge")
            .await?;
        require_scope(Some(&request.resource_scope), &registry.scope_key)?;
        let resource = self
            .db
            .assessment_resource(registry.id)
            .await
            .map_err(RpcError::internal)?
            .filter(|resource| resource.partition == registry.scope_key)
            .ok_or_else(|| RpcError::not_found("assessment resource"))?;
        let fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.alert.acknowledge")
            .await?;
        let alert = self
            .db
            .acknowledge_assessment_alert_fenced(
                registry.id,
                resource.authorization_revision,
                request.expected_sequence,
                Acknowledgement {
                    idempotency_key: Some(request.idempotency_key),
                    issue_key: request.issue_key,
                    episode: request.episode,
                    actor_ref: super::assessment_scans::actor_ref(&claims)?,
                    acknowledged_at: self
                        .db
                        .assessment_database_time()
                        .await
                        .map_err(RpcError::internal)?,
                    reason: request.reason,
                },
                &fences,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let page = AlertPageV1 {
            schema: "aos.assessment-alert-page/v1".into(),
            resource_scope: registry.scope_key.clone(),
            as_of: self
                .db
                .assessment_database_time()
                .await
                .map_err(RpcError::internal)?,
            alerts: vec![alert],
            next_issue: None,
        };
        let document_json = page.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.alert.acknowledge")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}

fn require_scope(requested: Option<&str>, current: &str) -> Result<(), RpcError> {
    if requested.is_some_and(|scope| scope != current) {
        return Err(RpcError::FailedPrecondition(
            "assessment continuation resource was replaced".into(),
        ));
    }
    Ok(())
}
