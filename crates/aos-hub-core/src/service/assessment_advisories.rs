//! Authorized cached advisory lookup with current registry and principal checks.

use aos_assessment_runtime::advisories::AdvisoryQueryV1;

use super::{pb, RpcError, RpcService};

impl RpcService {
    /// Reads exact retained advisory revisions without performing provider work.
    ///
    /// # Errors
    /// Returns an error for invalid selection, absent admitted context, revoked
    /// current read authority, excessive response size or unavailable custody.
    pub async fn get_assessment_advisory(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = AdvisoryQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let page = self
            .db
            .assessment_advisory_page(registry.id, &query)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment advisory selection"))?;
        let document_json = page.to_bytes().map_err(|_| RpcError::ResourceExhausted(
            "advisory response exceeds its finite size; reduce the revision limit or select one subject".into(),
        ))?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}
