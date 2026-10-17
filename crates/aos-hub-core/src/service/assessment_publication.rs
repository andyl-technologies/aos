//! Current authorized publication availability without implicit provider work.
//!
//! Outputs without declarations retain exact publisher coordinates. Availability
//! never substitutes old inventory evidence or makes vulnerability-status claims.

use aos_assessment_runtime::publication::{
    PublicationContextChanged, PublicationQueryV1, PublicationResponseLimit,
};

use super::{pb, RpcError, RpcService};

impl RpcService {
    /// Reads a bounded publication and unsupported-output projection.
    ///
    /// # Errors
    /// Returns an error for missing current read authority, invalid selectors,
    /// changed publication context, response bounds or unavailable persistence.
    pub async fn get_assessment_publication_status(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = PublicationQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let status = self.db.assessment_publication_status(registry.id, &query).await
            .map_err(|error| {
                if error.downcast_ref::<PublicationResponseLimit>().is_some() {
                    RpcError::ResourceExhausted("complete publication page exceeds its response bound; reduce the page limit".into())
                } else if error.downcast_ref::<PublicationContextChanged>().is_some() {
                    RpcError::FailedPrecondition(error.to_string())
                } else {
                    RpcError::internal(error)
                }
            })?;
        let document_json = status.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}
