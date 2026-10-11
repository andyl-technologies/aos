//! Authorized cached advisory lookup with current registry and principal checks.

use aos_assessment_runtime::advisories::retained::AdvisoryQueryV2;
use aos_assessment_runtime::advisories::{AdvisoryProjectionLimit, AdvisoryQueryV1};
use aos_assessment_runtime::read_snapshot::ScanPageError;

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
        let retained = AdvisoryQueryV2::from_slice(&req.document_json).ok();
        let legacy = if retained.is_none() {
            Some(
                AdvisoryQueryV1::from_slice(&req.document_json)
                    .map_err(|error| RpcError::invalid(error.to_string()))?,
            )
        } else {
            None
        };
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let document_json = if let Some(query) = retained {
            self.db
                .assessment_retained_advisory_page(registry.id, &query)
                .await
                .map_err(projection_error)?
                .ok_or_else(|| RpcError::not_found("assessment advisory selection"))?
                .to_bytes()
                .map_err(projection_error)?
        } else {
            let query = legacy.ok_or_else(|| RpcError::invalid("advisory query is absent"))?;
            self.db
                .assessment_advisory_page(registry.id, &query)
                .await
                .map_err(projection_error)?
                .ok_or_else(|| RpcError::not_found("assessment advisory selection"))?
                .to_bytes()
                .map_err(projection_error)?
        };
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }
}

fn projection_error(error: anyhow::Error) -> RpcError {
    if let Some(page) = error.downcast_ref::<ScanPageError>() {
        return match page {
            ScanPageError::InvalidCursor => RpcError::invalid(page.to_string()),
            ScanPageError::CursorExpired | ScanPageError::SelectorChanged => {
                RpcError::FailedPrecondition(page.to_string())
            }
            ScanPageError::CapacityExceeded => RpcError::ResourceExhausted(page.to_string()),
        };
    }
    if let Some(limit) = error.downcast_ref::<AdvisoryProjectionLimit>() {
        RpcError::ResourceExhausted(limit.to_string())
    } else {
        RpcError::internal(error)
    }
}
