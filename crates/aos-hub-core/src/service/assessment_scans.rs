//! Authorized scan admission and lifecycle controls over the durable Hub journal.
//!
//! Client documents contain selection, never actor or authorization identities.
//! Operation IDs remain scoped reads, and retry preserves the original selector
//! and ceilings rather than reinterpreting a moving package name.

use aos_assessment_runtime::application::ScanReceiptV1;
use aos_assessment_runtime::control::{
    ScanCancellationV1, ScanListQueryV1, ScanListV1, ScanLookupV1, ScanRetryV1, ScanSubmissionV1,
    ScanSummary,
};
use aos_contract::Sha256Digest;

use super::{pb, Claims, RpcError, RpcService};
use crate::db::AssessmentScanRecord;

impl RpcService {
    /// Admits one pinned request without performing provider work in the handler.
    ///
    /// # Errors
    /// Returns an error for invalid selection, absent current authority, stale
    /// inventory/policy, conflicting idempotency or unavailable persistence.
    pub async fn request_package_scan(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let submission = ScanSubmissionV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.scan")
            .await?;
        let request = submission
            .bind(
                &registry.scope_key,
                &registry.scope_key,
                &actor_ref(&claims)?,
            )
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.scan")
            .await?;
        let scan = self
            .db
            .request_assessment_scan_fenced(registry.id, &request, &fences)
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        self.recheck_assessment(&claims, &registry, "assessment.scan")
            .await?;
        receipt(scan)
    }

    /// Reads a scoped operation and its exact immutable request without refresh.
    ///
    /// # Errors
    /// Returns an error for invalid identity, revoked access or unavailable state.
    pub async fn get_package_scan(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = ScanLookupV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let scan = self
            .db
            .assessment_scan(registry.id, &query.scan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment scan"))?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        receipt(scan)
    }

    /// Lists bounded summaries in stable operation-identity order.
    ///
    /// # Errors
    /// Returns an error for invalid pagination, revoked access or unavailable state.
    pub async fn list_package_scans(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = ScanListQueryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let page = self
            .db
            .assessment_scan_summaries(
                registry.id,
                query.after_scan.as_deref().unwrap_or(""),
                query.limit,
            )
            .await
            .map_err(RpcError::internal)?;
        let next_scan = if let Some(last) = page.last() {
            let next = self
                .db
                .assessment_scan_summaries(registry.id, &last.scan_id, 1)
                .await
                .map_err(RpcError::internal)?;
            (!next.is_empty()).then(|| last.scan_id.clone())
        } else {
            None
        };
        let list = ScanListV1 {
            schema: "aos.assessment-scan-list/v1".into(),
            resource_scope: registry.scope_key.clone(),
            as_of: self
                .db
                .assessment_database_time()
                .await
                .map_err(RpcError::internal)?,
            scans: page
                .into_iter()
                .map(|scan| ScanSummary {
                    scan_id: scan.scan_id,
                    request_digest: scan.request_digest,
                    state: scan.state,
                    generation: scan.generation,
                    resource_version: scan.resource_version,
                    created_at: scan.created_at,
                    assessment_digest: scan.assessment_digest,
                })
                .collect(),
            next_scan,
        };
        let document_json = list.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Fences an exact operation revision and returns its durable cancellation state.
    ///
    /// # Errors
    /// Returns an error for stale revisions, terminal operations, revoked authority
    /// or unavailable persistence. Cancellation preserves historical results.
    pub async fn cancel_package_scan(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = ScanCancellationV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.scan")
            .await?;
        let fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.scan")
            .await?;
        self.db
            .cancel_assessment_scan_fenced(
                registry.id,
                &query.scan_id,
                query.expected_revision,
                &fences,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        let scan = self
            .db
            .assessment_scan(registry.id, &query.scan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment scan"))?;
        self.recheck_assessment(&claims, &registry, "assessment.scan")
            .await?;
        receipt(scan)
    }

    /// Retries a terminal request with unchanged selection and fresh quota accounting.
    ///
    /// # Errors
    /// Returns an error for nonterminal originals, replaced inventory/policy,
    /// reused conflicting keys, revoked authority or unavailable persistence.
    pub async fn retry_package_scan(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentControlRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let query = ScanRetryV1::from_slice(&req.document_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.scan")
            .await?;
        let original = self
            .db
            .assessment_scan(registry.id, &query.scan_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("assessment scan"))?;
        if !original.state.is_terminal() {
            return Err(RpcError::FailedPrecondition(
                "retry requires a terminal assessment scan".into(),
            ));
        }
        let mut request = original.request;
        request.actor_ref = actor_ref(&claims)?;
        // The original operation participates in the idempotency identity, so
        // a caller's key cannot accidentally resume a different retry lineage.
        request.idempotency_key = Sha256Digest::of_canonical(
            "aos.assessment-scan-retry-key/v1",
            &(query.scan_id, query.idempotency_key),
        )
        .map_err(RpcError::internal)?
        .to_string();
        request.trigger = "manual".into();
        let fences = self
            .assessment_mutation_fences(&claims, &registry, "assessment.scan")
            .await?;
        let scan = self
            .db
            .request_assessment_scan_fenced(registry.id, &request, &fences)
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        self.recheck_assessment(&claims, &registry, "assessment.scan")
            .await?;
        receipt(scan)
    }
}

fn actor_ref(claims: &Claims) -> Result<String, RpcError> {
    let incarnation = claims.owner_incarnation.as_ref().ok_or_else(|| {
        RpcError::PermissionDenied("assessment scans require stable principal identity".into())
    })?;
    let identity = uuid::Uuid::parse_str(incarnation).map_err(|_| {
        RpcError::PermissionDenied("assessment principal identity is invalid".into())
    })?;
    if !matches!(claims.owner_kind.as_str(), "user" | "service_account") {
        return Err(RpcError::PermissionDenied(
            "assessment principal kind is invalid".into(),
        ));
    }
    Sha256Digest::of_canonical(
        "aos.assessment-actor/v1",
        &(claims.owner_kind.as_str(), identity.to_string()),
    )
    .map(|digest| digest.to_string())
    .map_err(RpcError::internal)
}

fn receipt(scan: AssessmentScanRecord) -> Result<pb::AssessmentDocumentResponse, RpcError> {
    let receipt = ScanReceiptV1 {
        schema: "aos.assessment-scan-receipt/v1".into(),
        scan_id: scan.scan_id,
        request: scan.request,
        request_digest: scan.request_digest,
        generation: scan.generation,
        state: scan.state,
        admission_complete: scan.admission_complete,
        usage: scan.usage,
        created_at: scan.created_at,
        resource_version: scan.resource_version,
        assessment_digest: scan.assessment_digest,
    };
    Ok(pb::AssessmentDocumentResponse {
        document_json: receipt.to_bytes().map_err(RpcError::internal)?,
    })
}
