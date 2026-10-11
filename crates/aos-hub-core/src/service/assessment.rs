//! Authorized package assessment reads over admitted immutable database state.
//!
//! Canonical inner documents use the exact contracts consumed by local tools.
//! Every read rechecks current principal and token authority after asynchronous
//! database work. A missing assessment permission policy denies access.

use aos_assessment::result::PackageAssessmentV1;
use aos_assessment_runtime::application::retained::StatusQueryV2;
use aos_assessment_runtime::application::{
    AssessmentStatusV1, ProfileStatus, StatusQueryV1, SubjectStatus,
};
use aos_assessment_runtime::read_snapshot::ScanPageError;
use aos_contract::Sha256Digest;

use super::{pb, Claims, Permission, RegistryRecord, RpcError, RpcService};
use crate::db::AssessmentObjectKind;

impl RpcService {
    /// Returns bounded current profile status without acquiring provider evidence.
    ///
    /// # Errors
    /// Returns an error for unauthorized access, malformed selection, absent
    /// inventory, changed pagination context or unavailable persistence.
    pub async fn get_assessment_status(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentStatusRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        if let Ok(query) = StatusQueryV2::from_slice(&req.query_json) {
            return self.get_retained_assessment_status(auth, req, query).await;
        }
        let query = StatusQueryV1::from_slice(&req.query_json)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        if self
            .db
            .assessment_resource(registry.id)
            .await
            .map_err(RpcError::internal)?
            .is_none()
        {
            return Err(RpcError::FailedPrecondition(
                "No declared assessment inventory is active for this publication".into(),
            ));
        }
        let page = self
            .db
            .assessment_status_page(
                registry.id,
                &query.profiles,
                query.after_subject.as_deref().unwrap_or(""),
                query.limit,
            )
            .await
            .map_err(RpcError::internal)?;
        if page.resource.partition != registry.scope_key {
            return Err(RpcError::NotFound(
                "assessment resource was replaced".into(),
            ));
        }
        if query
            .inventory_digest
            .is_some_and(|digest| digest != page.resource.inventory_digest)
            || query
                .policy_digest
                .is_some_and(|digest| digest != page.resource.policy_digest)
        {
            return Err(RpcError::FailedPrecondition(
                "assessment inventory or policy changed; restart pagination".into(),
            ));
        }
        // Current status cannot borrow freshness from a superseded publication.
        // Exact historical assessments remain available through their own read.
        let source_status = self
            .db
            .assessment_source_status(&registry.scope_key, &page.as_of)
            .await
            .map_err(RpcError::internal)?;
        let publication_fences = self
            .db
            .assessment_publication_fences(
                registry.id,
                &registry.scope_key,
                page.resource.inventory_digest,
                page.resource.policy_digest,
            )
            .await
            .map_err(|_| {
                RpcError::FailedPrecondition(
                    "current assessment publication is unavailable or changed".into(),
                )
            })?;
        self.db
            .backend
            .checked_batch(&publication_fences)
            .await
            .map_err(|_| {
                RpcError::FailedPrecondition(
                    "assessment publication changed during status read".into(),
                )
            })?;
        let status = AssessmentStatusV1 {
            schema: "aos.assessment-status/v1".into(),
            resource_scope: registry.scope_key.clone(),
            inventory_digest: page.resource.inventory_digest,
            inventory_revision: page.resource.inventory_revision,
            policy_digest: page.resource.policy_digest,
            source_status,
            as_of: page.as_of,
            next_subject: page.next_subject,
            subjects: page
                .subjects
                .into_iter()
                .map(|subject| SubjectStatus {
                    subject_ref: subject.subject_ref,
                    package_coordinate: subject.package_coordinate,
                    version: subject.version,
                    platform: subject.platform,
                    output: subject.output,
                    profiles: subject
                        .profiles
                        .into_iter()
                        .map(|profile| ProfileStatus {
                            profile: profile.profile,
                            desired_generation: profile.desired_generation,
                            committed_generation: profile.committed_generation,
                            assessment_digest: profile.assessment_digest,
                            input_digest: profile.input_digest,
                            validated_until: profile.validated_until,
                            fresh: profile.fresh,
                            pending: profile.pending,
                        })
                        .collect(),
                })
                .collect(),
        };
        let document_json = status.to_bytes().map_err(RpcError::internal)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    // Retained continuations are historical observations. Current registry and
    // principal authority remain mandatory; first-page capture additionally
    // requires an unchanged current publication before returning its receipt.
    async fn get_retained_assessment_status(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentStatusRequest,
        query: StatusQueryV2,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        let page = self
            .db
            .assessment_retained_status_page(registry.id, &query)
            .await
            .map_err(status_projection_error)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "No declared assessment inventory is active for this publication".into(),
                )
            })?;
        if query.cursor.is_none() {
            let publication_fences = self
                .db
                .assessment_publication_fences(
                    registry.id,
                    &registry.scope_key,
                    page.page.inventory_digest,
                    page.page.policy_digest,
                )
                .await
                .map_err(|_| {
                    RpcError::FailedPrecondition(
                        "current assessment publication is unavailable or changed".into(),
                    )
                })?;
            self.db
                .backend
                .checked_batch(&publication_fences)
                .await
                .map_err(|_| {
                    RpcError::FailedPrecondition(
                        "assessment publication changed during status capture".into(),
                    )
                })?;
        }
        let document_json = page.to_bytes().map_err(status_projection_error)?;
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    /// Returns one exact canonical assessment admitted by a successful scan.
    ///
    /// # Errors
    /// Returns an error for unauthorized access, invalid identity, absent
    /// successful admission, unavailable custody or conflicting object content.
    pub async fn get_package_assessment(
        &self,
        auth: Option<&str>,
        req: pb::AssessmentObjectRequest,
    ) -> Result<pb::AssessmentDocumentResponse, RpcError> {
        let digest = Sha256Digest::parse(&req.assessment_digest)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        let registry = self.registry_or_not_found(&req.registry_slug).await?;
        let claims = self
            .authorize_assessment(auth, &registry, "assessment.read")
            .await?;
        if !self
            .db
            .has_admitted_assessment(registry.id, digest)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::NotFound(
                "assessment has no successful admission in this resource".into(),
            ));
        }
        let document_json = self
            .db
            .assessment_object(
                &registry.scope_key,
                AssessmentObjectKind::Assessment,
                digest,
            )
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::NotFound("assessment evidence is unavailable".into()))?;
        let assessment =
            PackageAssessmentV1::from_slice(&document_json).map_err(RpcError::internal)?;
        if assessment.digest().map_err(RpcError::internal)? != digest {
            return Err(RpcError::FailedPrecondition(
                "assessment content differs from its admitted identity".into(),
            ));
        }
        self.recheck_assessment(&claims, &registry, "assessment.read")
            .await?;
        Ok(pb::AssessmentDocumentResponse { document_json })
    }

    pub(super) async fn authorize_assessment(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        verb: &str,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.recheck_assessment(&claims, registry, verb).await?;
        Ok(claims)
    }

    pub(super) async fn recheck_assessment(
        &self,
        claims: &Claims,
        registry: &RegistryRecord,
        verb: &str,
    ) -> Result<(), RpcError> {
        let permission = Permission::parse(verb).ok_or_else(|| {
            RpcError::PermissionDenied("assessment permission policy is unavailable".into())
        })?;
        if let Some(org) = registry.org_id {
            if !self
                .db
                .org_is_active(org)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("assessment resource"));
            }
        }
        self.require_permission(claims, permission, &self.registry_scope(registry).await?)
            .await?;
        let current = self
            .db
            .registry_by_id(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if current
            .as_ref()
            .is_none_or(|current| current.scope_key != registry.scope_key)
        {
            return Err(RpcError::not_found("assessment resource"));
        }
        Ok(())
    }

    pub(super) async fn assessment_mutation_fences(
        &self,
        claims: &Claims,
        registry: &RegistryRecord,
        verb: &str,
    ) -> Result<Vec<crate::backend::CheckedStatement>, RpcError> {
        self.recheck_assessment(claims, registry, verb).await?;
        let permission = Permission::parse(verb).ok_or_else(|| {
            RpcError::PermissionDenied("assessment permission policy is unavailable".into())
        })?;
        self.db
            .assessment_iam_statements(claims, &registry.scope_key, permission)
            .await
            .map_err(|_| {
                RpcError::PermissionDenied(
                    "assessment granting authority is no longer current".into(),
                )
            })
    }
}

// Keep finite capture failures distinct from unavailable storage diagnostics.
fn status_projection_error(error: anyhow::Error) -> RpcError {
    if let Some(page) = error.downcast_ref::<ScanPageError>() {
        match page {
            ScanPageError::InvalidCursor => RpcError::invalid(page.to_string()),
            ScanPageError::CursorExpired | ScanPageError::SelectorChanged => {
                RpcError::FailedPrecondition(page.to_string())
            }
            ScanPageError::CapacityExceeded => RpcError::ResourceExhausted(page.to_string()),
        }
    } else {
        RpcError::internal(error)
    }
}
