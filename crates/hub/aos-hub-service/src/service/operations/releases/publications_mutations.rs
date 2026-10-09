//! Publications mutations in the releases capability.

use super::*;

impl RpcService {
    /// Loads native desired declarations after the caller authorizes registry visibility.
    ///
    /// # Errors
    /// Returns an error for incomplete releases, unavailable artifacts, or invalid native identities.
    pub(crate) async fn native_release_graph_for_registry(
        &self,
        registry_id: i64,
        release: &str,
        selected_platform: &str,
    ) -> Result<aos_module_docs::runtime::deployment::NativeReleaseGraph, RpcError> {
        use aos_module_docs::runtime::deployment::{
            NativePackageIdentity, NativeReleaseGraph, ReleasedReference,
        };
        let documents = self
            .db
            .native_documentation_at_release(registry_id, &release)
            .await
            .map_err(RpcError::internal)?;
        let platform = if selected_platform.is_empty() {
            documents
                .iter()
                .map(|document| document.platform.clone())
                .min()
                .ok_or_else(|| RpcError::not_found("native release references"))?
        } else {
            selected_platform.to_owned()
        };
        let fetch = self.topology_surface_fetcher(crate::db::SurfaceTarget::Registry(registry_id));
        let mut references = Vec::new();
        let mut commit = None;
        for document in documents
            .iter()
            .filter(|document| document.platform == platform)
        {
            let locator = self
                .db
                .native_documentation_locator(
                    registry_id,
                    &document.package,
                    &document.version,
                    &platform,
                    Some(&release),
                )
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("native release reference"))?;
            let (bytes, _) =
                crate::indexer::native_documentation::fetch_native_documentation_content(
                    fetch.as_ref(),
                    &locator.package,
                    &locator.version,
                    &platform,
                    &locator.artifact,
                )
                .await
                .map_err(RpcError::internal)?;
            commit = Some(locator.commit.clone());
            references.push(ReleasedReference {
                identity: NativePackageIdentity {
                    registry_commit: locator.commit,
                    package: locator.package,
                    version: locator.version,
                    platform: platform.clone(),
                    document_sha256: aos_core::Sha256Digest::parse(
                        &locator.artifact.document_sha256,
                    )
                    .map_err(RpcError::internal)?,
                },
                reference_json: String::from_utf8(bytes).map_err(RpcError::internal)?,
            });
        }
        references.sort_by(|left, right| {
            (&left.identity.package, &left.identity.version)
                .cmp(&(&right.identity.package, &right.identity.version))
        });
        let registry_commit =
            commit.ok_or_else(|| RpcError::not_found("native release references"))?;
        Ok(NativeReleaseGraph {
            schema: "aos.module.release-graph".into(),
            release: release.to_owned(),
            registry_commit: registry_commit.clone(),
            platform: platform.clone(),
            references,
        })
    }

    /// Applies one reviewed organization-domain release exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when the claim changed or atomic apply fails.
    pub async fn apply_release_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        const KIND: &str = "release_organization_domain";
        let claims = self
            .require_control_plan_permission(auth, &req.plan_id, Permission::IamAdmin)
            .await?;
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, OrganizationDomainPlanInput) = self
            .load_control_plan(auth, &req.plan_id, KIND, Some(&req.confirmation_hash))
            .await?;
        let org = self
            .db
            .org_by_slug(&input.org_slug)
            .await
            .map_err(RpcError::internal)?
            .filter(|org| org.id == input.org_id)
            .ok_or_else(|| {
                RpcError::FailedPrecondition("organization changed after planning".into())
            })?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let current = self
            .db
            .org_domain(&input.domain)
            .await
            .map_err(RpcError::internal)?
            .filter(|record| record.org_id == org.id)
            .ok_or_else(|| RpcError::FailedPrecondition("domain claim disappeared".into()))?;
        if current.resource_version != input.baseline_resource_version.unwrap_or(-1)
            || current.incarnation_id != input.baseline_incarnation_id
        {
            return Err(RpcError::FailedPrecondition(
                "domain claim changed after planning".into(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        let event_id = control_audit_event_id("domain:release", &plan.plan_id);
        self.db
            .apply_org_domain_release_plan(
                &current,
                scope.as_str(),
                &plan.plan_id,
                &req.idempotency_key,
                &result_json,
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                &event_id,
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!(
                    "domain claim changed after planning: {error:#}"
                ))
            })?;
        Ok(response)
    }
}
