//! Publications plans in the releases capability.

use super::*;

impl RpcService {
    /// Plans release of one exact organization-domain claim.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, lookup, version, or persistence error.
    pub async fn plan_release_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::PlanReleaseOrganizationDomainRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        let scope = Scope::parse(&org.stable_id);
        self.require_permission(&claims, Permission::IamAdmin, &scope)
            .await?;
        let domain = canonical_identity_domain(&req.domain)?;
        if let Some(replayed) = self
            .replayed_organization_domain_plan(
                &claims,
                "release_organization_domain",
                &req.org_slug,
                &domain,
                &req.expected_resource_version,
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(replayed);
        }
        let record = self
            .organization_domain_revision(&org, &domain, &req.expected_resource_version)
            .await?;
        let input = OrganizationDomainPlanInput {
            org_id: org.id,
            org_slug: org.slug,
            domain: record.domain,
            txt_challenge: record.txt_challenge,
            baseline_resource_version: Some(record.resource_version),
            baseline_incarnation_id: record.incarnation_id.clone(),
            incarnation_id: record
                .incarnation_id
                .clone()
                .unwrap_or_else(|| format!("domain-incarnation-{}", uuid::Uuid::new_v4())),
        };
        self.create_control_plan(
            &claims,
            "release_organization_domain",
            scope.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!("release {} from {}", input.domain, input.org_slug)],
            vec!["email-first SSO routing for this domain will stop".to_string()],
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }
}
