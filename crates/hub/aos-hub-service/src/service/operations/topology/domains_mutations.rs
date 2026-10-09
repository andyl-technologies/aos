//! Domains mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies an immutable delivery-domain creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authentication, confirmation, authorization, conflict, or persistence error.
    pub async fn create_domain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDomainMutationRequest,
    ) -> Result<pb::DomainResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_domain",
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
            "create_domain",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, DomainCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_domain",
                Some(&req.confirmation_hash),
            )
            .await?;
        self.require_delivery_scope(
            auth,
            &input.request.owner_scope_key,
            Permission::DomainManage,
        )
        .await?;
        if let Some(domain) = self
            .db
            .delivery_domain_created_by_plan(
                &plan.plan_id,
                &input.request.owner_scope_key,
                input.org_id,
                &input.request.hostname,
            )
            .await
            .map_err(RpcError::internal)?
        {
            let response = pb::DomainResponse {
                domain: Some(Self::delivery_domain_message(domain)?),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }
        let domain = self
            .db
            .create_delivery_domain(
                &input.request.owner_scope_key,
                input.org_id,
                &input.request.hostname,
                &plan.plan_id,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("create domain: {error:#}")))?;
        let response = pb::DomainResponse {
            domain: Some(Self::delivery_domain_message(domain)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a reviewed DNS desired-state replacement.
    pub async fn configure_domain_dns(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDomainConfigurationRequest,
    ) -> Result<pb::DomainResponse, RpcError> {
        self.apply_domain_configuration(auth, req, "configure_domain_dns")
            .await
    }

    /// Applies a reviewed certificate desired-state replacement.
    pub async fn configure_domain_certificate(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDomainConfigurationRequest,
    ) -> Result<pb::DomainResponse, RpcError> {
        self.apply_domain_configuration(auth, req, "configure_domain_certificate")
            .await
    }

    /// Applies a reviewed domain deletion exactly once.
    pub async fn delete_domain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_domain",
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
            "delete_domain",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, DomainDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_domain",
                Some(&req.confirmation_hash),
            )
            .await?;
        self.require_delivery_scope(auth, &input.owner_scope_key, Permission::DomainManage)
            .await?;
        if self
            .db
            .delivery_domain(&input.stable_id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            self.db
                .delete_delivery_domain(&input.stable_id, input.baseline_resource_version)
                .await
                .map_err(|error| {
                    RpcError::FailedPrecondition(format!("delete domain: {error:#}"))
                })?;
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Produces a replay-protected TLS-terminator proof for one domain nonce.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime has no signer provider, the authority
    /// is not configured for the exact endpoint generation, or signing/replay
    /// validation fails.
    pub async fn domain_probe_response(
        &self,
        authority: &str,
        nonce: &str,
        now: i64,
    ) -> anyhow::Result<Vec<u8>> {
        let provider = self
            .domain_probe_terminator
            .as_deref()
            .context("domain probe terminator provider is not configured")?;
        crate::topology_probe::respond_to_domain_probe(&self.db, provider, authority, nonce, now)
            .await
    }

    /// Applies one reviewed domain claim or challenge rotation exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when ownership or revision changed or atomic apply fails.
    pub async fn apply_claim_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::OrganizationDomainResponse, RpcError> {
        const KIND: &str = "claim_organization_domain";
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
        let record = crate::db::OrgDomainRecord {
            domain: input.domain,
            org_id: org.id,
            txt_challenge: input.txt_challenge,
            verified_at: None,
            resource_version: input.baseline_resource_version.unwrap_or(0) + 1,
            incarnation_id: Some(input.incarnation_id),
            mutation_plan_id: Some(plan.plan_id.clone()),
        };
        let response = pb::OrganizationDomainResponse {
            domain: Some(organization_domain_message(&org.slug, record.clone())),
        };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        let event_id = control_audit_event_id("domain:claim", &plan.plan_id);
        self.db
            .apply_org_domain_claim_plan(
                &record,
                input.baseline_resource_version,
                input.baseline_incarnation_id.as_deref(),
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

    /// Resolves DNS and atomically verifies one reviewed domain challenge.
    ///
    /// # Errors
    ///
    /// Returns an error when DNS lacks the exact challenge, the revision changed,
    /// the runtime has no verifier, or atomic apply fails.
    pub async fn apply_verify_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::OrganizationDomainResponse, RpcError> {
        const KIND: &str = "verify_organization_domain";
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
            || current.txt_challenge != input.txt_challenge
            || current.verified_at.is_some()
        {
            return Err(RpcError::FailedPrecondition(
                "domain claim changed after planning".into(),
            ));
        }
        let verifier = self.identity_domain_verifier.as_ref().ok_or_else(|| {
            RpcError::FailedPrecondition("DNS domain verification is not configured".into())
        })?;
        if !verifier
            .challenge_is_published(&current.domain, &current.txt_challenge)
            .await
            .map_err(|error| {
                tracing::warn!(
                    domain = %current.domain,
                    error = %format!("{error:#}"),
                    "organization-domain DNS verification unavailable"
                );
                RpcError::Unavailable("DNS TXT verification is temporarily unavailable".to_string())
            })?
        {
            return Err(RpcError::FailedPrecondition(
                "the exact DNS TXT challenge is not published".into(),
            ));
        }
        let verified_at = clock::now_unix_secs();
        let mut verified = current.clone();
        verified.verified_at = Some(verified_at);
        verified.resource_version += 1;
        verified.incarnation_id = Some(input.incarnation_id.clone());
        verified.mutation_plan_id = Some(plan.plan_id.clone());
        let response = pb::OrganizationDomainResponse {
            domain: Some(organization_domain_message(&org.slug, verified)),
        };
        let result_json = serde_json::to_string(&response).map_err(RpcError::internal)?;
        let event_id = control_audit_event_id("domain:verify", &plan.plan_id);
        self.db
            .apply_org_domain_verify_plan(
                &current,
                &input.incarnation_id,
                verified_at,
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
                    "domain claim changed after DNS verification: {error:#}"
                ))
            })?;
        Ok(response)
    }
}
