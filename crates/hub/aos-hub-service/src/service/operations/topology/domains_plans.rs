//! Domains plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of one immutable delivery-domain identity.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, conflict, or persistence error.
    pub async fn plan_create_domain(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDomainMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        self.require_delivery_scope(auth, &req.owner_scope_key, Permission::DomainManage)
            .await?;
        req.hostname = aos_hub_db::db::canonical_delivery_hostname(&req.hostname)
            .map_err(|error| RpcError::invalid(format!("hostname: {error:#}")))?;
        let (_kind, org_id, _project_id) = self
            .db
            .authorization_scope_owner(&req.owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("owner scope"))?;
        if self
            .db
            .delivery_domain_by_hostname(&req.hostname)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "delivery domain hostname already exists".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = DomainCreatePlanInput {
            request: req,
            org_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_domain",
            &input.request.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "create immutable delivery domain '{}'",
                input.request.hostname
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a lossless DNS desired-state replacement.
    pub async fn plan_configure_domain_dns(
        &self,
        auth: Option<&str>,
        req: pb::PlanDomainDnsRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let configuration = delivery_dns_spec(
            req.configuration
                .ok_or_else(|| RpcError::invalid("configuration is required"))?,
        )?;
        self.plan_domain_configuration(
            auth,
            req.stable_id,
            req.expected_resource_version,
            req.idempotency_key,
            Some(configuration),
            None,
        )
        .await
    }

    /// Plans a lossless certificate desired-state replacement.
    pub async fn plan_configure_domain_certificate(
        &self,
        auth: Option<&str>,
        req: pb::PlanDomainCertificateRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let configuration = delivery_certificate_spec(
            req.configuration
                .ok_or_else(|| RpcError::invalid("configuration is required"))?,
        )?;
        self.plan_domain_configuration(
            auth,
            req.stable_id,
            req.expected_resource_version,
            req.idempotency_key,
            None,
            Some(configuration),
        )
        .await
    }

    /// Plans deletion of an unreferenced domain under exact CAS.
    pub async fn plan_delete_domain(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let current = self
            .db
            .delivery_domain(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("domain"))?;
        self.require_delivery_scope(auth, &current.owner_scope_key, Permission::DomainManage)
            .await?;
        if req
            .expected_resource_version
            .as_deref()
            .is_none_or(str::is_empty)
            || parse_resource_version(
                req.expected_resource_version.as_deref().unwrap_or_default(),
                current.resource_version,
            )? != current.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "domain resource version is required and must be current".to_string(),
            ));
        }
        let input = DomainDeletePlanInput {
            stable_id: current.stable_id,
            owner_scope_key: current.owner_scope_key,
            baseline_resource_version: current.resource_version,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_domain",
            &input.owner_scope_key,
            &input,
            &req.idempotency_key,
            vec![format!("delete unreferenced domain '{}'", input.stable_id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a new domain claim or exact-version challenge rotation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, foreign ownership, a stale version,
    /// insufficient authority, or persistence failure.
    pub async fn plan_claim_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::PlanClaimOrganizationDomainRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotency_key is required"));
        }
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
                "claim_organization_domain",
                &req.org_slug,
                &domain,
                &req.expected_resource_version,
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(replayed);
        }
        let existing = self
            .db
            .org_domain(&domain)
            .await
            .map_err(RpcError::internal)?;
        if existing
            .as_ref()
            .is_some_and(|record| record.org_id != org.id)
        {
            return Err(RpcError::AlreadyExists(
                "domain is claimed by another organization".into(),
            ));
        }
        let baseline_resource_version = require_exact_identity_version(
            &req.expected_resource_version,
            existing
                .as_ref()
                .map(|record| (record.resource_version, record.incarnation_id.as_deref())),
        )?;
        let baseline_incarnation_id = existing
            .as_ref()
            .and_then(|record| record.incarnation_id.clone());
        let incarnation_id = baseline_incarnation_id
            .clone()
            .unwrap_or_else(|| format!("domain-incarnation-{}", uuid::Uuid::new_v4()));
        let challenge = format!(
            "aos-domain-verify={}",
            hex::encode(Sha256::digest(
                format!("{}:{domain}:{}", org.stable_id, req.idempotency_key).as_bytes()
            ))
        );
        let input = OrganizationDomainPlanInput {
            org_id: org.id,
            org_slug: org.slug,
            domain,
            txt_challenge: challenge,
            baseline_resource_version,
            baseline_incarnation_id,
            incarnation_id,
        };
        self.create_control_plan(
            &claims,
            "claim_organization_domain",
            scope.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!("claim {} for {}", input.domain, input.org_slug)],
            vec![
                "the claim remains inactive until its exact DNS TXT challenge is verified"
                    .to_string(),
            ],
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }

    /// Plans DNS verification of one exact pending domain revision.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, lookup, version, or persistence error.
    pub async fn plan_verify_organization_domain(
        &self,
        auth: Option<&str>,
        req: pb::PlanVerifyOrganizationDomainRequest,
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
                "verify_organization_domain",
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
        if record.verified_at.is_some() {
            return Err(RpcError::FailedPrecondition(
                "domain is already verified".into(),
            ));
        }
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
            "verify_organization_domain",
            scope.as_str(),
            &input,
            &req.idempotency_key,
            vec![format!("verify DNS ownership of {}", input.domain)],
            Vec::new(),
            Some(control_confirmation_hash(&input)?),
        )
        .await
    }
}
