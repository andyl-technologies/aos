//! Domains helpers in the topology capability.

use super::*;

impl RpcService {
    /// Enforces the instance email-domain allowlist at the signup moment.
    ///
    /// When `signup_domains` is set (non-empty), a *new* user principal — one
    /// with no existing membership and no instance-admin grant — must present an
    /// email whose lowercased domain is on the allowlist. Service accounts,
    /// existing members, and instance admins are exempt (the allowlist gates who
    /// may join, not who may keep operating). A user with no email on file is
    /// rejected when the allowlist is active (fail closed).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::PermissionDenied`] when the caller's email domain is
    /// not allowlisted, and [`RpcError::Internal`] on database failure.
    pub(in crate::service) async fn enforce_signup_domain(
        &self,
        claims: &Claims,
    ) -> Result<(), RpcError> {
        let principal = claims_principal(claims)
            .ok_or_else(|| RpcError::PermissionDenied("active principal required".to_string()))?;
        if !self
            .db
            .principal_is_live(principal.kind.as_str(), principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::PermissionDenied(
                "active principal required".to_string(),
            ));
        }
        let settings = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        if settings.signup_domains.is_empty() {
            return Ok(());
        }
        // Only user signups are gated; service accounts are provisioned by admins.
        if principal.kind != PrincipalKind::User {
            return Ok(());
        }
        // Established users (already a member or an instance admin) are exempt.
        if self
            .db
            .user_has_any_membership(principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(());
        }
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?;
        if iam::allow(
            &grants,
            Permission::IamAdmin,
            &iam::AuthorizationContext::instance(),
        ) {
            return Ok(());
        }
        // A new user: their email domain must be on the allowlist.
        let email = self
            .db
            .user_email(principal.id)
            .await
            .map_err(RpcError::internal)?;
        let domain = email
            .as_deref()
            .and_then(|e| e.rsplit_once('@'))
            .map(|(_, d)| d.to_lowercase());
        match domain {
            Some(d) if settings.signup_domains.iter().any(|allowed| allowed == &d) => Ok(()),
            _ => Err(RpcError::PermissionDenied(
                "your email domain is not permitted to sign up on this instance".into(),
            )),
        }
    }

    pub(in crate::service) fn delivery_domain_message(
        record: crate::db::DeliveryDomainRecord,
    ) -> Result<pb::Domain, RpcError> {
        let dns_configuration = record
            .dns_configuration_json
            .as_deref()
            .map(serde_json::from_str::<crate::db::DeliveryDnsConfigurationSpec>)
            .transpose()
            .map_err(RpcError::internal)?
            .map(delivery_dns_message);
        let certificate_configuration = record
            .certificate_configuration_json
            .as_deref()
            .map(serde_json::from_str::<crate::db::DeliveryCertificateConfigurationSpec>)
            .transpose()
            .map_err(RpcError::internal)?
            .map(delivery_certificate_message);
        Ok(pb::Domain {
            stable_id: record.stable_id,
            owner_scope_key: record.owner_scope_key,
            hostname: record.hostname,
            desired: Some(pb::DomainDesiredState {
                dns_configuration,
                certificate_configuration,
            }),
            observed: Some(pb::DomainObservedState {
                dns_state: record.dns_state,
                certificate_state: record.certificate_state,
                verified_at: record.verified_at.unwrap_or_default(),
                observed_at: record.observed_at.unwrap_or_default(),
                error: record.observation_error.unwrap_or_default(),
                observation_digest: record.observation_digest.unwrap_or_default(),
                probe_location: record.probe_location.unwrap_or_default(),
            }),
            resource_version: record.resource_version.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    /// Queues external verification of one domain desired-state snapshot.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, not-found, or scheduling error.
    pub(in crate::service) async fn execute_verify_domain(
        &self,
        auth: Option<&str>,
        req: pb::PlanVerifyDomainRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        self.require_claims(auth)?;
        let domain = match self
            .db
            .delivery_domain(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
        {
            Some(domain) => Some(domain),
            None if crate::db::canonical_delivery_hostname(&req.stable_id).is_ok() => self
                .db
                .delivery_domain_by_hostname(&req.stable_id)
                .await
                .map_err(RpcError::internal)?,
            None => None,
        }
        .ok_or_else(|| RpcError::not_found("domain"))?;
        if let Err(error) = self
            .require_delivery_scope(auth, &domain.owner_scope_key, Permission::DomainManage)
            .await
        {
            return match error {
                RpcError::Internal | RpcError::Unauthenticated(_) => Err(error),
                _ => Err(RpcError::not_found("domain")),
            };
        }
        if req.expected_resource_version.is_empty()
            || parse_resource_version(&req.expected_resource_version, domain.resource_version)?
                != domain.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "domain resource version is required and must be current".to_string(),
            ));
        }
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let operation_id = hex::encode(Sha256::digest(
            format!(
                "domain-probe-v1\0{}\0{}\0{}",
                domain.stable_id, domain.resource_version, req.idempotency_key
            )
            .as_bytes(),
        ));
        let operation = self
            .topology_probes
            .schedule(
                &operation_id,
                crate::topology_probe::TopologyProbe::Domain {
                    stable_id: domain.stable_id.clone(),
                    resource_version: domain.resource_version,
                },
            )
            .await
            .map_err(|error| {
                RpcError::FailedPrecondition(format!("schedule domain probe: {error:#}"))
            })?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }

    pub(in crate::service) async fn plan_domain_configuration(
        &self,
        auth: Option<&str>,
        stable_id: String,
        expected_resource_version: String,
        idempotency_key: String,
        dns: Option<crate::db::DeliveryDnsConfigurationSpec>,
        certificate: Option<crate::db::DeliveryCertificateConfigurationSpec>,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if dns.is_some() == certificate.is_some() {
            return Err(RpcError::invalid(
                "exactly one domain configuration family is required",
            ));
        }
        let current = self
            .db
            .delivery_domain(&stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("domain"))?;
        self.require_delivery_scope(auth, &current.owner_scope_key, Permission::DomainManage)
            .await?;
        if expected_resource_version.is_empty()
            || parse_resource_version(&expected_resource_version, current.resource_version)?
                != current.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "domain resource version is required and must be current".to_string(),
            ));
        }
        let kind = if dns.is_some() {
            "configure_domain_dns"
        } else {
            "configure_domain_certificate"
        };
        let input = DomainConfigurationPlanInput {
            stable_id,
            owner_scope_key: current.owner_scope_key,
            baseline_resource_version: current.resource_version,
            dns,
            certificate,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            kind,
            &input.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "replace desired domain configuration for '{}'",
                input.stable_id
            )],
            vec!["verification is queued separately and observations remain unchanged".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_domain_configuration(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDomainConfigurationRequest,
        kind: &str,
    ) -> Result<pb::DomainResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                kind,
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
            kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, DomainConfigurationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, kind, Some(&req.confirmation_hash))
            .await?;
        self.require_delivery_scope(auth, &input.owner_scope_key, Permission::DomainManage)
            .await?;
        if self
            .db
            .delivery_domain_matches_configuration_plan(
                &input.stable_id,
                input.baseline_resource_version + 1,
                &plan.plan_id,
                input.dns.as_ref(),
                input.certificate.as_ref(),
            )
            .await
            .map_err(RpcError::internal)?
        {
            let domain = self
                .db
                .delivery_domain(&input.stable_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("domain"))?;
            let response = pb::DomainResponse {
                domain: Some(Self::delivery_domain_message(domain)?),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }
        let domain = match (input.dns.as_ref(), input.certificate.as_ref()) {
            (Some(configuration), None) if kind == "configure_domain_dns" => {
                self.db
                    .configure_delivery_domain_dns(
                        &input.stable_id,
                        configuration,
                        input.baseline_resource_version,
                        &plan.plan_id,
                    )
                    .await
            }
            (None, Some(configuration)) if kind == "configure_domain_certificate" => {
                self.db
                    .configure_delivery_domain_certificate(
                        &input.stable_id,
                        configuration,
                        input.baseline_resource_version,
                        &plan.plan_id,
                    )
                    .await
            }
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "invalid domain plan payload"
                )));
            }
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("apply domain config: {error:#}")))?;
        let response = pb::DomainResponse {
            domain: Some(Self::delivery_domain_message(domain)?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    pub(in crate::service) async fn organization_domain_revision(
        &self,
        org: &crate::db::OrgRecord,
        domain: &str,
        expected_resource_version: &str,
    ) -> Result<crate::db::OrgDomainRecord, RpcError> {
        let record = self
            .db
            .org_domain(domain)
            .await
            .map_err(RpcError::internal)?
            .filter(|record| record.org_id == org.id)
            .ok_or_else(|| RpcError::not_found("organization domain"))?;
        if expected_resource_version
            != identity_resource_version(record.resource_version, record.incarnation_id.as_deref())
        {
            return Err(RpcError::FailedPrecondition(
                "domain claim revision changed".into(),
            ));
        }
        Ok(record)
    }

    pub(in crate::service) async fn replayed_organization_domain_plan(
        &self,
        claims: &Claims,
        kind: &str,
        org_slug: &str,
        domain: &str,
        expected_resource_version: &str,
        idempotency_key: &str,
    ) -> Result<Option<pb::TopologyPlanResponse>, RpcError> {
        let Some((plan, input)) = self
            .replayed_control_plan_input::<OrganizationDomainPlanInput>(
                claims,
                kind,
                idempotency_key,
            )
            .await?
        else {
            return Ok(None);
        };
        let expected_version = input.baseline_resource_version.map_or_else(
            || "absent".to_string(),
            |version| identity_resource_version(version, input.baseline_incarnation_id.as_deref()),
        );
        if input.org_slug != org_slug
            || input.domain != domain
            || expected_version != expected_resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "plan idempotency key was already used for different input".into(),
            ));
        }
        Self::control_plan_response(plan).map(Some)
    }
}
