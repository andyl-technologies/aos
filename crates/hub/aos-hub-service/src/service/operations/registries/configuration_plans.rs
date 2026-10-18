//! Configuration plans in the registries capability.

use super::*;

impl RpcService {
    /// Plans creation of an identity-only managed registry.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, conflict, quota,
    /// or persistence error.
    pub async fn plan_create_registry(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreateRegistryRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        let org = self.org_or_not_found(&req.org_slug).await?;
        req.project_path = req.project_path.trim_matches('/').to_string();
        let owner_scope = if req.project_path.is_empty() {
            org.stable_id.clone()
        } else {
            self.db
                .project_scope_by_path(org.id, &req.project_path)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("project"))?
        };
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&owner_scope),
        )
        .await?;
        req.name = req.name.trim().to_string();
        if req.name.is_empty() || req.name.contains('/') {
            return Err(RpcError::invalid(
                "registry name must be one non-empty path segment",
            ));
        }
        match req.visibility.as_str() {
            "" => req.visibility = "private".to_string(),
            "public" | "internal" | "private" => {}
            other => return Err(RpcError::invalid(format!("invalid visibility '{other}'"))),
        }
        validate_registry_trust_keys(&req.trust_keys)?;
        if self
            .db
            .registry_by_scope(&org.slug, &req.project_path, &req.name)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "registry identity already exists".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RegistryCreatePlanInput {
            request: req,
            org_id: org.id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_registry",
            &owner_scope,
            &input,
            &idempotency_key,
            vec![format!(
                "create read-only registry identity '{}/{}/{}' without storage placement",
                org.slug, input.request.project_path, input.request.name
            )],
            vec!["publishing remains disabled until a placement and authority reconcile".into()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a CAS-sealed registry configuration update.
    pub async fn plan_update_registry(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanUpdateRegistryRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &self.registry_scope(&registry).await?,
        )
        .await?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || expected != registry.resource_version {
            return Err(RpcError::FailedPrecondition(
                "registry resource version is required and must be current".to_string(),
            ));
        }
        const FIELDS: &[&str] = &["visibility", "crawl_policy", "llms_txt_body", "trust_keys"];
        let mask = req
            .update_mask
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if mask.is_empty()
            || mask.len() != req.update_mask.len()
            || mask.iter().any(|field| !FIELDS.contains(field))
        {
            return Err(RpcError::invalid(
                "updateMask must contain unique mutable registry fields",
            ));
        }
        if !mask.contains("visibility") {
            req.visibility = registry.visibility.clone();
        }
        if !mask.contains("crawl_policy") {
            req.crawl_policy = registry.crawl_policy.clone();
        }
        if !mask.contains("llms_txt_body") {
            req.llms_txt_body = registry.llms_txt_body.clone().unwrap_or_default();
        }
        if !mask.contains("trust_keys") {
            req.trust_keys = registry.trust_keys.clone();
        }
        if !matches!(req.visibility.as_str(), "public" | "internal" | "private") {
            return Err(RpcError::invalid("invalid registry visibility"));
        }
        aos_hub_model::crawl::CrawlPolicy::parse(&req.crawl_policy)
            .map_err(|error| RpcError::invalid(error.to_string()))?;
        validate_registry_trust_keys(&req.trust_keys)?;
        let effects = registry_policy::effects(&registry, &req);
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RegistryUpdatePlanInput {
            request: req,
            registry_id: registry.id,
            owner_scope_key: registry.owner_scope_key.clone(),
            expected_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "update_registry",
            &registry.scope_key,
            &input,
            &idempotency_key,
            effects,
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans creation or exact replacement of registry-owned mirror configuration.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, stale-version, or
    /// database error.
    pub async fn plan_set_registry_mirror(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanRegistryMirrorMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.registry_id).await?;
        let claims = self.authorize_registry_mirror(auth, &registry).await?;
        let desired = req
            .desired
            .as_mut()
            .ok_or_else(|| RpcError::invalid("desired is required"))?;
        let mode = Self::canonicalize_registry_mirror_spec(desired)?;
        const ALLOWED_MASKS: &[&str] = &[
            "desired",
            "source_url",
            "refspec",
            "auth_secret_ref",
            "interval_seconds",
            "signature_policy",
            "mode",
        ];
        if let Some(field) = req
            .update_mask
            .iter()
            .find(|field| !ALLOWED_MASKS.contains(&field.as_str()))
        {
            return Err(RpcError::invalid(format!(
                "unsupported registry mirror update_mask field: {field}"
            )));
        }
        let current = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?;
        let expected = match req.expected_resource_version.as_deref() {
            Some("") => {
                return Err(RpcError::invalid(
                    "expected_resource_version cannot be empty when present",
                ));
            }
            Some(value) => Some(parse_resource_version(value, 0)?),
            None => None,
        };
        if expected != current.as_ref().map(|record| record.resource_version) {
            return Err(RpcError::FailedPrecondition(match current {
                Some(_) if expected.is_none() => {
                    "expected_resource_version is required to replace a registry mirror".to_string()
                }
                Some(_) => "registry mirror resource version is stale".to_string(),
                None => "registry mirror does not exist at the expected version".to_string(),
            }));
        }
        let idempotency_key = req.idempotency_key.clone();
        let input = RegistryMirrorMutationPlanInput {
            request: req,
            registry_db_id: registry.id,
            baseline_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_registry_mirror",
            self.registry_scope(&registry).await?.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "{} registry mirror '{}' from '{}' using refspec '{}'",
                if expected.is_some() {
                    "replace"
                } else {
                    "create"
                },
                mode,
                input
                    .request
                    .desired
                    .as_ref()
                    .map_or("", |spec| spec.source_url.as_str()),
                input
                    .request
                    .desired
                    .as_ref()
                    .map_or("", |spec| spec.refspec.as_str()),
            )],
            if input
                .request
                .desired
                .as_ref()
                .is_some_and(|spec| spec.signature_policy == "allow_unsigned")
            {
                vec!["upstream signatures will not be required".to_string()]
            } else {
                Vec::new()
            },
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans exact deletion of registry-owned mirror configuration.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, stale-version,
    /// not-found, or database error.
    pub async fn plan_delete_registry_mirror(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.stable_id).await?;
        let claims = self.authorize_registry_mirror(auth, &registry).await?;
        let current = self
            .db
            .registry_mirror(registry.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry mirror"))?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| RpcError::invalid("expected_resource_version is required"))?;
        if parse_resource_version(expected, 0)? != current.resource_version {
            return Err(RpcError::FailedPrecondition(
                "registry mirror resource version is stale".to_string(),
            ));
        }
        let idempotency_key = req.idempotency_key.clone();
        let input = RegistryMirrorDeletePlanInput {
            request: req,
            registry_db_id: registry.id,
            baseline_resource_version: current.resource_version,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_registry_mirror",
            self.registry_scope(&registry).await?.as_str(),
            &input,
            &idempotency_key,
            vec![format!(
                "remove upstream mirroring from registry '{}'",
                registry.slug
            )],
            vec!["previously mirrored objects are not deleted".to_string()],
            Some(confirmation_hash),
        )
        .await
    }
}
