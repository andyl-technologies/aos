//! Configuration plans in the caches capability.

use super::*;

impl RpcService {
    /// Plans creation of an identity-only binary-cache surface.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, conflict, or database error.
    pub async fn plan_create_binary_cache(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanBinaryCacheMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let desired = req
            .desired
            .as_mut()
            .ok_or_else(|| RpcError::invalid("desired is required"))?;
        // Cache creation exposes identity and access posture. Protocol defaults
        // are server policy, so clients do not have to manufacture hidden wire
        // literals simply to create the identity resource.
        if desired.compression.is_empty() {
            desired.compression = "zstd".to_string();
        }
        if desired.nix_priority == 0 {
            desired.nix_priority = 40;
        }
        Self::validate_binary_cache_spec(desired)?;
        if self
            .db
            .binary_cache_by_slug(&desired.slug)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Err(RpcError::AlreadyExists(
                "binary cache already exists".to_string(),
            ));
        }
        let org = self
            .db
            .org_by_stable_id(&desired.owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binary-cache owner scope"))?;
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::RegistryConfigure,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let plan_idempotency_key = req.idempotency_key.clone();
        let input = BinaryCacheMutationPlanInput {
            request: req,
            org_id: org.id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims, "create_binary_cache", &org.stable_id, &input,
            &plan_idempotency_key,
            vec!["create the binary-cache identity without implicit placement, route, publication, retention, or population".to_string()],
            Vec::new(), Some(confirmation_hash),
        ).await
    }

    /// Plans a version-checked binary-cache identity update.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, validation, stale-version, or database error.
    pub async fn plan_update_binary_cache(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanBinaryCacheMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.stable_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        let patch = req
            .desired
            .as_ref()
            .ok_or_else(|| RpcError::invalid("desired is required"))?;
        let owner_scope = self.binary_cache_owner_scope(&cache).await?;
        if (!patch.slug.is_empty() && patch.slug != cache.slug)
            || (!patch.owner_scope_key.is_empty() && patch.owner_scope_key != owner_scope)
        {
            return Err(RpcError::invalid(
                "binary-cache slug and owner_scope_key are immutable",
            ));
        }
        if req.update_mask.is_empty() {
            return Err(RpcError::invalid(
                "update_mask must name at least one mutable field",
            ));
        }
        let mut desired = pb::BinaryCacheSpec {
            slug: cache.slug.clone(),
            name: cache.name.clone(),
            owner_scope_key: owner_scope.clone(),
            visibility: cache.visibility.clone(),
            nix_priority: u32::try_from(cache.priority)
                .map_err(|_| RpcError::internal(anyhow::anyhow!("negative cache priority")))?,
            compression: cache.compression.clone(),
            want_mass_query: cache.want_mass_query,
        };
        let mut seen = std::collections::BTreeSet::new();
        for field in &req.update_mask {
            if !seen.insert(field.as_str()) {
                return Err(RpcError::invalid(format!(
                    "update_mask contains duplicate field '{field}'"
                )));
            }
            match field.as_str() {
                "name" => desired.name = patch.name.clone(),
                "visibility" => desired.visibility = patch.visibility.clone(),
                "nix_priority" => desired.nix_priority = patch.nix_priority,
                "compression" => desired.compression = patch.compression.clone(),
                "want_mass_query" => desired.want_mass_query = patch.want_mass_query,
                "slug" | "owner_scope_key" => {
                    return Err(RpcError::invalid(format!(
                        "binary-cache field '{field}' is immutable"
                    )));
                }
                _ => {
                    return Err(RpcError::invalid(format!(
                        "unsupported binary-cache update field '{field}'"
                    )));
                }
            }
        }
        Self::validate_binary_cache_spec(&desired)?;
        req.desired = Some(desired);
        if req.expected_resource_version.is_empty() {
            return Err(RpcError::invalid("expectedResourceVersion is required"));
        }
        let expected =
            parse_resource_version(&req.expected_resource_version, cache.resource_version)?;
        if expected != cache.resource_version {
            return Err(RpcError::FailedPrecondition(
                "binary cache resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let plan_idempotency_key = req.idempotency_key.clone();
        let input = BinaryCacheMutationPlanInput {
            request: req,
            org_id: cache.org_id.unwrap_or_default(),
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "update_binary_cache",
            &owner_scope,
            &input,
            &plan_idempotency_key,
            vec!["update only binary-cache identity and protocol defaults".to_string()],
            vec![
                "placements, routes, publication, retention, and population remain unchanged"
                    .to_string(),
            ],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans dependency-guarded binary-cache deletion.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-version, or database error.
    pub async fn plan_delete_binary_cache(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.stable_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        let expected = parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            cache.resource_version,
        )?;
        if expected != cache.resource_version {
            return Err(RpcError::FailedPrecondition(
                "binary cache resource version is stale".to_string(),
            ));
        }
        let input = BinaryCacheDeletePlanInput {
            cache_id: cache.id,
            stable_id: cache.stable_id.clone(),
            expected_resource_version: expected,
        };
        let confirmation = hex::encode(Sha256::digest(
            format!("delete-binary-cache\0{}\0{expected}", cache.stable_id).as_bytes(),
        ));
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims, "delete_binary_cache", &cache.scope_key, &input,
            &req.idempotency_key,
            vec!["tombstone the unreferenced binary-cache identity".to_string()],
            vec!["apply fails while placements, routes, retention subscriptions, or population targets remain".to_string()],
            Some(confirmation),
        ).await
    }
}
