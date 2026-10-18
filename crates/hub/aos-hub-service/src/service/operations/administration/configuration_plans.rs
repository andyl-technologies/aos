//! Configuration plans in the administration capability.

use super::*;

impl RpcService {
    /// Persists an immutable, exact-version instance-settings plan.
    pub async fn plan_set_instance_settings(
        &self,
        auth: Option<&str>,
        req: pb::PlanSetInstanceSettingsRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
            .await?;
        let mut writes: Vec<(String, Option<String>)> = Vec::new();
        for (key, value) in &req.values {
            let normalized = normalize_instance_value(key, value)?;
            writes.push((key.clone(), normalized));
        }
        let mut cleared = BTreeSet::new();
        for key in &req.clear {
            if req.values.contains_key(key) || !cleared.insert(key) {
                return Err(RpcError::invalid(format!(
                    "duplicate instance setting: {key}"
                )));
            }
            if !is_instance_key(key) {
                return Err(RpcError::invalid(format!(
                    "unknown instance setting: {key}"
                )));
            }
            writes.push((key.clone(), None));
        }
        writes.sort_by(|left, right| left.0.cmp(&right.0));
        let current = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?;
        let baseline_digest = instance_settings_digest(&current)?;
        if req.expected_resource_version != baseline_digest {
            return Err(RpcError::FailedPrecondition(
                "instance settings resource version is stale".to_string(),
            ));
        }
        let effects = instance_settings::effects(&current, &writes)?;
        let input = InstanceSettingsPlanInput {
            writes,
            baseline_digest,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_instance_settings",
            "instance",
            &input,
            &req.idempotency_key,
            effects,
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans creation or replacement of a population target.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or database error.
    pub async fn plan_set_population_target(
        &self,
        auth: Option<&str>,
        req: pb::PlanPopulationTargetRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let desired = req
            .desired
            .as_ref()
            .ok_or_else(|| RpcError::invalid("desired is required"))?;
        Self::validate_population_spec(desired)?;
        let current = self
            .population_target_for_pair(cache.id, registry.id)
            .await?;
        let expected = req.expected_resource_version.parse::<i64>().ok();
        if expected != current.as_ref().map(|target| target.resource_version) {
            return Err(RpcError::FailedPrecondition(
                "population target resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "set_population_target",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec![
                "create or replace the independent registry-to-cache population target".to_string(),
            ],
            vec!["publication and retention remain unchanged".to_string()],
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans deletion of a population target.
    ///
    /// # Errors
    ///
    /// Returns an authorization, ambiguity, stale-version, or database error.
    pub async fn plan_delete_population_target(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeletePopulationTargetRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, true)
            .await?;
        let current = self.single_population_target(cache.id, registry.id).await?;
        if parse_resource_version(&req.expected_resource_version, current.resource_version)?
            != current.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "population target resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_population_target",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["delete the population target".to_string()],
            vec![
                "publication, retention, and already-present objects remain unchanged".to_string(),
            ],
            Some(confirmation_hash),
        )
        .await
    }

    /// `TopologyService.PlanRemoveWriteAuthority` — plans an explicit read-only transition.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors or
    /// [`RpcError::FailedPrecondition`] unless authority is fully reconciled.
    pub async fn plan_remove_write_authority(
        &self,
        auth: Option<&str>,
        mut req: pb::SurfaceMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition("the surface is already read-only".to_string())
            })?;
        let observed_id = authority.observed_placement_id.ok_or_else(|| {
            RpcError::FailedPrecondition("write authority is not fully reconciled".to_string())
        })?;
        let observed_generation = authority.observed_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("write authority is not fully reconciled".to_string())
        })?;
        if authority.reconciliation_state != "ready"
            || authority.desired_placement_id != observed_id
            || authority.desired_generation != observed_generation
        {
            return Err(RpcError::FailedPrecondition(
                "write authority is not fully reconciled".to_string(),
            ));
        }
        let expected = parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            authority.resource_version,
        )?;
        if expected != authority.resource_version {
            return Err(RpcError::FailedPrecondition(
                "write-authority resource version is stale".to_string(),
            ));
        }
        let observed_name = self
            .db
            .surface_placement(observed_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("observed writer is missing")))?
            .name;
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = RemoveWriteAuthorityPlanInput {
            registry_id,
            cache_id,
            authority_id: authority.id,
            authority_incarnation_id: authority.incarnation_id.clone(),
            authority_resource_version: authority.resource_version,
            observed_generation,
            observed_placement_name: observed_name.clone(),
        };
        let effects = vec![
            "remove desired and observed write authority".to_string(),
            "leave every placement and readable object intact".to_string(),
            "make all Hub writes fail closed until a new promotion".to_string(),
        ];
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        self.create_control_plan(
            &claims,
            "remove_write_authority",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            effects,
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }
}
