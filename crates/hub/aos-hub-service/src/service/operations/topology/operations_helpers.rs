//! Operations helpers in the topology capability.

use super::*;

impl RpcService {
    /// Projects stable topology defaults onto the public contract.
    pub(in crate::service) fn stable_topology_defaults_message(
        record: crate::db::StableTopologyDefaultsRecord,
    ) -> pb::TopologyDefaults {
        pb::TopologyDefaults {
            scope_key: record.scope_key,
            binding_id: record.binding_id.unwrap_or_default(),
            domain_id: record.domain_id.unwrap_or_default(),
            endpoint_id: record.endpoint_id.unwrap_or_default(),
            endpoint_generation: record.endpoint_generation.unwrap_or_default(),
            gateway_id: record.gateway_id.unwrap_or_default(),
            gateway_generation: record.gateway_generation.unwrap_or_default(),
            resource_version: record.resource_version.to_string(),
        }
    }

    /// Projects stored defaults or the editable empty state for an unset scope.
    pub(in crate::service) fn topology_defaults_or_empty(
        scope_key: &str,
        record: Option<crate::db::StableTopologyDefaultsRecord>,
    ) -> pb::TopologyDefaults {
        record
            .map(Self::stable_topology_defaults_message)
            .unwrap_or_else(|| pb::TopologyDefaults {
                scope_key: scope_key.to_string(),
                ..Default::default()
            })
    }

    /// Persists an immutable topology-default replacement plan.
    pub(in crate::service) async fn plan_set_topology_defaults(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanSetTopologyDefaultsRequest,
        instance: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let defaults = req
            .defaults
            .as_mut()
            .ok_or_else(|| RpcError::invalid("defaults is required"))?;
        let org_id = self
            .writable_storage_owner(auth, &defaults.scope_key)
            .await?;
        if instance != org_id.is_none() {
            return Err(RpcError::invalid(
                "defaults scope does not match the selected instance/organization method",
            ));
        }
        if defaults.endpoint_id.is_empty() != (defaults.endpoint_generation == 0)
            || defaults.gateway_id.is_empty() != (defaults.gateway_generation == 0)
        {
            return Err(RpcError::invalid(
                "endpoint and gateway ids require positive paired generations",
            ));
        }
        let current = self
            .db
            .stable_topology_defaults(&defaults.scope_key)
            .await
            .map_err(RpcError::internal)?;
        let baseline = current.as_ref().map(|current| current.resource_version);
        match baseline {
            Some(version)
                if parse_resource_version(&req.expected_resource_version, version)? != version =>
            {
                return Err(RpcError::FailedPrecondition(
                    "topology defaults resource version is stale".to_string(),
                ));
            }
            None if !req.expected_resource_version.is_empty() => {
                return Err(RpcError::invalid(
                    "new topology defaults forbid expectedResourceVersion",
                ));
            }
            _ => {}
        }
        defaults.resource_version.clear();
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = TopologyDefaultsPlanInput {
            defaults: defaults.clone(),
            org_id,
            baseline_resource_version: baseline,
        };
        let plan_kind = if instance {
            "set_instance_topology_defaults"
        } else {
            "set_organization_topology_defaults"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &input.defaults.scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "replace topology defaults for '{}'",
                input.defaults.scope_key
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Applies an instance or organization topology-default replacement plan.
    pub(in crate::service) async fn apply_set_topology_defaults(
        &self,
        auth: Option<&str>,
        req: pb::ApplySetTopologyDefaultsRequest,
        instance: bool,
    ) -> Result<pb::TopologyDefaultsResponse, RpcError> {
        let plan_kind = if instance {
            "set_instance_topology_defaults"
        } else {
            "set_organization_topology_defaults"
        };
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                plan_kind,
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
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, TopologyDefaultsPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        if instance != input.org_id.is_none()
            || self
                .writable_storage_owner(auth, &input.defaults.scope_key)
                .await?
                != input.org_id
        {
            return Err(RpcError::FailedPrecondition(
                "topology-default ownership changed after planning".to_string(),
            ));
        }

        let current = self
            .db
            .stable_topology_defaults(&input.defaults.scope_key)
            .await
            .map_err(RpcError::internal)?;
        if let Some(current) = current {
            let current_message = Self::stable_topology_defaults_message(current.clone());
            let exact_recovery = current.resource_version
                == input.baseline_resource_version.unwrap_or_default() + 1
                && current_message.binding_id == input.defaults.binding_id
                && current_message.domain_id == input.defaults.domain_id
                && current_message.endpoint_id == input.defaults.endpoint_id
                && current_message.endpoint_generation == input.defaults.endpoint_generation
                && current_message.gateway_id == input.defaults.gateway_id
                && current_message.gateway_generation == input.defaults.gateway_generation;
            if exact_recovery {
                let response = pb::TopologyDefaultsResponse {
                    defaults: Some(current_message),
                };
                self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                    .await?;
                return Ok(response);
            }
            if Some(current.resource_version) != input.baseline_resource_version {
                return Err(RpcError::FailedPrecondition(
                    "topology defaults changed after planning".to_string(),
                ));
            }
        } else if input.baseline_resource_version.is_some() {
            return Err(RpcError::FailedPrecondition(
                "topology defaults were deleted after planning".to_string(),
            ));
        }

        fn optional(value: &str) -> Option<&str> {
            (!value.is_empty()).then_some(value)
        }
        let optional_generation = |value: i64| (value > 0).then_some(value);
        let defaults = self
            .db
            .set_stable_topology_defaults(
                if instance { "instance" } else { "organization" },
                input.org_id,
                &input.defaults.scope_key,
                optional(&input.defaults.binding_id),
                optional(&input.defaults.domain_id),
                optional(&input.defaults.endpoint_id),
                optional_generation(input.defaults.endpoint_generation),
                optional(&input.defaults.gateway_id),
                optional_generation(input.defaults.gateway_generation),
                input.baseline_resource_version,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::TopologyDefaultsResponse {
            defaults: Some(Self::stable_topology_defaults_message(defaults)),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Resolves and authorizes a typed topology surface reference.
    pub(in crate::service) async fn readable_topology_surface(
        &self,
        auth: Option<&str>,
        surface: Option<pb::SurfaceRef>,
    ) -> Result<crate::db::SurfaceTarget, RpcError> {
        match surface.and_then(|surface| surface.target) {
            Some(pb::surface_ref::Target::RegistrySlug(slug)) if !slug.is_empty() => {
                let registry = self.registry_or_not_found(&slug).await?;
                self.require_read(auth, &registry).await?;
                Ok(crate::db::SurfaceTarget::Registry(registry.id))
            }
            Some(pb::surface_ref::Target::CacheSlug(slug)) if !slug.is_empty() => {
                let cache = self
                    .db
                    .binary_cache_by_slug(&slug)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("cache"))?;
                self.require_cache_read(auth, &cache).await?;
                Ok(crate::db::SurfaceTarget::BinaryCache(cache.id))
            }
            Some(_) => Err(RpcError::invalid("surface slug must not be empty")),
            None => Err(RpcError::invalid(
                "surface must select exactly one registrySlug or cacheSlug",
            )),
        }
    }

    /// Resolves a typed surface and requires topology write authority.
    ///
    /// The IAM model does not yet have a dedicated `topology.manage` verb.
    /// Placement changes therefore temporarily use the stronger
    /// [`Permission::StorageManage`] capability on the owning organization;
    /// org-less resources require root [`Permission::IamAdmin`]. This mapping
    /// is intentionally centralized so a future dedicated verb is one change.
    pub(in crate::service) async fn writable_topology_surface(
        &self,
        auth: Option<&str>,
        surface: Option<pb::SurfaceRef>,
    ) -> Result<(crate::db::SurfaceTarget, Option<i64>), RpcError> {
        let claims = self.require_claims(auth)?;
        let (target, org_id) = match surface.and_then(|surface| surface.target) {
            Some(pb::surface_ref::Target::RegistrySlug(slug)) if !slug.is_empty() => {
                let registry = self.registry_or_not_found(&slug).await?;
                (
                    crate::db::SurfaceTarget::Registry(registry.id),
                    registry.org_id,
                )
            }
            Some(pb::surface_ref::Target::CacheSlug(slug)) if !slug.is_empty() => {
                let cache = self
                    .db
                    .binary_cache_by_slug(&slug)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("cache"))?;
                if cache.deleted_at.is_some() {
                    return Err(RpcError::not_found("cache"));
                }
                (
                    crate::db::SurfaceTarget::BinaryCache(cache.id),
                    cache.org_id,
                )
            }
            Some(_) => return Err(RpcError::invalid("surface slug must not be empty")),
            None => {
                return Err(RpcError::invalid(
                    "surface must select exactly one registrySlug or cacheSlug",
                ));
            }
        };
        match org_id {
            Some(id) => {
                if !self
                    .db
                    .org_is_active(id)
                    .await
                    .map_err(RpcError::internal)?
                {
                    return Err(RpcError::not_found("surface"));
                }
                let org = self
                    .db
                    .org_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("org"))?;
                self.require_permission(
                    &claims,
                    Permission::StorageManage,
                    &Scope::parse(&org.stable_id),
                )
                .await?;
            }
            None => {
                self.require_permission(&claims, Permission::IamAdmin, &Scope::root())
                    .await?;
            }
        }
        Ok((target, org_id))
    }

    /// Returns the canonical authorization and plan scope for one typed surface.
    pub(in crate::service) fn topology_scope(
        registry_id: Option<i64>,
        cache_id: Option<i64>,
    ) -> String {
        match (registry_id, cache_id) {
            (Some(id), None) => format!("topology:registry:{id}"),
            (None, Some(id)) => format!("topology:cache:{id}"),
            _ => "topology:invalid".to_string(),
        }
    }

    /// Builds a reusable reader whose every object access is placement-planned.
    pub(in crate::service) fn topology_surface_fetcher(
        &self,
        surface: SurfaceTarget,
    ) -> Box<dyn SurfaceFetch> {
        Box::new(crate::placement_read::TopologySurfaceFetch::new(
            Arc::clone(&self.db),
            Arc::clone(&self.surface),
            surface,
        ))
    }

    /// Returns the database-id tuple for a typed surface.
    pub(in crate::service) fn topology_surface_ids(
        surface: SurfaceTarget,
    ) -> (Option<i64>, Option<i64>) {
        match surface {
            SurfaceTarget::Registry(id) => (Some(id), None),
            SurfaceTarget::BinaryCache(id) => (None, Some(id)),
        }
    }
}
