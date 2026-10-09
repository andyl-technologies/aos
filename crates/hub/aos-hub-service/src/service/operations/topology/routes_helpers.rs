//! Routes helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn route_surface_plan_seal(
        surface: SurfaceTarget,
    ) -> RouteSurfacePlanSeal {
        match surface {
            SurfaceTarget::Registry(id) => RouteSurfacePlanSeal {
                registry_id: Some(id),
                cache_id: None,
            },
            SurfaceTarget::BinaryCache(id) => RouteSurfacePlanSeal {
                registry_id: None,
                cache_id: Some(id),
            },
        }
    }

    pub(in crate::service) fn route_surface_from_plan(
        seal: &RouteSurfacePlanSeal,
    ) -> Result<SurfaceTarget, RpcError> {
        match (seal.registry_id, seal.cache_id) {
            (Some(id), None) => Ok(SurfaceTarget::Registry(id)),
            (None, Some(id)) => Ok(SurfaceTarget::BinaryCache(id)),
            _ => Err(RpcError::internal(anyhow::anyhow!(
                "route plan has an invalid surface discriminator"
            ))),
        }
    }

    pub(in crate::service) async fn route_surface_message(
        &self,
        surface: SurfaceTarget,
    ) -> Result<pb::SurfaceRef, RpcError> {
        let target = match surface {
            SurfaceTarget::Registry(id) => pb::surface_ref::Target::RegistrySlug(
                self.db
                    .registry_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry"))?
                    .slug,
            ),
            SurfaceTarget::BinaryCache(id) => pb::surface_ref::Target::CacheSlug(
                self.db
                    .binary_cache_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("binary cache"))?
                    .slug,
            ),
        };
        Ok(pb::SurfaceRef {
            target: Some(target),
        })
    }

    pub(in crate::service) async fn authorized_route(
        &self,
        auth: Option<&str>,
        stable_id: &str,
        permission: Permission,
    ) -> Result<aos_hub_db::db::RouteRecord, RpcError> {
        let route = self
            .db
            .route(stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route"))?;
        let owner_scope_key = self
            .db
            .topology_operation_target_scope("route", &route.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("route"))?;
        self.require_cloaked_delivery_scope(auth, &owner_scope_key, permission, "route")
            .await?;
        Ok(route)
    }

    pub(in crate::service) fn normalize_route_base_path(path: &str) -> Result<String, RpcError> {
        if path.is_empty() || path == "/" {
            return Ok(String::new());
        }
        if !path.starts_with('/')
            || path.ends_with('/')
            || path.contains(['?', '#'])
            || path.contains("//")
            || path.split('/').any(|segment| matches!(segment, "." | ".."))
        {
            return Err(RpcError::invalid(
                "basePath must be a normalized rooted path without a trailing slash",
            ));
        }
        Ok(path.to_string())
    }

    pub(in crate::service) async fn rendered_route_url(
        &self,
        endpoint: &aos_hub_db::db::EndpointRecord,
        base_path: &str,
    ) -> Result<String, RpcError> {
        let host = if let Some(domain_id) = endpoint.domain_stable_id.as_deref() {
            self.db
                .delivery_domain(domain_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("endpoint domain"))?
                .hostname
        } else if let Some(bytes) = endpoint.ipv4_bytes.as_deref() {
            let octets: [u8; 4] = bytes.try_into().map_err(|_| {
                RpcError::internal(anyhow::anyhow!("persisted endpoint IPv4 is invalid"))
            })?;
            std::net::Ipv4Addr::from(octets).to_string()
        } else if let Some(bytes) = endpoint.ipv6_bytes.as_deref() {
            let octets: [u8; 16] = bytes.try_into().map_err(|_| {
                RpcError::internal(anyhow::anyhow!("persisted endpoint IPv6 is invalid"))
            })?;
            format!("[{}]", std::net::Ipv6Addr::from(octets))
        } else {
            return Err(RpcError::internal(anyhow::anyhow!(
                "persisted endpoint has no host"
            )));
        };
        let authority = if (endpoint.scheme == "http" && endpoint.effective_port == 80)
            || (endpoint.scheme == "https" && endpoint.effective_port == 443)
        {
            host
        } else {
            format!("{host}:{}", endpoint.effective_port)
        };
        Ok(format!("{}://{}{}", endpoint.scheme, authority, base_path))
    }

    pub(in crate::service) async fn route_reservation_plan_seal(
        &self,
        endpoint: &aos_hub_db::db::EndpointRecord,
        base_path: &str,
        canonical_url: &str,
    ) -> Result<RouteReservationPlanSeal, RpcError> {
        let keyring = self.route_reservation_keyring.as_deref().ok_or_else(|| {
            RpcError::FailedPrecondition("route reservation keyring is not configured".to_string())
        })?;
        let mut keys = keyring.snapshot().map_err(RpcError::internal)?;
        keys.sort_by_key(|key| key.version);
        let mut versions = BTreeSet::new();
        if keys.is_empty()
            || keys.iter().any(|key| {
                key.version <= 0 || key.secret.is_empty() || !versions.insert(key.version)
            })
            || keys.iter().filter(|key| key.active).count() != 1
        {
            return Err(RpcError::FailedPrecondition(
                "route reservation keyring must contain unique positive versions and exactly one active key"
                    .to_string(),
            ));
        }
        let referenced = self
            .db
            .route_reservation_key_versions()
            .await
            .map_err(RpcError::internal)?;
        if referenced.iter().any(|version| !versions.contains(version)) {
            return Err(RpcError::FailedPrecondition(
                "a retained route reservation key referenced by storage is unavailable".to_string(),
            ));
        }
        let endpoint_digest =
            hex::decode(&endpoint.endpoint_identity_digest).map_err(RpcError::internal)?;
        if endpoint_digest.len() != 32 {
            return Err(RpcError::internal(anyhow::anyhow!(
                "persisted endpoint identity digest is invalid"
            )));
        }
        let active_version = keys
            .iter()
            .find(|key| key.active)
            .map(|key| key.version)
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("active key disappeared")))?;
        let mut candidates = Vec::with_capacity(keys.len());
        for key in keys {
            let digest = aos_hub_db::db::Database::route_reservation_digest(
                &key.secret,
                &endpoint_digest,
                base_path,
                canonical_url,
            )
            .map_err(RpcError::internal)?;
            candidates.push(RouteReservationDigestPlanSeal {
                key_version: key.version,
                digest: hex::encode(digest),
            });
        }
        Ok(RouteReservationPlanSeal {
            active_version,
            candidates,
        })
    }

    pub(in crate::service) async fn route_surface_owner_scope(
        &self,
        surface: SurfaceTarget,
    ) -> Result<String, RpcError> {
        match surface {
            SurfaceTarget::Registry(id) => self
                .db
                .registry_by_id(id)
                .await
                .map_err(RpcError::internal)?
                .map(|record| record.owner_scope_key)
                .ok_or_else(|| RpcError::not_found("registry")),
            SurfaceTarget::BinaryCache(id) => self
                .db
                .binary_cache_by_id(id)
                .await
                .map_err(RpcError::internal)?
                .filter(|record| record.deleted_at.is_none())
                .map(|record| record.owner_scope_key)
                .ok_or_else(|| RpcError::not_found("binary cache")),
        }
    }

    pub(in crate::service) async fn managed_route_surface(
        &self,
        auth: Option<&str>,
        surface: Option<pb::SurfaceRef>,
    ) -> Result<(SurfaceTarget, String), RpcError> {
        let target = self.readable_topology_surface(auth, surface).await?;
        let owner_scope_key = self.route_surface_owner_scope(target).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteManage)
            .await?;
        Ok((target, owner_scope_key))
    }

    pub(in crate::service) fn route_access_policy_fields(
        policy: pb::DeliveryAccessPolicy,
    ) -> Result<
        (
            String,
            String,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
        RpcError,
    > {
        use pb::delivery_access_policy::Policy;
        let (kind, boundary_id, boundary_revision, provider_kind, resource_id, revision) =
            match policy.policy.as_ref() {
                Some(Policy::Public(true)) => ("public", None, None, None, None, None),
                Some(Policy::Public(false)) => {
                    return Err(RpcError::invalid("public access policy must be true"));
                }
                Some(Policy::HubAuth(_)) => ("hub_auth", None, None, None, None, None),
                Some(Policy::PrivateNetwork(value))
                    if !value.boundary_id.is_empty() && value.boundary_revision > 0 =>
                {
                    (
                        "private_network",
                        Some(value.boundary_id.clone()),
                        Some(value.boundary_revision),
                        None,
                        None,
                        None,
                    )
                }
                Some(Policy::ExternalProvider(value))
                    if !value.provider_kind.is_empty()
                        && !value.resource_id.is_empty()
                        && !value.revision.is_empty() =>
                {
                    (
                        "external_provider",
                        None,
                        None,
                        Some(value.provider_kind.clone()),
                        Some(value.resource_id.clone()),
                        Some(value.revision.clone()),
                    )
                }
                _ => return Err(RpcError::invalid("invalid closed route access policy")),
            };
        let json = serde_json::to_string(&policy).map_err(RpcError::internal)?;
        Ok((
            kind.to_string(),
            json,
            boundary_id,
            boundary_revision,
            provider_kind,
            resource_id,
            revision,
        ))
    }

    pub(in crate::service) async fn route_spec(
        &self,
        surface: SurfaceTarget,
        owner_scope_key: &str,
        mut spec: pb::RouteSpec,
    ) -> Result<
        (
            aos_hub_db::db::RouteSpec,
            String,
            aos_hub_db::db::EndpointRecord,
        ),
        RpcError,
    > {
        if spec.surface.as_ref() != Some(&self.route_surface_message(surface).await?) {
            return Err(RpcError::invalid(
                "route spec surface does not match request surface",
            ));
        }
        let endpoint = self
            .db
            .endpoint(&spec.endpoint_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint"))?;
        let endpoint_revision = self
            .db
            .endpoint_revision(&endpoint.id, spec.endpoint_generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
        let mut base_path = Self::normalize_route_base_path(&spec.base_path)?;
        let target = spec
            .target
            .and_then(|target| target.target)
            .ok_or_else(|| RpcError::invalid("route target is required"))?;
        let mut placements = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?;
        let mut gateway_id = None;
        let mut gateway_generation = None;
        let mut target_binding_id = None;
        let mut gateway_client_base_path = None;
        let mut target_placement_prefix = None;
        let mut placement_id = None;
        let mut placement_policy_revision_id = None;
        let mode = match target {
            pb::route_target::Target::HubPlacement(target) => {
                let placement = placements
                    .drain(..)
                    .find(|placement| placement.name == target.placement_name)
                    .ok_or_else(|| RpcError::not_found("surface placement"))?;
                placement_id = Some(placement.id);
                match pb::HubDeliveryKind::try_from(target.delivery_kind) {
                    Ok(pb::HubDeliveryKind::Proxy) => "hub_proxy",
                    Ok(pb::HubDeliveryKind::Redirect) => "hub_redirect",
                    _ => return Err(RpcError::invalid("hub deliveryKind is required")),
                }
            }
            pb::route_target::Target::HubPolicyRevision(target) => {
                let identity = self
                    .db
                    .list_placement_policy_identities(surface)
                    .await
                    .map_err(RpcError::internal)?
                    .into_iter()
                    .find(|identity| identity.name == target.policy_name)
                    .ok_or_else(|| RpcError::not_found("placement policy"))?;
                let revision = self
                    .db
                    .list_placement_policy_revisions(&identity.id)
                    .await
                    .map_err(RpcError::internal)?
                    .into_iter()
                    .find(|revision| revision.revision == target.revision)
                    .filter(|revision| revision.state == "published")
                    .ok_or_else(|| RpcError::not_found("published placement policy revision"))?;
                placement_policy_revision_id = Some(revision.id);
                match pb::HubDeliveryKind::try_from(target.delivery_kind) {
                    Ok(pb::HubDeliveryKind::Proxy) => "hub_proxy",
                    Ok(pb::HubDeliveryKind::Redirect) => "hub_redirect",
                    _ => return Err(RpcError::invalid("hub deliveryKind is required")),
                }
            }
            pb::route_target::Target::DirectGatewayPlacement(target) => {
                let placement = placements
                    .drain(..)
                    .find(|placement| placement.name == target.placement_name)
                    .ok_or_else(|| RpcError::not_found("surface placement"))?;
                let gateway = self
                    .db
                    .gateway_revision(&target.gateway_id, target.gateway_generation)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("gateway generation"))?;
                // A direct route is reachable only through its gateway, so
                // its path and policy derive from the gateway generation and
                // placement unless the caller pins them explicitly. The
                // database rejects any other path, so deriving here lets a
                // client omit what it cannot choose.
                if base_path.is_empty() {
                    base_path = aos_hub_db::db::join_route_segments(
                        &gateway.spec.client_base_path,
                        &placement.prefix,
                    )
                    .map_err(|error| RpcError::invalid(format!("direct route path: {error:#}")))?;
                }
                if spec.access_policy.is_none() {
                    spec.access_policy = Some(
                        serde_json::from_str(&gateway.spec.access_policy_json)
                            .map_err(RpcError::internal)?,
                    );
                }
                gateway_id = Some(gateway.gateway_id);
                gateway_generation = Some(gateway.generation);
                target_binding_id = Some(placement.binding_id);
                gateway_client_base_path = Some(gateway.spec.client_base_path);
                target_placement_prefix = Some(placement.prefix.clone());
                placement_id = Some(placement.id);
                "direct"
            }
        };
        let access_policy = spec
            .access_policy
            .ok_or_else(|| RpcError::invalid("accessPolicy is required"))?;
        let (
            access_policy_kind,
            access_policy_json,
            access_boundary_id,
            access_boundary_revision,
            external_provider_kind,
            external_provider_resource_id,
            external_provider_revision,
        ) = Self::route_access_policy_fields(access_policy)?;
        let access_policy_digest = hex::encode(Sha256::digest(access_policy_json.as_bytes()));
        let capabilities = spec
            .capabilities
            .ok_or_else(|| RpcError::invalid("capabilities are required"))?;
        let canonical_url = self.rendered_route_url(&endpoint, &base_path).await?;
        Ok((
            aos_hub_db::db::RouteSpec {
                consumer_scope_key: owner_scope_key.to_string(),
                endpoint_id: endpoint.id.clone(),
                endpoint_generation: spec.endpoint_generation,
                endpoint_ingress_kind: endpoint_revision.spec.ingress_kind,
                base_path,
                mode: mode.to_string(),
                access_policy_kind,
                access_policy_json,
                access_policy_digest,
                access_boundary_id,
                access_boundary_revision,
                external_provider_kind,
                external_provider_resource_id,
                external_provider_revision,
                gateway_id,
                gateway_generation,
                target_binding_id,
                gateway_client_base_path,
                target_placement_prefix,
                placement_id,
                placement_policy_revision_id,
                serves_git: capabilities.serves_git,
                serves_cache: capabilities.serves_cache,
                serves_web: capabilities.serves_web,
                serves_oci: capabilities.serves_oci,
                enabled: spec.enabled,
            },
            canonical_url,
            endpoint,
        ))
    }

    pub(in crate::service) async fn route_message(
        &self,
        route: aos_hub_db::db::RouteRecord,
    ) -> Result<pb::Route, RpcError> {
        let snapshot = self
            .db
            .route_snapshot(&route.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route snapshot is missing")))?;
        let target = if let Some(placement_id) = snapshot.spec.placement_id {
            let placement = self
                .db
                .surface_placement(placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route placement is missing")))?;
            if snapshot.spec.mode == "direct" {
                pb::route_target::Target::DirectGatewayPlacement(pb::DirectGatewayPlacementTarget {
                    placement_name: placement.name,
                    gateway_id: snapshot.spec.gateway_id.clone().unwrap_or_default(),
                    gateway_generation: snapshot.spec.gateway_generation.unwrap_or_default(),
                })
            } else {
                pb::route_target::Target::HubPlacement(pb::HubPlacementTarget {
                    placement_name: placement.name,
                    delivery_kind: if snapshot.spec.mode == "hub_redirect" {
                        pb::HubDeliveryKind::Redirect as i32
                    } else {
                        pb::HubDeliveryKind::Proxy as i32
                    },
                })
            }
        } else {
            let revision_id = snapshot
                .spec
                .placement_policy_revision_id
                .as_deref()
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route target is missing")))?;
            let revision = self
                .db
                .placement_policy_revision(revision_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("route policy revision is missing"))
                })?;
            let identity = self
                .db
                .placement_policy_identity(&revision.policy_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route policy is missing")))?;
            pb::route_target::Target::HubPolicyRevision(pb::HubPolicyRevisionTarget {
                policy_name: identity.name,
                revision: revision.revision,
                delivery_kind: if snapshot.spec.mode == "hub_redirect" {
                    pb::HubDeliveryKind::Redirect as i32
                } else {
                    pb::HubDeliveryKind::Proxy as i32
                },
            })
        };
        let surface = self.route_surface_message(route.surface).await?;
        Self::route_message_from_parts(route, snapshot, target, surface)
    }

    pub(in crate::service) fn route_message_from_parts(
        route: aos_hub_db::db::RouteRecord,
        snapshot: aos_hub_db::db::RouteSnapshotRecord,
        target: pb::route_target::Target,
        surface: pb::SurfaceRef,
    ) -> Result<pb::Route, RpcError> {
        let access_policy =
            serde_json::from_str(&snapshot.spec.access_policy_json).map_err(RpcError::internal)?;
        let configuration_generation = route.configuration_generation.unwrap_or_default();
        let configuration_digest = route.configuration_digest.unwrap_or_default();
        Ok(pb::Route {
            stable_id: route.id,
            spec: Some(pb::RouteSpec {
                surface: Some(surface),
                endpoint_id: snapshot.spec.endpoint_id,
                endpoint_generation: snapshot.spec.endpoint_generation,
                base_path: snapshot.spec.base_path,
                target: Some(pb::RouteTarget {
                    target: Some(target),
                }),
                access_policy: Some(access_policy),
                capabilities: Some(pb::RouteCapabilities {
                    serves_git: snapshot.spec.serves_git,
                    serves_cache: snapshot.spec.serves_cache,
                    serves_web: snapshot.spec.serves_web,
                    serves_oci: snapshot.spec.serves_oci,
                }),
                enabled: snapshot.spec.enabled,
            }),
            configuration_generation,
            configuration_digest: configuration_digest.clone(),
            canonical_rendered_url: snapshot.canonical_url,
            observation: Some(pb::RouteObservation {
                configuration_generation,
                configuration_digest,
                state: snapshot.observation_state,
                observed_at: snapshot.observed_at,
                error: snapshot.observation_error.unwrap_or_default(),
            }),
            resource_version: route.resource_version.to_string(),
            created_at: route.created_at,
            updated_at: route.updated_at,
        })
    }

    pub(in crate::service) async fn plan_route_mutation(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanRouteMutationRequest,
        update: bool,
        predecessor_route_id: Option<String>,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, owner_scope_key, expected_resource_version) = if update {
            let current = self
                .authorized_route(auth, &req.stable_id, Permission::RouteManage)
                .await?;
            let expected = parse_resource_version(&req.expected_resource_version, 0)?;
            if expected <= 0 || expected != current.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "route resource version is required and must be current".to_string(),
                ));
            }
            let current_message = self.route_message(current.clone()).await?;
            let current_spec = current_message
                .spec
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route spec is missing")))?;
            let desired = req
                .spec
                .as_mut()
                .ok_or_else(|| RpcError::invalid("spec is required"))?;
            const FIELDS: &[&str] = &[
                "spec.endpoint_generation",
                "spec.target",
                "spec.access_policy",
                "spec.capabilities",
                "spec.enabled",
            ];
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
                    "updateMask must contain unique mutable route fields",
                ));
            }
            if desired.surface != current_spec.surface
                || desired.endpoint_id != current_spec.endpoint_id
                || Self::normalize_route_base_path(&desired.base_path)?
                    != Self::normalize_route_base_path(&current_spec.base_path)?
            {
                return Err(RpcError::invalid(
                    "route surface, endpoint identity, and base path require ReplaceRoute",
                ));
            }
            if !mask.contains("spec.endpoint_generation") {
                desired.endpoint_generation = current_spec.endpoint_generation;
            }
            if !mask.contains("spec.target") {
                desired.target = current_spec.target;
            }
            if !mask.contains("spec.access_policy") {
                desired.access_policy = current_spec.access_policy;
            }
            if !mask.contains("spec.capabilities") {
                desired.capabilities = current_spec.capabilities;
            }
            if !mask.contains("spec.enabled") {
                desired.enabled = current_spec.enabled;
            }
            (
                current.surface,
                self.route_surface_owner_scope(current.surface).await?,
                Some(expected),
            )
        } else {
            if !req.expected_resource_version.is_empty() || !req.update_mask.is_empty() {
                return Err(RpcError::invalid(
                    "route creation forbids expectedResourceVersion and updateMask",
                ));
            }
            if self
                .db
                .route(&req.stable_id)
                .await
                .map_err(RpcError::internal)?
                .is_some()
            {
                return Err(RpcError::AlreadyExists("route already exists".to_string()));
            }
            let surface_ref = req.spec.as_ref().and_then(|spec| spec.surface.clone());
            let (surface, owner_scope_key) = self.managed_route_surface(auth, surface_ref).await?;
            (surface, owner_scope_key, None)
        };
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteManage)
            .await?;
        let (spec, canonical_url, endpoint) = self
            .route_spec(
                surface,
                &owner_scope_key,
                req.spec
                    .clone()
                    .ok_or_else(|| RpcError::invalid("spec is required"))?,
            )
            .await?;
        if update {
            let current = self
                .db
                .route_snapshot(&req.stable_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("route"))?;
            if current.canonical_url != canonical_url {
                return Err(RpcError::FailedPrecondition(
                    "a route URL identity change requires ReplaceRoute".to_string(),
                ));
            }
        }
        let reservation = if update {
            None
        } else {
            Some(
                self.route_reservation_plan_seal(&endpoint, &spec.base_path, &canonical_url)
                    .await?,
            )
        };
        let predecessor_resource_version =
            if let Some(predecessor_id) = predecessor_route_id.as_deref() {
                let predecessor = self
                    .authorized_route(auth, predecessor_id, Permission::RouteManage)
                    .await?;
                if predecessor.surface != surface {
                    return Err(RpcError::invalid(
                        "replacement route must belong to the predecessor surface",
                    ));
                }
                Some(predecessor.resource_version)
            } else {
                None
            };
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RouteMutationPlanInput {
            request: req,
            predecessor_route_id,
            predecessor_resource_version,
            surface: Self::route_surface_plan_seal(surface),
            canonical_url,
            reservation,
            expected_resource_version,
        };
        let plan_kind = if input.predecessor_route_id.is_some() {
            "replace_route"
        } else if update {
            "update_route"
        } else {
            "create_route"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("{plan_kind} '{}'", input.request.stable_id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_route_mutation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyRouteMutationRequest,
        plan_kind: &str,
    ) -> Result<pb::RouteResponse, RpcError> {
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
            self.wake_route_probe_controller().await;
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
        let (plan, input): (_, RouteMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let surface = Self::route_surface_from_plan(&input.surface)?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteManage)
            .await?;
        let (spec, canonical_url, endpoint) = self
            .route_spec(
                surface,
                &owner_scope_key,
                input
                    .request
                    .spec
                    .clone()
                    .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route plan has no spec")))?,
            )
            .await?;
        if canonical_url != input.canonical_url {
            return Err(RpcError::FailedPrecondition(
                "route canonical URL changed after planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let record = if plan_kind == "update_route" {
            self.db
                .update_route(
                    &input.request.stable_id,
                    &spec,
                    &canonical_url,
                    input.expected_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("route update plan has no version"))
                    })?,
                    &claims.sub,
                )
                .await
        } else {
            let sealed = input.reservation.as_ref().ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("route create plan has no reservation seal"))
            })?;
            let current = self
                .route_reservation_plan_seal(&endpoint, &spec.base_path, &canonical_url)
                .await?;
            if current != *sealed {
                return Err(RpcError::FailedPrecondition(
                    "route reservation keyring changed after planning; create a new plan"
                        .to_string(),
                ));
            }
            let mut candidates = Vec::with_capacity(sealed.candidates.len());
            for candidate in &sealed.candidates {
                candidates.push((
                    candidate.key_version,
                    hex::decode(&candidate.digest).map_err(RpcError::internal)?,
                ));
            }
            let active_digest = candidates
                .iter()
                .find(|(version, _)| *version == sealed.active_version)
                .map(|(_, digest)| digest.as_slice())
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("active reservation digest is missing"))
                })?;
            let predecessor = match (
                input.predecessor_route_id.as_deref(),
                input.predecessor_resource_version,
            ) {
                (Some(id), Some(version)) => Some((id, version)),
                (None, None) => None,
                _ => {
                    return Err(RpcError::internal(anyhow::anyhow!(
                        "route replacement plan has an incomplete predecessor seal"
                    )));
                }
            };
            self.db
                .create_route(
                    &input.request.stable_id,
                    surface,
                    &spec,
                    &canonical_url,
                    sealed.active_version,
                    active_digest,
                    &candidates,
                    predecessor,
                    &claims.sub,
                )
                .await
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::RouteResponse {
            route: Some(self.route_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        self.wake_route_probe_controller().await;
        Ok(response)
    }

    /// Wakes the controller after a route mutation has durably queued probe work.
    pub(in crate::service) async fn wake_route_probe_controller(&self) {
        if let Err(error) = self.topology_probes.wake_controller().await {
            // The operation is already durable and the periodic controller can
            // recover it. Do not report a failed mutation after it committed.
            tracing::warn!(
                error = %format!("{error:#}"),
                "waking delivery-route probe controller"
            );
        }
    }

    pub(in crate::service) async fn plan_route_lifecycle(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
        operation: &str,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let route = self
            .authorized_route(auth, &req.stable_id, Permission::RouteManage)
            .await?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected <= 0 || expected != route.resource_version {
            return Err(RpcError::FailedPrecondition(
                "route resource version is stale".to_string(),
            ));
        }
        if (operation == "enable" && route.enabled) || (operation == "disable" && !route.enabled) {
            return Err(RpcError::FailedPrecondition(format!(
                "route is already {}",
                if route.enabled { "enabled" } else { "disabled" }
            )));
        }
        if operation == "delete" && route.enabled {
            return Err(RpcError::FailedPrecondition(
                "route must be disabled before deletion".to_string(),
            ));
        }
        let owner_scope_key = self.route_surface_owner_scope(route.surface).await?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = RouteLifecyclePlanInput {
            request: req,
            expected_resource_version: expected,
        };
        let plan_kind = format!("{operation}_route");
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            &plan_kind,
            &owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("{operation} route '{}'", route.id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_route_lifecycle(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
        operation: &str,
    ) -> Result<Result<pb::RouteResponse, pb::DeleteTopologyResourceResponse>, RpcError> {
        let plan_kind = format!("{operation}_route");
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            &plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RouteLifecyclePlanInput) = self
            .load_control_plan(auth, &req.plan_id, &plan_kind, Some(&req.confirmation_hash))
            .await?;
        let route = self
            .authorized_route(auth, &input.request.stable_id, Permission::RouteManage)
            .await?;
        if operation == "delete" {
            let claims = self.require_claims(auth)?;
            let deleted = self
                .db
                .delete_route(
                    &route.id,
                    input.expected_resource_version,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(RpcError::internal)?;
            if !deleted {
                return Err(RpcError::FailedPrecondition(
                    "route is stale, enabled, canonical, pinned, or referenced".to_string(),
                ));
            }
            let response = pb::DeleteTopologyResourceResponse { deleted: true };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            Ok(Err(response))
        } else {
            let mut snapshot = self
                .db
                .route_snapshot(&route.id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("route configuration"))?;
            snapshot.spec.enabled = operation == "enable";
            let claims = self.require_claims(auth)?;
            let updated = self
                .db
                .update_route(
                    &route.id,
                    &snapshot.spec,
                    &snapshot.canonical_url,
                    input.expected_resource_version,
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            let response = pb::RouteResponse {
                route: Some(self.route_message(updated).await?),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            self.wake_route_probe_controller().await;
            Ok(Ok(response))
        }
    }
}
