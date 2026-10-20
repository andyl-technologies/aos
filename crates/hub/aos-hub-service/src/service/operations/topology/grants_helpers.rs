//! Grants helpers in the topology capability.

use super::*;

impl RpcService {
    /// Enforces the membership role ceiling for a currently authenticated actor.
    ///
    /// Members with `members.manage` may administer grants at or below their
    /// own effective role. Only an owner may create, replace, or remove an
    /// owner grant. The service repeats this check during apply so a sealed plan
    /// cannot outlive an intervening demotion.
    pub(in crate::service) async fn require_membership_grant_ceiling(
        &self,
        claims: &Claims,
        scope: &Scope,
        current_role: Option<Role>,
        desired_role: Option<Role>,
    ) -> Result<(), RpcError> {
        let actor = claims_principal(claims)
            .ok_or_else(|| RpcError::PermissionDenied("active principal required".into()))?;
        let context = self
            .db
            .authorization_context(scope.as_str())
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("authorization scope"))?;
        let actor_rank = self
            .db
            .effective_scopes(actor)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|(grant_scope, _)| context.is_covered_by(grant_scope))
            .map(|(_, role)| role.rank())
            .max()
            .unwrap_or(0);
        if current_role.is_some_and(|role| role.rank() > actor_rank) {
            return Err(RpcError::PermissionDenied(
                "cannot modify a membership above the actor's role".into(),
            ));
        }
        if desired_role.is_some_and(|role| role.rank() > actor_rank) {
            return Err(RpcError::PermissionDenied(
                "cannot grant a membership above the actor's role".into(),
            ));
        }
        if (current_role == Some(Role::Owner) || desired_role == Some(Role::Owner))
            && actor_rank < Role::Owner.rank()
        {
            return Err(RpcError::PermissionDenied(
                "only an owner may modify owner memberships".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::service) fn topology_pin_impact_message(
        pin: aos_hub_db::db::ConsumerScopeGrantPinRecord,
    ) -> pb::TopologyPinImpact {
        let allowed_actions = match pin.target_kind.as_str() {
            "endpoint" | "listener" => vec![
                pb::PinResolutionAction::MoveEndpoint as i32,
                pb::PinResolutionAction::Release as i32,
            ],
            "route" => vec![
                pb::PinResolutionAction::ReplaceRoute as i32,
                pb::PinResolutionAction::Release as i32,
            ],
            "placement" => vec![pb::PinResolutionAction::Release as i32],
            _ => Vec::new(),
        };
        pb::TopologyPinImpact {
            pin_id: pin.pin_id,
            target_kind: pin.target_kind,
            target_stable_id: pin.target_stable_id,
            target_generation: pin.target_generation_key,
            configuration_digest: pin.target_configuration_digest,
            expected_source_resource_version: pin.target_resource_version.to_string(),
            allowed_actions,
        }
    }

    pub(in crate::service) async fn topology_grant_message(
        &self,
        record: aos_hub_db::db::ConsumerScopeGrantRecord,
        resource: aos_hub_db::db::GrantResource<'_>,
    ) -> Result<pb::ConsumerScopeGrant, RpcError> {
        let impacts = self
            .db
            .consumer_scope_grant_pin_records(resource, &record.consumer_scope_key)
            .await
            .map_err(RpcError::internal)?;
        Ok(Self::topology_grant_message_with_pins(record, impacts))
    }

    pub(in crate::service) fn topology_grant_message_with_pins(
        record: aos_hub_db::db::ConsumerScopeGrantRecord,
        impacts: Vec<aos_hub_db::db::ConsumerScopeGrantPinRecord>,
    ) -> pb::ConsumerScopeGrant {
        let impacts = impacts
            .into_iter()
            .map(Self::topology_pin_impact_message)
            .collect::<Vec<_>>();
        pb::ConsumerScopeGrant {
            resource_kind: record.resource_kind,
            resource_stable_id: record.resource_stable_id,
            resource_generation: record.resource_generation,
            consumer_scope_key: record.consumer_scope_key,
            grant_generation: record.grant_generation,
            grant_kind: record.grant_kind,
            state: record.state,
            granted_by: record.granted_by,
            granted_at: record.granted_at,
            revoked_by: record.revoked_by.unwrap_or_default(),
            revoked_at: record.revoked_at.unwrap_or_default(),
            live_pin_count: u64::try_from(impacts.len()).unwrap_or_default(),
            live_pin_impacts: impacts,
            resource_version: record.resource_version.to_string(),
        }
    }

    pub(in crate::service) async fn seal_boundary_pin_resolutions(
        &self,
        auth: Option<&str>,
        boundary_id: &str,
        target_revision: i64,
        impacts: &[aos_hub_db::db::NetworkPolicyServingPinRecord],
        requested: &[pb::PinResolution],
    ) -> Result<Vec<aos_hub_db::db::NetworkPolicyPinResolutionSeal>, RpcError> {
        let mut by_pin = BTreeMap::new();
        for resolution in requested {
            if resolution.pin_id.is_empty() {
                return Err(RpcError::invalid("pinResolution.pinId is required"));
            }
            if by_pin
                .insert(resolution.pin_id.as_str(), resolution)
                .is_some()
            {
                return Err(RpcError::invalid(format!(
                    "duplicate pin resolution for '{}'",
                    resolution.pin_id
                )));
            }
        }
        let impact_ids = impacts
            .iter()
            .map(|impact| impact.pin_id.as_str())
            .collect::<BTreeSet<_>>();
        if by_pin.keys().copied().collect::<BTreeSet<_>>() != impact_ids {
            return Err(RpcError::invalid(
                "pinResolutions must contain exactly one action for every live pin and no extras",
            ));
        }

        let mut sealed = Vec::with_capacity(impacts.len());
        for impact in impacts {
            let resolution = by_pin.get(impact.pin_id.as_str()).ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("validated pin resolution disappeared"))
            })?;
            let action = resolution.resolution.as_ref().ok_or_else(|| {
                RpcError::invalid(format!("pin '{}' has no resolution action", impact.pin_id))
            })?;
            let (action_kind, source_resource_version, replacement) = match action {
                pb::pin_resolution::Resolution::MoveEndpoint(action) => {
                    if impact.target_kind != "endpoint" || impact.usage_kind != "endpoint_listener"
                    {
                        return Err(RpcError::invalid(format!(
                            "pin '{}' is not an endpoint-listener pin",
                            impact.pin_id
                        )));
                    }
                    let source_version =
                        parse_resource_version(&action.expected_source_resource_version, 0)?;
                    let target = action.replacement_endpoint.as_ref().ok_or_else(|| {
                        RpcError::invalid("moveEndpoint.replacementEndpoint is required")
                    })?;
                    if target.resource_kind != "endpoint"
                        || target.resource_stable_id != impact.target_stable_id
                        || target.resource_generation <= 0
                        || target.configuration_digest.is_empty()
                    {
                        return Err(RpcError::invalid(
                            "endpoint moves require another exact generation of the same endpoint",
                        ));
                    }
                    let endpoint = self
                        .managed_endpoint(
                            auth,
                            &target.resource_stable_id,
                            Permission::EndpointManage,
                        )
                        .await?;
                    let target_version =
                        parse_resource_version(&target.expected_resource_version, 0)?;
                    if source_version <= 0
                        || target_version <= 0
                        || source_version != endpoint.resource_version
                        || target_version != endpoint.resource_version
                    {
                        return Err(RpcError::FailedPrecondition(
                            "endpoint source or replacement resource version is stale".to_string(),
                        ));
                    }
                    let revision = self
                        .db
                        .endpoint_revision(&target.resource_stable_id, target.resource_generation)
                        .await
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found("replacement endpoint generation"))?;
                    if revision.network_policy_id != boundary_id
                        || revision.boundary_revision != target_revision
                        || revision.content_digest != target.configuration_digest
                    {
                        return Err(RpcError::FailedPrecondition(
                            "replacement endpoint generation does not seal the target boundary revision"
                                .to_string(),
                        ));
                    }
                    (
                        "move_endpoint",
                        source_version,
                        Some((target.clone(), target_version)),
                    )
                }
                pb::pin_resolution::Resolution::ReplaceRoute(action) => {
                    if impact.target_kind != "route" {
                        return Err(RpcError::invalid(format!(
                            "pin '{}' is not a route pin",
                            impact.pin_id
                        )));
                    }
                    let source_version =
                        parse_resource_version(&action.expected_source_resource_version, 0)?;
                    let source = self
                        .authorized_route(auth, &impact.target_stable_id, Permission::RouteManage)
                        .await?;
                    if source.resource_version != source_version
                        || source.configuration_generation != Some(impact.target_generation_key)
                        || source.configuration_digest.as_deref()
                            != Some(impact.target_configuration_digest.as_str())
                    {
                        return Err(RpcError::FailedPrecondition(
                            "source route changed after its pin was observed".to_string(),
                        ));
                    }
                    let target = action.replacement_route.as_ref().ok_or_else(|| {
                        RpcError::invalid("replaceRoute.replacementRoute is required")
                    })?;
                    if target.resource_kind != "route"
                        || target.resource_stable_id == impact.target_stable_id
                        || target.resource_generation <= 0
                        || target.configuration_digest.is_empty()
                    {
                        return Err(RpcError::invalid(
                            "route replacement requires a different exact route",
                        ));
                    }
                    let replacement = self
                        .authorized_route(auth, &target.resource_stable_id, Permission::RouteManage)
                        .await?;
                    let target_version =
                        parse_resource_version(&target.expected_resource_version, 0)?;
                    if replacement.resource_version != target_version
                        || replacement.configuration_generation != Some(target.resource_generation)
                        || replacement.configuration_digest.as_deref()
                            != Some(target.configuration_digest.as_str())
                        || replacement.surface != source.surface
                        || !replacement.enabled
                    {
                        return Err(RpcError::FailedPrecondition(
                            "replacement route is stale, disabled, or serves another surface"
                                .to_string(),
                        ));
                    }
                    (
                        "replace_route",
                        source_version,
                        Some((target.clone(), target_version)),
                    )
                }
                pb::pin_resolution::Resolution::Release(action) => {
                    let source_version =
                        parse_resource_version(&action.expected_source_resource_version, 0)?;
                    match impact.target_kind.as_str() {
                        "endpoint" => {
                            let endpoint = self
                                .managed_endpoint(
                                    auth,
                                    &impact.target_stable_id,
                                    Permission::EndpointManage,
                                )
                                .await?;
                            if endpoint.resource_version != source_version {
                                return Err(RpcError::FailedPrecondition(
                                    "source endpoint resource version is stale".to_string(),
                                ));
                            }
                        }
                        "route" => {
                            let route = self
                                .authorized_route(
                                    auth,
                                    &impact.target_stable_id,
                                    Permission::RouteManage,
                                )
                                .await?;
                            if route.resource_version != source_version
                                || route.configuration_generation
                                    != Some(impact.target_generation_key)
                                || route.configuration_digest.as_deref()
                                    != Some(impact.target_configuration_digest.as_str())
                            {
                                return Err(RpcError::FailedPrecondition(
                                    "source route resource version is stale".to_string(),
                                ));
                            }
                        }
                        _ => {
                            return Err(RpcError::invalid(
                                "boundary pin release supports endpoint and route targets only",
                            ));
                        }
                    }
                    ("release", source_version, None)
                }
            };
            let (
                replacement_target_kind,
                replacement_target_stable_id,
                replacement_target_generation_key,
                replacement_target_configuration_digest,
                replacement_resource_version,
            ) = replacement.map_or((None, None, None, None, None), |(target, version)| {
                (
                    Some(target.resource_kind),
                    Some(target.resource_stable_id),
                    Some(target.resource_generation),
                    Some(target.configuration_digest),
                    Some(version),
                )
            });
            sealed.push(aos_hub_db::db::NetworkPolicyPinResolutionSeal {
                source: impact.clone(),
                action_kind: action_kind.to_string(),
                source_resource_version,
                replacement_target_kind,
                replacement_target_stable_id,
                replacement_target_generation_key,
                replacement_target_configuration_digest,
                replacement_resource_version,
            });
        }
        Ok(sealed)
    }

    pub(in crate::service) async fn seal_grant_pin_resolutions(
        &self,
        auth: Option<&str>,
        pins: &[aos_hub_db::db::ConsumerScopeGrantPinRecord],
        requested: &[pb::PinResolution],
    ) -> Result<Vec<GrantPinResolutionSeal>, RpcError> {
        let mut by_pin = BTreeMap::new();
        for resolution in requested {
            if resolution.pin_id.is_empty()
                || by_pin
                    .insert(resolution.pin_id.as_str(), resolution)
                    .is_some()
            {
                return Err(RpcError::invalid(
                    "pin resolutions require unique, non-empty pin ids",
                ));
            }
        }
        if pins
            .iter()
            .map(|pin| pin.pin_id.as_str())
            .collect::<BTreeSet<_>>()
            != by_pin.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err(RpcError::invalid(
                "pinResolutions must contain exactly one action for every live grant pin and no extras",
            ));
        }
        let mut sealed = Vec::with_capacity(pins.len());
        for pin in pins {
            let requested = by_pin.get(pin.pin_id.as_str()).ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("validated grant pin disappeared"))
            })?;
            let action = requested.resolution.as_ref().ok_or_else(|| {
                RpcError::invalid(format!("pin '{}' has no resolution action", pin.pin_id))
            })?;
            let (action_kind, source_version, replacement) = match action {
                pb::pin_resolution::Resolution::Release(action) => (
                    "release",
                    parse_resource_version(&action.expected_source_resource_version, 0)?,
                    None,
                ),
                pb::pin_resolution::Resolution::ReplaceRoute(action) => {
                    if pin.target_kind != "route" {
                        return Err(RpcError::invalid(format!(
                            "pin '{}' is not a route pin",
                            pin.pin_id
                        )));
                    }
                    let target = action.replacement_route.clone().ok_or_else(|| {
                        RpcError::invalid("replaceRoute.replacementRoute is required")
                    })?;
                    if target.resource_kind != "route"
                        || target.resource_stable_id == pin.target_stable_id
                    {
                        return Err(RpcError::invalid(
                            "a route pin requires a different stable replacement route",
                        ));
                    }
                    (
                        "replace_route",
                        parse_resource_version(&action.expected_source_resource_version, 0)?,
                        Some(target),
                    )
                }
                pb::pin_resolution::Resolution::MoveEndpoint(action) => {
                    if !matches!(pin.target_kind.as_str(), "endpoint" | "listener") {
                        return Err(RpcError::invalid(format!(
                            "pin '{}' is not an endpoint pin",
                            pin.pin_id
                        )));
                    }
                    let target = action.replacement_endpoint.clone().ok_or_else(|| {
                        RpcError::invalid("moveEndpoint.replacementEndpoint is required")
                    })?;
                    if target.resource_kind != "endpoint"
                        || target.resource_stable_id != pin.target_stable_id
                    {
                        return Err(RpcError::invalid(
                            "endpoint moves require another exact generation of the same endpoint",
                        ));
                    }
                    (
                        "move_endpoint",
                        parse_resource_version(&action.expected_source_resource_version, 0)?,
                        Some(target),
                    )
                }
            };
            if source_version <= 0 || source_version != pin.target_resource_version {
                return Err(RpcError::FailedPrecondition(format!(
                    "source target for pin '{}' changed after inspection",
                    pin.pin_id
                )));
            }
            match pin.target_kind.as_str() {
                "route" => {
                    let route = self
                        .authorized_route(auth, &pin.target_stable_id, Permission::RouteManage)
                        .await?;
                    if route.resource_version != source_version
                        || route.configuration_generation != Some(pin.target_generation_key)
                        || route.configuration_digest.as_deref()
                            != Some(pin.target_configuration_digest.as_str())
                    {
                        return Err(RpcError::FailedPrecondition(
                            "source route no longer matches its grant pin".to_string(),
                        ));
                    }
                }
                "endpoint" | "listener" => {
                    let endpoint = self
                        .managed_endpoint(auth, &pin.target_stable_id, Permission::EndpointManage)
                        .await?;
                    if endpoint.resource_version != source_version {
                        return Err(RpcError::FailedPrecondition(
                            "source endpoint no longer matches its grant pin".to_string(),
                        ));
                    }
                    if action_kind == "release" {
                        if endpoint.desired_generation != Some(pin.target_generation_key)
                            || !self
                                .db
                                .endpoint_generation_impacts(
                                    &pin.target_stable_id,
                                    pin.target_generation_key,
                                )
                                .await
                                .map_err(RpcError::internal)?
                                .is_empty()
                        {
                            return Err(RpcError::FailedPrecondition(
                                "endpoint release requires the exact selected generation with no routes, gateways, or defaults"
                                    .to_string(),
                            ));
                        }
                    }
                }
                "placement" => {
                    let placement_id = pin
                        .target_stable_id
                        .split(':')
                        .nth(1)
                        .and_then(|value| value.parse::<i64>().ok())
                        .ok_or_else(|| {
                            RpcError::internal(anyhow::anyhow!(
                                "placement pin has malformed stable identity"
                            ))
                        })?;
                    let placement = self
                        .db
                        .surface_placement(placement_id)
                        .await
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found("placement"))?;
                    let owner_scope = self
                        .route_surface_owner_scope(placement.registry_id.map_or_else(
                            || SurfaceTarget::BinaryCache(placement.cache_id.unwrap_or_default()),
                            SurfaceTarget::Registry,
                        ))
                        .await?;
                    self.require_delivery_scope(auth, &owner_scope, Permission::PlacementManage)
                        .await?;
                    if placement.resource_version != source_version {
                        return Err(RpcError::FailedPrecondition(
                            "source placement no longer matches its grant pin".to_string(),
                        ));
                    }
                    if action_kind != "release" {
                        return Err(RpcError::invalid(
                            "placement pins currently support exact release only",
                        ));
                    }
                    if placement.desired_state != "offline"
                        || placement.effective_read_enabled
                        || placement.effective_write_enabled
                        || self
                            .db
                            .surface_placement_blockers(placement.id)
                            .await
                            .map_err(RpcError::internal)?
                            .prevents_deletion()
                    {
                        return Err(RpcError::FailedPrecondition(
                            "placement release requires an offline, drain-complete, unreferenced placement"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(RpcError::invalid(format!(
                        "unsupported grant pin target kind '{}'",
                        pin.target_kind
                    )));
                }
            }
            let replacement_resource_version = if let Some(target) = replacement.as_ref() {
                let expected = parse_resource_version(&target.expected_resource_version, 0)?;
                if target.resource_generation <= 0
                    || target.configuration_digest.is_empty()
                    || expected <= 0
                {
                    return Err(RpcError::invalid(
                        "replacement targets require generation, digest, and resource version",
                    ));
                }
                match target.resource_kind.as_str() {
                    "route" => {
                        let route = self
                            .authorized_route(
                                auth,
                                &target.resource_stable_id,
                                Permission::RouteManage,
                            )
                            .await?;
                        if !route.enabled
                            || route.resource_version != expected
                            || route.configuration_generation != Some(target.resource_generation)
                            || route.configuration_digest.as_deref()
                                != Some(target.configuration_digest.as_str())
                        {
                            return Err(RpcError::FailedPrecondition(
                                "replacement route target is stale or disabled".to_string(),
                            ));
                        }
                    }
                    "endpoint" => {
                        let endpoint = self
                            .managed_endpoint(
                                auth,
                                &target.resource_stable_id,
                                Permission::EndpointManage,
                            )
                            .await?;
                        let revision = self
                            .db
                            .endpoint_revision(
                                &target.resource_stable_id,
                                target.resource_generation,
                            )
                            .await
                            .map_err(RpcError::internal)?
                            .ok_or_else(|| {
                                RpcError::not_found("replacement endpoint generation")
                            })?;
                        if endpoint.resource_version != expected
                            || revision.content_digest != target.configuration_digest
                        {
                            return Err(RpcError::FailedPrecondition(
                                "replacement endpoint target is stale".to_string(),
                            ));
                        }
                    }
                    _ => return Err(RpcError::invalid("unsupported replacement target kind")),
                }
                Some(expected)
            } else {
                None
            };
            sealed.push(GrantPinResolutionSeal {
                source: pin.clone(),
                action_kind: action_kind.to_string(),
                replacement,
                replacement_resource_version,
            });
        }
        Ok(sealed)
    }

    pub(in crate::service) async fn schedule_grant_revocation(
        &self,
        plan_id: &str,
        resource_kind: &str,
        resource_stable_id: &str,
        resource_generation: i64,
        consumer_scope_key: &str,
        expected_grant_resource_version: i64,
        resolutions: Vec<GrantPinResolutionSeal>,
        actor: &str,
        request_id: &str,
        permission: Permission,
    ) -> Result<pb::OperationRef, RpcError> {
        let operation_id = format!(
            "grant-revoke:{}",
            &hex::encode(Sha256::digest(plan_id.as_bytes()))[..32]
        );
        if let Some(existing) = self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(pb::OperationRef {
                operation_id: existing.operation_id,
                kind: existing.operation_kind,
                state: existing.state,
                created_at: existing.created_at,
            });
        }
        let primary = resolutions.first().ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!(
                "coordinated revocation has no pin resolution"
            ))
        })?;
        let target = match primary.source.target_kind.as_str() {
            "endpoint" | "listener" => aos_hub_db::db::NewTopologyOperationTargetRef::Endpoint(
                primary.source.target_stable_id.clone(),
            ),
            "route" => aos_hub_db::db::NewTopologyOperationTargetRef::Route(
                primary.source.target_stable_id.clone(),
            ),
            "placement" => {
                if resource_kind != "binding" {
                    return Err(RpcError::invalid(
                        "placement pins require a storage-binding grant",
                    ));
                }
                let binding = self
                    .db
                    .binding_by_stable_id(resource_stable_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("binding"))?;
                aos_hub_db::db::NewTopologyOperationTargetRef::Binding(binding.id)
            }
            _ => return Err(RpcError::invalid("unsupported grant pin target kind")),
        };
        let (target_generation, target_digest) = if primary.source.target_kind == "placement" {
            (resource_generation, String::new())
        } else {
            (
                primary.source.target_generation_key,
                primary.source.target_configuration_digest.clone(),
            )
        };
        let detail = GrantRevocationOperationDetail {
            resource_kind: resource_kind.to_string(),
            resource_stable_id: resource_stable_id.to_string(),
            resource_generation,
            consumer_scope_key: consumer_scope_key.to_string(),
            expected_grant_resource_version,
            resolutions,
            actor: actor.to_string(),
            request_id: request_id.to_string(),
        };
        let operation = self
            .db
            .create_topology_operation(&aos_hub_db::db::NewTopologyOperation {
                operation_id,
                operation_kind: "consumer_scope_grant_revocation".to_string(),
                control_permission: permission,
                targets: vec![aos_hub_db::db::NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target,
                    generation_key: target_generation,
                    configuration_digest: target_digest,
                }],
                detail_json: serde_json::to_string(&detail).map_err(RpcError::internal)?,
                progress_total: Some(
                    i64::try_from(detail.resolutions.len()).map_err(RpcError::internal)? + 1,
                ),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok(pb::OperationRef {
            operation_id: operation.operation_id,
            kind: operation.operation_kind,
            state: operation.state,
            created_at: operation.created_at,
        })
    }
}
