//! Gateways helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn gateway_message(
        &self,
        record: aos_hub_db::db::GatewayRecord,
    ) -> Result<pb::Gateway, RpcError> {
        let desired = if let Some(generation) = record.desired_generation {
            let revision = self
                .db
                .gateway_revision(&record.id, generation)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("gateway revision is missing"))
                })?;
            let binding = self
                .db
                .binding(revision.spec.binding_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("gateway binding is missing")))?;
            let access_policy = serde_json::from_str(&revision.spec.access_policy_json)
                .map_err(RpcError::internal)?;
            Some(pb::GatewayRevisionSpec {
                binding_id: binding.stable_id,
                endpoint_id: revision.spec.endpoint_id,
                endpoint_generation: revision.spec.endpoint_generation,
                client_base_path: revision.spec.client_base_path,
                origin_prefix: revision.spec.origin_prefix,
                access_policy: Some(access_policy),
            })
        } else {
            None
        };
        let generation = record.desired_generation.unwrap_or_default();
        let grant_records = if generation > 0 {
            self.db
                .list_consumer_scope_grants(aos_hub_db::db::GrantResource::Gateway {
                    id: &record.id,
                    generation,
                })
                .await
                .map_err(RpcError::internal)?
        } else {
            Vec::new()
        };
        let mut grants = Vec::with_capacity(grant_records.len());
        for grant in grant_records {
            grants.push(
                self.topology_grant_message(
                    grant,
                    aos_hub_db::db::GrantResource::Gateway {
                        id: &record.id,
                        generation,
                    },
                )
                .await?,
            );
        }
        Ok(pb::Gateway {
            stable_id: record.id,
            owner_scope_key: record.owner_scope_key,
            enabled: record.enabled,
            desired_generation: generation,
            observed_generation: record.observed_generation.unwrap_or_default(),
            reconciliation_state: record.reconciliation_state,
            reconciliation_error: record.reconciliation_error.unwrap_or_default(),
            desired,
            grants,
            resource_version: record.resource_version.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    pub(in crate::service) async fn authorized_gateway(
        &self,
        auth: Option<&str>,
        stable_id: &str,
        permission: Permission,
    ) -> Result<aos_hub_db::db::GatewayRecord, RpcError> {
        let record = self
            .db
            .gateway(stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("gateway"))?;
        self.require_cloaked_delivery_scope(auth, &record.owner_scope_key, permission, "gateway")
            .await?;
        Ok(record)
    }

    pub(in crate::service) fn gateway_revision_spec(
        spec: Option<pb::GatewayRevisionSpec>,
        binding_id: i64,
    ) -> Result<aos_hub_db::db::GatewayRevisionSpec, RpcError> {
        use pb::delivery_access_policy::Policy;

        let spec = spec.ok_or_else(|| RpcError::invalid("revision is required"))?;
        if spec.endpoint_id.is_empty() || spec.endpoint_generation <= 0 {
            return Err(RpcError::invalid(
                "endpointId and a positive endpointGeneration are required",
            ));
        }
        let access_policy = spec
            .access_policy
            .ok_or_else(|| RpcError::invalid("accessPolicy is required"))?;
        let (
            access_policy_kind,
            access_boundary_id,
            access_boundary_revision,
            external_provider_kind,
            external_provider_resource_id,
            external_provider_revision,
        ) = match access_policy.policy.as_ref() {
            Some(Policy::Public(true)) => ("public", None, None, None, None, None),
            Some(Policy::Public(false)) => {
                return Err(RpcError::invalid("public access policy must be true"));
            }
            Some(Policy::PrivateNetwork(policy))
                if !policy.boundary_id.is_empty() && policy.boundary_revision > 0 =>
            {
                (
                    "private_network",
                    Some(policy.boundary_id.clone()),
                    Some(policy.boundary_revision),
                    None,
                    None,
                    None,
                )
            }
            Some(Policy::ExternalProvider(policy))
                if !policy.provider_kind.is_empty()
                    && !policy.resource_id.is_empty()
                    && !policy.revision.is_empty() =>
            {
                (
                    "external_provider",
                    None,
                    None,
                    Some(policy.provider_kind.clone()),
                    Some(policy.resource_id.clone()),
                    Some(policy.revision.clone()),
                )
            }
            Some(Policy::HubAuth(_)) => {
                return Err(RpcError::invalid(
                    "gateways do not support hubAuth access policy",
                ));
            }
            _ => return Err(RpcError::invalid("invalid closed gateway access policy")),
        };
        let access_policy_json =
            serde_json::to_string(&access_policy).map_err(RpcError::internal)?;
        Ok(aos_hub_db::db::GatewayRevisionSpec {
            binding_id,
            endpoint_id: spec.endpoint_id,
            endpoint_generation: spec.endpoint_generation,
            client_base_path: spec.client_base_path,
            origin_prefix: spec.origin_prefix,
            access_policy_kind: access_policy_kind.to_string(),
            access_boundary_id,
            access_boundary_revision,
            external_provider_kind,
            external_provider_resource_id,
            external_provider_revision,
            access_policy_json,
        })
    }

    pub(in crate::service) async fn plan_gateway_mutation(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanGatewayMutationRequest,
        update: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (org_id, expected_resource_version, owner_grant, carried_grants, scope) = if update {
            let current = self
                .authorized_gateway(auth, &req.stable_id, Permission::GatewayManage)
                .await?;
            self.require_cloaked_delivery_scope(
                auth,
                &current.owner_scope_key,
                Permission::GatewayGrant,
                "gateway",
            )
            .await?;
            if req.owner_scope_key.is_empty() {
                req.owner_scope_key = current.owner_scope_key.clone();
            } else if req.owner_scope_key != current.owner_scope_key {
                return Err(RpcError::invalid("gateway owner scope is immutable"));
            }
            let expected = parse_resource_version(&req.expected_resource_version, 0)?;
            if expected <= 0 || expected != current.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "gateway resource version is required and must be current".to_string(),
                ));
            }
            let generation = current.desired_generation.ok_or_else(|| {
                RpcError::FailedPrecondition("gateway has no desired generation".to_string())
            })?;
            let current_revision = self
                .db
                .gateway_revision(&current.id, generation)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("gateway generation"))?;
            let binding = self
                .db
                .binding(current_revision.spec.binding_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("binding"))?;
            let mut desired = req
                .revision
                .take()
                .ok_or_else(|| RpcError::invalid("revision is required"))?;
            const FIELDS: &[&str] = &[
                "revision.binding_id",
                "revision.endpoint_id",
                "revision.endpoint_generation",
                "revision.client_base_path",
                "revision.origin_prefix",
                "revision.access_policy",
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
                    "updateMask must contain unique gateway revision fields",
                ));
            }
            let current_message = pb::GatewayRevisionSpec {
                binding_id: binding.stable_id,
                endpoint_id: current_revision.spec.endpoint_id,
                endpoint_generation: current_revision.spec.endpoint_generation,
                client_base_path: current_revision.spec.client_base_path,
                origin_prefix: current_revision.spec.origin_prefix,
                access_policy: Some(
                    serde_json::from_str(&current_revision.spec.access_policy_json)
                        .map_err(RpcError::internal)?,
                ),
            };
            if !mask.contains("revision.binding_id") {
                desired.binding_id = current_message.binding_id;
            }
            if !mask.contains("revision.endpoint_id") {
                desired.endpoint_id = current_message.endpoint_id;
            }
            if !mask.contains("revision.endpoint_generation") {
                desired.endpoint_generation = current_message.endpoint_generation;
            }
            if !mask.contains("revision.client_base_path") {
                desired.client_base_path = current_message.client_base_path;
            }
            if !mask.contains("revision.origin_prefix") {
                desired.origin_prefix = current_message.origin_prefix;
            }
            if !mask.contains("revision.access_policy") {
                desired.access_policy = current_message.access_policy;
            }
            req.revision = Some(desired);
            let grants = self
                .db
                .list_consumer_scope_grants(aos_hub_db::db::GrantResource::Gateway {
                    id: &current.id,
                    generation,
                })
                .await
                .map_err(RpcError::internal)?;
            let owner = grants
                .iter()
                .find(|grant| {
                    grant.consumer_scope_key == current.owner_scope_key
                        && grant.grant_kind == "owner"
                        && grant.state == "active"
                })
                .ok_or_else(|| RpcError::not_found("active gateway owner grant"))?;
            let owner_grant = GatewayGrantPlanSeal {
                consumer_scope_key: owner.consumer_scope_key.clone(),
                grant_generation: owner.grant_generation,
                resource_version: owner.resource_version,
            };
            let mut carried = Vec::new();
            let mut seen = BTreeSet::new();
            for consumer_scope_key in &req.carry_forward_consumer_scopes {
                self.require_permission(
                    &claims,
                    Permission::GatewayGrant,
                    &parse_authorization_scope(consumer_scope_key)?,
                )
                .await?;
                if !seen.insert(consumer_scope_key.clone()) {
                    return Err(RpcError::invalid("duplicate carry-forward consumer scope"));
                }
                let grant = grants
                    .iter()
                    .find(|grant| {
                        grant.consumer_scope_key == *consumer_scope_key
                            && grant.grant_kind == "explicit"
                            && grant.state == "active"
                    })
                    .ok_or_else(|| RpcError::not_found("active gateway consumer grant"))?;
                carried.push(GatewayGrantPlanSeal {
                    consumer_scope_key: grant.consumer_scope_key.clone(),
                    grant_generation: grant.grant_generation,
                    resource_version: grant.resource_version,
                });
            }
            let (_, org_id, _) = self
                .db
                .authorization_scope_owner(&current.owner_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("owner scope"))?;
            (
                org_id,
                Some(expected),
                Some(owner_grant),
                carried,
                current.owner_scope_key,
            )
        } else {
            self.require_delivery_scope(auth, &req.owner_scope_key, Permission::GatewayManage)
                .await?;
            if !req.expected_resource_version.is_empty()
                || !req.update_mask.is_empty()
                || !req.carry_forward_consumer_scopes.is_empty()
            {
                return Err(RpcError::invalid(
                    "gateway creation forbids expectedResourceVersion, updateMask, and carryForwardConsumerScopes",
                ));
            }
            if self
                .db
                .gateway(&req.stable_id)
                .await
                .map_err(RpcError::internal)?
                .is_some()
            {
                return Err(RpcError::AlreadyExists(
                    "gateway already exists".to_string(),
                ));
            }
            let (_, org_id, _) = self
                .db
                .authorization_scope_owner(&req.owner_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("owner scope"))?;
            (org_id, None, None, Vec::new(), req.owner_scope_key.clone())
        };
        let binding_stable_id = req
            .revision
            .as_ref()
            .map(|revision| revision.binding_id.as_str())
            .filter(|id| !id.is_empty())
            .ok_or_else(|| RpcError::invalid("bindingId is required"))?;
        let binding = self
            .db
            .binding_by_stable_id(binding_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        self.authorize_gateway_binding(auth, &binding, &scope)
            .await?;
        Self::gateway_revision_spec(req.revision.clone(), binding.id)?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = GatewayMutationPlanInput {
            request: req,
            org_id,
            binding_id: binding.id,
            expected_resource_version,
            owner_grant,
            carried_grants,
        };
        let plan_kind = if update {
            "update_gateway"
        } else {
            "create_gateway"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &scope,
            &input,
            &idempotency_key,
            vec![format!(
                "{} gateway '{}'",
                if update {
                    "select a new generation for"
                } else {
                    "create"
                },
                input.request.stable_id
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_gateway_mutation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyGatewayMutationRequest,
        update: bool,
    ) -> Result<pb::GatewayResponse, RpcError> {
        let plan_kind = if update {
            "update_gateway"
        } else {
            "create_gateway"
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
        let (plan, input): (_, GatewayMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.require_delivery_scope(
            auth,
            &input.request.owner_scope_key,
            Permission::GatewayManage,
        )
        .await?;
        let binding_stable_id = input
            .request
            .revision
            .as_ref()
            .map(|revision| revision.binding_id.as_str())
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("gateway plan has no revision")))?;
        let binding = self
            .db
            .binding_by_stable_id(binding_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        if binding.id != input.binding_id {
            return Err(RpcError::FailedPrecondition(
                "binding identity changed after planning".to_string(),
            ));
        }
        self.authorize_gateway_binding(auth, &binding, &input.request.owner_scope_key)
            .await?;
        let revision = Self::gateway_revision_spec(input.request.revision.clone(), binding.id)?;
        let claims = self.require_claims(auth)?;
        let record = if update {
            self.require_cloaked_delivery_scope(
                auth,
                &input.request.owner_scope_key,
                Permission::GatewayGrant,
                "gateway",
            )
            .await?;
            for seal in &input.carried_grants {
                self.require_permission(
                    &claims,
                    Permission::GatewayGrant,
                    &parse_authorization_scope(&seal.consumer_scope_key)?,
                )
                .await?;
            }
            let owner = input.owner_grant.ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("gateway update plan has no owner grant"))
            })?;
            let owner = aos_hub_db::db::GatewayGrantCarryForward {
                consumer_scope_key: owner.consumer_scope_key,
                grant_generation: owner.grant_generation,
                resource_version: owner.resource_version,
            };
            let carried = input
                .carried_grants
                .into_iter()
                .map(|seal| aos_hub_db::db::GatewayGrantCarryForward {
                    consumer_scope_key: seal.consumer_scope_key,
                    grant_generation: seal.grant_generation,
                    resource_version: seal.resource_version,
                })
                .collect::<Vec<_>>();
            self.db
                .revise_gateway(
                    &input.request.stable_id,
                    &revision,
                    &owner,
                    &carried,
                    input.expected_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!(
                            "gateway update plan has no resource version"
                        ))
                    })?,
                    &claims.sub,
                    &req.idempotency_key,
                )
                .await
        } else {
            self.db
                .create_gateway(
                    &input.request.stable_id,
                    &input.request.owner_scope_key,
                    input.org_id,
                    &revision,
                    &claims.sub,
                )
                .await
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::GatewayResponse {
            gateway: Some(self.gateway_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    pub(in crate::service) async fn plan_gateway_scope_grant(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.resource_kind != "gateway" || req.consumer_scope_key.is_empty() {
            return Err(RpcError::invalid(
                "resourceKind must be gateway and consumerScopeKey is required",
            ));
        }
        let gateway = self
            .authorized_gateway(auth, &req.resource_stable_id, Permission::GatewayGrant)
            .await?;
        self.require_permission(
            &claims,
            Permission::GatewayGrant,
            &parse_authorization_scope(&req.consumer_scope_key)?,
        )
        .await?;
        let generation = gateway.desired_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("gateway has no desired generation".to_string())
        })?;
        if req.resource_generation != generation {
            return Err(RpcError::FailedPrecondition(
                "gateway generation is stale".to_string(),
            ));
        }
        let resource = aos_hub_db::db::GrantResource::Gateway {
            id: &gateway.id,
            generation,
        };
        let grants = self
            .db
            .list_consumer_scope_grants(resource)
            .await
            .map_err(RpcError::internal)?;
        let existing = grants
            .iter()
            .find(|grant| grant.consumer_scope_key == req.consumer_scope_key);
        let baseline = existing.map(|grant| grant.resource_version);
        let pin_resolutions = if revoke {
            let grant = existing.ok_or_else(|| RpcError::not_found("consumer grant"))?;
            if grant.grant_kind != "explicit" || grant.state != "active" {
                return Err(RpcError::FailedPrecondition(
                    "only an active explicit grant may be revoked".to_string(),
                ));
            }
            let expected = parse_resource_version(&req.expected_resource_version, 0)?;
            if expected <= 0 || expected != grant.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "grant resource version is required and must be current".to_string(),
                ));
            }
            let pins = self
                .db
                .consumer_scope_grant_pin_records(resource, &req.consumer_scope_key)
                .await
                .map_err(RpcError::internal)?;
            self.seal_grant_pin_resolutions(auth, &pins, &req.pin_resolutions)
                .await?
        } else if existing.is_some_and(|grant| grant.state == "active") {
            return Err(RpcError::AlreadyExists(
                "consumer scope is already granted".to_string(),
            ));
        } else if existing.is_none() && !req.expected_resource_version.is_empty() {
            return Err(RpcError::invalid(
                "new consumer grants forbid expectedResourceVersion",
            ));
        } else {
            if !req.pin_resolutions.is_empty() {
                return Err(RpcError::invalid("grant creation forbids pinResolutions"));
            }
            Vec::new()
        };
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = GatewayScopeGrantPlanInput {
            request: req,
            owner_scope_key: gateway.owner_scope_key.clone(),
            gateway_generation: generation,
            baseline_grant_resource_version: baseline,
            pin_resolutions,
        };
        let plan_kind = if revoke {
            "revoke_gateway_scope"
        } else {
            "grant_gateway_scope"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &gateway.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "{} gateway generation {} access for '{}'",
                if revoke { "revoke" } else { "grant" },
                generation,
                input.request.consumer_scope_key
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_gateway_scope_grant(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        let plan_kind = if revoke {
            "revoke_gateway_scope"
        } else {
            "grant_gateway_scope"
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
        let (plan, input): (_, GatewayScopeGrantPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let gateway = self
            .authorized_gateway(
                auth,
                &input.request.resource_stable_id,
                Permission::GatewayGrant,
            )
            .await?;
        if gateway.owner_scope_key != input.owner_scope_key
            || gateway.desired_generation != Some(input.gateway_generation)
        {
            return Err(RpcError::FailedPrecondition(
                "gateway owner or desired generation changed after planning".to_string(),
            ));
        }
        let resource = aos_hub_db::db::GrantResource::Gateway {
            id: &gateway.id,
            generation: input.gateway_generation,
        };
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::GatewayGrant,
            &parse_authorization_scope(&input.request.consumer_scope_key)?,
        )
        .await?;
        if revoke && !input.pin_resolutions.is_empty() {
            let record = self
                .db
                .load_consumer_scope_grant(resource, &input.request.consumer_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("gateway consumer grant"))?;
            let coordination_operation = self
                .schedule_grant_revocation(
                    &plan.plan_id,
                    "gateway",
                    &gateway.id,
                    input.gateway_generation,
                    &input.request.consumer_scope_key,
                    input.baseline_grant_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("revoke plan has no grant version"))
                    })?,
                    input.pin_resolutions,
                    &claims.sub,
                    &req.idempotency_key,
                    Permission::GatewayGrant,
                )
                .await?;
            let response = pb::ConsumerScopeGrantResponse {
                grant: Some(self.topology_grant_message(record, resource).await?),
                coordination_operation: Some(coordination_operation),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }
        let record = if revoke {
            self.db
                .revoke_consumer_scope(
                    resource,
                    &input.request.consumer_scope_key,
                    input.baseline_grant_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("revoke plan has no grant version"))
                    })?,
                    &claims.sub,
                    &req.idempotency_key,
                )
                .await
        } else {
            self.db
                .grant_consumer_scope(
                    resource,
                    &input.request.consumer_scope_key,
                    "explicit",
                    &claims.sub,
                    &req.idempotency_key,
                )
                .await
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::ConsumerScopeGrantResponse {
            grant: Some(self.topology_grant_message(record, resource).await?),
            coordination_operation: None,
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    pub(in crate::service) async fn plan_gateway_lifecycle(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
        operation: &str,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let gateway = self
            .authorized_gateway(auth, &req.stable_id, Permission::GatewayManage)
            .await?;
        let expected = req
            .expected_resource_version
            .as_deref()
            .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))
            .and_then(|value| parse_resource_version(value, 0))?;
        if expected <= 0 || expected != gateway.resource_version {
            return Err(RpcError::FailedPrecondition(
                "gateway resource version is stale".to_string(),
            ));
        }
        if operation == "enable"
            && (gateway.desired_generation != gateway.observed_generation
                || gateway.reconciliation_state != "ready")
        {
            return Err(RpcError::FailedPrecondition(
                "gateway must be reconciled and ready before enable".to_string(),
            ));
        }
        if operation == "delete" && gateway.enabled {
            return Err(RpcError::FailedPrecondition(
                "gateway must be disabled before deletion".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = GatewayLifecyclePlanInput {
            request: req,
            owner_scope_key: gateway.owner_scope_key.clone(),
            expected_resource_version: expected,
        };
        let plan_kind = format!("{operation}_gateway");
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            &plan_kind,
            &gateway.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!("{operation} gateway '{}'", gateway.id)],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_gateway_lifecycle(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
        operation: &str,
    ) -> Result<Result<pb::GatewayResponse, pb::DeleteTopologyResourceResponse>, RpcError> {
        let plan_kind = format!("{operation}_gateway");
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            &plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, GatewayLifecyclePlanInput) = self
            .load_control_plan(auth, &req.plan_id, &plan_kind, Some(&req.confirmation_hash))
            .await?;
        let gateway = self
            .authorized_gateway(auth, &input.request.stable_id, Permission::GatewayManage)
            .await?;
        if gateway.owner_scope_key != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "gateway owner changed after planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        if operation == "delete" {
            let deleted = self
                .db
                .delete_gateway(
                    &gateway.id,
                    input.expected_resource_version,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(RpcError::internal)?;
            if !deleted {
                return Err(RpcError::FailedPrecondition(
                    "gateway is stale, enabled, or still referenced".to_string(),
                ));
            }
            let response = pb::DeleteTopologyResourceResponse { deleted: true };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            Ok(Err(response))
        } else {
            let record = self
                .db
                .set_gateway_enabled(
                    &gateway.id,
                    operation == "enable",
                    input.expected_resource_version,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            let response = pb::GatewayResponse {
                gateway: Some(self.gateway_message(record).await?),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            Ok(Ok(response))
        }
    }
}
