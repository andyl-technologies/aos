//! Networks helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn network_policy_identity_spec(
        kind: &str,
        identity: Option<pb::NetworkPolicyIdentity>,
    ) -> Result<aos_hub_db::db::NetworkPolicyIdentitySpec, RpcError> {
        use pb::network_policy_identity::Identity;
        let identity = identity
            .and_then(|value| value.identity)
            .ok_or_else(|| RpcError::invalid("identity is required"))?;
        let provider_resource = |value: pb::ProviderResourceIdentity| {
            (value.provider, value.account_or_tenant, value.resource_id)
        };
        match (kind, identity) {
            ("public", Identity::Public(true)) => {
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::Public)
            }
            ("vpn", Identity::Vpn(value)) => {
                let (provider, account_or_tenant, resource_id) = provider_resource(value);
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::Vpn {
                    provider,
                    account_or_tenant,
                    resource_id,
                })
            }
            ("vpc", Identity::ProviderNetwork(value)) => {
                if !value.listener_id.is_empty() {
                    return Err(RpcError::invalid("vpc identity forbids listenerId"));
                }
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::Vpc {
                    provider: value.provider,
                    account_or_tenant: value.account_or_tenant,
                    resource_id: value.resource_id,
                })
            }
            ("tunnel", Identity::Tunnel(value)) => {
                let (provider, account_or_tenant, resource_id) = provider_resource(value);
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::Tunnel {
                    provider,
                    account_or_tenant,
                    resource_id,
                })
            }
            ("source_allowlist", Identity::SourceAllowlistId(logical_id)) => {
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::SourceAllowlist { logical_id })
            }
            ("trusted_ingress", Identity::TrustedIngress(value)) => {
                if !value.resource_id.is_empty() {
                    return Err(RpcError::invalid(
                        "trusted ingress identity forbids resourceId",
                    ));
                }
                Ok(aos_hub_db::db::NetworkPolicyIdentitySpec::TrustedIngress {
                    provider: value.provider,
                    account_or_tenant: value.account_or_tenant,
                    listener_id: value.listener_id,
                })
            }
            _ => Err(RpcError::invalid(
                "kind and network-boundary identity variant must match",
            )),
        }
    }

    pub(in crate::service) fn network_policy_identity_message(
        identity: aos_hub_db::db::NetworkPolicyIdentitySpec,
    ) -> pb::NetworkPolicyIdentity {
        use pb::network_policy_identity::Identity;
        let identity = match identity {
            aos_hub_db::db::NetworkPolicyIdentitySpec::Public => Identity::Public(true),
            aos_hub_db::db::NetworkPolicyIdentitySpec::Vpn {
                provider,
                account_or_tenant,
                resource_id,
            } => Identity::Vpn(pb::ProviderResourceIdentity {
                provider,
                account_or_tenant,
                resource_id,
            }),
            aos_hub_db::db::NetworkPolicyIdentitySpec::Vpc {
                provider,
                account_or_tenant,
                resource_id,
            } => Identity::ProviderNetwork(pb::ProviderNetworkIdentity {
                provider,
                account_or_tenant,
                resource_id,
                listener_id: String::new(),
            }),
            aos_hub_db::db::NetworkPolicyIdentitySpec::Tunnel {
                provider,
                account_or_tenant,
                resource_id,
            } => Identity::Tunnel(pb::ProviderResourceIdentity {
                provider,
                account_or_tenant,
                resource_id,
            }),
            aos_hub_db::db::NetworkPolicyIdentitySpec::SourceAllowlist { logical_id } => {
                Identity::SourceAllowlistId(logical_id)
            }
            aos_hub_db::db::NetworkPolicyIdentitySpec::TrustedIngress {
                provider,
                account_or_tenant,
                listener_id,
            } => Identity::TrustedIngress(pb::ProviderNetworkIdentity {
                provider,
                account_or_tenant,
                resource_id: String::new(),
                listener_id,
            }),
        };
        pb::NetworkPolicyIdentity {
            identity: Some(identity),
        }
    }

    pub(in crate::service) fn network_policy_revision_spec(
        spec: Option<pb::NetworkPolicyRevisionSpec>,
    ) -> Result<aos_hub_db::db::NetworkPolicyRevisionSpec, RpcError> {
        #[derive(serde::Serialize)]
        struct Mtls<'a> {
            ca_secret_ref: &'a str,
            client_sans: &'a [String],
        }
        #[derive(serde::Serialize)]
        struct SignedAssertion<'a> {
            issuer: &'a str,
            audience: &'a str,
            verification_key_secret_ref: &'a str,
        }
        use pb::trusted_ingress_configuration::Configuration;
        let spec = spec.ok_or_else(|| RpcError::invalid("revision spec is required"))?;
        let (trusted_ingress_kind, trusted_ingress_configuration) = match spec
            .trusted_ingress
            .and_then(|trusted| trusted.configuration)
            .ok_or_else(|| RpcError::invalid("trustedIngress is required"))?
        {
            Configuration::None(true) => ("none".to_string(), "{}".to_string()),
            Configuration::Mtls(value) => (
                "mtls".to_string(),
                serde_json::to_string(&Mtls {
                    ca_secret_ref: &value.ca_secret_ref,
                    client_sans: &value.client_sans,
                })
                .map_err(RpcError::internal)?,
            ),
            Configuration::SignedAssertion(value) => (
                "signed_assertion".to_string(),
                serde_json::to_string(&SignedAssertion {
                    issuer: &value.issuer,
                    audience: &value.audience,
                    verification_key_secret_ref: &value.verification_key_secret_ref,
                })
                .map_err(RpcError::internal)?,
            ),
            _ => return Err(RpcError::invalid("invalid trustedIngress variant")),
        };
        Ok(aos_hub_db::db::NetworkPolicyRevisionSpec {
            protected_transport_required: spec.protected_transport_required,
            trusted_ingress_kind,
            trusted_ingress_configuration,
            source_allowlist_cidrs: if spec.source_allowlist_cidrs.is_empty() {
                None
            } else {
                Some(
                    serde_json::to_string(&spec.source_allowlist_cidrs)
                        .map_err(RpcError::internal)?,
                )
            },
            probe_location_configuration: spec.probe_location_configuration_ref,
        })
    }

    pub(in crate::service) fn network_policy_revision_spec_message(
        spec: &aos_hub_db::db::NetworkPolicyRevisionSpec,
    ) -> Result<pb::NetworkPolicyRevisionSpec, RpcError> {
        use pb::trusted_ingress_configuration::Configuration;
        let configuration = match spec.trusted_ingress_kind.as_str() {
            "none" => Configuration::None(true),
            "mtls" => {
                let value: serde_json::Value =
                    serde_json::from_str(&spec.trusted_ingress_configuration)
                        .map_err(RpcError::internal)?;
                Configuration::Mtls(pb::MtlsTrustedIngress {
                    ca_secret_ref: value
                        .get("ca_secret_ref")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    client_sans: value
                        .get("client_sans")
                        .and_then(serde_json::Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect(),
                })
            }
            "signed_assertion" => {
                let value: serde_json::Value =
                    serde_json::from_str(&spec.trusted_ingress_configuration)
                        .map_err(RpcError::internal)?;
                Configuration::SignedAssertion(pb::SignedAssertionTrustedIngress {
                    issuer: value
                        .get("issuer")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    audience: value
                        .get("audience")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    verification_key_secret_ref: value
                        .get("verification_key_secret_ref")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
            }
            other => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "persisted boundary has invalid trusted-ingress kind '{other}'"
                )));
            }
        };
        Ok(pb::NetworkPolicyRevisionSpec {
            protected_transport_required: spec.protected_transport_required,
            trusted_ingress: Some(pb::TrustedIngressConfiguration {
                configuration: Some(configuration),
            }),
            source_allowlist_cidrs: spec
                .source_allowlist_cidrs
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(RpcError::internal)?
                .unwrap_or_default(),
            probe_location_configuration_ref: spec.probe_location_configuration.clone(),
        })
    }

    pub(in crate::service) async fn network_policy_message(
        &self,
        record: aos_hub_db::db::NetworkPolicyRecord,
    ) -> Result<pb::NetworkPolicy, RpcError> {
        let identity =
            serde_json::from_str(&record.identity_spec_json).map_err(RpcError::internal)?;
        let grant_records = self
            .db
            .list_consumer_scope_grants(aos_hub_db::db::GrantResource::NetworkPolicy {
                id: &record.id,
            })
            .await
            .map_err(RpcError::internal)?;
        let mut grants = Vec::with_capacity(grant_records.len());
        for grant in grant_records {
            grants.push(
                self.topology_grant_message(
                    grant,
                    aos_hub_db::db::GrantResource::NetworkPolicy { id: &record.id },
                )
                .await?,
            );
        }
        Ok(pb::NetworkPolicy {
            stable_id: record.id,
            owner_scope_key: record.owner_scope_key,
            name: record.name,
            kind: record.kind,
            identity: Some(Self::network_policy_identity_message(identity)),
            identity_fingerprint: record.identity_fingerprint,
            default_revision: record.default_revision.unwrap_or_default(),
            grants,
            resource_version: record.resource_version.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    pub(in crate::service) fn network_policy_revision_message(
        record: aos_hub_db::db::NetworkPolicyRevisionRecord,
    ) -> Result<pb::NetworkPolicyRevision, RpcError> {
        Ok(pb::NetworkPolicyRevision {
            boundary_id: record.boundary_id,
            revision: record.revision,
            spec: Some(Self::network_policy_revision_spec_message(&record.spec)?),
            observation: Some(pb::NetworkPolicyObservation {
                state: record.observation_state,
                protected_transport_observed: record.protected_transport_observed,
                trusted_ingress_observed: record.trusted_ingress_observed,
                observed_at: record.observed_at,
                error: record.observation_error.unwrap_or_default(),
            }),
            lifecycle: Some(pb::NetworkPolicyRevisionLifecycle {
                state: record.lifecycle_state,
                activation_mode: record.activation_mode,
                consumer_version: record.consumer_version,
                activated_at: record.activated_at.unwrap_or_default(),
                retired_at: record.retired_at.unwrap_or_default(),
                resource_version: record.resource_version.to_string(),
            }),
            content_digest: record.content_digest,
            created_at: record.created_at,
        })
    }

    pub(in crate::service) async fn managed_network_policy(
        &self,
        auth: Option<&str>,
        stable_id: &str,
    ) -> Result<aos_hub_db::db::NetworkPolicyRecord, RpcError> {
        let record = self
            .db
            .network_policy(stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &record.owner_scope_key,
            Permission::NetworkPolicyManage,
            "network policy",
        )
        .await?;
        Ok(record)
    }

    pub(in crate::service) async fn plan_network_policy_lifecycle(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanNetworkPolicyLifecycleRequest,
        activate: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let boundary = self.managed_network_policy(auth, &req.boundary_id).await?;
        let revision = self
            .db
            .network_policy_revision(&req.boundary_id, req.revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        let expected = parse_resource_version(&req.expected_resource_version, 0)?;
        if expected <= 0 || revision.resource_version != expected {
            return Err(RpcError::FailedPrecondition(
                "boundary revision resource version is required and must be current".to_string(),
            ));
        }
        if activate {
            if !matches!(req.activation_mode.as_str(), "overlap" | "coordinated") {
                return Err(RpcError::invalid(
                    "activationMode must be overlap or coordinated",
                ));
            }
            if revision.lifecycle_state != "staged" || revision.observation_state != "verified" {
                return Err(RpcError::FailedPrecondition(
                    "only a verified staged revision may be activated".to_string(),
                ));
            }
            if req.activation_mode == "overlap" && !req.pin_resolutions.is_empty() {
                return Err(RpcError::invalid(
                    "overlap activation forbids pinResolutions",
                ));
            }
        } else if req.default_for_new_plans
            || !req.activation_mode.is_empty()
            || !req.pin_resolutions.is_empty()
        {
            return Err(RpcError::invalid(
                "retirement forbids activationMode, defaultForNewPlans, and pinResolutions",
            ));
        }
        let default_cas = if activate && req.default_for_new_plans {
            let seal = self
                .db
                .network_policy_default_cas(&req.boundary_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("network policy"))?;
            Some(NetworkPolicyDefaultPlanSeal {
                boundary_resource_version: seal.boundary_resource_version,
                previous_revision: seal.previous_revision,
                previous_resource_version: seal.previous_resource_version,
            })
        } else {
            None
        };
        let coordination_impacts = if activate && req.activation_mode == "coordinated" {
            self.db
                .network_policy_coordination_impacts(&req.boundary_id, req.revision)
                .await
                .map_err(RpcError::internal)?
        } else {
            Vec::new()
        };
        if activate
            && req.activation_mode == "coordinated"
            && !coordination_impacts.is_empty()
            && !req.default_for_new_plans
        {
            return Err(RpcError::invalid(
                "coordinated activation with live consumers must become the default for new plans",
            ));
        }
        let impacted_revisions = coordination_impacts
            .iter()
            .map(|impact| impact.revision)
            .collect::<std::collections::BTreeSet<_>>();
        let mut coordination_revisions = Vec::with_capacity(impacted_revisions.len());
        for old_revision in impacted_revisions.iter().copied() {
            let old = self
                .db
                .network_policy_revision(&req.boundary_id, old_revision)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "live consumer references a missing boundary revision".to_string(),
                    )
                })?;
            if !matches!(old.lifecycle_state.as_str(), "active" | "retiring") {
                return Err(RpcError::FailedPrecondition(
                    "live consumer references an unfenceable boundary revision".to_string(),
                ));
            }
            coordination_revisions.push(aos_hub_db::db::NetworkPolicyCoordinationRevisionSeal {
                revision: old.revision,
                lifecycle_state: old.lifecycle_state,
                resource_version: old.resource_version,
                consumer_version: old.consumer_version,
                content_digest: old.content_digest,
            });
        }
        let coordination_resolutions = if activate && req.activation_mode == "coordinated" {
            self.seal_boundary_pin_resolutions(
                auth,
                &req.boundary_id,
                req.revision,
                &coordination_impacts,
                &req.pin_resolutions,
            )
            .await?
        } else {
            Vec::new()
        };
        let coordination_operation_id = (activate && req.activation_mode == "coordinated")
            .then(|| format!("operation:{}", uuid::Uuid::new_v4().simple()));
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = NetworkPolicyLifecyclePlanInput {
            request: req,
            expected_lifecycle_version: expected,
            expected_consumer_version: revision.consumer_version,
            default_cas,
            coordination_operation_id,
            coordination_impacts,
            coordination_revisions,
            coordination_resolutions,
        };
        let plan_kind = if activate {
            "activate_network_policy_revision"
        } else {
            "retire_network_policy_revision"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &boundary.owner_scope_key,
            &input,
            &idempotency_key,
            {
                let mut effects = vec![format!(
                    "{} network policy '{}' revision {}",
                    if activate {
                        "activate"
                    } else {
                        "advance retirement for"
                    },
                    input.request.boundary_id,
                    input.request.revision
                )];
                if input.coordination_operation_id.is_some() {
                    effects.push(format!(
                        "coordinate {} exact live serving pins through a durable operation",
                        input.coordination_impacts.len()
                    ));
                }
                effects
            },
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_network_policy_lifecycle(
        &self,
        auth: Option<&str>,
        req: pb::ApplyNetworkPolicyLifecycleRequest,
        activate: bool,
    ) -> Result<pb::NetworkPolicyRevisionResponse, RpcError> {
        let plan_kind = if activate {
            "activate_network_policy_revision"
        } else {
            "retire_network_policy_revision"
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
        let (plan, input): (_, NetworkPolicyLifecyclePlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.managed_network_policy(auth, &input.request.boundary_id)
            .await?;
        let claims = self.require_claims(auth)?;
        let record = if activate {
            let default_cas =
                input
                    .default_cas
                    .as_ref()
                    .map(|seal| aos_hub_db::db::NetworkPolicyDefaultCas {
                        boundary_resource_version: seal.boundary_resource_version,
                        previous_revision: seal.previous_revision,
                        previous_resource_version: seal.previous_resource_version,
                    });
            let current_impacts = if input.coordination_operation_id.is_some() {
                self.db
                    .network_policy_coordination_impacts(
                        &input.request.boundary_id,
                        input.request.revision,
                    )
                    .await
                    .map_err(RpcError::internal)?
            } else {
                Vec::new()
            };
            if current_impacts != input.coordination_impacts {
                return Err(RpcError::FailedPrecondition(
                    "network-boundary live consumers changed after planning".to_string(),
                ));
            }
            let current_resolutions = if input.coordination_operation_id.is_some() {
                self.seal_boundary_pin_resolutions(
                    auth,
                    &input.request.boundary_id,
                    input.request.revision,
                    &current_impacts,
                    &input.request.pin_resolutions,
                )
                .await?
            } else {
                Vec::new()
            };
            if current_resolutions != input.coordination_resolutions {
                return Err(RpcError::FailedPrecondition(
                    "network-boundary pin-resolution targets changed after planning".to_string(),
                ));
            }
            for seal in &input.coordination_revisions {
                let current = self
                    .db
                    .network_policy_revision(&input.request.boundary_id, seal.revision)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "coordinated old boundary revision disappeared".to_string(),
                        )
                    })?;
                if current.lifecycle_state != seal.lifecycle_state
                    || current.resource_version != seal.resource_version
                    || current.consumer_version != seal.consumer_version
                    || current.content_digest != seal.content_digest
                {
                    return Err(RpcError::FailedPrecondition(
                        "coordinated old boundary revision changed after planning".to_string(),
                    ));
                }
            }
            self.db
                .activate_network_policy_revision(
                    &input.request.boundary_id,
                    input.request.revision,
                    &input.request.activation_mode,
                    default_cas.as_ref(),
                    input.expected_lifecycle_version,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                    input.coordination_operation_id.as_deref(),
                    &input.coordination_impacts,
                    &input.coordination_revisions,
                    &input.coordination_resolutions,
                )
                .await
        } else {
            self.db
                .retire_network_policy_revision(
                    &input.request.boundary_id,
                    input.request.revision,
                    input.expected_lifecycle_version,
                    input.expected_consumer_version,
                    &claims.owner_kind,
                    Some(claims.owner_id),
                    &claims.sub,
                )
                .await
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let coordination_operation = if let Some(operation_id) = input.coordination_operation_id {
            let operation = self
                .db
                .topology_operation(&operation_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!(
                        "coordinated activation operation disappeared"
                    ))
                })?;
            Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            })
        } else {
            None
        };
        let response = pb::NetworkPolicyRevisionResponse {
            revision: Some(Self::network_policy_revision_message(record)?),
            coordination_operation,
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    pub(in crate::service) async fn plan_network_policy_grant(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.resource_kind != "network_policy"
            || req.resource_generation != 0
            || req.consumer_scope_key.is_empty()
        {
            return Err(RpcError::invalid(
                "resourceKind must be network_policy, resourceGeneration must be zero, and consumerScopeKey is required",
            ));
        }
        let boundary = self
            .db
            .network_policy(&req.resource_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyGrant,
            "network policy",
        )
        .await?;
        self.require_permission(
            &claims,
            Permission::NetworkPolicyGrant,
            &parse_authorization_scope(&req.consumer_scope_key)?,
        )
        .await?;
        let resource = aos_hub_db::db::GrantResource::NetworkPolicy { id: &boundary.id };
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
        } else if let Some(grant) = existing {
            if !req.expected_resource_version.is_empty()
                && parse_resource_version(&req.expected_resource_version, 0)?
                    != grant.resource_version
            {
                return Err(RpcError::FailedPrecondition(
                    "consumer grant resource version is stale".to_string(),
                ));
            }
            if !req.pin_resolutions.is_empty() {
                return Err(RpcError::invalid("grant creation forbids pinResolutions"));
            }
            Vec::new()
        } else {
            if !req.pin_resolutions.is_empty() {
                return Err(RpcError::invalid("grant creation forbids pinResolutions"));
            }
            Vec::new()
        };
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = NetworkPolicyGrantPlanInput {
            request: req,
            owner_scope_key: boundary.owner_scope_key.clone(),
            baseline_grant_resource_version: baseline,
            pin_resolutions,
        };
        let plan_kind = if revoke {
            "revoke_network_policy_scope"
        } else {
            "grant_network_policy_scope"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &boundary.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "{} network policy access for '{}'",
                if revoke { "revoke" } else { "grant" },
                input.request.consumer_scope_key
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_network_policy_grant(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        let plan_kind = if revoke {
            "revoke_network_policy_scope"
        } else {
            "grant_network_policy_scope"
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
        let (plan, input): (_, NetworkPolicyGrantPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let boundary = self
            .db
            .network_policy(&input.request.resource_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &boundary.owner_scope_key,
            Permission::NetworkPolicyGrant,
            "network policy",
        )
        .await?;
        if boundary.owner_scope_key != input.owner_scope_key {
            return Err(RpcError::FailedPrecondition(
                "network policy owner scope changed after planning".to_string(),
            ));
        }
        let resource = aos_hub_db::db::GrantResource::NetworkPolicy { id: &boundary.id };
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::NetworkPolicyGrant,
            &parse_authorization_scope(&input.request.consumer_scope_key)?,
        )
        .await?;
        if revoke && !input.pin_resolutions.is_empty() {
            let record = self
                .db
                .load_consumer_scope_grant(resource, &input.request.consumer_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("network policy consumer grant"))?;
            let coordination_operation = self
                .schedule_grant_revocation(
                    &plan.plan_id,
                    "network_policy",
                    &boundary.id,
                    0,
                    &input.request.consumer_scope_key,
                    input.baseline_grant_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("revoke plan has no grant version"))
                    })?,
                    input.pin_resolutions,
                    &claims.sub,
                    &req.idempotency_key,
                    Permission::NetworkPolicyGrant,
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
}
