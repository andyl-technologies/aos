//! Coordinated direct-delivery destination workflows.
//!
//! Reviewed intent is immutable. Each child plan is persisted before applying
//! its effects, so retries reuse the same authorization and idempotency fence.
//! Preparation creates unadvertised resources; activation reviews and switches
//! all requested audiences atomically against current verification evidence.
//!
//! Persisted intent uses an explicit schema version:
//!
//! ```json
//! {"version":1,"workflow_id":"...","intent":{},"prerequisites":[]}
//! ```

mod preparation;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{clock, pb, Permission, RpcError, RpcService};
use crate::db::{
    DeliveryActivationRoute, DeliveryAudienceBaseline, DeliveryWorkflowRecord, GrantResource,
};

const CREATE_KIND: &str = "delivery_destination";
const ACTIVATE_KIND: &str = "activate_delivery_destination";
const STEPS: &[(&str, &str)] = &[
    ("domain", "Register hostname"),
    ("endpoint", "Connect CDN attachment"),
    ("gateway", "Connect storage"),
    ("enable_gateway", "Verify storage delivery"),
    ("route", "Create delivery URL"),
];

#[derive(Clone, Serialize, Deserialize)]
struct IntentSeal {
    version: u32,
    workflow_id: String,
    intent: pb::DeliveryDestinationIntent,
    actor_kind: String,
    actor_id: i64,
    placement_id: i64,
    placement_resource_version: i64,
    binding_id: i64,
    binding_stable_id: String,
    binding_resource_version: i64,
    origin_prefix: String,
    route_base_path: String,
    canonical_url: String,
    prerequisites: Vec<PrerequisiteSeal>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrerequisiteSeal {
    kind: String,
    stable_id: String,
    resource_version: i64,
    revision: i64,
    content_digest: String,
    lifecycle_state: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Progress {
    plans: BTreeMap<String, pb::TopologyPlan>,
    completed: BTreeSet<String>,
    domain_id: String,
    endpoint_id: String,
    endpoint_generation: i64,
    gateway_id: String,
    route_id: String,
    error: String,
    active: bool,
    activation_plan_id: Option<String>,
    route_identity: Option<DeliveryActivationRoute>,
    operations: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct ActivationSeal {
    workflow_id: String,
    resource_version: i64,
    route: DeliveryActivationRoute,
    audiences: Vec<DeliveryAudienceBaseline>,
}

fn encode<T: Serialize>(value: &T) -> Result<String, RpcError> {
    serde_json::to_string(value).map_err(RpcError::internal)
}

fn decode(record: &DeliveryWorkflowRecord) -> Result<(IntentSeal, Progress), RpcError> {
    let intent: IntentSeal =
        serde_json::from_str(&record.intent_json).map_err(RpcError::internal)?;
    if intent.version != 1 {
        return Err(RpcError::FailedPrecondition(
            "unsupported delivery workflow intent version".into(),
        ));
    }
    Ok((
        intent,
        serde_json::from_str(&record.progress_json).map_err(RpcError::internal)?,
    ))
}

fn digest<T: Serialize>(value: &T) -> Result<String, RpcError> {
    Ok(hex::encode(Sha256::digest(encode(value)?.as_bytes())))
}

impl RpcService {
    /// Plans a direct CDN destination using existing storage and explicit grants.
    ///
    /// # Errors
    /// Returns an error for missing permissions, invalid intent, unavailable
    /// prerequisites, conflicting idempotency, or persistence failure.
    pub async fn plan_delivery_destination(
        &self,
        auth: Option<&str>,
        req: pb::PlanDeliveryDestinationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        super::require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        let mut intent = req
            .intent
            .ok_or_else(|| RpcError::invalid("intent is required"))?;
        intent.client_base_path = Self::normalize_route_base_path(&intent.client_base_path)?;
        intent.audiences.sort();
        intent.audiences.dedup();
        if let Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) =
            intent.endpoint.as_mut()
        {
            if let Some(pb::delivery_endpoint_input::HostnameSource::Hostname(hostname)) =
                input.hostname_source.as_mut()
            {
                *hostname = crate::db::canonical_delivery_hostname(hostname)
                    .map_err(|error| RpcError::invalid(format!("hostname: {error:#}")))?;
            }
        }
        let (surface, scope) = self
            .managed_route_surface(auth, intent.surface.clone())
            .await?;
        if intent.owner_scope_key != scope {
            return Err(RpcError::invalid(
                "destination owner must match the surface owner",
            ));
        }
        self.require_delivery_scope(auth, &scope, Permission::GatewayManage)
            .await?;
        self.require_delivery_scope(auth, &scope, Permission::BindingRead)
            .await?;
        let capabilities = intent
            .capabilities
            .as_ref()
            .ok_or_else(|| RpcError::invalid("capabilities are required"))?;
        if intent.audiences.is_empty()
            || intent
                .audiences
                .iter()
                .any(|audience| match audience.as_str() {
                    "git" => !capabilities.serves_git,
                    "nix_cache" => !capabilities.serves_cache,
                    "web" => !capabilities.serves_web,
                    _ => true,
                })
        {
            return Err(RpcError::invalid(
                "audiences must be supported by the requested capabilities",
            ));
        }
        let policy = intent
            .access_policy
            .clone()
            .ok_or_else(|| RpcError::invalid("accessPolicy is required"))?;
        Self::route_access_policy_fields(policy.clone())?;
        if matches!(
            policy.policy,
            Some(pb::delivery_access_policy::Policy::HubAuth(_))
        ) {
            return Err(RpcError::invalid(
                "direct CDN destinations cannot use Hub authentication",
            ));
        }
        if let Some((plan, seal)) = self
            .replayed_control_plan_input::<IntentSeal>(&claims, CREATE_KIND, &req.idempotency_key)
            .await?
        {
            if seal.intent != intent {
                return Err(RpcError::invalid(
                    "idempotency key has different destination intent",
                ));
            }
            return Self::control_plan_response(plan);
        }
        let placement = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|p| p.name == intent.placement_name)
            .ok_or_else(|| RpcError::not_found("surface placement"))?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("storage binding"))?;
        let route_base_path =
            crate::db::join_route_segments(&intent.client_base_path, &placement.prefix)
                .map_err(|error| RpcError::invalid(format!("delivery path: {error:#}")))?;
        self.require_workflow_grant(
            GrantResource::Binding {
                id: binding.id,
                stable_id: &binding.stable_id,
            },
            &scope,
        )
        .await?;
        let canonical_url = match intent.endpoint.as_mut() {
            Some(pb::delivery_destination_intent::Endpoint::ExistingEndpoint(reference)) => {
                self.require_delivery_scope(auth, &scope, Permission::EndpointRead)
                    .await?;
                self.require_workflow_grant(
                    GrantResource::Endpoint {
                        id: &reference.endpoint_id,
                        generation: reference.generation,
                    },
                    &scope,
                )
                .await?;
                let endpoint = self
                    .db
                    .endpoint(&reference.endpoint_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("endpoint"))?;
                let revision = self
                    .db
                    .endpoint_revision(&reference.endpoint_id, reference.generation)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
                if !matches!(revision.spec.ingress_kind.as_str(), "external" | "layer7") {
                    return Err(RpcError::invalid(
                        "CDN endpoint must use external or layer7 ingress",
                    ));
                }
                self.rendered_route_url(&endpoint, &route_base_path).await?
            }
            Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) => {
                self.require_delivery_scope(auth, &scope, Permission::EndpointManage)
                    .await?;
                // Verification records domain observations as well as the new
                // endpoint's listener and TLS evidence, including reused domains.
                self.require_delivery_scope(auth, &scope, Permission::DomainManage)
                    .await?;
                let revision = Self::endpoint_revision_spec(input.revision.clone())?;
                crate::db::validate_endpoint_revision_spec(&revision).map_err(|error| {
                    RpcError::invalid(format!("invalid endpoint revision: {error:#}"))
                })?;
                if revision.tls_configuration == "{}" {
                    return Err(RpcError::invalid(
                        "HTTPS CDN endpoints require TLS configuration",
                    ));
                }
                if !matches!(revision.ingress_kind.as_str(), "external" | "layer7") {
                    return Err(RpcError::invalid(
                        "CDN endpoint must use external or layer7 ingress",
                    ));
                }
                self.require_workflow_grant(
                    GrantResource::NetworkPolicy {
                        id: &input.network_policy_id,
                    },
                    &scope,
                )
                .await?;
                let hostname = match input.hostname_source.as_mut() {
                    Some(pb::delivery_endpoint_input::HostnameSource::Hostname(hostname)) => {
                        *hostname = crate::db::canonical_delivery_hostname(hostname)
                            .map_err(|error| RpcError::invalid(error.to_string()))?;
                        if self
                            .db
                            .delivery_domain_by_hostname(hostname)
                            .await
                            .map_err(RpcError::internal)?
                            .is_some()
                        {
                            return Err(RpcError::AlreadyExists(
                                "hostname already exists; select its domain".into(),
                            ));
                        }
                        hostname.clone()
                    }
                    Some(pb::delivery_endpoint_input::HostnameSource::DomainId(id)) => {
                        let domain = self
                            .get_domain(
                                auth,
                                pb::GetTopologyResourceRequest {
                                    stable_id: id.clone(),
                                },
                            )
                            .await?
                            .domain
                            .ok_or_else(|| RpcError::not_found("domain"))?;
                        if domain.owner_scope_key != scope {
                            return Err(RpcError::invalid(
                                "new endpoint domain must belong to its owner scope",
                            ));
                        }
                        domain.hostname
                    }
                    None => return Err(RpcError::invalid("hostname or domainId is required")),
                };
                format!("https://{hostname}{route_base_path}")
            }
            None => {
                return Err(RpcError::invalid(
                    "existingEndpoint or newEndpoint is required",
                ))
            }
        };
        let prerequisites = self.delivery_prerequisites(&intent).await?;
        let seal = IntentSeal {
            version: 1,
            workflow_id: uuid::Uuid::new_v4().to_string(),
            intent,
            actor_kind: claims.owner_kind.clone(),
            actor_id: claims.owner_id,
            placement_id: placement.id,
            placement_resource_version: placement.resource_version,
            binding_id: binding.id,
            binding_stable_id: binding.stable_id,
            binding_resource_version: binding.resource_version,
            origin_prefix: crate::db::join_route_segments(
                "",
                binding.object_prefix.as_deref().unwrap_or_default(),
            )
            .map_err(|error| RpcError::invalid(format!("storage origin prefix: {error:#}")))?,
            route_base_path,
            canonical_url,
            prerequisites,
        };
        self.create_control_plan(&claims, CREATE_KIND, &scope, &seal, &req.idempotency_key,
            vec![format!("prepare CDN delivery at {}", seal.canonical_url),
                 format!("connect existing placement '{}' and create gateway and route", seal.intent.placement_name),
                 format!("verify delivery before separately activating audiences: {}", seal.intent.audiences.join(", "))],
            vec!["The provider attachment must already exist; complete its configuration and verification before activation.".into()], Some(digest(&seal)?)).await
    }

    async fn require_workflow_grant(
        &self,
        resource: GrantResource<'_>,
        scope: &str,
    ) -> Result<(), RpcError> {
        let grant = self
            .db
            .load_consumer_scope_grant(resource, scope)
            .await
            .map_err(RpcError::internal)?;
        if !grant.is_some_and(|grant| grant.state == "active") {
            return Err(RpcError::FailedPrecondition(
                format!("an active grant for {resource:?} to consumer scope '{scope}' is required; ask the resource owner to grant access"),
            ));
        }
        Ok(())
    }

    async fn delivery_prerequisites(
        &self,
        intent: &pb::DeliveryDestinationIntent,
    ) -> Result<Vec<PrerequisiteSeal>, RpcError> {
        let mut result = Vec::new();
        let mut policies = BTreeSet::new();
        match intent.endpoint.as_ref() {
            Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) => {
                let revision = input
                    .revision
                    .as_ref()
                    .ok_or_else(|| RpcError::invalid("endpoint revision is required"))?;
                policies.insert((input.network_policy_id.clone(), revision.boundary_revision));
                if let Some(pb::delivery_endpoint_input::HostnameSource::DomainId(id)) =
                    &input.hostname_source
                {
                    let domain = self
                        .db
                        .delivery_domain(id)
                        .await
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found("domain prerequisite"))?;
                    result.push(PrerequisiteSeal {
                        kind: "domain".into(),
                        stable_id: id.clone(),
                        // Domain observations share the row's CAS counter. Seal
                        // desired configuration so successful verification does
                        // not invalidate the workflow it is meant to advance.
                        resource_version: 0,
                        revision: 0,
                        content_digest: digest(&(
                            domain.hostname,
                            domain.dns_configuration_json,
                            domain.certificate_configuration_json,
                        ))?,
                        lifecycle_state: String::new(),
                    });
                }
            }
            Some(pb::delivery_destination_intent::Endpoint::ExistingEndpoint(reference)) => {
                let endpoint = self
                    .db
                    .endpoint(&reference.endpoint_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("endpoint prerequisite"))?;
                let revision = self
                    .db
                    .endpoint_revision(&reference.endpoint_id, reference.generation)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("endpoint generation prerequisite"))?;
                policies.insert((endpoint.network_policy_id, revision.spec.boundary_revision));
            }
            None => return Err(RpcError::invalid("endpoint prerequisite is required")),
        }
        if let Some(pb::delivery_access_policy::Policy::PrivateNetwork(policy)) = intent
            .access_policy
            .as_ref()
            .and_then(|policy| policy.policy.as_ref())
        {
            self.require_workflow_grant(
                GrantResource::NetworkPolicy {
                    id: &policy.boundary_id,
                },
                &intent.owner_scope_key,
            )
            .await?;
            policies.insert((policy.boundary_id.clone(), policy.boundary_revision));
        }
        for (id, revision) in policies {
            let policy = self
                .db
                .network_policy(&id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("network policy prerequisite"))?;
            let generation = self
                .db
                .network_policy_revision(&id, revision)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("network policy revision prerequisite"))?;
            if generation.lifecycle_state != "active" {
                return Err(RpcError::FailedPrecondition(format!(
                    "network policy '{id}' revision {revision} must be active"
                )));
            }
            result.push(PrerequisiteSeal {
                kind: "network_policy".into(),
                stable_id: id,
                resource_version: policy.resource_version,
                revision,
                content_digest: generation.content_digest,
                lifecycle_state: generation.lifecycle_state,
            });
        }
        Ok(result)
    }

    async fn check_delivery_prerequisites(&self, seal: &IntentSeal) -> Result<(), RpcError> {
        if self.delivery_prerequisites(&seal.intent).await? != seal.prerequisites {
            return Err(RpcError::FailedPrecondition("domain or network policy prerequisites changed after review; create a new destination plan".into()));
        }
        Ok(())
    }

    async fn authorized_delivery_workflow(
        &self,
        auth: Option<&str>,
        id: &str,
        manage: bool,
    ) -> Result<DeliveryWorkflowRecord, RpcError> {
        let record = self
            .db
            .delivery_workflow(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("delivery workflow"))?;
        self.require_cloaked_delivery_scope(
            auth,
            &record.owner_scope_key,
            if manage {
                Permission::RouteManage
            } else {
                Permission::RouteRead
            },
            "delivery workflow",
        )
        .await?;
        if manage {
            let (seal, _) = decode(&record)?;
            let claims = self.require_claims(auth)?;
            if claims.owner_kind != seal.actor_kind || claims.owner_id != seal.actor_id {
                return Err(RpcError::FailedPrecondition(
                    "resume this workflow as the operator who reviewed its intent".into(),
                ));
            }
        }
        Ok(record)
    }

    /// Persists and begins a reviewed destination workflow.
    ///
    /// # Errors
    /// Returns an error for invalid confirmation, permissions, stale prerequisites,
    /// conflicting idempotency, or persistence failure.
    pub async fn apply_delivery_destination(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeliveryDestinationRequest,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result::<pb::DeliveryWorkflowResponse>(
                auth,
                &req.plan_id,
                CREATE_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            let id = response
                .workflow
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("workflow replay is missing")))?
                .workflow_id;
            return self
                .get_delivery_workflow(auth, pb::GetDeliveryWorkflowRequest { workflow_id: id })
                .await;
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            CREATE_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, seal): (_, IntentSeal) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                CREATE_KIND,
                Some(&req.confirmation_hash),
            )
            .await?;
        let (surface, scope) = self
            .managed_route_surface(auth, seal.intent.surface.clone())
            .await?;
        let mut progress = Progress {
            endpoint_id: format!("endpoint:delivery:{}", seal.workflow_id),
            endpoint_generation: 1,
            gateway_id: format!("gateway:delivery:{}", seal.workflow_id),
            route_id: format!("route:delivery:{}", seal.workflow_id),
            ..Default::default()
        };
        match seal.intent.endpoint.as_ref() {
            Some(pb::delivery_destination_intent::Endpoint::ExistingEndpoint(reference)) => {
                progress.endpoint_id = reference.endpoint_id.clone();
                progress.endpoint_generation = reference.generation;
                progress
                    .completed
                    .extend(["domain".into(), "endpoint".into()]);
            }
            Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) => {
                if let Some(pb::delivery_endpoint_input::HostnameSource::DomainId(id)) =
                    &input.hostname_source
                {
                    progress.domain_id = id.clone();
                    progress.completed.insert("domain".into());
                }
            }
            None => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "workflow intent has no endpoint"
                )))
            }
        }
        let record = self
            .db
            .create_delivery_workflow(
                &seal.workflow_id,
                &scope,
                surface,
                &encode(&seal)?,
                &encode(&progress)?,
            )
            .await
            .map_err(RpcError::internal)?;
        let initial = self.delivery_workflow_response(record.clone()).await?;
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &initial)
            .await?;
        self.run_delivery_workflow(auth, record, &req.idempotency_key)
            .await
    }

    /// Returns persisted progress and current verification blockers.
    ///
    /// # Errors
    /// Returns an error for unauthorized access, missing workflow, or persistence failure.
    pub async fn get_delivery_workflow(
        &self,
        auth: Option<&str>,
        req: pb::GetDeliveryWorkflowRequest,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        let record = self
            .authorized_delivery_workflow(auth, &req.workflow_id, false)
            .await?;
        self.delivery_workflow_response(record).await
    }

    /// Lists resumable workflows on an authorized surface.
    ///
    /// # Errors
    /// Returns an error for unauthorized access, invalid surface, or persistence failure.
    pub async fn list_delivery_workflows(
        &self,
        auth: Option<&str>,
        req: pb::ListDeliveryWorkflowsRequest,
    ) -> Result<pb::ListDeliveryWorkflowsResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let scope = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &scope, Permission::RouteRead)
            .await?;
        let page = self
            .db
            .list_delivery_workflows(surface, req.page_size, &req.page_token)
            .await
            .map_err(RpcError::internal)?;
        let mut workflows = Vec::with_capacity(page.records.len());
        for record in page.records {
            if let Some(workflow) = self.delivery_workflow_response(record).await?.workflow {
                workflows.push(workflow);
            }
        }
        Ok(pb::ListDeliveryWorkflowsResponse {
            workflows,
            next_page_token: page.next_cursor.unwrap_or_default(),
        })
    }

    /// Resumes preparation or rechecks the current destination evidence.
    ///
    /// # Errors
    /// Returns an error for unauthorized access, stale workflow version, missing
    /// idempotency key, or persistence failure.
    pub async fn resume_delivery_destination(
        &self,
        auth: Option<&str>,
        req: pb::ResumeDeliveryDestinationRequest,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        if req.idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let record = self
            .authorized_delivery_workflow(auth, &req.workflow_id, true)
            .await?;
        let claims = self.require_claims(auth)?;
        let expected = req
            .expected_resource_version
            .parse::<i64>()
            .map_err(|_| RpcError::invalid("expectedResourceVersion must be a positive version"))?;
        let completed = self
            .db
            .begin_delivery_resumption(
                &claims.owner_kind,
                claims.owner_id,
                &req.idempotency_key,
                &req.workflow_id,
                expected,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        if completed {
            return self.delivery_workflow_response(record).await;
        }
        let outcome = self
            .run_delivery_workflow(auth, record, &req.idempotency_key)
            .await;
        if matches!(&outcome, Err(RpcError::FailedPrecondition(message)) if message == "workflow changed; reload before resuming")
        {
            // Another retry won a progress CAS. Report its durable progress
            // without completing the still-running request on its behalf.
            return self
                .get_delivery_workflow(
                    auth,
                    pb::GetDeliveryWorkflowRequest {
                        workflow_id: req.workflow_id,
                    },
                )
                .await;
        }
        let response = outcome?;
        self.db
            .complete_delivery_resumption(&claims.owner_kind, claims.owner_id, &req.idempotency_key)
            .await
            .map_err(RpcError::internal)?;
        Ok(response)
    }

    async fn workflow_activation_route(
        &self,
        progress: &Progress,
    ) -> Result<DeliveryActivationRoute, RpcError> {
        let route = self
            .db
            .route(&progress.route_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("delivery route"))?;
        if let Some(expected) = &progress.route_identity {
            if route.configuration_generation != Some(expected.generation)
                || route.configuration_digest.as_deref() != Some(expected.digest.as_str())
                || route.resource_version != expected.resource_version
            {
                return Err(RpcError::FailedPrecondition(
                    "delivery route changed outside this workflow; create a new destination plan"
                        .into(),
                ));
            }
        }
        Ok(DeliveryActivationRoute {
            route_id: route.id,
            generation: route
                .configuration_generation
                .ok_or_else(|| RpcError::FailedPrecondition("route has no configuration".into()))?,
            digest: route.configuration_digest.ok_or_else(|| {
                RpcError::FailedPrecondition("route has no configuration digest".into())
            })?,
            resource_version: route.resource_version,
        })
    }

    async fn delivery_workflow_response(
        &self,
        record: DeliveryWorkflowRecord,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        let (seal, progress) = decode(&record)?;
        let mut drift = None;
        let ready = if progress.completed.contains("route") {
            match self.workflow_activation_route(&progress).await {
                Ok(route) => self
                    .db
                    .delivery_workflow_route_ready(&route)
                    .await
                    .map_err(RpcError::internal)?,
                Err(error @ (RpcError::NotFound(_) | RpcError::FailedPrecondition(_))) => {
                    drift = Some(error.to_string());
                    false
                }
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        let state = if progress.active {
            "active"
        } else if !progress.error.is_empty() || drift.is_some() {
            "blocked"
        } else if ready {
            "ready"
        } else if progress.completed.contains("route") {
            "awaiting_verification"
        } else {
            "preparing"
        };
        let mut blockers = Vec::new();
        if let Some(error) = &drift {
            blockers.push(error.clone());
        }
        if !progress.error.is_empty() && !progress.active {
            blockers.push(progress.error.clone());
        }
        if !ready && !progress.active {
            blockers.push("The CDN attachment, gateway, current storage publication, and delivery route must pass verification.".into());
        }
        let mut next_actions = if drift.is_some() {
            vec!["Inspect the changed resources and create a new destination plan.".into()]
        } else {
            match state {
                "active" => Vec::new(),
                "ready" => vec!["Review and activate the verified destination.".into()],
                _ => vec![
                    "Complete the provider attachment configuration and resume verification."
                        .into(),
                ],
            }
        };
        if !ready && !progress.active {
            if let Some(pb::delivery_destination_intent::Endpoint::ExistingEndpoint(reference)) =
                &seal.intent.endpoint
            {
                let observed = self
                    .db
                    .endpoint_observation(&reference.endpoint_id)
                    .await
                    .map_err(RpcError::internal)?;
                if !observed.is_some_and(|observed| {
                    observed.observed_generation == Some(reference.generation)
                        && observed.state == "healthy"
                        && observed.listener_observed
                        && observed.tls_observed
                }) {
                    blockers.push(format!(
                        "Endpoint '{}' generation {} requires owner verification.",
                        reference.endpoint_id, reference.generation,
                    ));
                    next_actions.push(
                        "Ask the endpoint owner to verify its HTTPS domain, or have its ingress controller report the exact endpoint generation when domain verification is unavailable."
                            .into(),
                    );
                }
            }
        }
        let mut operations = BTreeMap::new();
        for (step, operation_id) in &progress.operations {
            if let Some(operation) = self
                .db
                .topology_operation(operation_id)
                .await
                .map_err(RpcError::internal)?
            {
                operations.insert(
                    step.as_str(),
                    pb::OperationRef {
                        operation_id: operation.operation_id,
                        kind: operation.operation_kind,
                        state: operation.state,
                        created_at: operation.created_at,
                    },
                );
            }
        }
        let steps = STEPS
            .iter()
            .map(|(key, label)| pb::DeliveryWorkflowStep {
                key: (*key).into(),
                label: (*label).into(),
                state: if progress.completed.contains(*key) {
                    "complete"
                } else {
                    "pending"
                }
                .into(),
                detail: if !progress.completed.contains(*key) {
                    progress.error.clone()
                } else {
                    String::new()
                },
                resource_id: match *key {
                    "domain" => &progress.domain_id,
                    "endpoint" => &progress.endpoint_id,
                    "gateway" | "enable_gateway" => &progress.gateway_id,
                    _ => &progress.route_id,
                }
                .clone(),
                operation: operations.get(key).cloned(),
            })
            .chain(std::iter::once(pb::DeliveryWorkflowStep {
                key: "verification".into(),
                label: "Verify delivery".into(),
                state: if ready { "complete" } else { "pending" }.into(),
                detail: String::new(),
                resource_id: progress.route_id.clone(),
                operation: operations.get("verification").cloned(),
            }))
            .chain(std::iter::once(pb::DeliveryWorkflowStep {
                key: "activation".into(),
                label: "Activate destination".into(),
                state: if progress.active {
                    "complete"
                } else {
                    "pending"
                }
                .into(),
                detail: String::new(),
                resource_id: progress.route_id.clone(),
                operation: None,
            }))
            .collect();
        Ok(pb::DeliveryWorkflowResponse {
            workflow: Some(pb::DeliveryWorkflow {
                workflow_id: record.workflow_id,
                intent: Some(seal.intent),
                state: state.into(),
                steps,
                blockers,
                next_actions,
                domain_id: progress.domain_id,
                endpoint_id: progress.endpoint_id,
                endpoint_generation: progress.endpoint_generation,
                gateway_id: progress.gateway_id,
                route_id: progress.route_id,
                canonical_url: seal.canonical_url,
                resource_version: record.resource_version.to_string(),
                created_at: record.created_at,
                updated_at: record.updated_at,
            }),
        })
    }

    /// Plans an atomic switch of all audiences to the verified destination.
    ///
    /// # Errors
    /// Returns an error for missing authority, incomplete verification, changed
    /// workflow or route, conflicting idempotency, or persistence failure.
    pub async fn plan_activate_delivery_destination(
        &self,
        auth: Option<&str>,
        req: pb::PlanActivateDeliveryDestinationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let record = self
            .authorized_delivery_workflow(auth, &req.workflow_id, true)
            .await?;
        if req.expected_resource_version != record.resource_version.to_string() {
            return Err(RpcError::FailedPrecondition(
                "workflow changed; reload before activation".into(),
            ));
        }
        let (intent, progress) = decode(&record)?;
        self.check_delivery_prerequisites(&intent).await?;
        if progress.active || !progress.completed.contains("route") || !progress.error.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "destination preparation must complete before activation".into(),
            ));
        }
        let route = self.workflow_activation_route(&progress).await?;
        if !self
            .db
            .delivery_workflow_route_ready(&route)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "destination requires current verified delivery evidence".into(),
            ));
        }
        let mut audiences = Vec::with_capacity(intent.intent.audiences.len());
        let mut effects = Vec::with_capacity(intent.intent.audiences.len());
        for audience in &intent.intent.audiences {
            let baseline = self
                .db
                .route_advertisement(record.surface, audience)
                .await
                .map_err(RpcError::internal)?;
            effects.push(format!(
                "select {} for {audience} (previous route: {})",
                intent.canonical_url,
                baseline
                    .as_ref()
                    .map(|value| value.route_id.as_str())
                    .unwrap_or("none")
            ));
            audiences.push(DeliveryAudienceBaseline {
                audience: audience.clone(),
                resource_version: baseline.map(|value| value.resource_version),
            });
        }
        let seal = ActivationSeal {
            workflow_id: record.workflow_id,
            resource_version: record.resource_version,
            route,
            audiences,
        };
        self.create_control_plan(&claims, ACTIVATE_KIND, &record.owner_scope_key, &seal, &req.idempotency_key, effects,
            vec!["All selected audiences switch together only while the reviewed route and its verification remain current.".into()], Some(digest(&seal)?)).await
    }

    /// Atomically activates a reviewed and still verified delivery destination.
    ///
    /// # Errors
    /// Returns an error for invalid confirmation, missing authority, changed
    /// verification or audience baselines, conflicting idempotency, or database failure.
    pub async fn activate_delivery_destination(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeliveryDestinationRequest,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result::<pb::DeliveryWorkflowResponse>(
                auth,
                &req.plan_id,
                ACTIVATE_KIND,
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            let id = response
                .workflow
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("workflow replay missing")))?
                .workflow_id;
            return self
                .get_delivery_workflow(auth, pb::GetDeliveryWorkflowRequest { workflow_id: id })
                .await;
        }
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            ACTIVATE_KIND,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, seal): (_, ActivationSeal) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                ACTIVATE_KIND,
                Some(&req.confirmation_hash),
            )
            .await?;
        let record = self
            .authorized_delivery_workflow(auth, &seal.workflow_id, true)
            .await?;
        let (intent, mut progress) = decode(&record)?;
        if progress.activation_plan_id.as_deref() != Some(req.plan_id.as_str()) {
            self.check_delivery_prerequisites(&intent).await?;
            if progress.active || record.resource_version != seal.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "workflow changed since activation review".into(),
                ));
            }
            progress.active = true;
            progress.activation_plan_id = Some(req.plan_id.clone());
            self.db
                .activate_delivery_workflow(
                    &record,
                    &seal.route,
                    &seal.audiences,
                    &encode(&progress)?,
                )
                .await
                .map_err(|error| {
                    RpcError::FailedPrecondition(format!(
                        "activation changed or verification is no longer current: {error:#}"
                    ))
                })?;
        }
        let response = self
            .get_delivery_workflow(
                auth,
                pb::GetDeliveryWorkflowRequest {
                    workflow_id: seal.workflow_id,
                },
            )
            .await?;
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
