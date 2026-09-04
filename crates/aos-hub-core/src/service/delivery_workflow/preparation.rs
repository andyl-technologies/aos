//! Resumable preparation steps and verification scheduling for CDN destinations.
//!
//! Each child plan is saved before apply; completed steps retain their identities.

use super::*;

impl RpcService {
    async fn save_delivery_progress(
        &self,
        record: &mut DeliveryWorkflowRecord,
        progress: &Progress,
    ) -> Result<(), RpcError> {
        *record = self
            .db
            .update_delivery_workflow(
                &record.workflow_id,
                record.resource_version,
                &encode(progress)?,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(error.to_string()))?;
        Ok(())
    }

    pub(super) async fn run_delivery_workflow(
        &self,
        auth: Option<&str>,
        mut record: DeliveryWorkflowRecord,
        request_key: &str,
    ) -> Result<pb::DeliveryWorkflowResponse, RpcError> {
        let (seal, mut progress) = decode(&record)?;
        if progress.active {
            return self.delivery_workflow_response(record).await;
        }
        if let Err(error) = self.check_delivery_prerequisites(&seal).await {
            progress.error = error.to_string();
            self.save_delivery_progress(&mut record, &progress).await?;
            return self.delivery_workflow_response(record).await;
        }
        // Recheck authority on every resumed operation; the reviewed intent does
        // not keep a revoked role or prerequisite grant alive.
        self.require_delivery_scope(auth, &record.owner_scope_key, Permission::GatewayManage)
            .await?;
        self.require_delivery_scope(auth, &record.owner_scope_key, Permission::BindingRead)
            .await?;
        if matches!(
            seal.intent.endpoint,
            Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(_))
        ) {
            self.require_delivery_scope(auth, &record.owner_scope_key, Permission::EndpointManage)
                .await?;
        }
        self.require_workflow_grant(
            GrantResource::Binding {
                id: seal.binding_id,
                stable_id: &seal.binding_stable_id,
            },
            &record.owner_scope_key,
        )
        .await?;
        let placement = self
            .db
            .surface_placement(seal.placement_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("placement"))?;
        let binding = self
            .db
            .binding(seal.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        if placement.resource_version != seal.placement_resource_version
            || binding.resource_version != seal.binding_resource_version
        {
            progress.error =
                "Storage configuration changed after review; create a new destination plan.".into();
            self.save_delivery_progress(&mut record, &progress).await?;
            return self.delivery_workflow_response(record).await;
        }
        progress.error.clear();
        for (step, _) in STEPS {
            if progress.completed.contains(*step) {
                continue;
            }
            let result = self
                .run_delivery_step(auth, &mut record, &seal, &mut progress, step)
                .await;
            match result {
                Ok(()) => {
                    progress.completed.insert((*step).into());
                }
                Err(error) => {
                    progress.error = format!(
                        "{}: {}",
                        STEPS
                            .iter()
                            .find(|(key, _)| key == step)
                            .map(|(_, label)| *label)
                            .unwrap_or(step),
                        error
                    );
                    self.save_delivery_progress(&mut record, &progress).await?;
                    self.schedule_delivery_verification(&seal, &mut progress, request_key)
                        .await?;
                    self.save_delivery_progress(&mut record, &progress).await?;
                    return self.delivery_workflow_response(record).await;
                }
            }
            self.save_delivery_progress(&mut record, &progress).await?;
        }
        self.schedule_delivery_verification(&seal, &mut progress, request_key)
            .await?;
        self.save_delivery_progress(&mut record, &progress).await?;
        self.delivery_workflow_response(record).await
    }

    async fn run_delivery_step(
        &self,
        auth: Option<&str>,
        record: &mut DeliveryWorkflowRecord,
        seal: &IntentSeal,
        progress: &mut Progress,
        step: &str,
    ) -> Result<(), RpcError> {
        // An unstarted expired child plan can be replaced. Once apply begins,
        // its persisted result/reservation must be replayed even after expiry.
        let existing = if let Some(plan) = progress.plans.get(step) {
            let stored = self
                .db
                .topology_plan(&plan.plan_id)
                .await
                .map_err(RpcError::internal)?;
            stored
                .filter(|stored| {
                    stored.expires_at >= clock::now_unix_secs()
                        || stored.apply_idempotency_key.is_some()
                })
                .map(|_| plan.clone())
        } else {
            None
        };
        let plan = match existing {
            Some(plan) => plan,
            None => {
                let key = format!(
                    "delivery:{}:{step}:{}",
                    seal.workflow_id,
                    uuid::Uuid::new_v4()
                );
                let response = self
                    .plan_delivery_step(auth, seal, progress, step, key)
                    .await?;
                let plan = response
                    .plan
                    .ok_or_else(|| RpcError::internal(anyhow::anyhow!("child plan is missing")))?;
                progress.plans.insert(step.into(), plan.clone());
                self.save_delivery_progress(record, progress).await?;
                plan
            }
        };
        let apply_key = format!("delivery:{}:{step}:{}", seal.workflow_id, plan.plan_id);
        match step {
            "domain" => {
                let response = self
                    .create_domain(
                        auth,
                        pb::ApplyDomainMutationRequest {
                            plan_id: plan.plan_id,
                            confirmation_hash: plan.confirmation_hash,
                            idempotency_key: apply_key,
                        },
                    )
                    .await?;
                progress.domain_id = response
                    .domain
                    .ok_or_else(|| RpcError::internal(anyhow::anyhow!("created domain missing")))?
                    .stable_id;
            }
            "endpoint" => {
                self.apply_create_endpoint(
                    auth,
                    pb::ApplyEndpointMutationRequest {
                        plan_id: plan.plan_id,
                        confirmation_hash: plan.confirmation_hash,
                        idempotency_key: apply_key,
                    },
                )
                .await?;
            }
            "gateway" => {
                self.create_gateway(
                    auth,
                    pb::ApplyGatewayMutationRequest {
                        plan_id: plan.plan_id,
                        confirmation_hash: plan.confirmation_hash,
                        idempotency_key: apply_key,
                    },
                )
                .await?;
            }
            "enable_gateway" => {
                self.enable_gateway(
                    auth,
                    pb::ApplyDeleteTopologyResourceRequest {
                        plan_id: plan.plan_id,
                        confirmation_hash: plan.confirmation_hash,
                        idempotency_key: apply_key,
                    },
                )
                .await?;
            }
            "route" => {
                let route = self
                    .create_route(
                        auth,
                        pb::ApplyRouteMutationRequest {
                            plan_id: plan.plan_id,
                            confirmation_hash: plan.confirmation_hash,
                            idempotency_key: apply_key,
                        },
                    )
                    .await?
                    .route
                    .ok_or_else(|| RpcError::internal(anyhow::anyhow!("created route missing")))?;
                progress.route_identity = Some(DeliveryActivationRoute {
                    route_id: route.stable_id,
                    generation: route.configuration_generation,
                    digest: route.configuration_digest,
                    resource_version: route.resource_version.parse().map_err(RpcError::internal)?,
                });
            }
            _ => return Err(RpcError::internal(anyhow::anyhow!("unknown delivery step"))),
        }
        Ok(())
    }

    async fn plan_delivery_step(
        &self,
        auth: Option<&str>,
        seal: &IntentSeal,
        progress: &Progress,
        step: &str,
        key: String,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let intent = &seal.intent;
        match step {
            "domain" => {
                let Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) =
                    &intent.endpoint
                else {
                    return Err(RpcError::internal(anyhow::anyhow!("missing new endpoint")));
                };
                let Some(pb::delivery_endpoint_input::HostnameSource::Hostname(hostname)) =
                    &input.hostname_source
                else {
                    return Err(RpcError::internal(anyhow::anyhow!("missing new hostname")));
                };
                self.plan_create_domain(
                    auth,
                    pb::PlanDomainMutationRequest {
                        owner_scope_key: intent.owner_scope_key.clone(),
                        hostname: hostname.clone(),
                        idempotency_key: key,
                        ..Default::default()
                    },
                )
                .await
            }
            "endpoint" => {
                let Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) =
                    &intent.endpoint
                else {
                    return Err(RpcError::internal(anyhow::anyhow!("missing new endpoint")));
                };
                self.plan_create_endpoint(
                    auth,
                    pb::PlanEndpointMutationRequest {
                        stable_id: progress.endpoint_id.clone(),
                        owner_scope_key: intent.owner_scope_key.clone(),
                        scheme: "https".into(),
                        host: Some(pb::EndpointHost {
                            host: Some(pb::endpoint_host::Host::DomainId(
                                progress.domain_id.clone(),
                            )),
                        }),
                        effective_port: 443,
                        network_policy_id: input.network_policy_id.clone(),
                        revision: input.revision.clone(),
                        idempotency_key: key,
                        ..Default::default()
                    },
                )
                .await
            }
            "gateway" => {
                self.plan_create_gateway(
                    auth,
                    pb::PlanGatewayMutationRequest {
                        stable_id: progress.gateway_id.clone(),
                        owner_scope_key: intent.owner_scope_key.clone(),
                        revision: Some(pb::GatewayRevisionSpec {
                            binding_id: seal.binding_stable_id.clone(),
                            endpoint_id: progress.endpoint_id.clone(),
                            endpoint_generation: progress.endpoint_generation,
                            client_base_path: intent.client_base_path.clone(),
                            origin_prefix: seal.origin_prefix.clone(),
                            access_policy: intent.access_policy.clone(),
                        }),
                        idempotency_key: key,
                        ..Default::default()
                    },
                )
                .await
            }
            "enable_gateway" => {
                let gateway = self
                    .db
                    .gateway(&progress.gateway_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("gateway"))?;
                self.plan_enable_gateway(
                    auth,
                    pb::PlanDeleteTopologyResourceRequest {
                        stable_id: progress.gateway_id.clone(),
                        expected_resource_version: Some(gateway.resource_version.to_string()),
                        idempotency_key: key,
                    },
                )
                .await
            }
            "route" => {
                self.plan_create_route(
                    auth,
                    pb::PlanRouteMutationRequest {
                        stable_id: progress.route_id.clone(),
                        spec: Some(pb::RouteSpec {
                            surface: intent.surface.clone(),
                            endpoint_id: progress.endpoint_id.clone(),
                            endpoint_generation: progress.endpoint_generation,
                            base_path: intent.client_base_path.clone(),
                            target: Some(pb::RouteTarget {
                                target: Some(pb::route_target::Target::DirectGatewayPlacement(
                                    pb::DirectGatewayPlacementTarget {
                                        placement_name: intent.placement_name.clone(),
                                        gateway_id: progress.gateway_id.clone(),
                                        gateway_generation: 1,
                                    },
                                )),
                            }),
                            access_policy: intent.access_policy.clone(),
                            capabilities: intent.capabilities.clone(),
                            enabled: true,
                        }),
                        idempotency_key: key,
                        ..Default::default()
                    },
                )
                .await
            }
            _ => Err(RpcError::internal(anyhow::anyhow!("unknown delivery step"))),
        }
    }

    async fn schedule_delivery_verification(
        &self,
        seal: &IntentSeal,
        progress: &mut Progress,
        request_key: &str,
    ) -> Result<(), RpcError> {
        if progress.completed.contains("endpoint")
            && matches!(
                seal.intent.endpoint,
                Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(_))
            )
            && !self.delivery_probe_in_flight(progress, "endpoint").await?
        {
            let revision = self
                .db
                .endpoint_revision(&progress.endpoint_id, progress.endpoint_generation)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
            let operation_id = digest(&("delivery-endpoint", &seal.workflow_id, request_key))?;
            self.topology_probes
                .schedule(
                    &operation_id,
                    crate::topology_probe::TopologyProbe::Endpoint {
                        stable_id: progress.endpoint_id.clone(),
                        generation: progress.endpoint_generation,
                        configuration_digest: revision.content_digest,
                    },
                )
                .await
                .map_err(RpcError::internal)?;
            progress.operations.insert("endpoint".into(), operation_id);
        }
        if progress.completed.contains("route")
            && !self
                .delivery_probe_in_flight(progress, "verification")
                .await?
        {
            let route = self.workflow_activation_route(progress).await?;
            if self
                .db
                .delivery_workflow_route_ready(&route)
                .await
                .map_err(RpcError::internal)?
            {
                return Ok(());
            }
            let operation_id = digest(&("delivery-route", &seal.workflow_id, request_key))?;
            self.topology_probes
                .schedule(
                    &operation_id,
                    crate::topology_probe::TopologyProbe::Route {
                        stable_id: route.route_id,
                        generation: route.generation,
                        configuration_digest: route.digest,
                    },
                )
                .await
                .map_err(RpcError::internal)?;
            progress
                .operations
                .insert("verification".into(), operation_id);
        }
        Ok(())
    }

    async fn delivery_probe_in_flight(
        &self,
        progress: &Progress,
        step: &str,
    ) -> Result<bool, RpcError> {
        let Some(id) = progress.operations.get(step) else {
            return Ok(false);
        };
        Ok(self
            .db
            .topology_operation(id)
            .await
            .map_err(RpcError::internal)?
            .is_some_and(|operation| matches!(operation.state.as_str(), "pending" | "running")))
    }
}
