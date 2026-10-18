//! Endpoints helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn endpoint_host(
        host: Option<pb::EndpointHost>,
    ) -> Result<aos_hub_db::db::EndpointHostInput, RpcError> {
        use pb::endpoint_host::Host;
        match host.and_then(|value| value.host) {
            Some(Host::DomainId(id)) if !id.is_empty() => {
                Ok(aos_hub_db::db::EndpointHostInput::Domain(id))
            }
            Some(Host::Ipv4(bytes)) => Ok(aos_hub_db::db::EndpointHostInput::Ipv4(
                bytes
                    .try_into()
                    .map_err(|_| RpcError::invalid("ipv4 must contain exactly four bytes"))?,
            )),
            Some(Host::Ipv6(bytes)) => Ok(aos_hub_db::db::EndpointHostInput::Ipv6(
                bytes
                    .try_into()
                    .map_err(|_| RpcError::invalid("ipv6 must contain exactly sixteen bytes"))?,
            )),
            _ => Err(RpcError::invalid("endpoint host is required")),
        }
    }

    pub(in crate::service) fn endpoint_host_message(
        record: &aos_hub_db::db::EndpointRecord,
    ) -> Result<pb::EndpointHost, RpcError> {
        use pb::endpoint_host::Host;
        let host = match (
            record.domain_stable_id.as_ref(),
            record.ipv4_bytes.as_ref(),
            record.ipv6_bytes.as_ref(),
        ) {
            (Some(id), None, None) => Host::DomainId(id.clone()),
            (None, Some(bytes), None) if bytes.len() == 4 => Host::Ipv4(bytes.clone()),
            (None, None, Some(bytes)) if bytes.len() == 16 => Host::Ipv6(bytes.clone()),
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "persisted endpoint has an invalid host variant"
                )));
            }
        };
        Ok(pb::EndpointHost { host: Some(host) })
    }

    pub(in crate::service) fn endpoint_revision_spec(
        spec: Option<pb::EndpointRevisionSpec>,
    ) -> Result<aos_hub_db::db::EndpointRevisionSpec, RpcError> {
        #[derive(serde::Serialize)]
        struct Tls<'a> {
            provider: &'a str,
            certificate_ref: &'a str,
            require_client_certificate: bool,
        }
        let spec = spec.ok_or_else(|| RpcError::invalid("revision is required"))?;
        let ingress_kind = match pb::EndpointIngressKind::try_from(spec.ingress_kind) {
            Ok(pb::EndpointIngressKind::Hub) => "hub",
            Ok(pb::EndpointIngressKind::External) => "external",
            Ok(pb::EndpointIngressKind::Layer7) => "layer7",
            _ => return Err(RpcError::invalid("ingressKind is required")),
        };
        let tls_configuration = match spec.tls {
            Some(tls) => serde_json::to_string(&Tls {
                provider: &tls.provider,
                certificate_ref: &tls.certificate_ref,
                require_client_certificate: tls.require_client_certificate,
            })
            .map_err(RpcError::internal)?,
            None => "{}".to_string(),
        };
        Ok(aos_hub_db::db::EndpointRevisionSpec {
            boundary_revision: spec.boundary_revision,
            ingress_kind: ingress_kind.to_string(),
            listener_configuration: spec.listener_configuration_ref,
            tls_configuration,
            probe_configuration: spec.probe_configuration_ref,
        })
    }

    pub(in crate::service) fn endpoint_revision_spec_message(
        spec: &aos_hub_db::db::EndpointRevisionSpec,
    ) -> Result<pb::EndpointRevisionSpec, RpcError> {
        let ingress_kind = match spec.ingress_kind.as_str() {
            "hub" => pb::EndpointIngressKind::Hub as i32,
            "external" => pb::EndpointIngressKind::External as i32,
            "layer7" => pb::EndpointIngressKind::Layer7 as i32,
            other => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "persisted endpoint has invalid ingress kind '{other}'"
                )));
            }
        };
        let tls = if spec.tls_configuration == "{}" {
            None
        } else {
            let value: serde_json::Value =
                serde_json::from_str(&spec.tls_configuration).map_err(RpcError::internal)?;
            Some(pb::TlsConfiguration {
                provider: value
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                certificate_ref: value
                    .get("certificate_ref")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                require_client_certificate: value
                    .get("require_client_certificate")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        };
        Ok(pb::EndpointRevisionSpec {
            boundary_revision: spec.boundary_revision,
            ingress_kind,
            listener_configuration_ref: spec.listener_configuration.clone(),
            tls,
            probe_configuration_ref: spec.probe_configuration.clone(),
        })
    }

    pub(in crate::service) async fn endpoint_message(
        &self,
        record: aos_hub_db::db::EndpointRecord,
    ) -> Result<pb::Endpoint, RpcError> {
        let generation = record.desired_generation.ok_or_else(|| {
            RpcError::internal(anyhow::anyhow!("endpoint has no desired generation"))
        })?;
        let revision = self
            .db
            .endpoint_revision(&record.id, generation)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("endpoint revision is missing")))?;
        let observation = self
            .db
            .endpoint_observation(&record.id)
            .await
            .map_err(RpcError::internal)?;
        let grant_records = self
            .db
            .list_consumer_scope_grants(aos_hub_db::db::GrantResource::Endpoint {
                id: &record.id,
                generation,
            })
            .await
            .map_err(RpcError::internal)?;
        let mut pins = if grant_records.is_empty() {
            BTreeMap::new()
        } else {
            self.db
                .endpoint_grant_pins_by_consumer(&record.id, generation)
                .await
                .map_err(RpcError::internal)?
        };
        let grants = grant_records
            .into_iter()
            .map(|grant| {
                let impacts = pins.remove(&grant.consumer_scope_key).unwrap_or_default();
                Self::topology_grant_message_with_pins(grant, impacts)
            })
            .collect();
        let host = Self::endpoint_host_message(&record)?;
        Ok(pb::Endpoint {
            stable_id: record.id.clone(),
            owner_scope_key: record.owner_scope_key,
            scheme: record.scheme,
            host: Some(host),
            effective_port: u32::try_from(record.effective_port).map_err(RpcError::internal)?,
            network_policy_id: record.network_policy_id,
            desired_generation: generation,
            endpoint_identity_digest: record.endpoint_identity_digest,
            desired: Some(Self::endpoint_revision_spec_message(&revision.spec)?),
            observed: observation.map(|value| pb::EndpointObservedState {
                observed_generation: value.observed_generation.unwrap_or_default(),
                boundary_revision: value.boundary_revision.unwrap_or_default(),
                state: value.state,
                listener_observed: value.listener_observed,
                tls_observed: value.tls_observed,
                observed_at: value.observed_at,
                error: value.error.unwrap_or_default(),
            }),
            grants,
            resource_version: record.resource_version.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    pub(in crate::service) async fn endpoint_generation_message(
        &self,
        endpoint: &aos_hub_db::db::EndpointRecord,
        revision: aos_hub_db::db::EndpointRevisionRecord,
    ) -> Result<pb::EndpointGeneration, RpcError> {
        let observation = self
            .db
            .endpoint_generation_observation(&endpoint.id, revision.generation)
            .await
            .map_err(RpcError::internal)?;
        let grant_records = self
            .db
            .list_consumer_scope_grants(aos_hub_db::db::GrantResource::Endpoint {
                id: &endpoint.id,
                generation: revision.generation,
            })
            .await
            .map_err(RpcError::internal)?;
        let mut grants = Vec::with_capacity(grant_records.len());
        for grant in grant_records {
            grants.push(
                self.topology_grant_message(
                    grant,
                    aos_hub_db::db::GrantResource::Endpoint {
                        id: &endpoint.id,
                        generation: revision.generation,
                    },
                )
                .await?,
            );
        }
        Ok(pb::EndpointGeneration {
            endpoint_id: revision.endpoint_id,
            generation: revision.generation,
            network_policy_id: revision.network_policy_id,
            desired: Some(Self::endpoint_revision_spec_message(&revision.spec)?),
            observed: observation.map(|value| pb::EndpointObservedState {
                observed_generation: value.observed_generation.unwrap_or_default(),
                boundary_revision: value.boundary_revision.unwrap_or_default(),
                state: value.state,
                listener_observed: value.listener_observed,
                tls_observed: value.tls_observed,
                observed_at: value.observed_at,
                error: value.error.unwrap_or_default(),
            }),
            grants,
            content_digest: revision.content_digest,
            created_by: revision.created_by,
            created_at: revision.created_at,
            selected: endpoint.desired_generation == Some(revision.generation),
        })
    }

    pub(in crate::service) async fn managed_endpoint(
        &self,
        auth: Option<&str>,
        stable_id: &str,
        permission: Permission,
    ) -> Result<aos_hub_db::db::EndpointRecord, RpcError> {
        let record = self
            .db
            .endpoint(stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("endpoint"))?;
        self.require_cloaked_delivery_scope(auth, &record.owner_scope_key, permission, "endpoint")
            .await?;
        Ok(record)
    }

    pub(in crate::service) async fn plan_endpoint_mutation(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanEndpointMutationRequest,
        update: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let _host = Self::endpoint_host(req.host.clone())?;
        let port = u16::try_from(req.effective_port)
            .map_err(|_| RpcError::invalid("effectivePort exceeds 65535"))?;
        if port == 0 || !matches!(req.scheme.as_str(), "http" | "https") {
            return Err(RpcError::invalid("scheme and effectivePort are required"));
        }
        let (
            org_id,
            expected_resource_version,
            owner_grant,
            carried_grants,
            affected_resources,
            old_boundary_ref,
            scope,
        ): (
            Option<i64>,
            Option<i64>,
            Option<EndpointGrantPlanSeal>,
            Vec<EndpointGrantPlanSeal>,
            Vec<aos_hub_db::db::EndpointImpactRecord>,
            Option<(String, i64)>,
            String,
        ) = if update {
            let current = self
                .managed_endpoint(auth, &req.stable_id, Permission::EndpointManage)
                .await?;
            self.require_cloaked_delivery_scope(
                auth,
                &current.owner_scope_key,
                Permission::EndpointGrant,
                "endpoint",
            )
            .await?;
            let expected = parse_resource_version(&req.expected_resource_version, 0)?;
            if expected <= 0 || expected != current.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "endpoint resource version is required and must be current".to_string(),
                ));
            }
            let current_host = Self::endpoint_host_message(&current)?;
            if req.owner_scope_key != current.owner_scope_key
                || req.scheme != current.scheme
                || req.effective_port != u32::try_from(current.effective_port).unwrap_or_default()
                || req.network_policy_id != current.network_policy_id
                || req.host != Some(current_host)
            {
                return Err(RpcError::invalid(
                    "endpoint identity and owner fields are immutable",
                ));
            }
            const FIELDS: &[&str] = &[
                "revision.boundary_revision",
                "revision.ingress_kind",
                "revision.listener_configuration_ref",
                "revision.tls",
                "revision.probe_configuration_ref",
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
                    "updateMask must contain unique endpoint revision fields",
                ));
            }
            let generation = current.desired_generation.ok_or_else(|| {
                RpcError::FailedPrecondition("endpoint has no desired generation".to_string())
            })?;
            let current_revision = self
                .db
                .endpoint_revision(&current.id, generation)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("endpoint generation"))?;
            let current_spec = Self::endpoint_revision_spec_message(&current_revision.spec)?;
            let desired = req
                .revision
                .as_mut()
                .ok_or_else(|| RpcError::invalid("revision is required"))?;
            if !mask.contains("revision.boundary_revision") {
                desired.boundary_revision = current_spec.boundary_revision;
            }
            if !mask.contains("revision.ingress_kind") {
                desired.ingress_kind = current_spec.ingress_kind;
            }
            if !mask.contains("revision.listener_configuration_ref") {
                desired.listener_configuration_ref = current_spec.listener_configuration_ref;
            }
            if !mask.contains("revision.tls") {
                desired.tls = current_spec.tls;
            }
            if !mask.contains("revision.probe_configuration_ref") {
                desired.probe_configuration_ref = current_spec.probe_configuration_ref;
            }
            let grants = self
                .db
                .list_consumer_scope_grants(aos_hub_db::db::GrantResource::Endpoint {
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
                .ok_or_else(|| RpcError::not_found("active endpoint owner grant"))?;
            let owner_grant = EndpointGrantPlanSeal {
                consumer_scope_key: owner.consumer_scope_key.clone(),
                grant_generation: owner.grant_generation,
                resource_version: owner.resource_version,
            };
            let mut carried = Vec::new();
            let mut seen = BTreeSet::new();
            for consumer_scope_key in &req.carry_forward_consumer_scopes {
                self.require_permission(
                    &claims,
                    Permission::EndpointGrant,
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
                    .ok_or_else(|| RpcError::not_found("active endpoint consumer grant"))?;
                carried.push(EndpointGrantPlanSeal {
                    consumer_scope_key: grant.consumer_scope_key.clone(),
                    grant_generation: grant.grant_generation,
                    resource_version: grant.resource_version,
                });
            }
            (
                current.org_id,
                Some(expected),
                Some(owner_grant),
                carried,
                Vec::new(),
                None,
                current.owner_scope_key,
            )
        } else {
            self.require_delivery_scope(auth, &req.owner_scope_key, Permission::EndpointManage)
                .await?;
            if !req.expected_resource_version.is_empty()
                || !req.update_mask.is_empty()
                || !req.carry_forward_consumer_scopes.is_empty()
            {
                return Err(RpcError::invalid(
                    "endpoint creation forbids expectedResourceVersion, updateMask, and carryForwardConsumerScopes",
                ));
            }
            if self
                .db
                .endpoint(&req.stable_id)
                .await
                .map_err(RpcError::internal)?
                .is_some()
            {
                return Err(RpcError::AlreadyExists(
                    "endpoint already exists".to_string(),
                ));
            }
            let (_kind, org_id, _project_id) = self
                .db
                .authorization_scope_owner(&req.owner_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("owner scope"))?;
            (
                org_id,
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
                req.owner_scope_key.clone(),
            )
        };
        let revision = Self::endpoint_revision_spec(req.revision.clone())?;
        aos_hub_db::db::validate_endpoint_revision_spec(&revision)
            .map_err(|error| RpcError::invalid(format!("invalid endpoint revision: {error:#}")))?;
        if (req.scheme == "http" && revision.tls_configuration != "{}")
            || (req.scheme == "https" && revision.tls_configuration == "{}")
        {
            return Err(RpcError::invalid(
                "endpoint TLS configuration must match the immutable scheme",
            ));
        }
        let new_boundary = self
            .db
            .network_policy_revision(&req.network_policy_id, revision.boundary_revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        let new_boundary_revision = Self::delivery_boundary_revision_plan_seal(new_boundary);
        if ((!update && new_boundary_revision.lifecycle_state != "active")
            || (update
                && !matches!(
                    new_boundary_revision.lifecycle_state.as_str(),
                    "staged" | "activating" | "active"
                )))
            || new_boundary_revision.observation_state != "verified"
        {
            return Err(RpcError::FailedPrecondition(
                if update {
                    "staged endpoint generation requires a verified staged, activating, or active boundary revision"
                } else {
                    "endpoint creation requires an active verified boundary revision"
                }
                .to_string(),
            ));
        }
        let old_boundary_revision = if let Some((boundary_id, revision)) = old_boundary_ref {
            Some(Self::delivery_boundary_revision_plan_seal(
                self.db
                    .network_policy_revision(&boundary_id, revision)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("network policy revision"))?,
            ))
        } else {
            None
        };
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = EndpointMutationPlanInput {
            request: req,
            org_id,
            expected_resource_version,
            owner_grant,
            carried_grants,
            affected_resources,
            old_boundary_revision,
            new_boundary_revision,
        };
        let plan_kind = if update {
            "stage_endpoint_generation"
        } else {
            "create_endpoint"
        };
        let mut warnings = Vec::new();
        if input.request.scheme == "http" {
            warnings.push(
                "cleartext HTTP exposes request metadata and content on the network".to_string(),
            );
        }
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
                "{} endpoint '{}'",
                if update {
                    "stage a generation for"
                } else {
                    "create"
                },
                input.request.stable_id
            )],
            warnings,
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_endpoint_creation(
        &self,
        auth: Option<&str>,
        req: pb::ApplyEndpointMutationRequest,
    ) -> Result<pb::EndpointResponse, RpcError> {
        let plan_kind = "create_endpoint";
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
        let (plan, input): (_, EndpointMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.require_delivery_scope(
            auth,
            &input.request.owner_scope_key,
            Permission::EndpointManage,
        )
        .await?;
        let revision = Self::endpoint_revision_spec(input.request.revision)?;
        let claims = self.require_claims(auth)?;
        let current_new_boundary = self
            .db
            .network_policy_revision(
                &input.new_boundary_revision.boundary_id,
                input.new_boundary_revision.revision,
            )
            .await
            .map_err(RpcError::internal)?
            .map(Self::delivery_boundary_revision_plan_seal)
            .ok_or_else(|| RpcError::not_found("network policy revision"))?;
        if current_new_boundary != input.new_boundary_revision {
            return Err(RpcError::FailedPrecondition(
                "new boundary revision changed after endpoint planning".to_string(),
            ));
        }
        if input.expected_resource_version.is_some()
            || input.owner_grant.is_some()
            || !input.carried_grants.is_empty()
            || !input.affected_resources.is_empty()
            || input.old_boundary_revision.is_some()
        {
            return Err(RpcError::internal(anyhow::anyhow!(
                "endpoint creation plan contains generation-stage seals"
            )));
        }
        let host = Self::endpoint_host(input.request.host)?;
        let record = self
            .db
            .create_endpoint(
                &input.request.stable_id,
                &input.request.owner_scope_key,
                input.org_id,
                &input.request.scheme,
                &host,
                u16::try_from(input.request.effective_port)
                    .map_err(|_| RpcError::invalid("effectivePort exceeds 65535"))?,
                &input.request.network_policy_id,
                &revision,
                (input.request.scheme == "http").then_some(clock::now_unix_secs()),
                &claims.sub,
                &req.idempotency_key,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::EndpointResponse {
            endpoint: Some(self.endpoint_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    pub(in crate::service) async fn plan_endpoint_scope_grant(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.resource_kind != "endpoint" || req.consumer_scope_key.is_empty() {
            return Err(RpcError::invalid(
                "resourceKind must be endpoint and consumerScopeKey is required",
            ));
        }
        let endpoint = self
            .managed_endpoint(auth, &req.resource_stable_id, Permission::EndpointGrant)
            .await?;
        self.require_permission(
            &claims,
            Permission::EndpointGrant,
            &parse_authorization_scope(&req.consumer_scope_key)?,
        )
        .await?;
        let generation = endpoint.desired_generation.ok_or_else(|| {
            RpcError::FailedPrecondition("endpoint has no desired generation".to_string())
        })?;
        req.resource_generation =
            resolve_endpoint_grant_generation(req.resource_generation, generation)?;
        let resource = aos_hub_db::db::GrantResource::Endpoint {
            id: &endpoint.id,
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
        let input = EndpointScopeGrantPlanInput {
            request: req,
            owner_scope_key: endpoint.owner_scope_key.clone(),
            endpoint_generation: generation,
            baseline_grant_resource_version: baseline,
            pin_resolutions,
        };
        let plan_kind = if revoke {
            "revoke_endpoint_scope"
        } else {
            "grant_endpoint_scope"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &endpoint.owner_scope_key,
            &input,
            &idempotency_key,
            vec![format!(
                "{} endpoint generation {} access for '{}'",
                if revoke { "revoke" } else { "grant" },
                generation,
                input.request.consumer_scope_key
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_endpoint_scope_grant(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        let plan_kind = if revoke {
            "revoke_endpoint_scope"
        } else {
            "grant_endpoint_scope"
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
        let (plan, input): (_, EndpointScopeGrantPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let endpoint = self
            .managed_endpoint(
                auth,
                &input.request.resource_stable_id,
                Permission::EndpointGrant,
            )
            .await?;
        if endpoint.owner_scope_key != input.owner_scope_key
            || endpoint.desired_generation != Some(input.endpoint_generation)
        {
            return Err(RpcError::FailedPrecondition(
                "endpoint owner or desired generation changed after planning".to_string(),
            ));
        }
        let resource = aos_hub_db::db::GrantResource::Endpoint {
            id: &endpoint.id,
            generation: input.endpoint_generation,
        };
        let claims = self.require_claims(auth)?;
        self.require_permission(
            &claims,
            Permission::EndpointGrant,
            &parse_authorization_scope(&input.request.consumer_scope_key)?,
        )
        .await?;
        if revoke && !input.pin_resolutions.is_empty() {
            let record = self
                .db
                .load_consumer_scope_grant(resource, &input.request.consumer_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("endpoint consumer grant"))?;
            let coordination_operation = self
                .schedule_grant_revocation(
                    &plan.plan_id,
                    "endpoint",
                    &endpoint.id,
                    input.endpoint_generation,
                    &input.request.consumer_scope_key,
                    input.baseline_grant_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("revoke plan has no grant version"))
                    })?,
                    input.pin_resolutions,
                    &claims.sub,
                    &req.idempotency_key,
                    Permission::EndpointGrant,
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

    /// Returns normalized endpoint columns for persistence.
    pub(in crate::service) fn storage_endpoint_parts(
        spec: &pb::BindingSpec,
    ) -> (
        Option<&str>,
        Option<&'static str>,
        Option<&[u8]>,
        Option<i64>,
    ) {
        let endpoint = match spec.provider.as_ref() {
            Some(pb::binding_spec::Provider::S3(provider)) => provider.endpoint.as_ref(),
            Some(pb::binding_spec::Provider::R2(provider)) => provider.endpoint.as_ref(),
            _ => None,
        };
        let Some(endpoint) = endpoint else {
            return (None, None, None, None);
        };
        let (kind, bytes) = match endpoint.host.as_ref() {
            Some(pb::storage_endpoint::Host::DnsName(name)) => ("dns", name.as_bytes()),
            Some(pb::storage_endpoint::Host::Ipv4(bytes)) => ("ipv4", bytes.as_slice()),
            Some(pb::storage_endpoint::Host::Ipv6(bytes)) => ("ipv6", bytes.as_slice()),
            None => return (None, None, None, None),
        };
        (
            Some(endpoint.scheme.as_str()),
            Some(kind),
            Some(bytes),
            Some(i64::from(endpoint.port)),
        )
    }

    pub(in crate::service) async fn consumer_endpoint_toml(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        entry: &pb::ConsumerCacheStackEntry,
        ready_routes: &std::collections::BTreeMap<
            String,
            aos_hub_db::db::ReadyRouteAdvertisementIdentity,
        >,
    ) -> Result<toml::Value, RpcError> {
        let mut endpoint = toml::map::Map::new();
        let url = match entry.source.as_ref() {
            Some(pb::consumer_cache_stack_entry::Source::BinaryCacheId(_)) => ready_routes
                .get(&entry.entry_id)
                .map(|identity| identity.canonical_url.clone())
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "planned managed cache route identity is absent".to_string(),
                    )
                })?,
            _ => self.consumer_entry_url(auth, registry, entry).await?,
        };
        endpoint.insert("endpoint".to_string(), toml::Value::String(url));
        Ok(toml::Value::Table(endpoint))
    }
}
