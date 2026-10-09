//! Bindings helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn authorize_gateway_binding(
        &self,
        auth: Option<&str>,
        binding: &crate::db::BindingRecord,
        scope: &str,
    ) -> Result<(), RpcError> {
        self.require_delivery_scope(auth, scope, Permission::BindingRead)
            .await?;
        let grant = self
            .db
            .load_consumer_scope_grant(
                crate::db::GrantResource::Binding {
                    id: binding.id,
                    stable_id: &binding.stable_id,
                },
                scope,
            )
            .await
            .map_err(RpcError::internal)?;
        if !grant.is_some_and(|grant| grant.state == "active") {
            return Err(RpcError::not_found("active binding consumer grant"));
        }
        Ok(())
    }

    /// Resolves and authorizes one typed storage-binding reference.
    pub(in crate::service) async fn resolve_binding_reference(
        &self,
        auth: Option<&str>,
        reference: Option<pb::BindingRef>,
    ) -> Result<crate::db::BindingRecord, RpcError> {
        let target = reference
            .and_then(|binding| binding.target)
            .ok_or_else(|| RpcError::invalid("storageBinding reference is required"))?;
        match target {
            pb::binding_ref::Target::InstanceDefault(true) => {
                self.readable_storage_owner(auth, "instance").await?;
                self.db.instance_default_binding().await
            }
            pb::binding_ref::Target::InstanceDefault(false) => {
                return Err(RpcError::invalid("instanceDefault must be true"));
            }
            pb::binding_ref::Target::Organization(reference) => {
                let org = self.org_or_not_found(&reference.org_slug).await?;
                let scope = org.stable_id;
                let org_id = self
                    .readable_storage_owner(auth, &scope)
                    .await?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("org scope resolved as instance"))
                    })?;
                self.db.binding_by_name(org_id, &reference.name).await
            }
        }
        .map_err(RpcError::internal)?
        .ok_or_else(|| RpcError::not_found("binding"))
    }

    /// Validates and canonicalizes a storage-binding desired spec.
    pub(in crate::service) fn canonicalize_binding_spec(
        spec: &mut pb::BindingSpec,
    ) -> Result<(), RpcError> {
        spec.name = spec.name.trim().to_string();
        if spec.name.is_empty() {
            return Err(RpcError::invalid("binding name is required"));
        }
        match spec.provider.as_mut() {
            Some(pb::binding_spec::Provider::LocalFilesystem(provider)) => {
                provider.root_path = provider.root_path.trim().to_string();
                if !provider.root_path.starts_with('/') {
                    return Err(RpcError::invalid(
                        "local filesystem rootPath must be absolute",
                    ));
                }
            }
            Some(pb::binding_spec::Provider::S3(provider)) => {
                Self::canonicalize_object_storage_provider(
                    &mut provider.bucket,
                    &mut provider.prefix,
                    &mut provider.endpoint,
                    &mut provider.signing_region,
                    &mut provider.access_mode,
                )?;
            }
            Some(pb::binding_spec::Provider::R2(provider)) => {
                Self::canonicalize_object_storage_provider(
                    &mut provider.bucket,
                    &mut provider.prefix,
                    &mut provider.endpoint,
                    &mut provider.signing_region,
                    &mut provider.access_mode,
                )?;
            }
            Some(pb::binding_spec::Provider::DeploymentR2(provider)) => {
                provider.bucket_binding = provider.bucket_binding.trim().to_string();
                if provider.bucket_binding != crate::binding::DEPLOYMENT_R2_ATTACHMENT {
                    return Err(RpcError::invalid(
                        "deployment R2 bucketBinding must name the REGISTRY_BUCKET runtime attachment",
                    ));
                }
            }
            None => return Err(RpcError::invalid("binding provider is required")),
        }
        Ok(())
    }

    /// Reconstructs the final desired spec from one binding record.
    pub(in crate::service) fn binding_spec_from_record(
        record: &crate::db::BindingRecord,
    ) -> Result<pb::BindingSpec, RpcError> {
        let endpoint = match (
            record.endpoint_scheme.clone(),
            record.endpoint_host_kind.as_deref(),
            record.endpoint_host_bytes.clone(),
        ) {
            (Some(scheme), Some(kind), Some(bytes)) => {
                let host = match kind {
                    "dns" => pb::storage_endpoint::Host::DnsName(
                        String::from_utf8(bytes)
                            .map_err(|error| RpcError::internal(anyhow::anyhow!(error)))?,
                    ),
                    "ipv4" => pb::storage_endpoint::Host::Ipv4(bytes),
                    "ipv6" => pb::storage_endpoint::Host::Ipv6(bytes),
                    _ => {
                        return Err(RpcError::internal(anyhow::anyhow!(
                            "invalid endpoint host kind"
                        )));
                    }
                };
                Some(pb::StorageEndpoint {
                    scheme,
                    host: Some(host),
                    port: u32::try_from(record.endpoint_port.unwrap_or_default())
                        .unwrap_or_default(),
                })
            }
            (None, None, None) => None,
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "incomplete storage endpoint"
                )));
            }
        };
        let provider = match record.kind.as_str() {
            "local_fs" => {
                pb::binding_spec::Provider::LocalFilesystem(pb::LocalFilesystemStorageProvider {
                    root_path: record.local_root_path.clone().unwrap_or_default(),
                })
            }
            "s3" => pb::binding_spec::Provider::S3(pb::S3StorageProvider {
                bucket: record.object_bucket.clone().unwrap_or_default(),
                prefix: record.object_prefix.clone().unwrap_or_default(),
                endpoint,
                signing_region: record.signing_region.clone().unwrap_or_default(),
                access_mode: record.access_mode.clone().unwrap_or_default(),
            }),
            "r2" => pb::binding_spec::Provider::R2(pb::R2StorageProvider {
                bucket: record.object_bucket.clone().unwrap_or_default(),
                prefix: record.object_prefix.clone().unwrap_or_default(),
                endpoint,
                signing_region: record.signing_region.clone().unwrap_or_default(),
                access_mode: record.access_mode.clone().unwrap_or_default(),
            }),
            "deployment_r2" => {
                pb::binding_spec::Provider::DeploymentR2(pb::DeploymentR2StorageProvider {
                    bucket_binding: record.object_bucket.clone().unwrap_or_default(),
                })
            }
            kind => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "unknown storage provider kind '{kind}'"
                )));
            }
        };
        Ok(pb::BindingSpec {
            name: record.name.clone(),
            provider: Some(provider),
        })
    }

    /// Projects a storage-binding record without exposing credential material.
    pub(in crate::service) async fn binding_message(
        &self,
        record: crate::db::BindingRecord,
    ) -> Result<pb::Binding, RpcError> {
        let spec = Self::binding_spec_from_record(&record)?;
        let credentials = self
            .db
            .list_current_binding_credentials(record.id)
            .await
            .map_err(RpcError::internal)?;
        let has_valid_credential = |purpose: &str| {
            credentials.iter().any(|credential| {
                credential.purpose == purpose && credential.validation_state == "valid"
            })
        };
        let local_filesystem = record.kind == "local_fs";
        let public_object_store = record.access_mode.as_deref() == Some("public");
        let mut capabilities = pb::BindingCapabilities {
            reads_supported: local_filesystem
                || public_object_store
                || has_valid_credential("read"),
            writes_supported: false,
            conditional_writes_supported: false,
            deletes_supported: record.kind == "s3" && has_valid_credential("delete"),
            lists_supported: local_filesystem
                || public_object_store
                || has_valid_credential("list"),
            presigns_supported: !local_filesystem && has_valid_credential("presign"),
        };
        let health = if let Some(state) = self
            .db
            .binding_write_state(record.id)
            .await
            .map_err(RpcError::internal)?
        {
            if let Some(revision_number) = state.current_write_revision {
                let revision = self
                    .db
                    .binding_write_revision(record.id, revision_number)
                    .await
                    .map_err(RpcError::internal)?;
                let observation = self
                    .db
                    .binding_write_observation(record.id, revision_number)
                    .await
                    .map_err(RpcError::internal)?;
                if let Some(revision) = revision {
                    capabilities.writes_supported = revision.writes_supported;
                    capabilities.conditional_writes_supported =
                        revision.conditional_writes_supported;
                }
                observation.map(|observation| pb::BindingHealth {
                    state: observation.state,
                    observed_at: observation.validated_at.unwrap_or_default(),
                    error: observation.error.unwrap_or_default(),
                })
            } else {
                None
            }
        } else {
            None
        };
        let grant_records = self
            .db
            .list_consumer_scope_grants(crate::db::GrantResource::Binding {
                id: record.id,
                stable_id: &record.stable_id,
            })
            .await
            .map_err(RpcError::internal)?;
        let mut grants = Vec::with_capacity(grant_records.len());
        for grant in grant_records {
            let pins = self
                .db
                .consumer_scope_grant_pin_records(
                    crate::db::GrantResource::Binding {
                        id: record.id,
                        stable_id: &record.stable_id,
                    },
                    &grant.consumer_scope_key,
                )
                .await
                .map_err(RpcError::internal)?;
            grants.push(Self::binding_grant_message(&record.stable_id, grant, pins));
        }
        Ok(pb::Binding {
            stable_id: record.stable_id,
            owner_scope_key: record.owner_scope_key,
            spec: Some(spec),
            capabilities: Some(capabilities),
            health,
            grants,
            resource_version: record.resource_version.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }

    /// Projects one binding consumer-scope grant and its live pin impacts.
    pub(in crate::service) fn binding_grant_message(
        stable_id: &str,
        record: crate::db::ConsumerScopeGrantRecord,
        pins: Vec<crate::db::ConsumerScopeGrantPinRecord>,
    ) -> pb::ConsumerScopeGrant {
        let pins = pins
            .into_iter()
            .map(Self::topology_pin_impact_message)
            .collect::<Vec<_>>();
        pb::ConsumerScopeGrant {
            resource_kind: "binding".to_string(),
            resource_stable_id: stable_id.to_string(),
            resource_generation: 0,
            consumer_scope_key: record.consumer_scope_key,
            grant_generation: record.grant_generation,
            grant_kind: record.grant_kind,
            state: record.state,
            granted_by: record.granted_by,
            granted_at: record.granted_at,
            revoked_by: record.revoked_by.unwrap_or_default(),
            revoked_at: record.revoked_at.unwrap_or_default(),
            live_pin_count: u64::try_from(pins.len()).unwrap_or_default(),
            live_pin_impacts: pins,
            resource_version: record.resource_version.to_string(),
        }
    }

    /// Persists a binding grant/revoke plan with exact live-pin preconditions.
    pub(in crate::service) async fn plan_binding_grant(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.resource_kind != "binding" || req.consumer_scope_key.is_empty() {
            return Err(RpcError::invalid(
                "resourceKind must be binding and consumerScopeKey is required",
            ));
        }
        let binding = self
            .db
            .binding_by_stable_id(&req.resource_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        let owner_scope_key = binding.owner_scope_key.clone();
        self.writable_storage_owner(auth, &owner_scope_key).await?;
        // Bindings are stable, non-generational grant targets. Their mutable
        // resource version is carried separately by grant update requests and
        // must not be confused with the generation field used by gateways.
        if req.resource_generation != 0 {
            return Err(RpcError::invalid("binding resourceGeneration must be zero"));
        }
        let grants = self
            .db
            .list_consumer_scope_grants(crate::db::GrantResource::Binding {
                id: binding.id,
                stable_id: &req.resource_stable_id,
            })
            .await
            .map_err(RpcError::internal)?;
        let existing = grants
            .iter()
            .find(|grant| grant.consumer_scope_key == req.consumer_scope_key);
        let baseline = existing.map(|grant| grant.resource_version);
        let pin_resolutions = if revoke {
            let grant = existing.ok_or_else(|| RpcError::not_found("consumer grant"))?;
            let pins = self
                .db
                .consumer_scope_grant_pin_records(
                    crate::db::GrantResource::Binding {
                        id: binding.id,
                        stable_id: &req.resource_stable_id,
                    },
                    &req.consumer_scope_key,
                )
                .await
                .map_err(RpcError::internal)?;
            if grant.grant_kind != "explicit" || grant.state != "active" {
                return Err(RpcError::FailedPrecondition(
                    "only an active explicit grant may be revoked".to_string(),
                ));
            }
            if parse_resource_version(&req.expected_resource_version, grant.resource_version)?
                != grant.resource_version
            {
                return Err(RpcError::FailedPrecondition(
                    "consumer grant resource version is stale".to_string(),
                ));
            }
            self.seal_grant_pin_resolutions(auth, &pins, &req.pin_resolutions)
                .await?
        } else if let Some(grant) = existing {
            if !req.expected_resource_version.is_empty()
                && parse_resource_version(&req.expected_resource_version, grant.resource_version)?
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
        } else if !req.expected_resource_version.is_empty() {
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
        let input = BindingGrantPlanInput {
            request: req,
            binding_db_id: binding.id,
            owner_scope_key: owner_scope_key.clone(),
            baseline_grant_resource_version: baseline,
            pin_resolutions,
        };
        let plan_kind = if revoke {
            "revoke_binding_scope"
        } else {
            "grant_binding_scope"
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
            vec![format!(
                "{} binding access for '{}'",
                if revoke { "revoke" } else { "grant" },
                input.request.consumer_scope_key
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Applies a binding scope grant/revocation plan exactly once.
    pub(in crate::service) async fn apply_binding_grant(
        &self,
        auth: Option<&str>,
        req: pb::ApplyConsumerScopeGrantRequest,
        revoke: bool,
    ) -> Result<pb::ConsumerScopeGrantResponse, RpcError> {
        let plan_kind = if revoke {
            "revoke_binding_scope"
        } else {
            "grant_binding_scope"
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
        let (plan, input): (_, BindingGrantPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.writable_storage_owner(auth, &input.owner_scope_key)
            .await?;
        let binding = self
            .db
            .binding_by_stable_id(&input.request.resource_stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("binding"))?;
        if binding.id != input.binding_db_id {
            return Err(RpcError::FailedPrecondition(
                "binding identity changed after grant planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        if revoke && !input.pin_resolutions.is_empty() {
            let resource = crate::db::GrantResource::Binding {
                id: binding.id,
                stable_id: &input.request.resource_stable_id,
            };
            let record = self
                .db
                .load_consumer_scope_grant(resource, &input.request.consumer_scope_key)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("binding consumer grant"))?;
            let coordination_operation = self
                .schedule_grant_revocation(
                    &plan.plan_id,
                    "binding",
                    &input.request.resource_stable_id,
                    input.request.resource_generation,
                    &input.request.consumer_scope_key,
                    input.baseline_grant_resource_version.ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("revoke plan has no grant version"))
                    })?,
                    input.pin_resolutions,
                    &claims.sub,
                    &req.idempotency_key,
                    Permission::BindingGrant,
                )
                .await?;
            let response = pb::ConsumerScopeGrantResponse {
                grant: Some(Self::binding_grant_message(
                    &input.request.resource_stable_id,
                    record,
                    self.db
                        .consumer_scope_grant_pin_records(
                            resource,
                            &input.request.consumer_scope_key,
                        )
                        .await
                        .map_err(RpcError::internal)?,
                )),
                coordination_operation: Some(coordination_operation),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }
        if revoke {
            if let Some((record, pins)) = self
                .db
                .list_consumer_scope_grants(crate::db::GrantResource::Binding {
                    id: binding.id,
                    stable_id: &input.request.resource_stable_id,
                })
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .find(|grant| grant.consumer_scope_key == input.request.consumer_scope_key)
                .map(|grant| (grant, Vec::new()))
            {
                if record.state == "revoked"
                    && Some(record.resource_version)
                        == input
                            .baseline_grant_resource_version
                            .map(|version| version + 1)
                {
                    let response = pb::ConsumerScopeGrantResponse {
                        grant: Some(Self::binding_grant_message(
                            &input.request.resource_stable_id,
                            record,
                            pins,
                        )),
                        coordination_operation: None,
                    };
                    self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                        .await?;
                    return Ok(response);
                }
            }
        }
        let record = if revoke {
            self.db
                .revoke_consumer_scope(
                    crate::db::GrantResource::Binding {
                        id: binding.id,
                        stable_id: &input.request.resource_stable_id,
                    },
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
                    crate::db::GrantResource::Binding {
                        id: binding.id,
                        stable_id: &input.request.resource_stable_id,
                    },
                    &input.request.consumer_scope_key,
                    "explicit",
                    &claims.sub,
                    &req.idempotency_key,
                )
                .await
        }
        .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let pins = self
            .db
            .consumer_scope_grant_pin_records(
                crate::db::GrantResource::Binding {
                    id: binding.id,
                    stable_id: &input.request.resource_stable_id,
                },
                &record.consumer_scope_key,
            )
            .await
            .map_err(RpcError::internal)?;
        let response = pb::ConsumerScopeGrantResponse {
            grant: Some(Self::binding_grant_message(
                &input.request.resource_stable_id,
                record,
                pins,
            )),
            coordination_operation: None,
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Projects one immutable write revision with its mutable controller observation.
    pub(in crate::service) async fn binding_write_revision_message(
        &self,
        stable_id: &str,
        revision: crate::db::BindingWriteRevisionRecord,
    ) -> Result<pb::BindingWriteRevision, RpcError> {
        let observation = self
            .db
            .binding_write_observation(revision.binding_id, revision.revision)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::BindingWriteRevision {
            binding_id: stable_id.to_string(),
            revision: revision.revision,
            write_credential_purpose: revision.write_credential_purpose,
            write_credential_generation: revision.write_credential_generation,
            write_credential_version_ref: revision.write_credential_version_ref,
            writes_supported: revision.writes_supported,
            conditional_writes_supported: revision.conditional_writes_supported,
            revision_fingerprint: revision.revision_fingerprint,
            capability_fingerprint: revision.capability_fingerprint,
            validation_state: observation
                .as_ref()
                .map(|observation| observation.state.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            validated_at: observation
                .as_ref()
                .and_then(|observation| observation.validated_at)
                .unwrap_or_default(),
            validation_error: observation
                .as_ref()
                .and_then(|observation| observation.error.clone())
                .unwrap_or_default(),
            created_at: revision.created_at,
            resource_version: observation
                .map(|observation| observation.observation_version.to_string())
                .unwrap_or_else(|| "0".to_string()),
        })
    }

    /// Resolves a binding by stable id in a surface's owning scope.
    pub(in crate::service) async fn topology_binding_id(
        &self,
        org_id: Option<i64>,
        stable_id: &str,
    ) -> Result<i64, RpcError> {
        if stable_id.is_empty() {
            return Err(RpcError::invalid("bindingId is required"));
        }
        let owner_scope_key = match org_id {
            Some(id) => {
                self.db
                    .org_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("organization"))?
                    .stable_id
            }
            None => "instance".to_owned(),
        };
        self.db
            .list_bindings_available_to_scope(&owner_scope_key)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|binding| binding.stable_id == stable_id)
            .map(|binding| binding.id)
            .ok_or_else(|| RpcError::not_found("binding"))
    }

    pub(in crate::service) fn placement_message_with_binding(
        placement: crate::db::SurfacePlacementRecord,
        binding_name: String,
    ) -> Result<pb::Placement, RpcError> {
        let hash_range = match (placement.hash_range_start, placement.hash_range_end) {
            (Some(start), Some(end)) => Some(pb::HashRangeV1 {
                start: u32::try_from(start).map_err(RpcError::internal)?,
                end: u32::try_from(end).map_err(RpcError::internal)?,
            }),
            (None, None) => None,
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "placement '{}' has an incomplete hash range",
                    placement.name
                )));
            }
        };
        let desired_writer = placement.authority_desired_placement_id == Some(placement.id);
        let observed_writer = placement.authority_observed_placement_id == Some(placement.id);
        Ok(pb::Placement {
            name: placement.name,
            binding_name,
            prefix: placement.prefix,
            spec: Some(pb::PlacementSpec {
                kind: placement.kind,
                desired_state: placement.desired_state,
                desired_read_enabled: placement.desired_read_enabled,
                read_order: placement.read_order,
                write_spec_version: placement.write_spec_version,
                requires_conditional_writes: placement.requires_conditional_writes,
                hash_range,
            }),
            observation: Some(pb::PlacementObservation {
                state: placement.state,
                completeness: placement.completeness,
                observed_at: placement.observed_at.unwrap_or_default(),
                observation_version: placement
                    .observation_version
                    .map(|version| version.to_string())
                    .unwrap_or_default(),
                mutable_publication_id: placement.mutable_publication_id.unwrap_or_default(),
                pending_publication_id: placement
                    .watermark_pending_publication_id
                    .unwrap_or_default(),
                watermark_resource_version: placement
                    .watermark_resource_version
                    .map(|version| version.to_string())
                    .unwrap_or_default(),
            }),
            status: Some(pb::PlacementStatus {
                derived_role: placement.derived_role,
                desired_writer,
                observed_writer,
                promotion_pending: desired_writer
                    && placement.authority_desired_generation
                        != placement.authority_observed_generation,
                effective_read_enabled: placement.effective_read_enabled,
                effective_write_enabled: placement.effective_write_enabled,
            }),
            created_at: placement.created_at,
            updated_at: placement.updated_at,
            resource_version: placement.resource_version.to_string(),
        })
    }
}
