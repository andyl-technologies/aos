//! Placements helpers in the topology capability.

use super::*;

impl RpcService {
    pub(in crate::service) async fn placement_physical_identity_fingerprint(
        &self,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
    ) -> Result<String, RpcError> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("placement binding is missing")))?;
        let object_prefix = binding
            .object_prefix
            .as_deref()
            .unwrap_or_default()
            .trim_matches('/');
        let placement_prefix = placement.prefix.trim_matches('/');
        let combined_prefix = match (object_prefix.is_empty(), placement_prefix.is_empty()) {
            (true, true) => String::new(),
            (true, false) => placement_prefix.to_string(),
            (false, true) => object_prefix.to_string(),
            (false, false) => format!("{object_prefix}/{placement_prefix}"),
        };
        let canonical = serde_json::to_vec(&(
            binding.kind,
            binding.local_root_path,
            binding.object_bucket,
            combined_prefix,
            binding.endpoint_scheme,
            binding.endpoint_host_kind,
            binding.endpoint_host_bytes,
            binding.endpoint_port,
        ))
        .map_err(RpcError::internal)?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }

    /// Validates the complete desired shape of a placement.
    pub(in crate::service) fn validate_placement_shape(
        kind: &str,
        desired_state: &str,
        desired_read_enabled: Option<bool>,
        read_order: Option<i64>,
        hash_range: Option<&pb::HashRangeV1>,
    ) -> Result<(), RpcError> {
        let desired_read_enabled =
            Self::required_placement_field(desired_read_enabled, "desiredReadEnabled")?;
        let _ = Self::required_placement_field(read_order, "readOrder")?;
        if !matches!(kind, "complete" | "shard" | "archive") {
            return Err(RpcError::invalid(
                "kind must be complete, shard, or archive",
            ));
        }
        if !matches!(desired_state, "active" | "offline") {
            return Err(RpcError::invalid(
                "desiredState must be active or offline at creation",
            ));
        }
        if kind == "archive" && desired_read_enabled {
            return Err(RpcError::invalid(
                "archive placements cannot be read-enabled",
            ));
        }
        match (kind, hash_range) {
            ("shard", Some(range)) if range.start < range.end && range.end <= 65_536 => Ok(()),
            ("shard", _) => Err(RpcError::invalid(
                "shard placements require a non-empty 16-bit hashRange",
            )),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(RpcError::invalid(
                "hashRange is valid only for shard placements",
            )),
        }
    }

    /// Checks whether a prior successful create is the exact reviewed outcome.
    pub(in crate::service) fn placement_matches_create(
        placement: &aos_hub_db::db::SurfacePlacementRecord,
        input: &PlacementCreatePlanInput,
    ) -> bool {
        let range = input
            .request
            .hash_range
            .as_ref()
            .map(|range| (i64::from(range.start), i64::from(range.end)));
        placement.binding_id == input.binding_db_id
            && placement.prefix == input.request.prefix
            && placement.kind == input.request.kind
            && placement.desired_state == input.request.desired_state
            && placement.desired_read_enabled == input.request.desired_read_enabled.unwrap_or(false)
            && placement.read_order == input.request.read_order.unwrap_or_default()
            && placement.requires_conditional_writes == input.request.requires_conditional_writes
            && (placement.hash_range_start.zip(placement.hash_range_end)) == range
    }

    /// Finds one placement by its stable name within an already-resolved surface.
    pub(in crate::service) async fn topology_placement(
        &self,
        surface: aos_hub_db::db::SurfaceTarget,
        name: &str,
    ) -> Result<aos_hub_db::db::SurfacePlacementRecord, RpcError> {
        if name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        self.db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == name)
            .ok_or_else(|| RpcError::not_found("placement"))
    }

    /// Resolves the immutable binding revision and credential generation a
    /// caller must pin when creating an observing write ticket.
    pub(in crate::service) async fn placement_write_snapshot(
        &self,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
    ) -> Result<(i64, i64), RpcError> {
        let binding_revision = placement
            .authority_observed_binding_write_revision
            .ok_or_else(|| RpcError::FailedPrecondition("writer has no binding revision".into()))?;
        let revision = self
            .db
            .binding_write_revision(placement.binding_id, binding_revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("writer revision disappeared".into()))?;
        Ok((binding_revision, revision.write_credential_generation))
    }

    /// Parses and verifies an opaque placement resource version.
    pub(in crate::service) fn expected_placement_version(
        expected: &str,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
    ) -> Result<i64, RpcError> {
        let version = expected.parse::<i64>().map_err(|_| {
            RpcError::invalid("expectedResourceVersion must be a positive opaque version")
        })?;
        if version <= 0 {
            return Err(RpcError::invalid(
                "expectedResourceVersion must be a positive opaque version",
            ));
        }
        if version != placement.resource_version {
            return Err(RpcError::FailedPrecondition(
                "placement resource version is stale".to_string(),
            ));
        }
        Ok(version)
    }

    /// Requires an explicitly present proto3 optional placement field.
    pub(in crate::service) fn required_placement_field<T>(
        value: Option<T>,
        name: &str,
    ) -> Result<T, RpcError> {
        value.ok_or_else(|| RpcError::invalid(format!("{name} must be specified")))
    }

    /// Maps typed placement-create failures without parsing SQL-driver text.
    pub(in crate::service) fn placement_create_error(error: anyhow::Error) -> RpcError {
        let Some(failure) = aos_hub_db::db::surface_placement_create_failure(&error) else {
            return RpcError::internal(error);
        };
        match failure.kind() {
            aos_hub_db::db::SurfacePlacementCreateFailureKind::InvalidArgument => {
                RpcError::invalid(failure.public_message())
            }
            aos_hub_db::db::SurfacePlacementCreateFailureKind::AlreadyExists => {
                RpcError::AlreadyExists(failure.public_message().to_string())
            }
            aos_hub_db::db::SurfacePlacementCreateFailureKind::Conflict => {
                RpcError::FailedPrecondition(failure.public_message().to_string())
            }
        }
    }

    /// Returns a stable route-pin precondition without backend constraint text.
    pub(in crate::service) fn placement_route_pin_error(
        blockers: aos_hub_db::db::SurfacePlacementBlockers,
    ) -> Option<RpcError> {
        if blockers.direct_route {
            Some(RpcError::FailedPrecondition(
                "placement is pinned by a direct route".to_string(),
            ))
        } else if blockers.routed_policy {
            Some(RpcError::FailedPrecondition(
                "placement is pinned by a delivery-route placement policy".to_string(),
            ))
        } else {
            None
        }
    }

    /// Returns the first stable metadata-deletion precondition.
    pub(in crate::service) fn placement_delete_blocker_error(
        blockers: aos_hub_db::db::SurfacePlacementBlockers,
        registry_placement: bool,
    ) -> Option<RpcError> {
        if blockers.direct_route {
            Some(RpcError::FailedPrecondition(
                "placement is referenced by a direct route".to_string(),
            ))
        } else if blockers.policy_member {
            Some(RpcError::FailedPrecondition(
                "placement is referenced by a placement policy".to_string(),
            ))
        } else if blockers.object_presence && !registry_placement {
            Some(RpcError::FailedPrecondition(
                "placement has object-presence inventory".to_string(),
            ))
        } else if blockers.active_publication {
            Some(RpcError::FailedPrecondition(
                "placement has active registry-publication state".to_string(),
            ))
        } else if blockers.publication && !registry_placement {
            Some(RpcError::FailedPrecondition(
                "placement has registry-publication state".to_string(),
            ))
        } else if blockers.deletion_job {
            Some(RpcError::FailedPrecondition(
                "placement has object-deletion jobs".to_string(),
            ))
        } else if blockers.topology_operation {
            Some(RpcError::FailedPrecondition(
                "placement has topology operations".to_string(),
            ))
        } else {
            None
        }
    }

    /// Builds the public placement message without exposing database identity
    /// or backend-specific shard configuration.
    pub(in crate::service) async fn placement_message(
        &self,
        placement: aos_hub_db::db::SurfacePlacementRecord,
    ) -> Result<pb::Placement, RpcError> {
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!(
                    "placement '{}' references missing binding {}",
                    placement.name,
                    placement.binding_id
                ))
            })?;
        Self::placement_message_with_binding(placement, binding.name)
    }

    pub(in crate::service) async fn placement_policy_message(
        &self,
        identity: aos_hub_db::db::PlacementPolicyIdentityRecord,
    ) -> Result<pb::PlacementPolicy, RpcError> {
        let current = match identity.current_revision_id.as_deref() {
            Some(id) => self
                .db
                .placement_policy_revision(id)
                .await
                .map_err(RpcError::internal)?,
            None => None,
        };
        Ok(pb::PlacementPolicy {
            stable_id: identity.id,
            surface: Some(self.route_surface_message(identity.surface).await?),
            name: identity.name,
            kind: current
                .as_ref()
                .map(|revision| revision.spec.kind.clone())
                .unwrap_or_default(),
            current_revision: current
                .as_ref()
                .map(|revision| revision.revision)
                .unwrap_or_default(),
            current_content_digest: current
                .and_then(|revision| revision.content_digest)
                .unwrap_or_default(),
            resource_version: identity.resource_version.to_string(),
            created_at: identity.created_at,
            updated_at: identity.updated_at,
        })
    }

    pub(in crate::service) async fn placement_policy_revision_message(
        &self,
        revision: aos_hub_db::db::PlacementPolicyRevisionRecord,
    ) -> Result<pb::PlacementPolicyRevision, RpcError> {
        let (groups, members) = self
            .db
            .placement_policy_revision_shape(&revision.id)
            .await
            .map_err(RpcError::internal)?;
        let mut projected = Vec::with_capacity(groups.len());
        for group in &groups {
            let mut placement_names = Vec::new();
            for member in members
                .iter()
                .filter(|member| member.group_id == group.group_id)
            {
                placement_names.push(
                    self.db
                        .surface_placement(member.placement_id)
                        .await
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| {
                            RpcError::internal(anyhow::anyhow!(
                                "policy revision member placement is missing"
                            ))
                        })?
                        .name,
                );
            }
            let hash_range = if let (Some(start), Some(end)) = (group.range_start, group.range_end)
            {
                Some(pb::HashRangeV1 {
                    start: u32::try_from(start).map_err(|_| {
                        RpcError::internal(anyhow::anyhow!(
                            "persisted placement-policy range start is outside u32"
                        ))
                    })?,
                    end: u32::try_from(end).map_err(|_| {
                        RpcError::internal(anyhow::anyhow!(
                            "persisted placement-policy range end is outside u32"
                        ))
                    })?,
                })
            } else {
                None
            };
            projected.push(pb::PlacementPolicyReplicaGroup {
                placement_names,
                access_class: match group.purpose.as_str() {
                    "local" => pb::AccessClass::Local as i32,
                    "remote" => pb::AccessClass::Remote as i32,
                    _ => pb::AccessClass::Unspecified as i32,
                },
                hash_range,
            });
        }
        let selector = match revision.spec.kind.as_str() {
            "ordered_failover" => pb::placement_policy_revision_spec::Selector::OrderedFailover(
                pb::OrderedFailoverPlacementPolicy {
                    replica_groups: projected,
                },
            ),
            "local_then_remote" => pb::placement_policy_revision_spec::Selector::LocalThenRemote(
                pb::LocalThenRemotePlacementPolicy {
                    replica_groups: projected,
                    local_boundary: Some(pb::NetworkPolicyRevisionRef {
                        boundary_id: revision.spec.local_boundary_id.clone().unwrap_or_default(),
                        revision: revision.spec.local_boundary_revision.unwrap_or_default(),
                    }),
                    allow_remote_fallback: revision.spec.allow_remote_fallback.unwrap_or(false),
                },
            ),
            "hash_partition" => {
                let mut ranges = Vec::new();
                let mut complete_fallback_placements = Vec::new();
                for (record, message) in groups.iter().zip(projected) {
                    if record.purpose == "complete_fallback" {
                        complete_fallback_placements.extend(message.placement_names);
                    } else {
                        ranges.push(message);
                    }
                }
                pb::placement_policy_revision_spec::Selector::HashPartition(
                    pb::HashPartitionPlacementPolicy {
                        ranges,
                        complete_fallback_placements,
                    },
                )
            }
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "persisted placement policy kind is invalid"
                )));
            }
        };
        let retry_on = revision
            .spec
            .retry_on
            .iter()
            .map(|condition| Self::policy_retry_value(condition))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(pb::PlacementPolicyRevision {
            policy_id: revision.policy_id,
            revision: revision.revision,
            spec: Some(pb::PlacementPolicyRevisionSpec {
                selector: Some(selector),
                failure_contract: Some(pb::PolicyFailureContract { retry_on }),
            }),
            content_digest: revision.content_digest.unwrap_or_default(),
            created_by: revision.created_by,
            created_at: revision.created_at,
        })
    }

    pub(in crate::service) async fn normalize_placement_policy_request(
        &self,
        surface: SurfaceTarget,
        request: pb::PlanPlacementPolicyMutationRequest,
        owner_scope_key: String,
        baseline_policy_resource_version: Option<i64>,
    ) -> Result<PlacementPolicyMutationPlanInput, RpcError> {
        let desired = request
            .desired
            .as_ref()
            .ok_or_else(|| RpcError::invalid("desired policy revision is required"))?;
        let failure_contract = desired
            .failure_contract
            .as_ref()
            .ok_or_else(|| RpcError::invalid("failureContract is required"))?;
        let mut retry_names = Vec::with_capacity(failure_contract.retry_on.len());
        let mut unique_retry = BTreeSet::new();
        for condition in &failure_contract.retry_on {
            let name = Self::policy_retry_name(*condition)?;
            if !unique_retry.insert(name.clone()) {
                return Err(RpcError::invalid("retryOn cannot contain duplicates"));
            }
            retry_names.push(name);
        }
        let mut normalized_groups: Vec<(String, Option<(i64, i64)>, Vec<String>)> = Vec::new();
        let (kind, boundary, allow_remote_fallback) = match desired.selector.as_ref() {
            Some(pb::placement_policy_revision_spec::Selector::OrderedFailover(policy)) => {
                if policy.replica_groups.is_empty() {
                    return Err(RpcError::invalid(
                        "ordered failover requires at least one replica group",
                    ));
                }
                for group in &policy.replica_groups {
                    if group.access_class != pb::AccessClass::Unspecified as i32
                        || group.hash_range.is_some()
                    {
                        return Err(RpcError::invalid(
                            "ordered-failover groups forbid accessClass and hashRange",
                        ));
                    }
                    normalized_groups.push((
                        "ordered".to_string(),
                        None,
                        group.placement_names.clone(),
                    ));
                }
                ("ordered_failover".to_string(), None, None)
            }
            Some(pb::placement_policy_revision_spec::Selector::LocalThenRemote(policy)) => {
                if policy.replica_groups.is_empty() {
                    return Err(RpcError::invalid(
                        "local-then-remote requires at least one replica group",
                    ));
                }
                let boundary = policy.local_boundary.clone().ok_or_else(|| {
                    RpcError::invalid("localBoundary is required for local-then-remote")
                })?;
                if boundary.boundary_id.is_empty() || boundary.revision <= 0 {
                    return Err(RpcError::invalid(
                        "localBoundary must identify a positive exact revision",
                    ));
                }
                for group in &policy.replica_groups {
                    if group.hash_range.is_some() {
                        return Err(RpcError::invalid(
                            "local-then-remote groups forbid hashRange",
                        ));
                    }
                    let purpose = match pb::AccessClass::try_from(group.access_class) {
                        Ok(pb::AccessClass::Local) => "local",
                        Ok(pb::AccessClass::Remote) => "remote",
                        _ => {
                            return Err(RpcError::invalid(
                                "local-then-remote groups require local or remote accessClass",
                            ));
                        }
                    };
                    normalized_groups.push((
                        purpose.to_string(),
                        None,
                        group.placement_names.clone(),
                    ));
                }
                if normalized_groups.iter().all(|group| group.0 != "local")
                    || (policy.allow_remote_fallback
                        && normalized_groups.iter().all(|group| group.0 != "remote"))
                {
                    return Err(RpcError::invalid(
                        "local-then-remote group coverage is incomplete",
                    ));
                }
                (
                    "local_then_remote".to_string(),
                    Some(boundary),
                    Some(policy.allow_remote_fallback),
                )
            }
            Some(pb::placement_policy_revision_spec::Selector::HashPartition(policy)) => {
                if policy.ranges.is_empty() {
                    return Err(RpcError::invalid(
                        "hash partition requires at least one range",
                    ));
                }
                for group in &policy.ranges {
                    if group.access_class != pb::AccessClass::Unspecified as i32 {
                        return Err(RpcError::invalid(
                            "hash-partition ranges forbid accessClass",
                        ));
                    }
                    let range = group.hash_range.as_ref().ok_or_else(|| {
                        RpcError::invalid("hash-partition groups require hashRange")
                    })?;
                    if range.start >= range.end || range.end > 65_536 {
                        return Err(RpcError::invalid(
                            "hashRange must be a non-empty range within 0..65536",
                        ));
                    }
                    normalized_groups.push((
                        "hash_range".to_string(),
                        Some((i64::from(range.start), i64::from(range.end))),
                        group.placement_names.clone(),
                    ));
                }
                if !policy.complete_fallback_placements.is_empty() {
                    normalized_groups.push((
                        "complete_fallback".to_string(),
                        None,
                        policy.complete_fallback_placements.clone(),
                    ));
                }
                ("hash_partition".to_string(), None, None)
            }
            None => return Err(RpcError::invalid("policy selector is required")),
        };
        let mut groups = Vec::with_capacity(normalized_groups.len());
        let mut all_members = BTreeSet::new();
        for (index, (purpose, range, names)) in normalized_groups.into_iter().enumerate() {
            if names.is_empty() {
                return Err(RpcError::invalid(
                    "every placement-policy group requires at least one member",
                ));
            }
            let mut members = Vec::with_capacity(names.len());
            let mut local_members = BTreeSet::new();
            for name in names {
                if !local_members.insert(name.clone()) || !all_members.insert(name.clone()) {
                    return Err(RpcError::invalid(
                        "a placement may occur only once in a policy revision",
                    ));
                }
                let placement = self.topology_placement(surface, &name).await?;
                let expected_kind = if purpose == "hash_range" {
                    "shard"
                } else {
                    "complete"
                };
                if placement.kind != expected_kind {
                    return Err(RpcError::invalid(format!(
                        "placement '{name}' must be {expected_kind} for this group"
                    )));
                }
                if purpose == "hash_range"
                    && placement.hash_range_start.zip(placement.hash_range_end) != range
                {
                    return Err(RpcError::invalid(format!(
                        "shard placement '{name}' does not match its policy range"
                    )));
                }
                members.push(PlacementPolicyMemberPlanSeal {
                    name,
                    placement_id: placement.id,
                    resource_version: placement.resource_version,
                    kind: placement.kind,
                });
            }
            groups.push(PlacementPolicyGroupPlanSeal {
                group_id: format!("group:{index}"),
                purpose,
                range_start: range.map(|value| value.0),
                range_end: range.map(|value| value.1),
                members,
            });
        }
        let (local_boundary_id, local_boundary_revision, local_boundary_content_digest) =
            if let Some(boundary) = boundary {
                let record = self
                    .db
                    .network_policy_revision(&boundary.boundary_id, boundary.revision)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("network policy revision"))?;
                if record.lifecycle_state != "active" || record.observation_state != "verified" {
                    return Err(RpcError::FailedPrecondition(
                        "local boundary revision must be active and verified".to_string(),
                    ));
                }
                (
                    Some(record.boundary_id),
                    Some(record.revision),
                    Some(record.content_digest),
                )
            } else {
                (None, None, None)
            };
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        Ok(PlacementPolicyMutationPlanInput {
            request,
            registry_id,
            cache_id,
            owner_scope_key,
            baseline_policy_resource_version,
            kind,
            local_boundary_id,
            local_boundary_revision,
            local_boundary_content_digest,
            allow_remote_fallback,
            retry_on: retry_names,
            groups,
        })
    }

    pub(in crate::service) async fn plan_placement_policy_mutation(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanPlacementPolicyMutationRequest,
        create: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        if req.policy_id.is_empty() {
            return Err(RpcError::invalid("policyId is required"));
        }
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        let existing = self
            .db
            .placement_policy_identity(&req.policy_id)
            .await
            .map_err(RpcError::internal)?;
        let baseline = if create {
            if existing.is_some() {
                return Err(RpcError::AlreadyExists(
                    "placement policy already exists".to_string(),
                ));
            }
            if req.name.trim().is_empty() {
                return Err(RpcError::invalid("name is required"));
            }
            let expected = req.expected_resource_version.as_deref().unwrap_or("0");
            if expected != "0" {
                return Err(RpcError::invalid(
                    "policy creation requires expectedResourceVersion=0",
                ));
            }
            None
        } else {
            let identity = existing
                .filter(|identity| identity.surface == surface)
                .ok_or_else(|| RpcError::not_found("placement policy"))?;
            if !req.name.is_empty() && req.name != identity.name {
                return Err(RpcError::invalid(
                    "policy revision cannot rename the policy identity",
                ));
            }
            req.name = identity.name;
            let expected = parse_resource_version(
                req.expected_resource_version
                    .as_deref()
                    .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
                identity.resource_version,
            )?;
            if expected != identity.resource_version {
                return Err(RpcError::FailedPrecondition(
                    "placement-policy resource version is stale".to_string(),
                ));
            }
            Some(expected)
        };
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let input = self
            .normalize_placement_policy_request(surface, req, owner_scope_key, baseline)
            .await?;
        let plan_kind = if create {
            "create_placement_policy"
        } else {
            "revise_placement_policy"
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &Self::topology_scope(input.registry_id, input.cache_id),
            &input,
            &idempotency_key,
            vec![format!(
                "{} immutable revision for placement policy '{}'",
                if create {
                    "create an initial"
                } else {
                    "publish a new"
                },
                input.request.policy_id
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    pub(in crate::service) async fn apply_placement_policy_mutation(
        &self,
        auth: Option<&str>,
        req: &pb::ApplyTopologyPlanRequest,
        plan_kind: &str,
    ) -> Result<
        (
            aos_hub_db::db::TopologyPlanRecord,
            aos_hub_db::db::PlacementPolicyIdentityRecord,
            aos_hub_db::db::PlacementPolicyRevisionRecord,
        ),
        RpcError,
    > {
        let (plan, input): (_, PlacementPolicyMutationPlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        self.require_delivery_scope(
            auth,
            &input.owner_scope_key,
            Permission::PlacementPolicyManage,
        )
        .await?;
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id)
            || self.route_surface_owner_scope(surface).await? != input.owner_scope_key
        {
            return Err(RpcError::FailedPrecondition(
                "placement-policy surface changed after planning".to_string(),
            ));
        }
        for group in &input.groups {
            for member in &group.members {
                let placement = self
                    .db
                    .surface_placement(member.placement_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::FailedPrecondition(
                            "policy placement disappeared after planning".to_string(),
                        )
                    })?;
                if Self::topology_surface_ids(surface)
                    != (placement.registry_id, placement.cache_id)
                    || placement.name != member.name
                    || placement.kind != member.kind
                    || placement.resource_version != member.resource_version
                {
                    return Err(RpcError::FailedPrecondition(format!(
                        "policy placement '{}' changed after planning",
                        member.name
                    )));
                }
            }
        }
        if let (Some(id), Some(revision), Some(digest)) = (
            input.local_boundary_id.as_deref(),
            input.local_boundary_revision,
            input.local_boundary_content_digest.as_deref(),
        ) {
            let boundary = self
                .db
                .network_policy_revision(id, revision)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "local boundary disappeared after planning".to_string(),
                    )
                })?;
            if boundary.content_digest != digest
                || boundary.lifecycle_state != "active"
                || boundary.observation_state != "verified"
            {
                return Err(RpcError::FailedPrecondition(
                    "local boundary changed after policy planning".to_string(),
                ));
            }
        }
        let create = plan_kind == "create_placement_policy";
        let mut identity = match self
            .db
            .placement_policy_identity(&input.request.policy_id)
            .await
            .map_err(RpcError::internal)?
        {
            Some(identity) => identity,
            None if create => self
                .db
                .create_placement_policy_identity(
                    surface,
                    &input.request.policy_id,
                    &input.request.name,
                    &plan.plan_id,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?,
            None => return Err(RpcError::not_found("placement policy")),
        };
        if identity.surface != surface || identity.name != input.request.name {
            return Err(RpcError::FailedPrecondition(
                "placement-policy identity changed after planning".to_string(),
            ));
        }
        if create && identity.creation_token != plan.plan_id {
            return Err(RpcError::FailedPrecondition(
                "placement-policy identity was created by another plan".to_string(),
            ));
        }
        let expected_head_version = input
            .baseline_policy_resource_version
            .unwrap_or(identity.resource_version);
        if identity.resource_version == expected_head_version + 1 {
            let current_id = identity.current_revision_id.as_deref().ok_or_else(|| {
                RpcError::internal(anyhow::anyhow!("published policy has no current revision"))
            })?;
            let current = self
                .db
                .placement_policy_revision(current_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::internal(anyhow::anyhow!("current revision is missing"))
                })?;
            let projected = self
                .placement_policy_revision_message(current.clone())
                .await?;
            if projected.spec == input.request.desired {
                return Ok((plan, identity, current));
            }
            return Err(RpcError::FailedPrecondition(
                "placement policy advanced to a different revision".to_string(),
            ));
        }
        if identity.resource_version != expected_head_version {
            return Err(RpcError::FailedPrecondition(
                "placement policy changed after planning".to_string(),
            ));
        }
        let revision_spec = aos_hub_db::db::PlacementPolicyRevisionSpec {
            kind: input.kind.clone(),
            local_boundary_id: input.local_boundary_id.clone(),
            local_boundary_revision: input.local_boundary_revision,
            allow_remote_fallback: input.allow_remote_fallback,
            hash_rule: (input.kind == "hash_partition").then(|| "hash_range_v1".to_string()),
            expected_group_count: i64::try_from(input.groups.len()).map_err(RpcError::internal)?,
            expected_member_count: i64::try_from(
                input
                    .groups
                    .iter()
                    .map(|group| group.members.len())
                    .sum::<usize>(),
            )
            .map_err(RpcError::internal)?,
            retry_on: input.retry_on.clone(),
        };
        let revisions = self
            .db
            .list_placement_policy_revisions(&identity.id)
            .await
            .map_err(RpcError::internal)?;
        let mut revision = if let Some(building) = revisions
            .into_iter()
            .find(|revision| revision.state == "building" && revision.spec == revision_spec)
        {
            building
        } else {
            let claims = self.require_claims(auth)?;
            self.db
                .begin_placement_policy_revision(
                    &identity.id,
                    &input.owner_scope_key,
                    &revision_spec,
                    expected_head_version,
                    &claims.sub,
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?
        };
        for group in &input.groups {
            let (existing_groups, _) = self
                .db
                .placement_policy_revision_shape(&revision.id)
                .await
                .map_err(RpcError::internal)?;
            if !existing_groups
                .iter()
                .any(|record| record.group_id == group.group_id)
            {
                revision = self
                    .db
                    .add_placement_policy_group(
                        &revision.id,
                        revision.build_version,
                        &group.group_id,
                        i64::try_from(existing_groups.len()).map_err(RpcError::internal)?,
                        &group.purpose,
                        group.range_start,
                        group.range_end,
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
            for member in &group.members {
                let (_, existing_members) = self
                    .db
                    .placement_policy_revision_shape(&revision.id)
                    .await
                    .map_err(RpcError::internal)?;
                if existing_members.iter().any(|record| {
                    record.group_id == group.group_id && record.placement_id == member.placement_id
                }) {
                    continue;
                }
                let member_order = i64::try_from(
                    existing_members
                        .iter()
                        .filter(|record| record.group_id == group.group_id)
                        .count(),
                )
                .map_err(RpcError::internal)?;
                revision = if member.kind == "shard" {
                    self.db
                        .add_placement_policy_shard_member(
                            &revision.id,
                            revision.build_version,
                            &group.group_id,
                            member.placement_id,
                            member_order,
                        )
                        .await
                } else {
                    self.db
                        .add_placement_policy_complete_member(
                            &revision.id,
                            revision.build_version,
                            &group.group_id,
                            member.placement_id,
                            member_order,
                        )
                        .await
                }
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
        }
        let claims = self.require_claims(auth)?;
        revision = self
            .db
            .publish_placement_policy_revision(
                &revision.id,
                revision.build_version,
                expected_head_version,
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        identity = self
            .db
            .placement_policy_identity(&identity.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("published policy disappeared")))?;
        Ok((plan, identity, revision))
    }

    pub(in crate::service) async fn placement_equivalence_message(
        &self,
        record: aos_hub_db::db::PlacementEquivalenceRecord,
    ) -> Result<pb::PlacementEquivalence, RpcError> {
        Ok(pb::PlacementEquivalence {
            stable_id: record.id,
            surface: Some(self.route_surface_message(record.surface).await?),
            placement_a: record.placement_a,
            placement_b: record.placement_b,
            evidence_digest: record.evidence_digest,
            state: record.state,
            resource_version: record.resource_version.to_string(),
            confirmed_at: record.confirmed_at,
        })
    }

    /// Persists an exact placement lifecycle transition plan.
    pub(in crate::service) async fn plan_placement_lifecycle(
        &self,
        auth: Option<&str>,
        mut req: pb::PlacementMutationRequest,
        plan_kind: &str,
        resulting_state: &str,
        resulting_read_enabled: bool,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let current = self
            .topology_placement(surface, &req.placement_name)
            .await?;
        let expected = Self::expected_placement_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            &current,
        )?;
        if plan_kind == "drain_placement" {
            if current.authority_desired_placement_id == Some(current.id)
                || current.authority_observed_placement_id == Some(current.id)
            {
                return Err(RpcError::FailedPrecondition(
                    "an authority-owned placement cannot drain before write authority moves"
                        .to_string(),
                ));
            }
            let blockers = self
                .db
                .surface_placement_blockers(current.id)
                .await
                .map_err(RpcError::internal)?;
            if let Some(error) = Self::placement_route_pin_error(blockers) {
                return Err(error);
            }
            if current.desired_state != "active" {
                return Err(RpcError::FailedPrecondition(
                    "only an active placement may begin draining".to_string(),
                ));
            }
        } else if current.desired_state != "draining" {
            return Err(RpcError::FailedPrecondition(
                "only a draining placement may cancel its drain".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementLifecyclePlanInput {
            request: req,
            registry_id,
            cache_id,
            placement_id: current.id,
            baseline_resource_version: expected,
            resulting_state: resulting_state.to_string(),
            resulting_read_enabled,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            plan_kind,
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![
                format!("set placement desired state to {resulting_state}"),
                format!("set placement read selection to {resulting_read_enabled}"),
            ],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Applies a reviewed placement lifecycle transition exactly once.
    pub(in crate::service) async fn apply_placement_lifecycle(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
        plan_kind: &str,
    ) -> Result<
        (
            aos_hub_db::db::TopologyPlanRecord,
            aos_hub_db::db::SurfacePlacementRecord,
        ),
        RpcError,
    > {
        self.begin_control_plan_apply(
            auth,
            &req.plan_id,
            plan_kind,
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementLifecyclePlanInput) = self
            .load_control_plan(auth, &req.plan_id, plan_kind, Some(&req.confirmation_hash))
            .await?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id) {
            return Err(RpcError::FailedPrecondition(
                "placement plan belongs to another surface".to_string(),
            ));
        }
        let current = self
            .db
            .surface_placement(input.placement_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".to_string()))?;
        if current.name != input.request.placement_name
            || current.registry_id != input.registry_id
            || current.cache_id != input.cache_id
        {
            return Err(RpcError::FailedPrecondition(
                "placement identity changed after planning".to_string(),
            ));
        }
        if current.resource_version == input.baseline_resource_version + 1
            && current.desired_state == input.resulting_state
            && current.desired_read_enabled == input.resulting_read_enabled
        {
            return Ok((plan, current));
        }
        if current.resource_version != input.baseline_resource_version {
            return Err(RpcError::FailedPrecondition(
                "placement changed after lifecycle planning".to_string(),
            ));
        }
        if plan_kind == "drain_placement" {
            if current.authority_desired_placement_id == Some(current.id)
                || current.authority_observed_placement_id == Some(current.id)
            {
                return Err(RpcError::FailedPrecondition(
                    "placement gained write authority after drain planning".to_string(),
                ));
            }
            let blockers = self
                .db
                .surface_placement_blockers(current.id)
                .await
                .map_err(RpcError::internal)?;
            if let Some(error) = Self::placement_route_pin_error(blockers) {
                return Err(error);
            }
        }
        let read_order = current.read_order;
        let placement = self
            .db
            .update_surface_placement(
                current.id,
                &aos_hub_db::db::UpdateSurfacePlacementSpec {
                    expected_version: input.baseline_resource_version,
                    desired_state: input.resulting_state,
                    desired_read_enabled: input.resulting_read_enabled,
                    read_order,
                },
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        Ok((plan, placement))
    }

    /// Creates or replays one placement-scoped durable operation.
    pub(in crate::service) async fn schedule_placement_operation(
        &self,
        operation_kind: &str,
        idempotency_key: &str,
        targets: Vec<(String, aos_hub_db::db::SurfacePlacementRecord)>,
    ) -> Result<pb::OperationResponse, RpcError> {
        if idempotency_key.is_empty() {
            return Err(RpcError::invalid("idempotencyKey is required"));
        }
        let semantic_targets = targets
            .iter()
            .map(|(role, placement)| (role, placement.id, placement.resource_version))
            .collect::<Vec<_>>();
        let operation_id = hex::encode(Sha256::digest(
            serde_json::to_vec(&(operation_kind, idempotency_key, semantic_targets))
                .map_err(RpcError::internal)?,
        ));
        let operation = match self
            .db
            .topology_operation(&operation_id)
            .await
            .map_err(RpcError::internal)?
        {
            Some(operation) => operation,
            None => self
                .db
                .create_topology_operation(&aos_hub_db::db::NewTopologyOperation {
                    operation_id,
                    operation_kind: operation_kind.to_string(),
                    control_permission: Permission::StorageManage,
                    targets: targets
                        .into_iter()
                        .map(
                            |(role, placement)| aos_hub_db::db::NewTopologyOperationTarget {
                                role,
                                target: aos_hub_db::db::NewTopologyOperationTargetRef::Placement(
                                    placement.id,
                                ),
                                generation_key: placement.resource_version,
                                configuration_digest: String::new(),
                            },
                        )
                        .collect(),
                    detail_json: serde_json::json!({"phase":"pending"}).to_string(),
                    progress_total: None,
                })
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?,
        };
        if matches!(operation.state.as_str(), "pending" | "running") {
            self.topology_probes
                .wake_controller()
                .await
                .map_err(RpcError::internal)?;
        }
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }

    /// Schedules a complete inventory scan for one placement.
    pub(in crate::service) async fn execute_scan_placement(
        &self,
        auth: Option<&str>,
        req: pb::PlanScanPlacementRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let placement = self
            .topology_placement(surface, &req.placement_name)
            .await?;
        if parse_resource_version(&req.expected_resource_version, placement.resource_version)?
            != placement.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "placement resource version is stale".to_string(),
            ));
        }
        self.schedule_placement_operation(
            "scan_placement",
            &req.idempotency_key,
            vec![("primary".to_string(), placement)],
        )
        .await
    }

    /// Pins the destination's current validated binding revision for physical copies.
    pub(in crate::service) async fn bind_placement_copy_capability(
        &self,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
    ) -> Result<(), RpcError> {
        if self
            .db
            .placement_publication_write_revision(placement.id)
            .await
            .map_err(RpcError::internal)?
            .is_some()
        {
            return Ok(());
        }
        if placement.kind != "complete" || placement.desired_state != "active" {
            return Err(RpcError::FailedPrecondition(
                "a physical copy destination must be an active complete placement".to_string(),
            ));
        }

        let state = self
            .db
            .binding_write_state(placement.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "the destination binding has no write-revision state".to_string(),
                )
            })?;
        let revision_number = state.current_write_revision.ok_or_else(|| {
            RpcError::FailedPrecondition(
                "the destination binding has no current write revision".to_string(),
            )
        })?;
        let observation = self
            .db
            .binding_write_observation(placement.binding_id, revision_number)
            .await
            .map_err(RpcError::internal)?;
        if !observation.is_some_and(|observation| observation.state == "valid") {
            return Err(RpcError::FailedPrecondition(
                "the destination binding's current write revision is not valid".to_string(),
            ));
        }
        let revision = self
            .db
            .binding_write_revision(placement.binding_id, revision_number)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "the destination binding's current write revision is missing".to_string(),
                )
            })?;
        if !revision.writes_supported {
            return Err(RpcError::FailedPrecondition(
                "the destination binding's current revision does not support writes".to_string(),
            ));
        }
        if placement.requires_conditional_writes && !revision.conditional_writes_supported {
            return Err(RpcError::FailedPrecondition(
                "the destination requires conditional writes but its binding revision does not support them"
                    .to_string(),
            ));
        }
        let credential = self
            .db
            .binding_credential_revision(
                placement.binding_id,
                &revision.write_credential_purpose,
                revision.write_credential_generation,
            )
            .await
            .map_err(RpcError::internal)?;
        if !credential.is_some_and(|credential| credential.validation_state == "valid") {
            return Err(RpcError::FailedPrecondition(
                "the destination binding's write credential is not valid".to_string(),
            ));
        }

        self.db
            .bind_surface_placement_write_capability(placement.id, revision_number)
            .await
            .map_err(Self::authority_mutation_error)
    }

    /// Schedules replication from one placement to another on the same surface.
    pub(in crate::service) async fn execute_replicate_placement(
        &self,
        auth: Option<&str>,
        req: pb::PlanReplicatePlacementRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if req.source_placement_name == req.destination_placement_name {
            return Err(RpcError::invalid(
                "source and destination placements must differ",
            ));
        }
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let source = self
            .topology_placement(surface, &req.source_placement_name)
            .await?;
        let destination = self
            .topology_placement(surface, &req.destination_placement_name)
            .await?;
        if parse_resource_version(&req.expected_resource_version, destination.resource_version)?
            != destination.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "destination placement resource version is stale".to_string(),
            ));
        }
        if destination.desired_state == "offline" {
            return Err(RpcError::FailedPrecondition(
                "an offline placement cannot receive replication".to_string(),
            ));
        }
        if source.state != "ready" || source.completeness != "complete" {
            return Err(RpcError::FailedPrecondition(
                "replication requires a ready, complete source placement".to_string(),
            ));
        }
        self.bind_placement_copy_capability(&destination).await?;
        self.schedule_placement_operation(
            "replicate_placement",
            &req.idempotency_key,
            vec![
                ("source".to_string(), source),
                ("primary".to_string(), destination),
            ],
        )
        .await
    }

    /// Schedules repair of one placement, optionally from a named source.
    pub(in crate::service) async fn execute_repair_placement(
        &self,
        auth: Option<&str>,
        req: pb::PlanRepairPlacementRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if !req.source_placement_name.is_empty() && req.source_placement_name == req.placement_name
        {
            return Err(RpcError::invalid(
                "repair source and destination placements must differ",
            ));
        }
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let destination = self
            .topology_placement(surface, &req.placement_name)
            .await?;
        if parse_resource_version(&req.expected_resource_version, destination.resource_version)?
            != destination.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "placement resource version is stale".to_string(),
            ));
        }
        let source = if req.source_placement_name.is_empty() {
            self.db
                .list_surface_placements(surface)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .find(|placement| {
                    placement.id != destination.id
                        && placement.desired_state == "active"
                        && placement.state == "ready"
                        && placement.completeness == "complete"
                })
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "repair requires another ready, complete source placement".to_string(),
                    )
                })?
        } else {
            self.topology_placement(surface, &req.source_placement_name)
                .await?
        };
        if source.state != "ready" || source.completeness != "complete" {
            return Err(RpcError::FailedPrecondition(
                "repair requires a ready, complete source placement".to_string(),
            ));
        }
        self.bind_placement_copy_capability(&destination).await?;
        let mut targets = vec![("source".to_string(), source)];
        targets.push(("primary".to_string(), destination));
        self.schedule_placement_operation("repair_placement", &req.idempotency_key, targets)
            .await
    }

    /// Reads required upload destinations without changing publication watermarks.
    pub(in crate::service) async fn registry_publication_required_placements(
        &self,
        publication_id: &str,
    ) -> Result<Vec<aos_hub_db::db::SurfacePlacementRecord>, RpcError> {
        let progress = self
            .db
            .registry_publication_placement_records(publication_id)
            .await
            .map_err(RpcError::internal)?;
        let mut placements = Vec::new();
        for required in progress.iter().filter(|placement| placement.required) {
            let placement = self
                .db
                .surface_placement(required.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition("required placement disappeared".into())
                })?;
            placements.push(placement);
        }
        if placements.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "publication has no required placements".into(),
            ));
        }
        Ok(placements)
    }
}
