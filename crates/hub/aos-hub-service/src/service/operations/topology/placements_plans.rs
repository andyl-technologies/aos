//! Placements plans in the topology capability.

use super::*;

impl RpcService {
    /// Plans creation of a stable policy identity and its first revision.
    pub async fn plan_create_placement_policy(
        &self,
        auth: Option<&str>,
        req: pb::PlanPlacementPolicyMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_placement_policy_mutation(auth, req, true).await
    }

    /// Plans publication of a new immutable policy revision.
    pub async fn plan_revise_placement_policy(
        &self,
        auth: Option<&str>,
        req: pb::PlanPlacementPolicyMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_placement_policy_mutation(auth, req, false).await
    }

    /// Plans confirmation that two exact placements address the same bytes.
    pub async fn plan_confirm_placement_equivalence(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanPlacementEquivalenceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let combined_version = format!(
            "{}|{}",
            req.expected_a_resource_version
                .as_deref()
                .unwrap_or_default(),
            req.expected_b_resource_version
                .as_deref()
                .unwrap_or_default()
        );
        if req.expected_resource_version != combined_version {
            return Err(RpcError::FailedPrecondition(
                "placement-equivalence resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        if req.placement_a.is_empty()
            || req.placement_b.is_empty()
            || req.placement_a == req.placement_b
        {
            return Err(RpcError::invalid(
                "two distinct placement names are required",
            ));
        }
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let a = self.topology_placement(surface, &req.placement_a).await?;
        let b = self.topology_placement(surface, &req.placement_b).await?;
        let a_version = Self::expected_placement_version(
            req.expected_a_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedAResourceVersion is required"))?,
            &a,
        )?;
        let b_version = Self::expected_placement_version(
            req.expected_b_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedBResourceVersion is required"))?,
            &b,
        )?;
        if a.state != "ready"
            || b.state != "ready"
            || a.completeness != "complete"
            || b.completeness != "complete"
        {
            return Err(RpcError::FailedPrecondition(
                "equivalence confirmation requires two ready, complete placements".to_string(),
            ));
        }
        let a_observation_version = a.observation_version.ok_or_else(|| {
            RpcError::FailedPrecondition("placement A has no observation version".to_string())
        })?;
        let b_observation_version = b.observation_version.ok_or_else(|| {
            RpcError::FailedPrecondition("placement B has no observation version".to_string())
        })?;
        let a_fingerprint = self.placement_physical_identity_fingerprint(&a).await?;
        let b_fingerprint = self.placement_physical_identity_fingerprint(&b).await?;
        if a_fingerprint != b_fingerprint {
            return Err(RpcError::FailedPrecondition(
                "placements resolve to different physical object identities".to_string(),
            ));
        }
        let a_inventory_digest = self
            .db
            .placement_inventory_digest(a.id)
            .await
            .map_err(RpcError::internal)?;
        let b_inventory_digest = self
            .db
            .placement_inventory_digest(b.id)
            .await
            .map_err(RpcError::internal)?;
        if a_inventory_digest != b_inventory_digest {
            return Err(RpcError::FailedPrecondition(
                "placements do not contain the same observed object inventory".to_string(),
            ));
        }
        let evidence_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&(
                &a_fingerprint,
                a.id,
                a_version,
                a_observation_version,
                &a_inventory_digest,
                b.id,
                b_version,
                b_observation_version,
                &b_inventory_digest,
            ))
            .map_err(RpcError::internal)?,
        ));
        let stable_id = format!("equivalence:{}", &evidence_digest[..32]);
        if self
            .db
            .list_placement_equivalences(surface)
            .await
            .map_err(RpcError::internal)?
            .iter()
            .any(|record| {
                (record.placement_a == req.placement_a && record.placement_b == req.placement_b)
                    || (record.placement_a == req.placement_b
                        && record.placement_b == req.placement_a)
            })
        {
            return Err(RpcError::AlreadyExists(
                "placement equivalence already exists".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementEquivalencePlanInput {
            request: req,
            registry_id,
            cache_id,
            placement_a_id: a.id,
            placement_a_version: a_version,
            placement_a_observation_version: a_observation_version,
            placement_a_inventory_digest: a_inventory_digest,
            placement_b_id: b.id,
            placement_b_version: b_version,
            placement_b_observation_version: b_observation_version,
            placement_b_inventory_digest: b_inventory_digest,
            physical_identity_fingerprint: a_fingerprint,
            evidence_digest,
            stable_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "confirm_placement_equivalence",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![format!(
                "confirm '{}' and '{}' as the same physical object namespace",
                input.request.placement_a, input.request.placement_b
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans deletion of one placement equivalence.
    pub async fn plan_delete_placement_equivalence(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanDeleteTopologyResourceRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let record = self
            .db
            .placement_equivalence(&req.stable_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("placement equivalence"))?;
        let surface_ref = Some(self.route_surface_message(record.surface).await?);
        let (surface, _) = self.writable_topology_surface(auth, surface_ref).await?;
        let expected = parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            record.resource_version,
        )?;
        if expected != record.resource_version {
            return Err(RpcError::FailedPrecondition(
                "placement-equivalence resource version is stale".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementEquivalenceDeletePlanInput {
            stable_id: req.stable_id,
            registry_id,
            cache_id,
            baseline_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_placement_equivalence",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec!["remove the explicit physical-equivalence assertion".to_string()],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// `TopologyService.PlanCreatePlacement` validates and persists an immutable creation plan.
    ///
    /// # Errors
    ///
    /// Returns the placement mutation's authorization, validation, conflict, or
    /// persistence error without creating topology state.
    pub async fn plan_create_placement(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanCreatePlacementRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        require_absent_resource_version(&req.expected_resource_version)?;
        let claims = self.require_claims(auth)?;
        let (surface, org_id) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        if req.name.is_empty() {
            return Err(RpcError::invalid("placement name must not be empty"));
        }
        if self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .iter()
            .any(|placement| placement.name == req.name)
        {
            return Err(RpcError::AlreadyExists(
                "placement already exists".to_string(),
            ));
        }
        Self::validate_placement_shape(
            &req.kind,
            &req.desired_state,
            req.desired_read_enabled,
            req.read_order,
            req.hash_range.as_ref(),
        )?;
        let binding_id = self.topology_binding_id(org_id, &req.binding_id).await?;
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementCreatePlanInput {
            request: req,
            registry_id,
            cache_id,
            org_id,
            binding_db_id: binding_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "create_placement",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![format!(
                "create placement '{}' without write authority",
                input.request.name
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// `TopologyService.PlanUpdatePlacement` persists a reviewed replacement plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, validation, stale-version, or persistence error.
    pub async fn plan_update_placement(
        &self,
        auth: Option<&str>,
        mut req: pb::PlanUpdatePlacementRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let current = self.topology_placement(surface, &req.name).await?;
        let expected = Self::expected_placement_version(&req.expected_resource_version, &current)?;
        let mut mask = req.update_mask.iter().cloned().collect::<BTreeSet<_>>();
        if mask.len() != req.update_mask.len() || mask.is_empty() {
            return Err(RpcError::invalid(
                "updateMask must contain unique mutable placement fields",
            ));
        }
        if !mask.iter().all(|field| {
            matches!(
                field.as_str(),
                "desired_state" | "desired_read_enabled" | "read_order"
            )
        }) {
            return Err(RpcError::invalid(
                "updateMask contains an immutable or unknown field",
            ));
        }
        let desired_state = if mask.contains("desired_state") {
            req.desired_state.clone()
        } else {
            current.desired_state.clone()
        };
        let desired_read_enabled = if mask.contains("desired_read_enabled") {
            Self::required_placement_field(req.desired_read_enabled, "desiredReadEnabled")?
        } else {
            current.desired_read_enabled
        };
        let read_order = if mask.contains("read_order") {
            Self::required_placement_field(req.read_order, "readOrder")?
        } else {
            current.read_order
        };
        if !matches!(desired_state.as_str(), "active" | "offline") {
            return Err(RpcError::invalid("desiredState must be active or offline"));
        }
        if current.kind == "archive" && desired_read_enabled {
            return Err(RpcError::invalid(
                "archive placements cannot be read-enabled",
            ));
        }
        req.desired_state = desired_state;
        req.desired_read_enabled = Some(desired_read_enabled);
        req.read_order = Some(read_order);
        req.update_mask = std::mem::take(&mut mask).into_iter().collect();
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementUpdatePlanInput {
            request: req,
            registry_id,
            cache_id,
            placement_id: current.id,
            baseline_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "update_placement",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![format!(
                "replace selected desired fields on placement '{}'",
                input.request.name
            )],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// `TopologyService.PlanPromotePlacement` — stores immutable promotion preconditions.
    ///
    /// Planning is read-only with respect to placement and authority resources.
    /// It resolves the binding's current validated write revision and rejects a
    /// candidate whose desired or observed state cannot own writes.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown candidate, and [`RpcError::FailedPrecondition`] when the
    /// candidate or current authority is not promotable.
    pub async fn plan_promote_placement(
        &self,
        auth: Option<&str>,
        req: pb::PlacementMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let mut semantic_request = req.clone();
        semantic_request.idempotency_key.clear();
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let candidate = self
            .topology_placement(surface, &req.placement_name)
            .await?;
        if parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            candidate.resource_version,
        )? != candidate.resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "candidate placement resource version is stale".to_string(),
            ));
        }
        if candidate.kind != "complete"
            || candidate.desired_state != "active"
            || candidate.state != "ready"
            || candidate.completeness != "complete"
        {
            return Err(RpcError::FailedPrecondition(
                "the candidate must be a ready, complete, active complete placement".to_string(),
            ));
        }
        let write_state = self
            .db
            .binding_write_state(candidate.binding_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "the candidate binding has no write-revision state".to_string(),
                )
            })?;
        let binding_revision = write_state.current_write_revision.ok_or_else(|| {
            RpcError::FailedPrecondition(
                "the candidate binding has no current write revision".to_string(),
            )
        })?;
        let observation = self
            .db
            .binding_write_observation(candidate.binding_id, binding_revision)
            .await
            .map_err(RpcError::internal)?;
        if !observation.is_some_and(|observation| observation.state == "valid") {
            return Err(RpcError::FailedPrecondition(
                "the candidate binding's current write revision is not valid".to_string(),
            ));
        }
        let revision = self
            .db
            .binding_write_revision(candidate.binding_id, binding_revision)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "the candidate binding's current write revision is missing".to_string(),
                )
            })?;
        if !revision.writes_supported {
            return Err(RpcError::FailedPrecondition(
                "the candidate binding's current revision does not support writes".to_string(),
            ));
        }
        if candidate.requires_conditional_writes && !revision.conditional_writes_supported {
            return Err(RpcError::FailedPrecondition(
                "the candidate requires conditional writes but its binding revision does not support them"
                    .to_string(),
            ));
        }
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?;
        let (
            authority_incarnation_id,
            authority_id,
            authority_resource_version,
            authority_desired_generation,
            observed_placement_id,
            observed_name,
        ) = match authority {
            Some(authority) => {
                if authority.reconciliation_state != "ready"
                    || authority.observed_placement_id != Some(authority.desired_placement_id)
                    || authority.observed_generation != Some(authority.desired_generation)
                {
                    return Err(RpcError::FailedPrecondition(
                            "the current write authority must finish reconciling before another promotion"
                                .to_string(),
                        ));
                }
                let observed_id = authority.observed_placement_id.ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "the current write authority has no observed writer".to_string(),
                    )
                })?;
                let observed = self
                    .db
                    .surface_placement(observed_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::internal(anyhow::anyhow!("observed writer is missing"))
                    })?;
                (
                    authority.incarnation_id,
                    Some(authority.id),
                    Some(authority.resource_version),
                    Some(authority.desired_generation),
                    Some(observed_id),
                    Some(observed.name),
                )
            }
            None => (
                format!(
                    "auth:{}",
                    &hex::encode(Sha256::digest(
                        serde_json::to_vec(&(
                            claims.owner_kind.as_str(),
                            claims.owner_id,
                            &semantic_request,
                        ))
                        .map_err(RpcError::internal)?
                    ))[..32]
                ),
                None,
                None,
                None,
                None,
                None,
            ),
        };
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementPromotionPlanInput {
            request: semantic_request,
            registry_id,
            cache_id,
            candidate_placement_id: candidate.id,
            candidate_placement_name: candidate.name.clone(),
            candidate_resource_version: candidate.resource_version,
            candidate_write_spec_version: candidate.write_spec_version,
            candidate_binding_write_revision: binding_revision,
            authority_incarnation_id: authority_incarnation_id.clone(),
            authority_id,
            authority_resource_version,
            authority_desired_generation,
            observed_placement_id,
            observed_placement_name: observed_name.clone(),
        };
        let effects = if authority_id.is_some() {
            vec![
                "fence Hub writes while desired authority reconciles".to_string(),
                format!("request '{}' as the single writer", candidate.name),
                "preserve the observed writer until reconciliation confirms the new generation"
                    .to_string(),
            ]
        } else {
            vec![
                format!(
                    "establish '{}' as the initial single writer",
                    candidate.name
                ),
                "activate the already validated placement and binding-write tuple".to_string(),
            ]
        };
        let semantic_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "promote_placement",
            &format!(
                "topology:{}:{}",
                if registry_id.is_some() {
                    "registry"
                } else {
                    "cache"
                },
                registry_id.or(cache_id).unwrap_or_default()
            ),
            &input,
            &req.idempotency_key,
            effects,
            Vec::new(),
            Some(semantic_digest),
        )
        .await
    }

    /// Plans cancellation of an unconfirmed placement promotion.
    pub async fn plan_cancel_placement_promotion(
        &self,
        auth: Option<&str>,
        mut req: pb::SurfaceMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let (surface, _) = self
            .writable_topology_surface(auth, req.surface.clone())
            .await?;
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("write authority"))?;
        if !matches!(
            authority.reconciliation_state.as_str(),
            "pending" | "failed"
        ) {
            return Err(RpcError::FailedPrecondition(
                "write authority has no unconfirmed promotion".to_string(),
            ));
        }
        let observed_placement_id = authority.observed_placement_id.ok_or_else(|| {
            RpcError::FailedPrecondition("promotion has no prior observed writer".to_string())
        })?;
        if authority.desired_placement_id == observed_placement_id {
            return Err(RpcError::FailedPrecondition(
                "write authority is already returning to its observed writer".to_string(),
            ));
        }
        let expected = parse_resource_version(
            req.expected_resource_version
                .as_deref()
                .ok_or_else(|| RpcError::invalid("expectedResourceVersion is required"))?,
            authority.resource_version,
        )?;
        if expected != authority.resource_version {
            return Err(RpcError::FailedPrecondition(
                "write-authority resource version is stale".to_string(),
            ));
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = CancelPlacementPromotionPlanInput {
            request: req,
            registry_id,
            cache_id,
            authority_id: authority.id,
            authority_incarnation_id: authority.incarnation_id,
            authority_resource_version: authority.resource_version,
            desired_generation: authority.desired_generation,
            desired_placement_id: authority.desired_placement_id,
            observed_placement_id,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "cancel_placement_promotion",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![
                "request the previously observed writer under a new authority generation"
                    .to_string(),
                "keep writes fenced until the controller reconciles that generation".to_string(),
            ],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a safe placement drain.
    pub async fn plan_drain_placement(
        &self,
        auth: Option<&str>,
        req: pb::PlacementMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_placement_lifecycle(auth, req, "drain_placement", "draining", false)
            .await
    }

    /// Plans cancellation of a placement drain.
    pub async fn plan_cancel_placement_drain(
        &self,
        auth: Option<&str>,
        req: pb::PlacementMutationRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        self.plan_placement_lifecycle(auth, req, "cancel_placement_drain", "active", true)
            .await
    }

    /// `TopologyService.PlanDeletePlacement` persists a reviewed deletion plan.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-version, safety-precondition, or
    /// persistence error.
    pub async fn plan_delete_placement(
        &self,
        auth: Option<&str>,
        mut req: pb::PlacementMutationRequest,
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
        if current.authority_desired_placement_id == Some(current.id)
            || current.authority_observed_placement_id == Some(current.id)
        {
            return Err(RpcError::FailedPrecondition(
                "an authority-owned placement cannot be deleted".to_string(),
            ));
        }
        let blockers = self
            .db
            .surface_placement_blockers(current.id)
            .await
            .map_err(RpcError::internal)?;
        if let Some(error) = Self::placement_delete_blocker_error(
            blockers,
            matches!(surface, SurfaceTarget::Registry(_)),
        ) {
            return Err(error);
        }
        let idempotency_key = std::mem::take(&mut req.idempotency_key);
        let (registry_id, cache_id) = Self::topology_surface_ids(surface);
        let input = PlacementDeletePlanInput {
            request: req,
            registry_id,
            cache_id,
            placement_id: current.id,
            baseline_resource_version: expected,
        };
        let confirmation_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&input).map_err(RpcError::internal)?,
        ));
        self.create_control_plan(
            &claims,
            "delete_placement",
            &Self::topology_scope(registry_id, cache_id),
            &input,
            &idempotency_key,
            vec![
                format!(
                    "delete placement '{}' topology metadata",
                    input.request.placement_name
                ),
                "leave backing storage objects unchanged".to_string(),
            ],
            Vec::new(),
            Some(confirmation_hash),
        )
        .await
    }

    /// Plans a placement drain that removes it from cache read/write selection.
    pub async fn plan_run_placement_eviction(
        &self,
        auth: Option<&str>,
        req: pb::PlanRunPlacementEvictionRequest,
    ) -> Result<pb::TopologyPlanResponse, RpcError> {
        let cache_slug = match req
            .surface
            .as_ref()
            .and_then(|surface| surface.target.as_ref())
        {
            Some(pb::surface_ref::Target::CacheSlug(slug)) => slug,
            _ => {
                return Err(RpcError::invalid(
                    "placement eviction requires a binary cache",
                ));
            }
        };
        let cache = self.binary_cache_or_not_found(cache_slug).await?;
        self.require_cache_permission(auth, &cache, Permission::CacheGcExecute)
            .await?;
        let placement = self
            .db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == req.placement_name)
            .ok_or_else(|| RpcError::not_found("cache placement"))?;
        if req
            .expected_resource_version
            .as_deref()
            .map(|value| parse_resource_version(value, 0))
            .transpose()?
            .is_some_and(|version| version != placement.resource_version)
        {
            return Err(RpcError::FailedPrecondition(
                "placement resource version is stale".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        self.create_control_plan(
            &claims,
            "placement_eviction",
            &cache.scope_key,
            &req,
            &req.idempotency_key,
            vec!["mark the placement draining and enqueue physical evacuation".to_string()],
            vec!["the placement remains durable until reconciliation confirms absence".to_string()],
            Some(hex::encode(Sha256::digest(
                serde_json::to_vec(&req).map_err(RpcError::internal)?,
            ))),
        )
        .await
    }
}
