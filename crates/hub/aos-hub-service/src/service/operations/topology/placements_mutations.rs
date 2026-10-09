//! Placements mutations in the topology capability.

use super::*;

impl RpcService {
    /// Applies creation of a placement policy and its first immutable revision.
    pub async fn create_placement_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementPolicyResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_placement_policy",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        let (plan, identity, _) = self
            .apply_placement_policy_mutation(auth, &req, "create_placement_policy")
            .await?;
        let response = pb::PlacementPolicyResponse {
            policy: Some(self.placement_policy_message(identity).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies publication of a new immutable placement-policy revision.
    pub async fn revise_placement_policy(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementPolicyRevisionResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "revise_placement_policy",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        let (plan, _, revision) = self
            .apply_placement_policy_mutation(auth, &req, "revise_placement_policy")
            .await?;
        let response = pb::PlacementPolicyRevisionResponse {
            revision: Some(self.placement_policy_revision_message(revision).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Evaluates one immutable policy revision without performing a read.
    pub async fn test_placement_policy_revision(
        &self,
        auth: Option<&str>,
        req: pb::TestPlacementPolicyRevisionRequest,
    ) -> Result<pb::TestPlacementPolicyRevisionResponse, RpcError> {
        if req.revision <= 0 || req.object_ref.is_empty() {
            return Err(RpcError::invalid(
                "revision must be positive and objectRef is required",
            ));
        }
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let identity = self
            .db
            .placement_policy_identity(&req.policy_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|identity| identity.surface == surface)
            .ok_or_else(|| RpcError::not_found("placement policy"))?;
        let revision = self
            .db
            .list_placement_policy_revisions(&identity.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|revision| revision.revision == req.revision && revision.state == "published")
            .ok_or_else(|| RpcError::not_found("published placement policy revision"))?;
        let digest = Sha256::digest(req.object_ref.as_bytes());
        let bucket = u32::from(u16::from_be_bytes([digest[0], digest[1]]));
        let access_class = pb::AccessClass::try_from(req.access_class)
            .map_err(|_| RpcError::invalid("unknown accessClass"))?;
        let (groups, members) = self
            .db
            .placement_policy_revision_shape(&revision.id)
            .await
            .map_err(RpcError::internal)?;
        let mut selected_placements = Vec::new();
        let mut decisions = vec![format!("bucket={bucket}")];
        for group in &groups {
            let selected = match revision.spec.kind.as_str() {
                "ordered_failover" => true,
                "local_then_remote" => match access_class {
                    pb::AccessClass::Local => {
                        group.purpose == "local"
                            || (group.purpose == "remote"
                                && revision.spec.allow_remote_fallback == Some(true))
                    }
                    pb::AccessClass::Remote => group.purpose == "remote",
                    pb::AccessClass::Unspecified => {
                        return Err(RpcError::invalid(
                            "local-then-remote policy tests require accessClass",
                        ));
                    }
                },
                "hash_partition" => {
                    group.purpose == "complete_fallback"
                        || group
                            .range_start
                            .zip(group.range_end)
                            .is_some_and(|(start, end)| {
                                i64::from(bucket) >= start && i64::from(bucket) < end
                            })
                }
                _ => false,
            };
            if !selected {
                continue;
            }
            decisions.push(format!(
                "selected {} group {}",
                group.purpose, group.group_id
            ));
            for member in members
                .iter()
                .filter(|member| member.group_id == group.group_id)
            {
                selected_placements.push(
                    self.db
                        .surface_placement(member.placement_id)
                        .await
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| {
                            RpcError::internal(anyhow::anyhow!(
                                "policy member placement disappeared"
                            ))
                        })?
                        .name,
                );
            }
        }
        Ok(pb::TestPlacementPolicyRevisionResponse {
            bucket,
            selected_placements,
            decisions,
        })
    }

    /// Applies one reviewed placement-equivalence confirmation.
    pub async fn confirm_placement_equivalence(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementEquivalenceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "confirm_placement_equivalence",
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
            "confirm_placement_equivalence",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementEquivalencePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "confirm_placement_equivalence",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id) {
            return Err(RpcError::FailedPrecondition(
                "equivalence plan belongs to another surface".to_string(),
            ));
        }
        if let Some(record) = self
            .db
            .placement_equivalence(&input.stable_id)
            .await
            .map_err(RpcError::internal)?
        {
            if record.creation_token != plan.plan_id
                || record.evidence_digest != input.evidence_digest
            {
                return Err(RpcError::FailedPrecondition(
                    "equivalence identity was consumed by another plan".to_string(),
                ));
            }
            let response = pb::PlacementEquivalenceResponse {
                equivalence: Some(self.placement_equivalence_message(record).await?),
            };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        }
        let a = self
            .db
            .surface_placement(input.placement_a_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("placement A disappeared".to_string()))?;
        let b = self
            .db
            .surface_placement(input.placement_b_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::FailedPrecondition("placement B disappeared".to_string()))?;
        if a.resource_version != input.placement_a_version
            || a.observation_version != Some(input.placement_a_observation_version)
            || b.resource_version != input.placement_b_version
            || b.observation_version != Some(input.placement_b_observation_version)
            || self.placement_physical_identity_fingerprint(&a).await?
                != input.physical_identity_fingerprint
            || self.placement_physical_identity_fingerprint(&b).await?
                != input.physical_identity_fingerprint
            || self
                .db
                .placement_inventory_digest(a.id)
                .await
                .map_err(RpcError::internal)?
                != input.placement_a_inventory_digest
            || self
                .db
                .placement_inventory_digest(b.id)
                .await
                .map_err(RpcError::internal)?
                != input.placement_b_inventory_digest
            || input.placement_a_inventory_digest != input.placement_b_inventory_digest
        {
            return Err(RpcError::FailedPrecondition(
                "placement evidence changed after equivalence planning".to_string(),
            ));
        }
        let claims = self.require_claims(auth)?;
        let record = self
            .db
            .create_placement_equivalence(
                &input.stable_id,
                &plan.plan_id,
                input.placement_a_id,
                input.placement_a_version,
                input.placement_a_observation_version,
                input.placement_b_id,
                input.placement_b_version,
                input.placement_b_observation_version,
                &input.physical_identity_fingerprint,
                &input.evidence_digest,
                &claims.sub,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::PlacementEquivalenceResponse {
            equivalence: Some(self.placement_equivalence_message(record).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies one reviewed placement-equivalence deletion.
    pub async fn delete_placement_equivalence(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_placement_equivalence",
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
            "delete_placement_equivalence",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementEquivalenceDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_placement_equivalence",
                Some(&req.confirmation_hash),
            )
            .await?;
        match self
            .db
            .placement_equivalence(&input.stable_id)
            .await
            .map_err(RpcError::internal)?
        {
            None => {}
            Some(record) => {
                let surface_ref = Some(self.route_surface_message(record.surface).await?);
                let (surface, _) = self.writable_topology_surface(auth, surface_ref).await?;
                if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id)
                    || record.resource_version != input.baseline_resource_version
                {
                    return Err(RpcError::FailedPrecondition(
                        "placement equivalence changed after deletion planning".to_string(),
                    ));
                }
                if !self
                    .db
                    .delete_placement_equivalence(&input.stable_id, input.baseline_resource_version)
                    .await
                    .map_err(RpcError::internal)?
                {
                    return Err(RpcError::FailedPrecondition(
                        "placement equivalence changed during deletion".to_string(),
                    ));
                }
            }
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// `TopologyService.CreatePlacement` applies a persisted creation plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, conflict, or persistence error.
    pub async fn apply_create_placement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_placement",
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
            "create_placement",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementCreatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_placement",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (surface, org_id) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id)
            || org_id != input.org_id
            || self
                .topology_binding_id(org_id, &input.request.binding_id)
                .await?
                != input.binding_db_id
        {
            return Err(RpcError::FailedPrecondition(
                "placement plan inputs changed after review".to_string(),
            ));
        }
        if let Some(existing) = self
            .db
            .list_surface_placements(surface)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .find(|placement| placement.name == input.request.name)
        {
            if Self::placement_matches_create(&existing, &input) {
                let response = pb::PlacementResponse {
                    placement: Some(self.placement_message(existing).await?),
                };
                self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                    .await?;
                return Ok(response);
            }
            return Err(RpcError::AlreadyExists(
                "placement already exists".to_string(),
            ));
        }
        let hash_range =
            input
                .request
                .hash_range
                .as_ref()
                .map(|range| crate::db::SurfacePlacementHashRange {
                    start: i64::from(range.start),
                    end: i64::from(range.end),
                });
        let placement = self
            .db
            .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
                surface,
                name: input.request.name.clone(),
                binding_id: input.binding_db_id,
                prefix: input.request.prefix.clone(),
                kind: input.request.kind.clone(),
                desired_state: input.request.desired_state.clone(),
                hash_range,
                desired_read_enabled: input.request.desired_read_enabled.unwrap_or(false),
                read_order: input.request.read_order.unwrap_or_default(),
                requires_conditional_writes: input.request.requires_conditional_writes,
            })
            .await
            .map_err(Self::placement_create_error)?;
        let response = pb::PlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// `TopologyService.UpdatePlacement` applies a persisted replacement plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, or persistence error.
    pub async fn apply_update_placement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "update_placement",
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
            "update_placement",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementUpdatePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "update_placement",
                Some(&req.confirmation_hash),
            )
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
            .topology_placement(surface, &input.request.name)
            .await?;
        if current.id != input.placement_id {
            return Err(RpcError::FailedPrecondition(
                "placement identity changed after planning".to_string(),
            ));
        }
        let exact_outcome = current.resource_version == input.baseline_resource_version + 1
            && current.desired_state == input.request.desired_state
            && current.desired_read_enabled == input.request.desired_read_enabled.unwrap_or(false)
            && current.read_order == input.request.read_order.unwrap_or_default();
        let placement = if exact_outcome {
            current
        } else {
            if current.resource_version != input.baseline_resource_version {
                return Err(RpcError::FailedPrecondition(
                    "placement resource version changed after planning".to_string(),
                ));
            }
            self.db
                .update_surface_placement(
                    current.id,
                    &crate::db::UpdateSurfacePlacementSpec {
                        expected_version: input.baseline_resource_version,
                        desired_state: input.request.desired_state.clone(),
                        desired_read_enabled: input.request.desired_read_enabled.unwrap_or(false),
                        read_order: input.request.read_order.unwrap_or_default(),
                    },
                )
                .await
                .map_err(Self::authority_mutation_error)?
        };
        let response = pb::PlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// `TopologyService.PromotePlacement` — applies one immutable promotion plan.
    ///
    /// Existing authority moves through the portable single-row authority CAS.
    /// An authority-free surface uses the guarded initial-authority insert.
    /// Existing authority changes fence writes until the desired generation is
    /// observed. Initial authority creation synchronously establishes a ready
    /// tuple because both the placement and immutable binding revision were
    /// already observed valid before planning.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown plan, and [`RpcError::FailedPrecondition`] for an expired,
    /// consumed, cross-surface, stale, or no-longer-eligible plan.
    pub async fn promote_placement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::GetWriteAuthorityResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "promote_placement",
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
            "promote_placement",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementPromotionPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "promote_placement",
                Some(&req.confirmation_hash),
            )
            .await?;
        let claims = self.require_claims(auth)?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if (input.registry_id, input.cache_id) != Self::topology_surface_ids(surface) {
            return Err(RpcError::FailedPrecondition(
                "the promotion plan belongs to another surface".to_string(),
            ));
        }
        let expected_desired_generation = input
            .authority_desired_generation
            .map_or(1, |generation| generation + 1);
        if let Some(authority) = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
        {
            let exact_outcome = authority.incarnation_id == input.authority_incarnation_id
                && authority.desired_placement_id == input.candidate_placement_id
                && authority.desired_write_spec_version == input.candidate_write_spec_version
                && authority.desired_binding_write_revision
                    == input.candidate_binding_write_revision
                && authority.desired_generation == expected_desired_generation;
            if exact_outcome {
                let response = pb::GetWriteAuthorityResponse {
                    authority: Some(self.write_authority_message(authority).await?),
                };
                self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                    .await?;
                return Ok(response);
            }
        }
        self.db
            .bind_surface_placement_write_capability(
                input.candidate_placement_id,
                input.candidate_binding_write_revision,
            )
            .await
            .map_err(Self::authority_mutation_error)?;
        let authority = match (
            input.authority_id,
            input.authority_resource_version,
            input.observed_placement_id,
        ) {
            (Some(authority_id), Some(authority_version), Some(observed_id)) => {
                self.db
                    .request_surface_write_promotion(
                        authority_id,
                        &input.authority_incarnation_id,
                        authority_version,
                        observed_id,
                        input.candidate_placement_id,
                        input.candidate_write_spec_version,
                        input.candidate_binding_write_revision,
                    )
                    .await
            }
            (None, None, None) => {
                self.db
                    .create_surface_write_authority(
                        surface,
                        &input.authority_incarnation_id,
                        input.candidate_placement_id,
                        input.candidate_resource_version,
                        input.candidate_write_spec_version,
                        input.candidate_binding_write_revision,
                    )
                    .await
            }
            _ => {
                return Err(RpcError::internal(anyhow::anyhow!(
                    "promotion plan has an inconsistent authority tuple"
                )));
            }
        }
        .map_err(Self::authority_mutation_error)?;
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                "topology.placement.promote",
                &plan.scope,
                None,
                None,
                None,
                Some(&input.candidate_placement_name),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording placement promotion audit");
        }
        let response = pb::GetWriteAuthorityResponse {
            authority: Some(self.write_authority_message(authority).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        if let Err(error) = self.topology_probes.wake_controller().await {
            tracing::warn!(error = %format!("{error:#}"), "waking write-authority controller");
        }
        Ok(response)
    }

    /// Applies one reviewed placement-promotion cancellation.
    pub async fn cancel_placement_promotion(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::GetWriteAuthorityResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "cancel_placement_promotion",
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
            "cancel_placement_promotion",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, CancelPlacementPromotionPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "cancel_placement_promotion",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id) {
            return Err(RpcError::FailedPrecondition(
                "promotion-cancellation plan belongs to another surface".to_string(),
            ));
        }
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| {
                RpcError::FailedPrecondition("write authority disappeared".to_string())
            })?;
        let resulting_generation = input.desired_generation + 1;
        let authority = if authority.incarnation_id == input.authority_incarnation_id
            && authority.desired_placement_id == input.observed_placement_id
            && authority.desired_generation == resulting_generation
        {
            authority
        } else {
            if authority.id != input.authority_id
                || authority.incarnation_id != input.authority_incarnation_id
                || authority.resource_version != input.authority_resource_version
                || authority.desired_generation != input.desired_generation
                || authority.desired_placement_id != input.desired_placement_id
                || authority.observed_placement_id != Some(input.observed_placement_id)
            {
                return Err(RpcError::FailedPrecondition(
                    "write authority changed after cancellation was planned".to_string(),
                ));
            }
            self.db
                .cancel_surface_write_promotion(
                    input.authority_id,
                    input.authority_resource_version,
                )
                .await
                .map_err(Self::authority_mutation_error)?
        };
        let response = pb::GetWriteAuthorityResponse {
            authority: Some(self.write_authority_message(authority).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        if let Err(error) = self.topology_probes.wake_controller().await {
            tracing::warn!(error = %format!("{error:#}"), "waking write-authority controller");
        }
        Ok(response)
    }

    /// Applies a reviewed drain and schedules its durable controller operation.
    pub async fn drain_placement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "drain_placement",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        let (plan, placement) = self
            .apply_placement_lifecycle(auth, req.clone(), "drain_placement")
            .await?;
        let operation_id = hex::encode(Sha256::digest(
            format!("drain-placement-v1\0{}", plan.plan_id).as_bytes(),
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
                .create_topology_operation(&crate::db::NewTopologyOperation {
                    operation_id,
                    operation_kind: "drain_placement".to_string(),
                    control_permission: Permission::StorageManage,
                    targets: vec![crate::db::NewTopologyOperationTarget {
                        role: "primary".to_string(),
                        target: crate::db::NewTopologyOperationTargetRef::Placement(placement.id),
                        generation_key: placement.resource_version,
                        configuration_digest: String::new(),
                    }],
                    detail_json: serde_json::json!({"phase":"draining"}).to_string(),
                    progress_total: None,
                })
                .await
                .map_err(RpcError::internal)?,
        };
        let response = pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies cancellation of a reviewed drain.
    pub async fn cancel_placement_drain(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::PlacementResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "cancel_placement_drain",
                Some(&req.confirmation_hash),
                &req.idempotency_key,
            )
            .await?
        {
            return Ok(response);
        }
        let (plan, placement) = self
            .apply_placement_lifecycle(auth, req.clone(), "cancel_placement_drain")
            .await?;
        let response = pb::PlacementResponse {
            placement: Some(self.placement_message(placement).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// `TopologyService.DeletePlacement` applies a persisted deletion plan exactly once.
    ///
    /// # Errors
    ///
    /// Returns an authorization, confirmation, stale-plan, safety-precondition,
    /// or persistence error.
    pub async fn apply_delete_placement(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_placement",
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
            "delete_placement",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, PlacementDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_placement",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (surface, _) = self
            .writable_topology_surface(auth, input.request.surface.clone())
            .await?;
        if Self::topology_surface_ids(surface) != (input.registry_id, input.cache_id) {
            return Err(RpcError::FailedPrecondition(
                "placement plan belongs to another surface".to_string(),
            ));
        }
        let Some(current) = self
            .db
            .surface_placement(input.placement_id)
            .await
            .map_err(RpcError::internal)?
        else {
            let response = pb::DeleteTopologyResourceResponse { deleted: true };
            self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                .await?;
            return Ok(response);
        };
        if current.registry_id != input.registry_id
            || current.cache_id != input.cache_id
            || current.name != input.request.placement_name
            || current.resource_version != input.baseline_resource_version
        {
            return Err(RpcError::FailedPrecondition(
                "placement changed after deletion was planned".to_string(),
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
        let deleted = if matches!(surface, SurfaceTarget::Registry(_)) {
            self.db
                .delete_registry_surface_placement(current.id, input.baseline_resource_version)
                .await
        } else {
            self.db
                .delete_surface_placement(current.id, input.baseline_resource_version)
                .await
        }
        .map_err(RpcError::internal)?;
        if !deleted {
            return Err(RpcError::FailedPrecondition(
                "placement changed while deletion was applied".to_string(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a reviewed placement-eviction plan and creates its durable operation.
    pub async fn run_placement_eviction(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::OperationResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "placement_eviction",
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
            "placement_eviction",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (_, planned): (_, pb::PlanRunPlacementEvictionRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "placement_eviction",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache_slug = match planned
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
            .find(|placement| placement.name == planned.placement_name)
            .ok_or_else(|| RpcError::not_found("cache placement"))?;
        let placement_id = placement.id;
        let expected_version = planned
            .expected_resource_version
            .as_deref()
            .map(|value| parse_resource_version(value, placement.resource_version))
            .transpose()?
            .unwrap_or(placement.resource_version);
        let updated = self
            .db
            .update_surface_placement(
                placement_id,
                &crate::db::UpdateSurfacePlacementSpec {
                    expected_version,
                    desired_state: "draining".to_string(),
                    desired_read_enabled: false,
                    read_order: placement.read_order,
                },
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if let Some(state) = self
            .db
            .cache_gc_topology_state(cache.id)
            .await
            .map_err(RpcError::internal)?
        {
            self.db
                .advance_cache_gc_topology_generation(
                    cache.id,
                    state.epoch,
                    &uuid::Uuid::new_v4().to_string(),
                    clock::now_unix_secs(),
                )
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        }
        let operation = self
            .db
            .create_topology_operation(&crate::db::NewTopologyOperation {
                operation_id: hex::encode(Sha256::digest(
                    format!("evict:{}:{}", req.plan_id, req.idempotency_key).as_bytes(),
                )),
                operation_kind: "placement_eviction".to_string(),
                control_permission: Permission::CacheGcExecute,
                targets: vec![
                    crate::db::NewTopologyOperationTarget {
                        role: "primary".to_string(),
                        target: crate::db::NewTopologyOperationTargetRef::BinaryCache(cache.id),
                        generation_key: 0,
                        configuration_digest: String::new(),
                    },
                    crate::db::NewTopologyOperationTarget {
                        role: "placement".to_string(),
                        target: crate::db::NewTopologyOperationTargetRef::Placement(placement_id),
                        generation_key: updated.resource_version,
                        configuration_digest: String::new(),
                    },
                ],
                detail_json: serde_json::json!({
                    "placementName": planned.placement_name,
                    "desiredState": "draining"
                })
                .to_string(),
                progress_total: None,
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        };
        self.complete_control_plan(&req.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
