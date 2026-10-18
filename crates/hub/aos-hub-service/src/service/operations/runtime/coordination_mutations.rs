//! Coordination mutations in the runtime capability.

use super::*;

impl RpcService {
    /// Describes the authenticated principal and current access-token authority.
    ///
    /// The principal must still exist. Memberships are loaded from live state,
    /// while `access_scope`, `access_permissions`, and `access_expires_at`
    /// describe the bearer presented for this request.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing or invalid bearer,
    /// [`RpcError::PermissionDenied`] for a deleted principal, or
    /// [`RpcError::Internal`] on database failure.
    pub async fn who_am_i(
        &self,
        auth: Option<&str>,
        _req: pb::WhoAmIRequest,
    ) -> Result<pb::WhoAmIResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let principal = claims_principal(&claims)
            .ok_or_else(|| RpcError::PermissionDenied("active principal required".into()))?;
        if !self
            .db
            .principal_is_live(principal.kind.as_str(), principal.id)
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::PermissionDenied(
                "active principal required".into(),
            ));
        }

        let (principal_ref, email) = match principal.kind {
            PrincipalKind::User => {
                let email = self
                    .db
                    .user_email(principal.id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::PermissionDenied("active principal required".into())
                    })?;
                (email.clone(), email)
            }
            PrincipalKind::ServiceAccount => {
                let reference = self
                    .db
                    .service_account_reference(principal.id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| {
                        RpcError::PermissionDenied("active principal required".into())
                    })?;
                (reference, String::new())
            }
        };
        let grants = self
            .db
            .effective_scopes(principal)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|(scope, role)| pb::IdentityGrant {
                scope: scope.as_str().to_string(),
                role: role.as_str().to_string(),
            })
            .collect();

        Ok(pb::WhoAmIResponse {
            principal_kind: principal.kind.as_str().to_string(),
            principal_ref,
            email,
            grants,
            access_scope: claims.scope,
            access_permissions: claims.perms,
            access_expires_at: claims.exp,
        })
    }

    /// Reads one machine path from a logical registry or cache surface.
    ///
    /// Typed delivery-route handlers and server-rendered browse pages share this
    /// placement-aware read primitive. It does not resolve an external URL or
    /// create a slug route: callers have already selected the logical resource.
    /// Selection, failover, and the byte/header contract remain single-sourced
    /// through the [`SurfaceProvider`] port. A surface without an active
    /// placement is unavailable.
    ///
    /// Returns `Ok(None)` — which the transport renders as a `404` — when
    /// `machine_path` is not part of the machine surface ([`keymap::is_machine_path`])
    /// or the surface store has no such object. On a hit it returns the
    /// [`SurfaceObjectResponse`] carrying the bytes plus the path's
    /// [`keymap::content_type`]/[`keymap::cache_control`].
    ///
    /// Reads follow registry visibility exactly as the other read RPCs do (see
    /// `Self::require_read`): a `public` registry serves anonymously, while an
    /// `internal`/`private` registry requires a bearer JWT granting
    /// [`Permission::Read`] on the registry scope — so the read primitive never
    /// discloses a hidden registry's bytes to an unauthorized caller.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::NotFound`] for an unknown slug or a registry under a
    /// soft-deleted org, [`RpcError::Unauthenticated`]/[`RpcError::PermissionDenied`]
    /// when a non-public registry is read without authority, and
    /// [`RpcError::Internal`] when resolving the surface fetcher or reading the
    /// object fails.
    pub async fn surface_fetch(
        &self,
        auth: Option<&str>,
        slug: &str,
        machine_path: &str,
    ) -> Result<Option<SurfaceObjectResponse>, RpcError> {
        if !keymap::is_machine_path(machine_path) {
            return Ok(None);
        }
        // A registry slug wins; a slug that is not a registry falls through to a
        // managed cache (the two are separate namespaces). Both shells reach this
        // one method, so cache serving is at parity automatically.
        if let Some(registry) = self
            .db
            .registry_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        {
            self.require_read(auth, &registry).await?;
            let bytes = match placement_read::fetch_from_placements(
                self.db.as_ref(),
                self.surface.as_ref(),
                SurfaceTarget::Registry(registry.id),
                machine_path,
            )
            .await
            .map_err(RpcError::internal)?
            {
                PlacementReadOutcome::Found(read) => read.value,
                PlacementReadOutcome::NotFound => return Ok(None),
            };
            return Ok(Some(SurfaceObjectResponse {
                bytes,
                content_type: keymap::content_type(machine_path),
                cache_control: keymap::cache_control(machine_path),
                redirect: None,
            }));
        }
        if let Some(cache) = self
            .db
            .binary_cache_by_slug(slug)
            .await
            .map_err(RpcError::internal)?
        {
            return self.cache_surface_fetch(auth, &cache, machine_path).await;
        }
        Err(RpcError::not_found("registry"))
    }

    /// Serve the instance-root `robots.txt` body.
    ///
    /// Returns the operator's custom override verbatim when one is set, else the
    /// document generated from the root crawl policy (see
    /// [`crate::robots::render_robots`]). The result is always a complete file
    /// body; the route layer wraps it in a `text/plain` response.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_root_robots(&self) -> Result<String, RpcError> {
        if let Some(body) = self
            .db
            .root_robots_body()
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(body);
        }
        let policy = self
            .db
            .root_crawl_policy()
            .await
            .map_err(RpcError::internal)?;
        let llms_url = format!("{}/llms.txt", self.external_url.trim_end_matches('/'));
        Ok(crate::robots::render_robots(policy, Some(&llms_url)))
    }

    /// Serve the instance-root `llms.txt` body.
    ///
    /// Returns the operator's custom override verbatim when one is set, else the
    /// document generated from the instance's **public** registries (see
    /// [`crate::robots::render_root_llms`]).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Internal`] on database failure.
    pub async fn serve_root_llms(&self) -> Result<String, RpcError> {
        if let Some(body) = self.db.root_llms_body().await.map_err(RpcError::internal)? {
            return Ok(body);
        }
        let base = self.external_url.trim_end_matches('/');
        let brand = self
            .db
            .instance_settings()
            .await
            .map_err(RpcError::internal)?
            .site_title
            .unwrap_or_default();
        let registries = self
            .db
            .list_registries()
            .await
            .map_err(RpcError::internal)?;
        let views: Vec<crate::robots::RootRegistryView> = registries
            .into_iter()
            .filter(|r| r.visibility == "public")
            .map(|r| crate::robots::RootRegistryView {
                browse_url: format!("{base}/{}/", r.slug),
                slug: r.slug,
                description: None,
            })
            .collect();
        Ok(crate::robots::render_root_llms(&brand, &views))
    }

    /// Authorizes one typed delivery-route surface without opening its origin.
    ///
    /// Redirect mode uses this gate before minting a path-scoped bearer URL, so
    /// it applies the same liveness, visibility, and IAM rules as proxy mode.
    ///
    /// # Errors
    ///
    /// Returns the normal authentication/authorization error, not-found for a
    /// deleted surface, or internal on database failure.
    pub async fn authorize_delivery_surface_read(
        &self,
        auth: ReadAuthorization<'_>,
        surface: SurfaceTarget,
    ) -> Result<(), RpcError> {
        match surface {
            SurfaceTarget::Registry(id) => {
                let registry = self
                    .db
                    .registry_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry"))?;
                self.require_registry_stream_read(auth, &registry).await
            }
            SurfaceTarget::BinaryCache(id) => {
                let cache = self
                    .db
                    .binary_cache_by_id(id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("cache"))?;
                self.require_cache_stream_read(auth, &cache).await
            }
        }
    }

    /// Applies a reviewed population-target change.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, validation, stale-version, or database error.
    pub async fn set_population_target(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::PopulationTargetResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "set_population_target",
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
            "set_population_target",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, pb::PlanPopulationTargetRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "set_population_target",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &input.cache_id, &input.registry_id, true)
            .await?;
        let desired = input
            .desired
            .ok_or_else(|| RpcError::invalid("plan desired state is missing"))?;
        let placement_policy_revision_id = if desired.placement_policy_revision_id.is_empty() {
            None
        } else {
            Some(desired.placement_policy_revision_id.clone())
        };
        let record = self
            .db
            .set_cache_population_target(&aos_hub_db::db::SetCachePopulationTarget {
                cache_id: cache.id,
                registry_id: registry.id,
                trigger_kind: desired.trigger,
                required: desired.required,
                placement_policy_revision_id,
                selector_json: "{}".to_string(),
                validation_gate: desired.validation_gate,
                enabled: true,
                expected_version: input.expected_resource_version.parse::<i64>().ok(),
            })
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let response = pb::PopulationTargetResponse {
            target: Some(Self::population_target_message(
                &record,
                &cache.slug,
                &registry.slug,
            )),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies deletion of a population target.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale-plan, ambiguity, stale-version, or database error.
    pub async fn delete_population_target(
        &self,
        auth: Option<&str>,
        req: pb::ApplyCachePlanRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_population_target",
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
            "delete_population_target",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, pb::PlanDeletePopulationTargetRequest) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_population_target",
                Some(&req.confirmation_hash),
            )
            .await?;
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &input.cache_id, &input.registry_id, true)
            .await?;
        let current = self.single_population_target(cache.id, registry.id).await?;
        let deleted = self
            .db
            .delete_cache_population_target(
                current.id,
                parse_resource_version(&input.expected_resource_version, current.resource_version)?,
            )
            .await
            .map_err(RpcError::internal)?;
        if !deleted {
            return Err(RpcError::FailedPrecondition(
                "population target changed after planning".to_string(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Reports one fenced write-authority observation for a desired generation.
    ///
    /// The generation and authority resource version fence a controller retry
    /// from confirming or failing a newer promotion. A ready observation also
    /// revalidates every placement and immutable binding-capability prerequisite.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an authority-free surface, [`RpcError::InvalidArgument`] for malformed
    /// state/error fields, or [`RpcError::FailedPrecondition`] for stale or
    /// no-longer-eligible authority.
    pub async fn report_write_authority(
        &self,
        auth: Option<&str>,
        req: pb::ReportWriteAuthorityRequest,
    ) -> Result<pb::WriteAuthorityObservationResponse, RpcError> {
        let claims = self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let (surface, org_id) = self.writable_topology_surface(auth, req.surface).await?;
        let reconcile_scope = match org_id {
            Some(org_id) => {
                let org = self
                    .db
                    .org_by_id(org_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("org"))?;
                Scope::parse(&org.stable_id)
            }
            None => Scope::root(),
        };
        self.require_permission(&claims, Permission::TopologyReconcile, &reconcile_scope)
            .await?;
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("write authority"))?;
        let expected_version = req
            .expected_observation_version
            .parse::<i64>()
            .map_err(|_| {
                RpcError::invalid("expectedResourceVersion must be a positive opaque version")
            })?;
        if expected_version <= 0 {
            return Err(RpcError::invalid(
                "expectedResourceVersion must be a positive opaque version",
            ));
        }
        if req.desired_generation <= 0 || req.desired_generation != authority.desired_generation {
            return Err(RpcError::FailedPrecondition(
                "write-authority desired generation is stale".to_string(),
            ));
        }
        if req.state == "failed" {
            if req.error.trim().is_empty() {
                return Err(RpcError::invalid(
                    "a non-whitespace error is required when reconciliation state is failed",
                ));
            }
            if req.error.len() > RECONCILIATION_ERROR_MAX_BYTES {
                return Err(RpcError::invalid(
                    "reconciliation error must not exceed 4096 UTF-8 bytes",
                ));
            }
        } else if !req.error.is_empty() {
            return Err(RpcError::invalid(
                "error is allowed only when reconciliation state is failed",
            ));
        }
        let already_reconciled = match req.state.as_str() {
            "ready" => {
                authority.reconciliation_state == "ready"
                    && authority.observed_generation == Some(req.desired_generation)
                    && authority.observed_placement_id == Some(authority.desired_placement_id)
                    && authority.observed_write_spec_version
                        == Some(authority.desired_write_spec_version)
                    && authority.observed_binding_write_revision
                        == Some(authority.desired_binding_write_revision)
            }
            "failed" => {
                authority.reconciliation_state == "failed"
                    && authority.reconciliation_error.as_deref() == Some(req.error.as_str())
            }
            _ => false,
        };
        if already_reconciled {
            return Ok(pb::WriteAuthorityObservationResponse {
                authority: Some(self.write_authority_message(authority).await?),
            });
        }
        if expected_version != authority.resource_version {
            return Err(RpcError::FailedPrecondition(
                "write-authority resource version is stale".to_string(),
            ));
        }
        let reconciled = match req.state.as_str() {
            "ready" => {
                self.db
                    .confirm_surface_write_authority(
                        authority.id,
                        expected_version,
                        req.desired_generation,
                    )
                    .await
            }
            "failed" => {
                self.db
                    .fail_surface_write_authority(
                        authority.id,
                        expected_version,
                        req.desired_generation,
                        &req.error,
                    )
                    .await
            }
            _ => {
                return Err(RpcError::invalid(
                    "reconciliation state must be ready or failed",
                ));
            }
        }
        .map_err(Self::authority_mutation_error)?;
        let detail = format!("generation={} state={}", req.desired_generation, req.state);
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                "topology.write_authority.reconcile",
                &format!(
                    "topology:{}:{}",
                    if authority.registry_id.is_some() {
                        "registry"
                    } else {
                        "cache"
                    },
                    authority
                        .registry_id
                        .or(authority.cache_id)
                        .unwrap_or_default()
                ),
                None,
                None,
                None,
                Some(&detail),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording write-authority reconciliation audit");
        }
        Ok(pb::WriteAuthorityObservationResponse {
            authority: Some(self.write_authority_message(reconciled).await?),
        })
    }

    /// `TopologyService.RemoveWriteAuthority` — consumes a read-only transition plan.
    ///
    /// # Errors
    ///
    /// Returns authentication/authorization errors, [`RpcError::NotFound`] for
    /// an unknown plan, or [`RpcError::FailedPrecondition`] for stale plan data.
    pub async fn remove_write_authority(
        &self,
        auth: Option<&str>,
        req: pb::ApplyTopologyPlanRequest,
    ) -> Result<pb::RemoveWriteAuthorityResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "remove_write_authority",
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
            "remove_write_authority",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, RemoveWriteAuthorityPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "remove_write_authority",
                Some(&req.confirmation_hash),
            )
            .await?;
        let surface_ref = if let Some(registry_id) = input.registry_id {
            let slug = self
                .db
                .registry_by_id(registry_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("registry"))?
                .slug;
            pb::SurfaceRef {
                target: Some(pb::surface_ref::Target::RegistrySlug(slug)),
            }
        } else if let Some(cache_id) = input.cache_id {
            let slug = self
                .db
                .binary_cache_by_id(cache_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("cache"))?
                .slug;
            pb::SurfaceRef {
                target: Some(pb::surface_ref::Target::CacheSlug(slug)),
            }
        } else {
            return Err(RpcError::internal(anyhow::anyhow!(
                "read-only plan has no surface"
            )));
        };
        let (surface, _) = self
            .writable_topology_surface(auth, Some(surface_ref))
            .await?;
        match self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?
        {
            None => {
                let response = pb::RemoveWriteAuthorityResponse { removed: true };
                self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                    .await?;
                return Ok(response);
            }
            Some(authority) if authority.incarnation_id != input.authority_incarnation_id => {
                return Err(RpcError::FailedPrecondition(
                    "the surface gained a newer write authority after this read-only plan"
                        .to_string(),
                ));
            }
            Some(_) => {}
        }
        let removed = self
            .db
            .remove_surface_write_authority(
                input.authority_id,
                &input.authority_incarnation_id,
                input.authority_resource_version,
                input.observed_generation,
            )
            .await
            .map_err(RpcError::internal)?;
        if !removed {
            match self
                .db
                .surface_write_authority(surface)
                .await
                .map_err(RpcError::internal)?
            {
                None => {
                    let response = pb::RemoveWriteAuthorityResponse { removed: true };
                    self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
                        .await?;
                    return Ok(response);
                }
                Some(authority) if authority.incarnation_id != input.authority_incarnation_id => {
                    return Err(RpcError::FailedPrecondition(
                        "the surface gained a newer write authority after this read-only plan"
                            .to_string(),
                    ));
                }
                Some(_) => {
                    return Err(RpcError::FailedPrecondition(
                        "the read-only plan is stale or authority is no longer reconciled"
                            .to_string(),
                    ));
                }
            }
        }
        let claims = self.require_claims(auth)?;
        if let Err(error) = self
            .db
            .record_audit(
                &claims.owner_kind,
                Some(claims.owner_id),
                &claims.sub,
                "topology.write_authority.remove",
                &plan.scope,
                None,
                None,
                None,
                Some(&input.observed_placement_name),
            )
            .await
        {
            tracing::warn!(error = %format!("{error:#}"), "recording write-authority removal audit");
        }
        let response = pb::RemoveWriteAuthorityResponse { removed: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }
}
