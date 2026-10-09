//! Coordination reads in the runtime capability.

use super::*;

impl RpcService {
    /// `RegistryConfigurationService.ListChangesets` — change-sets at a scope, newest first.
    ///
    /// Reads require [`Permission::AuditRead`] on the scope (RegistryConfigurationService
    /// reads are an admin+ surface, same as the audit feed).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::PermissionDenied`] when the caller lacks `audit.read` on the
    /// scope, [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_changesets(
        &self,
        auth: Option<&str>,
        req: pb::ListChangesetsRequest,
    ) -> Result<pb::ListChangesetsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let scope = parse_authorization_scope(&req.scope)?;
        self.require_permission(&claims, Permission::AuditRead, &scope)
            .await?;
        let changesets: Vec<pb::Changeset> = self
            .db
            .list_changesets(&req.scope)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(changeset_message)
            .collect();
        let (changesets, next_page_token) = paginate(changesets, req.page_size, &req.page_token)?;
        Ok(pb::ListChangesetsResponse {
            changesets,
            next_page_token,
        })
    }

    /// A registry's trust-key roster, read-through cached in KV when one is
    /// attached (RFC-0004 ch.14 Phase C, `roster:{registry_id}`).
    ///
    /// Each entry is `(key_id, public_key, status)` as
    /// [`Database::list_roster`](crate::db::Database::list_roster) returns. A
    /// short-TTL cache off the database; falls back to the database with no `kv`.
    ///
    /// # Errors
    ///
    /// Returns an error on a KV read or database failure.
    pub async fn list_roster_cached(
        &self,
        registry_id: i64,
    ) -> anyhow::Result<Vec<(String, String, String)>> {
        let Some(kv) = &self.kv else {
            return self.db.list_roster(registry_id).await;
        };
        let key = format!("roster:{registry_id}");
        let db = &self.db;
        let cached = crate::cache::read_through(
            kv.as_ref(),
            &key,
            Some(crate::cache::HOT_TTL_SECS),
            || async move { db.list_roster(registry_id).await.map(Some) },
        )
        .await?;
        match cached {
            Some(roster) => Ok(roster),
            None => self.db.list_roster(registry_id).await,
        }
    }

    /// Lists exact object-presence evidence across a surface's placements.
    pub async fn list_object_presence(
        &self,
        auth: Option<&str>,
        req: pb::ListObjectPresenceRequest,
    ) -> Result<pb::ListObjectPresenceResponse, RpcError> {
        if req.object_ref.is_empty() {
            return Err(RpcError::invalid("objectRef is required"));
        }
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let records = self
            .db
            .list_object_presence(surface, &req.object_ref)
            .await
            .map_err(RpcError::internal)?;
        let mut presences = Vec::with_capacity(records.len());
        for record in records {
            presences.push(pb::ObjectPresence {
                object_ref: record.object_ref,
                placement_name: record.placement_name,
                state: record.state,
                content_digest: record.content_digest.unwrap_or_default(),
                size: record
                    .size
                    .map(u64::try_from)
                    .transpose()
                    .map_err(RpcError::internal)?
                    .unwrap_or_default(),
                observed_at: record.observed_at,
            });
        }
        let (presences, next_page_token) = paginate(presences, req.page_size, &req.page_token)?;
        Ok(pb::ListObjectPresenceResponse {
            presences,
            next_page_token,
        })
    }

    /// `ImageService.ListImages` lists signed, directly downloadable disk encodings.
    ///
    /// # Errors
    ///
    /// Returns the normal registry visibility error, invalid selection errors,
    /// or an internal error when authenticated index metadata is malformed.
    pub async fn list_images(
        &self,
        auth: Option<&str>,
        req: pb::ListImagesRequest,
    ) -> Result<pb::ListImagesResponse, RpcError> {
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let control_base = self.control_image_download_base(registry.id)?;
        let download_base = if registry.visibility == "public" {
            self.registry_consumer_url(&registry)
                .await
                .unwrap_or(control_base)
        } else {
            control_base
        };
        if !req.release.is_empty() && !req.channel.is_empty() {
            return Err(RpcError::invalid(
                "release and channel are mutually exclusive",
            ));
        }
        let release = (!req.release.is_empty()).then(|| req.release.clone());
        let mut channel_releases = None;
        if !req.channel.is_empty() {
            let selected = self
                .db
                .list_channels(registry.id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .find(|candidate| candidate.name == req.channel)
                .ok_or_else(|| RpcError::not_found("channel"))?;
            let releases = selected
                .partitions
                .into_iter()
                .flatten()
                .collect::<HashSet<_>>();
            if releases.is_empty() {
                return Err(RpcError::FailedPrecondition(
                    "channel has no assigned release partitions".to_string(),
                ));
            }
            channel_releases = Some(releases);
        }
        let target = parse_image_target(&req.target)?;
        let cache_delivery = registry.visibility == "public";
        let cache_urls = if cache_delivery {
            self.db
                .registry_cache_stack_entries(registry.id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .map(|entry| entry.committed_url)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut messages = Vec::new();
        for image in self
            .db
            .list_system_images(registry.id)
            .await
            .map_err(RpcError::internal)?
        {
            if release
                .as_ref()
                .is_some_and(|value| value != &image.release)
                || channel_releases
                    .as_ref()
                    .is_some_and(|releases| !releases.contains(&image.release))
                || (!req.package.is_empty() && req.package != image.package)
                || (!req.architecture.is_empty() && req.architecture != image.delivery.architecture)
                || (!req.format.is_empty() && req.format != image.format)
                || target.is_some_and(|value| !image.delivery.compatible_targets.contains(&value))
            {
                continue;
            }
            messages.push(self.system_image_message(
                &download_base,
                image,
                (!req.channel.is_empty()).then_some(req.channel.as_str()),
                &cache_urls,
                cache_delivery,
            )?);
        }
        let (images, next_page_token) = paginate(messages, req.page_size, &req.page_token)?;
        Ok(pb::ListImagesResponse {
            images,
            next_page_token,
        })
    }

    /// `ImageService.GetImage` inspects one exact immutable image encoding.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an incomplete identity and a
    /// not-found or failed-precondition error unless exactly one image matches.
    pub async fn get_image(
        &self,
        auth: Option<&str>,
        req: pb::GetImageRequest,
    ) -> Result<pb::GetImageResponse, RpcError> {
        if req.release.is_empty() || req.architecture.is_empty() || req.format.is_empty() {
            return Err(RpcError::invalid(
                "release, architecture, and format are required",
            ));
        }
        self.resolve_image(
            auth,
            pb::ResolveImageRequest {
                slug: req.slug,
                release: req.release,
                channel: String::new(),
                architecture: req.architecture,
                format: req.format,
                target: String::new(),
                package: req.package,
            },
        )
        .await
    }

    /// `ImageService.ResolveImage` resolves a release or channel selection.
    ///
    /// # Errors
    ///
    /// Returns the normal registry visibility error, invalid selection errors,
    /// not found when no image matches, or failed precondition when ambiguous.
    pub async fn resolve_image(
        &self,
        auth: Option<&str>,
        req: pb::ResolveImageRequest,
    ) -> Result<pb::GetImageResponse, RpcError> {
        if req.release.is_empty() == req.channel.is_empty() {
            return Err(RpcError::invalid(
                "exactly one of release or channel is required",
            ));
        }
        let registry = self.registry_or_not_found(&req.slug).await?;
        self.require_read(auth, &registry).await?;
        let channel_label = (!req.channel.is_empty()).then(|| req.channel.clone());
        let mut release = req.release;
        if let Some(channel) = channel_label.as_deref() {
            release = self
                .db
                .list_channels(registry.id)
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .find(|candidate| candidate.name == channel)
                .ok_or_else(|| RpcError::not_found("channel"))?
                .frontier
                .ok_or_else(|| {
                    RpcError::FailedPrecondition("channel has no release frontier".to_string())
                })?;
        }
        let mut response = self
            .list_images(
                auth,
                pb::ListImagesRequest {
                    slug: req.slug,
                    release,
                    channel: String::new(),
                    architecture: req.architecture,
                    format: req.format,
                    target: req.target,
                    page_size: 2,
                    page_token: String::new(),
                    package: req.package,
                },
            )
            .await?;
        if let Some(channel) = channel_label {
            for image in &mut response.images {
                image.channel = channel.clone();
            }
        }
        match response.images.as_slice() {
            [image] => Ok(pb::GetImageResponse {
                image: Some(image.clone()),
            }),
            [] => Err(RpcError::not_found("system image")),
            _ => Err(RpcError::FailedPrecondition(
                "image selection is ambiguous; specify architecture, format, or target".to_string(),
            )),
        }
    }

    /// Resolves the single fully reconciled placement that may receive writes.
    pub(crate) async fn effective_surface_writer(
        &self,
        surface: SurfaceTarget,
    ) -> Result<crate::db::SurfacePlacementRecord, RpcError> {
        self.db
            .reconciled_surface_writer(surface)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))
    }

    /// Explains route selection for one surface URL and machine path.
    pub async fn explain_surface_request(
        &self,
        auth: Option<&str>,
        req: pb::ExplainSurfaceRequestRequest,
    ) -> Result<pb::ExplainSurfaceRequestResponse, RpcError> {
        let surface = self.readable_topology_surface(auth, req.surface).await?;
        let owner_scope_key = self.route_surface_owner_scope(surface).await?;
        self.require_delivery_scope(auth, &owner_scope_key, Permission::RouteRead)
            .await?;
        let parsed = url::Url::parse(&req.url)
            .map_err(|error| RpcError::invalid(format!("url: {error}")))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.username() != ""
            || parsed.password().is_some()
        {
            return Err(RpcError::invalid(
                "url must be an absolute HTTP(S) URL without userinfo",
            ));
        }
        let machine_path = if req.machine_path.is_empty() {
            parsed.path().to_string()
        } else {
            req.machine_path.clone()
        };
        if !machine_path.starts_with('/')
            || machine_path
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
            || machine_path.contains('?')
            || machine_path.contains('#')
        {
            return Err(RpcError::invalid(
                "machinePath must be an absolute normalized path",
            ));
        }
        let origin = parsed.origin().ascii_serialization();
        let mut candidates = Vec::new();
        let mut rejection_reasons = Vec::new();
        for route in self
            .db
            .list_routes(surface)
            .await
            .map_err(RpcError::internal)?
        {
            let snapshot = self
                .db
                .route_snapshot(&route.id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::internal(anyhow::anyhow!("route snapshot is missing")))?;
            let route_url = url::Url::parse(&snapshot.canonical_url).map_err(RpcError::internal)?;
            let route_origin = route_url.origin().ascii_serialization();
            let path_matches = snapshot.spec.base_path.is_empty()
                || machine_path == snapshot.spec.base_path
                || machine_path
                    .strip_prefix(&snapshot.spec.base_path)
                    .is_some_and(|suffix| suffix.starts_with('/'));
            let capability = match req.access_class.as_str() {
                "git" => snapshot.spec.serves_git,
                "nix_cache" => snapshot.spec.serves_cache,
                "web" => snapshot.spec.serves_web,
                "oci" => snapshot.spec.serves_oci,
                _ => {
                    return Err(RpcError::invalid(
                        "accessClass must be git, nix_cache, web, or oci",
                    ));
                }
            };
            if route.enabled
                && snapshot.observation_state == "healthy"
                && route_origin == origin
                && path_matches
                && capability
            {
                candidates.push((snapshot.spec.base_path.len(), route.id));
            } else if route_origin == origin {
                rejection_reasons.push(format!(
                    "route '{}' rejected: enabled={}, healthy={}, path_match={}, capability={}",
                    route.id,
                    route.enabled,
                    snapshot.observation_state == "healthy",
                    path_matches,
                    capability
                ));
            }
        }
        candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let selected_route_id = candidates
            .first()
            .map(|candidate| candidate.1.clone())
            .unwrap_or_default();
        let mut decisions = vec![format!("normalized origin is {origin}")];
        if selected_route_id.is_empty() {
            rejection_reasons.push("no healthy enabled route matched the request".to_string());
        } else {
            decisions.push(format!(
                "selected longest matching base path on route '{selected_route_id}'"
            ));
        }
        Ok(pb::ExplainSurfaceRequestResponse {
            normalized_url: format!("{origin}{machine_path}"),
            selected_route_id,
            decisions,
            rejection_reasons,
        })
    }

    /// Lists active, provenance-bearing retention reasons for a binary cache.
    ///
    /// # Errors
    ///
    /// Returns an authorization, registry-resolution, or database error.
    pub async fn list_root_reasons(
        &self,
        auth: Option<&str>,
        req: pb::ListRootReasonsRequest,
    ) -> Result<pb::ListRootReasonsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_operational_read(auth, &cache).await?;
        let registry_id = if req.registry_id.is_empty() {
            None
        } else {
            let (_, registry) = self
                .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, false)
                .await?;
            Some(registry.id)
        };
        let records = self
            .db
            .active_cache_root_reasons(cache.id, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|reason| registry_id.is_none_or(|id| reason.registry_id == Some(id)))
            .filter(|reason| req.store_hash.is_empty() || reason.store_hash == req.store_hash)
            .collect::<Vec<_>>();
        let mut reasons = Vec::with_capacity(records.len());
        for record in records {
            reasons.push(self.root_reason_message(&cache.slug, &record).await?);
        }
        let (reasons, next_page_token) = paginate(reasons, req.page_size, &req.page_token)?;
        Ok(pb::ListRootReasonsResponse {
            reasons,
            next_page_token,
        })
    }

    /// Returns the population target for one cache/registry pair.
    ///
    /// # Errors
    ///
    /// Returns an authorization, ambiguity, not-found, or database error.
    pub async fn get_population_target(
        &self,
        auth: Option<&str>,
        req: pb::GetPopulationTargetRequest,
    ) -> Result<pb::PopulationTargetResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, false)
            .await?;
        let record = self.single_population_target(cache.id, registry.id).await?;
        Ok(pb::PopulationTargetResponse {
            target: Some(Self::population_target_message(
                &record,
                &cache.slug,
                &registry.slug,
            )),
        })
    }

    /// Lists population targets for one binary cache.
    ///
    /// # Errors
    ///
    /// Returns an authorization or database error.
    pub async fn list_population_targets(
        &self,
        auth: Option<&str>,
        req: pb::ListPopulationTargetsRequest,
    ) -> Result<pb::ListPopulationTargetsResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &cache).await?;
        let records = self
            .db
            .list_cache_population_targets(cache.id)
            .await
            .map_err(RpcError::internal)?;
        let mut targets = Vec::new();
        for record in &records {
            let registry = self
                .db
                .registry_by_id(record.registry_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("registry"))?;
            targets.push(Self::population_target_message(
                record,
                &cache.slug,
                &registry.slug,
            ));
        }
        let (targets, next_page_token) = paginate(targets, req.page_size, &req.page_token)?;
        Ok(pb::ListPopulationTargetsResponse {
            targets,
            next_page_token,
        })
    }

    /// Computes current retention-root object coverage.
    ///
    /// # Errors
    ///
    /// Returns an authorization or database error.
    pub async fn get_coverage(
        &self,
        auth: Option<&str>,
        req: pb::GetPopulationTargetRequest,
    ) -> Result<pb::CoverageResponse, RpcError> {
        let (cache, registry) = self
            .authorized_cache_registry_pair(auth, &req.cache_id, &req.registry_id, false)
            .await?;
        let hashes = self
            .db
            .active_cache_root_reasons(cache.id, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .filter(|reason| reason.registry_id == Some(registry.id))
            .map(|reason| reason.store_hash)
            .collect::<std::collections::BTreeSet<_>>();
        let mut missing = Vec::new();
        for hash in &hashes {
            if self
                .db
                .normalized_cache_object(cache.id, hash)
                .await
                .map_err(RpcError::internal)?
                .is_none()
            {
                missing.push(hash.clone());
            }
        }
        Ok(pb::CoverageResponse {
            cache_id: cache.slug,
            registry_id: registry.slug,
            state: if missing.is_empty() {
                "complete"
            } else {
                "incomplete"
            }
            .to_string(),
            required_objects: u64::try_from(hashes.len()).unwrap_or_default(),
            present_objects: u64::try_from(hashes.len().saturating_sub(missing.len()))
                .unwrap_or_default(),
            missing_store_hashes: missing,
            observed_at: clock::now_unix_secs(),
        })
    }

    /// `OrganizationService.ListOrganizations` — the caller's organizations,
    /// ordered by slug.
    ///
    /// This is *not* a public directory: the caller must present a bearer JWT,
    /// and each org is included only when that caller holds
    /// [`Permission::Read`] covering its scope (soft-deleted orgs are already
    /// excluded by [`Database::list_orgs`](crate::db::Database::list_orgs)).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::Unauthenticated`] for a missing/invalid bearer JWT,
    /// [`RpcError::InvalidArgument`] for a malformed `page_token`, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn list_organizations(
        &self,
        auth: Option<&str>,
        req: pb::ListOrganizationsRequest,
    ) -> Result<pb::ListOrganizationsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let all_orgs = self.db.list_orgs().await.map_err(RpcError::internal)?;
        let mut organizations: Vec<pb::Organization> = Vec::new();
        for org in all_orgs.iter() {
            if self
                .claims_allow(
                    Some(&claims),
                    Permission::Read,
                    &Scope::parse(&org.stable_id),
                )
                .await
            {
                organizations.push(organization_message(org));
            }
        }
        let (organizations, next_page_token) =
            paginate(organizations, req.page_size, &req.page_token)?;
        Ok(pb::ListOrganizationsResponse {
            organizations,
            next_page_token,
        })
    }

    /// Lists the service accounts owned by one organization.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error when the caller cannot
    /// manage organization members, [`RpcError::NotFound`] when the organization
    /// does not exist, and [`RpcError::Internal`] on database failure.
    pub async fn list_service_accounts(
        &self,
        auth: Option<&str>,
        req: pb::ListServiceAccountsRequest,
    ) -> Result<pb::ListServiceAccountsResponse, RpcError> {
        let claims = self.require_claims(auth)?;
        let org = self
            .db
            .org_by_slug(&req.org_slug)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("organization"))?;
        self.require_permission(
            &claims,
            Permission::MembersManage,
            &Scope::parse(&org.stable_id),
        )
        .await?;
        let accounts = self
            .db
            .list_service_accounts(org.id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|record| service_account_message(&org.slug, record))
            .collect::<Result<Vec<_>, _>>()?;
        let (service_accounts, next_page_token) =
            paginate(accounts, req.page_size, &req.page_token)?;
        Ok(pb::ListServiceAccountsResponse {
            service_accounts,
            next_page_token,
        })
    }

    /// `BindingService.ListBindings` lists one authorized owner scope.
    ///
    /// # Errors
    ///
    /// Returns an authorization, pagination, or persistence error.
    pub async fn list_bindings_v1(
        &self,
        auth: Option<&str>,
        req: pb::ListBindingsRequest,
    ) -> Result<pb::ListBindingsResponse, RpcError> {
        self.readable_storage_owner(auth, &req.owner_scope_key)
            .await?;
        let records = if req.include_granted {
            self.db
                .list_bindings_available_to_scope(&req.owner_scope_key)
                .await
        } else {
            self.db.list_bindings_by_scope(&req.owner_scope_key).await
        }
        .map_err(RpcError::internal)?;
        let mut bindings = Vec::with_capacity(records.len());
        for record in records {
            bindings.push(self.binding_message(record).await?);
        }
        let (bindings, next_page_token) = paginate(bindings, req.page_size, &req.page_token)?;
        Ok(pb::ListBindingsResponse {
            bindings,
            next_page_token,
        })
    }

    /// `TopologyService.GetWriteAuthority` — reads desired and observed authority.
    ///
    /// An absent authority is a valid, explicitly read-only surface and is
    /// returned as an absent response field rather than a not-found error.
    ///
    /// # Errors
    ///
    /// Returns control-plane authorization errors or
    /// [`RpcError::Internal`] when the authority projection is inconsistent.
    pub async fn get_write_authority(
        &self,
        auth: Option<&str>,
        req: pb::GetWriteAuthorityRequest,
    ) -> Result<pb::GetWriteAuthorityResponse, RpcError> {
        let (surface, _) = self.writable_topology_surface(auth, req.surface).await?;
        let authority = self
            .db
            .surface_write_authority(surface)
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::GetWriteAuthorityResponse {
            authority: match authority {
                Some(authority) => Some(self.write_authority_message(authority).await?),
                None => None,
            },
        })
    }
}
