//! Configuration helpers in the caches capability.

use super::*;

impl RpcService {
    // -- BinaryCacheService (RFC-0004 "11-caches") ---------------------------------

    /// Resolves a managed cache by immutable stable identity or canonical slug.
    ///
    /// Stable identities remain the durable relationship key. Canonical slugs
    /// are accepted at the API boundary because they are the cache locator
    /// exposed by the CLI and Web UI. The two namespaces cannot collide:
    /// generated stable identities use the `cache:` prefix, while validated
    /// cache slugs are qualified ownership paths.
    pub(in crate::service) async fn binary_cache_or_not_found(
        &self,
        identifier: &str,
    ) -> Result<crate::db::BinaryCache, RpcError> {
        if let Some(cache) = self
            .db
            .binary_cache_by_stable_id(identifier)
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(cache);
        }

        self.db
            .binary_cache_by_slug(identifier)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache"))
    }

    /// Authorize a cache write at the cache's exact stable resource scope.
    pub(in crate::service) async fn require_cache_admin(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
    ) -> Result<(), RpcError> {
        let claims = self.require_claims(auth)?;
        match cache.org_id {
            Some(id) => {
                // A tombstoned (soft-deleted) org stops accepting mutations to
                // its caches, mirroring the registry write path's `resolve_writable`
                // → `org_is_active` gate. Without this, a cache under a deleted
                // org would keep accepting uploads and charge its quota.
                if !self
                    .db
                    .org_is_active(id)
                    .await
                    .map_err(RpcError::internal)?
                {
                    return Err(RpcError::not_found("cache"));
                }
                self.require_permission(
                    &claims,
                    Permission::RegistryConfigure,
                    &Scope::parse(&cache.scope_key),
                )
                .await
            }
            None => {
                self.require_permission(
                    &claims,
                    Permission::RegistryConfigure,
                    &Scope::parse(&cache.scope_key),
                )
                .await
            }
        }
    }

    /// Authorize a cache read: public caches are open; otherwise `read` on the
    /// cache's exact stable resource scope (with normal ancestor inheritance).
    pub(in crate::service) async fn require_cache_read(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
    ) -> Result<(), RpcError> {
        // A soft-deleted (tombstoned) cache is invisible to reads — symmetric
        // with `list_binary_caches`, which filters `deleted_at`, and with typed delivery.
        // Unconditional: a standalone cache (org_id = None) has no org-activity
        // check to fall back on, and registries rely on org-level soft-delete
        // only (they carry no per-row tombstone), so this guard is cache-specific.
        if cache.deleted_at.is_some() {
            return Err(RpcError::not_found("cache"));
        }
        if let Some(org_id) = cache.org_id {
            if !self
                .db
                .org_is_active(org_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::not_found("cache"));
            }
        }
        if cache.visibility == "public" {
            return Ok(());
        }
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, Permission::Read, &Scope::parse(&cache.scope_key))
            .await
    }

    /// Authorize a cache machine read while rechecking cache liveness.
    pub(in crate::service) async fn require_cache_stream_read(
        &self,
        auth: ReadAuthorization<'_>,
        cache: &crate::db::BinaryCache,
    ) -> Result<(), RpcError> {
        match auth {
            ReadAuthorization::AuthorizationHeader(header) => {
                self.require_cache_read(header, cache).await
            }
            ReadAuthorization::SessionCookie(secret) => {
                if cache.deleted_at.is_some() {
                    return Err(RpcError::not_found("cache"));
                }
                if let Some(org_id) = cache.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("cache"));
                    }
                }
                if cache.visibility == "public" {
                    return Ok(());
                }
                let session = self
                    .resolve_session_cached(secret)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::Unauthenticated("invalid session".into()))?;
                let grants = self
                    .db
                    .effective_scopes(Principal::user(session.auth.user_id))
                    .await
                    .map_err(RpcError::internal)?;
                let context = self
                    .db
                    .authorization_context(&cache.scope_key)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("cache scope"))?;
                if iam::allow(&grants, Permission::Read, &context) {
                    Ok(())
                } else {
                    Err(RpcError::PermissionDenied(
                        "read permission required".into(),
                    ))
                }
            }
            ReadAuthorization::PreauthorizedSession => {
                if cache.deleted_at.is_some() {
                    return Err(RpcError::not_found("cache"));
                }
                if let Some(org_id) = cache.org_id {
                    if !self
                        .db
                        .org_is_active(org_id)
                        .await
                        .map_err(RpcError::internal)?
                    {
                        return Err(RpcError::not_found("cache"));
                    }
                }
                Ok(())
            }
        }
    }

    pub(in crate::service) async fn admit_cache_proxy_writes(
        &self,
        cache: &crate::db::BinaryCache,
        placement: &crate::db::SurfacePlacementRecord,
        paths: &[String],
        sizes: &[u64],
        proxy_limit: u64,
        now: i64,
    ) -> Result<Vec<Option<String>>, RpcError> {
        let (binding_revision, credential_generation) =
            self.placement_write_snapshot(placement).await?;
        let mut candidates = Vec::new();
        let mut results = vec![None; paths.len()];
        for (index, (path, size)) in paths.iter().zip(sizes).enumerate() {
            if !keymap::is_machine_path(path) || *size > proxy_limit {
                continue;
            }
            let declared_size = i64::try_from(*size)
                .map_err(|_| RpcError::invalid("declared upload size is too large"))?;
            candidates.push((
                index,
                crate::db::CacheProxyWriteAdmission {
                    ticket_id: uuid::Uuid::new_v4().simple().to_string(),
                    object_key: path.clone(),
                    declared_size,
                },
            ));
        }
        if candidates.is_empty() {
            return Ok(results);
        }

        let object_keys = candidates
            .iter()
            .map(|(_, candidate)| candidate.object_key.clone())
            .collect::<Vec<_>>();
        let expires_at = now.saturating_add(INTERNAL_UPLOAD_AUTH_TTL_SECS);
        let mut last_conflict = None;
        for _ in 0..3 {
            let occupied = self
                .db
                .cache_write_ticket_slots(
                    cache.id,
                    &object_keys,
                    placement.id,
                    placement.resource_version,
                    binding_revision,
                    credential_generation,
                    now,
                )
                .await
                .map_err(RpcError::internal)?
                .into_iter()
                .map(|slot| (slot.ticket.object_key.clone(), slot))
                .collect::<BTreeMap<_, _>>();
            let mut missing = Vec::new();
            for (index, candidate) in &candidates {
                if let Some(slot) = occupied.get(&candidate.object_key) {
                    if slot.topology_current
                        && slot.ticket.declared_size == candidate.declared_size
                        && slot.ticket.upload_kind == "single"
                        && matches!(slot.ticket.state.as_str(), "observing" | "active")
                    {
                        results[*index] = Some(slot.ticket.ticket_id.clone());
                    }
                    continue;
                }
                missing.push(candidate.clone());
            }
            if missing.is_empty() {
                return Ok(results);
            }
            match self
                .db
                .begin_cache_proxy_write_tickets(
                    cache.id,
                    placement.id,
                    placement.resource_version,
                    binding_revision,
                    credential_generation,
                    cache.org_id,
                    expires_at,
                    now,
                    &missing,
                )
                .await
            {
                Ok(()) => {
                    let ticket_ids = missing
                        .into_iter()
                        .map(|ticket| (ticket.object_key, ticket.ticket_id))
                        .collect::<BTreeMap<_, _>>();
                    for (index, candidate) in &candidates {
                        if let Some(ticket_id) = ticket_ids.get(&candidate.object_key) {
                            results[*index] = Some(ticket_id.clone());
                        }
                    }
                    return Ok(results);
                }
                Err(error) => last_conflict = Some(error),
            }
        }
        Err(RpcError::internal(last_conflict.unwrap_or_else(|| {
            anyhow::anyhow!("cache proxy upload admission conflicted repeatedly")
        })))
    }

    pub(in crate::service) async fn admit_cache_proxy_write(
        &self,
        cache: &crate::db::BinaryCache,
        path: &str,
        size: u64,
        now: i64,
    ) -> Result<String, RpcError> {
        let placement = self
            .effective_surface_writer(SurfaceTarget::BinaryCache(cache.id))
            .await?;
        let (binding_revision, credential_generation) =
            self.placement_write_snapshot(&placement).await?;
        let declared_size = i64::try_from(size)
            .map_err(|_| RpcError::invalid("declared upload size is too large"))?;
        if let Some(ticket) = self
            .db
            .reusable_cache_write_ticket(
                cache.id,
                path,
                declared_size,
                "single",
                "observing",
                None,
                placement.id,
                placement.resource_version,
                binding_revision,
                credential_generation,
                now,
            )
            .await
            .map_err(RpcError::internal)?
        {
            return Ok(ticket.ticket_id);
        }
        if let Some(ticket) = self
            .db
            .reusable_cache_write_ticket(
                cache.id,
                path,
                declared_size,
                "single",
                "active",
                None,
                placement.id,
                placement.resource_version,
                binding_revision,
                credential_generation,
                now,
            )
            .await
            .map_err(RpcError::internal)?
        {
            // Admission does not know the body digest. The upload endpoint
            // compares the retried bytes with the digest pinned when this
            // ticket became active before allowing another provider write.
            return Ok(ticket.ticket_id);
        }
        let ticket_id = uuid::Uuid::new_v4().simple().to_string();
        let created = self
            .db
            .begin_cache_write_ticket(
                &ticket_id,
                cache.id,
                placement.id,
                placement.resource_version,
                binding_revision,
                credential_generation,
                path,
                declared_size,
                "single",
                cache.org_id,
                0,
                0,
                now.saturating_add(INTERNAL_UPLOAD_AUTH_TTL_SECS),
                now,
                None,
                None,
            )
            .await;
        match created {
            Ok(ticket) => Ok(ticket.ticket_id),
            Err(error) => {
                // A concurrent identical admission may win the exclusive
                // object slot between the read and insert. Return only an
                // exact observing or active winner under the same topology.
                // An active ticket remains body-bound at the upload endpoint.
                let mut winner = None;
                for state in ["observing", "active"] {
                    winner = self
                        .db
                        .reusable_cache_write_ticket(
                            cache.id,
                            path,
                            declared_size,
                            "single",
                            state,
                            None,
                            placement.id,
                            placement.resource_version,
                            binding_revision,
                            credential_generation,
                            now,
                        )
                        .await
                        .map_err(RpcError::internal)?;
                    if winner.is_some() {
                        break;
                    }
                }
                winner
                    .map(|ticket| ticket.ticket_id)
                    .ok_or_else(|| RpcError::internal(error))
            }
        }
    }

    pub(in crate::service) async fn register_cache_narinfos_authorized(
        &self,
        cache: &crate::db::BinaryCache,
        narinfos: &[pb::CacheNarinfo],
    ) -> Result<pb::CacheNarinfoRegistrationResponse, RpcError> {
        if narinfos.len() > MAX_CACHE_NARINFO_REGISTRATION_BATCH {
            return Err(RpcError::ResourceExhausted(format!(
                "at most {MAX_CACHE_NARINFO_REGISTRATION_BATCH} narinfos may be registered at once"
            )));
        }
        if narinfos
            .iter()
            .map(|narinfo| narinfo.store_hash.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != narinfos.len()
        {
            return Err(RpcError::invalid(
                "cache narinfo store hashes must be unique",
            ));
        }
        let now = clock::now_unix_secs();
        let registered = futures_util::stream::iter(narinfos.iter().cloned())
            .map(|narinfo| async move {
                let path = format!("{}.narinfo", narinfo.store_hash);
                if !narinfo.nar_upload_ticket_id.is_empty() {
                    let parsed =
                        parse_cache_narinfo(cache.id, &narinfo.store_hash, &narinfo.narinfo, now)
                            .ok_or_else(|| RpcError::invalid("narinfo has no valid NAR URL"))?;
                    self.observe_presigned_cache_upload(
                        cache,
                        &parsed.nar_url,
                        &narinfo.nar_upload_ticket_id,
                    )
                    .await?;
                }
                match self
                    .write_cache_object_authorized(cache, &path, narinfo.narinfo.as_bytes(), None)
                    .await
                {
                    SurfaceWriteOutcome::Created | SurfaceWriteOutcome::Overwritten => Ok(1_i64),
                    SurfaceWriteOutcome::BadPath(reason) => Err(RpcError::invalid(reason)),
                    SurfaceWriteOutcome::TooLarge => Err(RpcError::invalid("narinfo too large")),
                    SurfaceWriteOutcome::QuotaExceeded => {
                        Err(RpcError::invalid("org storage quota exceeded"))
                    }
                    SurfaceWriteOutcome::NotFound => Err(RpcError::not_found("cache")),
                    SurfaceWriteOutcome::Unauthorized(reason)
                    | SurfaceWriteOutcome::NotWritable(reason) => Err(RpcError::invalid(reason)),
                    other => Err(RpcError::internal(anyhow::anyhow!(
                        "narinfo register failed: {other:?}"
                    ))),
                }
            })
            .buffer_unordered(CACHE_NARINFO_REGISTRATION_CONCURRENCY)
            .try_fold(0_i64, |registered, count| async move {
                Ok(registered.saturating_add(count))
            })
            .await?;
        Ok(pb::CacheNarinfoRegistrationResponse { registered })
    }

    /// Serve a managed cache's machine surface.
    ///
    /// `nix-cache-info` is generated from the cache's config; `<hash>.narinfo`
    /// and `nar/<file>` are served as stored bytes from the cache surface. Reads
    /// honor the cache's visibility ([`Self::require_cache_read`]) and use
    /// ordered placement failover when topology is configured.
    ///
    /// # Errors
    ///
    /// Auth errors for a non-public cache read without authority, and
    /// [`RpcError::Internal`] on store/database failure. `Ok(None)` is a 404 for
    /// an absent object.
    pub(in crate::service) async fn cache_surface_fetch(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
        path: &str,
    ) -> Result<Option<SurfaceObjectResponse>, RpcError> {
        self.require_cache_read(auth, cache).await?;
        if path == "nix-cache-info" {
            let body = render_nix_cache_info(cache.want_mass_query, cache.priority);
            return Ok(Some(SurfaceObjectResponse {
                bytes: body.into_bytes(),
                content_type: keymap::content_type(path),
                cache_control: keymap::cache_control(path),
                redirect: None,
            }));
        }
        match placement_read::fetch_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::BinaryCache(cache.id),
            path,
        )
        .await
        .map_err(RpcError::surface_read)?
        {
            PlacementReadOutcome::Found(read) => {
                return Ok(Some(SurfaceObjectResponse {
                    bytes: read.value,
                    content_type: keymap::content_type(path),
                    cache_control: keymap::cache_control(path),
                    redirect: None,
                }));
            }
            PlacementReadOutcome::NotFound => return Ok(None),
        }
    }

    pub(in crate::service) fn validate_binary_cache_spec(
        desired: &pb::BinaryCacheSpec,
    ) -> Result<(), RpcError> {
        if desired.slug.is_empty() || desired.name.trim().is_empty() {
            return Err(RpcError::invalid("slug and name are required"));
        }
        if !matches!(
            desired.visibility.as_str(),
            "public" | "internal" | "private"
        ) {
            return Err(RpcError::invalid(
                "visibility must be public, internal, or private",
            ));
        }
        if !matches!(desired.compression.as_str(), "zstd" | "xz" | "none") {
            return Err(RpcError::invalid("compression must be zstd, xz, or none"));
        }
        Ok(())
    }

    pub(in crate::service) async fn binary_cache_owner_scope(
        &self,
        cache: &crate::db::BinaryCache,
    ) -> Result<String, RpcError> {
        Ok(cache.owner_scope_key.clone())
    }

    /// Requires one cache-specific management capability at its stable owner scope.
    pub(in crate::service) async fn require_cache_permission(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
        permission: Permission,
    ) -> Result<Claims, RpcError> {
        let claims = self.require_claims(auth)?;
        self.require_permission(&claims, permission, &Scope::parse(&cache.scope_key))
            .await?;
        Ok(claims)
    }

    /// Requires an authenticated cache reader, even when content delivery is public.
    pub(in crate::service) async fn require_cache_operational_read(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
    ) -> Result<Claims, RpcError> {
        self.require_cache_permission(auth, cache, Permission::Read)
            .await
    }

    pub(in crate::service) async fn binary_cache_message(
        &self,
        cache: &crate::db::BinaryCache,
        include_usage: bool,
    ) -> Result<pb::BinaryCache, RpcError> {
        let usage = if include_usage {
            self.db
                .cache_usage(cache.id)
                .await
                .map_err(RpcError::internal)?
        } else {
            crate::db::CacheUsage::default()
        };
        let placement_count = self
            .db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache.id))
            .await
            .map_err(RpcError::internal)?
            .len();
        let retention_root_count = self
            .db
            .active_cache_root_reasons(cache.id, clock::now_unix_secs())
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|reason| reason.store_hash)
            .collect::<BTreeSet<_>>()
            .len();
        Ok(pb::BinaryCache {
            stable_id: cache.stable_id.clone(),
            slug: cache.slug.clone(),
            name: cache.name.clone(),
            owner_scope_key: self.binary_cache_owner_scope(cache).await?,
            visibility: cache.visibility.clone(),
            nix_priority: u32::try_from(cache.priority).unwrap_or_default(),
            compression: cache.compression.clone(),
            want_mass_query: cache.want_mass_query,
            signed: self
                .db
                .signing_key_usage(&cache.stable_id, "narinfo")
                .await
                .map_err(RpcError::internal)?
                .is_some_and(|usage| usage.state == "active"),
            resource_version: cache.resource_version.to_string(),
            created_at: cache.created_at,
            updated_at: cache.updated_at,
            used_bytes: u64::try_from(usage.used_bytes).unwrap_or_default(),
            object_count: u64::try_from(usage.object_count).unwrap_or_default(),
            placement_count: u64::try_from(placement_count).unwrap_or_default(),
            retention_root_count: u64::try_from(retention_root_count).unwrap_or_default(),
            authorization_scope_key: cache.scope_key.clone(),
        })
    }

    pub(in crate::service) async fn authorized_cache_registry_pair(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        registry_id: &str,
        mutate: bool,
    ) -> Result<(crate::db::BinaryCache, RegistryRecord), RpcError> {
        let cache = self.binary_cache_or_not_found(cache_id).await?;
        let registry = self.registry_or_not_found(registry_id).await?;
        if mutate {
            self.require_cache_admin(auth, &cache).await?;
            let claims = self.require_claims(auth)?;
            self.require_permission(
                &claims,
                Permission::RegistryConfigure,
                &self.registry_scope(&registry).await?,
            )
            .await?;
        } else {
            self.require_cache_read(auth, &cache).await?;
            let claims = self.require_claims(auth)?;
            self.require_permission(
                &claims,
                Permission::Read,
                &self.registry_scope(&registry).await?,
            )
            .await?;
        }
        Ok((cache, registry))
    }

    pub(in crate::service) async fn create_cache_operation(
        &self,
        cache_id: i64,
        kind: &str,
        control_permission: Permission,
        detail: serde_json::Value,
    ) -> Result<pb::OperationResponse, RpcError> {
        let operation = self
            .db
            .create_topology_operation(&crate::db::NewTopologyOperation {
                operation_id: uuid::Uuid::new_v4().to_string(),
                operation_kind: kind.to_string(),
                control_permission,
                targets: vec![crate::db::NewTopologyOperationTarget {
                    role: "primary".to_string(),
                    target: crate::db::NewTopologyOperationTargetRef::BinaryCache(cache_id),
                    generation_key: 0,
                    configuration_digest: String::new(),
                }],
                progress_total: None,
                detail_json: detail.to_string(),
            })
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::OperationResponse {
            operation: Some(pb::OperationRef {
                operation_id: operation.operation_id,
                kind: operation.operation_kind,
                state: operation.state,
                created_at: operation.created_at,
            }),
        })
    }
}
