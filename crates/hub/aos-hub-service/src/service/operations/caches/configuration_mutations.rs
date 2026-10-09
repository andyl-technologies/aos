//! Configuration mutations in the caches capability.

use super::*;

impl RpcService {
    /// Invalidates the cached instance settings (call after a settings save).
    pub async fn invalidate_instance_settings_cache(&self) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), "cfg:instance").await;
        }
    }

    /// Invalidates a registry's cached roster (call after a key rotation/change).
    pub async fn invalidate_roster_cache(&self, registry_id: i64) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), &format!("roster:{registry_id}")).await;
        }
    }

    /// `BinaryCacheService.RegisterCacheNarinfos` — observes completed direct
    /// NAR uploads and publishes their narinfos in one bounded control request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid cache selector, an oversized batch,
    /// insufficient cache-write authority, failed upload evidence, malformed
    /// narinfo, quota exhaustion, or persistence failure.
    pub async fn register_cache_narinfos(
        &self,
        auth: Option<&str>,
        req: pb::RegisterCacheNarinfosRequest,
    ) -> Result<pb::CacheNarinfoRegistrationResponse, RpcError> {
        if req.narinfos.len() > MAX_CACHE_NARINFO_REGISTRATION_BATCH {
            return Err(RpcError::ResourceExhausted(format!(
                "at most {MAX_CACHE_NARINFO_REGISTRATION_BATCH} narinfos may be registered at once"
            )));
        }
        let cache = self
            .cache_upload_target(&req.cache_id, &req.delivery_url)
            .await?;
        self.require_cache_admin(auth, &cache).await?;
        self.register_cache_narinfos_authorized(&cache, &req.narinfos)
            .await
    }

    /// Reports and indexes a fenced batch of cache narinfos.
    ///
    /// Used after the NAR bytes were uploaded directly to the origin via
    /// presigned URLs: the client sends the (small) narinfos and the hub writes
    /// each to the surface and updates the index in one round-trip, so a bulk
    /// push is bounded by direct-to-origin NAR throughput rather than per-object
    /// Worker round-trips. Each narinfo goes through the same admitted write
    /// path as `Self::write_cache_object`: auth, server-side signing for a
    /// key-bearing cache, surface write, quota, and index write-through.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors,
    /// [`RpcError::invalid`] for a malformed narinfo path or oversize body, and
    /// [`RpcError::Internal`] on a surface/database failure.
    pub async fn report_cache_narinfos(
        &self,
        auth: Option<&str>,
        req: pb::ReportCacheNarinfosRequest,
    ) -> Result<pb::CacheNarinfoRegistrationResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        self.register_cache_narinfos_authorized(&cache, &req.narinfos)
            .await
    }

    /// `BinaryCacheService.CacheClosure` — the transitive closure of a store path.
    ///
    /// Breadth-first over `cache_objects.refs` from `store_hash` (root first); a
    /// reference absent from the cache appears with `present = false`. Bounded at
    /// `MAX_CLOSURE_NODES` to keep the response finite.
    ///
    /// # Errors
    ///
    /// [`RpcError::NotFound`] for an unknown cache, auth errors, and
    /// [`RpcError::Internal`] on database failure.
    pub async fn cache_closure(
        &self,
        auth: Option<&str>,
        req: pb::CacheClosureRequest,
    ) -> Result<pb::CacheClosureResponse, RpcError> {
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_read(auth, &cache).await?;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        queue.push_back(req.store_hash.clone());
        let mut nodes = Vec::new();
        let mut total_size = 0u64;
        while let Some(hash) = queue.pop_front() {
            if nodes.len() >= MAX_CLOSURE_NODES {
                break;
            }
            if !seen.insert(hash.clone()) {
                continue;
            }
            match self
                .db
                .normalized_cache_object(cache.id, &hash)
                .await
                .map_err(RpcError::internal)?
            {
                Some(object) => {
                    total_size = total_size
                        .saturating_add(u64::try_from(object.file_size).unwrap_or_default());
                    for r in &object.references {
                        if !seen.contains(r) {
                            queue.push_back(r.clone());
                        }
                    }
                    nodes.push(pb::CacheClosureNode {
                        store_hash: object.store_hash,
                        store_name: object.store_name,
                        file_size: u64::try_from(object.file_size).unwrap_or_default(),
                        refs: object.references,
                        present: true,
                    });
                }
                None => nodes.push(pb::CacheClosureNode {
                    store_hash: hash,
                    store_name: String::new(),
                    file_size: 0,
                    refs: Vec::new(),
                    present: false,
                }),
            }
        }
        Ok(pb::CacheClosureResponse { nodes, total_size })
    }

    /// Mint a presigned `GET` URL for a cache object on a private external
    /// origin, or `Ok(None)` when the cache is not presign-configured.
    ///
    /// A cache is presign-configured when its binding has private
    /// access, a typed S3/R2 origin, and a validated current `presign`
    /// credential generation. The resolved plaintext is
    /// `access_key:secret_key:region` (the secret may itself contain `:`; only
    /// the first and last separators are split on). The signed object key is
    /// `{prefix}/{path}` under the binding's origin host. Returns `Ok(None)` when
    /// not presign-mode or when no sealer is wired (the read then falls through
    /// to local byte serving).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, credential resolution failure, a
    /// malformed credential capability, or when the SigV4 signer rejects the inputs.
    pub async fn presign_cache_read(
        &self,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
        path: &str,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        if placement.cache_id.is_none() || !placement.effective_read_enabled {
            anyhow::bail!("cache read presign requires an effective cache placement");
        }
        self.presign_placement(placement, path, now, None, None)
            .await
    }

    /// Serve a managed cache's machine surface as a **streaming** response — the
    /// single shared cache-read path both shells route through.
    ///
    /// This replaces the former native-only `cache_serve_file` so the native hub
    /// and the Worker stream NAR/narinfo through the *same* code: visibility gate
    /// → generated `nix-cache-info` → placement selection/failover → a
    /// streaming body from
    /// [`SurfaceFetch::fetch_stream`]
    /// honoring `Range:` (`206` + `Content-Range`). Each shell's fetcher supplies
    /// the stream (native: a `tokio` file `ReaderStream`; Worker: an R2 ranged
    /// GET), so a large NAR never buffers into memory on either.
    ///
    /// Returns `Ok(None)` for an absent object (the caller renders `404`).
    ///
    /// # Errors
    ///
    /// Auth/visibility errors for a non-public cache read without authority, and
    /// [`RpcError::Internal`] on store/database failure.
    pub async fn cache_serve(
        &self,
        auth: ReadAuthorization<'_>,
        cache: &aos_hub_db::db::BinaryCache,
        path: &str,
        range_header: Option<&str>,
    ) -> Result<Option<axum::response::Response>, RpcError> {
        use axum::http::header;
        // As for registries, discard the route's potentially stale snapshot.
        // Soft/hard deletion must win before generated responses or topology
        // planning can serve bytes.
        let cache = self
            .db
            .binary_cache_by_id(cache.id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache"))?;
        self.require_cache_stream_read(auth, &cache).await?;

        // `nix-cache-info` is hub-generated — small, never streamed or presigned.
        if path == "nix-cache-info" {
            let body = render_nix_cache_info(cache.want_mass_query, cache.priority);
            let resp = axum::response::IntoResponse::into_response((
                [
                    (header::CONTENT_TYPE, keymap::content_type(path)),
                    (header::CACHE_CONTROL, keymap::cache_control(path)),
                ],
                body,
            ));
            return Ok(Some(resp));
        }

        let requested = parse_byte_range(range_header);
        match placement_read::stream_from_placements(
            self.db.as_ref(),
            self.surface.as_ref(),
            SurfaceTarget::BinaryCache(cache.id),
            path,
            requested,
        )
        .await
        .map_err(RpcError::surface_read)?
        {
            PlacementReadOutcome::Found(read) => {
                return Ok(Some(Self::streamed_surface_response(path, read.value)?));
            }
            PlacementReadOutcome::NotFound => return Ok(None),
        }
    }

    /// Applies a reviewed binary-cache creation plan.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-plan, conflict, or database error.
    pub async fn create_binary_cache(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBinaryCacheMutationRequest,
    ) -> Result<pb::BinaryCacheResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "create_binary_cache",
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
            "create_binary_cache",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BinaryCacheMutationPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "create_binary_cache",
                Some(&req.confirmation_hash),
            )
            .await?;
        let desired = input
            .request
            .desired
            .ok_or_else(|| RpcError::invalid("plan desired state is missing"))?;
        let id = self
            .db
            .create_binary_cache(
                Some(input.org_id),
                &desired.slug,
                &desired.name,
                &desired.visibility,
                i64::from(desired.nix_priority),
                &desired.compression,
                desired.want_mass_query,
            )
            .await
            .map_err(|error| RpcError::AlreadyExists(format!("{error:#}")))?;
        let cache = self
            .db
            .binary_cache_by_id(id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::internal(anyhow::anyhow!("created cache disappeared")))?;
        let response = pb::BinaryCacheResponse {
            cache: Some(self.binary_cache_message(&cache, true).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies a reviewed binary-cache identity update with CAS.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, stale-plan, stale-version, or database error.
    pub async fn update_binary_cache(
        &self,
        auth: Option<&str>,
        req: pb::ApplyBinaryCacheMutationRequest,
    ) -> Result<pb::BinaryCacheResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "update_binary_cache",
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
            "update_binary_cache",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BinaryCacheMutationPlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "update_binary_cache",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self
            .binary_cache_or_not_found(&input.request.stable_id)
            .await?;
        self.require_cache_admin(auth, &cache).await?;
        let desired = input
            .request
            .desired
            .ok_or_else(|| RpcError::invalid("plan desired state is missing"))?;
        let expected = parse_resource_version(
            &input.request.expected_resource_version,
            cache.resource_version,
        )?;
        let changed = self
            .db
            .update_binary_cache_identity(
                cache.id,
                expected,
                &desired.name,
                &desired.visibility,
                i64::from(desired.nix_priority),
                &desired.compression,
                desired.want_mass_query,
            )
            .await
            .map_err(RpcError::internal)?;
        if !changed {
            return Err(RpcError::FailedPrecondition(
                "binary cache changed after planning".to_string(),
            ));
        }
        let cache = self
            .binary_cache_or_not_found(&input.request.stable_id)
            .await?;
        let response = pb::BinaryCacheResponse {
            cache: Some(self.binary_cache_message(&cache, true).await?),
        };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Applies dependency-guarded binary-cache deletion.
    ///
    /// # Errors
    ///
    /// Returns an authentication, authorization, confirmation, dependency, stale-plan, or database error.
    pub async fn delete_binary_cache(
        &self,
        auth: Option<&str>,
        req: pb::ApplyDeleteTopologyResourceRequest,
    ) -> Result<pb::DeleteTopologyResourceResponse, RpcError> {
        if let Some(response) = self
            .replayed_control_result(
                auth,
                &req.plan_id,
                "delete_binary_cache",
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
            "delete_binary_cache",
            &req.idempotency_key,
            Some(&req.confirmation_hash),
        )
        .await?;
        let (plan, input): (_, BinaryCacheDeletePlanInput) = self
            .load_control_plan(
                auth,
                &req.plan_id,
                "delete_binary_cache",
                Some(&req.confirmation_hash),
            )
            .await?;
        let cache = self.binary_cache_or_not_found(&input.stable_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        let deleted = self
            .db
            .delete_binary_cache_identity(input.cache_id, input.expected_resource_version)
            .await
            .map_err(RpcError::internal)?;
        if !deleted {
            return Err(RpcError::FailedPrecondition(
                "binary cache changed or still has live dependencies".to_string(),
            ));
        }
        let response = pb::DeleteTopologyResourceResponse { deleted: true };
        self.complete_control_plan(&plan.plan_id, &req.idempotency_key, &response)
            .await?;
        Ok(response)
    }

    /// Invalidates the KV-cached session resolution for `secret` (delete-on-write).
    ///
    /// Call on logout / session revocation so the change is observed at the next
    /// read rather than after the TTL. A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached.
    pub async fn invalidate_session_cache(&self, secret: &str) {
        if let Some(kv) = &self.kv {
            crate::cache::invalidate(kv.as_ref(), &session_cache_key(secret)).await;
        }
    }

    /// Tombstones a token id so any KV-cached resolution for it is rejected
    /// (call on revoke/rotate). A no-op when no [`KvStore`](crate::kv::KvStore)
    /// is attached.
    ///
    /// The tombstone outlives the resolution cache TTL (so no stale resolution
    /// can outlast it), after which the resolution re-validates from the database.
    pub async fn invalidate_token_cache(&self, token_id: &str) {
        if let Some(kv) = &self.kv {
            // 10× the resolution TTL is a generous margin over any cached entry's
            // lifetime (and clock skew); the value is irrelevant (presence is).
            let ttl = crate::cache::HOT_TTL_SECS * 10;
            let _ = kv.put(&format!("tokrev:{token_id}"), b"1", Some(ttl)).await;
        }
    }
}
