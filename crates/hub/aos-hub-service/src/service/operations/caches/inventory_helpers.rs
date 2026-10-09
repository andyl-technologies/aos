//! Inventory helpers in the caches capability.

use super::*;

impl RpcService {
    /// Writes one admitted object (`<hash>.narinfo` or `nar/<file>`) into a
    /// managed cache surface.
    ///
    /// Simpler than the registry write: NARs/narinfo are content-addressed and
    /// immutable, so there is no publish lease and no re-index. Requires cache
    /// write authority ([`Self::require_cache_admin`]); charges the org storage
    /// quota with a TOCTOU-safe reserve-before-write.
    pub(in crate::service) async fn write_cache_object(
        &self,
        auth: Option<&str>,
        cache: &crate::db::BinaryCache,
        path: &str,
        body: &[u8],
        admission: Option<crate::db::CacheWriteTicketRecord>,
    ) -> SurfaceWriteOutcome {
        if let Err(deny) = self.require_cache_admin(auth, &cache).await {
            return auth_denial_to_write_outcome(deny);
        }
        self.write_cache_object_authorized(cache, path, body, admission)
            .await
    }

    /// Writes one cache object after the caller has checked cache authority.
    pub(in crate::service) async fn write_cache_object_authorized(
        &self,
        cache: &crate::db::BinaryCache,
        path: &str,
        body: &[u8],
        admission: Option<crate::db::CacheWriteTicketRecord>,
    ) -> SurfaceWriteOutcome {
        if cache.deleted_at.is_some() {
            return SurfaceWriteOutcome::NotFound;
        }
        if !keymap::is_machine_path(path) {
            return SurfaceWriteOutcome::BadPath("not a machine path");
        }
        if crate::url_guard::validate_http_surface_path(path).is_err() {
            return SurfaceWriteOutcome::BadPath("unsafe surface path");
        }
        if body.len() > self.effective_max_upload_bytes().await {
            return SurfaceWriteOutcome::TooLarge;
        }
        let intended_object_hash = hex::encode(Sha256::digest(body));
        if let Some(ticket) = admission
            .as_ref()
            .filter(|ticket| ticket.state == "completed")
        {
            if ticket.cache_id != cache.id
                || ticket.object_key != path
                || ticket.upload_kind != "single"
                || ticket.declared_size != i64::try_from(body.len()).unwrap_or(i64::MAX)
                || ticket.observed_final_size != Some(ticket.declared_size)
                || ticket.intended_object_hash.as_deref() != Some(intended_object_hash.as_str())
            {
                return SurfaceWriteOutcome::BadPath(
                    "completed cache upload retry does not match its durable request",
                );
            }
            return if ticket.prior_object.is_some() {
                SurfaceWriteOutcome::Overwritten
            } else {
                SurfaceWriteOutcome::Created
            };
        }
        // Private key material is never held by the Hub. Narinfo signatures
        // arrive with the immutable upload and are verified through the exact
        // signing-key generation pinned by the cache's `narinfo` usage.
        if path.ends_with(".narinfo") {
            let selected_key = match self
                .db
                .active_signing_key_for_usage(&cache.stable_id, "narinfo")
                .await
            {
                Ok(key) => key,
                Err(error) => return internal_write(error),
            };
            if let Some(selected_key) = selected_key {
                let narinfo = match std::str::from_utf8(body) {
                    Ok(narinfo) => narinfo,
                    Err(_) => return SurfaceWriteOutcome::BadPath("narinfo body is not UTF-8"),
                };
                if crate::nix_sign::verify_narinfo(
                    narinfo,
                    &selected_key.name,
                    &selected_key.public_key,
                )
                .is_err()
                {
                    return SurfaceWriteOutcome::BadPath(
                        "narinfo is not signed by its selected key generation",
                    );
                }
            }
        }
        let now = clock::now_unix_secs();
        let (placement, admitted) = if let Some(ticket) = admission {
            if ticket.cache_id != cache.id
                || ticket.object_key != path
                || ticket.upload_kind != "single"
                || ticket.expires_at <= now
                || ticket.declared_size != i64::try_from(body.len()).unwrap_or(i64::MAX)
            {
                if ticket.state == "observing" {
                    settle_cache_write_failure(
                        &self.db,
                        &ticket.ticket_id,
                        ticket.resource_version,
                        false,
                        now,
                    )
                    .await;
                }
                return SurfaceWriteOutcome::BadPath(
                    "cache upload does not match its admitted path and size",
                );
            }
            let ticket = match ticket.state.as_str() {
                "observing" => ticket,
                "active"
                    if ticket.intended_object_hash.as_deref()
                        == Some(intended_object_hash.as_str()) =>
                {
                    match self
                        .db
                        .validate_cache_write_ticket(&ticket.ticket_id, cache.id, path, now, false)
                        .await
                    {
                        Ok(ticket) => ticket,
                        Err(error) => return internal_write(error),
                    }
                }
                "active" => {
                    return SurfaceWriteOutcome::BadPath(
                        "cache upload retry does not match the admitted body",
                    );
                }
                _ => {
                    return SurfaceWriteOutcome::NotWritable(
                        "cache upload admission is not writable",
                    );
                }
            };
            let placement = match self.db.surface_placement(ticket.placement_id).await {
                Ok(Some(placement)) if placement.cache_id == Some(cache.id) => placement,
                Ok(_) => {
                    return SurfaceWriteOutcome::NotWritable("cache write placement disappeared");
                }
                Err(error) => return internal_write(error),
            };
            (placement, ticket)
        } else {
            let placement = match self
                .effective_surface_writer(SurfaceTarget::BinaryCache(cache.id))
                .await
            {
                Ok(placement) => placement,
                Err(RpcError::FailedPrecondition(_)) | Err(RpcError::NotFound(_)) => {
                    return SurfaceWriteOutcome::NotWritable(
                        "cache has no reconciled write placement",
                    );
                }
                Err(error) => return internal_write(anyhow::anyhow!(error.message().to_string())),
            };
            let (binding_revision, credential_generation) = match self
                .placement_write_snapshot(&placement)
                .await
            {
                Ok(snapshot) => snapshot,
                Err(error) => return internal_write(anyhow::anyhow!(error.message().to_string())),
            };
            let ticket_id = uuid::Uuid::new_v4().simple().to_string();
            let admitted = match self
                .db
                .begin_cache_write_ticket(
                    &ticket_id,
                    cache.id,
                    placement.id,
                    placement.resource_version,
                    binding_revision,
                    credential_generation,
                    path,
                    i64::try_from(body.len()).unwrap_or(i64::MAX),
                    "single",
                    cache.org_id,
                    0,
                    0,
                    now.saturating_add(INTERNAL_UPLOAD_AUTH_TTL_SECS),
                    now,
                    None,
                    None,
                )
                .await
            {
                Ok(ticket) => ticket,
                Err(err) => {
                    return internal_write(err.context("creating cache write observation fence"));
                }
            };
            (placement, admitted)
        };
        let writer = match self.surface_write.placement_writer(&placement).await {
            Ok(writer) => writer,
            Err(err) => {
                tracing::warn!(slug = %cache.slug, error = %format!("{err:#}"), "no writable surface for cache upload");
                return SurfaceWriteOutcome::NotWritable("cache surface is not writable");
            }
        };
        let inventory = match self.surface.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(error) => return internal_write(error),
        };
        let (ticket, existed) = if admitted.state == "active" {
            let existed = admitted.prior_object.is_some();
            (admitted, existed)
        } else {
            // Overwrite delta for the org quota: read the old size before the
            // ticket becomes active. An exact-body retry reuses the persisted
            // baseline and reservation instead of observing mutable state again.
            let prior_object = match inventory.inventory_evidence(path).await {
                Ok(evidence) => evidence.map(write_object_identity),
                Err(err) => {
                    settle_cache_write_failure(
                        &self.db,
                        &admitted.ticket_id,
                        admitted.resource_version,
                        false,
                        now,
                    )
                    .await;
                    return internal_write(err);
                }
            };
            let old_len = prior_object.as_ref().map(|identity| identity.size);
            let existed = prior_object.is_some();
            let delta_bytes = body.len() as i64 - old_len.unwrap_or(0);
            let delta_objects = i64::from(!existed);
            let ticket = match self
                .db
                .activate_cache_write_ticket(
                    &admitted.ticket_id,
                    admitted.resource_version,
                    cache.org_id,
                    delta_bytes,
                    delta_objects,
                    prior_object.as_ref(),
                    Some(&intended_object_hash),
                    now,
                )
                .await
            {
                Ok(ticket) => ticket,
                Err(err) => {
                    settle_cache_write_failure(
                        &self.db,
                        &admitted.ticket_id,
                        admitted.resource_version,
                        false,
                        now,
                    )
                    .await;
                    return internal_write(err.context("activating cache write ticket"));
                }
            };
            (ticket, existed)
        };
        if let Err(err) = writer.write(path, body).await {
            settle_cache_write_failure(
                &self.db,
                &ticket.ticket_id,
                ticket.resource_version,
                true,
                now,
            )
            .await;
            // An opaque transport result leaves the active ticket and its
            // reservation intact. Identity-aware expiry recovery decides
            // whether the intended bytes landed or the prior object survived.
            return internal_write(err);
        }
        let observed = match self.surface.placement_fetcher(&placement).await {
            Ok(fetch) => match fetch.inventory_evidence(path).await {
                Ok(Some(evidence)) => evidence,
                Ok(None) => {
                    settle_cache_write_failure(
                        &self.db,
                        &ticket.ticket_id,
                        ticket.resource_version,
                        true,
                        now,
                    )
                    .await;
                    return SurfaceWriteOutcome::NotWritable("completed cache write is absent");
                }
                Err(error) => {
                    settle_cache_write_failure(
                        &self.db,
                        &ticket.ticket_id,
                        ticket.resource_version,
                        true,
                        now,
                    )
                    .await;
                    return internal_write(error);
                }
            },
            Err(error) => {
                settle_cache_write_failure(
                    &self.db,
                    &ticket.ticket_id,
                    ticket.resource_version,
                    true,
                    now,
                )
                .await;
                return internal_write(error);
            }
        };
        if observed.size != i64::try_from(body.len()).unwrap_or(i64::MAX)
            || hex::encode(observed.sha256) != intended_object_hash
        {
            settle_cache_write_failure(
                &self.db,
                &ticket.ticket_id,
                ticket.resource_version,
                true,
                now,
            )
            .await;
            return SurfaceWriteOutcome::NotWritable(
                "completed cache write does not match the admitted body",
            );
        }
        // Completion records an uncovered inventory delta and advances the
        // cache epoch atomically. A later complete inventory scan covers every
        // finished delta; GC remains fail-closed until that publication.
        if let Err(err) = self
            .db
            .complete_cache_write_ticket(
                &ticket.ticket_id,
                ticket.resource_version,
                clock::now_unix_secs(),
            )
            .await
        {
            if matches!(
                self.db.cache_write_ticket(&ticket.ticket_id).await,
                Ok(Some(current)) if current.state == "completed"
            ) {
                return if existed {
                    SurfaceWriteOutcome::Overwritten
                } else {
                    SurfaceWriteOutcome::Created
                };
            }
            settle_cache_write_failure(
                &self.db,
                &ticket.ticket_id,
                ticket.resource_version,
                true,
                now,
            )
            .await;
            return internal_write(err.context("finalizing cache write ticket"));
        }
        if existed {
            SurfaceWriteOutcome::Overwritten
        } else {
            SurfaceWriteOutcome::Created
        }
    }
}
