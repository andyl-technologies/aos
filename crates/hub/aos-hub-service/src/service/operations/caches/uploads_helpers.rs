//! Uploads helpers in the caches capability.

use super::*;

impl RpcService {
    pub(in crate::service) fn cache_proxy_upload_url(
        &self,
        cache: &crate::db::BinaryCache,
        ticket_id: &str,
        path: &str,
    ) -> String {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(path);
        format!(
            "{}/aos.hub.v1.BinaryCacheService/UploadObject/{}/{}/{}",
            self.external_url.trim_end_matches('/'),
            cache.stable_id,
            ticket_id,
            encoded
        )
    }

    pub(in crate::service) async fn cache_upload_target(
        &self,
        cache_id: &str,
        delivery_url: &str,
    ) -> Result<crate::db::BinaryCache, RpcError> {
        match (!cache_id.is_empty(), !delivery_url.is_empty()) {
            (true, false) => self.binary_cache_or_not_found(cache_id).await,
            (false, true) => self
                .db
                .binary_cache_by_ready_delivery_url(delivery_url)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("cache route")),
            _ => Err(RpcError::invalid(
                "exactly one of cache_id or delivery_url is required",
            )),
        }
    }

    /// Byte-verifies and records one direct-origin cache upload.
    pub(in crate::service) async fn observe_presigned_cache_upload(
        &self,
        cache: &crate::db::BinaryCache,
        path: &str,
        upload_ticket_id: &str,
    ) -> Result<pb::CacheUploadObservationResponse, RpcError> {
        let now = clock::now_unix_secs();
        let ticket = self
            .db
            .validate_cache_write_ticket(upload_ticket_id, cache.id, path, now, false)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if ticket.upload_kind != "presigned" {
            return Err(RpcError::invalid("upload ticket is not a presigned PUT"));
        }
        let placement = self
            .db
            .surface_placement(ticket.placement_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("upload placement"))?;
        let fetch = self
            .surface
            .placement_fetcher(&placement)
            .await
            .map_err(RpcError::internal)?;
        let observed = fetch
            .inventory_evidence(path)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("uploaded object"))?;
        let observed_size = observed.size;
        if observed_size != ticket.declared_size {
            return Err(RpcError::FailedPrecondition(
                "uploaded object size does not match the signed Content-Length".into(),
            ));
        }
        self.db
            .acknowledge_presigned_cache_write_ticket(
                &ticket.ticket_id,
                ticket.resource_version,
                observed.strong_etag.as_deref(),
                Some(&hex::encode(observed.sha256)),
                observed_size,
                now,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::CacheUploadObservationResponse {
            observed: true,
            expires_at: ticket
                .expires_at
                .saturating_sub(PRESIGN_WRITE_FENCE_GRACE_SECS),
        })
    }

    pub(in crate::service) async fn prepare_registry_publication_object_upload(
        &self,
        publication: &crate::db::RegistryPublicationRecord,
        registry: &crate::db::RegistryRecord,
        object: &crate::db::RegistryPublicationUploadObjectRecord,
    ) -> Result<(), RpcError> {
        if let Some(state) = self
            .db
            .staged_publication_state(&publication.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            if matches!(state.as_str(), "discarded" | "superseded") {
                return Err(RpcError::FailedPrecondition(
                    "staged release inventory is retired".into(),
                ));
            }
        }
        if object.object_kind == "immutable" && publication.state != "preparing" {
            return Err(RpcError::FailedPrecondition(
                "immutable upload phase is closed".into(),
            ));
        }
        if object.object_kind != "mutable_pointer" {
            return Ok(());
        }
        if let Some(state) = self
            .db
            .staged_publication_state(&publication.publication_id)
            .await
            .map_err(RpcError::internal)?
        {
            if state != "releasing" {
                return Err(RpcError::FailedPrecondition(
                    "staged release pointers require explicit finalization".into(),
                ));
            }
        }
        if !self
            .db
            .registry_publication_class_is_complete(&publication.publication_id, "immutable")
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::FailedPrecondition(
                "all immutable objects must verify before pointer upload".into(),
            ));
        }
        self.lease
            .acquire(
                registry.id,
                &publication.publication_id,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|holder| {
                RpcError::FailedPrecondition(format!(
                    "registry publication lease is held by {holder}"
                ))
            })?;
        if publication.state == "preparing" {
            let advanced = self
                .db
                .advance_registry_publication(
                    &publication.publication_id,
                    "preparing",
                    "writing_pointers",
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            if !advanced {
                // Independent pointer writes may all observe `preparing` before
                // one of them opens the pointer phase. The losing requests are
                // valid only when that exact transition won the race.
                let current = self
                    .db
                    .registry_publication(&publication.publication_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry publication"))?;
                if current.state != "writing_pointers" {
                    return Err(RpcError::FailedPrecondition(
                        "publication pointer phase changed concurrently".into(),
                    ));
                }
            }
        } else if !matches!(publication.state.as_str(), "preparing" | "writing_pointers") {
            return Err(RpcError::FailedPrecondition(
                "publication no longer accepts pointer uploads".into(),
            ));
        }
        Ok(())
    }

    pub(in crate::service) async fn registry_publication_multipart_context(
        &self,
        auth: Option<&str>,
        upload_id: &str,
    ) -> Result<
        (
            crate::db::RegistryPublicationMultipartUploadRecord,
            crate::db::RegistryPublicationUploadObjectRecord,
            Vec<RegistryPublicationMultipartBackend>,
        ),
        RpcError,
    > {
        let upload = self
            .db
            .registry_publication_multipart_upload(upload_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("publication multipart upload"))?;
        if upload.state == "active" && upload.expires_at <= clock::now_unix_secs() {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload has expired".into(),
            ));
        }
        let (publication, registry, object) = self
            .registry_publication_object_context(
                auth,
                &upload.publication_id,
                upload.surface_object_id,
            )
            .await?;
        self.prepare_registry_publication_object_upload(&publication, &registry, &object)
            .await?;
        if upload.registry_id != registry.id {
            return Err(RpcError::FailedPrecondition(
                "publication multipart registry identity changed".into(),
            ));
        }
        let mut backends = self
            .db
            .registry_publication_multipart_backends(&upload.upload_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(
                |(placement_id, placement_resource_version, backend_upload_id, completion_etag)| {
                    RegistryPublicationMultipartBackend {
                        placement_id,
                        placement_resource_version,
                        backend_upload_id,
                        completion_etag,
                    }
                },
            )
            .collect::<Vec<_>>();
        backends.sort_by_key(|backend| backend.placement_id);
        if backends.is_empty()
            || backends
                .windows(2)
                .any(|pair| pair[0].placement_id == pair[1].placement_id)
        {
            return Err(RpcError::Internal);
        }
        let mut current = self
            .prepare_registry_publication_upload_placements(
                &upload.publication_id,
                &object.object_kind,
            )
            .await?;
        current.sort_by_key(|placement| placement.id);
        if current.len() != backends.len()
            || current.iter().zip(&backends).any(|(placement, backend)| {
                placement.id != backend.placement_id
                    || placement.resource_version != backend.placement_resource_version
            })
        {
            return Err(RpcError::FailedPrecondition(
                "publication placement topology changed during multipart upload".into(),
            ));
        }
        Ok((upload, object, backends))
    }

    pub(in crate::service) async fn abort_registry_publication_multipart_record(
        &self,
        auth: Option<&str>,
        upload: crate::db::RegistryPublicationMultipartUploadRecord,
    ) -> Result<(), RpcError> {
        let (_, registry, object) = self
            .registry_publication_object_context(
                auth,
                &upload.publication_id,
                upload.surface_object_id,
            )
            .await?;
        if upload.registry_id != registry.id {
            return Err(RpcError::FailedPrecondition(
                "publication multipart registry identity changed".into(),
            ));
        }
        if !matches!(upload.state.as_str(), "active" | "completing") {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload is not abortable".into(),
            ));
        }

        let backends = self
            .db
            .registry_publication_multipart_backends(&upload.upload_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(
                |(placement_id, placement_resource_version, backend_upload_id, completion_etag)| {
                    RegistryPublicationMultipartBackend {
                        placement_id,
                        placement_resource_version,
                        backend_upload_id,
                        completion_etag,
                    }
                },
            )
            .collect::<Vec<_>>();
        if backends.is_empty() {
            return Err(RpcError::Internal);
        }
        let required = self
            .prepare_registry_publication_upload_placements(
                &upload.publication_id,
                &object.object_kind,
            )
            .await?;
        if required.len() != backends.len() {
            return Err(RpcError::FailedPrecondition(
                "publication multipart backend creation is unresolved".into(),
            ));
        }
        for backend in backends {
            let placement = self
                .db
                .surface_placement(backend.placement_id)
                .await
                .map_err(RpcError::internal)?
                .filter(|placement| {
                    placement.resource_version == backend.placement_resource_version
                })
                .ok_or_else(|| {
                    RpcError::FailedPrecondition(
                        "publication placement changed before multipart cleanup".into(),
                    )
                })?;
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            match writer
                .abort_multipart(&object.object_key, &backend.backend_upload_id)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
            {
                crate::surface_write::MultipartAbortOutcome::Aborted
                | crate::surface_write::MultipartAbortOutcome::Absent => {}
                crate::surface_write::MultipartAbortOutcome::PossiblyCompleted => {
                    return Err(RpcError::FailedPrecondition(
                        "multipart abort could not exclude a completed object".into(),
                    ));
                }
            }
        }
        self.db
            .finish_registry_publication_multipart_upload(
                &upload.upload_id,
                "aborted",
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)
    }

    /// Mints a ticket-fenced presigned PUT for one cache object.
    pub(in crate::service) async fn mint_presigned_cache_write(
        &self,
        cache: &crate::db::BinaryCache,
        path: &str,
        size: u64,
        now: i64,
    ) -> Result<Option<(String, String)>, RpcError> {
        let placement = self
            .db
            .reconciled_surface_writer(SurfaceTarget::BinaryCache(cache.id))
            .await
            .map_err(RpcError::internal)?;
        let declared_size = i64::try_from(size)
            .map_err(|_| RpcError::invalid("declared upload size is too large"))?;
        let (binding_revision, credential_generation) =
            self.placement_write_snapshot(&placement).await?;
        let inventory = self
            .surface
            .placement_fetcher(&placement)
            .await
            .map_err(RpcError::internal)?;
        if self
            .presign_placement(&placement, path, now, Some(size), None)
            .await
            .map_err(RpcError::internal)?
            .is_none()
        {
            return Ok(None);
        }
        let ticket_id = uuid::Uuid::new_v4().simple().to_string();
        let expires_at = now + i64::from(PRESIGN_EXPIRES_SECS) + PRESIGN_WRITE_FENCE_GRACE_SECS;
        let observing = self
            .db
            .begin_presigned_cache_write_ticket(
                &ticket_id,
                cache.id,
                placement.id,
                placement.resource_version,
                binding_revision,
                credential_generation,
                path,
                declared_size,
                cache.org_id,
                0,
                0,
                expires_at,
                now,
                None,
                None,
            )
            .await
            .map_err(RpcError::internal)?;
        let prior_object = match inventory.inventory_evidence(path).await {
            Ok(evidence) => evidence.map(write_object_identity),
            Err(error) => {
                settle_cache_write_failure(
                    &self.db,
                    &observing.ticket_id,
                    observing.resource_version,
                    false,
                    now,
                )
                .await;
                return Err(RpcError::internal(error));
            }
        };
        let old_size = prior_object.as_ref().map(|identity| identity.size);
        let delta_bytes = declared_size - old_size.unwrap_or(0);
        let delta_objects = i64::from(old_size.is_none());
        let ticket = match self
            .db
            .activate_cache_write_ticket(
                &observing.ticket_id,
                observing.resource_version,
                cache.org_id,
                delta_bytes,
                delta_objects,
                prior_object.as_ref(),
                None,
                now,
            )
            .await
        {
            Ok(ticket) => ticket,
            Err(error) => {
                settle_cache_write_failure(
                    &self.db,
                    &observing.ticket_id,
                    observing.resource_version,
                    false,
                    now,
                )
                .await;
                return Err(RpcError::internal(error));
            }
        };
        match self
            .presign_placement(
                &placement,
                path,
                now,
                Some(size),
                ticket.presign_credential_generation,
            )
            .await
        {
            Ok(Some(url)) => Ok(Some((url, ticket.ticket_id))),
            Ok(None) => {
                self.db
                    .abort_cache_write_ticket(
                        &ticket.ticket_id,
                        ticket.resource_version,
                        "aborted",
                        now,
                    )
                    .await
                    .map_err(RpcError::internal)?;
                Ok(None)
            }
            Err(error) => {
                settle_cache_write_failure(
                    &self.db,
                    &ticket.ticket_id,
                    ticket.resource_version,
                    false,
                    now,
                )
                .await;
                Err(RpcError::internal(error))
            }
        }
    }

    /// The effective per-request upload cap in bytes.
    ///
    /// The instance `max_upload_bytes` setting overrides the built-in
    /// [`MAX_UPLOAD_BYTES`] when an operator has set a positive value; otherwise
    /// the built-in default applies. Read on the write path so a change takes
    /// effect without a restart; a malformed or non-positive stored value falls
    /// back to the default (fail safe).
    pub(in crate::service) async fn effective_max_upload_bytes(&self) -> usize {
        match self.db.instance_config_get("max_upload_bytes").await {
            Ok(Some(v)) => v
                .parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .map_or(MAX_UPLOAD_BYTES, |n| {
                    usize::try_from(n)
                        .unwrap_or(MAX_UPLOAD_BYTES)
                        .min(MAX_UPLOAD_BYTES)
                }),
            _ => MAX_UPLOAD_BYTES,
        }
    }

    /// The effective limit for any complete object upload request.
    ///
    /// Cache and publication object uploads share the static Connect namespace
    /// even though their bodies contain raw bytes. Both runtime shells apply
    /// the unary-request buffer limit before dispatch. Advertise multipart
    /// delivery above the smaller of that transport limit and the configured
    /// object limit so clients never receive a direct URL whose request the
    /// ingress must reject.
    pub(in crate::service) async fn effective_complete_upload_bytes(&self) -> usize {
        complete_upload_bytes(self.effective_max_upload_bytes().await)
    }

    pub(in crate::service) async fn resolve_cache_upload_ticket(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        ticket_id: &str,
        allow_completing: bool,
    ) -> Result<
        Option<(
            crate::db::BinaryCache,
            crate::db::CacheWriteTicketRecord,
            Box<dyn crate::surface_write::SurfaceWrite>,
        )>,
        SurfaceWriteOutcome,
    > {
        let Some(raw) = self
            .db
            .cache_write_ticket(ticket_id)
            .await
            .map_err(internal_write)?
        else {
            if self
                .db
                .binary_cache_by_slug(slug)
                .await
                .map_err(internal_write)?
                .is_some()
                || self
                    .db
                    .binary_cache_by_stable_id(slug)
                    .await
                    .map_err(internal_write)?
                    .is_some()
            {
                return Err(SurfaceWriteOutcome::NotWritable(
                    "cache multipart upload ticket does not exist",
                ));
            }
            return Ok(None);
        };
        let cache = match self.db.binary_cache_by_stable_id(slug).await {
            Ok(Some(cache)) => Some(cache),
            Ok(None) => self
                .db
                .binary_cache_by_slug(slug)
                .await
                .map_err(internal_write)?,
            Err(error) => return Err(internal_write(error)),
        }
        .filter(|cache| cache.id == raw.cache_id && cache.deleted_at.is_none())
        .ok_or(SurfaceWriteOutcome::NotFound)?;
        if let Err(deny) = self.require_cache_admin(auth, &cache).await {
            return Err(auth_denial_to_write_outcome(deny));
        }
        let now = clock::now_unix_secs();
        let ticket = self
            .db
            .validate_cache_write_ticket(ticket_id, cache.id, path, now, allow_completing)
            .await
            .map_err(internal_write)?;
        let placement = self
            .db
            .surface_placement(ticket.placement_id)
            .await
            .map_err(internal_write)?
            .filter(|placement| placement.cache_id == Some(cache.id))
            .ok_or(SurfaceWriteOutcome::NotWritable(
                "cache write placement disappeared",
            ))?;
        let writer = self
            .surface_write
            .placement_writer(&placement)
            .await
            .map_err(|_| SurfaceWriteOutcome::NotWritable("cache surface is not writable"))?;
        Ok(Some((cache, ticket, writer)))
    }

    /// Creates and durably attaches one provider multipart identity.
    ///
    /// A competing retry may attach its provider upload first. In that case
    /// this request aborts only the provider identity it created and returns
    /// the durable winner without disturbing the shared cache-write fence.
    pub(in crate::service) async fn create_and_attach_cache_multipart(
        &self,
        writer: &dyn crate::surface_write::SurfaceWrite,
        path: &str,
        ticket: &crate::db::CacheWriteTicketRecord,
    ) -> Result<String, SurfaceWriteOutcome> {
        if writer.abandoned_multipart_lifetime_secs().is_none() {
            return Err(SurfaceWriteOutcome::NotWritable(
                "cache multipart backend has no bounded abandoned-upload lifecycle",
            ));
        }
        let create_token = uuid::Uuid::new_v4().simple().to_string();
        let claim_now = clock::now_unix_secs();
        let claimed = self
            .db
            .claim_cache_write_backend_creation(
                &ticket.ticket_id,
                ticket.resource_version,
                &create_token,
                claim_now.saturating_add(CACHE_MULTIPART_CREATE_LEASE_SECS),
                claim_now,
            )
            .await
            .map_err(internal_write)?;
        let create = writer.create_multipart(path);
        let timeout = clock::sleep(std::time::Duration::from_secs(
            CACHE_MULTIPART_CREATE_TIMEOUT_SECS,
        ));
        futures_util::pin_mut!(create, timeout);
        let backend_upload_id = match futures_util::future::select(create, timeout).await {
            futures_util::future::Either::Left((Ok(upload_id), _)) => upload_id,
            futures_util::future::Either::Left((Err(error), _)) => {
                let failure_now = clock::now_unix_secs();
                settle_cache_write_failure(
                    &self.db,
                    &ticket.ticket_id,
                    claimed.resource_version,
                    true,
                    failure_now,
                )
                .await;
                return Err(internal_write(error));
            }
            futures_util::future::Either::Right(((), _)) => {
                // Cancellation cannot prove whether the provider accepted the
                // request. Keep the claim until its lease expires so retries
                // cannot create unbounded overlapping provider uploads.
                return Err(SurfaceWriteOutcome::NotWritable(
                    "cache multipart provider creation timed out; retry after the claim lease",
                ));
            }
        };
        let attach_now = clock::now_unix_secs();
        match self
            .db
            .attach_cache_write_backend_upload(
                &ticket.ticket_id,
                claimed.resource_version,
                &create_token,
                &backend_upload_id,
                attach_now,
            )
            .await
        {
            Ok(attached) => return Ok(attached.ticket_id),
            Err(attach_error) => {
                let current = self
                    .db
                    .cache_write_ticket(&ticket.ticket_id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| ticket.clone());
                let abort = writer.abort_multipart(path, &backend_upload_id).await;
                if current.state == "active"
                    && current.expires_at > attach_now
                    && current.backend_upload_id.is_some()
                {
                    if matches!(
                        abort,
                        Ok(crate::surface_write::MultipartAbortOutcome::Aborted)
                            | Ok(crate::surface_write::MultipartAbortOutcome::Absent)
                    ) {
                        return Ok(current.ticket_id);
                    }
                    return Err(SurfaceWriteOutcome::NotWritable(
                        "competing multipart creation could not be cleaned up",
                    ));
                }
                match abort {
                    Ok(
                        crate::surface_write::MultipartAbortOutcome::Aborted
                        | crate::surface_write::MultipartAbortOutcome::Absent,
                    ) => {
                        let _ = self
                            .db
                            .abort_cache_write_ticket(
                                &current.ticket_id,
                                current.resource_version,
                                "failed",
                                attach_now,
                            )
                            .await;
                    }
                    Ok(crate::surface_write::MultipartAbortOutcome::PossiblyCompleted) | Err(_) => {
                        let _ = self
                            .db
                            .mark_cache_write_ticket_uncertain(
                                &current.ticket_id,
                                current.resource_version,
                                attach_now,
                            )
                            .await;
                    }
                }
                Err(internal_write(attach_error))
            }
        }
    }

    pub(in crate::service) async fn cache_multipart_identity(
        &self,
        upload_id: &str,
    ) -> Result<(crate::db::BinaryCache, String), RpcError> {
        let ticket = self
            .db
            .cache_write_ticket(upload_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache multipart upload"))?;
        if ticket.upload_kind != "multipart" {
            return Err(RpcError::invalid("cache upload is not multipart"));
        }
        let cache = self
            .db
            .binary_cache_by_id(ticket.cache_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("cache"))?;
        Ok((cache, ticket.object_key))
    }

    /// Opens mutable watermark advances only for an admitted object upload.
    pub(in crate::service) async fn prepare_registry_publication_upload_placements(
        &self,
        publication_id: &str,
        object_kind: &str,
    ) -> Result<Vec<crate::db::SurfacePlacementRecord>, RpcError> {
        let progress = self
            .db
            .registry_publication_placement_records(publication_id)
            .await
            .map_err(RpcError::internal)?;
        let mut placements = Vec::new();
        for placement_progress in progress {
            if !placement_progress.required {
                continue;
            }
            let mut placement = self
                .db
                .surface_placement(placement_progress.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            if object_kind == "mutable_pointer" && placement_progress.state == "preparing" {
                let watermark_version = placement.watermark_resource_version.ok_or_else(|| {
                    RpcError::FailedPrecondition("placement has no publication watermark".into())
                })?;
                placement = self
                    .db
                    .begin_registry_pointer_advance(
                        publication_id,
                        placement.id,
                        placement.resource_version,
                        watermark_version,
                        clock::now_unix_secs(),
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
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
