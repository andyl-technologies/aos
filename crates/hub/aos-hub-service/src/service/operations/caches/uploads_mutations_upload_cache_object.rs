//! Uploads mutations in the caches capability.

use super::*;

impl RpcService {
    /// Stores one cache object through its typed, authenticated Hub proxy URL.
    ///
    /// # Errors
    ///
    /// Returns an authorization, path, quota, placement, or storage error.
    pub async fn upload_cache_object(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        ticket_id: &str,
        encoded_path: &str,
        body: &[u8],
    ) -> Result<(), RpcError> {
        let cache = self.binary_cache_or_not_found(cache_id).await?;
        let ticket = self
            .db
            .cache_write_ticket(ticket_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|ticket| ticket.cache_id == cache.id)
            .ok_or_else(|| RpcError::not_found("cache upload"))?;
        let path = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_path)
            .map_err(|_| RpcError::invalid("cache upload path identity is invalid"))?;
        let path = std::str::from_utf8(&path)
            .map_err(|_| RpcError::invalid("cache upload path is not UTF-8"))?;
        match self
            .write_cache_object(auth, &cache, path, body, Some(ticket))
            .await
        {
            SurfaceWriteOutcome::Created | SurfaceWriteOutcome::Overwritten => Ok(()),
            SurfaceWriteOutcome::BadPath(reason) => Err(RpcError::invalid(reason)),
            SurfaceWriteOutcome::TooLarge => Err(RpcError::ResourceExhausted(
                "cache upload exceeds the configured body limit".into(),
            )),
            SurfaceWriteOutcome::QuotaExceeded => Err(RpcError::ResourceExhausted(
                "organization storage quota exceeded".into(),
            )),
            SurfaceWriteOutcome::NotFound => Err(RpcError::not_found("cache")),
            SurfaceWriteOutcome::Unauthorized(reason) => {
                Err(RpcError::Unauthenticated(reason.into()))
            }
            SurfaceWriteOutcome::Forbidden => Err(RpcError::PermissionDenied(
                "cache write permission required".into(),
            )),
            SurfaceWriteOutcome::NotWritable(reason) => {
                Err(RpcError::FailedPrecondition(reason.into()))
            }
            other => Err(RpcError::internal(anyhow::anyhow!(
                "cache upload failed: {other:?}"
            ))),
        }
    }

    /// Begins a durable multipart upload for one exact cache object.
    ///
    /// # Errors
    ///
    /// Returns an authorization, target, path, placement, quota, or backend
    /// capability error.
    pub async fn begin_cache_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::BeginCacheMultipartUploadRequest,
    ) -> Result<pb::BeginCacheMultipartUploadResponse, RpcError> {
        let cache = self
            .cache_upload_target(&req.cache_id, &req.delivery_url)
            .await?;
        let expected_sha256 = (!req.sha256.is_empty()).then_some(req.sha256.as_str());
        let upload_id = self
            .initiate_upload(
                auth,
                &cache.stable_id,
                &req.path,
                req.byte_size,
                expected_sha256,
            )
            .await
            .map_err(write_outcome_error)?;
        Ok(pb::BeginCacheMultipartUploadResponse {
            part_upload_url: format!(
                "{}/aos.hub.v1.BinaryCacheService/UploadPart/{}",
                self.external_url.trim_end_matches('/'),
                upload_id
            ),
            upload_id,
            part_size: REGISTRY_PUBLICATION_PART_BYTES as u64,
        })
    }

    /// Stores one bounded part of a durable cache multipart upload.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload identity, body-size, or backend error.
    pub async fn upload_cache_multipart_part(
        &self,
        auth: Option<&str>,
        upload_id: &str,
        part_number: u32,
        body: &[u8],
    ) -> Result<pb::CacheMultipartPart, RpcError> {
        let (cache, path) = self.cache_multipart_identity(upload_id).await?;
        let tag = self
            .upload_part(auth, &cache.stable_id, &path, upload_id, part_number, body)
            .await
            .map_err(write_outcome_error)?;
        Ok(pb::CacheMultipartPart {
            part_number: tag.part_number,
            etag: tag.etag,
        })
    }

    /// Completes a durable cache multipart upload after exact part validation.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload identity, part-set, or backend error.
    pub async fn complete_cache_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::CompleteCacheMultipartUploadRequest,
    ) -> Result<pb::CacheMultipartUploadResponse, RpcError> {
        let (cache, path) = self.cache_multipart_identity(&req.upload_id).await?;
        let parts = req
            .parts
            .into_iter()
            .map(|part| PartTag {
                part_number: part.part_number,
                etag: part.etag,
            })
            .collect::<Vec<_>>();
        write_outcome_result(
            self.complete_upload(auth, &cache.stable_id, &path, &req.upload_id, &parts)
                .await,
        )?;
        Ok(pb::CacheMultipartUploadResponse {
            upload_id: req.upload_id,
            state: "completed".into(),
        })
    }

    /// Aborts a durable cache multipart upload and releases staged bytes.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload identity, or backend cleanup error.
    pub async fn abort_cache_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::AbortCacheMultipartUploadRequest,
    ) -> Result<pb::CacheMultipartUploadResponse, RpcError> {
        let (cache, path) = self.cache_multipart_identity(&req.upload_id).await?;
        write_outcome_result(
            self.abort_upload(auth, &cache.stable_id, &path, &req.upload_id)
                .await,
        )?;
        Ok(pb::CacheMultipartUploadResponse {
            upload_id: req.upload_id,
            state: "aborted".into(),
        })
    }

    /// Records a placement observation for a direct cache PUT.
    ///
    /// The ticket deliberately remains active until the presigned URL expires;
    /// acknowledgement cannot revoke a replayable capability.
    ///
    /// # Errors
    ///
    /// Returns authorization, ticket identity, storage observation, or database errors.
    pub async fn report_cache_upload(
        &self,
        auth: Option<&str>,
        req: pb::ReportCacheUploadRequest,
    ) -> Result<pb::CacheUploadObservationResponse, RpcError> {
        self.require_controller_fence(
            auth,
            &req.controller_lease_id,
            req.controller_generation,
            &req.expected_observation_version,
        )?;
        let cache = self.binary_cache_or_not_found(&req.cache_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        self.observe_presigned_cache_upload(&cache, &req.path, &req.upload_ticket_id)
            .await
    }

    /// Begins a durable, bounded multipart upload for one declared object.
    ///
    /// # Errors
    ///
    /// Returns an authorization, publication phase, object-size, placement, or
    /// backend capability error.
    pub async fn begin_registry_publication_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::BeginRegistryPublicationMultipartUploadRequest,
    ) -> Result<pb::BeginRegistryPublicationMultipartUploadResponse, RpcError> {
        let (publication, registry, object) = self
            .registry_publication_object_context(auth, &req.publication_id, req.object_id)
            .await?;
        self.prepare_registry_publication_object_upload(&publication, &registry, &object)
            .await?;
        if keymap::is_loose_git_object_path(&object.object_key)
            || keymap::is_git_pack_index_path(&object.object_key)
            || keymap::is_git_pack_path(&object.object_key)
        {
            return Err(RpcError::FailedPrecondition(
                "Git object metadata and packs must use bounded whole-object upload".into(),
            ));
        }
        let expected_size = u64::try_from(object.expected_size)
            .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
        if expected_size <= self.effective_complete_upload_bytes().await as u64 {
            return Err(RpcError::FailedPrecondition(
                "publication object does not require multipart upload".into(),
            ));
        }
        let part_count = expected_size.div_ceil(REGISTRY_PUBLICATION_PART_BYTES as u64);
        if part_count > MAX_REGISTRY_PUBLICATION_MULTIPART_PARTS {
            return Err(RpcError::ResourceExhausted(
                "publication object exceeds the multipart part-count limit".into(),
            ));
        }
        let now = clock::now_unix_secs();
        if let Some(existing) = self
            .db
            .active_registry_publication_multipart_upload(
                &publication.publication_id,
                object.surface_object_id,
            )
            .await
            .map_err(RpcError::internal)?
        {
            if self
                .db
                .registry_publication_multipart_has_creating_backend(&existing.upload_id)
                .await
                .map_err(RpcError::internal)?
            {
                return Err(RpcError::Unavailable(
                    "publication multipart backend creation is unresolved; retry after provider cleanup"
                        .into(),
                ));
            }
            let claim_expired = match (&existing.pending_token, existing.pending_since) {
                (Some(_), Some(since)) => {
                    since <= now.saturating_sub(REGISTRY_PUBLICATION_PART_CLAIM_SECS)
                }
                (None, None) => false,
                _ => {
                    return Err(RpcError::internal(anyhow::anyhow!(
                        "multipart claim state is incomplete"
                    )));
                }
            };
            if existing.state == "active" && (existing.expires_at <= now || claim_expired) {
                self.abort_registry_publication_multipart_record(auth, existing)
                    .await?;
            } else if existing.state == "active" && existing.pending_token.is_some() {
                return Err(RpcError::Unavailable(
                    "publication multipart part outcome is still unresolved; retry after the claim timeout"
                        .into(),
                ));
            } else {
                let state = existing.state.clone();
                let next_part_number = multipart_next_part(&existing, expected_size)?;
                return Ok(pb::BeginRegistryPublicationMultipartUploadResponse {
                    part_upload_url: format!(
                        "{}/aos.hub.v1.PublishService/UploadPart/{}",
                        self.external_url.trim_end_matches('/'),
                        existing.upload_id
                    ),
                    upload_id: existing.upload_id,
                    part_size: REGISTRY_PUBLICATION_PART_BYTES as u64,
                    state,
                    next_part_number,
                });
            }
        }

        let placements = self
            .prepare_registry_publication_upload_placements(
                &publication.publication_id,
                &object.object_kind,
            )
            .await?;
        for placement in &placements {
            let writer = self
                .surface_write
                .placement_writer(placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            if writer.multipart_protocol_version() != Some(1) {
                return Err(RpcError::FailedPrecondition(
                    "a required publication placement does not support multipart uploads".into(),
                ));
            }
        }
        let upload_id = uuid::Uuid::new_v4().simple().to_string();
        if let Err(error) = self
            .db
            .create_registry_publication_multipart_upload(
                &upload_id,
                &publication.publication_id,
                registry.id,
                object.surface_object_id,
                now.saturating_add(REGISTRY_PUBLICATION_UPLOAD_TTL_SECS),
                now,
                &placements
                    .iter()
                    .map(|placement| (placement.id, placement.resource_version))
                    .collect::<Vec<_>>(),
            )
            .await
        {
            if let Some(existing) = self
                .db
                .active_registry_publication_multipart_upload(
                    &publication.publication_id,
                    object.surface_object_id,
                )
                .await
                .map_err(RpcError::internal)?
                .filter(|existing| existing.expires_at > now && existing.state == "active")
            {
                let next_part_number = multipart_next_part(&existing, expected_size)?;
                return Ok(pb::BeginRegistryPublicationMultipartUploadResponse {
                    part_upload_url: format!(
                        "{}/aos.hub.v1.PublishService/UploadPart/{}",
                        self.external_url.trim_end_matches('/'),
                        existing.upload_id
                    ),
                    upload_id: existing.upload_id,
                    part_size: REGISTRY_PUBLICATION_PART_BYTES as u64,
                    state: "active".into(),
                    next_part_number,
                });
            }
            return Err(RpcError::internal(error));
        }
        let mut started: Vec<(RegistryPublicationMultipartBackend, Box<dyn SurfaceWrite>)> =
            Vec::new();
        for placement in placements {
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let backend_upload_id = match writer.create_multipart(&object.object_key).await {
                Ok(upload_id) => upload_id,
                Err(error) => {
                    for (backend, writer) in &mut started {
                        let _ = writer
                            .abort_multipart(&object.object_key, &backend.backend_upload_id)
                            .await;
                    }
                    let _ = self
                        .db
                        .finish_registry_publication_multipart_upload(
                            &upload_id,
                            "failed",
                            clock::now_unix_secs(),
                        )
                        .await;
                    return Err(RpcError::Unavailable(format!("{error:#}")));
                }
            };
            if let Err(error) = self
                .db
                .attach_registry_publication_multipart_backend(
                    &upload_id,
                    placement.id,
                    &backend_upload_id,
                )
                .await
            {
                let _ = writer
                    .abort_multipart(&object.object_key, &backend_upload_id)
                    .await;
                for (backend, writer) in &mut started {
                    let _ = writer
                        .abort_multipart(&object.object_key, &backend.backend_upload_id)
                        .await;
                }
                let _ = self
                    .db
                    .finish_registry_publication_multipart_upload(
                        &upload_id,
                        "failed",
                        clock::now_unix_secs(),
                    )
                    .await;
                return Err(RpcError::internal(error));
            }
            started.push((
                RegistryPublicationMultipartBackend {
                    placement_id: placement.id,
                    placement_resource_version: placement.resource_version,
                    backend_upload_id,
                    completion_etag: None,
                },
                writer,
            ));
        }
        Ok(pb::BeginRegistryPublicationMultipartUploadResponse {
            part_upload_url: format!(
                "{}/aos.hub.v1.PublishService/UploadPart/{upload_id}",
                self.external_url.trim_end_matches('/')
            ),
            upload_id,
            part_size: REGISTRY_PUBLICATION_PART_BYTES as u64,
            state: "active".into(),
            next_part_number: 1,
        })
    }

    /// Stores one exact bounded part on every frozen publication placement.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload lifecycle, part shape, topology, or
    /// backend error.
    pub async fn upload_registry_publication_multipart_part(
        &self,
        auth: Option<&str>,
        upload_id: &str,
        part_number: u32,
        body: &[u8],
    ) -> Result<pb::RegistryPublicationMultipartPart, RpcError> {
        let (upload, object, backends) = self
            .registry_publication_multipart_context(auth, upload_id)
            .await?;
        if upload.state != "active" {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload no longer accepts parts".into(),
            ));
        }
        let expected_size = u64::try_from(object.expected_size)
            .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
        let part_size = REGISTRY_PUBLICATION_PART_BYTES as u64;
        let offset = u64::from(
            part_number
                .checked_sub(1)
                .ok_or_else(|| RpcError::invalid("multipart part numbers are 1-based"))?,
        )
        .checked_mul(part_size)
        .ok_or_else(|| RpcError::invalid("multipart part offset overflowed"))?;
        if offset >= expected_size {
            return Err(RpcError::invalid("multipart part exceeds the object size"));
        }
        let expected_part_size = (expected_size - offset).min(part_size);
        if body.len() as u64 != expected_part_size {
            return Err(RpcError::invalid(
                "multipart part does not have its exact expected size",
            ));
        }
        let prior_hashed_size = u64::try_from(upload.hashed_size).map_err(|_| {
            RpcError::internal(anyhow::anyhow!("multipart hash progress is negative"))
        })?;
        if offset != prior_hashed_size {
            return Err(RpcError::FailedPrecondition(
                "multipart parts must be uploaded contiguously".into(),
            ));
        }
        let body_hash = hex::encode(Sha256::digest(body));
        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        let claimed_at = clock::now_unix_secs();
        self.db
            .claim_registry_publication_multipart_part(
                &upload.upload_id,
                part_number,
                &body_hash,
                upload.hashed_size,
                &claim_token,
                claimed_at,
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        let hashed_size = prior_hashed_size
            .checked_add(body.len() as u64)
            .ok_or_else(|| RpcError::invalid("multipart hash progress overflowed"))?;
        let sha256_state = advance_multipart_sha256(
            &upload.sha256_state,
            body,
            hashed_size,
            hashed_size == expected_size,
        )
        .map_err(RpcError::internal)?;
        if hashed_size == expected_size && sha256_state != object.expected_hash {
            return Err(RpcError::invalid(
                "multipart bytes do not match the declared SHA-256",
            ));
        }

        let mut placements = Vec::with_capacity(backends.len());
        for backend in backends {
            let placement = self
                .db
                .surface_placement(backend.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let tag = writer
                .upload_part(
                    &object.object_key,
                    &backend.backend_upload_id,
                    part_number,
                    body,
                )
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            if tag.part_number != part_number {
                return Err(RpcError::Unavailable(
                    "publication backend returned a mismatched part number".into(),
                ));
            }
            placements.push(pb::RegistryPublicationPlacementPart {
                placement_id: backend.placement_id,
                etag: tag.etag,
            });
        }
        self.db
            .record_registry_publication_multipart_part(
                &upload.upload_id,
                part_number,
                &placements
                    .iter()
                    .map(|placement| (placement.placement_id, placement.etag.clone()))
                    .collect::<Vec<_>>(),
                i64::try_from(prior_hashed_size).map_err(RpcError::internal)?,
                i64::try_from(hashed_size).map_err(RpcError::internal)?,
                &sha256_state,
                &body_hash,
                &claim_token,
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RegistryPublicationMultipartPart {
            part_number,
            placements,
        })
    }

    /// Completes and verifies a durable multipart publication object.
    ///
    /// # Errors
    ///
    /// Returns an authorization, part-manifest, topology, backend completion,
    /// or exact read-after-write verification error.
    pub async fn complete_registry_publication_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::CompleteRegistryPublicationMultipartUploadRequest,
    ) -> Result<pb::RegistryPublicationMultipartUploadResponse, RpcError> {
        let (upload, object, backends) = self
            .registry_publication_multipart_context(auth, &req.upload_id)
            .await?;
        if !matches!(upload.state.as_str(), "active" | "completing") {
            return Err(RpcError::FailedPrecondition(
                "publication multipart upload is not completable".into(),
            ));
        }
        let expected_size = u64::try_from(object.expected_size)
            .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
        let part_count = expected_size.div_ceil(REGISTRY_PUBLICATION_PART_BYTES as u64);
        if u64::try_from(upload.hashed_size).ok() != Some(expected_size)
            || upload.sha256_state != object.expected_hash
        {
            return Err(RpcError::invalid(
                "multipart upload has not verified the complete declared object",
            ));
        }
        let durable_parts = self
            .db
            .registry_publication_multipart_parts(&req.upload_id)
            .await
            .map_err(RpcError::internal)?;
        let mut parts =
            std::collections::BTreeMap::<u32, Vec<pb::RegistryPublicationPlacementPart>>::new();
        for part in durable_parts {
            parts
                .entry(part.part_number)
                .or_default()
                .push(pb::RegistryPublicationPlacementPart {
                    placement_id: part.placement_id,
                    etag: part.etag,
                });
        }
        let parts = parts
            .into_iter()
            .map(
                |(part_number, placements)| pb::RegistryPublicationMultipartPart {
                    part_number,
                    placements,
                },
            )
            .collect::<Vec<_>>();
        if parts.len() as u64 != part_count {
            return Err(RpcError::invalid(
                "multipart completion does not have every durable object part",
            ));
        }
        if !req.parts.is_empty() && req.parts != parts {
            return Err(RpcError::invalid(
                "multipart completion differs from the durable part manifest",
            ));
        }
        let backend_ids = backends
            .iter()
            .map(|backend| backend.placement_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut per_placement = std::collections::BTreeMap::<i64, Vec<PartTag>>::new();
        for (index, part) in parts.iter().enumerate() {
            if part.part_number != u32::try_from(index + 1).map_err(RpcError::internal)? {
                return Err(RpcError::invalid(
                    "multipart completion parts must be contiguous and ordered",
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for placement in &part.placements {
                if !backend_ids.contains(&placement.placement_id)
                    || !seen.insert(placement.placement_id)
                    || placement.etag.is_empty()
                {
                    return Err(RpcError::invalid(
                        "multipart completion placement tags are invalid",
                    ));
                }
                per_placement
                    .entry(placement.placement_id)
                    .or_default()
                    .push(PartTag {
                        part_number: part.part_number,
                        etag: placement.etag.clone(),
                    });
            }
            if seen != backend_ids {
                return Err(RpcError::invalid(
                    "multipart completion omits a required placement tag",
                ));
            }
        }
        // The token identifies the durable logical completion, not one HTTP
        // request. Reuse it after cancellation so a client retry can reconcile
        // an object that may already have landed at the provider.
        let completion_token = match upload.state.as_str() {
            "active" => uuid::Uuid::new_v4().simple().to_string(),
            "completing" => upload.completion_token.clone().ok_or_else(|| {
                RpcError::FailedPrecondition(
                    "multipart completion has no durable ownership token".into(),
                )
            })?,
            _ => {
                return Err(RpcError::FailedPrecondition(
                    "publication multipart upload is not completable".into(),
                ));
            }
        };
        let completion_claimed_at = clock::now_unix_secs();
        self.db
            .begin_registry_publication_multipart_completion(
                &req.upload_id,
                &completion_token,
                completion_claimed_at,
                completion_claimed_at.saturating_sub(REGISTRY_PUBLICATION_PART_CLAIM_SECS),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;

        for backend in &backends {
            let placement = self
                .db
                .surface_placement(backend.placement_id)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::FailedPrecondition("placement disappeared".into()))?;
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let fetch = self
                .surface
                .placement_fetcher(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let placement_parts = per_placement
                .get(&backend.placement_id)
                .ok_or(RpcError::Internal)?;
            let mut completion_etag = backend.completion_etag.clone();
            if completion_etag.is_none() {
                completion_etag = writer
                    .expected_multipart_etag(placement_parts)
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                if let Some(etag) = &completion_etag {
                    self.db
                        .record_registry_publication_multipart_completion_etag(
                            &upload.upload_id,
                            backend.placement_id,
                            etag,
                        )
                        .await
                        .map_err(RpcError::internal)?;
                }
            }
            let already_landed = if let Some(expected_etag) = &completion_etag {
                let observed_size = fetch
                    .inventory_size(&object.object_key)
                    .await
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                let observed_etag = fetch
                    .inventory_strong_etag(&object.object_key)
                    .await
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                    .map(|etag| crate::surface_write::strong_if_match_etag(&etag))
                    .transpose()
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                observed_size == Some(object.expected_size)
                    && observed_etag.as_ref() == Some(expected_etag)
            } else {
                // Native filesystems cannot predict their metadata-derived
                // strong tag before rename. On a retry, hash the landed bytes
                // against the frozen manifest before adopting that backend tag.
                let evidence = fetch
                    .inventory_evidence(&object.object_key)
                    .await
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                let expected_hash =
                    hex::decode(&object.expected_hash).map_err(RpcError::internal)?;
                let exact = evidence.as_ref().is_some_and(|evidence| {
                    evidence.size == object.expected_size
                        && evidence.sha256.as_slice() == expected_hash.as_slice()
                });
                if exact {
                    completion_etag = evidence
                        .and_then(|evidence| evidence.strong_etag)
                        .map(|etag| crate::surface_write::strong_if_match_etag(&etag))
                        .transpose()
                        .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                    if let Some(etag) = &completion_etag {
                        self.db
                            .record_registry_publication_multipart_completion_etag(
                                &upload.upload_id,
                                backend.placement_id,
                                etag,
                            )
                            .await
                            .map_err(RpcError::internal)?;
                    }
                }
                exact && completion_etag.is_some()
            };
            if !already_landed {
                let returned_etag = match writer
                    .complete_multipart(
                        &object.object_key,
                        &backend.backend_upload_id,
                        placement_parts,
                    )
                    .await
                {
                    Ok(etag) => crate::surface_write::strong_if_match_etag(&etag)
                        .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?,
                    Err(error) => {
                        let recovered = fetch
                            .inventory_evidence(&object.object_key)
                            .await
                            .map_err(|observe_error| {
                                RpcError::Unavailable(format!(
                                    "multipart completion failed: {error:#}; recovery observation failed: {observe_error:#}"
                                ))
                            })?;
                        let expected_hash =
                            hex::decode(&object.expected_hash).map_err(RpcError::internal)?;
                        let Some(evidence) = recovered.filter(|evidence| {
                            evidence.size == object.expected_size
                                && evidence.sha256.as_slice() == expected_hash.as_slice()
                        }) else {
                            return Err(RpcError::Unavailable(format!("{error:#}")));
                        };
                        let etag = evidence.strong_etag.ok_or_else(|| {
                            RpcError::Unavailable(format!(
                                "multipart completion failed without recoverable strong identity: {error:#}"
                            ))
                        })?;
                        crate::surface_write::strong_if_match_etag(&etag).map_err(|etag_error| {
                            RpcError::Unavailable(format!("{etag_error:#}"))
                        })?
                    }
                };
                if completion_etag
                    .as_ref()
                    .is_some_and(|etag| etag != &returned_etag)
                {
                    return Err(RpcError::Unavailable(
                        "provider returned an unexpected multipart object identity".into(),
                    ));
                }
                if completion_etag.is_none() {
                    self.db
                        .record_registry_publication_multipart_completion_etag(
                            &upload.upload_id,
                            backend.placement_id,
                            &returned_etag,
                        )
                        .await
                        .map_err(RpcError::internal)?;
                    completion_etag = Some(returned_etag);
                }
            }
            let completion_etag = completion_etag.ok_or_else(|| {
                RpcError::Unavailable("provider returned no durable completion identity".into())
            })?;
            let observed_size = fetch
                .inventory_size(&object.object_key)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                .ok_or_else(|| RpcError::Unavailable("completed object is absent".into()))?;
            if observed_size != object.expected_size {
                return Err(RpcError::Unavailable(
                    "completed object failed exact read-after-write verification".into(),
                ));
            }
            let observed_etag = fetch
                .inventory_strong_etag(&object.object_key)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                .map(|etag| crate::surface_write::strong_if_match_etag(&etag))
                .transpose()
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            if observed_etag.as_deref() != Some(completion_etag.as_str()) {
                return Err(RpcError::Unavailable(
                    "completed object identity changed before verification".into(),
                ));
            }
            self.db
                .record_registry_publication_object_presence(
                    &upload.publication_id,
                    object.surface_object_id,
                    placement.id,
                    &object.expected_hash,
                    observed_size,
                    observed_etag.as_deref(),
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            writer
                .settle_multipart(&object.object_key, &backend.backend_upload_id)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
        }
        self.db
            .finish_owned_registry_publication_multipart_completion(
                &req.upload_id,
                &completion_token,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?;
        Ok(pb::RegistryPublicationMultipartUploadResponse {
            upload_id: req.upload_id,
            state: "completed".into(),
        })
    }

    /// Aborts every backend transaction for one incomplete multipart object.
    ///
    /// # Errors
    ///
    /// Returns an authorization, upload lifecycle, topology, or backend cleanup error.
    pub async fn abort_registry_publication_multipart_upload(
        &self,
        auth: Option<&str>,
        req: pb::AbortRegistryPublicationMultipartUploadRequest,
    ) -> Result<pb::RegistryPublicationMultipartUploadResponse, RpcError> {
        let upload = self
            .db
            .registry_publication_multipart_upload(&req.upload_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("publication multipart upload"))?;
        self.abort_registry_publication_multipart_record(auth, upload)
            .await?;
        Ok(pb::RegistryPublicationMultipartUploadResponse {
            upload_id: req.upload_id,
            state: "aborted".into(),
        })
    }

    /// Stores one declared publication object on every required placement.
    ///
    /// The URL carries only the publication and object ids; the path, digest,
    /// size, placement set, and mutability class all come from the frozen
    /// manifest. Mutable uploads cannot begin until every immutable byte is
    /// verified everywhere.
    ///
    /// # Errors
    ///
    /// Returns an authorization error, a manifest/body mismatch, a publication
    /// ordering failure, or an unavailable error when a placement write or
    /// exact read-after-write verification fails.
    pub async fn upload_registry_publication_object(
        &self,
        auth: Option<&str>,
        publication_id: &str,
        surface_object_id: i64,
        body: axum::body::Body,
    ) -> Result<(), RpcError> {
        let (publication, registry, object) = self
            .registry_publication_object_context(auth, publication_id, surface_object_id)
            .await?;
        self.prepare_registry_publication_object_upload(&publication, &registry, &object)
            .await?;

        let mut uploads = Vec::new();
        for placement in self
            .prepare_registry_publication_upload_placements(publication_id, &object.object_kind)
            .await?
        {
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            uploads.push(RegistryPublicationUploadPlacement { placement, writer });
        }

        let expected_size = usize::try_from(object.expected_size)
            .map_err(|_| RpcError::invalid("publication object size is out of range"))?;
        if expected_size > self.effective_complete_upload_bytes().await {
            return Err(RpcError::FailedPrecondition(
                "publication object requires bounded multipart upload".into(),
            ));
        }
        let pack_validation = Arc::clone(&self.pack_validation);
        let validates_git_pack = keymap::is_git_pack_path(&object.object_key)
            || keymap::is_git_pack_index_path(&object.object_key);
        let _pack_validation_guard = if validates_git_pack {
            Some(pack_validation.lock().await)
        } else {
            None
        };
        let bytes = if validates_git_pack {
            let collect = collect_exact_publication_body(body, expected_size);
            let timeout = clock::sleep(std::time::Duration::from_secs(
                REGISTRY_PUBLICATION_GIT_PACK_OPERATION_TIMEOUT_SECS,
            ));
            futures_util::pin_mut!(collect, timeout);
            match futures_util::future::select(collect, timeout).await {
                futures_util::future::Either::Left((result, _)) => result?,
                futures_util::future::Either::Right(((), _)) => {
                    return Err(RpcError::Unavailable(
                        "Git pack upload body timed out".into(),
                    ));
                }
            }
        } else {
            collect_exact_publication_body(body, expected_size).await?
        };
        verify_publication_bytes(&object, &bytes)?;
        if keymap::is_git_pack_index_path(&object.object_key) {
            let companion =
                aos_registry_format::pack_index::companion_pack_path(&object.object_key)
                    .ok_or_else(|| RpcError::invalid("Git pack index path is invalid"))?;
            for upload in &mut uploads {
                let fetch = self
                    .surface
                    .placement_fetcher(&upload.placement)
                    .await
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                let read = fetch.fetch_bounded(
                    &companion,
                    aos_registry_format::pack_index::MAX_PUBLISHED_PACK_BYTES as usize,
                );
                let timeout = clock::sleep(std::time::Duration::from_secs(
                    REGISTRY_PUBLICATION_GIT_PACK_OPERATION_TIMEOUT_SECS,
                ));
                futures_util::pin_mut!(read, timeout);
                let pack = match futures_util::future::select(read, timeout).await {
                    futures_util::future::Either::Left((result, _)) => result
                        .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                        .ok_or_else(|| {
                            RpcError::FailedPrecondition(
                                "pack index companion is absent from a required placement".into(),
                            )
                        })?,
                    futures_util::future::Either::Right(((), _)) => {
                        return Err(RpcError::Unavailable(
                            "Git pack companion read timed out".into(),
                        ));
                    }
                };
                aos_registry_format::pack_index::validate_against_pack(
                    &object.object_key,
                    &bytes,
                    &pack,
                )
                .map_err(|_| {
                    RpcError::invalid("pack index does not describe its companion pack")
                })?;
            }
        }
        for upload in &mut uploads {
            if validates_git_pack {
                let write = upload.writer.write(&object.object_key, &bytes);
                let timeout = clock::sleep(std::time::Duration::from_secs(
                    REGISTRY_PUBLICATION_GIT_PACK_OPERATION_TIMEOUT_SECS,
                ));
                futures_util::pin_mut!(write, timeout);
                match futures_util::future::select(write, timeout).await {
                    futures_util::future::Either::Left((result, _)) => {
                        result.map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
                    }
                    futures_util::future::Either::Right(((), _)) => {
                        return Err(RpcError::Unavailable(
                            "Git pack publication write timed out".into(),
                        ));
                    }
                }
            } else {
                upload
                    .writer
                    .write(&object.object_key, &bytes)
                    .await
                    .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            }
        }
        drop(_pack_validation_guard);
        drop(bytes);

        for upload in &mut uploads {
            let fetch = self
                .surface
                .placement_fetcher(&upload.placement)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?;
            let evidence = fetch
                .inventory_evidence(&object.object_key)
                .await
                .map_err(|error| RpcError::Unavailable(format!("{error:#}")))?
                .ok_or_else(|| {
                    RpcError::Unavailable("uploaded object is absent after write".into())
                })?;
            let observed_hash = hex::encode(evidence.sha256);
            if evidence.size != object.expected_size || observed_hash != object.expected_hash {
                return Err(RpcError::Unavailable(
                    "uploaded object failed exact read-after-write verification".into(),
                ));
            }
            self.db
                .record_registry_publication_object_presence(
                    publication_id,
                    object.surface_object_id,
                    upload.placement.id,
                    &observed_hash,
                    evidence.size,
                    evidence.strong_etag.as_deref(),
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
        }
        Ok(())
    }

    /// Begin a multipart upload of `path` under `slug`, returning the backend's
    /// opaque `upload_id`.
    ///
    /// Authorizes exactly as the single-`PUT` path; the client then
    /// streams parts via [`upload_part`](Self::upload_part) and finalizes with
    /// [`complete_upload`](Self::complete_upload), each echoing this `upload_id`.
    ///
    /// # Errors
    ///
    /// Returns a [`SurfaceWriteOutcome`] denial or an internal
    /// error when the backend cannot begin a multipart upload.
    pub async fn initiate_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        declared_size: u64,
        expected_sha256: Option<&str>,
    ) -> Result<String, SurfaceWriteOutcome> {
        if !keymap::is_machine_path(path)
            || crate::url_guard::validate_http_surface_path(path).is_err()
        {
            return Err(SurfaceWriteOutcome::BadPath("unsafe or non-machine path"));
        }
        if let Some(path_sha256) = keymap::image_object_sha256(path) {
            if expected_sha256 != Some(path_sha256) {
                return Err(SurfaceWriteOutcome::BadPath(
                    "immutable image multipart upload requires its path-bound SHA-256",
                ));
            }
        }
        if expected_sha256.is_some_and(|sha256| {
            sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(SurfaceWriteOutcome::BadPath("invalid multipart SHA-256"));
        }
        if let Some(cache) = match self.db.binary_cache_by_stable_id(slug).await {
            Ok(Some(cache)) => Some(cache),
            Ok(None) => self
                .db
                .binary_cache_by_slug(slug)
                .await
                .map_err(internal_write)?,
            Err(error) => return Err(internal_write(error)),
        } {
            if cache.deleted_at.is_some() {
                return Err(SurfaceWriteOutcome::NotFound);
            }
            if let Err(deny) = self.require_cache_admin(auth, &cache).await {
                return Err(auth_denial_to_write_outcome(deny));
            }
            if path.ends_with(".narinfo") {
                return Err(SurfaceWriteOutcome::BadPath(
                    "narinfo uploads require an atomic single PUT",
                ));
            }
            let placement = self
                .effective_surface_writer(SurfaceTarget::BinaryCache(cache.id))
                .await
                .map_err(|_| SurfaceWriteOutcome::NotWritable("cache has no write placement"))?;
            let (binding_revision, credential_generation) = self
                .placement_write_snapshot(&placement)
                .await
                .map_err(|error| internal_write(anyhow::anyhow!(error.message().to_string())))?;
            let writer = self
                .surface_write
                .placement_writer(&placement)
                .await
                .map_err(|_| SurfaceWriteOutcome::NotWritable("cache surface is not writable"))?;
            if writer.multipart_protocol_version() != Some(1) {
                return Err(SurfaceWriteOutcome::NotWritable(
                    "cache write placement does not support multipart uploads",
                ));
            }
            let inventory = self
                .surface
                .placement_fetcher(&placement)
                .await
                .map_err(internal_write)?;
            let declared_size =
                i64::try_from(declared_size).map_err(|_| SurfaceWriteOutcome::TooLarge)?;
            let now = clock::now_unix_secs();

            // A transport-limit reduction can leave an observing single-PUT
            // admission that ingress can no longer deliver. Multipart is the
            // authoritative recovery path for this size. Terminalize only the
            // exact pre-mutation ticket under the current topology; a racing
            // activation advances its version and makes this CAS a no-op.
            if declared_size > self.effective_complete_upload_bytes().await as i64 {
                if let Some(single) = self
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
                    .map_err(internal_write)?
                {
                    settle_cache_write_failure(
                        &self.db,
                        &single.ticket_id,
                        single.resource_version,
                        false,
                        now,
                    )
                    .await;
                }
            }

            for state in ["completing", "active"] {
                if let Some(ticket) = self
                    .db
                    .reusable_cache_write_ticket(
                        cache.id,
                        path,
                        declared_size,
                        "multipart",
                        state,
                        expected_sha256,
                        placement.id,
                        placement.resource_version,
                        binding_revision,
                        credential_generation,
                        now,
                    )
                    .await
                    .map_err(internal_write)?
                {
                    if state == "completing" || ticket.backend_upload_id.is_some() {
                        return Ok(ticket.ticket_id);
                    }
                    // An active ticket without a provider id was interrupted
                    // around provider creation. Continue below and attach a
                    // fresh resumable upload; an untracked provider attempt is
                    // never allowed to block this object's durable slot.
                    return self
                        .create_and_attach_cache_multipart(writer.as_ref(), path, &ticket)
                        .await;
                }
            }

            let observing = if let Some(ticket) = self
                .db
                .reusable_cache_write_ticket(
                    cache.id,
                    path,
                    declared_size,
                    "multipart",
                    "observing",
                    None,
                    placement.id,
                    placement.resource_version,
                    binding_revision,
                    credential_generation,
                    now,
                )
                .await
                .map_err(internal_write)?
            {
                ticket
            } else {
                let ticket_id = uuid::Uuid::new_v4().simple().to_string();
                match self
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
                        "multipart",
                        cache.org_id,
                        0,
                        0,
                        now.saturating_add(86_400),
                        now,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(ticket) => ticket,
                    Err(error) => {
                        let winner = self
                            .db
                            .reusable_cache_write_ticket(
                                cache.id,
                                path,
                                declared_size,
                                "multipart",
                                "observing",
                                None,
                                placement.id,
                                placement.resource_version,
                                binding_revision,
                                credential_generation,
                                now,
                            )
                            .await
                            .map_err(internal_write)?;
                        match winner {
                            Some(ticket) => ticket,
                            None => return Err(internal_write(error)),
                        }
                    }
                }
            };
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
                    return Err(internal_write(error));
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
                    expected_sha256,
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
                    return Err(internal_write(error));
                }
            };
            return self
                .create_and_attach_cache_multipart(writer.as_ref(), path, &ticket)
                .await;
        }
        Err(SurfaceWriteOutcome::NotFound)
    }

    /// Upload one part (`part_number`, 1-based) of the in-progress multipart
    /// upload `upload_id` for `(slug, path)`, returning its
    /// [`PartTag`](crate::surface_write::PartTag).
    ///
    /// Re-authorizes the caller and rebuilds the backend writer, then streams
    /// the single sub-cap part straight to the backend — peak memory is one part.
    ///
    /// # Errors
    ///
    /// Returns a [`SurfaceWriteOutcome`] denial or an internal error when the part
    /// cannot be uploaded.
    pub async fn upload_part(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
        part_number: u32,
        body: &[u8],
    ) -> Result<crate::surface_write::PartTag, SurfaceWriteOutcome> {
        if body.len() > self.effective_max_upload_bytes().await {
            return Err(SurfaceWriteOutcome::TooLarge);
        }
        if let Some((_cache, ticket, writer)) = self
            .resolve_cache_upload_ticket(auth, slug, path, upload_id, true)
            .await?
        {
            let backend_upload_id =
                ticket
                    .backend_upload_id
                    .as_deref()
                    .ok_or(SurfaceWriteOutcome::NotWritable(
                        "multipart ticket is not initialized",
                    ))?;
            let part_size = i64::try_from(body.len()).map_err(|_| SurfaceWriteOutcome::TooLarge)?;
            let body_digest = hex::encode(Sha256::digest(body));
            if ticket.state == "completing" {
                let durable = self
                    .db
                    .cache_write_ticket_part(&ticket.ticket_id, part_number)
                    .await
                    .map_err(internal_write)?
                    .ok_or(SurfaceWriteOutcome::NotWritable(
                        "multipart completion is missing a durable part",
                    ))?;
                if durable.state != "confirmed"
                    || durable.admitted_size != part_size
                    || durable.body_digest != body_digest
                {
                    return Err(SurfaceWriteOutcome::NotWritable(
                        "multipart completion part does not match the retry body",
                    ));
                }
                let etag = durable.etag.filter(|etag| !etag.is_empty()).ok_or(
                    SurfaceWriteOutcome::NotWritable(
                        "multipart completion part has no durable provider identity",
                    ),
                )?;
                return Ok(crate::surface_write::PartTag { part_number, etag });
            }
            let admitted = self
                .db
                .admit_cache_write_part(
                    &ticket.ticket_id,
                    ticket.resource_version,
                    part_number,
                    part_size,
                    &body_digest,
                )
                .await
                .map_err(internal_write)?;
            let durable_part = self
                .db
                .cache_write_ticket_part(&ticket.ticket_id, part_number)
                .await
                .map_err(internal_write)?
                .ok_or_else(|| {
                    internal_write(anyhow::anyhow!("admitted cache part disappeared"))
                })?;
            if durable_part.state == "confirmed" {
                return Ok(crate::surface_write::PartTag {
                    part_number,
                    etag: durable_part.etag.unwrap_or_default(),
                });
            }
            return match writer
                .upload_part(path, backend_upload_id, part_number, body)
                .await
            {
                Ok(tag) => {
                    self.db
                        .confirm_cache_write_part(
                            &ticket.ticket_id,
                            admitted.resource_version,
                            part_number,
                            &tag.etag,
                        )
                        .await
                        .map_err(internal_write)?;
                    Ok(tag)
                }
                Err(error) => {
                    let _ = self
                        .db
                        .mark_cache_write_part_ambiguous(
                            &ticket.ticket_id,
                            admitted.resource_version,
                            part_number,
                        )
                        .await;
                    Err(internal_write(error))
                }
            };
        }
        Err(SurfaceWriteOutcome::NotFound)
    }
}
