//! Inventory mutations in the caches capability.

use super::*;

impl RpcService {
    /// Admits one or a bounded batch of exact cache-object uploads.
    ///
    /// Requires cache-write authority. A presign-capable placement returns a
    /// direct-origin URL; every other placement returns a typed Hub-proxy URL.
    /// Neither case derives a write path from a consumer route.
    ///
    /// # Errors
    ///
    /// Returns not found for an unknown cache, authentication or authorization
    /// errors, invalid argument or resource exhausted for malformed or
    /// oversized batches, failed precondition for conflicting durable state,
    /// and internal error on signing or persistence failure.
    pub async fn create_cache_object_uploads(
        &self,
        auth: Option<&str>,
        req: pb::CreateCacheObjectUploadsRequest,
    ) -> Result<pb::CreateCacheObjectUploadsResponse, RpcError> {
        let cache = match (!req.cache_id.is_empty(), !req.delivery_url.is_empty()) {
            (true, false) => self.binary_cache_or_not_found(&req.cache_id).await?,
            (false, true) => self
                .db
                .binary_cache_by_ready_delivery_url(&req.delivery_url)
                .await
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("cache route"))?,
            _ => {
                return Err(RpcError::invalid(
                    "exactly one of cache_id or delivery_url is required",
                ));
            }
        };
        self.require_cache_admin(auth, &cache).await?;
        let now = clock::now_unix_secs();
        let expires_at = now + i64::from(PRESIGN_EXPIRES_SECS);
        let proxy_limit = self.effective_complete_upload_bytes().await as u64;
        // Batch form: one round-trip mints a URL per path (the single-path
        // `upload_url` is unused). A non-machine path, or an object too large
        // for both the selected direct-origin mode and the typed proxy, yields
        // an empty URL so the client falls back to multipart.
        if !req.paths.is_empty() {
            if req.paths.len() != req.sizes.len() {
                return Err(RpcError::invalid("paths and sizes must have equal length"));
            }
            if req.paths.len() > MAX_CACHE_UPLOAD_ADMISSION_BATCH {
                return Err(RpcError::ResourceExhausted(format!(
                    "at most {MAX_CACHE_UPLOAD_ADMISSION_BATCH} cache uploads may be admitted at once"
                )));
            }
            if req.paths.iter().collect::<BTreeSet<_>>().len() != req.paths.len() {
                return Err(RpcError::invalid("cache upload paths must be unique"));
            }

            // Resolve the physical authority and presign capability once. The
            // bound-R2 Worker path is not presign-configured; it admits every
            // eligible proxy ticket below with one active-slot query and one
            // atomic database batch instead of repeating the topology and
            // ticket workflow for every path.
            let first_machine = req
                .paths
                .iter()
                .zip(&req.sizes)
                .find(|(path, _)| keymap::is_machine_path(path));
            let mut batch_placement = None;
            let presignable = if let Some((path, size)) = first_machine {
                let placement = self
                    .effective_surface_writer(SurfaceTarget::BinaryCache(cache.id))
                    .await?;
                let presignable = self
                    .presign_placement(&placement, path, now, Some(*size), None)
                    .await
                    .map_err(RpcError::internal)?
                    .is_some();
                batch_placement = Some(placement);
                presignable
            } else {
                false
            };
            if !presignable {
                let tickets = match batch_placement.as_ref() {
                    Some(placement) => {
                        self.admit_cache_proxy_writes(
                            &cache,
                            placement,
                            &req.paths,
                            &req.sizes,
                            proxy_limit,
                            now,
                        )
                        .await?
                    }
                    None => vec![None; req.paths.len()],
                };
                let uploads = req
                    .paths
                    .into_iter()
                    .zip(tickets)
                    .map(|(path, ticket)| {
                        let (upload_url, upload_ticket_id) = ticket.map_or_else(
                            || (String::new(), String::new()),
                            |ticket_id| {
                                (
                                    self.cache_proxy_upload_url(&cache, &ticket_id, &path),
                                    ticket_id,
                                )
                            },
                        );
                        pb::CacheObjectUpload {
                            path,
                            upload_url,
                            expires_at: 0,
                            upload_ticket_id,
                        }
                    })
                    .collect();
                return Ok(pb::CreateCacheObjectUploadsResponse {
                    upload_url: String::new(),
                    expires_at,
                    uploads,
                    upload_ticket_id: String::new(),
                });
            }

            let mut uploads = Vec::with_capacity(req.paths.len());
            for (path, size) in req.paths.iter().zip(&req.sizes) {
                let (upload_url, upload_ticket_id) = if keymap::is_machine_path(path) {
                    match self
                        .mint_presigned_cache_write(&cache, path, *size, now)
                        .await?
                    {
                        Some((url, ticket_id)) => (url, ticket_id),
                        None if *size <= proxy_limit => {
                            let ticket_id = self
                                .admit_cache_proxy_write(&cache, path, *size, now)
                                .await?;
                            (
                                self.cache_proxy_upload_url(&cache, &ticket_id, path),
                                ticket_id,
                            )
                        }
                        None => (String::new(), String::new()),
                    }
                } else {
                    (String::new(), String::new())
                };
                let upload_expires_at = if upload_url.is_empty()
                    || upload_url.starts_with(&format!(
                        "{}/aos.hub.v1.BinaryCacheService/UploadObject/",
                        self.external_url.trim_end_matches('/')
                    )) {
                    0
                } else {
                    expires_at
                };
                uploads.push(pb::CacheObjectUpload {
                    path: path.clone(),
                    upload_url,
                    expires_at: upload_expires_at,
                    upload_ticket_id,
                });
            }
            return Ok(pb::CreateCacheObjectUploadsResponse {
                upload_url: String::new(),
                expires_at,
                uploads,
                upload_ticket_id: String::new(),
            });
        }
        // Only canonical machine paths are mintable — a presigned PUT bypasses the
        // typed upload path's narinfo signing, so an arbitrary key would land
        // unvalidated. Mirrors the `write_cache_object` machine-path guard.
        if !keymap::is_machine_path(&req.path) {
            return Err(RpcError::invalid("not a cache machine path"));
        }
        let upload = self
            .mint_presigned_cache_write(&cache, &req.path, req.size, now)
            .await?;
        let (upload_url, upload_ticket_id) = match upload {
            Some((url, ticket_id)) => (url, ticket_id),
            None if req.size <= proxy_limit => {
                let ticket_id = self
                    .admit_cache_proxy_write(&cache, &req.path, req.size, now)
                    .await?;
                (
                    self.cache_proxy_upload_url(&cache, &ticket_id, &req.path),
                    ticket_id,
                )
            }
            None => (String::new(), String::new()),
        };
        Ok(pb::CreateCacheObjectUploadsResponse {
            expires_at: if upload_url.is_empty()
                || upload_url.starts_with(&format!(
                    "{}/aos.hub.v1.BinaryCacheService/UploadObject/",
                    self.external_url.trim_end_matches('/')
                )) {
                0
            } else {
                expires_at
            },
            upload_url,
            uploads: Vec::new(),
            upload_ticket_id,
        })
    }
}
