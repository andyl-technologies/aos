//! Durable cache upload admission and completion for the hybrid Worker.
//!
//! The Worker owns client bytes and the R2 PUT. Native owns authentication,
//! signature checks, quota reservations, placement authority, and final SQL
//! state. Both phases use the existing cache write ticket so ambiguous writes
//! remain fenced for expiry recovery.

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::hybrid_ingress::{
    HybridCacheUploadAdmission, HybridCacheUploadAdmissionRequest,
    HybridCacheUploadCompletionRequest, HybridCacheUploadPreflight,
};
use crate::keymap;

use super::{clock, settle_cache_write_failure, write_object_identity, RpcError, RpcService};

impl RpcService {
    /// Checks cache write authority and the exact ticket before Worker reads bytes.
    ///
    /// # Errors
    ///
    /// Returns an authorization, ticket, expiry, topology, or size error.
    pub async fn preflight_hybrid_cache_upload(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        ticket_id: &str,
        encoded_path: &str,
    ) -> Result<HybridCacheUploadPreflight, RpcError> {
        let (cache, path) = self
            .hybrid_cache_upload_identity(auth, cache_id, encoded_path)
            .await?;
        let ticket = self
            .db
            .cache_write_ticket(ticket_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|ticket| ticket.cache_id == cache.id)
            .ok_or_else(|| RpcError::not_found("cache upload"))?;
        if ticket.object_key != path || ticket.upload_kind != "single" {
            return Err(RpcError::invalid("cache upload does not match its ticket"));
        }
        let expected_size = u64::try_from(ticket.declared_size)
            .map_err(|_| RpcError::invalid("cache ticket size is invalid"))?;
        if expected_size > self.effective_complete_upload_bytes().await as u64 {
            return Err(RpcError::ResourceExhausted(
                "cache upload exceeds the configured body limit".into(),
            ));
        }
        if path.ends_with(".narinfo")
            && expected_size > crate::fetch::MAX_CACHE_NARINFO_BYTES as u64
        {
            return Err(RpcError::ResourceExhausted(
                "narinfo upload exceeds its metadata limit".into(),
            ));
        }
        if ticket.state != "completed" {
            if !matches!(ticket.state.as_str(), "observing" | "active")
                || ticket.expires_at <= clock::now_unix_secs()
            {
                return Err(RpcError::FailedPrecondition(
                    "cache upload ticket is not writable".into(),
                ));
            }
            self.hybrid_cache_upload_placement(&cache, &ticket).await?;
        }
        Ok(HybridCacheUploadPreflight { expected_size })
    }

    /// Authorizes and reserves one exact cache object before an edge R2 PUT.
    ///
    /// # Errors
    ///
    /// Returns an auth, ticket, signature, quota, topology, or storage error.
    pub async fn admit_hybrid_cache_upload(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        ticket_id: &str,
        encoded_path: &str,
        request: HybridCacheUploadAdmissionRequest,
    ) -> Result<HybridCacheUploadAdmission, RpcError> {
        let (cache, path) = self
            .hybrid_cache_upload_identity(auth, cache_id, encoded_path)
            .await?;
        validate_upload_digest(&request.sha256)?;
        if request.size > self.effective_complete_upload_bytes().await as u64 {
            return Err(RpcError::ResourceExhausted(
                "cache upload exceeds the configured body limit".into(),
            ));
        }
        let declared_size = i64::try_from(request.size)
            .map_err(|_| RpcError::invalid("cache upload size exceeds i64"))?;
        let ticket = self
            .db
            .cache_write_ticket(ticket_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|ticket| ticket.cache_id == cache.id)
            .ok_or_else(|| RpcError::not_found("cache upload"))?;
        if ticket.object_key != path
            || ticket.upload_kind != "single"
            || ticket.declared_size != declared_size
        {
            return Err(RpcError::invalid("cache upload does not match its ticket"));
        }
        if ticket.state == "completed" {
            if ticket.intended_object_hash.as_deref() == Some(request.sha256.as_str())
                && ticket.observed_final_size == Some(declared_size)
            {
                return Ok(HybridCacheUploadAdmission {
                    object_key: None,
                    completed: true,
                });
            }
            return Err(RpcError::invalid(
                "completed cache upload retry has different bytes",
            ));
        }

        validate_narinfo(&self.db, &cache.stable_id, &path, &request).await?;
        let now = clock::now_unix_secs();
        let ticket = match ticket.state.as_str() {
            "active" if ticket.intended_object_hash.as_deref() == Some(request.sha256.as_str()) => {
                self.db
                    .validate_cache_write_ticket(ticket_id, cache.id, &path, now, false)
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?
            }
            "observing" if ticket.expires_at > now => {
                let prior = self.hybrid_cache_upload_prior(&cache, &ticket, &path).await;
                let prior = match prior {
                    Ok(prior) => prior,
                    Err(error) => {
                        settle_cache_write_failure(
                            &self.db,
                            ticket_id,
                            ticket.resource_version,
                            false,
                            now,
                        )
                        .await;
                        return Err(error);
                    }
                };
                let old_size = prior.as_ref().map_or(0, |identity| identity.size);
                let delta_bytes = declared_size - old_size;
                let delta_objects = i64::from(prior.is_none());
                match self
                    .db
                    .activate_cache_write_ticket(
                        ticket_id,
                        ticket.resource_version,
                        cache.org_id,
                        delta_bytes,
                        delta_objects,
                        prior.as_ref(),
                        Some(&request.sha256),
                        now,
                    )
                    .await
                {
                    Ok(active) => active,
                    Err(error) => {
                        if let Ok(Some(current)) = self.db.cache_write_ticket(ticket_id).await {
                            if current.state == "completed"
                                && current.intended_object_hash.as_deref()
                                    == Some(request.sha256.as_str())
                                && current.observed_final_size == Some(declared_size)
                            {
                                return Ok(HybridCacheUploadAdmission {
                                    object_key: None,
                                    completed: true,
                                });
                            }
                            if current.state == "active"
                                && current.intended_object_hash.as_deref()
                                    == Some(request.sha256.as_str())
                                && self
                                    .db
                                    .validate_cache_write_ticket(
                                        ticket_id, cache.id, &path, now, false,
                                    )
                                    .await
                                    .is_ok()
                            {
                                current
                            } else {
                                settle_cache_write_failure(
                                    &self.db,
                                    ticket_id,
                                    ticket.resource_version,
                                    false,
                                    now,
                                )
                                .await;
                                return Err(RpcError::internal(error));
                            }
                        } else {
                            settle_cache_write_failure(
                                &self.db,
                                ticket_id,
                                ticket.resource_version,
                                false,
                                now,
                            )
                            .await;
                            return Err(RpcError::internal(error));
                        }
                    }
                }
            }
            "active" => return Err(RpcError::invalid("cache upload retry has different bytes")),
            _ => {
                return Err(RpcError::FailedPrecondition(
                    "cache upload ticket is not writable".into(),
                ));
            }
        };
        let placement = self.hybrid_cache_upload_placement(&cache, &ticket).await?;
        Ok(HybridCacheUploadAdmission {
            object_key: Some(keymap::r2_key(&placement.prefix, &path)),
            completed: false,
        })
    }

    /// Reobserves the Worker-written R2 object and completes its SQL ticket.
    ///
    /// # Errors
    ///
    /// Returns an auth, ticket, topology, object-integrity, or database error.
    pub async fn complete_hybrid_cache_upload(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        ticket_id: &str,
        encoded_path: &str,
        request: HybridCacheUploadCompletionRequest,
    ) -> Result<(), RpcError> {
        let (cache, path) = self
            .hybrid_cache_upload_identity(auth, cache_id, encoded_path)
            .await?;
        validate_upload_digest(&request.sha256)?;
        let now = clock::now_unix_secs();
        let ticket = self
            .db
            .validate_cache_write_ticket(ticket_id, cache.id, &path, now, false)
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        if ticket.upload_kind != "single"
            || ticket.declared_size != i64::try_from(request.size).unwrap_or(i64::MAX)
            || ticket.intended_object_hash.as_deref() != Some(request.sha256.as_str())
        {
            return Err(RpcError::invalid(
                "cache upload completion does not match admission",
            ));
        }
        let observed = async {
            let placement = self.hybrid_cache_upload_placement(&cache, &ticket).await?;
            let fetch = self
                .surface
                .placement_fetcher(&placement)
                .await
                .map_err(RpcError::internal)?;
            fetch
                .inventory_evidence(&path)
                .await
                .map_err(RpcError::internal)
        }
        .await;
        let observed = match observed {
            Ok(Some(observed)) => observed,
            Ok(None) => {
                settle_cache_write_failure(&self.db, ticket_id, ticket.resource_version, true, now)
                    .await;
                return Err(RpcError::FailedPrecondition(
                    "cache upload R2 object disappeared after PUT".into(),
                ));
            }
            Err(error) => {
                settle_cache_write_failure(&self.db, ticket_id, ticket.resource_version, true, now)
                    .await;
                return Err(error);
            }
        };
        if observed.size != ticket.declared_size || hex::encode(observed.sha256) != request.sha256 {
            settle_cache_write_failure(&self.db, ticket_id, ticket.resource_version, true, now)
                .await;
            return Err(RpcError::FailedPrecondition(
                "cache upload R2 object does not match the admitted bytes".into(),
            ));
        }
        if let Err(error) = self
            .db
            .complete_cache_write_ticket(ticket_id, ticket.resource_version, now)
            .await
        {
            if matches!(self.db.cache_write_ticket(ticket_id).await,
                Ok(Some(current)) if current.state == "completed")
            {
                return Ok(());
            }
            settle_cache_write_failure(&self.db, ticket_id, ticket.resource_version, true, now)
                .await;
            return Err(RpcError::internal(error));
        }
        Ok(())
    }

    async fn hybrid_cache_upload_identity(
        &self,
        auth: Option<&str>,
        cache_id: &str,
        encoded_path: &str,
    ) -> Result<(crate::db::BinaryCache, String), RpcError> {
        let cache = self.binary_cache_or_not_found(cache_id).await?;
        self.require_cache_admin(auth, &cache).await?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_path)
            .map_err(|_| RpcError::invalid("cache upload path identity is invalid"))?;
        let path = String::from_utf8(decoded)
            .map_err(|_| RpcError::invalid("cache upload path is not UTF-8"))?;
        if cache.deleted_at.is_some()
            || !keymap::is_machine_path(&path)
            || crate::url_guard::validate_http_surface_path(&path).is_err()
        {
            return Err(RpcError::invalid("cache upload path is unsafe"));
        }
        Ok((cache, path))
    }

    async fn hybrid_cache_upload_placement(
        &self,
        cache: &crate::db::BinaryCache,
        ticket: &crate::db::CacheWriteTicketRecord,
    ) -> Result<crate::db::SurfacePlacementRecord, RpcError> {
        let placement = self
            .db
            .surface_placement(ticket.placement_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|placement| {
                placement.cache_id == Some(cache.id)
                    && placement.binding_id == ticket.binding_id
                    && placement.resource_version == ticket.placement_resource_version
                    && placement.effective_write_enabled
            })
            .ok_or_else(|| RpcError::FailedPrecondition("cache write placement changed".into()))?;
        self.db
            .binding(placement.binding_id)
            .await
            .map_err(RpcError::internal)?
            .filter(|binding| {
                binding.kind == "deployment_r2"
                    && binding.is_instance_default
                    && binding.resource_version == ticket.binding_resource_version
            })
            .ok_or_else(|| RpcError::FailedPrecondition("cache R2 binding changed".into()))?;
        Ok(placement)
    }

    async fn hybrid_cache_upload_prior(
        &self,
        cache: &crate::db::BinaryCache,
        ticket: &crate::db::CacheWriteTicketRecord,
        path: &str,
    ) -> Result<Option<crate::db::WriteObjectIdentity>, RpcError> {
        let placement = self.hybrid_cache_upload_placement(cache, ticket).await?;
        let fetch = self
            .surface
            .placement_fetcher(&placement)
            .await
            .map_err(RpcError::internal)?;
        fetch
            .inventory_evidence(path)
            .await
            .map(|evidence| evidence.map(write_object_identity))
            .map_err(RpcError::internal)
    }
}

fn validate_upload_digest(digest: &str) -> Result<(), RpcError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RpcError::invalid("cache upload SHA-256 is invalid"));
    }
    Ok(())
}

async fn validate_narinfo(
    db: &crate::db::Database,
    cache_id: &str,
    path: &str,
    request: &HybridCacheUploadAdmissionRequest,
) -> Result<(), RpcError> {
    if !path.ends_with(".narinfo") {
        if request.narinfo.is_some() {
            return Err(RpcError::invalid(
                "NAR upload cannot carry narinfo metadata",
            ));
        }
        return Ok(());
    }
    let narinfo = request
        .narinfo
        .as_deref()
        .ok_or_else(|| RpcError::invalid("narinfo upload omitted its signed body"))?;
    if narinfo.len() > crate::fetch::MAX_CACHE_NARINFO_BYTES
        || narinfo.len() as u64 != request.size
        || hex::encode(Sha256::digest(narinfo.as_bytes())) != request.sha256
    {
        return Err(RpcError::invalid(
            "narinfo body does not match the upload digest",
        ));
    }
    if let Some(selected) = db
        .active_signing_key_for_usage(cache_id, "narinfo")
        .await
        .map_err(RpcError::internal)?
    {
        crate::nix_sign::verify_narinfo(narinfo, &selected.name, &selected.public_key)
            .map_err(|_| RpcError::invalid("narinfo is not signed by its selected key"))?;
    }
    Ok(())
}
