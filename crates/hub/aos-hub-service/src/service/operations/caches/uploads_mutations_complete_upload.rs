//! Uploads mutations in the caches capability.

use super::*;

impl RpcService {
    /// Finalize the multipart upload `upload_id` for `(slug, path)`, assembling
    /// `parts` into the object.
    ///
    /// # Errors
    ///
    /// Returns a [`SurfaceWriteOutcome`] denial or an internal error when assembly
    /// fails. On success returns [`SurfaceWriteOutcome::Created`].
    pub async fn complete_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
        parts: &[crate::surface_write::PartTag],
    ) -> SurfaceWriteOutcome {
        if let Ok(Some(ticket)) = self.db.cache_write_ticket(upload_id).await {
            if ticket.state == "completed" {
                let cache = match self.db.binary_cache_by_stable_id(slug).await {
                    Ok(Some(cache)) => Some(cache),
                    Ok(None) => match self.db.binary_cache_by_slug(slug).await {
                        Ok(cache) => cache,
                        Err(error) => return internal_write(error),
                    },
                    Err(error) => return internal_write(error),
                };
                let Some(cache) =
                    cache.filter(|cache| cache.id == ticket.cache_id && cache.deleted_at.is_none())
                else {
                    return SurfaceWriteOutcome::NotFound;
                };
                if let Err(deny) = self.require_cache_admin(auth, &cache).await {
                    return auth_denial_to_write_outcome(deny);
                }
                let durable_parts = match self.db.cache_write_ticket_parts(upload_id).await {
                    Ok(parts) => parts,
                    Err(error) => return internal_write(error),
                };
                return if ticket.upload_kind == "multipart"
                    && ticket.object_key == path
                    && ticket.observed_final_size == Some(ticket.declared_size)
                    && multipart_completion_matches(&durable_parts, parts, ticket.declared_size)
                {
                    SurfaceWriteOutcome::Created
                } else {
                    SurfaceWriteOutcome::NotWritable(
                        "completed multipart retry does not match its durable request",
                    )
                };
            }
        }
        match self
            .resolve_cache_upload_ticket(auth, slug, path, upload_id, true)
            .await
        {
            Ok(Some((_cache, ticket, writer))) => {
                let Some(backend_upload_id) = ticket.backend_upload_id.clone() else {
                    return SurfaceWriteOutcome::NotWritable("multipart ticket is not initialized");
                };
                if ticket.uploaded_size != ticket.declared_size {
                    return SurfaceWriteOutcome::NotWritable(
                        "multipart uploaded bytes do not equal the declared size",
                    );
                }
                let durable_parts = match self.db.cache_write_ticket_parts(&ticket.ticket_id).await
                {
                    Ok(parts) => parts,
                    Err(error) => return internal_write(error),
                };
                if !multipart_completion_matches(&durable_parts, parts, ticket.declared_size) {
                    return SurfaceWriteOutcome::NotWritable(
                        "multipart completion does not match the confirmed part set",
                    );
                }
                let expected_etag = match writer.expected_multipart_etag(parts) {
                    Ok(Some(etag)) => match crate::surface_write::strong_if_match_etag(&etag) {
                        Ok(etag) => etag,
                        Err(error) => return internal_write(error),
                    },
                    Ok(None) => {
                        return SurfaceWriteOutcome::NotWritable(
                            "cache multipart backend has no deterministic completion identity",
                        );
                    }
                    Err(error) => return internal_write(error),
                };
                let ticket = if ticket.state == "completing" {
                    ticket
                } else {
                    match self
                        .db
                        .begin_cache_multipart_completion(
                            &ticket.ticket_id,
                            ticket.resource_version,
                            clock::now_unix_secs(),
                        )
                        .await
                    {
                        Ok(ticket) => ticket,
                        Err(error) => return internal_write(error),
                    }
                };
                let placement = match self.db.surface_placement(ticket.placement_id).await {
                    Ok(Some(placement)) => placement,
                    Ok(None) => {
                        return SurfaceWriteOutcome::NotWritable(
                            "cache write placement disappeared",
                        );
                    }
                    Err(error) => return internal_write(error),
                };
                let inventory = match self.surface.placement_fetcher(&placement).await {
                    Ok(fetch) => fetch,
                    Err(error) => return internal_write(error),
                };
                let already_complete = match inventory.inventory_evidence(path).await {
                    Ok(Some(evidence)) => {
                        cache_multipart_evidence_matches(&evidence, &ticket, &expected_etag)
                    }
                    Ok(None) => false,
                    Err(error) => return internal_write(error),
                };
                if !already_complete {
                    let provider_result = writer
                        .complete_multipart(path, &backend_upload_id, parts)
                        .await;
                    match provider_result {
                        Ok(etag) => {
                            let completed_etag =
                                match crate::surface_write::strong_if_match_etag(&etag) {
                                    Ok(etag) => etag,
                                    Err(error) => return internal_write(error),
                                };
                            if completed_etag != expected_etag {
                                return SurfaceWriteOutcome::NotWritable(
                                    "cache multipart provider returned an unexpected identity",
                                );
                            }
                        }
                        Err(error) => {
                            let recovered = match inventory.inventory_evidence(path).await {
                                Ok(Some(evidence)) => cache_multipart_evidence_matches(
                                    &evidence,
                                    &ticket,
                                    &expected_etag,
                                ),
                                Ok(None) => false,
                                Err(observe_error) => return internal_write(observe_error),
                            };
                            if !recovered {
                                return internal_write(error);
                            }
                        }
                    }
                }
                let observed = match inventory.inventory_evidence(path).await {
                    Ok(Some(evidence)) => evidence,
                    Ok(None) => {
                        return SurfaceWriteOutcome::NotWritable(
                            "completed cache upload is absent",
                        );
                    }
                    Err(error) => return internal_write(error),
                };
                if !cache_multipart_evidence_matches(&observed, &ticket, &expected_etag) {
                    return SurfaceWriteOutcome::NotWritable(
                        "completed cache upload does not match its admitted identity",
                    );
                }
                let observed_size = observed.size;
                let ticket = match self
                    .db
                    .reconcile_cache_write_ticket_size(
                        &ticket.ticket_id,
                        ticket.resource_version,
                        observed_size,
                        clock::now_unix_secs(),
                    )
                    .await
                {
                    Ok(ticket) => ticket,
                    Err(error) => match self.db.cache_write_ticket(&ticket.ticket_id).await {
                        Ok(Some(current)) if current.state == "completed" => {
                            return SurfaceWriteOutcome::Created;
                        }
                        Ok(Some(current))
                            if current.state == "completing"
                                && current.observed_final_size == Some(observed_size) =>
                        {
                            current
                        }
                        _ => return internal_write(error),
                    },
                };
                return match self
                    .db
                    .complete_cache_write_ticket(
                        &ticket.ticket_id,
                        ticket.resource_version,
                        clock::now_unix_secs(),
                    )
                    .await
                {
                    Ok(()) => {
                        if let Err(error) = writer.settle_multipart(path, &backend_upload_id).await
                        {
                            tracing::warn!(
                                upload_id = %backend_upload_id,
                                error = %format!("{error:#}"),
                                "settled multipart marker cleanup failed"
                            );
                        }
                        SurfaceWriteOutcome::Created
                    }
                    Err(error) => match self.db.cache_write_ticket(&ticket.ticket_id).await {
                        Ok(Some(current)) if current.state == "completed" => {
                            SurfaceWriteOutcome::Created
                        }
                        _ => internal_write(error),
                    },
                };
            }
            Ok(None) => {}
            Err(deny) => return deny,
        }
        SurfaceWriteOutcome::NotFound
    }

    /// Abort the multipart upload `upload_id` for `(slug, path)`, freeing backend
    /// state. Best-effort; an unknown upload is not an error.
    ///
    /// # Errors
    ///
    /// Returns a [`SurfaceWriteOutcome`] denial, or an internal error only on a fatal
    /// backend failure.
    pub async fn abort_upload(
        &self,
        auth: Option<&str>,
        slug: &str,
        path: &str,
        upload_id: &str,
    ) -> SurfaceWriteOutcome {
        match self
            .resolve_cache_upload_ticket(auth, slug, path, upload_id, false)
            .await
        {
            Ok(Some((_cache, ticket, writer))) => {
                let Some(backend_upload_id) = ticket.backend_upload_id.as_deref() else {
                    return SurfaceWriteOutcome::NotWritable("multipart ticket is not initialized");
                };
                match writer.abort_multipart(path, backend_upload_id).await {
                    Ok(
                        crate::surface_write::MultipartAbortOutcome::Aborted
                        | crate::surface_write::MultipartAbortOutcome::Absent,
                    ) => {}
                    Ok(crate::surface_write::MultipartAbortOutcome::PossiblyCompleted) => {
                        return SurfaceWriteOutcome::NotWritable(
                            "multipart abort is uncertain; durable recovery retains the fence",
                        );
                    }
                    Err(error) => return internal_write(error),
                }
                return match self
                    .db
                    .abort_cache_write_ticket(
                        &ticket.ticket_id,
                        ticket.resource_version,
                        "aborted",
                        clock::now_unix_secs(),
                    )
                    .await
                {
                    Ok(()) => SurfaceWriteOutcome::Created,
                    Err(error) => internal_write(error),
                };
            }
            Ok(None) => {}
            Err(deny) => return deny,
        }
        SurfaceWriteOutcome::NotFound
    }
}
