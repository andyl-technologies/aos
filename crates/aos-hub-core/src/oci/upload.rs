//! Durable OCI Distribution upload request handling.
//!
//! Each PATCH body is first written as an immutable, digest-named staging
//! object and only then committed to the portable database continuation state.
//! Cancellation first makes the database state authoritative, then removes
//! unreachable staging objects on a best-effort basis. This makes retries safe
//! across native Hub processes, Worker isolates, and short-lived OCI bearer
//! tokens without exposing a resumable session after its only bytes were
//! deleted.

mod manifest;

use std::collections::BTreeMap;

use aos_oci_types::{RepositoryName, Sha256Digest};
use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse as _, Response};
use futures_util::TryStreamExt as _;
use uuid::Uuid;

use super::{
    add_distribution_version, distribution_error_response, unavailable_response,
    DistributionErrorCode, OciRequest, RegistryRecord, RpcService,
};
use crate::db::{
    oci_blob_object_key, AppendOciUploadChunk, BeginOciUpload, BindingWriteRevisionRecord,
    ClaimOciUpload, CompleteOciUpload, Database, OciBlobClaimOutcome, OciRepositoryRecord,
    OciUploadChunkRecord, OciUploadCleanupRecord, SurfacePlacementRecord, SurfaceTarget,
    OCI_MAX_SESSION_SECONDS,
};
use crate::surface_write::{MultipartAbortOutcome, PartTag, SurfaceWriteProvider};

/// Maximum body accepted in one resumable PATCH request.
const MAX_PATCH_BYTES: usize = 20 * 1024 * 1024;
/// Maximum complete blob accepted by the first Hub deployment contract.
const MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Provider part size used while coalescing arbitrary Distribution chunks.
const MULTIPART_PART_BYTES: usize = 8 * 1024 * 1024;
/// Stable upload-session lifetime.
const UPLOAD_SESSION_SECONDS: i64 = OCI_MAX_SESSION_SECONDS;
/// Lease granted to a finalizer before another process may expire its work.
const COMPLETION_LEASE_SECONDS: i64 = 15 * 60;

/// Outcome of one bounded OCI upload/publication recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciRecoverySummary {
    /// Publication sessions failed after their durable lease expired.
    pub expired_publications: u32,
    /// Upload sessions failed after their durable lease expired.
    pub expired_uploads: u32,
    /// Terminal upload staging sets confirmed physically absent.
    pub cleaned_uploads: u32,
}

/// Expires overdue OCI work and reconciles terminal staging objects.
///
/// Cleanup resolves the exact placement id, binding, and immutable write
/// revision frozen by the first accepted PATCH. A moved write authority or an
/// ordinary placement-state change therefore cannot redirect physical cleanup.
///
/// # Errors
///
/// Returns an error for invalid bounds, database failure, missing or changed
/// frozen placement identity, or physical deletion failure. Terminal cleanup
/// remains pending and safely retryable after every error.
pub async fn recover_expired_oci_work(
    db: &Database,
    writers: &dyn SurfaceWriteProvider,
    now: i64,
    limit: u32,
) -> anyhow::Result<OciRecoverySummary> {
    let expired_publications = db.expire_due_oci_publications(now, limit).await?;
    let expired_uploads = db.expire_due_oci_uploads(now, limit).await?;
    let candidates = db.oci_upload_cleanup_candidates(limit).await?;
    let mut cleaned_uploads = 0_u32;
    for candidate in candidates {
        cleanup_upload_staging(db, writers, &candidate, now).await?;
        cleaned_uploads = cleaned_uploads.saturating_add(1);
    }
    Ok(OciRecoverySummary {
        expired_publications,
        expired_uploads,
        cleaned_uploads,
    })
}

async fn cleanup_upload_staging(
    db: &Database,
    writers: &dyn SurfaceWriteProvider,
    candidate: &OciUploadCleanupRecord,
    now: i64,
) -> anyhow::Result<()> {
    if !candidate.chunks.is_empty() {
        let (placement, revision) = exact_upload_placement(
            db,
            candidate.upload.registry_id,
            candidate.upload.staging_placement_id,
            candidate.upload.staging_binding_id,
            candidate.upload.staging_binding_write_revision,
        )
        .await?;
        let writer = writers
            .placement_writer_at_revision(&placement, &revision)
            .await?;
        for chunk in &candidate.chunks {
            writer.delete(&chunk.staging_object_key).await?;
        }
    }
    db.complete_oci_upload_cleanup(&candidate.upload.id, candidate.upload.resource_version, now)
        .await?;
    Ok(())
}

async fn exact_upload_placement(
    db: &Database,
    registry_id: i64,
    placement_id: Option<i64>,
    binding_id: Option<i64>,
    binding_write_revision: Option<i64>,
) -> anyhow::Result<(SurfacePlacementRecord, BindingWriteRevisionRecord)> {
    let placement_id = placement_id
        .ok_or_else(|| anyhow::anyhow!("OCI upload with staged chunks has no frozen placement"))?;
    let binding_id =
        binding_id.ok_or_else(|| anyhow::anyhow!("OCI upload has no frozen storage binding"))?;
    let binding_write_revision = binding_write_revision
        .ok_or_else(|| anyhow::anyhow!("OCI upload has no frozen binding revision"))?;
    let placement = db
        .surface_placement(placement_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("frozen OCI upload placement disappeared"))?;
    anyhow::ensure!(
        placement.registry_id == Some(registry_id) && placement.binding_id == binding_id,
        "frozen OCI upload placement identity changed"
    );
    let revision = db
        .binding_write_revision(binding_id, binding_write_revision)
        .await?
        .ok_or_else(|| anyhow::anyhow!("frozen OCI upload binding revision disappeared"))?;
    Ok((placement, revision))
}

#[derive(Debug, Default)]
struct StartQuery {
    mount: Option<Sha256Digest>,
    from: Option<RepositoryName>,
    digest: Option<Sha256Digest>,
    size: Option<u64>,
}

impl RpcService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn serve_oci_write(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        request: OciRequest,
        method: Method,
        headers: HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> Response {
        let owner = match upload_owner(self, &headers) {
            Ok(owner) => owner,
            Err(response) => return response,
        };

        match (request, method) {
            (OciRequest::BlobUploadCollection { .. }, Method::POST) => {
                self.begin_blob_upload(registry, repository, &owner, &headers, query, body)
                    .await
            }
            (OciRequest::BlobUpload { upload_id, .. }, Method::GET | Method::HEAD) => {
                self.blob_upload_status(repository, &owner, &upload_id)
                    .await
            }
            (OciRequest::BlobUpload { upload_id, .. }, Method::PATCH) => {
                self.append_blob_upload(repository, &owner, &upload_id, &headers, body)
                    .await
            }
            (OciRequest::BlobUpload { upload_id, .. }, Method::DELETE) => {
                self.cancel_blob_upload(repository, &owner, &upload_id)
                    .await
            }
            (OciRequest::BlobUpload { upload_id, .. }, Method::PUT) => {
                self.finalize_blob_upload(repository, &owner, &upload_id, &headers, query, body)
                    .await
            }
            (OciRequest::Manifest { reference, .. }, Method::PUT) => {
                self.put_manifest(registry, repository, owner, reference, headers, body)
                    .await
            }
            (OciRequest::Manifest { reference, .. }, Method::DELETE) => {
                self.delete_manifest(repository, reference, owner).await
            }
            _ => distribution_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                DistributionErrorCode::Unsupported,
                "method is not supported for this Distribution endpoint",
                None,
                false,
            ),
        }
    }

    async fn begin_blob_upload(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        headers: &HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> Response {
        let body = match to_bytes(body, 1).await {
            Ok(body) if body.is_empty() => body,
            Ok(_) | Err(_) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "upload creation body must be empty",
                );
            }
        };
        drop(body);
        let query = match parse_start_query(query.unwrap_or_default()) {
            Ok(query) => query,
            Err(message) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    message,
                );
            }
        };

        if let (Some(source_name), Some(mount)) = (&query.from, query.mount) {
            if !upload_token_allows(self, headers, registry, source_name, "pull") {
                return upload_error(
                    StatusCode::UNAUTHORIZED,
                    DistributionErrorCode::Unauthorized,
                    "cross-repository mount requires source pull authority",
                );
            }
            let source = match self.db.oci_repository(registry.id, source_name).await {
                Ok(source) => source,
                Err(_) => return unavailable_response("repository catalog is unavailable", false),
            };
            if let Some(source) = source {
                match self
                    .db
                    .mount_oci_repository_blob(source.id, repository.id, mount, now())
                    .await
                {
                    Ok(()) => return mounted_response(repository, mount),
                    Err(_) => {
                        // The Distribution mount contract falls back to a new
                        // upload when the source does not contain the blob.
                    }
                }
            }
        }

        let expected_digest = match (query.digest, query.mount) {
            (Some(digest), Some(mount)) if digest != mount => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::DigestInvalid,
                    "digest and mount hints disagree",
                );
            }
            (Some(digest), _) | (None, Some(digest)) => Some(digest),
            (None, None) => None,
        };
        if query.size.is_some_and(|size| size > MAX_BLOB_BYTES) {
            return upload_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                DistributionErrorCode::SizeInvalid,
                "declared blob size exceeds the server limit",
            );
        }
        let current = now();
        let begin = BeginOciUpload {
            registry_id: registry.id,
            repository_id: repository.id,
            publication_id: None,
            writer_id: owner.to_string(),
            token_id: owner.to_string(),
            idempotency_key: Uuid::new_v4().simple().to_string(),
            expected_digest,
            expected_size: query.size,
            maximum_size: MAX_BLOB_BYTES,
            now: current,
            expires_at: current + UPLOAD_SESSION_SECONDS,
        };
        match self.db.begin_oci_upload(&begin).await {
            Ok(upload) => upload_progress_response(
                StatusCode::ACCEPTED,
                repository,
                &upload.id,
                upload.uploaded_size,
                false,
            ),
            Err(_) => unavailable_response("upload session could not be created", false),
        }
    }

    async fn blob_upload_status(
        &self,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
    ) -> Response {
        match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload))
                if upload.repository_id == repository.id
                    && matches!(upload.state.as_str(), "active" | "completing") =>
            {
                upload_progress_response(
                    StatusCode::NO_CONTENT,
                    repository,
                    upload_id,
                    upload.uploaded_size,
                    false,
                )
            }
            Ok(_) => upload_unknown(),
            Err(_) => unavailable_response("upload status is unavailable", false),
        }
    }

    async fn append_blob_upload(
        &self,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        headers: &HeaderMap,
        body: Body,
    ) -> Response {
        let upload = match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload))
                if upload.repository_id == repository.id && upload.state == "active" =>
            {
                upload
            }
            Ok(_) => return upload_unknown(),
            Err(_) => return unavailable_response("upload status is unavailable", false),
        };
        let bytes = match to_bytes(body, MAX_PATCH_BYTES).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "upload chunk must not be empty",
                );
            }
            Err(_) => {
                return upload_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    DistributionErrorCode::SizeInvalid,
                    "upload chunk exceeds the request limit",
                );
            }
        };
        if !content_range_matches(headers, upload.uploaded_size, bytes.len()) {
            return upload_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                DistributionErrorCode::BlobUploadInvalid,
                "upload content range is not contiguous",
            );
        }
        let chunks = match self.db.oci_upload_chunks(upload_id).await {
            Ok(chunks) => chunks,
            Err(_) => return unavailable_response("upload state is unavailable", false),
        };
        let Ok(ordinal) = u32::try_from(chunks.len()) else {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "upload contains too many chunks",
            );
        };
        let digest = Sha256Digest::digest(&bytes);
        let staging_object_key = format!(
            "oci/uploads/{upload_id}/chunks/{ordinal}-{}-{}",
            Uuid::new_v4().simple(),
            digest.encoded()
        );
        let (placement, revision) = match upload.staging_placement_id {
            Some(_) => match exact_upload_placement(
                &self.db,
                upload.registry_id,
                upload.staging_placement_id,
                upload.staging_binding_id,
                upload.staging_binding_write_revision,
            )
            .await
            {
                Ok(placement) => placement,
                Err(_) => {
                    return unavailable_response("frozen upload writer is unavailable", false);
                }
            },
            None => match self
                .effective_surface_writer(SurfaceTarget::Registry(upload.registry_id))
                .await
            {
                Ok(placement) => match self
                    .db
                    .placement_publication_write_revision(placement.id)
                    .await
                {
                    Ok(Some(revision)) => (placement, revision),
                    Ok(None) | Err(_) => {
                        return unavailable_response("registry writer is unavailable", false);
                    }
                },
                Err(_) => return unavailable_response("registry writer is unavailable", false),
            },
        };
        let writer = match self
            .surface_write
            .placement_writer_at_revision(&placement, &revision)
            .await
        {
            Ok(writer) => writer,
            Err(_) => return unavailable_response("registry writer is unavailable", false),
        };
        if writer.write(&staging_object_key, &bytes).await.is_err() {
            return unavailable_response("upload chunk could not be stored", false);
        }
        let mut next_sha256 = upload.sha256.clone();
        if next_sha256.update(&bytes).is_err() {
            let _ = writer.delete(&staging_object_key).await;
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "upload digest state is invalid",
            );
        }
        let append = AppendOciUploadChunk {
            upload_id: upload_id.to_string(),
            writer_id: owner.to_string(),
            token_id: owner.to_string(),
            expected_resource_version: upload.resource_version,
            staging_placement_id: placement.id,
            staging_placement_resource_version: placement.resource_version,
            staging_binding_id: revision.binding_id,
            staging_binding_write_revision: revision.revision,
            chunk: OciUploadChunkRecord {
                ordinal,
                byte_offset: upload.uploaded_size,
                byte_size: bytes.len() as u64,
                digest,
                staging_object_key: staging_object_key.clone(),
                created_at: now(),
            },
            next_sha256,
            now: now(),
        };
        match self.db.append_oci_upload_chunk(&append).await {
            Ok(upload) => upload_progress_response(
                StatusCode::ACCEPTED,
                repository,
                upload_id,
                upload.uploaded_size,
                false,
            ),
            Err(_) => {
                // A database transport failure can be ambiguous. Probe the
                // durable row before deleting this attempt-unique key; if the
                // probe itself fails, preserve bytes for reconciliation.
                if matches!(
                    self.db
                        .oci_upload_references_staging_key(upload_id, &staging_object_key)
                        .await,
                    Ok(false)
                ) {
                    let _ = writer.delete(&staging_object_key).await;
                }
                upload_error(
                    StatusCode::CONFLICT,
                    DistributionErrorCode::BlobUploadInvalid,
                    "upload state changed; query status before retrying",
                )
            }
        }
    }

    async fn cancel_blob_upload(
        &self,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
    ) -> Response {
        let upload = match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload)) if upload.repository_id == repository.id => upload,
            Ok(_) => return upload_unknown(),
            Err(_) => return unavailable_response("upload status is unavailable", false),
        };
        if upload.state != "active" {
            return upload_error(
                StatusCode::CONFLICT,
                DistributionErrorCode::BlobUploadInvalid,
                "upload finalization already owns the session",
            );
        }
        let chunks = match self.db.oci_upload_chunks(upload_id).await {
            Ok(chunks) => chunks,
            Err(_) => return unavailable_response("upload state is unavailable", false),
        };
        let cancelled = self
            .db
            .cancel_oci_upload(upload_id, owner, owner, upload.resource_version, now())
            .await;
        let cancelled = match cancelled {
            Ok(cancelled) => cancelled,
            Err(_) => {
                return unavailable_response("upload cancellation could not be committed", false);
            }
        };

        // Cancellation is authoritative before physical cleanup. Reversing
        // this order can delete the only staged copy while a failed database
        // transaction leaves the session active and apparently resumable.
        // Orphaned chunks are unreachable and the retention reconciler can
        // retry their deletion without resurrecting a cancelled session.
        let cleanup = OciUploadCleanupRecord {
            upload: cancelled,
            chunks,
        };
        if let Err(error) =
            cleanup_upload_staging(&self.db, self.surface_write.as_ref(), &cleanup, now()).await
        {
            tracing::warn!(
                upload_id,
                %error,
                "cancelled OCI upload left staging cleanup pending"
            );
        }

        let mut response = StatusCode::NO_CONTENT.into_response();
        add_distribution_version(&mut response);
        response
    }

    async fn finalize_blob_upload(
        &self,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        headers: &HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> Response {
        let digest = match parse_final_digest(query.unwrap_or_default()) {
            Ok(digest) => digest,
            Err(message) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::DigestInvalid,
                    message,
                );
            }
        };
        let final_bytes = match to_bytes(body, MAX_PATCH_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return upload_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    DistributionErrorCode::SizeInvalid,
                    "final upload chunk exceeds the request limit",
                );
            }
        };
        if !final_bytes.is_empty() {
            let appended = self
                .append_blob_upload(
                    repository,
                    owner,
                    upload_id,
                    headers,
                    Body::from(final_bytes),
                )
                .await;
            if appended.status() != StatusCode::ACCEPTED {
                return appended;
            }
        }

        let upload = match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload)) if upload.repository_id == repository.id => upload,
            Ok(_) => return upload_unknown(),
            Err(_) => return unavailable_response("upload status is unavailable", false),
        };
        if upload.state == "complete" {
            return if upload.final_digest == Some(digest) {
                completed_upload_response(repository, digest)
            } else {
                upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::DigestInvalid,
                    "declared digest does not match the completed upload",
                )
            };
        }
        if (!matches!(upload.state.as_str(), "active" | "completing"))
            || upload.sha256.final_digest().ok() != Some(digest)
            || upload.final_digest.is_some_and(|frozen| frozen != digest)
        {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::DigestInvalid,
                "declared digest does not match the uploaded bytes",
            );
        }
        let (materialization_placement, materialization_revision) =
            match upload.materialization_placement_id {
                Some(_) => match exact_upload_placement(
                    &self.db,
                    upload.registry_id,
                    upload.materialization_placement_id,
                    upload.materialization_binding_id,
                    upload.materialization_binding_write_revision,
                )
                .await
                {
                    Ok(placement) => placement,
                    Err(_) => {
                        return unavailable_response(
                            "frozen materialization writer is unavailable",
                            false,
                        );
                    }
                },
                None => match self
                    .effective_surface_writer(SurfaceTarget::Registry(upload.registry_id))
                    .await
                {
                    Ok(placement) => match self
                        .db
                        .placement_publication_write_revision(placement.id)
                        .await
                    {
                        Ok(Some(revision)) => (placement, revision),
                        Ok(None) | Err(_) => {
                            return unavailable_response("registry writer is unavailable", false);
                        }
                    },
                    Err(_) => return unavailable_response("registry writer is unavailable", false),
                },
            };
        let claim_now = now();
        let claim = match self
            .db
            .claim_oci_upload(&ClaimOciUpload {
                upload_id: upload_id.to_string(),
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                expected_resource_version: upload.resource_version,
                materialization_placement_id: materialization_placement.id,
                materialization_placement_resource_version: materialization_placement
                    .resource_version,
                materialization_binding_id: materialization_revision.binding_id,
                materialization_binding_write_revision: materialization_revision.revision,
                digest,
                now: claim_now,
                lease_expires_at: claim_now + COMPLETION_LEASE_SECONDS,
            })
            .await
        {
            Ok(claim) => claim,
            Err(_) => {
                return upload_error(
                    StatusCode::CONFLICT,
                    DistributionErrorCode::BlobUploadInvalid,
                    "upload finalization raced; verify the blob before retrying",
                );
            }
        };
        let claimed = match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload)) if upload.state == "completing" => upload,
            Ok(Some(upload)) if upload.state == "complete" => {
                return if upload.final_digest == Some(digest) {
                    completed_upload_response(repository, digest)
                } else {
                    upload_error(
                        StatusCode::BAD_REQUEST,
                        DistributionErrorCode::DigestInvalid,
                        "declared digest does not match the completed upload",
                    )
                };
            }
            Ok(_) => return upload_unknown(),
            Err(_) => return unavailable_response("upload status is unavailable", false),
        };
        let (placement, revision) = match exact_upload_placement(
            &self.db,
            claimed.registry_id,
            claimed.materialization_placement_id,
            claimed.materialization_binding_id,
            claimed.materialization_binding_write_revision,
        )
        .await
        {
            Ok(placement) => placement,
            Err(_) => {
                return unavailable_response("frozen materialization writer is unavailable", false);
            }
        };
        let chunks = match self.db.oci_upload_chunks(upload_id).await {
            Ok(chunks) => chunks,
            Err(_) => return unavailable_response("upload state is unavailable", false),
        };
        let (evidence, provider_upload_id) = match claim {
            OciBlobClaimOutcome::AlreadyPresent => match self
                .db
                .oci_blob_placement_evidence(upload.registry_id, digest, Some(placement.id))
                .await
            {
                Ok(Some(evidence)) => (evidence, None),
                Ok(None) | Err(_) => {
                    return unavailable_response(
                        "existing blob placement evidence is unavailable",
                        false,
                    );
                }
            },
            OciBlobClaimOutcome::InProgress => {
                return upload_error(
                    StatusCode::CONFLICT,
                    DistributionErrorCode::BlobUploadInvalid,
                    "another upload is finalizing this digest",
                );
            }
            OciBlobClaimOutcome::Claimed => {
                let pending = self
                    .db
                    .oci_pending_uploaded_object_evidence(
                        claimed.registry_id,
                        placement.id,
                        digest,
                        claimed.uploaded_size,
                    )
                    .await;
                match pending {
                    Ok(Some(evidence)) => (evidence, None),
                    Ok(None) => {
                        let probe = self
                            .probe_materialized_blob(
                                claimed.registry_id,
                                &placement,
                                digest,
                                claimed.uploaded_size,
                            )
                            .await;
                        match probe {
                            Ok(Some(evidence)) => (evidence, None),
                            Ok(None) => {
                                let staging = if chunks.is_empty() {
                                    None
                                } else {
                                    match exact_upload_placement(
                                        &self.db,
                                        claimed.registry_id,
                                        claimed.staging_placement_id,
                                        claimed.staging_binding_id,
                                        claimed.staging_binding_write_revision,
                                    )
                                    .await
                                    {
                                        Ok(placement) => Some(placement),
                                        Err(_) => {
                                            return unavailable_response(
                                                "frozen upload staging reader is unavailable",
                                                false,
                                            );
                                        }
                                    }
                                };
                                match self
                                    .materialize_blob(
                                        claimed.registry_id,
                                        &placement,
                                        &revision,
                                        staging.as_ref().map(|(placement, _)| placement),
                                        digest,
                                        claimed.uploaded_size,
                                        &chunks,
                                    )
                                    .await
                                {
                                    Ok(materialized) => materialized,
                                    Err(()) => {
                                        return unavailable_response(
                                            "uploaded blob could not be materialized",
                                            false,
                                        );
                                    }
                                }
                            }
                            Err(()) => {
                                return unavailable_response(
                                    "canonical blob bytes failed verification",
                                    false,
                                );
                            }
                        }
                    }
                    Err(_) => {
                        return unavailable_response(
                            "uploaded blob placement evidence is unavailable",
                            false,
                        );
                    }
                }
            }
        };
        let completed = self
            .db
            .complete_oci_upload(&CompleteOciUpload {
                upload_id: upload_id.to_string(),
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                expected_resource_version: claimed.resource_version,
                digest,
                byte_size: claimed.uploaded_size,
                surface_object_id: evidence.surface_object_id,
                placement_id: evidence.placement_id,
                now: now(),
            })
            .await;
        let completed = match completed {
            Ok(completed) => completed,
            Err(_) => {
                return unavailable_response("upload completion could not be committed", false);
            }
        };
        if let Ok(writer) = self
            .surface_write
            .placement_writer_at_revision(&placement, &revision)
            .await
        {
            if let Some(provider_upload_id) = provider_upload_id {
                let _ = writer
                    .settle_multipart(&oci_blob_object_key(digest), &provider_upload_id)
                    .await;
            }
        }
        let cleanup = OciUploadCleanupRecord {
            upload: completed,
            chunks,
        };
        if let Err(error) =
            cleanup_upload_staging(&self.db, self.surface_write.as_ref(), &cleanup, now()).await
        {
            tracing::warn!(
                upload_id,
                %error,
                "completed OCI upload left staging cleanup pending"
            );
        }
        completed_upload_response(repository, digest)
    }

    async fn materialize_blob(
        &self,
        registry_id: i64,
        placement: &crate::db::SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
        staging_placement: Option<&crate::db::SurfacePlacementRecord>,
        digest: Sha256Digest,
        byte_size: u64,
        chunks: &[OciUploadChunkRecord],
    ) -> Result<(crate::db::OciUploadedObjectEvidence, Option<String>), ()> {
        let path = oci_blob_object_key(digest);
        let writer = self
            .surface_write
            .placement_writer_at_revision(placement, revision)
            .await
            .map_err(|_| ())?;
        let mut provider_upload = None;
        if byte_size == 0 {
            writer.write(&path, &[]).await.map_err(|_| ())?;
        } else {
            let staging_placement = staging_placement.ok_or(())?;
            let staging_fetcher = self
                .surface
                .placement_fetcher(staging_placement)
                .await
                .map_err(|_| ())?;
            if writer.multipart_protocol_version() != Some(1) {
                return Err(());
            }
            let upload_id = writer.create_multipart(&path).await.map_err(|_| ())?;
            provider_upload = Some(upload_id.clone());
            let mut parts = Vec::<PartTag>::new();
            let mut pending = Vec::new();
            for chunk in chunks {
                let bytes = staging_fetcher
                    .fetch_bounded(&chunk.staging_object_key, MAX_PATCH_BYTES)
                    .await
                    .map_err(|_| ())?
                    .ok_or(())?;
                if bytes.len() as u64 != chunk.byte_size
                    || Sha256Digest::digest(&bytes) != chunk.digest
                {
                    abort_materialization(writer.as_ref(), &path, &upload_id).await;
                    return Err(());
                }
                pending.extend_from_slice(&bytes);
                while pending.len() >= MULTIPART_PART_BYTES {
                    let remaining = pending.split_off(MULTIPART_PART_BYTES);
                    let part = upload_materialization_part(
                        writer.as_ref(),
                        &path,
                        &upload_id,
                        &parts,
                        &pending,
                    )
                    .await;
                    let Ok(part) = part else {
                        abort_materialization(writer.as_ref(), &path, &upload_id).await;
                        return Err(());
                    };
                    parts.push(part);
                    pending = remaining;
                }
            }
            if !pending.is_empty() {
                let part = upload_materialization_part(
                    writer.as_ref(),
                    &path,
                    &upload_id,
                    &parts,
                    &pending,
                )
                .await;
                let Ok(part) = part else {
                    abort_materialization(writer.as_ref(), &path, &upload_id).await;
                    return Err(());
                };
                parts.push(part);
            }
            if parts.is_empty()
                || writer
                    .complete_multipart(&path, &upload_id, &parts)
                    .await
                    .is_err()
            {
                abort_materialization(writer.as_ref(), &path, &upload_id).await;
                return Err(());
            }
        }

        let evidence = self
            .probe_materialized_blob(registry_id, placement, digest, byte_size)
            .await?
            .ok_or(())?;
        Ok((evidence, provider_upload))
    }

    async fn probe_materialized_blob(
        &self,
        registry_id: i64,
        placement: &crate::db::SurfacePlacementRecord,
        digest: Sha256Digest,
        byte_size: u64,
    ) -> Result<Option<crate::db::OciUploadedObjectEvidence>, ()> {
        let path = oci_blob_object_key(digest);
        let fetcher = self
            .surface
            .placement_fetcher(placement)
            .await
            .map_err(|_| ())?;
        match fetcher.size(&path).await.map_err(|_| ())? {
            None => return Ok(None),
            Some(observed) if observed != byte_size => return Err(()),
            Some(_) => {}
        }
        let Some(read) = fetcher.fetch_stream(&path, None).await.map_err(|_| ())? else {
            return Ok(None);
        };
        if read.total != byte_size || read.range.is_some() {
            return Err(());
        }
        let etag = read.strong_etag.ok_or(())?;
        let mut state = crate::db::OciSha256State::initial();
        let mut observed = 0_u64;
        let mut stream = read.body.into_data_stream();
        while let Some(chunk) = stream.try_next().await.map_err(|_| ())? {
            observed = observed.checked_add(chunk.len() as u64).ok_or(())?;
            if observed > byte_size {
                return Err(());
            }
            state.update(&chunk).map_err(|_| ())?;
        }
        if observed != byte_size || state.final_digest().map_err(|_| ())? != digest {
            return Err(());
        }
        let evidence = self
            .db
            .record_oci_uploaded_object(registry_id, placement.id, digest, byte_size, &etag, now())
            .await
            .map_err(|_| ())?;
        Ok(Some(evidence))
    }
}

async fn upload_materialization_part(
    writer: &dyn crate::surface_write::SurfaceWrite,
    path: &str,
    upload_id: &str,
    prior: &[PartTag],
    bytes: &[u8],
) -> anyhow::Result<PartTag> {
    let part_number = u32::try_from(prior.len() + 1)?;
    writer
        .upload_part(path, upload_id, part_number, bytes)
        .await
}

async fn abort_materialization(
    writer: &dyn crate::surface_write::SurfaceWrite,
    path: &str,
    upload_id: &str,
) {
    match writer.abort_multipart(path, upload_id).await {
        Ok(MultipartAbortOutcome::Aborted | MultipartAbortOutcome::Absent) | Err(_) => {}
        Ok(MultipartAbortOutcome::PossiblyCompleted) => {}
    }
}

fn upload_owner(service: &RpcService, headers: &HeaderMap) -> Result<String, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| {
            upload_error(
                StatusCode::UNAUTHORIZED,
                DistributionErrorCode::Unauthorized,
                "authenticated OCI bearer token is required",
            )
        })?;
    let claims = service.jwt_keys.verify_oci_claims(token).map_err(|_| {
        upload_error(
            StatusCode::UNAUTHORIZED,
            DistributionErrorCode::Unauthorized,
            "OCI bearer token is invalid",
        )
    })?;
    if claims.sub == "anonymous" || claims.sub.is_empty() {
        return Err(upload_error(
            StatusCode::UNAUTHORIZED,
            DistributionErrorCode::Unauthorized,
            "anonymous OCI tokens cannot mutate repositories",
        ));
    }
    Ok(claims.sub)
}

fn upload_token_allows(
    service: &RpcService,
    headers: &HeaderMap,
    registry: &RegistryRecord,
    repository: &RepositoryName,
    action: &str,
) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|token| service.jwt_keys.verify_oci_claims(token).ok())
        .is_some_and(|claims| {
            claims.registry == registry.stable_id
                && claims.grants.iter().any(|grant| {
                    grant.repository == *repository
                        && grant.actions.iter().any(|granted| granted == action)
                })
        })
}

fn parse_start_query(query: &str) -> Result<StartQuery, &'static str> {
    let mut values = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !matches!(name.as_ref(), "mount" | "from" | "digest" | "size")
            || values
                .insert(name.into_owned(), value.into_owned())
                .is_some()
        {
            return Err("upload query contains an unknown or duplicate field");
        }
    }
    let mount = values
        .remove("mount")
        .map(|value| Sha256Digest::parse(&value))
        .transpose()
        .map_err(|_| "mount digest is invalid")?;
    let from = values
        .remove("from")
        .map(|value| RepositoryName::parse(&value))
        .transpose()
        .map_err(|_| "mount source repository is invalid")?;
    if mount.is_some() != from.is_some() {
        return Err("mount and from must be supplied together");
    }
    let digest = values
        .remove("digest")
        .map(|value| Sha256Digest::parse(&value))
        .transpose()
        .map_err(|_| "upload digest hint is invalid")?;
    let size = values
        .remove("size")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| "upload size hint is invalid")?;
    Ok(StartQuery {
        mount,
        from,
        digest,
        size,
    })
}

fn parse_final_digest(query: &str) -> Result<Sha256Digest, &'static str> {
    let mut digest = None;
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if name != "digest" || digest.is_some() {
            return Err("final upload query requires exactly one digest");
        }
        digest = Some(Sha256Digest::parse(&value).map_err(|_| "final upload digest is invalid")?);
    }
    digest.ok_or("final upload digest is required")
}

fn content_range_matches(headers: &HeaderMap, offset: u64, length: usize) -> bool {
    let Some(value) = headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let value = value.strip_prefix("bytes ").unwrap_or(value);
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let Ok(start) = start.parse::<u64>() else {
        return false;
    };
    let Ok(end) = end.parse::<u64>() else {
        return false;
    };
    start == offset
        && u64::try_from(length)
            .ok()
            .and_then(|length| offset.checked_add(length.saturating_sub(1)))
            == Some(end)
}

fn mounted_response(repository: &OciRepositoryRecord, digest: Sha256Digest) -> Response {
    let mut response = StatusCode::CREATED.into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("/v2/{}/blobs/{digest}", repository.name))
    {
        response.headers_mut().insert(header::LOCATION, location);
    }
    if let Ok(digest) = HeaderValue::from_str(&digest.to_string()) {
        response
            .headers_mut()
            .insert(super::CONTENT_DIGEST_HEADER, digest);
    }
    add_distribution_version(&mut response);
    response
}

fn completed_upload_response(repository: &OciRepositoryRecord, digest: Sha256Digest) -> Response {
    mounted_response(repository, digest)
}

fn upload_progress_response(
    status: StatusCode,
    repository: &OciRepositoryRecord,
    upload_id: &str,
    offset: u64,
    head: bool,
) -> Response {
    let mut response = if head {
        (status, Body::empty()).into_response()
    } else {
        status.into_response()
    };
    if let Ok(location) = HeaderValue::from_str(&format!(
        "/v2/{}/blobs/uploads/{upload_id}",
        repository.name
    )) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    if let Ok(upload_id) = HeaderValue::from_str(upload_id) {
        response
            .headers_mut()
            .insert("docker-upload-uuid", upload_id);
    }
    if offset > 0 {
        if let Ok(range) = HeaderValue::from_str(&format!("0-{}", offset - 1)) {
            response.headers_mut().insert(header::RANGE, range);
        }
    }
    add_distribution_version(&mut response);
    response
}

fn upload_unknown() -> Response {
    upload_error(
        StatusCode::NOT_FOUND,
        DistributionErrorCode::BlobUploadUnknown,
        "blob upload unknown",
    )
}

fn upload_error(
    status: StatusCode,
    code: DistributionErrorCode,
    message: &'static str,
) -> Response {
    distribution_error_response(status, code, message, None, false)
}

fn now() -> i64 {
    crate::clock::now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_query_is_strict_and_bounded_by_types() {
        let digest = Sha256Digest::digest(b"blob");
        let query = parse_start_query(&format!(
            "mount={digest}&from=base/runtime&digest={digest}&size=12"
        ))
        .unwrap();
        assert_eq!(query.mount, Some(digest));
        assert_eq!(query.from.unwrap().as_str(), "base/runtime");
        assert_eq!(query.size, Some(12));

        assert!(parse_start_query("mount=bad&from=source").is_err());
        assert!(parse_start_query("mount=sha256%3A00&from=source").is_err());
        assert!(parse_start_query("size=1&size=2").is_err());
        assert!(parse_start_query("unknown=value").is_err());
    }

    #[test]
    fn content_ranges_must_advance_contiguously() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_RANGE, HeaderValue::from_static("bytes 4-7"));
        assert!(content_range_matches(&headers, 4, 4));
        assert!(!content_range_matches(&headers, 3, 4));
        assert!(!content_range_matches(&headers, 4, 3));
    }
}
