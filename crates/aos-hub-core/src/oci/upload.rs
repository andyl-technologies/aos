//! Durable OCI Distribution upload request handling.
//!
//! Each PATCH body is first written as an immutable, digest-named staging
//! object and only then committed to the portable database continuation state.
//! Cancellation first makes the database state authoritative, then removes
//! unreachable staging objects on a best-effort basis. This makes retries safe
//! across native Hub processes, Worker isolates, and short-lived OCI bearer
//! tokens without exposing a resumable session after its only bytes were
//! deleted.

mod direct;
mod external_allocation;
mod manifest;
pub(super) mod observations;

use std::collections::BTreeMap;

use aos_oci_types::{RepositoryName, Sha256Digest};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::TryStreamExt as _;
use uuid::Uuid;

use super::{
    DistributionErrorCode, OciRequest, RegistryRecord, RpcService, add_distribution_version,
    distribution_error_response, unavailable_response,
};
use crate::db::{
    AppendOciUploadChunk, BeginOciUpload, BindingWriteRevisionRecord, ClaimOciUpload,
    CompleteOciUpload, Database, OCI_MAX_SESSION_SECONDS, OciBlobClaimOutcome, OciRepositoryRecord,
    OciUploadChunkRecord, OciUploadCleanupRecord, OciUploadRecord, SurfacePlacementRecord,
    SurfaceTarget, oci_blob_object_key,
};
use crate::hybrid_ingress::{
    HYBRID_UPLOAD_PHASE_HEADER, HybridOciChunkAdmission, HybridOciChunkCompletionRequest,
    MAX_HYBRID_OCI_CHUNK_BYTES, oci_chunk_range_matches,
};
use crate::surface_write::{MultipartAbortOutcome, PartTag, SurfaceWriteProvider};

/// Maximum body accepted in one resumable PATCH request.
const MAX_PATCH_BYTES: usize = MAX_HYBRID_OCI_CHUNK_BYTES;
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
/// revision frozen by the first accepted PATCH. Placement state and read order
/// may change while cleanup is pending; neither changes its immutable prefix
/// or the frozen physical write location.
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
        let mut writer = None;
        for chunk in &candidate.chunks {
            let claim = db.claim_terminal_oci_chunk_cleanup(candidate, chunk).await?;
            if writers.cleanup_oci_upload_chunk(&claim).await? {
                claim.check_current(db).await?;
                continue;
            }

            if writer.is_none() {
                writer = Some(
                    writers
                        .placement_writer_at_revision(&placement, &revision)
                        .await?,
                );
            }
            let writer = writer
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("OCI cleanup writer absent"))?;
            claim.check_current(db).await?;
            writer.delete(&chunk.staging_object_key).await?;
            claim.check_current(db).await?;
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
/// Canonical initial-upload metadata, including a retained direct operation.
pub(crate) struct StartQuery {
    mount: Option<Sha256Digest>,
    from: Option<RepositoryName>,
    digest: Option<Sha256Digest>,
    size: Option<u64>,
    operation_id: Option<String>,
}

impl StartQuery {
    pub(super) fn validate_direct_allocation(&self) -> Result<(), &'static str> {
        if self.operation_id.is_none()
            || self.digest.is_none()
            || self.size.is_none()
            || self.mount.is_some()
            || self.from.is_some()
            || self.size.is_some_and(|size| size > MAX_BLOB_BYTES)
        {
            return Err("direct OCI requires one exact operation, digest and size");
        }
        Ok(())
    }
}

impl RpcService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn serve_oci_write(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authority: &str,
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
        if self.hybrid_delivery && method == Method::PUT {
            if let OciRequest::Manifest { reference, .. } = &request {
                let phase = headers
                    .get(HYBRID_UPLOAD_PHASE_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let Some(phase) = phase else {
                    return unavailable_response("manifest requires Worker-local staging", false);
                };
                return self
                    .serve_hybrid_manifest(
                        registry,
                        repository,
                        owner,
                        authority,
                        reference.clone(),
                        headers,
                        query,
                        body,
                        &phase,
                    )
                    .await;
            }
        }
        if let Some(phase) = headers
            .get(HYBRID_UPLOAD_PHASE_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            let OciRequest::BlobUpload { upload_id, .. } = &request else {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "invalid hybrid OCI upload phase",
                );
            };
            if method != Method::PATCH || !self.hybrid_delivery {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "hybrid OCI upload phase is unavailable",
                );
            }
            return match phase {
                crate::hybrid_ingress::HYBRID_OCI_FINAL_AUTHORIZATION_PHASE => {
                    if !matches!(to_bytes(body, 1).await, Ok(bytes) if bytes.is_empty()) {
                        return upload_error(
                            StatusCode::BAD_REQUEST,
                            DistributionErrorCode::BlobUploadInvalid,
                            "OCI final authorization requires an empty request",
                        );
                    }
                    match self
                        .authorize_hybrid_oci_final(
                            registry, repository, &owner, upload_id, authority, &headers, query,
                        )
                        .await
                    {
                        Ok(admission) => axum::Json(admission).into_response(),
                        Err(response) => response,
                    }
                }
                "preflight" => {
                    if !matches!(to_bytes(body, 1).await, Ok(bytes) if bytes.is_empty()) {
                        return upload_error(
                            StatusCode::BAD_REQUEST,
                            DistributionErrorCode::BlobUploadInvalid,
                            "hybrid OCI preflight requires an empty request",
                        );
                    }
                    match self
                        .preflight_hybrid_oci_chunk(
                            registry, repository, &owner, upload_id, authority, &headers,
                        )
                        .await
                    {
                        Ok(admission) => axum::Json(admission).into_response(),
                        Err(response) => response,
                    }
                }
                "complete" => {
                    let request = to_bytes(body, 16 * 1024).await.ok().and_then(|body| {
                        serde_json::from_slice::<HybridOciChunkCompletionRequest>(&body).ok()
                    });
                    match request {
                        Some(request) => {
                            self.complete_hybrid_oci_chunk(
                                registry, repository, &owner, upload_id, authority, &headers,
                                request,
                            )
                            .await
                        }
                        None => upload_error(
                            StatusCode::BAD_REQUEST,
                            DistributionErrorCode::BlobUploadInvalid,
                            "hybrid OCI completion evidence is invalid",
                        ),
                    }
                }
                _ => upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::BlobUploadInvalid,
                    "invalid hybrid OCI upload phase",
                ),
            };
        }

        match (request, method) {
            (OciRequest::BlobUploadCollection { .. }, Method::POST) => {
                self.begin_blob_upload(
                    registry, repository, authority, &owner, &headers, query, body,
                )
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
                self.finalize_blob_upload(
                    registry, repository, &owner, &upload_id, authority, &headers, query, body,
                )
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

    async fn authorize_hybrid_oci_final(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        authority: &str,
        headers: &HeaderMap,
        query: Option<&str>,
    ) -> Result<crate::hybrid_ingress::HybridOciFinalAdmission, Response> {
        let authenticated = manifest::authority::HybridManifestAuthority::resolve(
            self, registry, repository, authority, headers,
        )
        .await?;
        let upload = self
            .db
            .oci_upload(upload_id, owner, owner, now())
            .await
            .map_err(|_| unavailable_response("OCI upload is unavailable", false))?
            .filter(|upload| {
                upload.registry_id == registry.id
                    && upload.repository_id == repository.id
                    && matches!(upload.state.as_str(), "active" | "completing" | "complete")
            })
            .ok_or_else(upload_unknown)?;
        let digest = parse_final_digest(query.unwrap_or_default()).map_err(|message| {
            upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::DigestInvalid,
                message,
            )
        })?;
        let completion_only = upload.state != "active";
        if completion_only && upload.final_digest != Some(digest) {
            return Err(upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::DigestInvalid,
                "declared digest differs from the frozen completion",
            ));
        }

        if upload.state == "complete" {
            // Cleanup may retire physical locators. An exact terminal replay
            // uses durable business evidence and never selects a new writer.
            let blob = self
                .db
                .oci_blob_for_repository(repository.id, digest)
                .await
                .map_err(|_| unavailable_response("OCI completed catalogue is unavailable", false))?
                .filter(|blob| {
                    blob.registry_id == upload.registry_id
                        && blob.digest == digest
                        && blob.byte_size == upload.uploaded_size
                        && blob.object_key == oci_blob_object_key(digest)
                        && blob.lifecycle_state == "active"
                })
                .ok_or_else(|| unavailable_response("OCI completed catalogue differs", false))?;
            let object = self
                .db
                .surface_object(blob.surface_object_id)
                .await
                .map_err(|_| unavailable_response("OCI completed object is unavailable", false))?
                .filter(|object| {
                    object.registry_id == Some(upload.registry_id)
                        && object.object_key == blob.object_key
                        && object.content_hash == Some(digest.encoded())
                        && object.size.and_then(|size| u64::try_from(size).ok())
                            == Some(upload.uploaded_size)
                        && object.object_kind == "immutable"
                        && object.lifecycle_state == "active"
                });
            if object.is_none() {
                return Err(unavailable_response("OCI completed object differs", false));
            }
            authenticated.recheck(self, registry, repository).await?;
            return Ok(crate::hybrid_ingress::HybridOciFinalAdmission {
                external: false,
                completion_only: true,
            });
        }

        let placement = if completion_only {
            let (placement, _) = exact_upload_placement(
                &self.db,
                upload.registry_id,
                upload.materialization_placement_id,
                upload.materialization_binding_id,
                upload.materialization_binding_write_revision,
            )
            .await
            .map_err(|_| {
                unavailable_response("OCI frozen completion writer is unavailable", false)
            })?;
            if upload.materialization_placement_resource_version != Some(placement.resource_version)
            {
                return Err(unavailable_response(
                    "OCI frozen completion placement changed",
                    false,
                ));
            }
            placement
        } else {
            match upload.staging_placement_id {
                Some(_) => {
                    exact_upload_placement(
                        &self.db,
                        upload.registry_id,
                        upload.staging_placement_id,
                        upload.staging_binding_id,
                        upload.staging_binding_write_revision,
                    )
                    .await
                    .map_err(|_| unavailable_response("OCI frozen writer is unavailable", false))?
                    .0
                }
                None => self
                    .effective_surface_writer(SurfaceTarget::Registry(registry.id))
                    .await
                    .map_err(|_| {
                        unavailable_response("OCI current writer is unavailable", false)
                    })?,
            }
        };
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(|_| unavailable_response("OCI binding is unavailable", false))?
            .ok_or_else(|| unavailable_response("OCI binding disappeared", false))?;
        let external = !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2");
        if !external && (!binding.is_instance_default || binding.kind != "deployment_r2") {
            return Err(unavailable_response(
                "OCI writer kind is unsupported",
                false,
            ));
        }
        // This is a bodyless routing decision after current Publish permission,
        // not a reservation, provider proof or mutation permission.
        authenticated.recheck(self, registry, repository).await?;
        Ok(crate::hybrid_ingress::HybridOciFinalAdmission {
            external,
            completion_only,
        })
    }

    async fn preflight_hybrid_oci_chunk(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        authority: &str,
        headers: &HeaderMap,
    ) -> Result<HybridOciChunkAdmission, Response> {
        let mut upload = match self.db.oci_upload(upload_id, owner, owner, now()).await {
            Ok(Some(upload))
                if upload.repository_id == repository.id && upload.state == "active" =>
            {
                upload
            }
            Ok(_) => return Err(upload_unknown()),
            Err(_) => return Err(unavailable_response("upload state is unavailable", false)),
        };
        if upload.sha256.validate().is_err() || upload.sha256.total_bytes != upload.uploaded_size {
            return Err(unavailable_response(
                "upload digest state is invalid",
                false,
            ));
        }
        let chunks = self
            .db
            .oci_upload_chunks(upload_id)
            .await
            .map_err(|_| unavailable_response("upload chunks are unavailable", false))?;
        let ordinal = u32::try_from(chunks.len()).map_err(|_| {
            upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "upload contains too many chunks",
            )
        })?;
        let remaining = upload
            .maximum_size
            .saturating_sub(upload.uploaded_size)
            .min(
                upload
                    .expected_size
                    .map_or(u64::MAX, |size| size.saturating_sub(upload.uploaded_size)),
            );
        let maximum_chunk_bytes = remaining.min(MAX_PATCH_BYTES as u64);
        if maximum_chunk_bytes == 0 {
            return Err(upload_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                DistributionErrorCode::SizeInvalid,
                "upload has no remaining byte allowance",
            ));
        }

        // Reject an intrinsically invalid declared range before reserving the
        // private writer or issuing a control that can create a provider object.
        // The positive completion still checks the independently counted body.
        if !content_range_admits(headers, upload.uploaded_size, maximum_chunk_bytes) {
            return Err(upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "OCI chunk range is invalid for the current upload allowance",
            ));
        }

        let (placement, revision) = match upload.staging_placement_id {
            Some(_) => exact_upload_placement(
                &self.db,
                upload.registry_id,
                upload.staging_placement_id,
                upload.staging_binding_id,
                upload.staging_binding_write_revision,
            )
            .await
            .map_err(|_| unavailable_response("frozen upload writer is unavailable", false))?,
            None => {
                let placement = self
                    .effective_surface_writer(SurfaceTarget::Registry(upload.registry_id))
                    .await
                    .map_err(|_| unavailable_response("registry writer is unavailable", false))?;
                let revision = self
                    .db
                    .placement_publication_write_revision(placement.id)
                    .await
                    .map_err(|_| unavailable_response("registry writer is unavailable", false))?
                    .ok_or_else(|| unavailable_response("registry writer is unavailable", false))?;
                (placement, revision)
            }
        };
        if upload
            .staging_placement_resource_version
            .is_some_and(|version| version != placement.resource_version)
        {
            return Err(unavailable_response(
                "frozen upload placement changed",
                false,
            ));
        }
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(|_| unavailable_response("upload binding is unavailable", false))?
            .ok_or_else(|| unavailable_response("upload binding is unavailable", false))?;
        let external = !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2");
        if (!binding.is_instance_default || binding.kind != "deployment_r2") && !external {
            return Err(unavailable_response(
                "hybrid OCI upload binding is unsupported",
                false,
            ));
        }

        let (staging_object_key, external) = if external {
            use crate::storage_authority::external_object::oci::{
                OciUploadOriginal, OciWriterOriginal, admission::ExternalOciStagePreparation,
            };
            let authenticated = manifest::authority::HybridManifestAuthority::resolve(
                self, registry, repository, authority, headers,
            )
            .await?;
            let write_authority = self
                .db
                .surface_write_authority(SurfaceTarget::Registry(upload.registry_id))
                .await
                .map_err(|_| unavailable_response("OCI writer authority unavailable", false))?
                .ok_or_else(|| unavailable_response("OCI writer authority absent", false))?;
            let writer = OciWriterOriginal::from_records(
                &OciUploadOriginal::from_record(&upload)
                    .map_err(|_| unavailable_response("OCI upload original invalid", false))?,
                &placement,
                &binding,
                &revision,
                &write_authority,
            )
            .map_err(|_| unavailable_response("external OCI writer is not ready", false))?;
            let iam = authenticated.statements(self, registry, repository).await?;
            upload = self
                .db
                .reserve_external_oci_staging(
                    &upload,
                    &placement,
                    &writer,
                    iam,
                    authenticated.expires_at(),
                    now(),
                )
                .await
                .map_err(|_| {
                    unavailable_response("external OCI writer reservation refused", false)
                })?;
            let key = ExternalOciStagePreparation::chunk_key(&upload, ordinal)
                .map_err(|_| unavailable_response("OCI operation identity invalid", false))?;
            let permit = self
                .surface_write
                .prepare_external_oci_stage(&ExternalOciStagePreparation {
                    upload: upload.clone(),
                    actor: authenticated
                        .external_original()
                        .map_err(|_| unavailable_response("OCI current actor invalid", false))?,
                    writer,
                    staging_key: key.clone(),
                    ordinal,
                    offset: upload.uploaded_size,
                    prior_sha256: upload.sha256.clone(),
                    maximum_bytes: maximum_chunk_bytes,
                    expected: None,
                })
                .await
                .map_err(|_| {
                    unavailable_response("external OCI workflow qualification unavailable", false)
                })?;
            authenticated.recheck(self, registry, repository).await?;
            if let Ok(actor) = authenticated.external_original() {
                observations::external_admission("chunk", &permit, &actor);
            }
            (key, Some(permit))
        } else {
            (
                format!(
                    "oci/uploads/{upload_id}/chunks/{ordinal}-{}",
                    Uuid::new_v4().simple()
                ),
                None,
            )
        };
        Ok(HybridOciChunkAdmission {
            external,
            upload_resource_version: upload.resource_version,
            offset: upload.uploaded_size,
            ordinal,
            maximum_chunk_bytes,
            placement_id: placement.id,
            placement_resource_version: placement.resource_version,
            binding_id: revision.binding_id,
            binding_write_revision: revision.revision,
            placement_prefix: placement.prefix,
            staging_object_key,
            sha256_state: upload.sha256,
        })
    }

    async fn complete_hybrid_oci_chunk(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        authority: &str,
        headers: &HeaderMap,
        request: HybridOciChunkCompletionRequest,
    ) -> Response {
        let admission = &request.admission;
        let chunk_digest = match Sha256Digest::parse(&format!("sha256:{}", request.chunk_sha256)) {
            Ok(digest) => digest,
            Err(_) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    DistributionErrorCode::DigestInvalid,
                    "OCI chunk digest is invalid",
                );
            }
        };
        let Some(next_size) = admission.offset.checked_add(request.byte_size) else {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::SizeInvalid,
                "OCI chunk size overflows the upload",
            );
        };
        let chunk_length = usize::try_from(request.byte_size).ok();
        let expected_size = i64::try_from(request.byte_size).ok();
        if request.byte_size == 0
            || request.byte_size > admission.maximum_chunk_bytes
            || expected_size.is_none()
            || request.next_sha256_state.validate().is_err()
            || request.next_sha256_state.total_bytes != next_size
            || !chunk_length
                .is_some_and(|length| content_range_matches(headers, admission.offset, length))
        {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "OCI chunk completion does not match its admission",
            );
        }
        let prefix = format!("oci/uploads/{upload_id}/chunks/{}-", admission.ordinal);
        let valid_key = admission
            .staging_object_key
            .strip_prefix(&prefix)
            .is_some_and(|attempt| {
                attempt.len() == 32
                    && attempt
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !valid_key {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::BlobUploadInvalid,
                "OCI staging key is invalid",
            );
        }
        let current = match self
            .preflight_hybrid_oci_chunk(registry, repository, owner, upload_id, authority, headers)
            .await
        {
            Ok(current) => current,
            Err(response) => return response,
        };
        let mut expected = current;
        let external_permit = expected.external.take();
        let mut received = admission.clone();
        received.external = None;
        if external_permit.is_none() {
            expected.staging_object_key = admission.staging_object_key.clone();
        }
        if received != expected {
            return upload_error(
                StatusCode::CONFLICT,
                DistributionErrorCode::BlobUploadInvalid,
                "OCI upload changed before chunk completion",
            );
        }

        let placement = match self.db.surface_placement(admission.placement_id).await {
            Ok(Some(placement))
                if placement.resource_version == admission.placement_resource_version =>
            {
                placement
            }
            _ => return unavailable_response("OCI staging placement changed", false),
        };
        if let Some(permit) = &external_permit {
            let proof = match self.surface_write.external_oci_stage_readback(permit).await {
                Ok(proof) => proof,
                Err(_) => return unavailable_response("external OCI stage is unsettled", false),
            };
            let reply = match proof.for_original(&permit.request.original) {
                Ok(reply) if reply.pending_effect_digest.is_none() => reply,
                _ => return unavailable_response("external OCI stage proof differs", false),
            };
            if !reply.closed.as_ref().is_some_and(|closed| {
                closed.bytes.size == request.byte_size
                    && closed.bytes.sha256 == request.chunk_sha256
            }) || reply.upload_sha256 != request.next_sha256_state
            {
                return unavailable_response(
                    "external OCI staged bytes differ from completion",
                    false,
                );
            }
        } else {
            let fetcher = match self.surface.placement_fetcher(&placement).await {
                Ok(fetcher) => fetcher,
                Err(_) => return unavailable_response("OCI staging object is unavailable", false),
            };
            let evidence = fetcher
                .inventory_evidence_bounded(&admission.staging_object_key, request.byte_size)
                .await;
            let evidence = match evidence {
                Ok(Some(evidence)) => evidence,
                _ => return unavailable_response("OCI staging object is unverified", false),
            };
            if Some(evidence.size) != expected_size || evidence.sha256 != *chunk_digest.as_bytes() {
                return unavailable_response("OCI staging object differs from the chunk", false);
            }
        }

        let append = AppendOciUploadChunk {
            upload_id: upload_id.to_string(),
            writer_id: owner.to_string(),
            token_id: owner.to_string(),
            expected_resource_version: admission.upload_resource_version,
            staging_placement_id: admission.placement_id,
            staging_placement_resource_version: admission.placement_resource_version,
            staging_binding_id: admission.binding_id,
            staging_binding_write_revision: admission.binding_write_revision,
            chunk: OciUploadChunkRecord {
                ordinal: admission.ordinal,
                byte_offset: admission.offset,
                byte_size: request.byte_size,
                digest: chunk_digest,
                staging_object_key: admission.staging_object_key.clone(),
                created_at: now(),
            },
            next_sha256: request.next_sha256_state,
            now: now(),
        };
        let current_authority = if external_permit.is_some() {
            let authenticated = match manifest::authority::HybridManifestAuthority::resolve(
                self, registry, repository, authority, headers,
            )
            .await
            {
                Ok(authenticated) => authenticated,
                Err(response) => return response,
            };
            let permit = external_permit.as_ref().map(|permit| &permit.request);
            if permit.is_none_or(|permit| {
                authenticated.external_original().map_or(true, |actor| {
                    actor.account != permit.actor.account || actor.token_id != permit.actor.token_id
                })
            }) {
                return unavailable_response("OCI current actor changed during readback", false);
            }
            let mut statements = match authenticated.statements(self, registry, repository).await {
                Ok(statements) => statements,
                Err(response) => return response,
            };
            let Some(permit) = permit else {
                return unavailable_response("OCI original disappeared during readback", false);
            };
            match self.db.external_oci_writer_statements(
                registry.id,
                &placement,
                &permit.original.writer,
            ) {
                Ok(writer) => statements.extend(writer),
                Err(_) => return unavailable_response("OCI writer changed during readback", false),
            }
            statements
        } else {
            Vec::new()
        };
        match self
            .db
            .append_oci_upload_chunk_checked(&append, current_authority)
            .await
        {
            Ok(upload) => {
                crate::hybrid_ingress::observation::record_existing_check(
                    "oci_chunk_catalog_current", &(
                        &upload.id, upload.resource_version, upload.uploaded_size,
                        admission.placement_id, admission.placement_resource_version,
                        admission.binding_id, admission.binding_write_revision,
                        &admission.staging_object_key, &request.chunk_sha256,
                    ));
                upload_progress_response(
                    StatusCode::ACCEPTED,
                    repository,
                    upload_id,
                    upload.uploaded_size,
                    false,
                )
            },
            Err(_) => upload_error(
                StatusCode::CONFLICT,
                DistributionErrorCode::BlobUploadInvalid,
                "upload state changed; query status before retrying",
            ),
        }
    }

    async fn begin_blob_upload(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authority: &str,
        owner: &str,
        headers: &HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> Response {
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
        let external = if self.hybrid_delivery {
            match self.hybrid_external_oci_writer(registry).await {
                Ok(external) => external,
                Err(response) => return response,
            }
        } else {
            false
        };
        if self.hybrid_delivery && !external {
            return self
                .begin_direct_blob_upload(registry, repository, authority, headers, query, body)
                .await;
        }
        if query.operation_id.is_some() {
            return upload_error(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::Unsupported,
                "direct OCI allocation is unavailable on this legacy endpoint",
            );
        }

        let authenticated = if external {
            match manifest::authority::HybridManifestAuthority::resolve(
                self, registry, repository, authority, headers,
            )
            .await
            {
                Ok(value) => Some(value),
                Err(response) => return response,
            }
        } else {
            None
        };
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
        let allocated = if let Some(authenticated) = authenticated {
            let mut statements = match authenticated.statements(self, registry, repository).await {
                Ok(statements) => statements,
                Err(response) => return response,
            };
            let placement = match self
                .effective_surface_writer(SurfaceTarget::Registry(registry.id))
                .await
            {
                Ok(placement) => placement,
                Err(_) => return unavailable_response("OCI current writer unavailable", false),
            };
            let binding = match self.db.binding(placement.binding_id).await {
                Ok(Some(binding)) => binding,
                _ => return unavailable_response("OCI current binding unavailable", false),
            };
            let revision = match self
                .db
                .placement_publication_write_revision(placement.id)
                .await
            {
                Ok(Some(revision)) => revision,
                _ => return unavailable_response("OCI write revision unavailable", false),
            };
            let write_authority = match self
                .db
                .surface_write_authority(SurfaceTarget::Registry(registry.id))
                .await
            {
                Ok(Some(value)) => value,
                _ => return unavailable_response("OCI write authority unavailable", false),
            };
            let writer = match crate::storage_authority::external_object::oci::OciWriterOriginal::from_registry_records(
                registry.id, &placement, &binding, &revision, &write_authority) {
                Ok(writer) => writer, Err(_) => return unavailable_response("OCI external writer changed", false),
            };
            match self
                .db
                .external_oci_writer_statements(registry.id, &placement, &writer)
            {
                Ok(writer) => statements.extend(writer),
                Err(_) => return unavailable_response("OCI external writer changed", false),
            }
            if let Err(response) = authenticated.recheck(self, registry, repository).await {
                return response;
            }
            self.db.begin_oci_upload_checked(&begin, statements).await
        } else {
            self.db.begin_oci_upload(&begin).await
        };
        match allocated {
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
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        authority: &str,
        headers: &HeaderMap,
        query: Option<&str>,
        body: Body,
    ) -> Response {
        let authenticated = if self.hybrid_delivery {
            match manifest::authority::HybridManifestAuthority::resolve(
                self, registry, repository, authority, headers,
            )
            .await
            {
                Ok(value) => Some(value),
                Err(response) => return response,
            }
        } else {
            None
        };
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
        let completion_expires_at = claim_now + COMPLETION_LEASE_SECONDS;
        // External physical originals own the initial upload cutoff. Entering
        // completing must never turn a near-expiry upload into fresh permission,
        // including empty blobs that have no private chunk reservation.
        let completion_expires_at = if self.hybrid_delivery {
            match self.db.binding(materialization_revision.binding_id).await {
                Ok(Some(binding)) if binding.kind != "deployment_r2" => {
                    completion_expires_at.min(upload.expires_at)
                }
                Ok(Some(_)) => completion_expires_at,
                _ => return unavailable_response("materialization binding is unavailable", false),
            }
        } else {
            completion_expires_at
        };
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
                lease_expires_at: completion_expires_at,
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
        if claimed.materialization_placement_resource_version != Some(placement.resource_version) {
            return unavailable_response("frozen materialization placement changed", false);
        }
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
                                if staging.as_ref().is_some_and(|(placement, _)| {
                                    claimed.staging_placement_resource_version
                                        != Some(placement.resource_version)
                                }) {
                                    return unavailable_response(
                                        "frozen upload staging placement changed",
                                        false,
                                    );
                                }
                                match self
                                    .materialize_blob(
                                        claimed.registry_id,
                                        &placement,
                                        &revision,
                                        staging.as_ref().map(|(placement, _)| placement),
                                        digest,
                                        claimed.uploaded_size,
                                        &chunks,
                                        None,
                                        Some((
                                            &claimed,
                                            authenticated.as_ref(),
                                            registry,
                                            repository,
                                        )),
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
        let current = match self
            .external_oci_completion_statements(
                &claimed,
                registry,
                repository,
                authenticated.as_ref(),
            )
            .await
        {
            Ok(current) => current,
            Err(response) => return response,
        };
        let completed = self
            .db
            .complete_oci_upload_checked(
                &CompleteOciUpload {
                    upload_id: upload_id.to_string(),
                    writer_id: owner.to_string(),
                    token_id: owner.to_string(),
                    expected_resource_version: claimed.resource_version,
                    digest,
                    byte_size: claimed.uploaded_size,
                    surface_object_id: evidence.surface_object_id,
                    placement_id: evidence.placement_id,
                    now: now(),
                },
                current,
            )
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

    async fn external_oci_completion_statements(
        &self,
        upload: &OciUploadRecord,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        authenticated: Option<&manifest::authority::HybridManifestAuthority>,
    ) -> Result<Vec<crate::backend::CheckedStatement>, Response> {
        if !self.hybrid_delivery {
            return Ok(Vec::new());
        }
        let (placement, revision) = exact_upload_placement(
            &self.db,
            upload.registry_id,
            upload.materialization_placement_id,
            upload.materialization_binding_id,
            upload.materialization_binding_write_revision,
        )
        .await
        .map_err(|_| unavailable_response("OCI completion writer unavailable", false))?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(|_| unavailable_response("OCI completion binding unavailable", false))?
            .ok_or_else(|| unavailable_response("OCI completion binding absent", false))?;
        if binding.is_instance_default && binding.kind == "deployment_r2" {
            return Ok(Vec::new());
        }
        let authenticated = authenticated.ok_or_else(|| {
            unavailable_response("external OCI completion lacks current actor", false)
        })?;
        let authority = self
            .db
            .surface_write_authority(SurfaceTarget::Registry(upload.registry_id))
            .await
            .map_err(|_| unavailable_response("OCI current writer unavailable", false))?
            .ok_or_else(|| unavailable_response("OCI current writer absent", false))?;
        let writer =
            crate::storage_authority::external_object::oci::OciWriterOriginal::from_records(
                &crate::storage_authority::external_object::oci::OciUploadOriginal::from_record(
                    upload,
                )
                .map_err(|_| unavailable_response("OCI original upload invalid", false))?,
                &placement,
                &binding,
                &revision,
                &authority,
            )
            .map_err(|_| unavailable_response("OCI current writer differs", false))?;
        if upload.materialization_placement_resource_version != Some(placement.resource_version) {
            return Err(unavailable_response(
                "OCI completion placement changed",
                false,
            ));
        }
        let mut statements = authenticated.statements(self, registry, repository).await?;
        statements.extend(
            self.db
                .external_oci_writer_statements(upload.registry_id, &placement, &writer)
                .map_err(|_| unavailable_response("OCI completion writer fence invalid", false))?,
        );
        Ok(statements)
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
        managed_effect: Option<&crate::hybrid_ingress::OciDocumentEffect>,
        business: Option<(
            &OciUploadRecord,
            Option<&manifest::authority::HybridManifestAuthority>,
            &RegistryRecord,
            &OciRepositoryRecord,
        )>,
    ) -> Result<(crate::db::OciUploadedObjectEvidence, Option<String>), ()> {
        let path = oci_blob_object_key(digest);
        if self.hybrid_delivery {
            let binding = self
                .db
                .binding(placement.binding_id)
                .await
                .map_err(|_| ())?
                .ok_or(())?;
            let external =
                !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2");
            let (evidence, external_preparation) = if external {
                use crate::storage_authority::external_object::oci::{
                    OciUploadOriginal, OciWriterOriginal,
                    materialization::ExternalOciMaterialization,
                };
                let (upload, authenticated, registry, repository) = business.ok_or(())?;
                let authenticated = authenticated.ok_or(())?;
                let write_authority = self
                    .db
                    .surface_write_authority(SurfaceTarget::Registry(registry_id))
                    .await
                    .map_err(|_| ())?
                    .ok_or(())?;
                let writer = OciWriterOriginal::from_records(
                    &OciUploadOriginal::from_record(upload).map_err(|_| ())?,
                    placement,
                    &binding,
                    revision,
                    &write_authority,
                )
                .map_err(|_| ())?;
                let preparation = ExternalOciMaterialization::new(
                    upload.clone(),
                    authenticated.external_original().map_err(|_| ())?,
                    writer,
                    chunks.to_vec(),
                    digest,
                    authenticated
                        .statements(self, registry, repository)
                        .await
                        .map_err(|_| ())?,
                )
                .map_err(|_| ())?;
                let evidence = self
                    .surface_write
                    .materialize_external_oci(&preparation)
                    .await
                    .map_err(|_| ())?;
                authenticated
                    .recheck(self, registry, repository)
                    .await
                    .map_err(|_| ())?;
                (evidence, Some(preparation))
            } else {
                let composed = if let Some(effect) = managed_effect {
                    self.surface_write
                        .compose_oci_document(
                            placement,
                            revision,
                            staging_placement,
                            &path,
                            chunks,
                            digest,
                            byte_size,
                            effect,
                        )
                        .await
                } else {
                    self.surface_write
                        .compose_oci_blob(
                            placement,
                            revision,
                            staging_placement,
                            &path,
                            chunks,
                            digest,
                            byte_size,
                        )
                        .await
                };
                let evidence = composed.map_err(|_| ())?.ok_or(())?;
                (evidence, None)
            };
            if evidence.size != i64::try_from(byte_size).map_err(|_| ())?
                || evidence.sha256 != *digest.as_bytes()
            {
                return Err(());
            }
            let etag = evidence.strong_etag.ok_or(())?;
            let record = if let Some(preparation) = &external_preparation {
                self.db
                    .record_external_oci_uploaded_object(preparation, &etag)
                    .await
                    .map_err(|_| ())?
            } else {
                self.db
                    .record_oci_uploaded_object(
                        registry_id,
                        placement.id,
                        digest,
                        byte_size,
                        &etag,
                        now(),
                    )
                    .await
                    .map_err(|_| ())?
            };
            return Ok((record, None));
        }
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
        if self.hybrid_delivery {
            let binding = self
                .db
                .binding(placement.binding_id)
                .await
                .map_err(|_| ())?
                .ok_or(())?;
            if !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2") {
                // Missing SQL evidence does not infer provider absence. The
                // actual OCI producer recovers its permanent original next.
                return Ok(None);
            }
            let evidence = fetcher
                .inventory_evidence_bounded(&path, byte_size.max(1))
                .await
                .map_err(|_| ())?;
            let Some(evidence) = evidence else {
                return Ok(None);
            };
            if evidence.size != i64::try_from(byte_size).map_err(|_| ())?
                || evidence.sha256 != *digest.as_bytes()
            {
                return Err(());
            }
            let etag = evidence.strong_etag.ok_or(())?;
            let record = self
                .db
                .record_oci_uploaded_object(
                    registry_id,
                    placement.id,
                    digest,
                    byte_size,
                    &etag,
                    now(),
                )
                .await
                .map_err(|_| ())?;
            return Ok(Some(record));
        }
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

/// Parses one closed initial-upload query without accepting ambiguous direct identity.
///
/// # Errors
/// Returns an error for unknown or repeated fields, malformed selectors, or
/// noncanonical direct operation and size fields.
pub(crate) fn parse_start_query(query: &str) -> Result<StartQuery, &'static str> {
    let mut values = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if !matches!(
            name.as_ref(),
            "mount" | "from" | "digest" | "size" | "aos_operation_id"
        ) || values
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
    let operation_id = values.remove("aos_operation_id");
    if let Some(operation) = &operation_id {
        if !crate::direct_upload::valid_direct_digest(operation)
            || !query
                .split('&')
                .any(|field| field.strip_prefix("aos_operation_id=") == Some(operation.as_str()))
        {
            return Err("direct OCI operation identity must be canonical lowercase hex");
        }
        if let Some(size) = size {
            if !query
                .split('&')
                .any(|field| field.strip_prefix("size=") == Some(size.to_string().as_str()))
            {
                return Err("direct OCI size must be canonical decimal");
            }
        }
    }
    Ok(StartQuery {
        mount,
        from,
        digest,
        size,
        operation_id,
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

fn content_range_admits(headers: &HeaderMap, offset: u64, maximum_bytes: u64) -> bool {
    let Some(value) = headers.get(header::CONTENT_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let value = value.strip_prefix("bytes ").unwrap_or(value);
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let (Ok(start), Ok(end)) = (start.parse::<u64>(), end.parse::<u64>()) else {
        return false;
    };
    !value.contains('+')
        && start == offset
        && end
            .checked_sub(start)
            .and_then(|last| last.checked_add(1))
            .is_some_and(|length| length > 0 && length <= maximum_bytes)
}

fn content_range_matches(headers: &HeaderMap, offset: u64, length: usize) -> bool {
    let range = headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok());
    oci_chunk_range_matches(range, offset, length)
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
    fn declared_chunk_ranges_refuse_before_private_admission() {
        let mut headers = HeaderMap::new();
        assert!(content_range_admits(&headers, 4, 4));
        for value in [
            "bytes 3-6",
            "bytes 4-8",
            "bytes 4-3",
            "bytes 4-7/8",
            "bytes 4-18446744073709551615",
            "bytes +4-7",
            "invalid",
        ] {
            headers.insert(header::CONTENT_RANGE, HeaderValue::from_str(value).unwrap());
            assert!(!content_range_admits(&headers, 4, 4), "{value}");
        }
        headers.insert(header::CONTENT_RANGE, HeaderValue::from_static("bytes 4-7"));
        assert!(content_range_admits(&headers, 4, 4));
        assert!(!content_range_admits(&headers, 4, 0));
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
