//! Worker-local manifest staging with Native-owned quota and graph admission.
//!
//! Preflight reserves the entire bounded byte identity and cleanup address in
//! SQL before the Worker writes R2. Completion carries the original document
//! inbound once; no manifest body is returned across the cloud boundary.

use aos_oci_types::{ManifestReference, Sha256Digest};
use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use uuid::Uuid;

use super::{manifest_invalid, now, unavailable_response, RpcService, MAX_MANIFEST_BYTES};
use crate::db::{
    AppendOciUploadChunk, BeginOciUpload, OciRepositoryRecord, OciUploadChunkRecord,
    OciUploadRecord, RegistryRecord, SurfacePlacementRecord, SurfaceTarget,
};
use crate::hybrid_ingress::{
    HybridOciManifestAdmission, HybridOciManifestPreflight, HYBRID_OCI_MANIFEST_UPLOAD_QUERY,
};
use crate::oci::upload::{exact_upload_placement, UPLOAD_SESSION_SECONDS};

#[cfg(test)]
mod tests;

impl RpcService {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::oci::upload) async fn serve_hybrid_manifest(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: String,
        reference: ManifestReference,
        headers: HeaderMap,
        query: Option<&str>,
        body: Body,
        phase: &str,
    ) -> Response {
        match phase {
            "preflight" => {
                if !matches!(private_manifest_upload(query), Ok(None)) {
                    return manifest_invalid("manifest preflight has a private upload query");
                }
                let request = to_bytes(body, 2048).await.ok().and_then(|bytes| {
                    serde_json::from_slice::<HybridOciManifestPreflight>(&bytes).ok()
                });
                let Some(request) = request else {
                    return manifest_invalid("manifest preflight identity is invalid");
                };
                match self
                    .reserve_hybrid_manifest(registry, repository, &owner, &reference, request)
                    .await
                {
                    Ok(admission) => axum::Json(admission).into_response(),
                    Err(response) => response,
                }
            }
            "complete" => {
                let upload_id = match private_manifest_upload(query) {
                    Ok(Some(upload_id)) => upload_id,
                    _ => return manifest_invalid("manifest completion reservation is invalid"),
                };
                self.put_manifest(
                    registry,
                    repository,
                    owner,
                    reference,
                    headers,
                    body,
                    Some(&upload_id),
                )
                .await
            }
            _ => manifest_invalid("manifest upload phase is invalid"),
        }
    }

    async fn reserve_hybrid_manifest(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: &str,
        reference: &ManifestReference,
        request: HybridOciManifestPreflight,
    ) -> Result<HybridOciManifestAdmission, Response> {
        let size = request.sha256_state.total_bytes;
        if size == 0 || size > MAX_MANIFEST_BYTES as u64 {
            return Err(manifest_invalid("manifest size is outside the 4 MiB limit"));
        }
        let digest = request
            .sha256_state
            .final_digest()
            .map_err(|_| manifest_invalid("manifest digest state is invalid"))?;
        if matches!(reference, ManifestReference::Digest(expected) if *expected != digest) {
            return Err(crate::oci::distribution_error_response(
                StatusCode::BAD_REQUEST,
                crate::oci::DistributionErrorCode::DigestInvalid,
                "manifest digest reference does not match the request body",
                None,
                false,
            ));
        }
        let placement = self
            .effective_surface_writer(SurfaceTarget::Registry(registry.id))
            .await
            .map_err(|_| unavailable_response("registry writer is unavailable", false))?;
        let revision = self
            .db
            .placement_publication_write_revision(placement.id)
            .await
            .map_err(|_| unavailable_response("registry write revision is unavailable", false))?
            .ok_or_else(|| unavailable_response("registry writer is not authorized", false))?;
        let binding = self
            .db
            .binding(placement.binding_id)
            .await
            .map_err(|_| unavailable_response("registry binding is unavailable", false))?
            .ok_or_else(|| unavailable_response("registry binding is unavailable", false))?;
        if !binding.is_instance_default || binding.kind != "deployment_r2" {
            return Err(unavailable_response(
                "hybrid manifest writer is unsupported",
                false,
            ));
        }

        let current = now();
        let upload = self
            .db
            .begin_oci_upload(&BeginOciUpload {
                registry_id: registry.id,
                repository_id: repository.id,
                publication_id: None,
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                idempotency_key: format!("manifest-hybrid-{}", Uuid::new_v4().simple()),
                expected_digest: Some(digest),
                expected_size: Some(size),
                maximum_size: MAX_MANIFEST_BYTES as u64,
                now: current,
                expires_at: current + UPLOAD_SESSION_SECONDS,
            })
            .await
            .map_err(|_| unavailable_response("manifest quota could not be reserved", false))?;
        let staging_object_key = format!(
            "oci/uploads/{}/chunks/0-{}-{}",
            upload.id,
            Uuid::new_v4().simple(),
            digest.encoded()
        );
        // Reserve bytes and the exact cleanup address before any provider IO.
        // This is not canonical object evidence: completion must independently
        // verify R2 and the closed graph before publishing anything.
        let reserved = self
            .db
            .append_oci_upload_chunk(&AppendOciUploadChunk {
                upload_id: upload.id.clone(),
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                expected_resource_version: upload.resource_version,
                staging_placement_id: placement.id,
                staging_placement_resource_version: placement.resource_version,
                staging_binding_id: revision.binding_id,
                staging_binding_write_revision: revision.revision,
                chunk: OciUploadChunkRecord {
                    ordinal: 0,
                    byte_offset: 0,
                    byte_size: size,
                    digest,
                    staging_object_key: staging_object_key.clone(),
                    created_at: current,
                },
                next_sha256: request.sha256_state,
                now: current,
            })
            .await;
        if reserved.is_err() {
            // A lost commit acknowledgement may leave the reservation live.
            // No Worker PUT has been admitted yet; expiry recovers that state.
            let _ = self
                .db
                .cancel_oci_upload(&upload.id, owner, owner, upload.resource_version, now())
                .await;
            return Err(unavailable_response(
                "manifest staging reservation failed",
                false,
            ));
        }
        Ok(HybridOciManifestAdmission {
            upload_id: upload.id,
            placement_prefix: placement.prefix,
            staging_object_key,
            byte_size: size,
            sha256: digest.encoded().to_string(),
        })
    }

    pub(super) async fn verified_hybrid_manifest_staging(
        &self,
        repository: &OciRepositoryRecord,
        owner: &str,
        upload_id: &str,
        digest: Sha256Digest,
        size: usize,
    ) -> Result<
        (
            SurfacePlacementRecord,
            OciUploadRecord,
            Vec<OciUploadChunkRecord>,
        ),
        Response,
    > {
        let upload = self
            .db
            .hybrid_oci_manifest_upload(upload_id, owner, now())
            .await
            .map_err(|_| unavailable_response("manifest reservation is unavailable", false))?
            .ok_or_else(|| manifest_invalid("manifest reservation is absent or expired"))?;
        if upload.registry_id != repository.registry_id
            || upload.repository_id != repository.id
            || upload.expected_digest != Some(digest)
            || upload.expected_size != Some(size as u64)
            || upload.uploaded_size != size as u64
            || upload.sha256.final_digest().ok() != Some(digest)
        {
            return Err(manifest_invalid(
                "manifest body differs from its reservation",
            ));
        }
        let chunks =
            self.db.oci_upload_chunks(upload_id).await.map_err(|_| {
                unavailable_response("manifest staging identity is unavailable", false)
            })?;
        if chunks.len() != 1 || chunks[0].digest != digest || chunks[0].byte_size != size as u64 {
            return Err(manifest_invalid("manifest staging identity is invalid"));
        }
        let (placement, _) = exact_upload_placement(
            &self.db,
            upload.registry_id,
            upload.staging_placement_id,
            upload.staging_binding_id,
            upload.staging_binding_write_revision,
        )
        .await
        .map_err(|_| unavailable_response("frozen manifest writer is unavailable", false))?;
        if upload.staging_placement_resource_version != Some(placement.resource_version) {
            return Err(unavailable_response(
                "manifest staging placement changed",
                false,
            ));
        }
        let fetcher = self
            .surface
            .placement_fetcher(&placement)
            .await
            .map_err(|_| unavailable_response("manifest staging object is unavailable", false))?;
        let evidence = fetcher
            .inventory_evidence_bounded(&chunks[0].staging_object_key, size as u64)
            .await
            .map_err(|_| unavailable_response("manifest staging verification failed", false))?
            .ok_or_else(|| unavailable_response("manifest staging object is absent", false))?;
        if evidence.size != size as i64 || evidence.sha256 != *digest.as_bytes() {
            return Err(unavailable_response(
                "manifest staging object differs from its body",
                false,
            ));
        }
        Ok((placement, upload, chunks))
    }
}

fn private_manifest_upload(query: Option<&str>) -> Result<Option<String>, Response> {
    let values: Vec<(String, String)> = serde_urlencoded::from_str(query.unwrap_or_default())
        .map_err(|_| manifest_invalid("manifest query is invalid"))?;
    let mut ids = values
        .into_iter()
        .filter(|(key, _)| key == HYBRID_OCI_MANIFEST_UPLOAD_QUERY)
        .map(|(_, value)| value);
    let Some(id) = ids.next() else {
        return Ok(None);
    };
    if ids.next().is_some()
        || id.len() != 32
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(manifest_invalid("manifest upload identity is invalid"));
    }
    Ok(Some(id))
}
