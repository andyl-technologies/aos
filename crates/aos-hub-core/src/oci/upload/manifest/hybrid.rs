//! Worker-local manifest staging with Native-owned quota and graph admission.
//!
//! Preflight reserves the entire bounded byte identity and cleanup address in
//! SQL before the Worker writes R2. Completion carries an empty closed control;
//! independently authenticated stored-read metadata supplies the graph. Original
//! manifest and config bytes remain storage-local.

use crate::oci_projection::manifest_original_digest;
use aos_oci_types::{ManifestReference, MediaType, Sha256Digest};
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
    HybridOciManifestAdmission, HybridOciManifestCompletion, HybridOciManifestPreflight,
    HYBRID_OCI_MANIFEST_UPLOAD_QUERY,
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
        authority: &str,
        reference: ManifestReference,
        headers: HeaderMap,
        query: Option<&str>,
        body: Body,
        phase: &str,
    ) -> Response {
        let authenticated = match super::authority::HybridManifestAuthority::resolve(
            self, registry, repository, authority, &headers,
        )
        .await
        {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
        match phase {
            "authorize" => {
                if !matches!(private_manifest_upload(query), Ok(None)) {
                    return manifest_invalid("manifest authorization has a private upload query");
                }
                // No body or SQL reservation is needed to check the original
                // current actor before the Worker consumes its raw document.
                if let Err(response) = authenticated.recheck(self, registry, repository).await {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
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
                    Ok(admission) => {
                        if let Err(response) =
                            authenticated.recheck(self, registry, repository).await
                        {
                            // An admitted SQL reservation remains retained for
                            // exact cleanup; no Worker PUT is granted here.
                            return response;
                        }
                        axum::Json(admission).into_response()
                    }
                    Err(response) => response,
                }
            }
            "complete" => {
                let upload_id = match private_manifest_upload(query) {
                    Ok(Some(upload_id)) => upload_id,
                    _ => return manifest_invalid("manifest completion reservation is invalid"),
                };
                let completion = to_bytes(body, 128).await.ok().and_then(|bytes| {
                    serde_json::from_slice::<HybridOciManifestCompletion>(&bytes).ok()
                });
                if completion.is_none() {
                    return manifest_invalid(
                        "manifest completion requires closed metadata, not original bytes",
                    );
                }
                self.complete_hybrid_manifest(
                    registry,
                    repository,
                    owner,
                    reference,
                    headers,
                    &upload_id,
                    authenticated,
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
        if !request.media_type.is_image_manifest() && !request.media_type.is_image_index() {
            return Err(manifest_invalid(
                "manifest preflight media type is unsupported",
            ));
        }
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

        let authority = self
            .db
            .surface_write_authority(SurfaceTarget::Registry(registry.id))
            .await
            .map_err(|_| unavailable_response("manifest write authority is unavailable", false))?
            .ok_or_else(|| unavailable_response("manifest write authority is absent", false))?;
        let original_digest = manifest_original_digest(
            registry.id,
            repository.id,
            owner,
            reference,
            request.media_type,
            &placement,
            &binding,
            revision.revision,
            &authority,
        )
        .map_err(|_| unavailable_response("manifest original could not be retained", false))?;
        let current = now();
        let upload = self
            .db
            .begin_oci_upload(&BeginOciUpload {
                registry_id: registry.id,
                repository_id: repository.id,
                publication_id: None,
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                idempotency_key: format!(
                    "manifest-hybrid-{original_digest}-{}",
                    Uuid::new_v4().simple()
                ),
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
            original_digest,
            upload_id: upload.id,
            placement_prefix: placement.prefix,
            staging_object_key,
            byte_size: size,
            sha256: digest.encoded().to_string(),
        })
    }

    async fn load_hybrid_manifest_staging(
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
        Ok((placement, upload, chunks))
    }

    #[cfg(test)]
    async fn verified_hybrid_manifest_staging(
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
        let (placement, upload, chunks) = self
            .load_hybrid_manifest_staging(repository, owner, upload_id, digest, size)
            .await?;
        let fetcher = self
            .surface
            .placement_fetcher(&placement)
            .await
            .map_err(|_| unavailable_response("manifest storage unavailable", false))?;
        let evidence = fetcher
            .inventory_evidence_bounded(&chunks[0].staging_object_key, size as u64)
            .await
            .map_err(|_| unavailable_response("manifest storage evidence unavailable", false))?
            .ok_or_else(|| unavailable_response("manifest storage absent", false))?;
        if evidence.size != size as i64 || evidence.sha256 != *digest.as_bytes() {
            return Err(manifest_invalid(
                "manifest staging differs from its original",
            ));
        }
        Ok((placement, upload, chunks))
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_hybrid_manifest(
        &self,
        registry: &RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: String,
        reference: ManifestReference,
        headers: HeaderMap,
        upload_id: &str,
        authority: super::authority::HybridManifestAuthority,
    ) -> Response {
        let media_type = match super::manifest_content_type(&headers) {
            Ok(media_type) => media_type,
            Err(message) => return manifest_invalid(message),
        };
        let upload = match self
            .db
            .hybrid_oci_manifest_upload(upload_id, &owner, now())
            .await
        {
            Ok(Some(upload)) => upload,
            _ => return manifest_invalid("manifest reservation is absent or expired"),
        };
        let (Some(digest), Some(size)) = (upload.expected_digest, upload.expected_size) else {
            return manifest_invalid("manifest reservation has no exact byte identity");
        };
        let (placement, upload, chunks) = match self
            .load_hybrid_manifest_staging(repository, &owner, upload_id, digest, size as usize)
            .await
        {
            Ok(staged) => staged,
            Err(response) => return response,
        };
        let binding = match self.db.binding(placement.binding_id).await {
            Ok(Some(binding)) => binding,
            _ => return unavailable_response("manifest binding is unavailable", false),
        };
        let current_authority = match self
            .db
            .surface_write_authority(SurfaceTarget::Registry(registry.id))
            .await
        {
            Ok(Some(authority)) => authority,
            _ => return unavailable_response("manifest write authority is unavailable", false),
        };
        let original_digest = match manifest_original_digest(
            registry.id,
            repository.id,
            &owner,
            &reference,
            media_type,
            &placement,
            &binding,
            upload.staging_binding_write_revision.unwrap_or(0),
            &current_authority,
        ) {
            Ok(digest) => digest,
            Err(_) => return unavailable_response("manifest original is invalid", false),
        };
        if self
            .db
            .hybrid_oci_manifest_original_digest(upload_id, &owner)
            .await
            .ok()
            .flatten()
            .as_deref()
            != Some(original_digest.as_str())
        {
            return manifest_invalid(
                "manifest target, actor, reference or writer differs from its original",
            );
        }
        let admission = HybridOciManifestAdmission {
            original_digest,
            upload_id: upload.id.clone(),
            placement_prefix: placement.prefix.clone(),
            staging_object_key: chunks[0].staging_object_key.clone(),
            byte_size: size,
            sha256: digest.encoded().to_string(),
        };
        let descriptor = aos_oci_types::Descriptor {
            media_type,
            digest,
            size,
            urls: Vec::new(),
            annotations: aos_oci_types::Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        };
        let fetcher = match self.surface.placement_fetcher(&placement).await {
            Ok(fetcher) => fetcher,
            Err(_) => {
                return unavailable_response("manifest projection reader is unavailable", false)
            }
        };
        let projection_path = if upload.state == "complete" {
            if upload.final_digest != Some(digest)
                || upload.materialization_placement_id != Some(placement.id)
                || upload.materialization_placement_resource_version
                    != Some(placement.resource_version)
                || upload.materialization_binding_id != Some(placement.binding_id)
                || upload.materialization_binding_write_revision
                    != upload.staging_binding_write_revision
            {
                return manifest_invalid(
                    "completed manifest differs from its original materialization",
                );
            }
            crate::db::oci_blob_object_key(digest)
        } else {
            admission.staging_object_key.clone()
        };
        let proof = match fetcher
            .oci_document_projection(&projection_path, &descriptor, Some(&admission))
            .await
        {
            Ok(Some(document)) => document,
            _ => {
                return unavailable_response(
                    "exact stored manifest projection could not be verified",
                    false,
                )
            }
        };
        let document = match proof.check(&descriptor, now()) {
            Ok(document) => document.clone(),
            Err(_) => return unavailable_response("stored manifest proof expired", false),
        };
        if document.validate(media_type).is_err() {
            return manifest_invalid("stored manifest projection is invalid");
        }
        let root = super::document_descriptor(media_type, digest, size, &document);
        self.finish_manifest_graph(
            registry,
            repository,
            owner,
            reference,
            root,
            document,
            placement,
            upload,
            chunks,
            vec![proof],
            Some(authority),
        )
        .await
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
