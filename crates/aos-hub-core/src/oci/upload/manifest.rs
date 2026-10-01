//! Exact-byte manifest/index admission for the Distribution write plane.
//!
//! Manifest bytes are hashed and retained without reserialization. Parsed OCI
//! documents are bounded projections used only to validate the closed graph;
//! every referenced object must already be linked to this repository and have
//! exact evidence on the selected writer placement.

mod authority;
mod hybrid;

use std::collections::BTreeMap;
use std::time::Duration;

use aos_oci_types::{
    Annotations, Descriptor, ImageConfig, ImageManifest, ManifestReference, MediaType, Platform,
    Sha256Digest,
};
use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use uuid::Uuid;

use super::{
    add_distribution_version, cleanup_upload_staging, completed_upload_response,
    distribution_error_response, exact_upload_placement, now, unavailable_response,
    DistributionErrorCode, OciRepositoryRecord, RpcService, SurfaceTarget,
    COMPLETION_LEASE_SECONDS, UPLOAD_SESSION_SECONDS,
};
use crate::db::{
    oci_blob_object_key, AppendOciUploadChunk, BeginOciUpload, ClaimOciUpload, CompleteOciUpload,
    IndexOciRepositoryCatalog, OciBlobClaimOutcome, OciCatalogObject, OciCatalogProjection,
    OciImageConfigProjection, OciLayerProjection, OciUploadChunkRecord, OciUploadCleanupRecord,
    OciUploadRecord,
};

const MAX_MANIFEST_BYTES: usize = crate::hybrid_ingress::MAX_HYBRID_OCI_MANIFEST_BYTES;
const DIGEST_WAIT_BUDGET: Duration = Duration::from_secs(10);
const DIGEST_POLL_MAX_DELAY: Duration = Duration::from_millis(100);

use crate::oci_projection::OciDocumentProjection as ParsedDocument;

impl RpcService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn put_manifest(
        &self,
        registry: &crate::db::RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: String,
        reference: ManifestReference,
        headers: HeaderMap,
        body: Body,
    ) -> Response {
        let media_type = match manifest_content_type(&headers) {
            Ok(media_type) => media_type,
            Err(message) => return manifest_invalid(message),
        };
        let bytes = match to_bytes(body, MAX_MANIFEST_BYTES).await {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => return manifest_invalid("manifest body must not be empty"),
            Err(_) => {
                return distribution_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    DistributionErrorCode::SizeInvalid,
                    "manifest body exceeds the 4 MiB limit",
                    None,
                    false,
                );
            }
        };
        let document = match parse_document(media_type, &bytes) {
            Ok(document) => document,
            Err(message) => return manifest_invalid(message),
        };
        let digest = Sha256Digest::digest(&bytes);
        if matches!(reference, ManifestReference::Digest(expected) if expected != digest) {
            return distribution_error_response(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::DigestInvalid,
                "manifest digest reference does not match the request body",
                None,
                false,
            );
        }
        let root = document_descriptor(media_type, digest, bytes.len() as u64, &document);
        let placement = match self
            .effective_surface_writer(SurfaceTarget::Registry(registry.id))
            .await
        {
            Ok(placement) => placement,
            Err(_) => return unavailable_response("registry writer is unavailable", false),
        };
        let (upload, chunks) = match self
            .stage_manifest_bytes(
                registry.id,
                repository.id,
                &owner,
                &placement,
                digest,
                &bytes,
            )
            .await
        {
            Ok(staged) => staged,
            Err(response) => return response,
        };
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
            Vec::new(),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_manifest_graph(
        &self,
        registry: &crate::db::RegistryRecord,
        repository: &OciRepositoryRecord,
        owner: String,
        reference: ManifestReference,
        root: Descriptor,
        document: ParsedDocument,
        placement: crate::db::SurfacePlacementRecord,
        upload: OciUploadRecord,
        chunks: Vec<OciUploadChunkRecord>,
        mut proofs: Vec<crate::oci_projection::guard::VerifiedOciProjection>,
        authority: Option<authority::HybridManifestAuthority>,
    ) -> Response {
        let digest = root.digest;
        let (root_digest, objects) = match self
            .manifest_graph(repository, &placement, root.clone(), document, &mut proofs)
            .await
        {
            Ok(graph) => graph,
            Err(response) => {
                self.cancel_staged_manifest(upload, chunks).await;
                return response;
            }
        };
        if let Some(authority) = &authority {
            if let Err(response) = authority.recheck(self, registry, repository).await {
                return response;
            }
        }
        // Exact terminal recovery reads the canonical stored original and must
        // not repeat materialization or transfer its quota a second time.
        if upload.state != "complete" {
            if let Err(response) = self
                .complete_staged_manifest(&owner, &placement, digest, upload, &chunks)
                .await
            {
                return response;
            }
        };
        if self.hybrid_delivery {
            let Some(original) = proofs.iter().find_map(|proof| proof.admission().cloned()) else {
                return unavailable_response("manifest has no retained root original", false);
            };
            let fetcher = match self.surface.placement_fetcher(&placement).await {
                Ok(fetcher) => fetcher,
                Err(_) => {
                    return unavailable_response("final manifest reader is unavailable", false)
                }
            };
            let final_proof = match fetcher
                .oci_document_projection(&oci_blob_object_key(digest), &root, Some(&original))
                .await
            {
                Ok(Some(proof)) => proof,
                _ => {
                    return unavailable_response(
                        "canonical manifest readback is unavailable or unsettled",
                        false,
                    )
                }
            };
            // A positive staging read cannot publish a later materialization.
            // Replace it with the independently observed canonical incarnation.
            proofs.retain(|proof| proof.admission().is_none());
            proofs.push(final_proof);
        }
        let tag = match &reference {
            ManifestReference::Tag(tag) => Some(tag.clone()),
            ManifestReference::Digest(_) => None,
        };
        let catalog = IndexOciRepositoryCatalog {
            registry_id: registry.id,
            placement_id: placement.id,
            repository: repository.name.clone(),
            objects,
            root_digest,
            tag,
            source_kind: "manual".to_string(),
            actor_id: owner,
            observed_at: crate::clock::now_unix_secs(),
        };
        let mut admitted = false;
        for attempt in 0..20 {
            let indexed = if self.hybrid_delivery {
                {
                    let Some(authority) = &authority else {
                        return unavailable_response(
                            "manifest completion has no live authority",
                            false,
                        );
                    };
                    let statements = match authority.statements(self, registry, repository).await {
                        Ok(statements) => statements,
                        Err(response) => return response,
                    };
                    self.db
                        .index_oci_repository_catalog_guarded(
                            &catalog,
                            &proofs,
                            statements,
                            authority.expires_at(),
                        )
                        .await
                }
            } else {
                self.db.index_oci_repository_catalog(&catalog).await
            };
            match indexed {
                Ok(_) => {
                    admitted = true;
                    break;
                }
                Err(_) => {}
            }
            if attempt < 19 {
                crate::clock::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        if !admitted {
            return distribution_error_response(
                StatusCode::BAD_REQUEST,
                DistributionErrorCode::ManifestBlobUnknown,
                "manifest graph is incomplete or changed",
                None,
                false,
            );
        }
        if let Some(authority) = &authority {
            if let Err(response) = authority.recheck(self, registry, repository).await {
                // The SQL outcome may be committed. A late reply never claims
                // rollback; exact original completion can resolve it later.
                return response;
            }
        }
        if proofs.iter().any(|proof| now() >= proof.deadline()) {
            return unavailable_response(
                "manifest acknowledgement needs exact original requery",
                false,
            );
        }
        manifest_created_response(repository, &reference, digest)
    }

    async fn stage_manifest_bytes(
        &self,
        registry_id: i64,
        repository_id: i64,
        owner: &str,
        placement: &crate::db::SurfacePlacementRecord,
        digest: Sha256Digest,
        bytes: &[u8],
    ) -> Result<(OciUploadRecord, Vec<OciUploadChunkRecord>), Response> {
        let revision = self
            .db
            .placement_publication_write_revision(placement.id)
            .await
            .map_err(|_| unavailable_response("registry write revision is unavailable", false))?
            .ok_or_else(|| unavailable_response("registry writer is not authorized", false))?;
        let current = now();
        let upload = self
            .db
            .begin_oci_upload(&BeginOciUpload {
                registry_id,
                repository_id,
                publication_id: None,
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                idempotency_key: format!("manifest-{}", Uuid::new_v4().simple()),
                expected_digest: Some(digest),
                expected_size: Some(bytes.len() as u64),
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
        let writer = match self
            .surface_write
            .placement_writer_at_revision(placement, &revision)
            .await
        {
            Ok(writer) => writer,
            Err(_) => {
                let _ = self
                    .db
                    .cancel_oci_upload(&upload.id, owner, owner, upload.resource_version, now())
                    .await;
                return Err(unavailable_response(
                    "registry writer is unavailable",
                    false,
                ));
            }
        };
        if writer.write(&staging_object_key, bytes).await.is_err() {
            let _ = self
                .db
                .cancel_oci_upload(&upload.id, owner, owner, upload.resource_version, now())
                .await;
            return Err(unavailable_response(
                "manifest staging bytes could not be stored",
                false,
            ));
        }

        let mut next_sha256 = upload.sha256.clone();
        if next_sha256.update(bytes).is_err() {
            let _ = writer.delete(&staging_object_key).await;
            let _ = self
                .db
                .cancel_oci_upload(&upload.id, owner, owner, upload.resource_version, now())
                .await;
            return Err(manifest_invalid("manifest digest state is invalid"));
        }
        let chunk = OciUploadChunkRecord {
            ordinal: 0,
            byte_offset: 0,
            byte_size: bytes.len() as u64,
            digest,
            staging_object_key: staging_object_key.clone(),
            created_at: now(),
        };
        let appended = self
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
                chunk: chunk.clone(),
                next_sha256,
                now: now(),
            })
            .await;
        match appended {
            Ok(appended) => Ok((appended, vec![chunk])),
            Err(_) => {
                // Only remove an attempt-unique staging key after proving the
                // ambiguous append did not durably reference it.
                if matches!(
                    self.db
                        .oci_upload_references_staging_key(&upload.id, &staging_object_key)
                        .await,
                    Ok(false)
                ) {
                    let _ = writer.delete(&staging_object_key).await;
                    let _ = self
                        .db
                        .cancel_oci_upload(&upload.id, owner, owner, upload.resource_version, now())
                        .await;
                }
                Err(unavailable_response(
                    "manifest staging state could not be committed",
                    false,
                ))
            }
        }
    }

    async fn cancel_staged_manifest(
        &self,
        upload: OciUploadRecord,
        chunks: Vec<OciUploadChunkRecord>,
    ) {
        let cancelled = self
            .db
            .cancel_oci_upload(
                &upload.id,
                &upload.writer_id,
                &upload.token_id,
                upload.resource_version,
                now(),
            )
            .await;
        let Ok(cancelled) = cancelled else {
            return;
        };
        let cleanup = OciUploadCleanupRecord {
            upload: cancelled,
            chunks,
        };
        if let Err(error) =
            cleanup_upload_staging(&self.db, self.surface_write.as_ref(), &cleanup, now()).await
        {
            tracing::warn!(
                upload_id = %cleanup.upload.id,
                %error,
                "rejected OCI manifest left staging cleanup pending"
            );
        }
    }

    async fn complete_staged_manifest(
        &self,
        owner: &str,
        placement: &crate::db::SurfacePlacementRecord,
        digest: Sha256Digest,
        upload: OciUploadRecord,
        chunks: &[OciUploadChunkRecord],
    ) -> Result<(), Response> {
        let claim_now = now();
        let revision = self
            .db
            .placement_publication_write_revision(placement.id)
            .await
            .map_err(|_| unavailable_response("registry write revision is unavailable", false))?
            .ok_or_else(|| unavailable_response("registry writer is not authorized", false))?;
        let mut claim = ClaimOciUpload {
            upload_id: upload.id.clone(),
            writer_id: owner.to_string(),
            token_id: owner.to_string(),
            expected_resource_version: upload.resource_version,
            materialization_placement_id: placement.id,
            materialization_placement_resource_version: placement.resource_version,
            materialization_binding_id: revision.binding_id,
            materialization_binding_write_revision: revision.revision,
            digest,
            now: claim_now,
            lease_expires_at: claim_now + COMPLETION_LEASE_SECONDS,
        };
        let mut outcome = self
            .db
            .claim_oci_upload(&claim)
            .await
            .map_err(|_| unavailable_response("manifest digest could not be claimed", false))?;
        let wait_started = crate::clock::Instant::now();
        let mut poll_delay = Duration::from_millis(5);

        // Remote materialization can outlast one second. Back off read-only
        // waiters within a request budget; the attempt ceiling also bounds
        // retries if a Worker host's wall clock moves backwards.
        for _ in 0..200 {
            if outcome != OciBlobClaimOutcome::InProgress {
                break;
            }
            let Some(remaining) = DIGEST_WAIT_BUDGET.checked_sub(wait_started.elapsed()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }

            crate::clock::sleep(poll_delay.min(remaining)).await;
            poll_delay = (poll_delay * 2).min(DIGEST_POLL_MAX_DELAY);
            claim.now = now();
            claim.lease_expires_at = claim.now + COMPLETION_LEASE_SECONDS;
            // Preserve the prior InProgress outcome across an ambiguous
            // database-contention error. An error never authorizes progress;
            // only an exact terminal outcome can leave this bounded window.
            if let Ok(next) = self.db.claim_oci_upload(&claim).await {
                outcome = next;
            }
        }
        if outcome == OciBlobClaimOutcome::InProgress {
            self.cancel_staged_manifest(upload, chunks.to_vec()).await;
            return Err(unavailable_response(
                "manifest digest finalization did not converge",
                false,
            ));
        }
        let claimed = self
            .db
            .oci_upload(&upload.id, owner, owner, now())
            .await
            .map_err(|_| unavailable_response("manifest upload state is unavailable", false))?
            .filter(|upload| upload.state == "completing")
            .ok_or_else(|| unavailable_response("manifest upload state changed", false))?;
        let (materialization, materialization_revision) = exact_upload_placement(
            &self.db,
            claimed.registry_id,
            claimed.materialization_placement_id,
            claimed.materialization_binding_id,
            claimed.materialization_binding_write_revision,
        )
        .await
        .map_err(|_| unavailable_response("frozen manifest writer is unavailable", false))?;

        let (evidence, provider_upload_id) = match outcome {
            OciBlobClaimOutcome::AlreadyPresent => {
                let evidence = self
                    .db
                    .oci_blob_placement_evidence(
                        claimed.registry_id,
                        digest,
                        Some(materialization.id),
                    )
                    .await
                    .map_err(|_| {
                        unavailable_response("manifest placement evidence is unavailable", false)
                    })?
                    .ok_or_else(|| {
                        unavailable_response("manifest is absent from the writer placement", false)
                    })?;
                (evidence, None)
            }
            OciBlobClaimOutcome::Claimed => {
                match self
                    .probe_materialized_blob(
                        claimed.registry_id,
                        &materialization,
                        digest,
                        claimed.uploaded_size,
                    )
                    .await
                {
                    Ok(Some(evidence)) => (evidence, None),
                    Ok(None) => {
                        let (staging, _) = exact_upload_placement(
                            &self.db,
                            claimed.registry_id,
                            claimed.staging_placement_id,
                            claimed.staging_binding_id,
                            claimed.staging_binding_write_revision,
                        )
                        .await
                        .map_err(|_| {
                            unavailable_response("frozen manifest staging is unavailable", false)
                        })?;
                        self.materialize_blob(
                            claimed.registry_id,
                            &materialization,
                            &materialization_revision,
                            Some(&staging),
                            digest,
                            claimed.uploaded_size,
                            chunks,
                        )
                        .await
                        .map_err(|_| {
                            unavailable_response("manifest bytes could not be materialized", false)
                        })?
                    }
                    Err(()) => {
                        // Never delete a digest-addressed path on failed
                        // readback: it may be a shared CAS object written by a
                        // prior publication whose catalog evidence was lost.
                        return Err(unavailable_response(
                            "existing manifest bytes failed verification",
                            false,
                        ));
                    }
                }
            }
            OciBlobClaimOutcome::InProgress => {
                return Err(unavailable_response(
                    "manifest digest ownership changed",
                    false,
                ));
            }
        };
        let completed = self
            .db
            .complete_oci_upload(&CompleteOciUpload {
                upload_id: claimed.id.clone(),
                writer_id: owner.to_string(),
                token_id: owner.to_string(),
                expected_resource_version: claimed.resource_version,
                digest,
                byte_size: claimed.uploaded_size,
                surface_object_id: evidence.surface_object_id,
                placement_id: evidence.placement_id,
                now: now(),
            })
            .await
            .map_err(|_| {
                unavailable_response("manifest completion could not be committed", false)
            })?;
        if let Some(provider_upload_id) = provider_upload_id {
            if let Ok(writer) = self
                .surface_write
                .placement_writer_at_revision(&materialization, &materialization_revision)
                .await
            {
                let _ = writer
                    .settle_multipart(&oci_blob_object_key(digest), &provider_upload_id)
                    .await;
            }
        }
        let cleanup = OciUploadCleanupRecord {
            upload: completed,
            chunks: chunks.to_vec(),
        };
        if let Err(error) =
            cleanup_upload_staging(&self.db, self.surface_write.as_ref(), &cleanup, now()).await
        {
            tracing::warn!(
                upload_id = %cleanup.upload.id,
                %error,
                "completed OCI manifest left staging cleanup pending"
            );
        }
        Ok(())
    }

    pub(super) async fn delete_manifest(
        &self,
        repository: &OciRepositoryRecord,
        reference: ManifestReference,
        _owner: String,
    ) -> Response {
        let ManifestReference::Digest(digest) = reference else {
            return manifest_invalid("manifest deletion requires a digest reference");
        };
        match self
            .db
            .delete_oci_repository_manifest(repository.id, digest, crate::clock::now_unix_secs())
            .await
        {
            Ok(()) => {
                let mut response = StatusCode::ACCEPTED.into_response();
                add_distribution_version(&mut response);
                response
            }
            Err(_) => distribution_error_response(
                StatusCode::CONFLICT,
                DistributionErrorCode::Denied,
                "manifest is tagged, signed, absent, or changed",
                None,
                false,
            ),
        }
    }

    async fn manifest_graph(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        root: Descriptor,
        document: ParsedDocument,
        proofs: &mut Vec<crate::oci_projection::guard::VerifiedOciProjection>,
    ) -> Result<(Sha256Digest, Vec<OciCatalogObject>), Response> {
        let mut objects = BTreeMap::new();
        let root_digest;
        match document {
            ParsedDocument::Manifest(manifest) => {
                root_digest = root.digest;
                if let Some(subject) = &manifest.subject {
                    let subject_graph = self
                        .db
                        .oci_repository_closed_graph(repository.id, std::slice::from_ref(subject))
                        .await
                        .map_err(|_| manifest_blob_unknown())?;
                    self.require_graph_placement(repository, placement, &subject_graph)
                        .await?;
                    merge_objects(&mut objects, subject_graph)?;
                }
                for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
                    self.require_raw_dependency(repository, placement, descriptor)
                        .await?;
                    insert_object(
                        &mut objects,
                        OciCatalogObject {
                            descriptor: descriptor.clone(),
                            projection: None,
                        },
                    )?;
                }
                let (platform, image_config) = if manifest.artifact_type.is_none() {
                    let (platform, projection) = self
                        .read_image_config_projection(repository, placement, &manifest, proofs)
                        .await?;
                    (Some(platform), Some(projection))
                } else {
                    (None, None)
                };
                insert_object(
                    &mut objects,
                    OciCatalogObject {
                        descriptor: root,
                        projection: Some(OciCatalogProjection::Manifest {
                            document: manifest,
                            platform,
                            image_config,
                        }),
                    },
                )?;
            }
            ParsedDocument::Config(_) => {
                return Err(manifest_invalid("image config is not a manifest root"))
            }
            ParsedDocument::Index(index) => {
                root_digest = root.digest;
                let children = self
                    .db
                    .oci_repository_closed_graph(repository.id, &index.manifests)
                    .await
                    .map_err(|_| manifest_blob_unknown())?;
                self.require_graph_placement(repository, placement, &children)
                    .await?;
                for descriptor in &index.manifests {
                    let Some(OciCatalogObject {
                        projection: Some(OciCatalogProjection::Manifest { platform, .. }),
                        ..
                    }) = children
                        .iter()
                        .find(|object| object.descriptor.digest == descriptor.digest)
                    else {
                        continue;
                    };
                    if descriptor.platform.as_ref() != platform.as_ref() {
                        return Err(manifest_invalid(
                            "index platform conflicts with the exact image config",
                        ));
                    }
                }
                merge_objects(&mut objects, children)?;
                insert_object(
                    &mut objects,
                    OciCatalogObject {
                        descriptor: root,
                        projection: Some(OciCatalogProjection::Index(index)),
                    },
                )?;
            }
        }
        Ok((root_digest, objects.into_values().collect()))
    }

    async fn require_raw_dependency(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        descriptor: &Descriptor,
    ) -> Result<(), Response> {
        let blob = self
            .db
            .oci_blob_for_repository(repository.id, descriptor.digest)
            .await
            .map_err(|_| unavailable_response("blob catalog is unavailable", false))?
            .ok_or_else(manifest_blob_unknown)?;
        if blob.byte_size != descriptor.size
            || !matches!(blob.media_type, MediaType::OctetStream)
                && blob.media_type != descriptor.media_type
        {
            return Err(manifest_blob_unknown());
        }
        if !self
            .repository_object_has_placement(repository, placement, descriptor)
            .await?
        {
            return Err(manifest_blob_unknown());
        }
        Ok(())
    }

    async fn require_graph_placement(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        objects: &[OciCatalogObject],
    ) -> Result<(), Response> {
        for object in objects {
            if !self
                .repository_object_has_placement(repository, placement, &object.descriptor)
                .await?
            {
                return Err(manifest_blob_unknown());
            }
        }
        Ok(())
    }

    async fn repository_object_has_placement(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        descriptor: &Descriptor,
    ) -> Result<bool, Response> {
        let exact = self
            .db
            .oci_repository_object_has_placement(
                repository.id,
                descriptor.digest,
                placement.id,
                descriptor.size,
                descriptor.media_type,
            )
            .await
            .map_err(|_| {
                unavailable_response("manifest graph placement evidence is unavailable", false)
            })?;
        if exact || descriptor.media_type == MediaType::OctetStream {
            return Ok(exact);
        }
        self.db
            .oci_repository_object_has_placement(
                repository.id,
                descriptor.digest,
                placement.id,
                descriptor.size,
                MediaType::OctetStream,
            )
            .await
            .map_err(|_| {
                unavailable_response("manifest graph placement evidence is unavailable", false)
            })
    }

    async fn read_image_config_projection(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        manifest: &ImageManifest,
        proofs: &mut Vec<crate::oci_projection::guard::VerifiedOciProjection>,
    ) -> Result<(Platform, OciImageConfigProjection), Response> {
        let descriptor = &manifest.config;
        if !descriptor.media_type.is_image_config() {
            return Err(manifest_invalid(
                "runnable manifest config has an unsupported media type",
            ));
        }
        let fetcher = self
            .surface
            .placement_fetcher(placement)
            .await
            .map_err(|_| unavailable_response("registry reader is unavailable", false))?;
        let (config, config_json) = if self.hybrid_delivery {
            let projection = fetcher
                .oci_document_projection(
                    &crate::db::oci_blob_object_key(descriptor.digest),
                    descriptor,
                    None,
                )
                .await
                .map_err(|_| {
                    unavailable_response("image config projection could not be verified", false)
                })?
                .ok_or_else(manifest_blob_unknown)?;
            let document = projection
                .check(descriptor, now())
                .map_err(|_| unavailable_response("image config readback expired", false))?
                .clone();
            let ParsedDocument::Config(config) = document else {
                return Err(manifest_invalid(
                    "image config projection has a different document kind",
                ));
            };
            let canonical = aos_oci_types::to_canonical_json(&config).map_err(|_| {
                manifest_invalid("image config projection exceeds the shared limit")
            })?;
            let config_json = String::from_utf8(canonical)
                .map_err(|_| manifest_invalid("image config projection is not UTF-8"))?;
            proofs.push(projection);
            (config, config_json)
        } else {
            let bytes = fetcher
                .fetch_bounded(
                    &crate::db::oci_blob_object_key(descriptor.digest),
                    MAX_MANIFEST_BYTES,
                )
                .await
                .map_err(|_| unavailable_response("image config could not be read", false))?
                .ok_or_else(manifest_blob_unknown)?;
            if bytes.len() as u64 != descriptor.size
                || Sha256Digest::digest(&bytes) != descriptor.digest
            {
                return Err(manifest_blob_unknown());
            }
            let config = ImageConfig::from_json(&bytes)
                .map_err(|_| manifest_invalid("image config JSON is invalid"))?;
            let config_json = String::from_utf8(bytes)
                .map_err(|_| manifest_invalid("image config JSON is not UTF-8"))?;
            (config, config_json)
        };
        if !self
            .repository_object_has_placement(repository, placement, descriptor)
            .await?
        {
            return Err(manifest_blob_unknown());
        }
        if config.rootfs.diff_ids.len() != manifest.layers.len() {
            return Err(manifest_invalid(
                "image config DiffIDs do not match manifest layers",
            ));
        }
        let mut layers = Vec::with_capacity(manifest.layers.len());
        for (descriptor, diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
            let unpacked_byte_size = self.read_layer_unpacked_size(placement, descriptor).await?;
            layers.push(OciLayerProjection {
                unpacked_byte_size,
                diff_id: *diff_id,
                closure_group: String::new(),
            });
        }
        let platform = config.platform();
        let aos_system = aos_system(&platform);
        Ok((
            platform,
            OciImageConfigProjection {
                config_json,
                aos_system,
                layers,
            },
        ))
    }

    async fn read_layer_unpacked_size(
        &self,
        placement: &crate::db::SurfacePlacementRecord,
        descriptor: &Descriptor,
    ) -> Result<u64, Response> {
        match descriptor.media_type {
            MediaType::OciLayerTar | MediaType::DockerLayerTar => Ok(descriptor.size),
            MediaType::OciLayerGzip | MediaType::DockerLayerGzip => {
                if descriptor.size < 4 {
                    return Err(manifest_invalid("gzip image layer is truncated"));
                }
                let start = descriptor.size - 4;
                let bytes = self
                    .read_layer_range(placement, descriptor, (start, descriptor.size - 1), 4)
                    .await?;
                let mut footer = [0_u8; 4];
                footer.copy_from_slice(&bytes);
                Ok(u64::from(u32::from_le_bytes(footer)))
            }
            MediaType::OciLayerZstd => {
                let end = descriptor.size.saturating_sub(1).min(17);
                let bytes = self
                    .read_layer_range(placement, descriptor, (0, end), 18)
                    .await?;
                parse_zstd_content_size(&bytes)
                    .ok_or_else(|| manifest_invalid("zstd image layer omits its content size"))
            }
            _ => Err(manifest_invalid(
                "runnable manifest has an unsupported layer media type",
            )),
        }
    }

    async fn read_layer_range(
        &self,
        placement: &crate::db::SurfacePlacementRecord,
        descriptor: &Descriptor,
        range: (u64, u64),
        limit: usize,
    ) -> Result<Vec<u8>, Response> {
        let fetcher = self
            .surface
            .placement_fetcher(placement)
            .await
            .map_err(|_| unavailable_response("registry reader is unavailable", false))?;
        let read = fetcher
            .inspect_oci_range(&oci_blob_object_key(descriptor.digest), range)
            .await
            .map_err(|_| unavailable_response("image layer could not be read", false))?
            .ok_or_else(manifest_blob_unknown)?;
        if read.total != descriptor.size || read.range != Some(range) {
            return Err(manifest_blob_unknown());
        }
        let bytes = to_bytes(read.body, limit)
            .await
            .map_err(|_| manifest_invalid("image layer metadata range is malformed"))?;
        Ok(bytes.to_vec())
    }
}

fn aos_system(platform: &Platform) -> String {
    match (platform.os.as_str(), platform.architecture.as_str()) {
        ("linux", "amd64") => "x86_64-linux".to_string(),
        ("linux", "arm64") => "aarch64-linux".to_string(),
        (os, architecture) => format!("{architecture}-{os}"),
    }
}

fn parse_zstd_content_size(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < 5 || bytes[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return None;
    }
    let descriptor = bytes[4];
    let single_segment = descriptor & 0x20 != 0;
    let dictionary_size = match descriptor & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let size_flag = descriptor >> 6;
    let size_length = match (size_flag, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    if size_length == 0 {
        return None;
    }
    let offset = 5 + usize::from(!single_segment) + dictionary_size;
    let field = bytes.get(offset..offset + size_length)?;
    let mut encoded = [0_u8; 8];
    encoded[..size_length].copy_from_slice(field);
    let size = u64::from_le_bytes(encoded);
    Some(if size_length == 2 { size + 256 } else { size })
}

fn manifest_content_type(headers: &HeaderMap) -> Result<MediaType, &'static str> {
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or("manifest Content-Type is required")?;
    let media_type = MediaType::parse(value).map_err(|_| "manifest Content-Type is unsupported")?;
    if !media_type.is_image_manifest() && !media_type.is_image_index() {
        return Err("Content-Type must identify an OCI or Docker schema 2 manifest or index");
    }
    Ok(media_type)
}

fn parse_document(media_type: MediaType, bytes: &[u8]) -> Result<ParsedDocument, &'static str> {
    let descriptor = Descriptor {
        media_type,
        digest: Sha256Digest::digest(bytes),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    ParsedDocument::from_stored_bytes(&descriptor, bytes).map_err(|_| "manifest JSON is invalid")
}

fn document_descriptor(
    media_type: MediaType,
    digest: Sha256Digest,
    size: u64,
    document: &ParsedDocument,
) -> Descriptor {
    Descriptor {
        media_type,
        digest,
        size,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: match document {
            ParsedDocument::Manifest(manifest) => manifest.artifact_type,
            ParsedDocument::Index(_) | ParsedDocument::Config(_) => None,
        },
        platform: None,
    }
}

fn merge_objects(
    objects: &mut BTreeMap<Sha256Digest, OciCatalogObject>,
    additional: Vec<OciCatalogObject>,
) -> Result<(), Response> {
    for object in additional {
        insert_object(objects, object)?;
    }
    Ok(())
}

fn insert_object(
    objects: &mut BTreeMap<Sha256Digest, OciCatalogObject>,
    object: OciCatalogObject,
) -> Result<(), Response> {
    if let Some(existing) = objects.insert(object.descriptor.digest, object.clone()) {
        if existing != object {
            return Err(manifest_invalid(
                "manifest graph contains conflicting descriptor identities",
            ));
        }
    }
    Ok(())
}

fn manifest_created_response(
    repository: &OciRepositoryRecord,
    reference: &ManifestReference,
    digest: Sha256Digest,
) -> Response {
    let mut response = completed_upload_response(repository, digest);
    if let Ok(location) =
        HeaderValue::from_str(&format!("/v2/{}/manifests/{reference}", repository.name))
    {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

fn manifest_invalid(message: &'static str) -> Response {
    distribution_error_response(
        StatusCode::BAD_REQUEST,
        DistributionErrorCode::ManifestInvalid,
        message,
        None,
        false,
    )
}

fn manifest_blob_unknown() -> Response {
    distribution_error_response(
        StatusCode::BAD_REQUEST,
        DistributionErrorCode::ManifestBlobUnknown,
        "a manifest descriptor is absent from this repository",
        None,
        false,
    )
}
