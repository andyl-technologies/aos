//! Exact-byte manifest/index admission for the Distribution write plane.
//!
//! Manifest bytes are hashed and retained without reserialization. Parsed OCI
//! documents are bounded projections used only to validate the closed graph;
//! every referenced object must already be linked to this repository and have
//! exact evidence on the selected writer placement.

use std::collections::BTreeMap;

use aos_oci_types::{
    Annotations, Descriptor, ImageConfig, ImageIndex, ImageManifest, ManifestReference, MediaType,
    Platform, Sha256Digest,
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
    OciUploadChunkRecord, OciUploadCleanupRecord, OciUploadRecord,
};

const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

enum ParsedDocument {
    Manifest(ImageManifest),
    Index(ImageIndex),
}

impl RpcService {
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
        let placement = match self
            .effective_surface_writer(SurfaceTarget::Registry(registry.id))
            .await
        {
            Ok(placement) => placement,
            Err(_) => return unavailable_response("registry writer is unavailable", false),
        };
        let root = document_descriptor(media_type, digest, bytes.len() as u64, &document);
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
        let (root_digest, objects) = match self
            .manifest_graph(repository, &placement, root.clone(), document)
            .await
        {
            Ok(graph) => graph,
            Err(response) => {
                self.cancel_staged_manifest(upload, chunks).await;
                return response;
            }
        };
        if let Err(response) = self
            .complete_staged_manifest(&owner, &placement, digest, upload, &chunks)
            .await
        {
            return response;
        };
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
            match self.db.index_oci_repository_catalog(&catalog).await {
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
        for _ in 0..200 {
            if outcome != OciBlobClaimOutcome::InProgress {
                break;
            }
            crate::clock::sleep(std::time::Duration::from_millis(5)).await;
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
                let platform = if manifest.artifact_type.is_none() {
                    Some(
                        self.read_image_config_platform(repository, placement, &manifest.config)
                            .await?,
                    )
                } else {
                    None
                };
                insert_object(
                    &mut objects,
                    OciCatalogObject {
                        descriptor: root,
                        projection: Some(OciCatalogProjection::Manifest {
                            document: manifest,
                            platform,
                        }),
                    },
                )?;
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

    async fn read_image_config_platform(
        &self,
        repository: &OciRepositoryRecord,
        placement: &crate::db::SurfacePlacementRecord,
        descriptor: &Descriptor,
    ) -> Result<Platform, Response> {
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
            || !self
                .repository_object_has_placement(repository, placement, descriptor)
                .await?
        {
            return Err(manifest_blob_unknown());
        }
        ImageConfig::from_json(&bytes)
            .map(|config| config.platform())
            .map_err(|_| manifest_invalid("image config JSON is invalid"))
    }
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
    if media_type.is_image_manifest() {
        let manifest = ImageManifest::from_json(bytes).map_err(|_| "manifest JSON is invalid")?;
        if manifest.media_type.is_some_and(|outer| outer != media_type) {
            return Err("manifest Content-Type conflicts with its mediaType field");
        }
        Ok(ParsedDocument::Manifest(manifest))
    } else {
        let index = ImageIndex::from_json(bytes).map_err(|_| "index JSON is invalid")?;
        if index.media_type.is_some_and(|outer| outer != media_type) {
            return Err("index Content-Type conflicts with its mediaType field");
        }
        Ok(ParsedDocument::Index(index))
    }
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
            ParsedDocument::Index(_) => None,
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
