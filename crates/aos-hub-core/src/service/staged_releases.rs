//! Publish-authorized management of unpublished exact release revisions.
//!
//! Draft admission persists inventory before bytes arrive. Finalization freezes
//! the revision, authenticates its prepared signed release, installs the held
//! pointers through the ordinary publication machinery, and records completion
//! only after the verified release index names the exact candidate commit.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_proto_types as pb;
use aos_registry_surface::staging::{StageObject, StageRevision};
use sha2::{Digest as _, Sha256};

use crate::db::{RegistryRecord, StagedReleaseRecord, SurfacePlacementRecord};
use crate::domain::Permission;
use crate::fetch::{SurfaceFetch, SurfaceProvider};

use super::{RpcError, RpcService};

const POINTER_UPLOAD_CONCURRENCY: usize = 8;
const POINTER_PRECONDITION_CONCURRENCY: usize = 4;

/// Reads only the exact verified draft inventory over the committed surface.
struct CandidateFetch<'a> {
    provider: Arc<dyn SurfaceProvider>,
    placement: SurfacePlacementRecord,
    inventory: BTreeMap<&'a str, &'a StageObject>,
    prepared_objects: BTreeMap<&'a str, &'a [u8]>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl SurfaceFetch for CandidateFetch<'_> {
    fn storage_local_git_inspection(&self) -> bool {
        self.provider.storage_local_git_inspection()
    }

    async fn inspect_git_object(
        &self,
        oid: aos_registry_surface::object::Oid,
    ) -> anyhow::Result<Option<(aos_registry_surface::object::ObjectKind, Vec<u8>)>> {
        let path = oid.loose_path();
        if let Some(bytes) = self.prepared_objects.get(path.as_str()) {
            return aos_registry_surface::object::decode_loose(bytes, Some(oid)).map(Some);
        }
        self.provider
            .placement_fetcher(&self.placement)
            .await?
            .inspect_git_object(oid)
            .await
    }

    async fn inspect_git_objects(
        &self,
        oids: &[aos_registry_surface::object::Oid],
    ) -> anyhow::Result<Vec<Option<(aos_registry_surface::object::ObjectKind, Vec<u8>)>>> {
        let mut results = vec![None; oids.len()];
        let mut pending = Vec::new();
        for (position, oid) in oids.iter().copied().enumerate() {
            let path = oid.loose_path();
            if let Some(bytes) = self.prepared_objects.get(path.as_str()) {
                results[position] = Some(aos_registry_surface::object::decode_loose(
                    bytes,
                    Some(oid),
                )?);
            } else {
                pending.push((position, oid));
            }
        }
        if !pending.is_empty() {
            let requested = pending.iter().map(|(_, oid)| *oid).collect::<Vec<_>>();
            let inspected = self
                .provider
                .placement_fetcher(&self.placement)
                .await?
                .inspect_git_objects(&requested)
                .await?;
            anyhow::ensure!(
                inspected.len() == pending.len(),
                "staged Git inspection batch is incomplete"
            );
            for ((position, _), object) in pending.into_iter().zip(inspected) {
                results[position] = object;
            }
        }
        Ok(results)
    }

    async fn verify_git_pack_index(
        &self,
        path: &str,
        index: &[u8],
        companion_sha256: Option<&str>,
    ) -> anyhow::Result<()> {
        self.provider
            .placement_fetcher(&self.placement)
            .await?
            .verify_git_pack_index(path, index, companion_sha256)
            .await
    }

    async fn inventory_evidence_bounded(
        &self,
        path: &str,
        maximum_bytes: u64,
    ) -> anyhow::Result<Option<crate::fetch::SurfaceObjectEvidence>> {
        self.provider
            .placement_fetcher(&self.placement)
            .await?
            .inventory_evidence_bounded(path, maximum_bytes)
            .await
    }

    fn describe(&self) -> String {
        format!("staged release on placement {}", self.placement.id)
    }

    async fn fetch(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.fetch_bounded(path, 8 * 1024 * 1024).await
    }

    async fn fetch_bounded(&self, path: &str, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        if let Some(bytes) = self.prepared_objects.get(path) {
            anyhow::ensure!(
                bytes.len() <= max_bytes,
                "prepared object exceeds the semantic read limit"
            );
            return Ok(Some(bytes.to_vec()));
        }
        let fetch = self.provider.placement_fetcher(&self.placement).await?;
        let Some(object) = self.inventory.get(path) else {
            return fetch.fetch_bounded(path, max_bytes).await;
        };
        let limit = usize::try_from(object.byte_size)?;
        anyhow::ensure!(
            limit <= max_bytes,
            "stage object exceeds the semantic read limit"
        );
        let bytes = fetch.fetch_bounded(path, limit.min(max_bytes)).await?;
        if let Some(bytes) = &bytes {
            anyhow::ensure!(bytes.len() == limit, "staged object size changed");
            let hash = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
            anyhow::ensure!(hash == object.sha256, "staged object digest changed");
        }
        Ok(bytes)
    }
}

impl RpcService {
    /// Creates, edits, or attaches an upload to an exact unpublished revision.
    ///
    /// # Errors
    ///
    /// Returns an authorization, malformed revision, stale compare-and-swap,
    /// inventory mismatch, or storage error.
    pub async fn upsert_staged_release(
        &self,
        auth: Option<&str>,
        req: pb::UpsertStagedReleaseRequest,
    ) -> Result<pb::StagedRelease, RpcError> {
        let registry = self.authorize_stage_registry(auth, &req.registry).await?;
        // Keep draft JSON and held pointer bodies below the ordinary whole
        // upload limit. Large artifact bytes belong in multipart storage.
        let revision = aos_registry_surface::staging::wire::decode_revision(
            &req.revision_json,
            &req.revision_gzip,
        )
        .map_err(invalid)?;
        if revision.registry != registry.slug {
            return Err(RpcError::invalid("stage registry identity does not match"));
        }
        if revision.publication.is_empty() {
            return Err(RpcError::invalid(
                "stage requires prepared release pointers",
            ));
        }
        for pointer in &revision.publication {
            if pointer.bytes.len() > self.effective_complete_upload_bytes().await {
                return Err(RpcError::invalid("prepared stage pointer is too large"));
            }
            if let Some(hash) = &pointer.expected_sha256 {
                aos_release::digest::Sha256Digest::parse(hash).map_err(invalid)?;
            }
        }
        if !req.publication_id.is_empty() {
            self.validate_stage_publication(&registry, &revision, &req.publication_id)
                .await?;
            if self
                .db
                .staged_publication_state(&req.publication_id)
                .await
                .map_err(RpcError::internal)?
                .is_none()
            {
                let publication = self
                    .db
                    .registry_publication(&req.publication_id)
                    .await
                    .map_err(RpcError::internal)?
                    .ok_or_else(|| RpcError::not_found("registry publication"))?;
                if publication.state != "preparing" {
                    return Err(RpcError::FailedPrecondition(
                        "stage must attach before public pointer writes begin".into(),
                    ));
                }
            }
        }
        self.db
            .upsert_staged_release(
                registry.id,
                &revision,
                req.expected_revision,
                (!req.publication_id.is_empty()).then_some(req.publication_id.as_str()),
                crate::clock::now_unix_secs(),
            )
            .await
            .map_err(precondition)?;
        let stage_id = revision.id.clone();
        self.cleanup_obsolete_stage_uploads(auth, registry.id, &stage_id)
            .await?;
        // The response reloads the persisted revision. Release request buffers
        // first so a full inventory does not coexist with a second decoded copy.
        drop(revision);
        drop(req);
        self.stage_response(&registry, &stage_id).await
    }

    /// Reads a private draft, including exact verified transfer progress.
    ///
    /// # Errors
    ///
    /// Returns an authorization, not-found, or storage error.
    pub async fn get_staged_release(
        &self,
        auth: Option<&str>,
        req: pb::GetStagedReleaseRequest,
    ) -> Result<pb::StagedRelease, RpcError> {
        let registry = self.authorize_stage_registry(auth, &req.registry).await?;
        self.stage_response(&registry, &req.stage_id).await
    }

    /// Lists private drafts only for a publisher of the registry.
    ///
    /// # Errors
    ///
    /// Returns an authorization or storage error.
    pub async fn list_staged_releases(
        &self,
        auth: Option<&str>,
        req: pb::ListStagedReleasesRequest,
    ) -> Result<pb::ListStagedReleasesResponse, RpcError> {
        let registry = self.authorize_stage_registry(auth, &req.registry).await?;
        if !req.page_token.is_empty() {
            aos_registry_surface::staging::validate_stage_id(&req.page_token).map_err(invalid)?;
        }
        let limit = if req.page_size == 0 {
            50
        } else {
            req.page_size.min(200)
        };
        let mut records = self
            .db
            .staged_release_summaries(registry.id, &req.page_token, limit + 1)
            .await
            .map_err(RpcError::internal)?;
        let next_page_token = if records.len() > limit as usize {
            records.pop();
            records
                .last()
                .map(|stage| stage.stage_id.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut stages = Vec::with_capacity(records.len());
        for mut record in records {
            record.registry = registry.slug.clone();
            let (oci_bytes, oci_count) = self
                .db
                .staged_container_summary_progress(registry.id, &record.stage_id, record.revision)
                .await
                .map_err(RpcError::internal)?;
            record.uploaded_bytes = record
                .uploaded_bytes
                .checked_add(oci_bytes)
                .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
            record.missing_object_count = record.missing_object_count.saturating_sub(oci_count);
            record.verified_bytes = record.uploaded_bytes;
            let oci_partial = self
                .db
                .staged_container_summary_partial_bytes(
                    registry.id,
                    &record.stage_id,
                    record.revision,
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            record.uploaded_bytes = record
                .uploaded_bytes
                .checked_add(oci_partial)
                .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
            for partial in self
                .db
                .staged_registry_partial_upload_progress(
                    &record.publication_id,
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?
            {
                record.uploaded_bytes = record
                    .uploaded_bytes
                    .checked_add(partial)
                    .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
            }
            if record.state == "draft"
                && !record.publication_id.is_empty()
                && record.missing_object_count == 0
            {
                record.state = "ready".into();
            }
            stages.push(record);
        }
        Ok(pb::ListStagedReleasesResponse {
            stages,
            next_page_token,
        })
    }

    /// Publishes the exact prepared signed release selected by a draft revision.
    ///
    /// Retrying a partial finalization continues its frozen pointer transaction.
    /// A completed publication whose derived index is still pending remains
    /// `releasing` until a later retry proves the signed release projection.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale revision, incomplete upload, changed
    /// pointer precondition, invalid signature, publication, or storage error.
    pub async fn finalize_staged_release(
        &self,
        auth: Option<&str>,
        req: pb::FinalizeStagedReleaseRequest,
    ) -> Result<pb::StagedRelease, RpcError> {
        let registry = self.authorize_stage_registry(auth, &req.registry).await?;
        let stage = self
            .db
            .staged_release(registry.id, &req.stage_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staged release"))?;
        if stage.revision.revision != req.expected_revision
            || stage.revision.release_id != req.release_id
        {
            return Err(RpcError::FailedPrecondition(
                "staged release identity changed".into(),
            ));
        }
        if stage.state == "released" {
            return self.stage_record_response(&registry, stage).await;
        }
        if stage.state == "discarded" {
            return Err(RpcError::FailedPrecondition(
                "staged release was discarded".into(),
            ));
        }
        let publication_id = stage.publication_id.as_deref().ok_or_else(|| {
            RpcError::FailedPrecondition("stage has no upload publication".into())
        })?;
        self.validate_stage_publication(&registry, &stage.revision, publication_id)
            .await?;
        let objects = self
            .db
            .registry_publication_upload_objects(publication_id)
            .await
            .map_err(RpcError::internal)?;
        if objects
            .iter()
            .any(|object| object.object_kind == "immutable" && !object.verified)
        {
            return Err(RpcError::FailedPrecondition(
                "stage immutable inventory is incomplete".into(),
            ));
        }

        let (_, _, missing_oci) = self
            .staged_container_progress(&registry, &stage.revision)
            .await?;
        if !missing_oci.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "stage OCI graph is incomplete".into(),
            ));
        }
        let publication = self
            .db
            .registry_publication(publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication"))?;
        if publication.state == "ready" {
            if stage.state != "releasing" {
                return Err(RpcError::FailedPrecondition(
                    "committed stage is not frozen".into(),
                ));
            }
            // A later valid publication can advance the same public pointers.
            // This exact transaction is already committed: recover its derived
            // release proof without replaying or comparing old mutable bytes.
            drop(objects);
            self.refresh_registry_index_after_publication(&registry, publication_id)
                .await;
            return self
                .finish_staged_release_projection(auth, &registry, stage)
                .await;
        }
        self.lease
            .acquire(registry.id, publication_id, crate::clock::now_unix_secs())
            .await
            .map_err(|holder| {
                RpcError::FailedPrecondition(format!(
                    "registry publication lease is held by {holder}"
                ))
            })?;
        if let Err(error) = self
            .validate_stage_pointer_preconditions(
                &stage.revision,
                publication_id,
                stage.state == "releasing",
            )
            .await
        {
            if stage.state != "releasing" {
                self.lease.release(registry.id, publication_id).await;
            }
            return Err(error);
        }
        if stage.state != "releasing" {
            let validation = self
                .validate_stage_candidate(&registry, &stage.revision, publication_id)
                .await;
            let timestamp = match validation {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    self.lease.release(registry.id, publication_id).await;
                    return Err(error);
                }
            };
            if let Err(error) = self
                .db
                .begin_staged_release_finalization(
                    registry.id,
                    &req.stage_id,
                    req.expected_revision,
                    timestamp.as_ref(),
                    crate::clock::now_unix_secs(),
                )
                .await
            {
                self.lease.release(registry.id, publication_id).await;
                return Err(precondition(error));
            }
        }

        let mut pointers: Vec<_> = stage.revision.publication.iter().collect();
        // Advertise refs only after every referenced object and pack listing
        // has reached all required destinations.
        pointers.sort_by_key(|pointer| {
            aos_registry_surface::publication::pointer_upload_rank(&pointer.path)
        });
        let objects_by_path: BTreeMap<_, _> = objects
            .iter()
            .map(|object| (object.object_key.as_str(), object))
            .collect();
        let mut pending = Vec::new();
        for pointer in pointers {
            let object = objects_by_path.get(pointer.path.as_str()).ok_or_else(|| {
                RpcError::FailedPrecondition("prepared pointer is absent from publication".into())
            })?;
            if !object.verified {
                pending.push((pointer, object.surface_object_id));
            }
        }

        // Initialize the pointer phase alone. Independent metadata can then
        // overlap, but discovery refs and HEAD wait for every earlier rank.
        for group in pending.chunk_by(|left, right| {
            aos_registry_surface::publication::pointer_upload_rank(&left.0.path)
                == aos_registry_surface::publication::pointer_upload_rank(&right.0.path)
        }) {
            let Some((first, rest)) = group.split_first() else {
                continue;
            };
            self.upload_registry_publication_object(
                auth,
                publication_id,
                first.1,
                axum::body::Body::from(first.0.bytes.clone()),
            )
            .await?;

            for batch in rest.chunks(POINTER_UPLOAD_CONCURRENCY) {
                let mut uploads = Vec::with_capacity(batch.len());
                for (pointer, object_id) in batch {
                    uploads.push(self.upload_registry_publication_object(
                        auth,
                        publication_id,
                        *object_id,
                        axum::body::Body::from(pointer.bytes.clone()),
                    ));
                }
                futures_util::future::try_join_all(uploads).await?;
            }
        }
        drop(objects_by_path);
        drop(objects);
        self.commit_registry_publication(
            auth,
            pb::CommitRegistryPublicationRequest {
                publication_id: publication_id.into(),
            },
        )
        .await?;

        self.finish_staged_release_projection(auth, &registry, stage)
            .await
    }

    /// Completes derived evidence after the exact pointer transaction is ready.
    async fn finish_staged_release_projection(
        &self,
        auth: Option<&str>,
        registry: &RegistryRecord,
        stage: StagedReleaseRecord,
    ) -> Result<pb::StagedRelease, RpcError> {
        // Reindexing is an asynchronous projection. Leave the frozen draft
        // resumable if a worker has not yet indexed the newly advertised tag.
        if self
            .db
            .staged_release_is_indexed(registry.id, &stage.revision)
            .await
            .map_err(RpcError::internal)?
        {
            self.finalize_staged_container_publications(auth, &stage.revision)
                .await?;
            self.db
                .complete_staged_release(
                    registry.id,
                    &stage.revision,
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(precondition)?;
        }
        let stage_id = stage.revision.id.clone();
        drop(stage);
        self.stage_response(registry, &stage_id).await
    }

    /// Discards an editable draft and retains its own inventory through grace.
    ///
    /// # Errors
    ///
    /// Returns an authorization, stale revision, frozen lifecycle, or storage error.
    pub async fn discard_staged_release(
        &self,
        auth: Option<&str>,
        req: pb::DiscardStagedReleaseRequest,
    ) -> Result<pb::StagedRelease, RpcError> {
        let registry = self.authorize_stage_registry(auth, &req.registry).await?;
        let stage = self
            .db
            .staged_release(registry.id, &req.stage_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staged release"))?;
        if stage.revision.revision != req.expected_revision {
            return Err(RpcError::FailedPrecondition(
                "staged release revision changed".into(),
            ));
        }
        if stage.state != "discarded" {
            self.db
                .discard_staged_release(
                    registry.id,
                    &req.stage_id,
                    req.expected_revision,
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(precondition)?;
        }
        self.cleanup_obsolete_stage_uploads(auth, registry.id, &req.stage_id)
            .await?;
        self.stage_response(&registry, &req.stage_id).await
    }

    /// Retries cleanup from immutable revision history after a lifecycle CAS.
    async fn cleanup_obsolete_stage_uploads(
        &self,
        auth: Option<&str>,
        registry_id: i64,
        stage_id: &str,
    ) -> Result<(), RpcError> {
        for publication_id in self
            .db
            .obsolete_staged_release_publications(registry_id, stage_id)
            .await
            .map_err(RpcError::internal)?
        {
            for upload in self
                .db
                .active_registry_publication_multipart_uploads(&publication_id)
                .await
                .map_err(RpcError::internal)?
            {
                self.abort_registry_publication_multipart_record(auth, upload)
                    .await?;
            }
            self.abort_registry_publication(
                auth,
                pb::AbortRegistryPublicationRequest { publication_id },
            )
            .await?;
        }
        Ok(())
    }

    async fn authorize_stage_registry(
        &self,
        auth: Option<&str>,
        name: &str,
    ) -> Result<RegistryRecord, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(name).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        Ok(registry)
    }

    async fn validate_stage_publication(
        &self,
        registry: &RegistryRecord,
        revision: &StageRevision,
        publication_id: &str,
    ) -> Result<(), RpcError> {
        let publication = self
            .db
            .registry_publication(publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication"))?;
        if publication.registry_id != registry.id
            || !matches!(
                publication.state.as_str(),
                "preparing" | "writing_pointers" | "ready"
            )
        {
            return Err(RpcError::FailedPrecondition(
                "stage publication is unavailable".into(),
            ));
        }
        let objects = self
            .db
            .registry_publication_upload_objects(publication_id)
            .await
            .map_err(RpcError::internal)?;
        let ordinary_inventory = revision
            .inventory
            .iter()
            .filter(|object| !object.path.starts_with("oci/blobs/"));
        let ordinary_count = ordinary_inventory.clone().count();
        if objects.len() != ordinary_count + revision.publication.len() {
            return Err(RpcError::invalid(
                "stage publication inventory differs from its revision",
            ));
        }
        let objects: BTreeMap<_, _> = objects
            .iter()
            .map(|object| (object.object_key.as_str(), object))
            .collect();
        for input in ordinary_inventory {
            let hash = input.sha256.strip_prefix("sha256:").unwrap_or_default();
            if !objects.get(input.path.as_str()).is_some_and(|object| {
                object.object_kind == "immutable"
                    && object.expected_hash == hash
                    && u64::try_from(object.expected_size).ok() == Some(input.byte_size)
            }) {
                return Err(RpcError::invalid(
                    "stage immutable object differs from its upload publication",
                ));
            }
        }
        for input in &revision.publication {
            let hash = hex::encode(Sha256::digest(&input.bytes));
            if !objects.get(input.path.as_str()).is_some_and(|object| {
                object.object_kind == "mutable_pointer"
                    && object.expected_hash == hash
                    && usize::try_from(object.expected_size).ok() == Some(input.bytes.len())
            }) {
                return Err(RpcError::invalid(
                    "prepared stage pointer differs from its upload publication",
                ));
            }
        }
        Ok(())
    }

    /// Checks every destination under the publication lease before any pointer write.
    async fn validate_stage_pointer_preconditions(
        &self,
        revision: &StageRevision,
        publication_id: &str,
        resuming: bool,
    ) -> Result<(), RpcError> {
        let read_limit = self.effective_complete_upload_bytes().await;
        // The read-only lookup leaves every placement watermark unchanged.
        for placement in self
            .registry_publication_required_placements(publication_id)
            .await?
        {
            let fetch = self
                .surface
                .placement_fetcher(&placement)
                .await
                .map_err(precondition)?;
            for batch in revision
                .publication
                .chunks(POINTER_PRECONDITION_CONCURRENCY)
            {
                let mut checks = Vec::with_capacity(batch.len());
                for pointer in batch {
                    let fetch = &fetch;
                    let placement_id = placement.id;
                    checks.push(async move {
                        // Only the exact predecessor digest crosses the runtime
                        // boundary. Hybrid providers hash encoded Git sources in
                        // Workers; Native providers retain their bounded stream.
                        let current_hash = pointer_predecessor_hash(
                            fetch.as_ref(),
                            &pointer.path,
                            read_limit as u64,
                        )
                        .await
                        .map_err(precondition)?;
                        let intended =
                            format!("sha256:{}", hex::encode(Sha256::digest(&pointer.bytes)));
                        if current_hash != pointer.expected_sha256
                            && !(resuming && current_hash.as_deref() == Some(intended.as_str()))
                        {
                            return Err(RpcError::FailedPrecondition(format!(
                                "prepared pointer '{}' changed on placement {}",
                                pointer.path, placement_id,
                            )));
                        }
                        Ok::<_, RpcError>(())
                    });
                }
                futures_util::future::try_join_all(checks).await?;
            }
        }
        Ok(())
    }

    async fn validate_stage_candidate(
        &self,
        registry: &RegistryRecord,
        revision: &StageRevision,
        publication_id: &str,
    ) -> Result<Option<crate::db::NewReleaseTimestampPublication>, RpcError> {
        let placements = self
            .registry_publication_required_placements(publication_id)
            .await?;
        let placement = placements.into_iter().next().ok_or_else(|| {
            RpcError::FailedPrecondition("stage has no required placement".into())
        })?;
        let candidate = CandidateFetch {
            provider: Arc::clone(&self.surface),
            placement,
            inventory: revision
                .inventory
                .iter()
                .map(|object| (object.path.as_str(), object))
                .collect(),
            prepared_objects: revision
                .publication
                .iter()
                .filter(|pointer| {
                    aos_registry_surface::keymap::is_loose_git_object_path(&pointer.path)
                        || aos_registry_surface::keymap::is_git_pack_index_path(&pointer.path)
                })
                .map(|pointer| (pointer.path.as_str(), pointer.bytes.as_slice()))
                .collect(),
        };
        crate::indexer::staging::validate_candidate(&self.db, &candidate, registry, revision)
            .await
            .map_err(precondition)?;
        let Some(timestamp) = revision
            .publication
            .iter()
            .find(|pointer| pointer.path == "tuf/timestamp.json")
        else {
            return Ok(None);
        };
        let mut metadata = BTreeMap::new();
        let mut retained_bytes = 0_u64;
        for object in revision
            .inventory
            .iter()
            .filter(|object| object.path.starts_with("tuf/"))
        {
            retained_bytes = retained_bytes
                .checked_add(object.byte_size)
                .ok_or_else(|| RpcError::invalid("TUF metadata size overflow"))?;
            if retained_bytes > 8 * 1024 * 1024 {
                return Err(RpcError::invalid(
                    "staged TUF metadata exceeds the semantic limit",
                ));
            }
            let bytes = candidate
                .fetch_bounded(&object.path, 8 * 1024 * 1024)
                .await
                .map_err(precondition)?
                .ok_or_else(|| {
                    RpcError::FailedPrecondition("staged TUF metadata is absent".into())
                })?;
            metadata.insert(object.path.clone(), bytes);
        }
        let binding = aos_release::tuf::staging::bind_staged_timestamp(
            &registry.slug,
            &timestamp.bytes,
            &metadata,
        )
        .map_err(precondition)?;
        Ok(Some(crate::db::NewReleaseTimestampPublication {
            registry_id: registry.id,
            snapshot_digest: binding.snapshot_digest.to_string(),
            snapshot_version: i64::try_from(binding.snapshot_version).map_err(invalid)?,
            timestamp_version: i64::try_from(binding.timestamp_version).map_err(invalid)?,
            timestamp_digest: binding.timestamp_digest.to_string(),
            publication_id: publication_id.into(),
            timestamp_path: timestamp.path.clone(),
            snapshot_path: binding.snapshot_path,
        }))
    }

    async fn stage_response(
        &self,
        registry: &RegistryRecord,
        stage_id: &str,
    ) -> Result<pb::StagedRelease, RpcError> {
        let stage = self
            .db
            .staged_release(registry.id, stage_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("staged release"))?;
        self.stage_record_response(registry, stage).await
    }

    async fn stage_record_response(
        &self,
        registry: &RegistryRecord,
        stage: StagedReleaseRecord,
    ) -> Result<pb::StagedRelease, RpcError> {
        let objects = if let Some(publication_id) = &stage.publication_id {
            self.db
                .registry_publication_upload_objects(publication_id)
                .await
                .map_err(RpcError::internal)?
        } else {
            Vec::new()
        };
        let objects: BTreeMap<_, _> = objects
            .iter()
            .map(|object| (object.object_key.as_str(), object))
            .collect();
        let mut total_bytes = 0_u64;
        let mut uploaded_bytes = 0_u64;
        let mut missing_paths = Vec::new();
        for object in stage
            .revision
            .inventory
            .iter()
            .filter(|object| !object.path.starts_with("oci/blobs/"))
        {
            total_bytes = total_bytes
                .checked_add(object.byte_size)
                .ok_or_else(|| RpcError::invalid("stage inventory size overflow"))?;
            if objects
                .get(object.path.as_str())
                .is_some_and(|present| present.verified)
            {
                uploaded_bytes += object.byte_size;
            } else {
                missing_paths.push(object.path.clone());
            }
        }
        let (oci_total, oci_uploaded, missing_oci) = self
            .staged_container_progress(registry, &stage.revision)
            .await?;
        total_bytes = total_bytes
            .checked_add(oci_total)
            .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
        let (oci_verified_bytes, _) = self
            .db
            .staged_container_summary_progress(
                registry.id,
                &stage.revision.id,
                stage.revision.revision,
            )
            .await
            .map_err(RpcError::internal)?;
        let verified_bytes = uploaded_bytes
            .checked_add(oci_verified_bytes)
            .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
        uploaded_bytes = uploaded_bytes
            .checked_add(oci_uploaded)
            .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
        if let Some(publication_id) = &stage.publication_id {
            for partial in self
                .db
                .staged_registry_partial_upload_progress(
                    publication_id,
                    crate::clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?
            {
                uploaded_bytes = uploaded_bytes
                    .checked_add(partial)
                    .ok_or_else(|| RpcError::invalid("stage byte count overflow"))?;
            }
        }
        missing_paths.extend(missing_oci);
        missing_paths.sort();
        let state =
            if stage.state == "draft" && stage.publication_id.is_some() && missing_paths.is_empty()
            {
                "ready".into()
            } else {
                stage.state
            };
        Ok(pb::StagedRelease {
            registry: registry.slug.clone(),
            stage_id: stage.revision.id.clone(),
            revision: stage.revision.revision,
            release_id: stage.revision.release_id.clone(),
            source_branch: stage.revision.source_branch.clone(),
            commit: stage.revision.commit.clone(),
            inventory_digest: stage.revision.inventory_digest.clone(),
            object_count: stage.revision.inventory.len() as u64,
            missing_object_count: missing_paths.len() as u64,
            revision_json: String::new(),
            revision_gzip: aos_registry_surface::staging::wire::encode_revision(&stage.revision)
                .map_err(RpcError::internal)?,
            state,
            publication_id: stage.publication_id.unwrap_or_default(),
            total_bytes,
            uploaded_bytes,
            verified_bytes,
            missing_paths,
            created_at: stage.created_at,
            updated_at: stage.updated_at,
            released_version: stage.released_version.unwrap_or_default(),
        })
    }
}

/// Observes a pointer's physical digest without transferring its body to the caller.
async fn pointer_predecessor_hash(
    fetch: &dyn SurfaceFetch,
    path: &str,
    maximum_bytes: u64,
) -> anyhow::Result<Option<String>> {
    let Some(evidence) = fetch
        .inventory_evidence_bounded(path, maximum_bytes)
        .await?
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        u64::try_from(evidence.size).is_ok_and(|size| size <= maximum_bytes),
        "prepared pointer predecessor exceeds its byte limit"
    );
    Ok(Some(format!("sha256:{}", hex::encode(evidence.sha256))))
}

fn invalid(error: impl std::fmt::Display) -> RpcError {
    RpcError::invalid(error.to_string())
}

fn precondition(error: impl std::fmt::Display) -> RpcError {
    RpcError::FailedPrecondition(format!("{error:#}"))
}

#[cfg(test)]
mod pointer_hash_tests {
    use super::*;
    use crate::fetch::SurfaceObjectEvidence;

    struct HashOnlyFetch {
        evidence: Option<SurfaceObjectEvidence>,
    }

    #[async_trait::async_trait]
    impl SurfaceFetch for HashOnlyFetch {
        fn describe(&self) -> String {
            "remote pointer hash fixture".into()
        }

        async fn fetch(&self, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
            anyhow::bail!("encoded pointer bodies cannot cross this port")
        }

        async fn inventory_evidence_bounded(
            &self,
            path: &str,
            maximum_bytes: u64,
        ) -> anyhow::Result<Option<SurfaceObjectEvidence>> {
            assert_eq!(path, "objects/aos-index-v1/all");
            assert_eq!(maximum_bytes, 4096);
            Ok(self.evidence.clone())
        }
    }

    #[tokio::test]
    async fn pointer_preconditions_use_physical_hashes_without_fetching_bodies() {
        let digest: [u8; 32] = Sha256::digest(b"encoded predecessor").into();
        let mut fetch = HashOnlyFetch {
            evidence: Some(SurfaceObjectEvidence {
                sha256: digest,
                size: 4096,
                strong_etag: None,
                provider_version: None,
            }),
        };
        let path = "objects/aos-index-v1/all";

        assert_eq!(
            pointer_predecessor_hash(&fetch, path, 4096).await.unwrap(),
            Some(format!("sha256:{}", hex::encode(digest)))
        );

        for size in [-1, 4097] {
            fetch.evidence.as_mut().unwrap().size = size;
            assert!(pointer_predecessor_hash(&fetch, path, 4096).await.is_err());
        }

        fetch.evidence = None;
        assert_eq!(
            pointer_predecessor_hash(&fetch, path, 4096).await.unwrap(),
            None
        );
    }
}
