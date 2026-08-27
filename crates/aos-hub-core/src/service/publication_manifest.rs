//! Resumable, bounded registry-publication manifest admission.
//!
//! A publication manifest is fixed by a declared object count and canonical
//! digest, then admitted as ordered pages under a durable lease. Sealing reads
//! the durable declarations back, re-derives the digest, and freezes the
//! required placement set atomically. The protocol therefore bounds request
//! memory and SQL work without weakening publication identity or placement
//! consistency.

use super::*;

fn validate_registry_publication_manifest_object(
    object: &pb::RegistryPublicationObjectInput,
    complete_upload_limit: u64,
) -> Result<(), RpcError> {
    if !keymap::is_machine_path(&object.path)
        || crate::url_guard::validate_http_surface_path(&object.path).is_err()
        || object.path.len() > MAX_REGISTRY_PUBLICATION_PATH_BYTES
        || object.path.split('/').count() > MAX_REGISTRY_PUBLICATION_PATH_COMPONENTS
    {
        return Err(RpcError::invalid("publication object path is invalid"));
    }
    if !matches!(object.kind.as_str(), "immutable" | "mutable_pointer") {
        return Err(RpcError::invalid(
            "publication object kind must be immutable or mutable_pointer",
        ));
    }
    if (object.kind == "mutable_pointer") != is_mutable_pointer(&object.path) {
        return Err(RpcError::invalid(
            "publication object kind does not match path mutability",
        ));
    }
    if object.media_type != publication_media_type(&object.path) {
        return Err(RpcError::invalid(format!(
            "publication object '{}' must declare media type '{}'",
            object.path,
            publication_media_type(&object.path)
        )));
    }
    if object.byte_size < 0
        || object.sha256.len() != 64
        || !object
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RpcError::invalid(
            "publication objects require a lowercase SHA-256 and non-negative size",
        ));
    }
    if keymap::is_loose_git_object_path(&object.path)
        && object.byte_size as u64
            > complete_upload_limit
                .min(aos_registry_surface::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES)
    {
        return Err(RpcError::invalid(format!(
            "loose Git object exceeds the {}-byte whole-upload limit",
            complete_upload_limit
                .min(aos_registry_surface::object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES)
        )));
    }
    if keymap::is_git_pack_index_path(&object.path)
        && object.byte_size as u64
            > complete_upload_limit
                .min(aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES)
    {
        return Err(RpcError::invalid(format!(
            "Git pack index exceeds the {}-byte whole-upload limit",
            complete_upload_limit
                .min(aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_INDEX_BYTES)
        )));
    }
    if keymap::is_git_pack_path(&object.path)
        && object.byte_size as u64
            > complete_upload_limit.min(aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES)
    {
        return Err(RpcError::invalid(format!(
            "Git pack exceeds the {}-byte whole-upload limit",
            complete_upload_limit.min(aos_registry_surface::pack_index::MAX_PUBLISHED_PACK_BYTES)
        )));
    }
    if !publication_nar_path_matches_sha256(&object.path, &object.sha256) {
        return Err(RpcError::invalid(
            "publication NAR object path must identify its declared SHA-256",
        ));
    }
    Ok(())
}

fn canonical_registry_publication_manifest_digest(
    objects: &[pb::RegistryPublicationObjectInput],
) -> Result<String, RpcError> {
    let mut paths = BTreeSet::new();
    let mut canonical = Vec::with_capacity(objects.len());
    for object in objects {
        if !paths.insert(object.path.as_str()) {
            return Err(RpcError::invalid("publication paths must be unique"));
        }
        canonical.push((
            object.path.clone(),
            object.sha256.clone(),
            object.byte_size,
            object.kind.clone(),
            object.media_type.clone(),
        ));
    }
    for path in paths
        .iter()
        .filter(|path| keymap::is_git_pack_index_path(path))
    {
        let companion = aos_registry_surface::pack_index::companion_pack_path(path)
            .ok_or_else(|| RpcError::invalid("Git pack index path is invalid"))?;
        if !paths.contains(companion.as_str()) {
            return Err(RpcError::invalid(format!(
                "Git pack index has no companion pack: {path}"
            )));
        }
    }
    for path in paths.iter().filter(|path| keymap::is_git_pack_path(path)) {
        let companion = format!("{}.idx", path.trim_end_matches(".pack"));
        if !paths.contains(companion.as_str()) {
            return Err(RpcError::invalid(format!(
                "Git pack has no companion index: {path}"
            )));
        }
    }
    canonical.sort();
    // Initial APR registries contain replaceable loose Git encodings but may
    // not have a pack, NAR, or another immutable transport object yet.
    if !canonical.iter().any(|object| object.3 == "mutable_pointer") {
        return Err(RpcError::invalid("publication requires mutable pointers"));
    }
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(RpcError::internal)?,
    )))
}

fn registry_publication_manifest_chunk_digest(
    objects: &[pb::RegistryPublicationObjectInput],
) -> Result<String, RpcError> {
    let canonical = objects
        .iter()
        .map(|object| {
            (
                &object.path,
                &object.sha256,
                object.byte_size,
                &object.kind,
                &object.media_type,
            )
        })
        .collect::<Vec<_>>();
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).map_err(RpcError::internal)?,
    )))
}

fn manifest_session_response(
    session: crate::db::RegistryPublicationManifestSessionRecord,
) -> Result<pb::RegistryPublicationManifestSession, RpcError> {
    Ok(pb::RegistryPublicationManifestSession {
        publication_id: session.publication_id,
        lease_token: session.lease_token,
        manifest_digest: session.manifest_digest,
        object_count: u32::try_from(session.expected_object_count).map_err(RpcError::internal)?,
        admitted_object_count: u32::try_from(session.admitted_object_count)
            .map_err(RpcError::internal)?,
        next_chunk_index: u32::try_from(session.next_chunk_index).map_err(RpcError::internal)?,
        state: session.state,
        lease_expires_at: session.lease_expires_at.unwrap_or_default(),
    })
}

impl RpcService {
    /// Begins or resumes bounded admission of one publication manifest.
    ///
    /// This metadata-only operation fixes the manifest digest and object count
    /// without placing a multi-megabyte object inventory in one Worker request.
    /// An expired session is reclaimed with a new lease; an exact active or
    /// sealed session returns its durable continuation cursor.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error, invalid argument for
    /// malformed metadata, failed precondition for a conflicting generation or
    /// unavailable placement, or internal error on persistence failure.
    pub async fn begin_registry_publication_manifest(
        &self,
        auth: Option<&str>,
        req: pb::BeginRegistryPublicationManifestRequest,
    ) -> Result<pb::RegistryPublicationManifestSession, RpcError> {
        let claims = self.require_claims(auth)?;
        let registry = self.registry_or_not_found(&req.registry).await?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;

        if req.generation.is_empty() || req.refs_digest.is_empty() {
            return Err(RpcError::invalid(
                "publication generation and refs digest are required",
            ));
        }
        if req.object_count == 0
            || req.object_count as usize > MAX_REGISTRY_PUBLICATION_OBJECTS
            || req.manifest_digest.len() != 64
            || !req
                .manifest_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RpcError::invalid(format!(
                "publication manifest requires a lowercase SHA-256 and 1..={MAX_REGISTRY_PUBLICATION_OBJECTS} objects"
            )));
        }
        let parent =
            (!req.parent_publication_id.is_empty()).then(|| req.parent_publication_id.clone());
        let default_commit = (!req.default_commit.is_empty()).then(|| req.default_commit.clone());
        let publication_id = if let Some(existing) = self
            .db
            .registry_publication_by_generation(registry.id, &req.generation)
            .await
            .map_err(RpcError::internal)?
        {
            if existing.manifest_digest != req.manifest_digest
                || existing.refs_digest != req.refs_digest
                || existing.default_commit != default_commit
                || existing.parent_publication_id != parent
            {
                return Err(RpcError::FailedPrecondition(
                    "publication generation already exists with different content".into(),
                ));
            }
            if existing.state == "retired" {
                return Err(RpcError::FailedPrecondition(
                    "retired publication generation cannot be resumed".into(),
                ));
            }
            if existing.state == "failed" {
                self.db
                    .retry_failed_registry_publication(
                        &existing.publication_id,
                        clock::now_unix_secs(),
                    )
                    .await
                    .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            }
            existing.publication_id
        } else {
            let publication_id = uuid::Uuid::new_v4().simple().to_string();
            self.db
                .create_registry_publication(&crate::db::NewRegistryPublication {
                    publication_id: publication_id.clone(),
                    registry_id: registry.id,
                    generation: req.generation,
                    manifest_digest: req.manifest_digest.clone(),
                    refs_digest: req.refs_digest,
                    default_commit,
                    parent_publication_id: parent,
                })
                .await
                .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
            publication_id
        };
        let lease_token = uuid::Uuid::new_v4().simple().to_string();
        let session = self
            .db
            .begin_registry_publication_manifest_session(
                &publication_id,
                registry.id,
                &req.manifest_digest,
                i64::from(req.object_count),
                &lease_token,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        manifest_session_response(session)
    }

    /// Appends one ordered, bounded page to a publication manifest session.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error, invalid argument for
    /// malformed objects or digest, failed precondition for stale ownership or
    /// ordering, or internal error on persistence failure.
    pub async fn append_registry_publication_manifest(
        &self,
        auth: Option<&str>,
        req: pb::AppendRegistryPublicationManifestRequest,
    ) -> Result<pb::RegistryPublicationManifestSession, RpcError> {
        let claims = self.require_claims(auth)?;
        let session = self
            .db
            .registry_publication_manifest_session(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication manifest session"))?;
        let registry = self
            .db
            .registry_by_id(session.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;
        if req.objects.is_empty()
            || req.objects.len() > crate::db::MAX_REGISTRY_MANIFEST_ADMISSION_BATCH
        {
            return Err(RpcError::invalid(format!(
                "publication manifest chunks require 1..={} objects",
                crate::db::MAX_REGISTRY_MANIFEST_ADMISSION_BATCH
            )));
        }
        let complete_upload_limit = self.effective_complete_upload_bytes().await as u64;
        for object in &req.objects {
            validate_registry_publication_manifest_object(object, complete_upload_limit)?;
        }
        let chunk_digest = registry_publication_manifest_chunk_digest(&req.objects)?;
        if req.chunk_digest != chunk_digest {
            return Err(RpcError::invalid(
                "publication manifest chunk digest does not match its objects",
            ));
        }
        let objects = req
            .objects
            .into_iter()
            .map(|object| crate::db::RegistryPublicationManifestObject {
                object_key: object.path,
                expected_hash: object.sha256,
                expected_size: object.byte_size,
                object_kind: object.kind,
            })
            .collect::<Vec<_>>();
        let session = self
            .db
            .append_registry_publication_manifest_chunk(
                &req.publication_id,
                &req.lease_token,
                i64::from(req.chunk_index),
                &chunk_digest,
                &objects,
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        manifest_session_response(session)
    }

    /// Seals a complete admitted manifest and exposes its upload inventory.
    ///
    /// Sealing re-derives the canonical digest from durable object declarations
    /// and atomically freezes the required placement set with the session.
    /// Exact retries complete evidence inheritance and return the same result.
    ///
    /// # Errors
    ///
    /// Returns an authentication or authorization error, failed precondition
    /// for stale, incomplete, or divergent state, or internal error on
    /// persistence failure.
    pub async fn seal_registry_publication_manifest(
        &self,
        auth: Option<&str>,
        req: pb::SealRegistryPublicationManifestRequest,
    ) -> Result<pb::RegistryPublication, RpcError> {
        let claims = self.require_claims(auth)?;
        let session = self
            .db
            .registry_publication_manifest_session(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry publication manifest session"))?;
        let registry = self
            .db
            .registry_by_id(session.registry_id)
            .await
            .map_err(RpcError::internal)?
            .ok_or_else(|| RpcError::not_found("registry"))?;
        let scope = self.registry_scope(&registry).await?;
        self.require_permission(&claims, Permission::Publish, &scope)
            .await?;

        if session.state == "sealed" {
            if session.lease_token != req.lease_token {
                return Err(RpcError::FailedPrecondition(
                    "publication manifest lease token is stale".into(),
                ));
            }
            self.db
                .inherit_registry_publication_object_evidence(
                    &req.publication_id,
                    clock::now_unix_secs(),
                )
                .await
                .map_err(RpcError::internal)?;
            return self
                .registry_publication_response(&req.publication_id, true)
                .await;
        }

        let objects = self
            .db
            .registry_publication_upload_objects(&req.publication_id)
            .await
            .map_err(RpcError::internal)?
            .into_iter()
            .map(|object| pb::RegistryPublicationObjectInput {
                media_type: publication_media_type(&object.object_key).into(),
                path: object.object_key,
                sha256: object.expected_hash,
                byte_size: object.expected_size,
                kind: object.object_kind,
            })
            .collect::<Vec<_>>();
        if i64::try_from(objects.len()).map_err(RpcError::internal)?
            != session.expected_object_count
            || canonical_registry_publication_manifest_digest(&objects)? != session.manifest_digest
        {
            return Err(RpcError::FailedPrecondition(
                "admitted publication manifest does not match its declaration".into(),
            ));
        }
        let placements = self
            .db
            .registry_publication_write_placements(registry.id)
            .await
            .map_err(RpcError::internal)?;
        if placements.is_empty() {
            return Err(RpcError::FailedPrecondition(
                "registry has no complete validated publication placement".into(),
            ));
        }
        self.db
            .seal_registry_publication_manifest_session(
                &req.publication_id,
                &req.lease_token,
                &placements
                    .iter()
                    .map(|placement| placement.id)
                    .collect::<Vec<_>>(),
                clock::now_unix_secs(),
            )
            .await
            .map_err(|error| RpcError::FailedPrecondition(format!("{error:#}")))?;
        self.db
            .inherit_registry_publication_object_evidence(
                &req.publication_id,
                clock::now_unix_secs(),
            )
            .await
            .map_err(RpcError::internal)?;
        self.registry_publication_response(&req.publication_id, true)
            .await
    }
}
