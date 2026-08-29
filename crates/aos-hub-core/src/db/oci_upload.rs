//! Durable OCI Distribution blob-upload state and resumable hashing.
//!
//! Uploads reserve quota before accepting bytes, freeze immutable staging
//! chunks, persist portable SHA-256 continuation state, and serialize final
//! digest materialization across concurrent writers.

use super::*;

#[path = "oci_upload/claim.rs"]
mod claim;
#[path = "oci_upload/model.rs"]
mod model;
#[path = "oci_upload/recovery.rs"]
mod recovery;
#[path = "oci_upload/sha256.rs"]
mod sha256;

pub use model::*;
pub use sha256::*;

impl Database {
    /// Opens or idempotently returns a bounded repository upload.
    ///
    /// The session reserves one object immediately and grows its byte
    /// reservation as contiguous chunks are accepted, up to the frozen
    /// maximum size. An optional declared size adds an exact completion fence
    /// without making it mandatory for standard Distribution clients.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed ownership/session data, an absent or
    /// mismatched repository/publication, quota exhaustion, or database
    /// failure.
    pub async fn begin_oci_upload(&self, input: &BeginOciUpload) -> Result<OciUploadRecord> {
        validate_session_identity(&input.writer_id, "writer id", 128)?;
        validate_session_identity(&input.token_id, "token id", 128)?;
        validate_session_identity(&input.idempotency_key, "idempotency key", 128)?;
        validate_session_times(input.now, input.expires_at)?;
        let expected_size = input
            .expected_size
            .map(|size| checked_u64(size, "expected upload size"))
            .transpose()?;
        let maximum_size = checked_u64(input.maximum_size, "maximum upload size")?;
        if input
            .expected_size
            .is_some_and(|expected| expected > input.maximum_size)
        {
            bail!("OCI expected upload size exceeds its frozen maximum");
        }
        let upload_id = Uuid::new_v4().simple().to_string();
        let quota_id = reservation_id(&upload_id);
        let initial = OciSha256State::initial();
        let expected_digest = input.expected_digest.map(|digest| digest.to_string());
        let mut statements = vec![
            Statement::new(
                "UPDATE registries SET updated_at = updated_at
                 WHERE id = ?1
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = ?1 AND purge.state = 'collecting')",
                vals![input.registry_id],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO oci_quota_reservations
                   (id, registry_id, org_id, owner_kind, owner_id,
                    reserved_bytes, reserved_objects, state, created_at, updated_at)
                 SELECT ?1, repository.registry_id, registry.org_id, 'upload', ?2,
                        0, 1, 'pending', ?3, ?3
                 FROM oci_repositories repository
                 JOIN registries registry ON registry.id = repository.registry_id
                 WHERE repository.id = ?4 AND repository.registry_id = ?5
                   AND repository.lifecycle_state = 'active'
                   AND (?6 IS NULL OR EXISTS (SELECT 1 FROM oci_publication_sessions publication
                     WHERE publication.id = ?6
                       AND publication.registry_id = repository.registry_id
                       AND publication.repository_id = repository.id
                       AND publication.writer_id = ?7 AND publication.token_id = ?8
                       AND publication.state = 'preparing'
                   AND publication.expires_at > ?3))
                   AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                     WHERE upload.registry_id = ?5 AND upload.writer_id = ?7
                       AND upload.idempotency_key = ?9)",
                vals![
                    quota_id,
                    upload_id,
                    input.now,
                    input.repository_id,
                    input.registry_id,
                    input.publication_id,
                    input.writer_id,
                    input.token_id,
                    input.idempotency_key
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE org_usage
                 SET object_count = object_count + 1, updated_at = ?1
                 WHERE org_id = (SELECT org_id FROM oci_quota_reservations
                   WHERE id = ?2 AND state = 'pending')
                   AND ((SELECT max_objects FROM org_quotas WHERE org_id = org_usage.org_id)
                         IS NULL
                     OR object_count + 1 <= (SELECT max_objects FROM org_quotas
                       WHERE org_id = org_usage.org_id))",
                vals![input.now, quota_id],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_quota_reservations SET state = 'reserved', updated_at = ?2
                 WHERE id = ?1 AND state = 'pending'",
                vals![quota_id, input.now],
            )
            .expecting(1),
        ];
        statements.push(
            Statement::new(
                "INSERT INTO oci_upload_sessions
                   (id, registry_id, repository_id, publication_id,
                    quota_reservation_id, writer_id, token_id, idempotency_key,
                    expected_digest, expected_size, maximum_size, uploaded_size,
                    sha256_state_version, sha256_h0, sha256_h1, sha256_h2,
                    sha256_h3, sha256_h4, sha256_h5, sha256_h6, sha256_h7,
                    sha256_total_bytes, sha256_tail_hex, state, expires_at,
                    created_at, finished_at, resource_version)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0,
                        ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                        0, '', 'active', ?21, ?22, NULL, 1
                 FROM oci_quota_reservations reservation
                 WHERE reservation.id = ?5 AND reservation.state = 'reserved'
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = ?2 AND purge.state = 'collecting')",
                vals![
                    upload_id,
                    input.registry_id,
                    input.repository_id,
                    input.publication_id,
                    quota_id,
                    input.writer_id,
                    input.token_id,
                    input.idempotency_key,
                    expected_digest,
                    expected_size,
                    maximum_size,
                    initial.version,
                    i64::from(initial.words[0]),
                    i64::from(initial.words[1]),
                    i64::from(initial.words[2]),
                    i64::from(initial.words[3]),
                    i64::from(initial.words[4]),
                    i64::from(initial.words[5]),
                    i64::from(initial.words[6]),
                    i64::from(initial.words[7]),
                    input.expires_at,
                    input.now
                ],
            )
            .expecting(1),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_registry_state
                 SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
                 WHERE registry_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = ?1 AND purge.state = 'collecting')",
                vals![input.registry_id, input.now],
            )
            .expecting(1),
        );
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_upload_by_idempotency(
                    input.registry_id,
                    &input.writer_id,
                    &input.idempotency_key,
                )
                .await?
            {
                if existing.repository_id == input.repository_id
                    && existing.publication_id == input.publication_id
                    && existing.token_id == input.token_id
                    && existing.expected_digest == input.expected_digest
                    && existing.expected_size == input.expected_size
                    && existing.maximum_size == input.maximum_size
                {
                    return Ok(existing);
                }
                bail!("OCI upload idempotency key conflicts with another request");
            }
            return Err(error).context("opening OCI upload and reserving quota");
        }
        self.oci_upload(&upload_id, &input.writer_id, &input.token_id, input.now)
            .await?
            .context("new OCI upload disappeared")
    }

    /// Returns a live or terminal upload only to its exact writer and token.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted state.
    pub async fn oci_upload(
        &self,
        upload_id: &str,
        writer_id: &str,
        token_id: &str,
        now: i64,
    ) -> Result<Option<OciUploadRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions
                     WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                       AND (state IN('complete', 'cancelled', 'failed') OR expires_at > ?4)"
                ),
                &vals![upload_id, writer_id, token_id, now],
            )
            .await?
            .as_ref()
            .map(row_to_oci_upload)
            .transpose()
    }

    async fn oci_upload_by_idempotency(
        &self,
        registry_id: i64,
        writer_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<OciUploadRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_UPLOAD_COLUMNS} FROM oci_upload_sessions
                     WHERE registry_id = ?1 AND writer_id = ?2
                       AND idempotency_key = ?3"
                ),
                &vals![registry_id, writer_id, idempotency_key],
            )
            .await?
            .as_ref()
            .map(row_to_oci_upload)
            .transpose()
    }

    /// Atomically appends an immutable staging chunk and advances the portable
    /// hash state. Exact replay returns the already-advanced upload.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed progress, stale ownership/version,
    /// expiry, conflicting retry identity, size overflow, or database failure.
    pub async fn append_oci_upload_chunk(
        &self,
        input: &AppendOciUploadChunk,
    ) -> Result<OciUploadRecord> {
        validate_session_identity(&input.writer_id, "writer id", 128)?;
        validate_session_identity(&input.token_id, "token id", 128)?;
        validate_session_identity(&input.chunk.staging_object_key, "staging key", 512)?;
        if input.now <= 0
            || input.expected_resource_version < 1
            || input.staging_placement_id <= 0
            || input.staging_placement_resource_version < 1
            || input.staging_binding_id <= 0
            || input.staging_binding_write_revision < 1
            || input.chunk.byte_size == 0
        {
            bail!("OCI upload chunk metadata is invalid");
        }
        let next_size = input
            .chunk
            .byte_offset
            .checked_add(input.chunk.byte_size)
            .context("OCI upload size overflow")?;
        validate_sha_progress(&input.next_sha256, next_size)?;
        let offset = checked_u64(input.chunk.byte_offset, "chunk offset")?;
        let size = checked_u64(input.chunk.byte_size, "chunk size")?;
        let next_size = checked_u64(next_size, "upload size")?;
        let ordinal = i64::from(input.chunk.ordinal);
        let statements = vec![
            Statement::new(
                "UPDATE oci_registry_state
                 SET updated_at = updated_at
                 WHERE registry_id = (SELECT registry_id FROM oci_upload_sessions
                   WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                     AND state = 'active' AND resource_version = ?4
                     AND expires_at > ?5)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = oci_registry_state.registry_id)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = oci_registry_state.registry_id
                       AND purge.state = 'collecting')",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    input.now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE org_usage SET used_bytes = used_bytes + ?6, updated_at = ?5
                 WHERE org_id = (SELECT reservation.org_id
                   FROM oci_upload_sessions upload JOIN oci_quota_reservations reservation
                     ON reservation.id = upload.quota_reservation_id
                   WHERE upload.id = ?1 AND upload.writer_id = ?2
                     AND upload.token_id = ?3 AND upload.state = 'active'
                     AND upload.expires_at > ?5 AND upload.resource_version = ?4
                     AND upload.uploaded_size = ?7
                     AND ?8 <= upload.maximum_size
                     AND (upload.expected_size IS NULL OR ?8 <= upload.expected_size)
                     AND reservation.state = 'reserved')
                   AND ((SELECT max_bytes FROM org_quotas WHERE org_id = org_usage.org_id)
                         IS NULL OR used_bytes + ?6 <= (SELECT max_bytes
                           FROM org_quotas WHERE org_id = org_usage.org_id))",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    input.now,
                    size,
                    offset,
                    next_size
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_quota_reservations
                 SET reserved_bytes = reserved_bytes + ?6, updated_at = ?5
                 WHERE id = (SELECT quota_reservation_id FROM oci_upload_sessions
                   WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                     AND state = 'active' AND expires_at > ?5
                     AND resource_version = ?4 AND uploaded_size = ?7
                     AND ?8 <= maximum_size
                     AND (expected_size IS NULL OR ?8 <= expected_size))
                   AND state = 'reserved'",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    input.now,
                    size,
                    offset,
                    next_size
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO oci_upload_chunks
                   (upload_id, ordinal, byte_offset, byte_size, digest,
                    staging_object_key, created_at)
                 SELECT upload.id, ?2, ?3, ?4, ?5, ?6, ?7
                 FROM oci_upload_sessions upload
                 WHERE upload.id = ?1 AND upload.writer_id = ?8
                   AND upload.token_id = ?9 AND upload.state = 'active'
                   AND upload.expires_at > ?7
                   AND upload.resource_version = ?10
                   AND upload.uploaded_size = ?3
                   AND ?11 <= upload.maximum_size
                   AND (upload.expected_size IS NULL OR ?11 <= upload.expected_size)
                 ON CONFLICT(upload_id, ordinal) DO NOTHING",
                vals![
                    input.upload_id,
                    ordinal,
                    offset,
                    size,
                    input.chunk.digest.to_string(),
                    input.chunk.staging_object_key,
                    input.now,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    next_size
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_upload_sessions SET uploaded_size = ?4,
                   staging_placement_id = COALESCE(staging_placement_id, ?23),
                   staging_placement_resource_version =
                     COALESCE(staging_placement_resource_version, ?24),
                   staging_binding_id = COALESCE(staging_binding_id, ?25),
                   staging_binding_write_revision =
                     COALESCE(staging_binding_write_revision, ?26),
                   sha256_state_version = ?5, sha256_h0 = ?6, sha256_h1 = ?7,
                   sha256_h2 = ?8, sha256_h3 = ?9, sha256_h4 = ?10,
                   sha256_h5 = ?11, sha256_h6 = ?12, sha256_h7 = ?13,
                   sha256_total_bytes = ?14, sha256_tail_hex = ?15,
                   resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'active' AND expires_at > ?16
                   AND resource_version = ?17 AND uploaded_size = ?18
                   AND ((staging_placement_id IS NULL AND EXISTS (
                     SELECT 1 FROM surface_placements placement
                     JOIN surface_placement_write_capabilities capability
                       ON capability.placement_id = placement.id
                      AND capability.placement_write_spec_version = placement.write_spec_version
                     WHERE placement.id = ?23
                       AND placement.registry_id = oci_upload_sessions.registry_id
                       AND placement.resource_version = ?24
                       AND placement.binding_id = ?25
                       AND capability.binding_id = ?25
                       AND capability.binding_write_revision = ?26))
                     OR (staging_placement_id = ?23
                       AND staging_placement_resource_version = ?24
                       AND staging_binding_id = ?25
                       AND staging_binding_write_revision = ?26))
                   AND EXISTS (SELECT 1 FROM oci_upload_chunks chunk
                     WHERE chunk.upload_id = oci_upload_sessions.id AND chunk.ordinal = ?19
                       AND chunk.byte_offset = ?18 AND chunk.byte_size = ?20
                       AND chunk.digest = ?21 AND chunk.staging_object_key = ?22)",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    next_size,
                    input.next_sha256.version,
                    i64::from(input.next_sha256.words[0]),
                    i64::from(input.next_sha256.words[1]),
                    i64::from(input.next_sha256.words[2]),
                    i64::from(input.next_sha256.words[3]),
                    i64::from(input.next_sha256.words[4]),
                    i64::from(input.next_sha256.words[5]),
                    i64::from(input.next_sha256.words[6]),
                    i64::from(input.next_sha256.words[7]),
                    checked_u64(input.next_sha256.total_bytes, "hash byte count")?,
                    input.next_sha256.tail_hex,
                    input.now,
                    input.expected_resource_version,
                    offset,
                    ordinal,
                    size,
                    input.chunk.digest.to_string(),
                    input.chunk.staging_object_key,
                    input.staging_placement_id,
                    input.staging_placement_resource_version,
                    input.staging_binding_id,
                    input.staging_binding_write_revision
                ],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_upload(
                    &input.upload_id,
                    &input.writer_id,
                    &input.token_id,
                    input.now,
                )
                .await?
            {
                let chunk = self
                    .oci_upload_chunk(&input.upload_id, input.chunk.ordinal)
                    .await?;
                if chunk.as_ref() == Some(&input.chunk)
                    && existing.uploaded_size == input.next_sha256.total_bytes
                    && existing.sha256 == input.next_sha256
                    && existing.staging_placement_id == Some(input.staging_placement_id)
                    && existing.staging_placement_resource_version
                        == Some(input.staging_placement_resource_version)
                    && existing.staging_binding_id == Some(input.staging_binding_id)
                    && existing.staging_binding_write_revision
                        == Some(input.staging_binding_write_revision)
                {
                    return Ok(existing);
                }
            }
            return Err(error).context("appending OCI upload chunk");
        }
        self.oci_upload(
            &input.upload_id,
            &input.writer_id,
            &input.token_id,
            input.now,
        )
        .await?
        .context("advanced OCI upload disappeared")
    }

    /// Returns one immutable upload chunk by ordinal.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted state.
    pub async fn oci_upload_chunk(
        &self,
        upload_id: &str,
        ordinal: u32,
    ) -> Result<Option<OciUploadChunkRecord>> {
        self.backend
            .query_opt(
                "SELECT ordinal, byte_offset, byte_size, digest,
                        staging_object_key, created_at
                 FROM oci_upload_chunks WHERE upload_id = ?1 AND ordinal = ?2",
                &vals![upload_id, ordinal],
            )
            .await?
            .as_ref()
            .map(row_to_oci_upload_chunk)
            .transpose()
    }

    /// Returns every staged chunk in strict contiguous assembly order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, malformed persisted state, or a
    /// gap/overlap in the durable chunk sequence.
    pub async fn oci_upload_chunks(&self, upload_id: &str) -> Result<Vec<OciUploadChunkRecord>> {
        let chunks: Vec<OciUploadChunkRecord> = self
            .backend
            .query(
                "SELECT ordinal, byte_offset, byte_size, digest,
                        staging_object_key, created_at
                 FROM oci_upload_chunks WHERE upload_id = ?1
                 ORDER BY ordinal",
                &vals![upload_id],
            )
            .await?
            .iter()
            .map(row_to_oci_upload_chunk)
            .collect::<Result<_>>()?;
        let mut expected_offset = 0_u64;
        for (expected_ordinal, chunk) in chunks.iter().enumerate() {
            if usize::try_from(chunk.ordinal).ok() != Some(expected_ordinal)
                || chunk.byte_offset != expected_offset
            {
                bail!("persisted OCI upload chunks are not contiguous");
            }
            expected_offset = expected_offset
                .checked_add(chunk.byte_size)
                .context("persisted OCI upload chunk range overflows u64")?;
        }
        Ok(chunks)
    }

    /// Claims final digest materialization after all declared bytes arrived.
    /// Exact retries are idempotent; only one upload can own a registry digest.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched digest/size, stale ownership/version,
    /// expiry, or database failure.
    pub async fn claim_oci_upload(&self, input: &ClaimOciUpload) -> Result<OciBlobClaimOutcome> {
        validate_session_times(input.now, input.lease_expires_at)?;
        if input.expected_resource_version < 1
            || input.materialization_placement_id <= 0
            || input.materialization_placement_resource_version < 1
            || input.materialization_binding_id <= 0
            || input.materialization_binding_write_revision < 1
        {
            bail!("OCI upload claim metadata is invalid");
        }
        if let Some(current) = self
            .oci_upload(
                &input.upload_id,
                &input.writer_id,
                &input.token_id,
                input.now,
            )
            .await?
        {
            if current.state == "completing" && current.final_digest != Some(input.digest) {
                bail!("OCI upload completion digest is already frozen");
            }
            if current.state == "completing"
                && (current.materialization_placement_id
                    != Some(input.materialization_placement_id)
                    || current.materialization_placement_resource_version
                        != Some(input.materialization_placement_resource_version)
                    || current.materialization_binding_id != Some(input.materialization_binding_id)
                    || current.materialization_binding_write_revision
                        != Some(input.materialization_binding_write_revision))
            {
                bail!("OCI upload materialization placement is already frozen");
            }
        }
        let statements = vec![
            Statement::new(
                "UPDATE oci_registry_state
                 SET mutation_epoch = mutation_epoch + 1, updated_at = ?5
                 WHERE registry_id = (SELECT registry_id FROM oci_upload_sessions
                   WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                     AND state = 'active' AND resource_version = ?6
                     AND expires_at > ?5)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = oci_registry_state.registry_id)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = oci_registry_state.registry_id
                       AND purge.state = 'collecting')
                   AND NOT EXISTS (SELECT 1 FROM oci_blobs deleting_blob
                     WHERE deleting_blob.registry_id = oci_registry_state.registry_id
                       AND deleting_blob.digest = ?4
                       AND deleting_blob.lifecycle_state <> 'active')",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.digest.to_string(),
                    input.now,
                    input.expected_resource_version
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_blobs SET unreferenced_since = NULL, updated_at = ?3
                 WHERE registry_id = (SELECT registry_id FROM oci_upload_sessions
                   WHERE id = ?1) AND digest = ?2 AND lifecycle_state = 'active'",
                vals![input.upload_id, input.digest.to_string(), input.now],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO oci_blob_claims(registry_id, digest, upload_id, claimed_at)
                 SELECT registry_id, ?4, id, ?5 FROM oci_upload_sessions
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'active' AND expires_at > ?5
                   AND resource_version = ?6
                   AND (expected_size IS NULL OR uploaded_size = expected_size)
                   AND sha256_total_bytes = uploaded_size
                   AND (expected_digest IS NULL OR expected_digest = ?4)
                   AND NOT EXISTS (SELECT 1 FROM oci_blobs stored_blob
                     WHERE stored_blob.registry_id = oci_upload_sessions.registry_id
                       AND stored_blob.digest = ?4
                       AND stored_blob.lifecycle_state = 'active')
                 ON CONFLICT(registry_id, digest) DO NOTHING",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.digest.to_string(),
                    input.now,
                    input.expected_resource_version
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_upload_sessions SET state = 'completing', final_digest = ?4,
                    materialization_placement_id =
                      COALESCE(materialization_placement_id, ?7),
                    materialization_placement_resource_version =
                      COALESCE(materialization_placement_resource_version, ?8),
                    materialization_binding_id =
                      COALESCE(materialization_binding_id, ?10),
                    materialization_binding_write_revision =
                      COALESCE(materialization_binding_write_revision, ?11),
                    expires_at = ?9,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND resource_version = ?6
                   AND expires_at > ?5
                   AND ((state = 'active' AND final_digest IS NULL
                         AND materialization_placement_id IS NULL
                         AND materialization_placement_resource_version IS NULL
                         AND materialization_binding_id IS NULL
                         AND materialization_binding_write_revision IS NULL
                         AND EXISTS (SELECT 1 FROM surface_placements placement
                           JOIN surface_placement_write_capabilities capability
                             ON capability.placement_id = placement.id
                            AND capability.placement_write_spec_version =
                                placement.write_spec_version
                           WHERE placement.id = ?7
                             AND placement.registry_id =
                                 oci_upload_sessions.registry_id
                             AND placement.resource_version = ?8
                             AND placement.binding_id = ?10
                             AND capability.binding_id = ?10
                             AND capability.binding_write_revision = ?11))
                     OR (state = 'completing' AND final_digest = ?4
                         AND materialization_placement_id = ?7
                         AND materialization_placement_resource_version = ?8
                         AND materialization_binding_id = ?10
                         AND materialization_binding_write_revision = ?11))
                   AND (expected_size IS NULL OR uploaded_size = expected_size)
                   AND sha256_total_bytes = uploaded_size
                   AND (expected_digest IS NULL OR expected_digest = ?4)
                   AND (EXISTS (SELECT 1 FROM oci_blob_claims claim
                          WHERE claim.upload_id = oci_upload_sessions.id
                            AND claim.digest = ?4)
                     OR EXISTS (SELECT 1 FROM oci_blobs stored_blob
                          WHERE stored_blob.registry_id = oci_upload_sessions.registry_id
                            AND stored_blob.digest = ?4
                            AND stored_blob.lifecycle_state = 'active'))",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.digest.to_string(),
                    input.now,
                    input.expected_resource_version,
                    input.materialization_placement_id,
                    input.materialization_placement_resource_version,
                    input.lease_expires_at,
                    input.materialization_binding_id,
                    input.materialization_binding_write_revision
                ],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(outcome) = self.oci_upload_claim_outcome(input).await? {
                return Ok(outcome);
            }
            let held = self
                .backend
                .query_opt(
                    "SELECT 1 FROM oci_blob_claims claim JOIN oci_upload_sessions upload
                       ON upload.registry_id = claim.registry_id
                     WHERE upload.id = ?1 AND claim.digest = ?2",
                    &vals![input.upload_id, input.digest.to_string()],
                )
                .await?
                .is_some();
            if held {
                return Ok(OciBlobClaimOutcome::InProgress);
            }
            return Err(error).context("claiming OCI upload digest");
        }
        self.oci_upload_claim_outcome(input)
            .await?
            .context("claimed OCI upload outcome disappeared")
    }

    /// Records exact immutable bytes observed immediately after a successful
    /// write to one registry placement.
    ///
    /// This is the narrow writer-admission path: it creates or validates the
    /// canonical logical object and one exact present-placement observation.
    /// Exact retries return the same evidence; identity drift is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence, an absent/mismatched placement,
    /// immutable identity drift, or database failure.
    pub async fn record_oci_uploaded_object(
        &self,
        registry_id: i64,
        placement_id: i64,
        digest: Sha256Digest,
        byte_size: u64,
        observed_etag: &str,
        now: i64,
    ) -> Result<OciUploadedObjectEvidence> {
        validate_session_identity(observed_etag, "uploaded object etag", 255)?;
        if registry_id <= 0 || placement_id <= 0 || now <= 0 {
            bail!("OCI uploaded-object evidence identity is invalid");
        }
        let size = checked_u64(byte_size, "uploaded object size")?;
        let object_key = oci_blob_object_key(digest);
        let surface_object_id = portable_relational_id(Uuid::new_v4());
        let partition_key = Sha256::digest(object_key.as_bytes()).to_vec();
        let statements = vec![
            Statement::new(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes,
                    charged_objects, updated_at)
                 SELECT id, 0, 0, 0, ?2 FROM registries WHERE id = ?1
                 ON CONFLICT(registry_id) DO NOTHING",
                vals![registry_id, now],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_registry_state
                 SET mutation_epoch = mutation_epoch + 1, updated_at = ?6
                 WHERE registry_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = ?1 AND purge.state = 'collecting')
                   AND NOT EXISTS (SELECT 1 FROM oci_blobs deleting_blob
                     WHERE deleting_blob.registry_id = ?1 AND deleting_blob.digest = ?2
                       AND deleting_blob.lifecycle_state <> 'active')
                   AND EXISTS (SELECT 1 FROM surface_placements placement
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     WHERE placement.id = ?7 AND placement.registry_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM surface_objects existing
                     JOIN object_placements presence
                       ON presence.surface_object_id = existing.id
                      AND presence.registry_id = existing.registry_id
                     WHERE existing.registry_id = ?1 AND existing.object_key = ?3
                       AND existing.lifecycle_state = 'active'
                       AND existing.content_hash = ?4 AND existing.size = ?5
                       AND presence.placement_id = ?7 AND presence.state = 'present'
                       AND presence.observed_hash = ?4 AND presence.observed_size = ?5
                       AND presence.etag = ?8)",
                vals![
                    registry_id,
                    digest.to_string(),
                    object_key.as_str(),
                    digest.encoded(),
                    size,
                    now,
                    placement_id,
                    observed_etag
                ],
            )
            .expecting(1),
            Statement::new(
                "INSERT INTO surface_objects
                   (id, registry_id, cache_id, object_key, object_kind,
                    partition_key, content_hash, size, mutable_publication_id,
                    lifecycle_state, tombstoned_at, created_at, updated_at,
                    resource_version)
                 SELECT ?1, ?2, NULL, ?3, 'immutable', ?4, ?5, ?6, NULL,
                        'active', NULL, ?7, ?7, 1
                 WHERE EXISTS (SELECT 1 FROM surface_placements placement
                   JOIN surface_placement_observations observation
                     ON observation.placement_id = placement.id
                   WHERE placement.id = ?8 AND placement.registry_id = ?2)
                 ON CONFLICT(registry_id, object_key) DO NOTHING",
                vals![
                    surface_object_id,
                    registry_id,
                    object_key,
                    partition_key,
                    digest.encoded(),
                    size,
                    now,
                    placement_id
                ],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO object_placements
                   (surface_object_id, cache_id, registry_id, placement_id,
                    state, observed_hash, observed_size, etag,
                    observed_inventory_generation, observed_at,
                    catalog_object_resource_version)
                 SELECT object.id, NULL, object.registry_id, placement.id,
                        'present', ?3, ?4, ?5,
                        COALESCE((SELECT MAX(existing.observed_inventory_generation)
                          FROM object_placements existing
                          WHERE existing.placement_id = placement.id), 0) + 1,
                        ?6, object.resource_version
                 FROM surface_objects object JOIN surface_placements placement
                   ON placement.id = ?7 AND placement.registry_id = object.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 WHERE object.registry_id = ?1 AND object.object_key = ?2
                   AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?3 AND object.size = ?4
                 ON CONFLICT(surface_object_id, placement_id) DO NOTHING",
                vals![
                    registry_id,
                    object_key,
                    digest.encoded(),
                    size,
                    observed_etag,
                    now,
                    placement_id
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE surface_objects SET resource_version = resource_version
                 WHERE registry_id = ?1 AND object_key = ?2
                   AND object_kind = 'immutable' AND lifecycle_state = 'active'
                   AND content_hash = ?3 AND size = ?4
                   AND EXISTS (SELECT 1 FROM object_placements presence
                     WHERE presence.surface_object_id = surface_objects.id
                       AND presence.registry_id = ?1 AND presence.placement_id = ?5
                       AND presence.state = 'present' AND presence.observed_hash = ?3
                       AND presence.observed_size = ?4 AND presence.etag = ?6
                       AND presence.observed_at = ?7
                       AND presence.catalog_object_resource_version =
                           surface_objects.resource_version)",
                vals![
                    registry_id,
                    object_key,
                    digest.encoded(),
                    size,
                    placement_id,
                    observed_etag,
                    now
                ],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_uploaded_object_evidence(
                    registry_id,
                    placement_id,
                    digest,
                    byte_size,
                    observed_etag,
                )
                .await?
            {
                return Ok(existing);
            }
            return Err(error).context("recording OCI uploaded-object evidence");
        }
        self.oci_uploaded_object_evidence(
            registry_id,
            placement_id,
            digest,
            byte_size,
            observed_etag,
        )
        .await?
        .context("recorded OCI uploaded-object evidence disappeared")
    }

    async fn oci_uploaded_object_evidence(
        &self,
        registry_id: i64,
        placement_id: i64,
        digest: Sha256Digest,
        byte_size: u64,
        observed_etag: &str,
    ) -> Result<Option<OciUploadedObjectEvidence>> {
        let size = checked_u64(byte_size, "uploaded object size")?;
        self.backend
            .query_opt(
                "SELECT object.id, presence.placement_id, object.resource_version,
                        placement.resource_version, observation.observation_version,
                        presence.observed_inventory_generation, presence.etag,
                        presence.observed_at
                 FROM surface_objects object JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 JOIN surface_placements placement ON placement.id = presence.placement_id
                   AND placement.registry_id = object.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 WHERE object.registry_id = ?1 AND object.object_key = ?2
                   AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?3 AND object.size = ?4
                   AND presence.placement_id = ?5 AND presence.state = 'present'
                   AND presence.observed_hash = ?3 AND presence.observed_size = ?4
                   AND presence.etag = ?6
                   AND presence.catalog_object_resource_version = object.resource_version",
                &vals![
                    registry_id,
                    oci_blob_object_key(digest),
                    digest.encoded(),
                    size,
                    placement_id,
                    observed_etag
                ],
            )
            .await?
            .map(|row| {
                Ok(OciUploadedObjectEvidence {
                    surface_object_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    object_resource_version: row.get(2)?,
                    placement_resource_version: row.get(3)?,
                    placement_observation_version: row.get(4)?,
                    observed_inventory_generation: row.get(5)?,
                    observed_etag: row.get(6)?,
                    observed_at: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Returns exact writer evidence recorded before upload completion.
    ///
    /// Materialization and relational completion are separate failure
    /// boundaries. This lookup lets a retry in `completing` state reuse the
    /// immutable object and placement observation instead of rewriting the
    /// same digest or abandoning the durable upload session.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted evidence.
    pub async fn oci_pending_uploaded_object_evidence(
        &self,
        registry_id: i64,
        placement_id: i64,
        digest: Sha256Digest,
        byte_size: u64,
    ) -> Result<Option<OciUploadedObjectEvidence>> {
        let size = checked_u64(byte_size, "uploaded object size")?;
        self.backend
            .query_opt(
                "SELECT object.id, presence.placement_id, object.resource_version,
                        placement.resource_version, observation.observation_version,
                        presence.observed_inventory_generation, presence.etag,
                        presence.observed_at
                 FROM surface_objects object JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 JOIN surface_placements placement ON placement.id = presence.placement_id
                   AND placement.registry_id = object.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 WHERE object.registry_id = ?1 AND object.object_key = ?2
                   AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?3 AND object.size = ?4
                   AND presence.placement_id = ?5 AND presence.state = 'present'
                   AND presence.observed_hash = ?3 AND presence.observed_size = ?4
                   AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version",
                &vals![
                    registry_id,
                    oci_blob_object_key(digest),
                    digest.encoded(),
                    size,
                    placement_id
                ],
            )
            .await?
            .map(|row| {
                Ok(OciUploadedObjectEvidence {
                    surface_object_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    object_resource_version: row.get(2)?,
                    placement_resource_version: row.get(3)?,
                    placement_observation_version: row.get(4)?,
                    observed_inventory_generation: row.get(5)?,
                    observed_etag: row.get(6)?,
                    observed_at: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Returns exact live placement evidence for an existing registry blob.
    ///
    /// A preferred placement is selected when it retains exact evidence;
    /// otherwise the lowest eligible placement id is returned. This allows a
    /// deduplicated upload to link the registry blob without rewriting bytes or
    /// manufacturing a new etag/observation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted evidence.
    pub async fn oci_blob_placement_evidence(
        &self,
        registry_id: i64,
        digest: Sha256Digest,
        preferred_placement_id: Option<i64>,
    ) -> Result<Option<OciUploadedObjectEvidence>> {
        self.backend
            .query_opt(
                "SELECT object.id, presence.placement_id, object.resource_version,
                        placement.resource_version, observation.observation_version,
                        presence.observed_inventory_generation, presence.etag,
                        presence.observed_at
                 FROM oci_blobs stored_blob JOIN surface_objects object
                   ON object.id = stored_blob.surface_object_id
                  AND object.registry_id = stored_blob.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 JOIN surface_placements placement ON placement.id = presence.placement_id
                   AND placement.registry_id = object.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 WHERE stored_blob.registry_id = ?1 AND stored_blob.digest = ?2
                   AND stored_blob.lifecycle_state = 'active'
                   AND object.object_key = ?3 AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?4 AND object.size = stored_blob.byte_size
                   AND presence.state = 'present' AND presence.observed_hash = ?4
                   AND presence.observed_size = stored_blob.byte_size
                   AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version
                 ORDER BY CASE WHEN presence.placement_id = ?5 THEN 0 ELSE 1 END,
                          presence.placement_id LIMIT 1",
                &vals![
                    registry_id,
                    digest.to_string(),
                    oci_blob_object_key(digest),
                    digest.encoded(),
                    preferred_placement_id
                ],
            )
            .await?
            .map(|row| {
                Ok(OciUploadedObjectEvidence {
                    surface_object_id: row.get(0)?,
                    placement_id: row.get(1)?,
                    object_resource_version: row.get(2)?,
                    placement_resource_version: row.get(3)?,
                    placement_observation_version: row.get(4)?,
                    observed_inventory_generation: row.get(5)?,
                    observed_etag: row.get(6)?,
                    observed_at: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Completes a claimed upload from independently observed immutable bytes,
    /// links it to the repository, and commits or releases quota exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership/version, digest/size mismatch,
    /// absent exact placement evidence, a conflicting immutable identity, or
    /// database failure.
    pub async fn complete_oci_upload(&self, input: &CompleteOciUpload) -> Result<OciUploadRecord> {
        if input.now <= 0 || input.expected_resource_version < 1 {
            bail!("OCI upload completion metadata is invalid");
        }
        let size = checked_u64(input.byte_size, "object size")?;
        let digest = input.digest.to_string();
        let encoded = input.digest.encoded();
        let object_key = oci_blob_object_key(input.digest);
        let statements = vec![
            Statement::new(
                "INSERT INTO oci_blobs
                   (registry_id, digest, byte_size, media_type, surface_object_id,
                    quota_bytes, lifecycle_state, created_at, updated_at)
                 SELECT upload.registry_id, ?4, ?5, ?6, object.id, ?5,
                        'active', ?7, ?7
                 FROM oci_upload_sessions upload
                 JOIN oci_blob_claims claim ON claim.upload_id = upload.id
                   AND claim.registry_id = upload.registry_id AND claim.digest = ?4
                 JOIN surface_objects object ON object.id = ?8
                   AND object.registry_id = upload.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                  AND presence.placement_id = ?9
                 WHERE upload.id = ?1 AND upload.writer_id = ?2
                   AND upload.token_id = ?3 AND upload.state = 'completing'
                   AND upload.resource_version = ?10
                   AND upload.expires_at > ?7 AND upload.final_digest = ?4
                   AND upload.uploaded_size = ?5
                   AND (upload.expected_size IS NULL OR upload.expected_size = ?5)
                   AND (upload.expected_digest IS NULL OR upload.expected_digest = ?4)
                   AND object.object_key = ?11 AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?12 AND object.size = ?5
                   AND presence.state = 'present'
                   AND presence.observed_hash = ?12 AND presence.observed_size = ?5
                   AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version
                 ON CONFLICT(registry_id, digest) DO NOTHING",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    digest,
                    size,
                    "application/octet-stream",
                    input.now,
                    input.surface_object_id,
                    input.placement_id,
                    input.expected_resource_version,
                    object_key,
                    encoded
                ],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO oci_repository_objects
                   (repository_id, registry_id, digest, object_kind, media_type, linked_at)
                 SELECT upload.repository_id, upload.registry_id, ?4, ?5, ?6, ?7
                 FROM oci_upload_sessions upload JOIN oci_blobs stored_blob
                   ON stored_blob.registry_id = upload.registry_id
                  AND stored_blob.digest = ?4
                 JOIN surface_objects object ON object.id = stored_blob.surface_object_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = stored_blob.registry_id
                  AND presence.placement_id = ?8
                 WHERE upload.id = ?1 AND upload.writer_id = ?2
                   AND upload.token_id = ?3 AND upload.state = 'completing'
                   AND upload.resource_version = ?9
                   AND upload.expires_at > ?7 AND upload.final_digest = ?4
                   AND stored_blob.byte_size = ?10
                   AND stored_blob.lifecycle_state = 'active'
                   AND object.content_hash = ?11 AND object.object_key = ?12
                   AND object.lifecycle_state = 'active'
                   AND presence.state = 'present' AND presence.observed_hash = ?11
                   AND presence.observed_size = ?10 AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version
                 ON CONFLICT(repository_id, digest) DO NOTHING",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    digest,
                    "blob",
                    "application/octet-stream",
                    input.now,
                    input.placement_id,
                    input.expected_resource_version,
                    size,
                    encoded,
                    object_key
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE org_usage
                 SET used_bytes = CASE WHEN used_bytes -
                       (CASE WHEN EXISTS (SELECT 1 FROM oci_blob_claims claim
                          WHERE claim.upload_id = ?1) THEN 0 ELSE
                          (SELECT reserved_bytes FROM oci_quota_reservations reservation
                           JOIN oci_upload_sessions upload
                             ON upload.quota_reservation_id = reservation.id
                           WHERE upload.id = ?1) END) < 0 THEN 0 ELSE
                       used_bytes - (CASE WHEN EXISTS (SELECT 1 FROM oci_blob_claims claim
                          WHERE claim.upload_id = ?1) THEN 0 ELSE
                          (SELECT reserved_bytes FROM oci_quota_reservations reservation
                           JOIN oci_upload_sessions upload
                             ON upload.quota_reservation_id = reservation.id
                           WHERE upload.id = ?1) END) END,
                     object_count = CASE WHEN EXISTS (SELECT 1 FROM oci_blob_claims claim
                       WHERE claim.upload_id = ?1) THEN object_count
                       WHEN object_count > 0 THEN object_count - 1 ELSE 0 END,
                     updated_at = ?2
                 WHERE org_id = (SELECT reservation.org_id
                   FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                     ON upload.quota_reservation_id = reservation.id
                   WHERE upload.id = ?1 AND upload.writer_id = ?3
                     AND upload.token_id = ?4 AND upload.state = 'completing'
                     AND upload.resource_version = ?5
                     AND upload.expires_at > ?2 AND upload.final_digest = ?6
                     AND reservation.state = 'reserved')",
                vals![
                    input.upload_id,
                    input.now,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    digest
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_quota_reservations SET
                   state = CASE WHEN EXISTS (SELECT 1 FROM oci_blob_claims claim
                     WHERE claim.upload_id = ?1) THEN 'committed' ELSE 'released' END,
                   updated_at = ?2
                 WHERE id = (SELECT quota_reservation_id FROM oci_upload_sessions
                   WHERE id = ?1 AND writer_id = ?3 AND token_id = ?4
                     AND state = 'completing' AND resource_version = ?5
                     AND expires_at > ?2 AND final_digest = ?6)
                   AND state = 'reserved'",
                vals![
                    input.upload_id,
                    input.now,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    digest
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_upload_sessions SET state = 'complete', finished_at = ?5,
                    cleanup_state = CASE WHEN EXISTS (SELECT 1 FROM oci_upload_chunks chunk
                      WHERE chunk.upload_id = oci_upload_sessions.id)
                      THEN 'pending' ELSE 'complete' END,
                    cleanup_finished_at = CASE WHEN EXISTS
                      (SELECT 1 FROM oci_upload_chunks chunk
                       WHERE chunk.upload_id = oci_upload_sessions.id)
                      THEN NULL ELSE ?5 END,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'completing' AND resource_version = ?4
                   AND expires_at > ?5 AND final_digest = ?6
                   AND EXISTS (SELECT 1 FROM oci_repository_objects link
                     WHERE link.repository_id = oci_upload_sessions.repository_id
                       AND link.registry_id = oci_upload_sessions.registry_id
                       AND link.digest = ?6)",
                vals![
                    input.upload_id,
                    input.writer_id,
                    input.token_id,
                    input.expected_resource_version,
                    input.now,
                    digest
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_blobs SET unreferenced_since = COALESCE(unreferenced_since, ?2),
                    updated_at = ?2
                 WHERE registry_id = (SELECT registry_id FROM oci_upload_sessions
                   WHERE id = ?1) AND digest = ?3 AND lifecycle_state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.registry_id = oci_blobs.registry_id
                       AND tag.digest = oci_blobs.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                     WHERE root.registry_id = oci_blobs.registry_id
                       AND root.index_digest = oci_blobs.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                     WHERE evidence.registry_id = oci_blobs.registry_id
                       AND evidence.referrer_digest = oci_blobs.digest
                       AND evidence.verification = 'verified')
                   AND NOT EXISTS (SELECT 1 FROM oci_upload_sessions upload
                     WHERE upload.registry_id = oci_blobs.registry_id
                       AND upload.state IN('active', 'completing')
                       AND (upload.expected_digest = oci_blobs.digest
                         OR upload.final_digest = oci_blobs.digest))
                   AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions publication
                     LEFT JOIN oci_publication_objects object
                       ON object.publication_id = publication.id
                      AND object.digest = oci_blobs.digest
                     WHERE publication.registry_id = oci_blobs.registry_id
                       AND publication.state IN('preparing', 'committing')
                       AND (publication.root_digest = oci_blobs.digest
                         OR object.digest IS NOT NULL))",
                vals![input.upload_id, input.now, digest],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes,
                    charged_objects, updated_at)
                 SELECT registry_id, 0, 0, 0, ?2 FROM oci_upload_sessions WHERE id = ?1
                 ON CONFLICT(registry_id) DO NOTHING",
                vals![input.upload_id, input.now],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_registry_state
                 SET mutation_epoch = mutation_epoch + 1,
                     charged_bytes = (SELECT COALESCE(SUM(byte_size), 0)
                       FROM oci_blobs WHERE registry_id = oci_registry_state.registry_id),
                     charged_objects = (SELECT COUNT(*) FROM oci_blobs
                       WHERE registry_id = oci_registry_state.registry_id),
                     updated_at = ?2
                 WHERE registry_id = (SELECT registry_id FROM oci_upload_sessions WHERE id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = oci_registry_state.registry_id)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = oci_registry_state.registry_id
                       AND purge.state = 'collecting')",
                vals![input.upload_id, input.now],
            )
            .expecting(1),
            Statement::new(
                "DELETE FROM oci_blob_claims WHERE upload_id = ?1",
                vals![input.upload_id],
            )
            .unchecked(),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_upload(
                    &input.upload_id,
                    &input.writer_id,
                    &input.token_id,
                    input.now,
                )
                .await?
            {
                if existing.state == "complete"
                    && existing.final_digest == Some(input.digest)
                    && existing.uploaded_size == input.byte_size
                    && existing
                        .expected_size
                        .is_none_or(|size| size == input.byte_size)
                    && existing
                        .expected_digest
                        .is_none_or(|digest| digest == input.digest)
                {
                    return Ok(existing);
                }
            }
            return Err(error).context("completing OCI upload");
        }
        self.oci_upload(
            &input.upload_id,
            &input.writer_id,
            &input.token_id,
            input.now,
        )
        .await?
        .context("completed OCI upload disappeared")
    }

    /// Cancels an active upload and releases its quota reservation atomically.
    /// Terminal exact retries return the existing cancelled record.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership/version, an already committed
    /// upload, or database failure.
    pub async fn cancel_oci_upload(
        &self,
        upload_id: &str,
        writer_id: &str,
        token_id: &str,
        expected_resource_version: i64,
        now: i64,
    ) -> Result<OciUploadRecord> {
        let statements = release_upload_statements(
            upload_id,
            Some(writer_id),
            Some(token_id),
            Some(expected_resource_version),
            now,
            "cancelled",
            false,
            false,
        );
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self.oci_upload(upload_id, writer_id, token_id, now).await? {
                if existing.state == "cancelled" {
                    return Ok(existing);
                }
            }
            return Err(error).context("cancelling OCI upload");
        }
        self.oci_upload(upload_id, writer_id, token_id, now)
            .await?
            .context("cancelled OCI upload disappeared")
    }

    /// Mounts an already-linked blob between repositories in one registry.
    ///
    /// The authorization layer must separately authorize pull on `source` and
    /// push on `destination`; the database prevents cross-registry linkage.
    ///
    /// # Errors
    ///
    /// Returns an error when the source link/object is absent, repositories
    /// differ in registry, or on database failure.
    pub async fn mount_oci_repository_blob(
        &self,
        source_repository_id: i64,
        destination_repository_id: i64,
        digest: Sha256Digest,
        now: i64,
    ) -> Result<()> {
        let statements = vec![
            Statement::new(
                "INSERT INTO oci_repository_objects
                   (repository_id, registry_id, digest, object_kind, media_type, linked_at)
                 SELECT destination.id, source.registry_id, link.digest,
                        link.object_kind, link.media_type, ?4
                 FROM oci_repository_objects link
                 JOIN oci_repositories source ON source.id = link.repository_id
                 JOIN oci_repositories destination ON destination.id = ?2
                   AND destination.registry_id = source.registry_id
                 JOIN oci_blobs stored_blob
                   ON stored_blob.registry_id = link.registry_id
                  AND stored_blob.digest = link.digest
                  AND stored_blob.lifecycle_state = 'active'
                 WHERE link.repository_id = ?1 AND link.digest = ?3
                   AND source.lifecycle_state = 'active'
                   AND destination.lifecycle_state = 'active'
                 ON CONFLICT(repository_id, digest) DO NOTHING",
                vals![
                    source_repository_id,
                    destination_repository_id,
                    digest.to_string(),
                    now
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_repositories SET resource_version = resource_version + 1,
                    updated_at = ?4
                 WHERE id = ?2 AND EXISTS (SELECT 1 FROM oci_repository_objects
                   WHERE repository_id = ?2 AND digest = ?3)",
                vals![
                    source_repository_id,
                    destination_repository_id,
                    digest.to_string(),
                    now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
                    updated_at = ?3
                 WHERE registry_id = (SELECT registry_id FROM oci_repositories WHERE id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     WHERE registry_lock.registry_id = oci_registry_state.registry_id)
                   AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                     WHERE purge.registry_id = oci_registry_state.registry_id
                       AND purge.state = 'collecting')",
                vals![source_repository_id, destination_repository_id, now],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }
}
fn release_upload_statements(
    upload_id: &str,
    writer_id: Option<&str>,
    token_id: Option<&str>,
    expected_resource_version: Option<i64>,
    now: i64,
    terminal_state: &'static str,
    require_expired: bool,
    allow_completing: bool,
) -> Vec<CheckedStatement> {
    let expiry_operator = if require_expired { "<=" } else { ">" };
    let ownership = if writer_id.is_some() {
        "AND upload.writer_id = ?2 AND upload.token_id = ?3
         AND upload.resource_version = ?4"
    } else {
        "AND ?2 IS NULL AND ?3 IS NULL AND ?4 IS NULL"
    };
    let eligible_states = if allow_completing {
        "upload.state IN('active', 'completing')"
    } else {
        "upload.state = 'active'"
    };
    let eligible = format!(
        "upload.id = ?1 {ownership} AND {eligible_states}
         AND upload.expires_at {expiry_operator} ?5"
    );
    let update_eligible = eligible.replace("upload.", "oci_upload_sessions.");
    vec![
        Statement::new(
            format!(
                "UPDATE org_usage SET
                   used_bytes = CASE WHEN used_bytes - (SELECT reservation.reserved_bytes
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE {eligible} AND reservation.state = 'reserved') < 0
                     THEN 0 ELSE used_bytes - (SELECT reservation.reserved_bytes
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE {eligible} AND reservation.state = 'reserved') END,
                   object_count = CASE WHEN object_count > 0 THEN object_count - 1 ELSE 0 END,
                   updated_at = ?5
                 WHERE org_id = (SELECT reservation.org_id
                   FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                     ON upload.quota_reservation_id = reservation.id
                   WHERE {eligible} AND reservation.state = 'reserved')"
            ),
            vals![
                upload_id,
                writer_id,
                token_id,
                expected_resource_version,
                now
            ],
        )
        .expecting(1),
        Statement::new(
            format!(
                "UPDATE oci_quota_reservations SET state = 'released', updated_at = ?5
                 WHERE id = (SELECT upload.quota_reservation_id FROM oci_upload_sessions upload
                   WHERE {eligible}) AND state = 'reserved'"
            ),
            vals![
                upload_id,
                writer_id,
                token_id,
                expected_resource_version,
                now
            ],
        )
        .expecting(1),
        Statement::new(
            "DELETE FROM oci_blob_claims WHERE upload_id = ?1",
            vals![upload_id],
        )
        .unchecked(),
        Statement::new(
            format!(
                "UPDATE oci_upload_sessions SET state = ?6, finished_at = ?5,
                    cleanup_state = CASE WHEN EXISTS (SELECT 1 FROM oci_upload_chunks chunk
                      WHERE chunk.upload_id = oci_upload_sessions.id)
                      THEN 'pending' ELSE 'complete' END,
                    cleanup_finished_at = CASE WHEN EXISTS
                      (SELECT 1 FROM oci_upload_chunks chunk
                       WHERE chunk.upload_id = oci_upload_sessions.id)
                      THEN NULL ELSE ?5 END,
                    resource_version = resource_version + 1
                 WHERE {update_eligible}"
            ),
            vals![
                upload_id,
                writer_id,
                token_id,
                expected_resource_version,
                now,
                terminal_state
            ],
        )
        .expecting(1),
    ]
}
