//! Uploads mutations in the caches capability.

use super::*;

impl Database {
    /// Lists the exact object manifest declared by a publication.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_upload_objects(
        &self,
        publication_id: &str,
    ) -> Result<Vec<RegistryPublicationUploadObjectRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .query(
                "SELECT po.publication_id, po.registry_id, po.surface_object_id,
                        object.object_key, po.object_kind, po.expected_hash,
                        po.expected_size,
                        CASE WHEN EXISTS (
                          SELECT 1 FROM registry_publication_placements required
                          WHERE required.publication_id = po.publication_id
                            AND required.required = 1)
                        AND NOT EXISTS (
                          SELECT 1 FROM registry_publication_placements required
                          WHERE required.publication_id = po.publication_id
                            AND required.required = 1
                            AND NOT EXISTS (
                              SELECT 1 FROM object_placements presence
                              WHERE presence.surface_object_id = po.surface_object_id
                                AND presence.placement_id = required.placement_id
                                AND presence.state = 'present'
                                AND presence.observed_hash = po.expected_hash
                                AND presence.observed_size = po.expected_size))
                        THEN 1 ELSE 0 END
                 FROM registry_publication_objects po
                 JOIN surface_objects object ON object.id = po.surface_object_id
                 WHERE po.publication_id = ?1
                 ORDER BY CASE po.object_kind WHEN 'immutable' THEN 0 ELSE 1 END,
                          object.object_key, object.id",
                &vals![publication_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RegistryPublicationUploadObjectRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    surface_object_id: row.get(2)?,
                    object_key: row.get(3)?,
                    object_kind: row.get(4)?,
                    expected_hash: row.get(5)?,
                    expected_size: row.get(6)?,
                    verified: row.get(7)?,
                })
            })
            .collect()
    }

    /// Returns one declared publication object by its typed upload identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_upload_object(
        &self,
        publication_id: &str,
        surface_object_id: i64,
    ) -> Result<Option<RegistryPublicationUploadObjectRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .query_opt(
                "SELECT po.publication_id, po.registry_id, po.surface_object_id,
                        object.object_key, po.object_kind, po.expected_hash,
                        po.expected_size,
                        CASE WHEN EXISTS (
                          SELECT 1 FROM registry_publication_placements required
                          WHERE required.publication_id = po.publication_id
                            AND required.required = 1)
                        AND NOT EXISTS (
                          SELECT 1 FROM registry_publication_placements required
                          WHERE required.publication_id = po.publication_id
                            AND required.required = 1
                            AND NOT EXISTS (
                              SELECT 1 FROM object_placements presence
                              WHERE presence.surface_object_id = po.surface_object_id
                                AND presence.placement_id = required.placement_id
                                AND presence.state = 'present'
                                AND presence.observed_hash = po.expected_hash
                                AND presence.observed_size = po.expected_size))
                        THEN 1 ELSE 0 END
                 FROM registry_publication_objects po
                 JOIN surface_objects object ON object.id = po.surface_object_id
                 WHERE po.publication_id = ?1 AND po.surface_object_id = ?2",
                &vals![publication_id, surface_object_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationUploadObjectRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    surface_object_id: row.get(2)?,
                    object_key: row.get(3)?,
                    object_kind: row.get(4)?,
                    expected_hash: row.get(5)?,
                    expected_size: row.get(6)?,
                    verified: row.get(7)?,
                })
            })
            .transpose()
    }

    /// Returns one durable registry-publication multipart upload.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed upload id or database failure.
    pub async fn registry_publication_multipart_upload(
        &self,
        upload_id: &str,
    ) -> Result<Option<RegistryPublicationMultipartUploadRecord>> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        self.backend
            .query_opt(
                "SELECT upload_id, publication_id, registry_id, surface_object_id,
                        state, expires_at, hashed_size, sha256_state,
                        pending_part, pending_hash, pending_token, pending_since,
                        completion_token, completion_since
                 FROM registry_publication_multipart_uploads WHERE upload_id = ?1",
                &vals![upload_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationMultipartUploadRecord {
                    upload_id: row.get(0)?,
                    publication_id: row.get(1)?,
                    registry_id: row.get(2)?,
                    surface_object_id: row.get(3)?,
                    state: row.get(4)?,
                    expires_at: row.get(5)?,
                    hashed_size: row.get(6)?,
                    sha256_state: row.get(7)?,
                    pending_part: row.get(8)?,
                    pending_hash: row.get(9)?,
                    pending_token: row.get(10)?,
                    pending_since: row.get(11)?,
                    completion_token: row.get(12)?,
                    completion_since: row.get(13)?,
                })
            })
            .transpose()
    }

    /// Returns the active multipart upload for one publication object.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities or database failure.
    pub async fn active_registry_publication_multipart_upload(
        &self,
        publication_id: &str,
        surface_object_id: i64,
    ) -> Result<Option<RegistryPublicationMultipartUploadRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        let row = self
            .backend
            .query_opt(
                "SELECT upload_id FROM registry_publication_multipart_uploads
                 WHERE publication_id = ?1 AND surface_object_id = ?2
                   AND active_object_slot = 1",
                &vals![publication_id, surface_object_id],
            )
            .await?;
        match row {
            Some(row) => {
                self.registry_publication_multipart_upload(&row.get::<String>(0)?)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Lists every active multipart upload owned by one publication.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed publication id or database failure.
    pub async fn active_registry_publication_multipart_uploads(
        &self,
        publication_id: &str,
    ) -> Result<Vec<RegistryPublicationMultipartUploadRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        let rows = self
            .backend
            .query(
                "SELECT upload_id FROM registry_publication_multipart_uploads
                 WHERE publication_id = ?1 AND active_object_slot = 1
                 ORDER BY upload_id",
                &vals![publication_id],
            )
            .await?;
        let mut uploads = Vec::with_capacity(rows.len());
        for row in rows {
            uploads.push(
                self.registry_publication_multipart_upload(&row.get::<String>(0)?)
                    .await?
                    .context("active publication multipart upload disappeared")?,
            );
        }
        Ok(uploads)
    }

    /// Creates one durable multipart upload after every backend has admitted it.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, invalid backend JSON, an
    /// existing active upload for the object, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_registry_publication_multipart_upload(
        &self,
        upload_id: &str,
        publication_id: &str,
        registry_id: i64,
        surface_object_id: i64,
        expires_at: i64,
        now: i64,
        placements: &[(i64, i64)],
    ) -> Result<RegistryPublicationMultipartUploadRecord> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(publication_id, "publication id", 64)?;
        if expires_at <= now {
            bail!("publication multipart expiry must be in the future");
        }
        let mut statements = vec![Statement::new(
            "INSERT INTO registry_publication_multipart_uploads
                 (upload_id, publication_id, registry_id, surface_object_id,
                  state, active_object_slot, expires_at,
                  created_at, finished_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', 1, ?5, ?6, NULL)",
            vals![
                upload_id,
                publication_id,
                registry_id,
                surface_object_id,
                expires_at,
                now
            ],
        )
        .expecting(1)];
        for (placement_id, placement_resource_version) in placements {
            statements.push(
                Statement::new(
                    "INSERT INTO registry_publication_multipart_backends
                 (upload_id, placement_id, placement_resource_version,
                  backend_upload_id, state)
                 VALUES (?1, ?2, ?3, NULL, 'creating')",
                    vals![upload_id, placement_id, placement_resource_version],
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await?;
        self.registry_publication_multipart_upload(upload_id)
            .await?
            .context("created publication multipart upload disappeared")
    }

    /// Lists every ready provider upload identity for one durable transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed upload id or database failure.
    pub async fn registry_publication_multipart_backends(
        &self,
        upload_id: &str,
    ) -> Result<Vec<(i64, i64, String, Option<String>)>> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        self.backend
            .query(
                "SELECT placement_id, placement_resource_version, backend_upload_id,
                        completion_etag
                 FROM registry_publication_multipart_backends
                 WHERE upload_id = ?1 AND state = 'ready'
                 ORDER BY placement_id",
                &vals![upload_id],
            )
            .await?
            .iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .collect()
    }

    /// Returns whether a durable multipart transaction has unresolved backend creation.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed upload id or database failure.
    pub async fn registry_publication_multipart_has_creating_backend(
        &self,
        upload_id: &str,
    ) -> Result<bool> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publication_multipart_backends
                 WHERE upload_id = ?1 AND state = 'creating' LIMIT 1",
                &vals![upload_id],
            )
            .await?
            .is_some())
    }

    /// Advances an active multipart upload into its idempotent completion phase.
    ///
    /// A retry carrying the durable completion token renews the same logical
    /// completion. A different request may only take ownership after the lease
    /// expires.
    ///
    /// # Errors
    ///
    /// Returns an error when the upload is not active/completing or persistence fails.
    pub async fn begin_registry_publication_multipart_completion(
        &self,
        upload_id: &str,
        completion_token: &str,
        claimed_at: i64,
        steal_before: i64,
    ) -> Result<RegistryPublicationMultipartUploadRecord> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(completion_token, "multipart completion token", 64)?;
        anyhow::ensure!(
            claimed_at > steal_before,
            "multipart completion claim is invalid"
        );
        let updated = self
            .backend
            .execute(
                "UPDATE registry_publication_multipart_uploads
                 SET state = 'completing', completion_token = ?2, completion_since = ?3
                 WHERE upload_id = ?1
                   AND ((state = 'active' AND completion_token IS NULL
                         AND completion_since IS NULL)
                     OR (state = 'completing' AND completion_token = ?2)
                     OR (state = 'completing' AND completion_since <= ?4))",
                &vals![upload_id, completion_token, claimed_at, steal_before],
            )
            .await?;
        anyhow::ensure!(updated == 1, "multipart completion is already owned");
        self.registry_publication_multipart_upload(upload_id)
            .await?
            .filter(|upload| {
                upload.state == "completing"
                    && upload.completion_token.as_deref() == Some(completion_token)
            })
            .context("publication multipart upload is not completable")
    }

    /// Atomically records every placement identity for one uploaded part.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, an invalid part number or
    /// entity tag, an inactive upload, or database failure.
    pub async fn record_registry_publication_multipart_part(
        &self,
        upload_id: &str,
        part_number: u32,
        placements: &[(i64, String)],
        prior_hashed_size: i64,
        hashed_size: i64,
        sha256_state: &str,
        pending_hash: &str,
        pending_token: &str,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(pending_hash, "publication multipart part hash", 64)?;
        validate_key_bytes(pending_token, "publication multipart claim token", 64)?;
        if part_number == 0 || placements.is_empty() || hashed_size <= prior_hashed_size {
            bail!("publication multipart part identity is incomplete");
        }
        validate_key_bytes(sha256_state, "publication SHA-256 state", 64)?;
        if sha256_state.len() != 64 || !sha256_state.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("publication SHA-256 state is invalid");
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut statements = Vec::with_capacity(placements.len() + 1);
        statements.push(
            Statement::new(
                "UPDATE registry_publication_multipart_uploads
                 SET hashed_size = ?3, sha256_state = ?4,
                     pending_part = NULL, pending_hash = NULL,
                     pending_token = NULL, pending_since = NULL
                 WHERE upload_id = ?1 AND state = 'active' AND hashed_size = ?2
                   AND pending_part = ?5 AND pending_hash = ?6
                   AND pending_token = ?7",
                vals![
                    upload_id,
                    prior_hashed_size,
                    hashed_size,
                    sha256_state,
                    i64::from(part_number),
                    pending_hash,
                    pending_token
                ],
            )
            .expecting(1),
        );
        for (placement_id, etag) in placements {
            if !seen.insert(*placement_id) || etag.is_empty() || etag.len() > 1024 {
                bail!("publication multipart placement identity is invalid");
            }
            statements.push(
                Statement::new(
                    "INSERT INTO registry_publication_multipart_parts
                 (upload_id, part_number, placement_id, etag)
                 SELECT ?1, ?2, ?3, ?4
                 WHERE EXISTS (SELECT 1 FROM registry_publication_multipart_uploads
                   WHERE upload_id = ?1 AND state = 'active' AND hashed_size = ?5)",
                    vals![
                        upload_id,
                        i64::from(part_number),
                        placement_id,
                        etag,
                        hashed_size
                    ],
                )
                .expecting(1),
            );
        }
        self.backend.checked_batch(&statements).await
    }

    /// Claims the next contiguous part before any provider side effect.
    ///
    /// A claim serializes writes for a part until the complete provider
    /// transaction is explicitly aborted. It is never stolen on the same
    /// provider upload because a timed-out writer may still have an in-flight
    /// side effect.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed claim data, an inactive upload, a
    /// conflicting claim, stale hash progress, or database failure.
    pub async fn claim_registry_publication_multipart_part(
        &self,
        upload_id: &str,
        part_number: u32,
        body_hash: &str,
        hashed_size: i64,
        claim_token: &str,
        claimed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(body_hash, "publication multipart part hash", 64)?;
        validate_key_bytes(claim_token, "publication multipart claim token", 64)?;
        if claimed_at < 0 {
            bail!("publication multipart claim lease is invalid");
        }
        if body_hash.len() != 64
            || !body_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("publication multipart part hash is invalid");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE registry_publication_multipart_uploads
                 SET pending_part = ?2, pending_hash = ?3,
                     pending_token = ?5, pending_since = ?6
                 WHERE upload_id = ?1 AND state = 'active' AND hashed_size = ?4
                   AND pending_part IS NULL AND pending_hash IS NULL
                   AND pending_token IS NULL AND pending_since IS NULL",
                vals![
                    upload_id,
                    i64::from(part_number),
                    body_hash,
                    hashed_size,
                    claim_token,
                    claimed_at
                ],
            )
            .expecting(1)])
            .await
    }

    /// Records the strong object identity returned by provider completion.
    pub async fn record_registry_publication_multipart_completion_etag(
        &self,
        upload_id: &str,
        placement_id: i64,
        etag: &str,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(etag, "multipart completion ETag", 1024)?;
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE registry_publication_multipart_backends SET completion_etag = ?3
             WHERE upload_id = ?1 AND placement_id = ?2 AND state = 'ready'
               AND (completion_etag IS NULL OR completion_etag = ?3)",
                vals![upload_id, placement_id, etag],
            )
            .expecting(1)])
            .await
    }

    /// Lists durable backend identities for every confirmed upload part.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed upload id, invalid persisted part
    /// numbers, or database failure.
    pub async fn registry_publication_multipart_parts(
        &self,
        upload_id: &str,
    ) -> Result<Vec<RegistryPublicationMultipartPartRecord>> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        self.backend
            .query(
                "SELECT upload_id, part_number, placement_id, etag
                 FROM registry_publication_multipart_parts
                 WHERE upload_id = ?1 ORDER BY part_number, placement_id",
                &vals![upload_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RegistryPublicationMultipartPartRecord {
                    upload_id: row.get(0)?,
                    part_number: u32::try_from(row.get::<i64>(1)?)?,
                    placement_id: row.get(2)?,
                    etag: row.get(3)?,
                })
            })
            .collect()
    }

    /// Finishes one active multipart upload with a terminal state.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid terminal state, lifecycle conflict, or
    /// database failure.
    pub async fn finish_registry_publication_multipart_upload(
        &self,
        upload_id: &str,
        state: &str,
        now: i64,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        if !matches!(state, "completed" | "aborted" | "failed") {
            bail!("invalid publication multipart terminal state");
        }
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE registry_publication_multipart_uploads
                     SET state = ?2, active_object_slot = NULL, finished_at = ?3
                     WHERE upload_id = ?1 AND state IN('active', 'completing')",
                vals![upload_id, state, now],
            )
            .expecting(1)])
            .await
    }

    /// Finishes a multipart completion only for its current durable owner.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, lost completion ownership,
    /// or database failure.
    pub async fn finish_owned_registry_publication_multipart_completion(
        &self,
        upload_id: &str,
        completion_token: &str,
        finished_at: i64,
    ) -> Result<()> {
        validate_key_bytes(upload_id, "publication multipart upload id", 64)?;
        validate_key_bytes(completion_token, "multipart completion token", 64)?;
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE registry_publication_multipart_uploads
                 SET state = 'completed', active_object_slot = NULL,
                     finished_at = ?3
                 WHERE upload_id = ?1 AND state = 'completing'
                   AND completion_token = ?2",
                vals![upload_id, completion_token, finished_at],
            )
            .expecting(1)])
            .await
    }
}
