//! Placements mutations in the topology capability.

use super::*;

impl Database {
    /// Confirms equivalence of two exact ready, complete placements.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/cross-surface/incomplete placements, a
    /// duplicate pair or identity, malformed evidence, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_placement_equivalence(
        &self,
        stable_id: &str,
        creation_token: &str,
        placement_a_id: i64,
        placement_a_version: i64,
        placement_a_observation_version: i64,
        placement_b_id: i64,
        placement_b_version: i64,
        placement_b_observation_version: i64,
        physical_identity_fingerprint: &str,
        evidence_digest: &str,
        actor: &str,
    ) -> Result<PlacementEquivalenceRecord> {
        validate_key_bytes(stable_id, "placement equivalence id", 64)?;
        validate_key_bytes(creation_token, "placement equivalence creation token", 64)?;
        validate_key_bytes(
            physical_identity_fingerprint,
            "physical identity fingerprint",
            128,
        )?;
        validate_key_bytes(
            evidence_digest,
            "placement equivalence evidence digest",
            128,
        )?;
        let (a_id, a_version, a_observation_version, b_id, b_version, b_observation_version) =
            if placement_a_id < placement_b_id {
                (
                    placement_a_id,
                    placement_a_version,
                    placement_a_observation_version,
                    placement_b_id,
                    placement_b_version,
                    placement_b_observation_version,
                )
            } else {
                (
                    placement_b_id,
                    placement_b_version,
                    placement_b_observation_version,
                    placement_a_id,
                    placement_a_version,
                    placement_a_observation_version,
                )
            };
        let now = unix_now();
        let affected = self
            .backend
            .execute(
                "INSERT INTO placement_equivalences
                 (id, placement_a_id, placement_b_id, physical_identity_fingerprint,
                  evidence_digest, state, creation_token, confirmed_by, confirmed_at,
                  validation_revision, created_at, updated_at)
                 SELECT ?1, a.id, b.id, ?8, ?9, 'active', ?10, ?11, ?12, ?9, ?12, ?12
                 FROM surface_placements a JOIN surface_placement_observations ao
                   ON ao.placement_id = a.id
                 CROSS JOIN surface_placements b JOIN surface_placement_observations bo
                   ON bo.placement_id = b.id
                 WHERE a.id = ?2 AND a.resource_version = ?3
                   AND b.id = ?4 AND b.resource_version = ?5
                   AND ao.observation_version = ?6
                   AND bo.observation_version = ?7
                   AND (a.registry_id = b.registry_id OR a.cache_id = b.cache_id)
                   AND ao.state = 'ready' AND ao.completeness = 'complete'
                   AND bo.state = 'ready' AND bo.completeness = 'complete'",
                &vals![
                    stable_id,
                    a_id,
                    a_version,
                    b_id,
                    b_version,
                    a_observation_version,
                    b_observation_version,
                    physical_identity_fingerprint,
                    evidence_digest,
                    creation_token,
                    actor,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("equivalence placements are missing, stale, cross-surface, or incomplete");
        }
        self.placement_equivalence(stable_id)
            .await?
            .context("created placement equivalence disappeared")
    }

    /// Deletes one placement equivalence under resource-version CAS.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_placement_equivalence(
        &self,
        stable_id: &str,
        expected_resource_version: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM placement_equivalences
                 WHERE id = ?1 AND resource_version = ?2",
                &vals![stable_id, expected_resource_version],
            )
            .await?
            == 1)
    }

    /// Lists physical placement operations eligible for a controller claim.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn due_surface_placement_scan_operations(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<TopologyOperationRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {OPERATION_COLUMNS} FROM topology_operations operation
                     WHERE operation.operation_kind IN
                       ('scan_placement', 'replicate_placement', 'repair_placement')
                       AND (operation.state = 'pending'
                         OR (operation.state = 'running' AND (
                           NOT EXISTS (SELECT 1 FROM placement_scan_claims claim
                             WHERE claim.operation_id = operation.operation_id)
                           OR EXISTS (SELECT 1 FROM placement_scan_claims claim
                             WHERE claim.operation_id = operation.operation_id
                               AND claim.lease_expires_at <= ?1))))
                     ORDER BY operation.created_at, operation.operation_id LIMIT ?2"
                ),
                &vals![now, i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_topology_operation)
            .collect()
    }

    /// Claims one pending or stale-running physical placement operation under CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease or database failure.
    pub async fn claim_surface_placement_scan_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        lease_seconds: i64,
    ) -> Result<Option<TopologyOperationRecord>> {
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        if lease_seconds <= 0 {
            bail!("placement scan claim lease must be positive");
        }
        let now = unix_now();
        let lease_expires_at = now
            .checked_add(lease_seconds)
            .context("placement scan claim deadline overflowed")?;
        let claimed_version = expected_version
            .checked_add(1)
            .context("placement scan claim version overflowed")?;
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations
                     SET state = 'running',
                         started_at = CASE WHEN state = 'pending' THEN ?3 ELSE started_at END,
                         finished_at = NULL, error = NULL,
                         resource_version = resource_version + 1
                     WHERE operation_id = ?1 AND operation_kind IN
                       ('scan_placement', 'replicate_placement', 'repair_placement')
                       AND resource_version = ?2
                       AND (state = 'pending' OR (state = 'running' AND (
                         NOT EXISTS (SELECT 1 FROM placement_scan_claims claim
                           WHERE claim.operation_id = topology_operations.operation_id)
                         OR EXISTS (SELECT 1 FROM placement_scan_claims claim
                           WHERE claim.operation_id = topology_operations.operation_id
                             AND claim.lease_expires_at <= ?3))))",
                    vals![operation_id, expected_version, now],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM placement_scan_claims
                     WHERE operation_id = ?1
                       AND EXISTS (SELECT 1 FROM topology_operations operation
                         WHERE operation.operation_id = ?1
                           AND operation.resource_version = ?2)",
                    vals![operation_id, claimed_version],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO placement_scan_claims
                       (operation_id, claim_token, operation_resource_version,
                        heartbeat_at, lease_expires_at)
                     SELECT operation_id, ?3, resource_version, ?4, ?5
                     FROM topology_operations
                     WHERE operation_id = ?1 AND resource_version = ?2
                       AND state = 'running'",
                    vals![
                        operation_id,
                        claimed_version,
                        claim_token,
                        now,
                        lease_expires_at
                    ],
                )
                .expecting(1),
            ])
            .await;
        if let Err(error) = result {
            let claim = self
                .backend
                .query_opt(
                    "SELECT claim_token FROM placement_scan_claims
                     WHERE operation_id = ?1 AND operation_resource_version = ?2",
                    &vals![operation_id, claimed_version],
                )
                .await?;
            if claim
                .as_ref()
                .and_then(|row| row.get::<String>(0).ok())
                .as_deref()
                == Some(claim_token)
            {
                return self.topology_operation(operation_id).await;
            }
            if claim.is_some()
                || self
                    .topology_operation(operation_id)
                    .await?
                    .is_some_and(|operation| operation.resource_version != claimed_version)
            {
                return Ok(None);
            }
            return Err(error).context("persisting placement scan claim");
        }
        self.topology_operation(operation_id).await
    }

    /// Renews one live physical-placement scan claim under its opaque fence.
    ///
    /// # Errors
    ///
    /// Returns an error when the claim expired or was replaced, the deadline is
    /// invalid, or persistence fails.
    pub async fn heartbeat_surface_placement_scan_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        heartbeat_at: i64,
        lease_seconds: i64,
    ) -> Result<()> {
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        if lease_seconds <= 0 {
            bail!("placement scan claim lease must be positive");
        }
        if heartbeat_at < 0 {
            bail!("placement scan heartbeat time is invalid");
        }
        let lease_expires_at = heartbeat_at
            .checked_add(lease_seconds)
            .context("placement scan heartbeat deadline overflowed")?;
        self.backend
            .checked_batch(&[Statement::new(
                "UPDATE placement_scan_claims
                 SET heartbeat_at = ?4, lease_expires_at = ?5
                 WHERE operation_id = ?1 AND operation_resource_version = ?2
                   AND claim_token = ?3 AND lease_expires_at > ?4
                   AND EXISTS (SELECT 1 FROM topology_operations operation
                     WHERE operation.operation_id = ?1
                       AND operation.resource_version = ?2
                       AND operation.state = 'running')",
                vals![
                    operation_id,
                    expected_version,
                    claim_token,
                    heartbeat_at,
                    lease_expires_at
                ],
            )
            .expecting(1)])
            .await
    }

    /// Terminalizes one live physical-placement operation under its exact claim.
    ///
    /// Returns `false` without mutation when the claim expired or was replaced.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid terminal state or progress, malformed
    /// detail, or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_claimed_surface_placement_scan_operation(
        &self,
        operation_id: &str,
        expected_version: i64,
        claim_token: &str,
        state: &str,
        progress_current: i64,
        progress_total: Option<i64>,
        detail_json: &str,
        error: Option<&str>,
        finished_at: i64,
    ) -> Result<bool> {
        validate_key_bytes(operation_id, "placement scan operation id", 64)?;
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        if !matches!((state, error), ("succeeded", None) | ("failed", Some(_))) {
            bail!("placement scan terminal state and error are inconsistent");
        }
        if progress_current < 0
            || progress_total.is_some_and(|total| total < progress_current)
            || finished_at < 0
        {
            bail!("placement scan terminal progress or time is invalid");
        }
        validate_json_value(detail_json, "placement scan operation detail")?;

        let affected = self
            .backend
            .execute(
                "UPDATE topology_operations
                 SET state = ?4, progress_current = ?5, progress_total = ?6,
                     detail_json = ?7, error = ?8, finished_at = ?9,
                     resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND resource_version = ?2
                   AND operation_kind IN
                     ('scan_placement', 'replicate_placement', 'repair_placement')
                   AND state = 'running'
                   AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                     WHERE claim.operation_id = topology_operations.operation_id
                       AND claim.operation_resource_version = ?2
                       AND claim.claim_token = ?3
                       AND claim.lease_expires_at > ?9)",
                &vals![
                    operation_id,
                    expected_version,
                    claim_token,
                    state,
                    progress_current,
                    progress_total,
                    detail_json,
                    error,
                    finished_at
                ],
            )
            .await?;
        if affected == 0 {
            return Ok(false);
        }
        self.backend
            .execute(
                "DELETE FROM placement_scan_claims
                 WHERE operation_id = ?1 AND claim_token = ?2",
                &vals![operation_id, claim_token],
            )
            .await?;
        Ok(true)
    }

    /// Returns the indexed strong version for one image object placement.
    pub async fn registry_image_placement_etag(
        &self,
        registry_id: i64,
        placement_id: i64,
        object_key: &str,
    ) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT presence.etag
                 FROM object_placements presence
                 JOIN surface_objects object ON object.id = presence.surface_object_id
                 WHERE presence.registry_id = ?1 AND presence.placement_id = ?2
                   AND object.object_key = ?3 AND presence.state = 'present'
                   AND presence.etag IS NOT NULL",
                &vals![registry_id, placement_id, object_key],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Returns publication-verified identity evidence for one object placement.
    ///
    /// The result exists only when the current publication declared the exact
    /// object, the selected required placement reached `ready`, and its
    /// durable publication receipt still matches the declaration byte-for-byte.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed keys or a database failure.
    pub async fn registry_publication_verified_object_at_placement(
        &self,
        publication_id: &str,
        placement_id: i64,
        object_key: &str,
    ) -> Result<Option<VerifiedRegistryImageObject>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(object_key, "surface object key", 512)?;
        self.backend
            .query_opt(
                "SELECT declared.expected_hash, declared.expected_size, evidence.strong_etag
                 FROM registry_publications publication
                 JOIN registry_publication_objects declared
                   ON declared.publication_id = publication.publication_id
                 JOIN surface_objects object
                   ON object.id = declared.surface_object_id
                  AND object.registry_id = publication.registry_id
                 JOIN registry_publication_placements required
                   ON required.publication_id = publication.publication_id
                  AND required.placement_id = ?2
                  AND required.required = 1 AND required.state = 'ready'
                 JOIN registry_publication_object_evidence evidence
                   ON evidence.publication_id = publication.publication_id
                  AND evidence.surface_object_id = object.id
                  AND evidence.placement_id = required.placement_id
                 WHERE publication.publication_id = ?1
                   AND publication.state = 'ready'
                   AND object.object_key = ?3
                   AND evidence.observed_hash = declared.expected_hash
                   AND evidence.observed_size = declared.expected_size
                   AND evidence.strong_etag IS NOT NULL",
                &vals![publication_id, placement_id, object_key],
            )
            .await?
            .map(|row| {
                Ok(VerifiedRegistryImageObject {
                    object_key: object_key.to_string(),
                    sha256: row.get(0)?,
                    byte_size: row.get(1)?,
                    strong_etag: row.get(2)?,
                })
            })
            .transpose()
    }
}
