//! Placements mutations in the topology capability.

use super::*;

impl Database {
    /// Atomically applies an index snapshot from an exact authoritative placement.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-authoritative source, malformed snapshot, or
    /// database failure.
    pub async fn apply_snapshot_from_placement(
        &self,
        registry_id: i64,
        snapshot: &IndexSnapshot,
        indexed_placement_id: Option<i64>,
    ) -> Result<()> {
        self.apply_snapshot_transaction(registry_id, snapshot, indexed_placement_id, None)
            .await
    }

    /// Mark a registry's index `empty`: it was indexed successfully and there is
    /// nothing published yet (no `info/refs` surface).
    ///
    /// This is a *terminal success* state — the index ran to completion and
    /// found no content — distinct from `pending` (a transient backend hiccup
    /// awaiting retry) and from `failed` (a real error). `indexed_at` is stamped
    /// so the registry reads as "checked, nothing here" rather than "never
    /// indexed", and the last-commit / refs-digest are cleared so the next pass
    /// (once something is published) takes the full index path, not the
    /// unchanged-refs fast path.
    ///
    /// # Errors
    ///
    /// Returns an error when `placement_id` is not the authoritative reconciled
    /// reader for the registry, or on database failure.
    pub async fn mark_index_empty_from_placement(
        &self,
        registry_id: i64,
        placement_id: i64,
    ) -> Result<()> {
        self.assert_registry_index_mutation_source(registry_id, Some(placement_id))
            .await?;
        let generation = self
            .index_status(registry_id)
            .await?
            .context("empty registry has no index state")?
            .generation;
        let next_generation = generation
            .checked_add(1)
            .context("registry index generation overflowed")?;
        let digest = hex::encode(sha2::Sha256::digest(b"registry-index:empty"));
        let statements = vec![
            Statement::new(
                "DELETE FROM object_placements
                     WHERE registry_id = ?1 AND surface_object_id IN (
                       SELECT id FROM surface_objects
                       WHERE registry_id = ?1 AND object_key LIKE 'images/sha256/%')",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM registry_image_roots WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM registry_system_images WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM cache_root_release_provenance WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM release_artifact_snapshot_heads WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM release_artifacts WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM release_artifact_snapshots WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM registry_public_catalog_heads WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM releases WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM channels WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM package_documentation WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM packages WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM key_rosters WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM registry_cache_stack_entries WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM registry_catalog_artifacts WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "DELETE FROM image_snapshot_references WHERE registry_id = ?1",
                vals![registry_id].to_vec(),
            ),
            Statement::new(
                "UPDATE image_snapshots SET state = 'collectible'
                     WHERE NOT EXISTS (
                       SELECT 1 FROM image_snapshot_references reference
                       WHERE reference.digest = image_snapshots.digest)",
                Vec::new(),
            ),
            Statement::new(
                "DELETE FROM registry_index
                     WHERE registry_id = ?1 AND generation = ?2",
                vals![registry_id, generation].to_vec(),
            ),
            Statement::new(
                "INSERT INTO registry_index
                     (registry_id, state, error, last_indexed_commit, name,
                      description, readme, indexed_at, refs_digest, cache_stack,
                      generation, content_digest, documentation_projection_generation)
                     VALUES (?1, 'empty', NULL, NULL, NULL, NULL, NULL, ?2,
                             NULL, NULL, ?3, ?4, 1)",
                vals![registry_id, unix_now(), next_generation, digest].to_vec(),
            ),
        ];
        let statement_count = statements.len();
        let mut checked = vec![Self::registry_index_mutation_guard(
            registry_id,
            Some(placement_id),
        )];
        checked.extend(
            statements
                .into_iter()
                .enumerate()
                .map(|(index, statement)| {
                    if index + 2 >= statement_count {
                        statement.expecting(1)
                    } else {
                        statement.unchecked()
                    }
                }),
        );
        self.backend.checked_batch(&checked).await
    }

    /// Lists the physical placements frozen into a publication manifest.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_placement_records(
        &self,
        publication_id: &str,
    ) -> Result<Vec<RegistryPublicationPlacementRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .query(
                "SELECT publication_id, registry_id, placement_id, required,
                        state, observed_at
                 FROM registry_publication_placements
                 WHERE publication_id = ?1 ORDER BY placement_id",
                &vals![publication_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(RegistryPublicationPlacementRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    placement_id: row.get(2)?,
                    required: row.get(3)?,
                    state: row.get(4)?,
                    observed_at: row.get(5)?,
                })
            })
            .collect()
    }

    /// Records non-authoritative per-placement publication progress.
    ///
    /// Only [`Database::finalize_registry_pointer_advance`] may mark a placement
    /// ready, because readiness must be coupled to its authoritative watermark.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid progress, cross-registry placement, incomplete presence, or database failure.
    pub async fn set_registry_publication_placement(
        &self,
        input: &SetRegistryPublicationPlacement,
    ) -> Result<RegistryPublicationPlacementRecord> {
        if !matches!(input.state.as_str(), "preparing" | "failed" | "retired") {
            bail!("invalid publication-placement state '{}'", input.state);
        }
        let exists = self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publication_placements
                 WHERE publication_id = ?1 AND placement_id = ?2",
                &vals![input.publication_id, input.placement_id],
            )
            .await?
            .is_some();
        if exists {
            self.backend
                .execute(
                    "UPDATE registry_publication_placements
                     SET state = ?4, observed_at = ?5
                     WHERE publication_id = ?1 AND placement_id = ?2
                       AND required = ?3
                       AND EXISTS (SELECT 1 FROM registry_publications pub
                         WHERE pub.publication_id = ?1 AND (
                           (?4 = 'preparing' AND pub.state = 'preparing') OR
                           (?4 = 'failed' AND pub.state IN
                             ('preparing', 'writing_pointers', 'failed')) OR
                           (?4 = 'retired' AND pub.state = 'retired')))
                       AND ((state = 'preparing' AND ?4 = 'failed')
                         OR (state = 'writing_pointers' AND ?4 = 'failed')
                         OR (state = 'failed' AND ?4 IN ('preparing', 'retired'))
                         OR (state = 'ready' AND ?4 = 'retired')
                         OR (state = ?4 AND required = ?3 AND observed_at = ?5))",
                    &vals![
                        input.publication_id,
                        input.placement_id,
                        input.required,
                        input.state,
                        input.observed_at
                    ],
                )
                .await?;
        } else {
            if input.state != "preparing" {
                bail!("new publication placement progress must start preparing");
            }
            // Required-placement membership is part of the frozen manifest.
            // Fence on the parent row before inserting it for the same reason
            // as publication-object attachment above.
            self.backend
                .execute(
                    "UPDATE registry_publications
                     SET mutation_version = mutation_version + 1
                     WHERE publication_id = ?1 AND state = 'preparing'",
                    &vals![input.publication_id],
                )
                .await?;
            self.backend
                .execute(
                    "INSERT INTO registry_publication_placements
                     (publication_id, registry_id, placement_id, required, state, observed_at)
                     SELECT pub.publication_id, pub.registry_id, p.id, ?3, 'preparing', ?5
                     FROM registry_publications pub JOIN surface_placements p
                       ON p.registry_id = pub.registry_id
                     WHERE pub.publication_id = ?1 AND p.id = ?2
                       AND pub.state = 'preparing'",
                    &vals![
                        input.publication_id,
                        input.placement_id,
                        input.required,
                        input.state,
                        input.observed_at
                    ],
                )
                .await?;
        }
        let row = self
            .backend
            .query_opt(
                "SELECT registry_id, required, state, observed_at
             FROM registry_publication_placements
             WHERE publication_id = ?1 AND placement_id = ?2
               AND required = ?3 AND state = ?4 AND observed_at = ?5",
                &vals![
                    input.publication_id,
                    input.placement_id,
                    input.required,
                    input.state,
                    input.observed_at
                ],
            )
            .await?
            .context("publication placement transition is invalid or cross-registry")?;
        Ok(RegistryPublicationPlacementRecord {
            publication_id: input.publication_id.clone(),
            registry_id: row.get(0)?,
            placement_id: input.placement_id,
            required: row.get(1)?,
            state: row.get(2)?,
            observed_at: row.get(3)?,
        })
    }

    /// Pins a placement write-spec version to one immutable binding revision.
    ///
    /// # Errors
    ///
    /// Returns an error unless the placement's current binding and
    /// write-spec version match the requested immutable revision.
    pub async fn bind_surface_placement_write_capability(
        &self,
        placement_id: i64,
        binding_write_revision: i64,
    ) -> Result<()> {
        let inserted = self
            .backend
            .execute(
                "INSERT INTO surface_placement_write_capabilities
             (placement_id, placement_write_spec_version, binding_id,
              binding_write_revision, created_at)
             SELECT p.id, p.write_spec_version, p.binding_id, r.revision, ?3
             FROM surface_placements p
             JOIN binding_write_revisions r
               ON r.binding_id = p.binding_id AND r.revision = ?2
             WHERE p.id = ?1
               AND NOT EXISTS (SELECT 1 FROM surface_placement_write_capabilities existing
                 WHERE existing.placement_id = p.id
                   AND existing.placement_write_spec_version = p.write_spec_version
                   AND existing.binding_write_revision = r.revision)",
                &vals![placement_id, binding_write_revision, unix_now()],
            )
            .await;
        let existing = || async {
            self.backend
                .query_opt(
                    "SELECT 1 FROM surface_placement_write_capabilities pc
                 JOIN surface_placements p ON p.id = pc.placement_id
                 WHERE pc.placement_id = ?1
                   AND pc.placement_write_spec_version = p.write_spec_version
                   AND pc.binding_write_revision = ?2",
                    &vals![placement_id, binding_write_revision],
                )
                .await
        };
        match inserted {
            Ok(1) => {}
            Ok(_) => {
                if existing().await?.is_none() {
                    return Err(SurfaceWriteAuthorityMutationFailure::new(
                        "the planned binding-write capability is no longer available",
                    )
                    .into());
                }
            }
            Err(error) => {
                if existing().await?.is_none() {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Records a controller observation without mutating desired topology.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, completeness, a stale observation,
    /// an absent placement, or a database failure.
    pub async fn observe_surface_placement(
        &self,
        placement_id: i64,
        state: &str,
        completeness: &str,
        expected_observation_version: i64,
    ) -> Result<SurfacePlacementRecord> {
        if !matches!(
            state,
            "provisioning" | "syncing" | "ready" | "degraded" | "offline"
        ) {
            bail!("invalid placement observation state '{state}'");
        }
        if !matches!(completeness, "complete" | "partial" | "unknown") {
            bail!("invalid placement observation completeness '{completeness}'");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE surface_placement_observations
             SET state = ?3, completeness = ?4, observed_at = ?5,
                 observation_version = observation_version + 1
             WHERE placement_id = ?1 AND observation_version = ?2",
                &vals![
                    placement_id,
                    expected_observation_version,
                    state,
                    completeness,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("placement is missing or its observation version is stale");
        }
        self.surface_placement(placement_id)
            .await?
            .context("observed placement disappeared")
    }

    /// Lists prior evidence before a physical scan replaces its inventory.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn reusable_placement_scan_evidence(
        &self,
        placement_id: i64,
    ) -> Result<Vec<ReusablePlacementEvidence>> {
        self.backend
            .query(
                "SELECT surface_object_id, state, observed_hash, observed_size, etag
                   FROM object_placements
                  WHERE placement_id = ?1
                  ORDER BY surface_object_id",
                &vals![placement_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(ReusablePlacementEvidence {
                    surface_object_id: row.get(0)?,
                    state: row.get(1)?,
                    observed_hash: row.get(2)?,
                    observed_size: row.get(3)?,
                    etag: row.get(4)?,
                })
            })
            .collect()
    }

    /// Starts a physical inventory scan while retaining reusable active evidence.
    ///
    /// The observation changes to syncing/unknown before any prior evidence can
    /// be selected by readers. Active rows remain available to the controller
    /// as strong-version checkpoints; inactive rows are removed immediately.
    /// A complete scan replaces every active row before restoring eligibility.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement topology or observation version is
    /// stale, or when persistence fails.
    pub async fn begin_surface_placement_scan(
        &self,
        placement_id: i64,
        expected_resource_version: i64,
        expected_observation_version: i64,
        operation_id: &str,
        operation_resource_version: i64,
        claim_token: &str,
    ) -> Result<SurfacePlacementRecord> {
        validate_key_bytes(operation_id, "placement scan operation id", 64)?;
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE surface_placement_observations
                     SET state = 'syncing', completeness = 'unknown', observed_at = ?4,
                         observation_version = observation_version + 1
                     WHERE placement_id = ?1 AND observation_version = ?3
                       AND EXISTS (SELECT 1 FROM surface_placements placement
                         WHERE placement.id = ?1 AND placement.resource_version = ?2)
                       AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                         JOIN topology_operations operation
                           ON operation.operation_id = claim.operation_id
                         WHERE claim.operation_id = ?5 AND claim.claim_token = ?6
                           AND claim.operation_resource_version = ?7
                           AND claim.lease_expires_at > ?4
                           AND operation.resource_version = ?7
                           AND operation.state = 'running')",
                    vals![
                        placement_id,
                        expected_resource_version,
                        expected_observation_version,
                        now,
                        operation_id,
                        claim_token,
                        operation_resource_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "DELETE FROM object_placements
                     WHERE placement_id = ?1
                       AND NOT EXISTS (
                         SELECT 1 FROM surface_objects object
                          WHERE object.id = object_placements.surface_object_id
                            AND object.lifecycle_state = 'active')
                       AND EXISTS (SELECT 1 FROM surface_placement_observations observation
                         WHERE observation.placement_id = ?1
                           AND observation.observation_version = ?2)",
                    vals![placement_id, expected_observation_version + 1],
                )
                .unchecked(),
            ])
            .await?;
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared after its scan began")
    }

    /// Records one bounded batch of logical-object evidence during a placement scan.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence, stale placement topology, an
    /// object on another surface, duplicate objects, an oversized batch, a
    /// placement no longer being scanned, or a database failure.
    pub async fn record_surface_placement_scan_presences(
        &self,
        placement_id: i64,
        expected_resource_version: i64,
        expected_observation_version: i64,
        operation_id: &str,
        operation_resource_version: i64,
        claim_token: &str,
        presences: &[(i64, PlacementScanPresence)],
        observed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(operation_id, "placement scan operation id", 64)?;
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        if presences.len() > MAX_PLACEMENT_SCAN_PRESENCE_BATCH {
            bail!(
                "placement scan presence batch exceeds {} objects",
                MAX_PLACEMENT_SCAN_PRESENCE_BATCH
            );
        }
        if observed_at < 0 {
            bail!("placement scan evidence has an invalid time or size");
        }
        if presences.is_empty() {
            return Ok(());
        }

        let mut seen = std::collections::BTreeSet::new();
        for (_, presence) in presences {
            if !seen.insert(presence.surface_object_id) {
                bail!(
                    "placement scan presence batch repeats object {}",
                    presence.surface_object_id
                );
            }
            if !matches!(presence.state.as_str(), "present" | "missing" | "corrupt") {
                bail!("invalid placement scan presence state '{}'", presence.state);
            }
            if presence.observed_size.is_some_and(|size| size < 0) {
                bail!("placement scan evidence has an invalid time or size");
            }
            if presence.state == "missing"
                && (presence.observed_hash.is_some()
                    || presence.observed_size.is_some()
                    || presence.etag.is_some())
            {
                bail!("missing placement scan evidence cannot describe physical bytes");
            }
            if presence.state != "missing"
                && (presence.observed_hash.is_none() || presence.observed_size.is_none())
            {
                bail!("present placement scan evidence requires a digest and size");
            }
            if let Some(hash) = presence.observed_hash.as_deref() {
                validate_key_bytes(hash, "placement scan observed hash", 128)?;
            }
        }
        let claim_checked_at = unix_now();

        let delete_count = presences.len().div_ceil(MAX_PLACEMENT_SCAN_DELETE_IDS);
        let mut statements = Vec::with_capacity(presences.len() + delete_count);
        for presence_chunk in presences.chunks(MAX_PLACEMENT_SCAN_DELETE_IDS) {
            let mut delete_params = Vec::with_capacity(presence_chunk.len() + 1);
            delete_params.push(crate::value::ToValue::to_value(&placement_id));
            delete_params.extend(
                presence_chunk.iter().map(|(_, presence)| {
                    crate::value::ToValue::to_value(&presence.surface_object_id)
                }),
            );
            let object_placeholders = (0..presence_chunk.len())
                .map(|index| format!("?{}", index + 2))
                .collect::<Vec<_>>()
                .join(", ");
            statements.push(
                Statement::new(
                    format!(
                        "DELETE FROM object_placements
                         WHERE placement_id = ?1
                           AND surface_object_id IN ({object_placeholders})"
                    ),
                    delete_params,
                )
                .unchecked(),
            );
        }
        for (expected_object_resource_version, presence) in presences {
            statements.push(
                Statement::new(
                    "INSERT INTO object_placements
                       (surface_object_id, cache_id, registry_id, placement_id,
                        state, observed_hash, observed_size, etag,
                        observed_inventory_generation, observed_at,
                        catalog_object_resource_version)
                     SELECT object.id, object.cache_id, object.registry_id, placement.id,
                            ?6, ?7, ?8, ?9, ?3, ?13, object.resource_version
                     FROM surface_objects object
                     JOIN surface_placements placement
                       ON object.registry_id = placement.registry_id
                       OR object.cache_id = placement.cache_id
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     WHERE placement.id = ?1 AND object.id = ?2
                       AND placement.resource_version = ?3
                       AND observation.observation_version = ?4
                       AND object.resource_version = ?5
                       AND object.lifecycle_state = 'active'
                       AND observation.state = 'syncing'
                       AND observation.completeness = 'unknown'
                       AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                         JOIN topology_operations operation
                           ON operation.operation_id = claim.operation_id
                         WHERE claim.operation_id = ?10 AND claim.claim_token = ?11
                           AND claim.operation_resource_version = ?12
                           AND claim.lease_expires_at > ?14
                           AND operation.resource_version = ?12
                           AND operation.state = 'running')",
                    vals![
                        placement_id,
                        presence.surface_object_id,
                        expected_resource_version,
                        expected_observation_version,
                        *expected_object_resource_version,
                        presence.state,
                        presence.observed_hash,
                        presence.observed_size,
                        presence.etag,
                        operation_id,
                        claim_token,
                        operation_resource_version,
                        observed_at,
                        claim_checked_at
                    ],
                )
                .expecting(1),
            );
        }

        self.backend.checked_batch(&statements).await
    }

    /// Publishes the terminal state of a complete physical inventory pass.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid state, stale topology or observation
    /// versions, or persistence failure.
    pub async fn finish_surface_placement_scan(
        &self,
        placement_id: i64,
        expected_resource_version: i64,
        expected_observation_version: i64,
        operation_id: &str,
        operation_resource_version: i64,
        claim_token: &str,
        state: &str,
        completeness: &str,
    ) -> Result<SurfacePlacementRecord> {
        validate_key_bytes(operation_id, "placement scan operation id", 64)?;
        validate_key_bytes(claim_token, "placement scan claim token", 64)?;
        if !matches!(
            (state, completeness),
            ("ready", "complete") | ("degraded", "partial")
        ) {
            bail!("placement scan state and completeness are inconsistent");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE surface_placement_observations
                 SET state = ?7, completeness = ?8, observed_at = ?9,
                     observation_version = observation_version + 1
                 WHERE placement_id = ?1 AND observation_version = ?3
                   AND state = 'syncing' AND completeness = 'unknown'
                   AND EXISTS (SELECT 1 FROM surface_placements placement
                     WHERE placement.id = ?1 AND placement.resource_version = ?2)
                   AND EXISTS (SELECT 1 FROM placement_scan_claims claim
                     JOIN topology_operations operation
                       ON operation.operation_id = claim.operation_id
                     WHERE claim.operation_id = ?4 AND claim.claim_token = ?5
                       AND claim.operation_resource_version = ?6
                       AND claim.lease_expires_at > ?9
                       AND operation.resource_version = ?6
                       AND operation.state = 'running')
                   AND NOT EXISTS (
                     SELECT 1 FROM surface_objects object
                     JOIN surface_placements placement ON placement.id = ?1
                     WHERE object.lifecycle_state = 'active'
                       AND (object.registry_id = placement.registry_id
                         OR object.cache_id = placement.cache_id)
                       AND NOT EXISTS (SELECT 1 FROM object_placements presence
                         WHERE presence.surface_object_id = object.id
                           AND presence.placement_id = ?1
                           AND presence.catalog_object_resource_version = object.resource_version))
                   AND (?7 <> 'ready' OR NOT EXISTS (
                     SELECT 1 FROM surface_objects object
                     JOIN surface_placements placement ON placement.id = ?1
                     WHERE object.lifecycle_state = 'active'
                       AND (object.registry_id = placement.registry_id
                         OR object.cache_id = placement.cache_id)
                       AND NOT EXISTS (SELECT 1 FROM object_placements presence
                         WHERE presence.surface_object_id = object.id
                           AND presence.placement_id = ?1
                           AND presence.catalog_object_resource_version = object.resource_version
                           AND presence.state = 'present'
                           AND presence.observed_hash = object.content_hash
                           AND presence.observed_size = object.size)))",
                &vals![
                    placement_id,
                    expected_resource_version,
                    expected_observation_version,
                    operation_id,
                    claim_token,
                    operation_resource_version,
                    state,
                    completeness,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            bail!("placement scan topology or observation version is stale");
        }
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared after its scan completed")
    }

    /// Creates one physical placement after atomically checking binding ownership.
    ///
    /// # Errors
    ///
    /// Returns a typed [`SurfacePlacementCreateFailure`] for invalid placement
    /// fields, a duplicate name, an absent/cross-scope target, or a physical
    /// location conflict. Unclassified errors are database failures.
    pub async fn create_surface_placement(
        &self,
        input: &NewSurfacePlacementSpec,
    ) -> Result<SurfacePlacementRecord> {
        let invalid = |error: anyhow::Error| {
            SurfacePlacementCreateFailure::new(
                SurfacePlacementCreateFailureKind::InvalidArgument,
                format!("{error:#}"),
            )
        };
        validate_stable_name(&input.name, "placement name").map_err(invalid)?;
        validate_placement_spec(
            input.kind.as_str(),
            input.desired_state.as_str(),
            input.hash_range,
            input.desired_read_enabled,
        )
        .map_err(invalid)?;
        let prefix = normalize_placement_prefix(&input.prefix).map_err(invalid)?;
        let (hash_range_start, hash_range_end) = input
            .hash_range
            .map_or((None, None), |range| (Some(range.start), Some(range.end)));
        let (registry_id, cache_id) = input.surface.ids();
        let now = unix_now();
        let affected = match self
            .backend
            .execute(
                "INSERT INTO surface_placements
                (registry_id, cache_id, name, binding_id,
                 consumer_scope_key, binding_grant_generation, binding_grant_state,
                 prefix, kind,
                 desired_state, desired_read_enabled, read_order,
                 hash_range_start, hash_range_end, write_spec_version,
                 requires_conditional_writes, created_at, updated_at)
             SELECT ?1, ?2, ?3, b.id, g.consumer_scope_key, g.grant_generation, g.state,
                    ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, ?13
             FROM bindings b
             LEFT JOIN registries r ON r.id = ?1
             LEFT JOIN binary_caches c ON c.id = ?2
             JOIN binding_consumer_scopes g
               ON g.binding_id = b.id
              AND g.consumer_scope_key = COALESCE(r.owner_scope_key, c.owner_scope_key)
              AND g.state = 'active'
             WHERE b.id = ?4
               AND ((?1 IS NOT NULL AND r.id IS NOT NULL)
                 OR (?2 IS NOT NULL AND c.id IS NOT NULL))
               AND (?1 IS NULL OR NOT EXISTS (
                 SELECT 1 FROM oci_gc_registry_locks registry_lock
                 WHERE registry_lock.registry_id = ?1))
               AND NOT EXISTS (SELECT 1 FROM surface_placements existing
                 WHERE existing.binding_id = b.id
                   AND (existing.prefix = '' OR ?5 = ''
                     OR existing.prefix = ?5
                     OR substr(existing.prefix, 1, length(?5) + 1) = ?5 || '/'
                     OR substr(?5, 1, length(existing.prefix) + 1) = existing.prefix || '/'))",
                &vals![
                    registry_id,
                    cache_id,
                    input.name,
                    input.binding_id,
                    prefix,
                    input.kind,
                    input.desired_state,
                    input.desired_read_enabled,
                    input.read_order,
                    hash_range_start,
                    hash_range_end,
                    input.requires_conditional_writes,
                    now
                ],
            )
            .await
        {
            Ok(affected) => affected,
            Err(error) => {
                // SQL engines format uniqueness failures differently. Inspect
                // the now-authoritative rows after the failed statement so a
                // concurrent winner and an ordinary duplicate receive the same
                // typed result without parsing backend error strings.
                let placements = self.list_surface_placements(input.surface).await?;
                if placements
                    .iter()
                    .any(|placement| placement.name == input.name)
                {
                    return Err(SurfacePlacementCreateFailure::new(
                        SurfacePlacementCreateFailureKind::AlreadyExists,
                        format!("placement '{}' already exists", input.name),
                    )
                    .into());
                }
                if self
                    .backend
                    .query_opt(
                        "SELECT 1 FROM surface_placements existing
                         WHERE existing.binding_id = ?1
                           AND (existing.prefix = '' OR ?2 = ''
                             OR existing.prefix = ?2
                             OR substr(existing.prefix, 1, length(?2) + 1) = ?2 || '/'
                             OR substr(?2, 1, length(existing.prefix) + 1) = existing.prefix || '/')
                         LIMIT 1",
                        &vals![input.binding_id, prefix],
                    )
                    .await?
                    .is_some()
                {
                    return Err(SurfacePlacementCreateFailure::new(
                        SurfacePlacementCreateFailureKind::Conflict,
                        "binding prefix overlaps another placement namespace",
                    )
                    .into());
                }
                return Err(error);
            }
        };
        if affected != 1 {
            if self
                .backend
                .query_opt(
                    "SELECT 1 FROM surface_placements existing
                     WHERE existing.binding_id = ?1
                       AND (existing.prefix = '' OR ?2 = ''
                         OR existing.prefix = ?2
                         OR substr(existing.prefix, 1, length(?2) + 1) = ?2 || '/'
                         OR substr(?2, 1, length(existing.prefix) + 1) = existing.prefix || '/')
                     LIMIT 1",
                    &vals![input.binding_id, prefix],
                )
                .await?
                .is_some()
            {
                return Err(SurfacePlacementCreateFailure::new(
                    SurfacePlacementCreateFailureKind::Conflict,
                    "binding prefix overlaps another placement namespace",
                )
                .into());
            }
            return Err(SurfacePlacementCreateFailure::new(
                SurfacePlacementCreateFailureKind::InvalidArgument,
                "surface and binding must exist in a compatible scope",
            )
            .into());
        }
        let placement = self
            .surface_placement_at(input.binding_id, &prefix)
            .await?
            .context("created placement disappeared")?;
        self.backend
            .execute(
                "INSERT INTO surface_placement_observations
                 (placement_id, state, completeness, observed_at)
                 VALUES (?1, 'provisioning', 'unknown', ?2)",
                &vals![placement.id, now],
            )
            .await?;
        self.backend
            .execute(
                "INSERT INTO registry_placement_publication_watermarks
                 (placement_id, registry_id, mutable_publication_id, observed_at)
                 SELECT id, registry_id, NULL, ?2 FROM surface_placements
                 WHERE id = ?1 AND registry_id IS NOT NULL",
                &vals![placement.id, now],
            )
            .await?;
        self.surface_placement(placement.id)
            .await?
            .context("created placement disappeared after observation")
    }

    /// Returns a placement by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_placement(&self, id: i64) -> Result<Option<SurfacePlacementRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective WHERE id = ?1"
                ),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_surface_placement).transpose()
    }

    /// Returns the placement occupying one binding-relative location.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_placement_at(
        &self,
        binding_id: i64,
        prefix: &str,
    ) -> Result<Option<SurfacePlacementRecord>> {
        let rows = self.backend.query(&format!("SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective WHERE binding_id = ?1 AND prefix = ?2"), &vals![binding_id, prefix]).await?;
        rows.first().map(row_to_surface_placement).transpose()
    }

    /// Lists placements eligible to receive one registry publication or repair.
    ///
    /// Publication eligibility is placement-local: every returned placement has
    /// a current, validated write capability for its own binding. A degraded
    /// placement remains eligible so an exact publication can restore missing
    /// or corrupt objects; its incomplete observation still keeps reads and
    /// mutable write authority disabled until a successful scan. Eligibility is
    /// not inferred from the surface's single mutable write authority.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_write_placements(
        &self,
        registry_id: i64,
    ) -> Result<Vec<SurfacePlacementRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective p
                     WHERE p.registry_id = ?1 AND p.kind = 'complete'
                       AND p.desired_state = 'active'
                       AND ((p.state = 'ready' AND p.completeness = 'complete')
                         OR (p.state = 'degraded' AND p.completeness = 'partial'))
                       AND EXISTS (
                         SELECT 1 FROM surface_placement_write_capabilities capability
                         JOIN binding_write_revisions revision
                           ON revision.binding_id = capability.binding_id
                          AND revision.revision = capability.binding_write_revision
                         JOIN binding_write_observations observation
                           ON observation.binding_id = revision.binding_id
                          AND observation.revision = revision.revision
                         JOIN binding_credential_revisions credential
                           ON credential.binding_id = revision.binding_id
                          AND credential.purpose = revision.write_credential_purpose
                          AND credential.generation = revision.write_credential_generation
                         WHERE capability.placement_id = p.id
                           AND capability.placement_write_spec_version = p.write_spec_version
                           AND revision.writes_supported = 1
                           AND observation.state = 'valid'
                           AND credential.validation_state = 'valid'
                           AND (p.requires_conditional_writes = 0
                             OR revision.conditional_writes_supported = 1))
                     ORDER BY p.read_order, p.name, p.id"
                ),
                &vals![registry_id],
            )
            .await?;
        rows.iter().map(row_to_surface_placement).collect()
    }

    /// Resolves the newest validated write revision pinned to a placement.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn placement_publication_write_revision(
        &self,
        placement_id: i64,
    ) -> Result<Option<BindingWriteRevisionRecord>> {
        self.backend
            .query_opt(
                "SELECT revision.binding_id, revision.revision,
                            revision.write_credential_version_ref,
                            revision.write_credential_purpose,
                            revision.write_credential_generation,
                            revision.writes_supported,
                            revision.conditional_writes_supported,
                            revision.revision_fingerprint,
                            revision.capability_fingerprint, revision.created_at
                     FROM surface_placements placement
                     JOIN surface_placement_write_capabilities capability
                       ON capability.placement_id = placement.id
                      AND capability.placement_write_spec_version = placement.write_spec_version
                     JOIN binding_write_revisions revision
                       ON revision.binding_id = capability.binding_id
                      AND revision.revision = capability.binding_write_revision
                     JOIN binding_write_observations observation
                       ON observation.binding_id = revision.binding_id
                      AND observation.revision = revision.revision
                     JOIN binding_credential_revisions credential
                       ON credential.binding_id = revision.binding_id
                      AND credential.purpose = revision.write_credential_purpose
                      AND credential.generation = revision.write_credential_generation
                     WHERE placement.id = ?1 AND placement.kind = 'complete'
                       AND placement.desired_state = 'active'
                       AND revision.writes_supported = 1
                       AND observation.state = 'valid'
                       AND credential.validation_state = 'valid'
                       AND (placement.requires_conditional_writes = 0
                         OR revision.conditional_writes_supported = 1)
                     ORDER BY revision.revision DESC LIMIT 1",
                &vals![placement_id],
            )
            .await?
            .map(|row| row_to_binding_write_revision(&row))
            .transpose()
    }

    /// Returns references that constrain a placement drain or deletion.
    ///
    /// The result names topology concepts instead of exposing backend foreign
    /// key or constraint details. Callers must re-read it immediately before a
    /// destructive apply; the guarded write remains the final race-safe check.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocker query fails or returns no row.
    pub async fn surface_placement_blockers(&self, id: i64) -> Result<SurfacePlacementBlockers> {
        let placement_target_id = self.surface_placement_operation_target_id(id).await?;
        let row = self
            .backend
            .query_opt(
                "SELECT
                   EXISTS (SELECT 1 FROM routes WHERE placement_id = ?1),
                   EXISTS (
                     SELECT 1 FROM routes r WHERE r.placement_policy_revision_id IN (
                       SELECT policy_revision_id FROM placement_policy_complete_members
                         WHERE placement_id = ?1
                       UNION ALL
                       SELECT policy_revision_id FROM placement_policy_shard_members
                         WHERE placement_id = ?1)),
                   EXISTS (
                     SELECT 1 FROM placement_policy_complete_members WHERE placement_id = ?1
                     UNION ALL
                     SELECT 1 FROM placement_policy_shard_members WHERE placement_id = ?1),
                   EXISTS (SELECT 1 FROM object_placements WHERE placement_id = ?1),
                   EXISTS (SELECT 1 FROM registry_publication_placements WHERE placement_id = ?1),
                   EXISTS (SELECT 1 FROM registry_publication_placements
                     WHERE placement_id = ?1
                       AND state IN ('preparing', 'writing_pointers')),
                   EXISTS (SELECT 1 FROM object_deletion_jobs WHERE placement_id = ?1),
                   EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.state IN ('pending', 'running') AND (
                       (o.primary_target_kind = 'placement'
                         AND o.primary_target_stable_id = ?2)
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                         WHERE t.operation_id = o.operation_id
                           AND t.target_kind = 'placement' AND t.stable_id = ?2)))",
                &vals![id, placement_target_id],
            )
            .await?
            .context("placement blocker query returned no row")?;
        Ok(SurfacePlacementBlockers {
            direct_route: row.get(0)?,
            routed_policy: row.get(1)?,
            policy_member: row.get(2)?,
            object_presence: row.get(3)?,
            publication: row.get(4)?,
            active_publication: row.get(5)?,
            deletion_job: row.get(6)?,
            topology_operation: row.get(7)?,
        })
    }

    /// Updates mutable placement selection fields with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, a stale version, an authority or
    /// route pin, a missing placement, or database failure.
    pub async fn update_surface_placement(
        &self,
        id: i64,
        input: &UpdateSurfacePlacementSpec,
    ) -> Result<SurfacePlacementRecord> {
        let existing = self
            .surface_placement(id)
            .await?
            .context("placement does not exist")?;
        if !matches!(
            input.desired_state.as_str(),
            "active" | "draining" | "offline"
        ) {
            bail!("invalid desired placement state '{}'", input.desired_state);
        }
        if existing.kind == "archive" && input.desired_read_enabled {
            bail!("an archive placement cannot be read-enabled");
        }
        let guard = "id = ?1 AND resource_version = ?2
               AND NOT EXISTS (SELECT 1 FROM surface_write_authorities a
                 WHERE (a.desired_placement_id = ?1 OR a.observed_placement_id = ?1)
                   AND ?3 <> 'active')
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                 WHERE ticket.placement_id = ?1 AND (ticket.active_cache_slot = 1 OR
                   (ticket.state = 'completed'
                     AND ticket.covered_inventory_generation IS NULL)))
               AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                 WHERE job.placement_id = ?1 AND job.active_slot = 1)
               AND NOT EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                 WHERE scan.placement_id = ?1 AND scan.completed_at IS NULL)
               AND NOT EXISTS (SELECT 1
                 FROM registry_publication_multipart_uploads upload
                 JOIN registry_publication_multipart_backends backend
                   ON backend.upload_id = upload.upload_id
                 WHERE backend.placement_id = ?1 AND upload.active_object_slot = 1)
               AND NOT EXISTS (
                 SELECT 1 FROM routes r
                 WHERE r.placement_id = ?1 OR r.placement_policy_revision_id IN (
                   SELECT policy_revision_id FROM placement_policy_complete_members
                     WHERE placement_id = ?1
                   UNION ALL
                   SELECT policy_revision_id FROM placement_policy_shard_members
                     WHERE placement_id = ?1))
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                 JOIN surface_placements gc_placement
                   ON gc_placement.registry_id = registry_lock.registry_id
                 WHERE gc_placement.id = ?1)
               AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_snapshots snapshot
                 JOIN oci_gc_runs run ON run.id = snapshot.run_id
                 WHERE snapshot.placement_id = ?1 AND run.state = 'applying')";
        let values = vals![
            id,
            input.expected_version,
            input.desired_state,
            input.desired_read_enabled,
            input.read_order,
            unix_now()
        ]
        .to_vec();
        self.backend
            .checked_batch(&[
                Statement::new(
                    format!(
                        "DELETE FROM surface_placement_write_capabilities
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements
                           WHERE {guard} AND desired_state <> ?3)"
                    ),
                    vals![id, input.expected_version, input.desired_state].to_vec(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "UPDATE surface_placements SET desired_state = ?3,
                desired_read_enabled = ?4, read_order = ?5,
                write_spec_version = CASE WHEN desired_state = ?3
                  THEN write_spec_version ELSE write_spec_version + 1 END,
                resource_version = resource_version + 1, updated_at = ?6
             WHERE {guard}"
                    ),
                    values,
                )
                .expecting(1),
            ])
            .await?;
        let updated = self.surface_placement(id).await?;
        if !updated
            .as_ref()
            .is_some_and(|placement| placement.resource_version == input.expected_version + 1)
        {
            bail!("placement is missing or its resource version is stale");
        }
        updated.context("updated placement disappeared")
    }

    /// Deletes a placement at an expected version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when routes/policies still reference it.
    pub async fn delete_surface_placement(&self, id: i64, expected_version: i64) -> Result<bool> {
        let placement_target_id = self.surface_placement_operation_target_id(id).await?;
        Ok(self
            .backend
            .execute(
                "DELETE FROM surface_placements
                 WHERE id = ?1 AND resource_version = ?2
                   AND NOT EXISTS (SELECT 1 FROM surface_write_authorities a
                     WHERE a.desired_placement_id = ?1 OR a.observed_placement_id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets ticket
                     WHERE ticket.placement_id = ?1 AND (ticket.active_cache_slot = 1 OR
                       (ticket.state = 'completed'
                         AND ticket.covered_inventory_generation IS NULL)))
                   AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
                     WHERE job.placement_id = ?1 AND job.active_slot = 1)
                   AND NOT EXISTS (SELECT 1 FROM cache_inventory_placement_scans scan
                     WHERE scan.placement_id = ?1 AND scan.completed_at IS NULL)
                   AND NOT EXISTS (SELECT 1
                     FROM registry_publication_multipart_uploads upload
                     JOIN registry_publication_multipart_backends backend
                       ON backend.upload_id = upload.upload_id
                     WHERE backend.placement_id = ?1 AND upload.active_object_slot = 1)
                   AND NOT EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.state IN ('pending', 'running') AND (
                       (o.primary_target_kind = 'placement'
                         AND o.primary_target_stable_id = ?3)
                       OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                         WHERE t.operation_id = o.operation_id
                           AND t.target_kind = 'placement' AND t.stable_id = ?3)))
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                     JOIN surface_placements gc_placement
                       ON gc_placement.registry_id = registry_lock.registry_id
                     WHERE gc_placement.id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_gc_placement_snapshots snapshot
                     JOIN oci_gc_runs run ON run.id = snapshot.run_id
                     WHERE snapshot.placement_id = ?1 AND run.state = 'applying')",
                &vals![id, expected_version, placement_target_id],
            )
            .await?
            == 1)
    }

    /// Deletes a registry placement and its terminal placement-scoped history.
    ///
    /// Registry placements have no physical-eviction workflow. Once routing,
    /// authority, and active work no longer select a drained placement, its
    /// observational inventory and terminal publication rows are historical
    /// metadata rather than deletion blockers. This transaction detaches only
    /// that placement's rows before applying the same guarded metadata delete.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when active work still refers
    /// to the placement.
    pub async fn delete_registry_surface_placement(
        &self,
        id: i64,
        expected_version: i64,
    ) -> Result<bool> {
        let placement_target_id = self.surface_placement_operation_target_id(id).await?;
        let guard = "id = ?1 AND resource_version = ?2 AND registry_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM surface_write_authorities a
            WHERE a.desired_placement_id = ?1 OR a.observed_placement_id = ?1)
          AND NOT EXISTS (SELECT 1 FROM registry_publication_placements progress
            WHERE progress.placement_id = ?1
              AND progress.state IN ('preparing', 'writing_pointers'))
          AND NOT EXISTS (SELECT 1 FROM object_deletion_jobs job
            WHERE job.placement_id = ?1)
          AND NOT EXISTS (SELECT 1
            FROM registry_publication_multipart_uploads upload
            JOIN registry_publication_multipart_backends backend
              ON backend.upload_id = upload.upload_id
            WHERE backend.placement_id = ?1 AND upload.active_object_slot = 1)
          AND NOT EXISTS (SELECT 1 FROM topology_operations o
            WHERE o.state IN ('pending', 'running') AND (
              (o.primary_target_kind = 'placement'
                AND o.primary_target_stable_id = ?3)
              OR EXISTS (SELECT 1 FROM operation_secondary_targets t
                WHERE t.operation_id = o.operation_id
                  AND t.target_kind = 'placement' AND t.stable_id = ?3)))";
        let values = vals![id, expected_version, placement_target_id].to_vec();

        if self
            .backend
            .query_opt(
                &format!("SELECT 1 FROM surface_placements WHERE {guard}"),
                &values,
            )
            .await?
            .is_none()
        {
            return Ok(false);
        }

        self.backend
            .checked_batch(&[
                Statement::new(
                    format!(
                        "DELETE FROM registry_publication_multipart_parts
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM registry_publication_multipart_backends
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM direct_route_evidence
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM placement_delivery_manifest_heads
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM placement_delivery_manifests
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM registry_publication_placements
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!(
                        "DELETE FROM object_placements
                         WHERE placement_id = ?1 AND EXISTS (
                           SELECT 1 FROM surface_placements WHERE {guard})"
                    ),
                    values.clone(),
                )
                .unchecked(),
                Statement::new(
                    format!("DELETE FROM surface_placements WHERE {guard}"),
                    values,
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    /// Resolves the stable placement identity captured by a topology operation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn surface_placement_by_operation_target(
        &self,
        stable_id: &str,
    ) -> Result<Option<SurfacePlacementRecord>> {
        validate_key_bytes(stable_id, "placement operation target", 255)?;
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective
                     WHERE id IN (
                       SELECT placement.id FROM surface_placements placement
                       LEFT JOIN registries registry ON registry.id = placement.registry_id
                       LEFT JOIN binary_caches cache ON cache.id = placement.cache_id
                       WHERE (registry.stable_id || '/placement:' || placement.name) = ?1
                          OR (cache.stable_id || '/placement:' || placement.name) = ?1)"
                ),
                &vals![stable_id],
            )
            .await?;
        if rows.len() > 1 {
            bail!("placement operation target is ambiguous");
        }
        rows.first().map(row_to_surface_placement).transpose()
    }

    /// Returns one placement equivalence by stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn placement_equivalence(
        &self,
        stable_id: &str,
    ) -> Result<Option<PlacementEquivalenceRecord>> {
        self.backend
            .query_opt(
                "SELECT equivalence.id, a.registry_id, a.cache_id, a.name, b.name,
                        equivalence.evidence_digest, equivalence.state,
                        equivalence.creation_token, equivalence.confirmed_at,
                        equivalence.resource_version
                 FROM placement_equivalences equivalence
                 JOIN surface_placements a ON a.id = equivalence.placement_a_id
                 JOIN surface_placements b ON b.id = equivalence.placement_b_id
                 WHERE equivalence.id = ?1",
                &vals![stable_id],
            )
            .await?
            .map(|row| {
                Ok(PlacementEquivalenceRecord {
                    id: row.get(0)?,
                    surface: match (row.get::<Option<i64>>(1)?, row.get::<Option<i64>>(2)?) {
                        (Some(id), None) => SurfaceTarget::Registry(id),
                        (None, Some(id)) => SurfaceTarget::BinaryCache(id),
                        _ => bail!("placement equivalence has an invalid surface"),
                    },
                    placement_a: row.get(3)?,
                    placement_b: row.get(4)?,
                    evidence_digest: row.get(5)?,
                    state: row.get(6)?,
                    creation_token: row.get(7)?,
                    confirmed_at: row.get(8)?,
                    resource_version: row.get(9)?,
                })
            })
            .transpose()
    }
}
