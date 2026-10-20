//! Configuration mutations in the registries capability.

use super::*;

impl Database {
    /// Reports whether every required placement has exact evidence for a class.
    ///
    /// An empty object class is complete. This lets a minimal loose-object Git
    /// publication advance directly to its pointer phase while retaining the
    /// same all-placements requirement for every class member that exists.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid class vocabulary or database failure.
    pub async fn registry_publication_class_is_complete(
        &self,
        publication_id: &str,
        object_kind: &str,
    ) -> Result<bool> {
        if !matches!(object_kind, "immutable" | "mutable_pointer") {
            bail!("invalid publication object kind");
        }
        let row = self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publications pub
                 WHERE pub.publication_id = ?1
                   AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                     WHERE pp.publication_id = pub.publication_id
                       AND pp.required = 1)
                   AND NOT EXISTS (
                     SELECT 1 FROM registry_publication_objects po
                     JOIN registry_publication_placements pp
                       ON pp.publication_id = po.publication_id AND pp.required = 1
                     WHERE po.publication_id = pub.publication_id
                       AND po.object_kind = ?2
                       AND NOT EXISTS (SELECT 1 FROM object_placements presence
                         WHERE presence.surface_object_id = po.surface_object_id
                           AND presence.placement_id = pp.placement_id
                           AND presence.state = 'present'
                           AND presence.observed_hash = po.expected_hash
                           AND presence.observed_size = po.expected_size))",
                &vals![publication_id, object_kind],
            )
            .await?;
        Ok(row.is_some())
    }

    /// Promotes the declared mutable object identities after all pointer bytes verify.
    ///
    /// Publication placement watermarks are cleared before this method is used,
    /// so current-publication readers fail closed throughout the transition.
    ///
    /// # Errors
    ///
    /// Returns an error unless every required mutable object is present exactly
    /// and the publication is writing pointers, or on database failure.
    pub async fn promote_registry_publication_mutable_objects(
        &self,
        publication_id: &str,
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        let expected: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM registry_publication_objects
                 WHERE publication_id = ?1 AND object_kind = 'mutable_pointer'",
                &vals![publication_id],
            )
            .await?
            .context("publication object count disappeared")?
            .get(0)?;
        if expected <= 0 {
            bail!("publication has no mutable pointers");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE surface_objects
                 SET content_hash = (SELECT po.expected_hash
                       FROM registry_publication_objects po
                       WHERE po.publication_id = ?1
                         AND po.surface_object_id = surface_objects.id),
                     size = (SELECT po.expected_size
                       FROM registry_publication_objects po
                       WHERE po.publication_id = ?1
                         AND po.surface_object_id = surface_objects.id),
                     mutable_publication_id = ?1, updated_at = ?2,
                     resource_version = resource_version + 1
                 WHERE id IN (SELECT po.surface_object_id
                       FROM registry_publication_objects po
                       JOIN registry_publications pub
                         ON pub.publication_id = po.publication_id
                       WHERE po.publication_id = ?1
                         AND po.object_kind = 'mutable_pointer'
                         AND pub.state = 'writing_pointers'
                         AND NOT EXISTS (
                           SELECT 1 FROM registry_publication_placements pp
                           WHERE pp.publication_id = pub.publication_id
                             AND pp.required = 1 AND NOT EXISTS (
                               SELECT 1 FROM object_placements presence
                               WHERE presence.surface_object_id = po.surface_object_id
                                 AND presence.placement_id = pp.placement_id
                                 AND presence.state = 'present'
                                 AND presence.observed_hash = po.expected_hash
                                 AND presence.observed_size = po.expected_size)))",
                    vals![publication_id, unix_now()],
                )
                .expecting(u64::try_from(expected).context("publication object count overflow")?),
                Statement::new(
                    "UPDATE object_placements
                     SET catalog_object_resource_version = (SELECT object.resource_version
                       FROM surface_objects object
                       WHERE object.id = object_placements.surface_object_id)
                     WHERE surface_object_id IN (
                       SELECT declared.surface_object_id
                       FROM registry_publication_objects declared
                       JOIN surface_objects object
                         ON object.id = declared.surface_object_id
                       WHERE declared.publication_id = ?1
                         AND declared.object_kind = 'mutable_pointer'
                         AND object.mutable_publication_id = ?1
                         AND object.content_hash = declared.expected_hash
                         AND object.size = declared.expected_size)
                       AND state = 'present'
                       AND observed_hash = (SELECT declared.expected_hash
                         FROM registry_publication_objects declared
                         WHERE declared.publication_id = ?1
                           AND declared.surface_object_id = object_placements.surface_object_id)
                       AND observed_size = (SELECT declared.expected_size
                         FROM registry_publication_objects declared
                         WHERE declared.publication_id = ?1
                           AND declared.surface_object_id = object_placements.surface_object_id)",
                    vals![publication_id],
                )
                .unchecked(),
            ])
            .await
    }

    /// Attaches one same-registry, content-exact object snapshot to a preparing publication.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/content, incompatible ownership/state, or database failure.
    pub async fn set_registry_publication_object(
        &self,
        input: &SetRegistryPublicationObject,
    ) -> Result<RegistryPublicationObjectRecord> {
        validate_key_bytes(&input.publication_id, "publication id", 64)?;
        validate_key_bytes(&input.expected_hash, "publication object hash", 128)?;
        if !matches!(input.object_kind.as_str(), "immutable" | "mutable_pointer")
            || input.expected_size < 0
        {
            bail!("publication object kind/size is invalid");
        }
        // Serialize manifest mutation against the publication row before the
        // child write. The child INSERT rechecks `preparing`, so a freeze that
        // wins after this fence makes the mutation fail closed; a crash after
        // the bump merely leaves a harmless skipped version.
        self.backend
            .execute(
                "UPDATE registry_publications
                 SET mutation_version = mutation_version + 1
                 WHERE publication_id = ?1 AND state = 'preparing'",
                &vals![input.publication_id],
            )
            .await?;
        let affected = self.backend.execute(
            "INSERT INTO registry_publication_objects
             (publication_id, registry_id, surface_object_id, object_kind, expected_hash, expected_size)
             SELECT pub.publication_id, pub.registry_id, o.id, ?3, ?4, ?5
             FROM registry_publications pub JOIN surface_objects o
               ON o.registry_id = pub.registry_id
             WHERE pub.publication_id = ?1 AND o.id = ?2 AND pub.state = 'preparing'
               AND o.lifecycle_state = 'active' AND o.object_kind = ?3
               AND (?3 = 'mutable_pointer'
                 OR (o.content_hash = ?4 AND o.size = ?5))
             ON CONFLICT(publication_id, surface_object_id) DO UPDATE SET
               object_kind = excluded.object_kind, expected_hash = excluded.expected_hash,
               expected_size = excluded.expected_size",
            &vals![input.publication_id, input.surface_object_id, input.object_kind,
                input.expected_hash, input.expected_size],
        ).await?;
        let _ = affected;
        let record = RegistryPublicationObjectRecord {
            publication_id: input.publication_id.clone(),
            registry_id: self
                .backend
                .query_opt(
                    "SELECT registry_id FROM registry_publications WHERE publication_id = ?1",
                    &vals![input.publication_id],
                )
                .await?
                .context("publication disappeared")?
                .get(0)?,
            surface_object_id: input.surface_object_id,
            object_kind: input.object_kind.clone(),
            expected_hash: input.expected_hash.clone(),
            expected_size: input.expected_size,
        };
        let exact = self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publication_objects po
             JOIN registry_publications pub ON pub.publication_id = po.publication_id
             WHERE po.publication_id = ?1 AND po.surface_object_id = ?2
               AND pub.state = 'preparing'
               AND object_kind = ?3 AND expected_hash = ?4 AND expected_size = ?5",
                &vals![
                    input.publication_id,
                    input.surface_object_id,
                    input.object_kind,
                    input.expected_hash,
                    input.expected_size
                ],
            )
            .await?;
        if exact.is_none() {
            bail!("publication object must exactly match an active object on the same registry");
        }
        Ok(record)
    }

    /// Advances a publication state by compare-and-set.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid transition, unmet required placements, stale state, or database failure.
    pub async fn advance_registry_publication(
        &self,
        publication_id: &str,
        expected_state: &str,
        next_state: &str,
        at: i64,
    ) -> Result<bool> {
        let valid = matches!(
            (expected_state, next_state),
            ("preparing", "writing_pointers")
                | ("preparing", "failed")
                | ("writing_pointers", "ready")
                | ("writing_pointers", "failed")
                | ("failed", "retired")
                | ("ready", "retired")
        );
        if !valid {
            bail!("invalid publication state transition {expected_state}->{next_state}");
        }
        Ok(self
            .backend
            .execute(
                "UPDATE registry_publications SET state = ?3,
               completed_at = CASE WHEN ?3 IN ('ready','failed') THEN ?4 ELSE completed_at END,
               retired_at = CASE WHEN ?3 = 'retired' THEN ?4 ELSE retired_at END
             WHERE publication_id = ?1 AND state = ?2
               AND (?3 <> 'writing_pointers' OR NOT EXISTS (
                 SELECT 1 FROM staged_release_revisions revision
                 JOIN staged_releases stage
                   ON stage.registry_id = revision.registry_id
                  AND stage.stage_id = revision.stage_id
                 WHERE revision.publication_id = ?1
                   AND (revision.revision <> stage.current_revision
                     OR stage.state <> 'releasing')))
               AND (?3 <> 'ready' OR (EXISTS (
                 SELECT 1 FROM registry_publication_placements pp
                 WHERE pp.publication_id = ?1 AND pp.required = 1)
                 AND NOT EXISTS (
                   SELECT 1 FROM registry_publication_placements pp
                   JOIN surface_placement_effective p ON p.id = pp.placement_id
                   WHERE pp.publication_id = ?1 AND pp.required = 1
                     AND (pp.state <> 'ready'
                       OR p.mutable_publication_id <> ?1
                       OR p.mutable_publication_id IS NULL))))
               AND (?3 <> 'retired' OR NOT EXISTS (
                 SELECT 1 FROM registry_publication_state ps
                 WHERE ps.current_publication_id = ?1)) ",
                &vals![publication_id, expected_state, next_state, at],
            )
            .await?
            == 1)
    }

    /// Fails an incomplete publication and every frozen placement atomically.
    ///
    /// A placement whose mutable pointers may have advanced remains failed and
    /// therefore ineligible for reads until reconciliation restores a complete
    /// ready publication. The method never rewinds a publication watermark.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed id, a terminal publication, or a
    /// database failure.
    pub async fn fail_registry_publication(&self, publication_id: &str, at: i64) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE registry_publications
                     SET state = 'failed', completed_at = ?2
                     WHERE publication_id = ?1
                       AND state IN ('preparing', 'writing_pointers')
                       AND NOT EXISTS (SELECT 1 FROM staged_releases stage
                         WHERE stage.publication_id = ?1 AND stage.state = 'releasing')",
                    vals![publication_id, at],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE registry_publication_placements
                     SET state = 'failed', observed_at = ?2
                     WHERE publication_id = ?1 AND state <> 'ready'",
                    vals![publication_id, at],
                )
                .unchecked(),
            ])
            .await
    }

    /// Compare-and-sets the one authoritative current ready publication for a registry.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale version, non-ready/cross-registry publication, or database failure.
    pub async fn set_current_registry_publication(
        &self,
        registry_id: i64,
        publication_id: &str,
        expected_version: Option<i64>,
    ) -> Result<RegistryPublicationStateRecord> {
        if let Some(row) = self
            .backend
            .query_opt(
                "SELECT registry_id, current_publication_id, next_ordinal,
                resource_version, updated_at
             FROM registry_publication_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            let current: Option<String> = row.get(1)?;
            let version: i64 = row.get(3)?;
            if current.as_deref() == Some(publication_id)
                && expected_version.map_or(true, |expected| expected == version)
            {
                return Ok(RegistryPublicationStateRecord {
                    registry_id: row.get(0)?,
                    current_publication_id: current,
                    next_ordinal: row.get(2)?,
                    resource_version: version,
                    updated_at: row.get(4)?,
                });
            }
        }
        let now = unix_now();
        let affected = if let Some(version) = expected_version {
            self.backend
                .execute(
                    "UPDATE registry_publication_state SET current_publication_id = ?2,
                    next_ordinal = CASE WHEN next_ordinal <= (SELECT ordinal
                      FROM registry_publications WHERE publication_id = ?2)
                      THEN (SELECT ordinal + 1 FROM registry_publications WHERE publication_id = ?2)
                      ELSE next_ordinal END,
                    resource_version = resource_version + 1, updated_at = ?4
                 WHERE registry_id = ?1 AND resource_version = ?3 AND EXISTS (
                   SELECT 1 FROM registry_publications pub
                   WHERE pub.publication_id = ?2 AND pub.registry_id = ?1 AND pub.state = 'ready'
                     AND ((registry_publication_state.current_publication_id IS NULL
                           AND pub.parent_publication_id IS NULL)
                       OR (pub.parent_publication_id = registry_publication_state.current_publication_id
                         AND pub.ordinal > (SELECT current.ordinal FROM registry_publications current
                           WHERE current.publication_id = registry_publication_state.current_publication_id)))
                     AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                       WHERE pp.publication_id = pub.publication_id AND pp.required = 1)
                     AND NOT EXISTS (SELECT 1 FROM registry_publication_placements pp
                       JOIN surface_placement_effective p ON p.id = pp.placement_id
                       WHERE pp.publication_id = pub.publication_id AND pp.required = 1
                         AND (pp.state <> 'ready'
                           OR p.mutable_publication_id <> pub.publication_id
                           OR p.mutable_publication_id IS NULL)))",
                    &vals![registry_id, publication_id, version, now],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO registry_publication_state
                 (registry_id, current_publication_id, next_ordinal, updated_at)
                 SELECT ?1, pub.publication_id, pub.ordinal + 1, ?3
                 FROM registry_publications pub
                 WHERE pub.publication_id = ?2 AND pub.registry_id = ?1 AND pub.state = 'ready'
                   AND pub.parent_publication_id IS NULL
                   AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                     WHERE pp.publication_id = pub.publication_id AND pp.required = 1)
                   AND NOT EXISTS (SELECT 1 FROM registry_publication_placements pp
                     JOIN surface_placement_effective p ON p.id = pp.placement_id
                     WHERE pp.publication_id = pub.publication_id AND pp.required = 1
                       AND (pp.state <> 'ready'
                         OR p.mutable_publication_id <> pub.publication_id
                         OR p.mutable_publication_id IS NULL))",
                    &vals![registry_id, publication_id, now],
                )
                .await?
        };
        if affected != 1 {
            bail!("current publication CAS is stale or publication is not ready on this registry");
        }
        let row = self.backend.query_opt(
            "SELECT registry_id, current_publication_id, next_ordinal, resource_version, updated_at
             FROM registry_publication_state WHERE registry_id = ?1",
            &vals![registry_id],
        ).await?.context("publication state disappeared")?;
        Ok(RegistryPublicationStateRecord {
            registry_id: row.get(0)?,
            current_publication_id: row.get(1)?,
            next_ordinal: row.get(2)?,
            resource_version: row.get(3)?,
            updated_at: row.get(4)?,
        })
    }

    /// Returns the authoritative publication head for a registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_state(
        &self,
        registry_id: i64,
    ) -> Result<Option<RegistryPublicationStateRecord>> {
        self.backend
            .query_opt(
                "SELECT registry_id, current_publication_id, next_ordinal,
                        resource_version, updated_at
                 FROM registry_publication_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationStateRecord {
                    registry_id: row.get(0)?,
                    current_publication_id: row.get(1)?,
                    next_ordinal: row.get(2)?,
                    resource_version: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })
            .transpose()
    }
}
