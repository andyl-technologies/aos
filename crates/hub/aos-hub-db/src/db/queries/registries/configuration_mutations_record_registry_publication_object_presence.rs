//! Configuration mutations in the registries capability.

use super::*;

impl Database {
    /// Records exact post-write evidence for one publication object placement.
    ///
    /// The expected object identity and same-registry placement are rechecked in
    /// the insert. This is the only evidence consumed by publication readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched evidence, a placement outside the
    /// publication, a terminal publication, or database failure.
    pub async fn record_registry_publication_object_presence(
        &self,
        publication_id: &str,
        surface_object_id: i64,
        placement_id: i64,
        observed_hash: &str,
        observed_size: i64,
        etag: Option<&str>,
        observed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(observed_hash, "observed object hash", 128)?;
        if observed_size < 0 {
            bail!("observed object size cannot be negative");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM object_placements
                     WHERE surface_object_id = ?2 AND placement_id = ?3
                       AND registry_id = (SELECT registry_id
                         FROM registry_publications WHERE publication_id = ?1)",
                    vals![publication_id, surface_object_id, placement_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO object_placements
                     (surface_object_id, cache_id, registry_id, placement_id,
                      state, observed_hash, observed_size, etag,
                      observed_inventory_generation, observed_at,
                      catalog_object_resource_version)
                     SELECT object.id, NULL, pub.registry_id, placement.id,
                            'present', ?4, ?5, ?6, pub.ordinal, ?7,
                            object.resource_version
                     FROM registry_publications pub
                     JOIN registry_publication_objects declared
                       ON declared.publication_id = pub.publication_id
                     JOIN surface_objects object
                       ON object.id = declared.surface_object_id
                      AND object.registry_id = pub.registry_id
                     JOIN registry_publication_placements progress
                       ON progress.publication_id = pub.publication_id
                     JOIN surface_placements placement
                       ON placement.id = progress.placement_id
                      AND placement.registry_id = pub.registry_id
                     WHERE pub.publication_id = ?1 AND object.id = ?2
                       AND placement.id = ?3
                       AND pub.state IN ('preparing', 'writing_pointers')
                       AND declared.expected_hash = ?4
                       AND declared.expected_size = ?5",
                    vals![
                        publication_id,
                        surface_object_id,
                        placement_id,
                        observed_hash,
                        observed_size,
                        etag,
                        observed_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registry_publication_object_evidence
                     (publication_id, surface_object_id, placement_id,
                      observed_hash, observed_size, strong_etag, observed_at)
                     SELECT pub.publication_id, object.id, placement.id,
                            ?4, ?5, ?6, ?7
                     FROM registry_publications pub
                     JOIN registry_publication_objects declared
                       ON declared.publication_id = pub.publication_id
                     JOIN surface_objects object
                       ON object.id = declared.surface_object_id
                      AND object.registry_id = pub.registry_id
                     JOIN registry_publication_placements progress
                       ON progress.publication_id = pub.publication_id
                     JOIN surface_placements placement
                       ON placement.id = progress.placement_id
                      AND placement.registry_id = pub.registry_id
                     WHERE pub.publication_id = ?1 AND object.id = ?2
                       AND placement.id = ?3
                       AND pub.state IN ('preparing', 'writing_pointers')
                       AND declared.expected_hash = ?4
                       AND declared.expected_size = ?5
                     ON CONFLICT(publication_id, surface_object_id, placement_id)
                     DO UPDATE SET observed_hash = excluded.observed_hash,
                       observed_size = excluded.observed_size,
                       strong_etag = excluded.strong_etag,
                       observed_at = excluded.observed_at",
                    vals![
                        publication_id,
                        surface_object_id,
                        placement_id,
                        observed_hash,
                        observed_size,
                        etag,
                        observed_at
                    ],
                )
                .expecting(1),
            ])
            .await
    }

    /// Refreshes exact placement evidence for an object in the current ready publication.
    ///
    /// This is the bounded repair counterpart to upload-time evidence recording.
    /// It cannot change a declaration or attach evidence to a retired, non-current,
    /// optional, or unreconciled placement.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched evidence, a stale publication or placement,
    /// malformed input, or a database failure.
    pub async fn refresh_ready_registry_publication_object_presence(
        &self,
        publication_id: &str,
        surface_object_id: i64,
        placement_id: i64,
        observed_hash: &str,
        observed_size: i64,
        etag: &str,
        observed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(observed_hash, "observed object hash", 128)?;
        validate_key_bytes(etag, "observed object ETag", 255)?;
        if observed_size < 0 {
            bail!("observed object size cannot be negative");
        }
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM object_placements
                     WHERE surface_object_id = ?2 AND placement_id = ?3
                       AND registry_id = (SELECT registry_id
                         FROM registry_publications WHERE publication_id = ?1)",
                    vals![publication_id, surface_object_id, placement_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO object_placements
                     (surface_object_id, cache_id, registry_id, placement_id,
                      state, observed_hash, observed_size, etag,
                      observed_inventory_generation, observed_at,
                      catalog_object_resource_version)
                     SELECT object.id, NULL, publication.registry_id, placement.id,
                            'present', ?4, ?5, ?6, publication.ordinal, ?7,
                            object.resource_version
                     FROM registry_publications publication
                     JOIN registry_publication_state current
                       ON current.registry_id = publication.registry_id
                      AND current.current_publication_id = publication.publication_id
                     JOIN registry_publication_objects declared
                       ON declared.publication_id = publication.publication_id
                      AND declared.surface_object_id = ?2
                     JOIN surface_objects object
                       ON object.id = declared.surface_object_id
                      AND object.registry_id = publication.registry_id
                     JOIN registry_publication_placements required
                       ON required.publication_id = publication.publication_id
                      AND required.placement_id = ?3
                      AND required.required = 1 AND required.state = 'ready'
                     JOIN surface_placement_effective placement
                       ON placement.id = required.placement_id
                      AND placement.registry_id = publication.registry_id
                      AND placement.mutable_publication_id = publication.publication_id
                     WHERE publication.publication_id = ?1
                       AND publication.state = 'ready'
                       AND declared.expected_hash = ?4
                       AND declared.expected_size = ?5",
                    vals![
                        publication_id,
                        surface_object_id,
                        placement_id,
                        observed_hash,
                        observed_size,
                        etag,
                        observed_at
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registry_publication_object_evidence
                     (publication_id, surface_object_id, placement_id,
                      observed_hash, observed_size, strong_etag, observed_at)
                     SELECT publication.publication_id, object.id, placement.id,
                            ?4, ?5, ?6, ?7
                     FROM registry_publications publication
                     JOIN registry_publication_state current
                       ON current.registry_id = publication.registry_id
                      AND current.current_publication_id = publication.publication_id
                     JOIN registry_publication_objects declared
                       ON declared.publication_id = publication.publication_id
                      AND declared.surface_object_id = ?2
                     JOIN surface_objects object
                       ON object.id = declared.surface_object_id
                      AND object.registry_id = publication.registry_id
                     JOIN registry_publication_placements required
                       ON required.publication_id = publication.publication_id
                      AND required.placement_id = ?3
                      AND required.required = 1 AND required.state = 'ready'
                     JOIN surface_placement_effective placement
                       ON placement.id = required.placement_id
                      AND placement.registry_id = publication.registry_id
                      AND placement.mutable_publication_id = publication.publication_id
                     WHERE publication.publication_id = ?1
                       AND publication.state = 'ready'
                       AND declared.expected_hash = ?4
                       AND declared.expected_size = ?5
                     ON CONFLICT(publication_id, surface_object_id, placement_id)
                     DO UPDATE SET observed_hash = excluded.observed_hash,
                       observed_size = excluded.observed_size,
                       strong_etag = excluded.strong_etag,
                       observed_at = excluded.observed_at",
                    vals![
                        publication_id,
                        surface_object_id,
                        placement_id,
                        observed_hash,
                        observed_size,
                        etag,
                        observed_at
                    ],
                )
                .expecting(1),
            ])
            .await
    }

    // -- system of record ---------------------------------------------------

    /// Bootstraps an instance-owned identity-only registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when an existing identity has
    /// different mutable configuration.
    pub async fn register_registry(
        &self,
        slug: &str,
        trust_keys: &[String],
        require_signatures: bool,
    ) -> Result<i64> {
        aos_hub_model::domain::iam::validate_org_slug(slug)
            .map_err(|error| anyhow::anyhow!("invalid instance registry slug '{slug}': {error}"))?;
        if let Some(existing) = self.registry_by_slug(slug).await? {
            if existing.trust_keys == trust_keys
                && existing.require_signatures == require_signatures
            {
                return Ok(existing.id);
            }
            bail!(
                "registry '{slug}' already exists with different configuration; use a sealed RegistryService update plan"
            );
        }
        let now = unix_now();
        let incarnation = uuid::Uuid::new_v4();
        let id = portable_relational_id(incarnation);
        let stable_id = format!("registry:{}", incarnation.simple());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO authorization_scopes
                     (scope_key, kind, org_id, parent_scope_key, resource_stable_id, created_at)
                     VALUES (?1, 'registry', NULL, 'instance', ?1, ?2)",
                    vals![stable_id, now],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     VALUES (?1, ?1, 0)",
                    vals![stable_id],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO authorization_scope_ancestors
                     (descendant_scope_key, ancestor_scope_key, depth)
                     SELECT ?1, ancestor_scope_key, depth + 1
                       FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = 'instance'",
                    vals![stable_id],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO registries
                     (id, stable_id, slug, trust_keys, require_signatures, created_at,
                      scope_key, owner_scope_key)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?2, 'instance')",
                    vals![
                        id,
                        stable_id,
                        slug,
                        serde_json::to_string(trust_keys)?,
                        require_signatures,
                        now,
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO registry_index (registry_id, state) VALUES (?1, 'empty')",
                    vals![id],
                )
                .expecting(1),
            ])
            .await?;
        // A freshly-created registry has nothing published yet, so it starts in
        // the terminal `empty` state — not `indexing` (which reads as work in
        // progress). The indexer's transient-error guard protects this state, so
        // a flaky `info/refs` read can't bump an empty registry to `pending`; the
        // first successful surface read after a publish moves it to `fresh`.
        Ok(id)
    }

    // -- mirror sources -----------------------------------------------------

    /// Returns final registry-owned mirror configuration and controller state.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_mirror(&self, registry_id: i64) -> Result<Option<RegistryMirrorRecord>> {
        self.backend
            .query_opt(
                "SELECT registry_id, upstream_url, refspec, auth_secret_ref, mode,
                 verify, schedule_secs, last_sync_status, upstream_frontier,
                 last_sync_error, last_sync_at, resource_version
                 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .map(|row| {
                let mode: String = row.get(4)?;
                let verify: bool = row.get(5)?;
                let status: Option<String> = row.get(7)?;
                Ok(RegistryMirrorRecord {
                    registry_id: row.get(0)?,
                    source_url: row.get(1)?,
                    refspec: row.get(2)?,
                    auth_secret_ref: row.get(3)?,
                    mode: if mode == "pullthrough" {
                        "pull_through".to_string()
                    } else {
                        mode
                    },
                    signature_policy: if verify {
                        "required".to_string()
                    } else {
                        "allow_unsigned".to_string()
                    },
                    interval_seconds: row.get(6)?,
                    state: match status.as_deref() {
                        Some("ok") => "ready".to_string(),
                        Some("failed") => "failed".to_string(),
                        _ => "pending".to_string(),
                    },
                    observed_commit: row.get(8)?,
                    error: row.get(9)?,
                    last_sync_at: row.get(10)?,
                    resource_version: row.get(11)?,
                })
            })
            .transpose()
    }

    /// Creates or replaces final mirror configuration under an exact CAS.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe URLs, invalid closed values, a stale/missing
    /// resource, or database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_registry_mirror(
        &self,
        registry_id: i64,
        source_url: &str,
        refspec: &str,
        auth_secret_ref: &str,
        mode: &str,
        signature_policy: &str,
        interval_seconds: i64,
        expected_resource_version: Option<i64>,
    ) -> Result<RegistryMirrorRecord> {
        aos_hub_model::url_guard::is_safe_remote_url(source_url)
            .with_context(|| format!("rejecting mirror upstream '{source_url}'"))?;
        if !matches!(mode, "full" | "pull_through") {
            bail!("mirror mode must be full or pull_through");
        }
        if !matches!(signature_policy, "required" | "allow_unsigned") {
            bail!("signature policy must be required or allow_unsigned");
        }
        if (mode == "full" && interval_seconds <= 0) || interval_seconds < 0 {
            bail!("full mirrors require a positive interval");
        }
        let stored_mode = if mode == "pull_through" {
            "pullthrough"
        } else {
            mode
        };
        let verify = signature_policy == "required";
        let affected = if let Some(expected) = expected_resource_version {
            self.backend
                .execute(
                    "UPDATE mirror_sources SET upstream_url = ?2, refspec = ?3,
                     auth_secret_ref = ?4, mode = ?5, verify = ?6,
                     schedule_secs = ?7, last_sync_status = NULL,
                     last_sync_error = NULL, resource_version = resource_version + 1
                     WHERE registry_id = ?1 AND resource_version = ?8",
                    &vals![
                        registry_id,
                        source_url,
                        refspec,
                        auth_secret_ref,
                        stored_mode,
                        verify,
                        interval_seconds,
                        expected
                    ],
                )
                .await?
        } else {
            self.backend
                .execute(
                    "INSERT INTO mirror_sources
                     (registry_id, upstream_url, refspec, auth_secret_ref, mode,
                      verify, schedule_secs, resource_version)
                     SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1
                     WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM mirror_sources WHERE registry_id = ?1)",
                    &vals![
                        registry_id,
                        source_url,
                        refspec,
                        auth_secret_ref,
                        stored_mode,
                        verify,
                        interval_seconds
                    ],
                )
                .await?
        };
        if affected != 1 {
            bail!("registry mirror is missing, duplicated, or stale");
        }
        self.registry_mirror(registry_id)
            .await?
            .context("registry mirror disappeared")
    }

    /// Deletes mirror configuration under an exact resource version.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_registry_mirror_at_version(
        &self,
        registry_id: i64,
        expected_resource_version: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "DELETE FROM mirror_sources WHERE registry_id = ?1
                 AND resource_version = ?2",
                &vals![registry_id, expected_resource_version],
            )
            .await?
            == 1)
    }

    /// Begins a mutable-pointer advance by first clearing the placement watermark.
    ///
    /// A crash between the clear and progress transition is fail-closed: readers
    /// never mistake the old watermark for the new publication.
    ///
    /// # Errors
    ///
    /// Returns an error for stale placement/publication progress or database failure.
    pub async fn begin_registry_pointer_advance(
        &self,
        publication_id: &str,
        placement_id: i64,
        expected_placement_version: i64,
        expected_watermark_version: i64,
        observed_at: i64,
    ) -> Result<SurfacePlacementRecord> {
        self.backend
            .execute(
                "UPDATE registry_placement_publication_watermarks
                 SET mutable_publication_id = NULL, pending_publication_id = ?1,
                     observed_at = ?5,
                     resource_version = resource_version + 1
                 WHERE placement_id = ?2 AND resource_version = ?4
                   AND pending_publication_id IS NULL
                   AND EXISTS (SELECT 1 FROM surface_placements p
                     JOIN registry_publications pub ON pub.registry_id = p.registry_id
                     JOIN registry_publication_placements pp
                       ON pp.publication_id = pub.publication_id AND pp.placement_id = p.id
                     WHERE p.id = ?2 AND p.resource_version = ?3
                       AND pub.publication_id = ?1 AND pub.state = 'writing_pointers'
                       AND pp.state = 'preparing')",
                &vals![
                    publication_id,
                    placement_id,
                    expected_placement_version,
                    expected_watermark_version,
                    observed_at
                ],
            )
            .await?;
        if self
            .backend
            .query_opt(
                "SELECT 1 FROM surface_placements p
                 JOIN registry_placement_publication_watermarks w ON w.placement_id = p.id
                 JOIN registry_publication_placements pp ON pp.placement_id = p.id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE p.id = ?2 AND pp.publication_id = ?1
                   AND p.resource_version = ?3
                   AND pp.state IN ('preparing', 'writing_pointers')
                   AND pub.state = 'writing_pointers'
                   AND w.resource_version IN (?4, ?4 + 1)
                   AND w.mutable_publication_id IS NULL
                   AND w.pending_publication_id = ?1",
                &vals![
                    publication_id,
                    placement_id,
                    expected_placement_version,
                    expected_watermark_version
                ],
            )
            .await?
            .is_none()
        {
            bail!("placement pointer advance is stale or cross-registry");
        }
        let moved = self.backend.execute(
            "UPDATE registry_publication_placements SET state = 'writing_pointers', observed_at = ?3
             WHERE publication_id = ?1 AND placement_id = ?2
               AND state = 'preparing'
               AND EXISTS (SELECT 1 FROM registry_publications pub
                 WHERE pub.publication_id = ?1 AND pub.state = 'writing_pointers')",
            &vals![publication_id, placement_id, observed_at],
        ).await?;
        if moved != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_publication_placements pp
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state = 'writing_pointers'
                   AND pub.state = 'writing_pointers'",
                    &vals![publication_id, placement_id],
                )
                .await?
                .is_none()
        {
            bail!("publication placement is not ready to write pointers");
        }
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared")
    }

    /// Publishes the authoritative placement watermark with one guarded CAS.
    ///
    /// # Errors
    ///
    /// Returns an error unless every manifest object is present exactly, progress
    /// is writing pointers, placement version is current, and ownership matches.
    pub async fn finalize_registry_pointer_advance(
        &self,
        publication_id: &str,
        placement_id: i64,
        expected_placement_version: i64,
        expected_watermark_version: i64,
        observed_at: i64,
    ) -> Result<SurfacePlacementRecord> {
        let published = self
            .backend
            .execute(
                "UPDATE registry_placement_publication_watermarks
             SET mutable_publication_id = ?1, pending_publication_id = NULL,
                 observed_at = ?5,
                 resource_version = resource_version + 1
             WHERE placement_id = ?2 AND resource_version = ?4
               AND mutable_publication_id IS NULL
               AND pending_publication_id = ?1
               AND EXISTS (SELECT 1 FROM surface_placements p
                 JOIN registry_publications pub ON pub.registry_id = p.registry_id
                 WHERE p.id = ?2 AND p.resource_version = ?3
               AND pub.publication_id = ?1 AND pub.state = 'writing_pointers'
               AND EXISTS (SELECT 1 FROM registry_publication_placements pp
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state IN ('writing_pointers', 'ready'))
               AND EXISTS (SELECT 1 FROM registry_publication_objects
                 WHERE publication_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM registry_publication_objects po
                 WHERE po.publication_id = ?1 AND NOT EXISTS (
                   SELECT 1 FROM object_placements op
                   WHERE op.surface_object_id = po.surface_object_id
                     AND op.placement_id = ?2 AND op.state = 'present'
                     AND op.observed_hash = po.expected_hash
                     AND op.observed_size = po.expected_size)))",
                &vals![
                    publication_id,
                    placement_id,
                    expected_placement_version,
                    expected_watermark_version,
                    observed_at
                ],
            )
            .await?;
        if published != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM surface_placements p
                 JOIN registry_placement_publication_watermarks w ON w.placement_id = p.id
                 JOIN registry_publication_placements pp ON pp.placement_id = p.id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE p.id = ?2 AND pp.publication_id = ?1
                   AND p.resource_version = ?3
                   AND w.resource_version = ?4 + 1
                   AND w.mutable_publication_id = ?1 AND w.observed_at = ?5
                   AND w.pending_publication_id IS NULL
                   AND pp.state IN ('writing_pointers', 'ready')
                   AND pub.state = 'writing_pointers'",
                    &vals![
                        publication_id,
                        placement_id,
                        expected_placement_version,
                        expected_watermark_version,
                        observed_at
                    ],
                )
                .await?
                .is_none()
        {
            bail!("placement watermark CAS is stale or cross-registry");
        }
        let ready = self
            .backend
            .execute(
                "UPDATE registry_publication_placements
                 SET state = 'ready', observed_at = ?3
                 WHERE publication_id = ?1 AND placement_id = ?2
                   AND state IN ('writing_pointers', 'ready')
                   AND EXISTS (SELECT 1 FROM registry_publications pub
                     WHERE pub.publication_id = ?1 AND pub.state = 'writing_pointers')
                   AND EXISTS (SELECT 1 FROM registry_placement_publication_watermarks w
                     WHERE w.placement_id = ?2 AND w.mutable_publication_id = ?1)",
                &vals![publication_id, placement_id, observed_at],
            )
            .await?;
        if ready != 1
            && self
                .backend
                .query_opt(
                    "SELECT 1 FROM registry_publication_placements pp
                 JOIN registry_placement_publication_watermarks w ON w.placement_id = pp.placement_id
                 JOIN registry_publications pub ON pub.publication_id = pp.publication_id
                 WHERE pp.publication_id = ?1 AND pp.placement_id = ?2
                   AND pp.state = 'ready' AND w.mutable_publication_id = ?1
                   AND pub.state = 'writing_pointers'",
                    &vals![publication_id, placement_id],
                )
                .await?
                .is_none()
        {
            bail!("publication placement progress could not record the published watermark");
        }
        self.surface_placement(placement_id)
            .await?
            .context("placement disappeared")
    }

    /// Converts one legacy immutable registry object into a replaceable pointer
    /// while preserving its currently published identity.
    ///
    /// This migration is reserved for paths classified as replaceable by the
    /// shared machine-surface policy. It lets deployments adopt stricter path
    /// semantics without taking the currently published bytes offline.
    /// When a current publication exists, the converted row remains owned by
    /// it until the new publication completes, so reads stay available
    /// throughout migration.
    ///
    /// # Errors
    ///
    /// Returns an error unless the object and preparing publication belong to
    /// the same registry, the object is active and immutable (or was already
    /// converted by an equivalent concurrent admission), or the database
    /// operation fails.
    pub async fn convert_registry_object_to_mutable(
        &self,
        registry_id: i64,
        surface_object_id: i64,
        object_key: &str,
        preparing_publication_id: &str,
    ) -> Result<SurfaceObjectRecord> {
        validate_key_bytes(object_key, "surface object key", 512)?;
        validate_key_bytes(preparing_publication_id, "publication id", 64)?;
        if !aos_registry_format::keymap::is_mutable_path(object_key) {
            bail!("surface object path is not replaceable metadata");
        }
        let now = unix_now();
        self.backend
            .execute(
                "UPDATE surface_objects
                 SET object_kind = 'mutable_pointer', partition_key = NULL,
                     mutable_publication_id = COALESCE(
                       (SELECT state.current_publication_id
                        FROM registry_publication_state state
                        WHERE state.registry_id = ?1),
                       ?4),
                     updated_at = ?5, resource_version = resource_version + 1
                 WHERE id = ?2 AND registry_id = ?1 AND cache_id IS NULL
                   AND object_key = ?3 AND lifecycle_state = 'active'
                   AND object_kind = 'immutable' AND mutable_publication_id IS NULL
                   AND EXISTS (SELECT 1 FROM registry_publications publication
                     WHERE publication.publication_id = ?4
                       AND publication.registry_id = ?1
                       AND publication.state = 'preparing')",
                &vals![
                    registry_id,
                    surface_object_id,
                    object_key,
                    preparing_publication_id,
                    now
                ],
            )
            .await?;
        let object = self
            .surface_object(surface_object_id)
            .await?
            .context("converted registry object disappeared")?;
        if object.registry_id != Some(registry_id)
            || object.object_key != object_key
            || object.lifecycle_state != "active"
            || object.object_kind != "mutable_pointer"
        {
            bail!("loose object conversion is stale or cross-registry");
        }
        Ok(object)
    }

    /// Records exact storage presence for signed image roots on the indexed placement.
    ///
    /// # Errors
    ///
    /// Returns an error when the placement is not on the registry, an object is
    /// not a matching signed root, or the database write fails.
    pub async fn record_registry_image_presence(
        &self,
        registry_id: i64,
        placement_id: i64,
        objects: &[VerifiedRegistryImageObject],
        observed_at: i64,
    ) -> Result<()> {
        let statements = Self::registry_image_presence_statements(
            registry_id,
            placement_id,
            objects,
            observed_at,
        )?;
        self.backend.checked_batch(&statements).await
    }

    /// Resolves the immutable authorization scope governing a registry.
    ///
    /// This is always the exact registry resource scope, never its organization
    /// or project infrastructure-owner scope.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry or its live owner scope is missing.
    pub async fn registry_authorization_scope(&self, registry_id: i64) -> Result<String> {
        self.backend
            .query_opt(
                "SELECT r.scope_key
                   FROM registries r LEFT JOIN orgs o ON o.id = r.org_id
                  WHERE r.id = ?1 AND (r.org_id IS NULL OR o.deleted_at IS NULL)",
                &vals![registry_id],
            )
            .await?
            .context("registry or live owner organization does not exist")?
            .get(0)
    }

    /// Resolve a managed registry by its canonical `{org}/{project_path}/{name}`
    /// coordinates.
    ///
    /// Builds the canonical slug (`"{org}/{name}"` when `project_path` is
    /// empty, otherwise `"{org}/{project_path}/{name}"`) and delegates to
    /// [`Database::registry_by_slug`] — managed registries store their full
    /// canonical path as their slug (see the [module docs](self)). Returns
    /// `Ok(None)` when no registry has that canonical path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_by_scope(
        &self,
        org_slug: &str,
        project_path: &str,
        name: &str,
    ) -> Result<Option<RegistryRecord>> {
        self.registry_by_slug(&canonical_slug(org_slug, project_path, name))
            .await
    }

    /// Creates a managed, organization-owned registry identity; returns its id.
    ///
    /// The registry is stored with its full canonical path
    /// (`{org}/{project_path}/{name}`) as its slug and stores the exact owning
    /// organization or project authorization scope. Canonical uniqueness is
    /// enforced both by the up-front
    /// [`Database::registry_by_scope`] check and by the underlying
    /// `UNIQUE(slug)` constraint.
    ///
    /// Physical storage is deliberately not part of identity creation. A
    /// caller creates placements independently and then reconciles an explicit
    /// write authority.
    ///
    /// # Errors
    ///
    /// Returns an error when a registry already exists at the canonical
    /// path or on database failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_managed_registry(
        &self,
        org_id: i64,
        project_path: &str,
        name: &str,
        visibility: &str,
        trust_keys: &[String],
        require_signatures: bool,
    ) -> Result<i64> {
        self.create_managed_registry_with_plan(
            org_id,
            project_path,
            name,
            visibility,
            trust_keys,
            require_signatures,
            "allow_all",
            None,
        )
        .await
    }

    /// Creates a managed registry attributed to one immutable control plan.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::create_managed_registry`], plus a
    /// duplicate-plan conflict.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_managed_registry_from_plan(
        &self,
        org_id: i64,
        project_path: &str,
        name: &str,
        visibility: &str,
        trust_keys: &[String],
        require_signatures: bool,
        crawl_policy: &str,
        plan_id: &str,
    ) -> Result<i64> {
        self.create_managed_registry_with_plan(
            org_id,
            project_path,
            name,
            visibility,
            trust_keys,
            require_signatures,
            crawl_policy,
            Some(plan_id),
        )
        .await
    }

    /// Returns whether a registry was created by the exact control plan.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_matches_creation_plan(
        &self,
        registry_id: i64,
        plan_id: &str,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM registries WHERE id = ?1 AND creation_plan_id = ?2",
                &vals![registry_id, plan_id],
            )
            .await?
            .is_some())
    }

    /// Deletes a registry fixture without exercising the control plane.
    ///
    /// Removes the `registries` row by id; the index tables
    /// (`registry_index`, `packages`, `channels`, the roster, validation runs,
    /// …) all carry `ON DELETE CASCADE` foreign keys on `registries(id)`, so
    /// they are removed in the same statement. This is the registry analog of
    /// the org [`Database::hard_purge_org`] hard delete.
    ///
    /// This does **not** delete the registry's surface content on the storage
    /// binding's backend (the `{root}/{prefix}` directory): that content lives
    /// outside SQL and is left in place, so the same surface can be re-bound by
    /// a new managed registry later. Returns `Ok(false)` when no registry has
    /// the given id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    /// This helper does not exist in optimized production builds. Runtime code
    /// must use the Registry service's sealed delete plan.
    #[cfg(any(test, debug_assertions))]
    pub async fn seed_delete_registry_for_test(&self, registry_id: i64) -> Result<bool> {
        let Some(scope_key) = self
            .backend
            .query_opt(
                "SELECT scope_key FROM registries WHERE id = ?1",
                &vals![registry_id],
            )
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?
        else {
            return Ok(false);
        };
        self.backend
            .checked_batch(&[
                Statement::new(
                    "DELETE FROM registries WHERE id = ?1 AND scope_key = ?2",
                    vals![registry_id, scope_key],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE authorization_scopes SET retired_at = ?2
                      WHERE scope_key = ?1 AND kind = 'registry' AND retired_at IS NULL",
                    vals![scope_key, unix_now()],
                )
                .expecting(1),
            ])
            .await?;
        Ok(true)
    }

    // -- registry configuration ---------------------------------------------

    /// Applies one planned registry configuration revision atomically.
    ///
    /// The exact registry-head CAS, applied change-set, full before/after
    /// revision, actor-attributed audit row, and durable topology event commit
    /// together. No caller can observe or retry a partially recorded change.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails or the checked transaction
    /// cannot commit. Returns `Ok(false)` when the registry no longer matches
    /// `expected_version`.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_registry_configuration_change(
        &self,
        registry_id: i64,
        expected_version: i64,
        visibility: &str,
        crawl_policy: &str,
        llms_txt_body: Option<&str>,
        trust_keys: &[String],
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        let Some(current) = self.registry_by_id(registry_id).await? else {
            return Ok(false);
        };
        if current.resource_version != expected_version {
            let replayed = current.resource_version == expected_version + 1
                && current.visibility == visibility
                && current.crawl_policy == crawl_policy
                && current.llms_txt_body.as_deref() == llms_txt_body
                && current.trust_keys == trust_keys
                && self
                    .changeset(change_id)
                    .await?
                    .map_or(false, |changeset| changeset.status == "applied")
                && self
                    .list_revisions(change_id)
                    .await?
                    .iter()
                    .any(|revision| {
                        revision.object_type == "registry"
                            && revision.object_id == current.stable_id.as_str()
                            && revision.op == "update"
                    });
            if replayed {
                return Ok(true);
            }
            return Ok(false);
        }
        let now = unix_now();
        let next_version = expected_version + 1;
        let old_json = serde_json::to_string(&serde_json::json!({
            "stableId": &current.stable_id,
            "slug": &current.slug,
            "visibility": &current.visibility,
            "crawlPolicy": &current.crawl_policy,
            "llmsTxtBody": &current.llms_txt_body,
            "trustKeys": &current.trust_keys,
            "resourceVersion": expected_version,
        }))?;
        let new_json = serde_json::to_string(&serde_json::json!({
            "stableId": &current.stable_id,
            "slug": &current.slug,
            "visibility": visibility,
            "crawlPolicy": crawl_policy,
            "llmsTxtBody": llms_txt_body,
            "trustKeys": trust_keys,
            "resourceVersion": next_version,
        }))?;
        let event_id = uuid::Uuid::new_v4().simple().to_string();
        let payload_json = serde_json::to_string(&serde_json::json!({
            "changeId": change_id,
            "registryId": &current.stable_id,
            "slug": &current.slug,
            "resourceVersion": next_version,
        }))?;
        let event = NewTopologyEvent {
            event_id: &event_id,
            event_name: "registry.configuration.updated",
            owner_scope_key: &current.scope_key,
            resource_kind: "registry",
            resource_stable_id: &current.stable_id,
            resource_generation_key: next_version,
            actor_kind,
            actor_id,
            actor_label,
            payload_json: &payload_json,
            occurred_at: now,
        };
        let summary = format!("update registry '{}' configuration", current.slug);
        let result = self
            .backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE registries SET visibility = ?3, crawl_policy = ?4,
                     llms_txt_body = ?5, trust_keys = ?6,
                     resource_version = resource_version + 1, updated_at = ?7
                     WHERE id = ?1 AND resource_version = ?2",
                    vals![
                        registry_id,
                        expected_version,
                        visibility,
                        crawl_policy,
                        llms_txt_body,
                        serde_json::to_string(trust_keys)?,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_requests
                     (change_id, actor_kind, actor_id, actor_label, scope, status,
                      summary, created_at, applied_at)
                     SELECT ?1, ?2, ?3, ?4, scope_key, 'applied', ?6, ?7, ?7
                       FROM registries WHERE id = ?5 AND resource_version = ?8",
                    vals![
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        registry_id,
                        summary,
                        now,
                        next_version
                    ],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO change_request_revisions
                     (change_id, object_type, object_id, op, old_json, new_json, seq)
                     VALUES (?1, 'registry', ?2, 'update', ?3, ?4, 0)",
                    vals![change_id, current.stable_id, old_json, new_json],
                )
                .expecting(1),
                Statement::new(
                    "INSERT INTO audit_log
                     (outbox_event_id, change_id, actor_kind, actor_id, actor_label,
                      action, scope, detail, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5,
                             'registry.configuration.updated', ?6, ?7, ?8)",
                    vals![
                        event_id,
                        change_id,
                        actor_kind,
                        actor_id,
                        sanitize_log_text(actor_label),
                        current.scope_key,
                        payload_json,
                        now
                    ],
                )
                .expecting(1),
                Self::topology_event_statement(&event),
            ])
            .await;
        if let Err(error) = result {
            if self
                .registry_by_id(registry_id)
                .await?
                .map_or(true, |record| record.resource_version != expected_version)
            {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(true)
    }

    /// Applies a registry configuration fixture through the production atomic path.
    ///
    /// This helper is absent from optimized production builds and exists only
    /// so integration tests can establish or perturb exact-version state.
    ///
    /// # Errors
    ///
    /// Returns the same errors as the internal normalized apply primitive.
    #[cfg(any(test, debug_assertions, feature = "do-e2e-test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn seed_registry_configuration_for_test(
        &self,
        registry_id: i64,
        expected_version: i64,
        visibility: &str,
        crawl_policy: &str,
        llms_txt_body: Option<&str>,
        trust_keys: &[String],
        change_id: &str,
        actor_kind: &str,
        actor_id: Option<i64>,
        actor_label: &str,
    ) -> Result<bool> {
        self.apply_registry_configuration_change(
            registry_id,
            expected_version,
            visibility,
            crawl_policy,
            llms_txt_body,
            trust_keys,
            change_id,
            actor_kind,
            actor_id,
            actor_label,
        )
        .await
    }

    /// Reports whether a publication can still change a registry's visible surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn registry_has_active_publication(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_publications
                 WHERE registry_id = ?1 AND state IN ('preparing', 'writing_pointers')
                 LIMIT 1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// Begins an invisible registry publication at the registry's next ordinal.
    ///
    /// The parent is compared with the authoritative current publication in the
    /// same transaction. A producer can therefore never build on a stale head.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, a stale parent, duplicate
    /// generation or manifest identity, a missing registry, or database failure.
    pub async fn create_registry_publication(
        &self,
        input: &NewRegistryPublication,
    ) -> Result<RegistryPublicationRecord> {
        validate_key_bytes(&input.publication_id, "publication id", 64)?;
        validate_key_bytes(&input.generation, "publication generation", 128)?;
        validate_key_bytes(&input.manifest_digest, "publication manifest digest", 128)?;
        validate_key_bytes(&input.refs_digest, "publication refs digest", 128)?;
        if let Some(commit) = input.default_commit.as_deref() {
            validate_key_bytes(commit, "publication default commit", 128)?;
        }
        if let Some(parent) = input.parent_publication_id.as_deref() {
            validate_key_bytes(parent, "parent publication id", 64)?;
        }
        let now = unix_now();
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO registry_publication_state
                     (registry_id, current_publication_id, next_ordinal,
                      resource_version, updated_at)
                     SELECT id, NULL, 1, 1, ?2 FROM registries WHERE id = ?1
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![input.registry_id, now],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO registry_publications
                     (publication_id, registry_id, ordinal, generation,
                      manifest_digest, refs_digest, default_commit,
                      parent_publication_id, state, created_at)
                     SELECT ?1, state.registry_id, state.next_ordinal, ?3, ?4,
                            ?5, ?6, ?7, 'preparing', ?8
                     FROM registry_publication_state state
                     JOIN registries registry ON registry.id = state.registry_id
                     LEFT JOIN orgs org ON org.id = registry.org_id
                     WHERE state.registry_id = ?2
                       AND (registry.org_id IS NULL OR org.deleted_at IS NULL)
                       AND (state.current_publication_id = ?7 OR
                            (state.current_publication_id IS NULL AND ?7 IS NULL))",
                    vals![
                        input.publication_id,
                        input.registry_id,
                        input.generation,
                        input.manifest_digest,
                        input.refs_digest,
                        input.default_commit,
                        input.parent_publication_id,
                        now
                    ],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE registry_publication_state
                     SET next_ordinal = next_ordinal + 1,
                         resource_version = resource_version + 1,
                         updated_at = ?3
                     WHERE registry_id = ?1 AND next_ordinal = (
                       SELECT ordinal FROM registry_publications
                       WHERE publication_id = ?2)",
                    vals![input.registry_id, input.publication_id, now],
                )
                .expecting(1),
            ])
            .await?;
        self.registry_publication(&input.publication_id)
            .await?
            .context("created registry publication disappeared")
    }

    /// Reopens an exact failed publication that has never become visible.
    ///
    /// The registry head must still equal the publication's frozen parent.
    /// Object identities remain immutable; admission replays their idempotent
    /// declarations after this state reset.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed id, stale parent, non-failed state, or
    /// database failure.
    pub async fn retry_failed_registry_publication(
        &self,
        publication_id: &str,
        now: i64,
    ) -> Result<RegistryPublicationRecord> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE registry_publications SET state = 'preparing',
                       completed_at = NULL, retired_at = NULL
                     WHERE publication_id = ?1 AND state = 'failed'
                       AND EXISTS (SELECT 1 FROM registry_publication_state state
                         WHERE state.registry_id = registry_publications.registry_id
                           AND (state.current_publication_id = registry_publications.parent_publication_id
                             OR (state.current_publication_id IS NULL
                               AND registry_publications.parent_publication_id IS NULL)))",
                    vals![publication_id],
                )
                .expecting(1),
                Statement::new(
                    "UPDATE registry_publication_placements
                     SET state = 'preparing', observed_at = ?2
                     WHERE publication_id = ?1 AND state = 'failed'",
                    vals![publication_id, now],
                )
                .unchecked(),
            ])
            .await?;
        self.registry_publication(publication_id)
            .await?
            .context("retried registry publication disappeared")
    }

    /// Returns one registry publication by stable id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication(
        &self,
        publication_id: &str,
    ) -> Result<Option<RegistryPublicationRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .query_opt(
                "SELECT publication_id, registry_id, ordinal, generation,
                        manifest_digest, refs_digest, default_commit,
                        parent_publication_id, state, created_at, completed_at,
                        retired_at
                 FROM registry_publications WHERE publication_id = ?1",
                &vals![publication_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    ordinal: row.get(2)?,
                    generation: row.get(3)?,
                    manifest_digest: row.get(4)?,
                    refs_digest: row.get(5)?,
                    default_commit: row.get(6)?,
                    parent_publication_id: row.get(7)?,
                    state: row.get(8)?,
                    created_at: row.get(9)?,
                    completed_at: row.get(10)?,
                    retired_at: row.get(11)?,
                })
            })
            .transpose()
    }

    /// Returns the publication that owns one registry generation identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn registry_publication_by_generation(
        &self,
        registry_id: i64,
        generation: &str,
    ) -> Result<Option<RegistryPublicationRecord>> {
        validate_key_bytes(generation, "publication generation", 128)?;
        self.backend
            .query_opt(
                "SELECT publication_id, registry_id, ordinal, generation,
                        manifest_digest, refs_digest, default_commit,
                        parent_publication_id, state, created_at, completed_at,
                        retired_at
                 FROM registry_publications
                 WHERE registry_id = ?1 AND generation = ?2",
                &vals![registry_id, generation],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    ordinal: row.get(2)?,
                    generation: row.get(3)?,
                    manifest_digest: row.get(4)?,
                    refs_digest: row.get(5)?,
                    default_commit: row.get(6)?,
                    parent_publication_id: row.get(7)?,
                    state: row.get(8)?,
                    created_at: row.get(9)?,
                    completed_at: row.get(10)?,
                    retired_at: row.get(11)?,
                })
            })
            .transpose()
    }

    /// Binds reusable placement evidence to a newly admitted publication.
    ///
    /// Immutable objects may already be present with an exact digest, size, and
    /// backend version from an earlier publication. This snapshots that evidence
    /// into the new publication receipt so deduplication does not weaken the
    /// publication-scoped image verification performed by the indexer.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed publication id or database failure.
    pub async fn inherit_registry_publication_object_evidence(
        &self,
        publication_id: &str,
        observed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        if observed_at < 0 {
            bail!("publication evidence observation time cannot be negative");
        }
        self.backend
            .execute(
                "INSERT INTO registry_publication_object_evidence
                   (publication_id, surface_object_id, placement_id,
                    observed_hash, observed_size, strong_etag, observed_at)
                 SELECT publication.publication_id, object.id, placement.id,
                        presence.observed_hash, presence.observed_size,
                        presence.etag, ?2
                 FROM registry_publications publication
                 JOIN registry_publication_objects declared
                   ON declared.publication_id = publication.publication_id
                 JOIN surface_objects object
                   ON object.id = declared.surface_object_id
                  AND object.registry_id = publication.registry_id
                  AND object.lifecycle_state = 'active'
                 JOIN registry_publication_placements required
                   ON required.publication_id = publication.publication_id
                  AND required.required = 1
                 JOIN surface_placements placement
                   ON placement.id = required.placement_id
                  AND placement.registry_id = publication.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.placement_id = placement.id
                  AND presence.registry_id = publication.registry_id
                  AND presence.cache_id IS NULL
                  AND presence.state = 'present'
                  AND presence.observed_hash = declared.expected_hash
                  AND presence.observed_size = declared.expected_size
                  AND presence.catalog_object_resource_version = object.resource_version
                 WHERE publication.publication_id = ?1
                   AND publication.state IN ('preparing', 'writing_pointers')
                 ON CONFLICT(publication_id, surface_object_id, placement_id)
                 DO NOTHING",
                &vals![publication_id, observed_at],
            )
            .await?;
        Ok(())
    }

    /// Restores missing evidence for the exact current ready publication.
    ///
    /// This is the idempotent commit-recovery path for objects whose durable
    /// placement identity is still exact. The signed index independently
    /// compares each inherited strong ETag with the live backend before making
    /// an image visible.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed publication id, a negative observation
    /// time, or database failure.
    pub async fn restore_ready_registry_publication_object_evidence(
        &self,
        publication_id: &str,
        observed_at: i64,
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        if observed_at < 0 {
            bail!("publication evidence observation time cannot be negative");
        }
        self.backend
            .execute(
                "INSERT INTO registry_publication_object_evidence
                   (publication_id, surface_object_id, placement_id,
                    observed_hash, observed_size, strong_etag, observed_at)
                 SELECT publication.publication_id, object.id, placement.id,
                        presence.observed_hash, presence.observed_size,
                        presence.etag, ?2
                 FROM registry_publications publication
                 JOIN registry_publication_state current
                   ON current.registry_id = publication.registry_id
                  AND current.current_publication_id = publication.publication_id
                 JOIN registry_publication_objects declared
                   ON declared.publication_id = publication.publication_id
                 JOIN surface_objects object
                   ON object.id = declared.surface_object_id
                  AND object.registry_id = publication.registry_id
                  AND object.lifecycle_state = 'active'
                  AND object.content_hash = declared.expected_hash
                  AND object.size = declared.expected_size
                  AND (object.object_kind = 'immutable'
                    OR object.mutable_publication_id = publication.publication_id)
                 JOIN registry_publication_placements required
                   ON required.publication_id = publication.publication_id
                  AND required.required = 1 AND required.state = 'ready'
                 JOIN surface_placement_effective placement
                   ON placement.id = required.placement_id
                  AND placement.registry_id = publication.registry_id
                  AND placement.mutable_publication_id = publication.publication_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.placement_id = placement.id
                  AND presence.registry_id = publication.registry_id
                  AND presence.cache_id IS NULL
                  AND presence.state = 'present'
                  AND presence.observed_hash = declared.expected_hash
                  AND presence.observed_size = declared.expected_size
                  AND presence.etag IS NOT NULL
                 WHERE publication.publication_id = ?1
                   AND publication.state = 'ready'
                 ON CONFLICT(publication_id, surface_object_id, placement_id)
                 DO NOTHING",
                &vals![publication_id, observed_at],
            )
            .await?;
        Ok(())
    }
}
