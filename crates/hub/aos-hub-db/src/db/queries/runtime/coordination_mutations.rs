//! Coordination mutations in the runtime capability.

use super::*;

impl Database {
    /// The instance's signup policy (defaulting to invite-only when unset).
    ///
    /// Reads the `signup_policy` instance-config key and parses it through
    /// [`SignupPolicy::parse`] (any unknown value falls closed to
    /// invite-only).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn signup_policy(&self) -> Result<SignupPolicy> {
        Ok(self
            .instance_config_get("signup_policy")
            .await?
            .map(|v| SignupPolicy::parse(&v))
            .unwrap_or(SignupPolicy::InviteOnly))
    }

    /// Set the instance signup policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_signup_policy(&self, policy: SignupPolicy) -> Result<()> {
        self.instance_config_set("signup_policy", policy.as_str())
            .await
    }

    /// Lists Hub-private image snapshots with zero live references.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn collectible_image_snapshots(&self, limit: i64) -> Result<Vec<(String, i64)>> {
        let now = unix_now();
        let rows = self
            .backend
            .query(
                "SELECT digest, byte_size FROM image_snapshots snapshot
                 WHERE NOT EXISTS (
                   SELECT 1 FROM image_snapshot_references reference
                   WHERE reference.digest = snapshot.digest)
                   AND NOT EXISTS (
                     SELECT 1 FROM staged_release_objects staged_object
                     JOIN staged_release_revisions staged_revision
                       ON staged_revision.registry_id = staged_object.registry_id
                      AND staged_revision.stage_id = staged_object.stage_id
                      AND staged_revision.revision = staged_object.revision
                     WHERE staged_object.sha256 = snapshot.digest
                       AND (staged_revision.retire_after IS NULL
                         OR staged_revision.retire_after > ?2))
                   AND NOT EXISTS (
                     SELECT 1 FROM image_snapshot_leases lease
                     WHERE lease.digest = snapshot.digest AND lease.expires_at > ?2)
                 ORDER BY digest LIMIT ?1",
                &vals![limit, now],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?)))
            .collect()
    }

    /// Returns all durable snapshot identities for native startup validation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn known_image_snapshots(&self) -> Result<Vec<(String, i64)>> {
        self.backend
            .query(
                "SELECT digest, byte_size FROM image_snapshots ORDER BY digest",
                &[],
            )
            .await?
            .iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?)))
            .collect()
    }

    /// Mark a registry as a mirror of `upstream_url` in `mode`.
    ///
    /// Idempotent: re-running for the same registry updates the upstream URL,
    /// mode, verify flag, and schedule, preserving the last-sync record. `mode`
    /// must be `full` or `pullthrough`. The `upstream_url` is validated as a
    /// safe remote target ([`aos_hub_model::url_guard::is_safe_remote_url`]) so a mirror
    /// can never be pointed at the local filesystem or an internal address.
    ///
    /// # Errors
    ///
    /// Returns an error for an unrecognized `mode`, an unsafe (local/internal
    /// or non-HTTP) `upstream_url`, or on database failure.
    pub async fn create_mirror_source(
        &self,
        registry_id: i64,
        upstream_url: &str,
        mode: &str,
        verify: bool,
        schedule_secs: i64,
    ) -> Result<()> {
        if !matches!(mode, "full" | "pullthrough") {
            bail!("unsupported mirror mode '{mode}' (expected full or pullthrough)");
        }
        aos_hub_model::url_guard::is_safe_remote_url(upstream_url)
            .with_context(|| format!("rejecting mirror upstream '{upstream_url}'"))?;
        self.backend
            .execute(
                "INSERT INTO mirror_sources
             (registry_id, upstream_url, mode, verify, schedule_secs)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(registry_id) DO UPDATE SET
               upstream_url = excluded.upstream_url,
               mode = excluded.mode,
               verify = excluded.verify,
               schedule_secs = excluded.schedule_secs",
                &vals![registry_id, upstream_url, mode, verify, schedule_secs],
            )
            .await?;
        Ok(())
    }

    /// Load a registry's mirror source, if it is a mirror.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mirror_source(&self, registry_id: i64) -> Result<Option<MirrorSource>> {
        self.backend
            .query_opt(
                "SELECT upstream_url, mode, verify, schedule_secs, last_sync_at,
                        last_sync_status, last_sync_error, upstream_frontier
                 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading mirror source")?
            .map(|row| row_to_mirror_source(&row))
            .transpose()
    }

    /// Stop mirroring: remove a registry's mirror source. Returns whether a row
    /// was removed.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delete_mirror_source(&self, registry_id: i64) -> Result<bool> {
        let n = self
            .backend
            .execute(
                "DELETE FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        Ok(n > 0)
    }

    /// Record the outcome of a mirror sync attempt.
    ///
    /// `status` is `ok` or `failed`; on success `error` is `None` and
    /// `upstream_frontier` records the synced frontier, on failure `error`
    /// carries the detail and the prior `upstream_frontier` is preserved (so a
    /// failed sync never overwrites the last good frontier with `NULL`).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn update_mirror_sync(
        &self,
        registry_id: i64,
        at: i64,
        status: &str,
        error: Option<&str>,
        upstream_frontier: Option<&str>,
    ) -> Result<()> {
        // On a failed sync, keep the prior upstream_frontier (COALESCE the new
        // NULL onto the old value) so the health page still shows the last good
        // frontier.
        self.backend
            .execute(
                "UPDATE mirror_sources SET
               last_sync_at = ?2,
               last_sync_status = ?3,
               last_sync_error = ?4,
               upstream_frontier = COALESCE(?5, upstream_frontier)
             WHERE registry_id = ?1",
                &vals![registry_id, at, status, error, upstream_frontier],
            )
            .await?;
        Ok(())
    }

    /// Requests promotion or credential rotation with an authority CAS.
    ///
    /// The candidate may equal the current placement when only the immutable
    /// binding revision changes.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale authority or an ineligible candidate.
    pub async fn request_surface_write_promotion(
        &self,
        authority_id: i64,
        expected_incarnation_id: &str,
        expected_version: i64,
        expected_observed_placement_id: i64,
        placement_id: i64,
        expected_candidate_write_spec_version: i64,
        binding_write_revision: i64,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        validate_key_bytes(
            expected_incarnation_id,
            "write authority incarnation id",
            64,
        )?;
        let affected = self
            .backend
            .execute(
                "UPDATE surface_write_authorities
             SET desired_placement_id = ?5,
                 desired_write_spec_version = ?6,
                 desired_binding_write_revision = ?7,
                 desired_generation = desired_generation + 1,
                 reconciliation_state = 'pending', reconciliation_error = NULL,
                 resource_version = resource_version + 1, updated_at = ?8
             WHERE id = ?1 AND incarnation_id = ?2 AND resource_version = ?3
               AND observed_placement_id = ?4
               AND desired_generation = observed_generation
               AND EXISTS (SELECT 1 FROM surface_placements p
                 JOIN surface_placement_observations po ON po.placement_id = p.id
                 JOIN surface_placement_write_capabilities pc
                   ON pc.placement_id = p.id
                  AND pc.placement_write_spec_version = p.write_spec_version
                  AND pc.binding_write_revision = ?7
                 JOIN binding_write_revisions br
                   ON br.binding_id = pc.binding_id
                  AND br.revision = pc.binding_write_revision
                 JOIN binding_write_observations bo
                   ON bo.binding_id = br.binding_id
                  AND bo.revision = br.revision
                 WHERE p.id = ?5
                   AND p.write_spec_version = ?6
                   AND (p.registry_id = surface_write_authorities.registry_id
                     OR p.cache_id = surface_write_authorities.cache_id)
                   AND p.kind = 'complete' AND p.desired_state = 'active'
                   AND po.state = 'ready' AND po.completeness = 'complete'
                   AND br.writes_supported = 1 AND bo.state = 'valid'
                   AND (p.requires_conditional_writes = 0
                     OR br.conditional_writes_supported = 1))
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets t
                 WHERE t.cache_id = surface_write_authorities.cache_id
                   AND (t.active_cache_slot = 1 OR
                     (t.state = 'completed' AND t.covered_inventory_generation IS NULL)))
               ",
                &vals![
                    authority_id,
                    expected_incarnation_id,
                    expected_version,
                    expected_observed_placement_id,
                    placement_id,
                    expected_candidate_write_spec_version,
                    binding_write_revision,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            return Err(SurfaceWriteAuthorityMutationFailure::new(
                "write authority is stale or the requested writer is ineligible",
            )
            .into());
        }
        self.surface_write_authority_by_id(authority_id)
            .await?
            .context("updated write authority disappeared")
    }

    /// Cancels an unconfirmed promotion by requesting the observed writer again.
    ///
    /// Cancellation is itself reconciled under a new generation. Effective
    /// writes therefore remain fenced until the controller confirms the
    /// restored tuple at that generation.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no previously observed writer or the
    /// authority resource version is stale.
    pub async fn cancel_surface_write_promotion(
        &self,
        authority_id: i64,
        expected_version: i64,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        let affected = self
            .backend
            .execute(
                "UPDATE surface_write_authorities
             SET desired_placement_id = observed_placement_id,
                 desired_write_spec_version = observed_write_spec_version,
                 desired_binding_write_revision = observed_binding_write_revision,
                 desired_generation = desired_generation + 1,
                 reconciliation_state = 'pending', reconciliation_error = NULL,
                 resource_version = resource_version + 1, updated_at = ?3
             WHERE id = ?1 AND resource_version = ?2
               AND observed_placement_id IS NOT NULL
               AND reconciliation_state IN ('pending', 'failed')
               AND EXISTS (SELECT 1 FROM surface_placements p
                 JOIN surface_placement_observations po ON po.placement_id = p.id
                 JOIN surface_placement_write_capabilities pc
                   ON pc.placement_id = p.id
                  AND pc.placement_write_spec_version = p.write_spec_version
                  AND pc.binding_write_revision = surface_write_authorities.observed_binding_write_revision
                 JOIN binding_write_revisions br
                   ON br.binding_id = pc.binding_id
                  AND br.revision = pc.binding_write_revision
                 JOIN binding_write_observations bo
                   ON bo.binding_id = br.binding_id
                  AND bo.revision = br.revision
                 WHERE p.id = surface_write_authorities.observed_placement_id
                   AND p.write_spec_version = surface_write_authorities.observed_write_spec_version
                   AND p.kind = 'complete' AND p.desired_state = 'active'
                   AND po.state = 'ready' AND po.completeness = 'complete'
                   AND br.writes_supported = 1 AND bo.state = 'valid'
                   AND (p.requires_conditional_writes = 0
                     OR br.conditional_writes_supported = 1))",
                &vals![authority_id, expected_version, unix_now()],
            )
            .await?;
        if affected != 1 {
            bail!("write authority has no observed writer or its resource version is stale");
        }
        self.surface_write_authority_by_id(authority_id)
            .await?
            .context("cancelled write promotion disappeared")
    }

    /// Creates a logical object on an existing surface.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key, negative size, missing surface,
    /// duplicate key, or database failure.
    pub async fn create_surface_object(
        &self,
        input: &SetSurfaceObject,
    ) -> Result<SurfaceObjectRecord> {
        validate_key_bytes(&input.object_key, "surface object key", 512)?;
        if !matches!(input.object_kind.as_str(), "immutable" | "mutable_pointer") {
            bail!("invalid surface-object kind '{}'", input.object_kind);
        }
        if (input.object_kind == "immutable") != input.mutable_publication_id.is_none() {
            bail!("immutable objects cannot name a publication and mutable pointers must name one");
        }
        if input.size.is_some_and(|size| size < 0) {
            bail!("surface object size cannot be negative");
        }
        if let Some(hash) = input.content_hash.as_deref() {
            validate_key_bytes(hash, "content hash", 128)?;
        }
        if let Some(publication_id) = input.mutable_publication_id.as_deref() {
            validate_key_bytes(publication_id, "mutable publication id", 64)?;
        }
        let (registry_id, cache_id) = input.surface.ids();
        let now = unix_now();
        let partition_key = (input.object_kind == "immutable")
            .then(|| sha2::Sha256::digest(input.object_key.as_bytes()).to_vec());
        let affected = self
            .backend
            .execute(
                "INSERT INTO surface_objects (registry_id, cache_id, object_key,
                object_kind, partition_key, content_hash, size,
                mutable_publication_id, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, ?8, ?5, ?6, ?7, ?9, ?9
             WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                AND (?4 = 'immutable' OR EXISTS (
                  SELECT 1 FROM registry_publications pub
                  WHERE pub.publication_id = ?7 AND pub.registry_id = ?1))
                OR (EXISTS (SELECT 1 FROM binary_caches WHERE id = ?2) AND ?4 = 'immutable')",
                &vals![
                    registry_id,
                    cache_id,
                    input.object_key,
                    input.object_kind,
                    input.content_hash,
                    input.size,
                    input.mutable_publication_id,
                    partition_key,
                    now
                ],
            )
            .await?;
        if affected != 1 {
            bail!("surface object target does not exist");
        }
        self.surface_object_named(input.surface, &input.object_key)
            .await?
            .context("created surface object disappeared")
    }

    /// Returns a logical object by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_object(&self, id: i64) -> Result<Option<SurfaceObjectRecord>> {
        let rows = self
            .backend
            .query(
                &format!("SELECT {SURFACE_OBJECT_COLUMNS} FROM surface_objects WHERE id = ?1"),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_surface_object).transpose()
    }

    /// Returns a logical object by surface-relative key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_object_named(
        &self,
        surface: SurfaceTarget,
        object_key: &str,
    ) -> Result<Option<SurfaceObjectRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {SURFACE_OBJECT_COLUMNS} FROM surface_objects
                WHERE (registry_id = ?1 OR cache_id = ?2) AND object_key = ?3"
                ),
                &vals![registry_id, cache_id, object_key],
            )
            .await?;
        rows.first().map(row_to_surface_object).transpose()
    }

    /// Logically tombstones an unreferenced registry object before physical deletion.
    ///
    /// Generic tombstoning is deliberately registry-only. Cache objects remain
    /// fail-closed until root-aware cache GC owns their plan/apply lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn tombstone_surface_object(
        &self,
        id: i64,
        expected_version: i64,
        tombstoned_at: i64,
    ) -> Result<bool> {
        Ok(self
            .backend
            .execute(
                "UPDATE surface_objects SET lifecycle_state = 'tombstoned',
                tombstoned_at = ?3, updated_at = ?3,
                resource_version = resource_version + 1
             WHERE id = ?1 AND resource_version = ?2 AND lifecycle_state = 'active'
               AND registry_id IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1 FROM staged_release_objects staged_object
                 JOIN staged_release_revisions staged_revision
                   ON staged_revision.registry_id = staged_object.registry_id
                  AND staged_revision.stage_id = staged_object.stage_id
                  AND staged_revision.revision = staged_object.revision
                 WHERE staged_object.registry_id = surface_objects.registry_id
                   AND staged_object.object_key = surface_objects.object_key
                   AND (staged_revision.retire_after IS NULL
                     OR staged_revision.retire_after > ?3))
               AND NOT EXISTS (
                 SELECT 1 FROM registry_image_roots root
                 WHERE root.surface_object_id = ?1)
               AND NOT EXISTS (
                 SELECT 1 FROM registry_publication_objects po
                 JOIN registry_publications pub
                   ON pub.publication_id = po.publication_id
                 WHERE po.surface_object_id = ?1 AND pub.state <> 'retired'
                   AND (NOT EXISTS (SELECT 1 FROM staged_release_revisions revision
                     WHERE revision.publication_id = pub.publication_id)
                     OR EXISTS (SELECT 1 FROM staged_release_revisions revision
                       WHERE revision.publication_id = pub.publication_id
                         AND (revision.retire_after IS NULL OR revision.retire_after > ?3))))
               AND NOT EXISTS (
                 SELECT 1 FROM registry_publication_multipart_uploads upload
                 WHERE upload.surface_object_id = ?1
                   AND upload.state IN('active', 'completing'))",
                &vals![id, expected_version, tombstoned_at],
            )
            .await?
            == 1)
    }

    /// Every distinct store hash the registry's index references, sorted.
    ///
    /// The union of (a) the hash prefix of every `version_platforms`
    /// `store_path` basename — the text before the first `-` — and (b)
    /// every entry of the per-platform `refs` JSON arrays. Basenames with
    /// no `-` separator carry no extractable hash and are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn all_store_hashes(&self, registry_id: i64) -> Result<Vec<String>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.store_path, vp.refs FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1",
                &vals![registry_id],
            )
            .await?;
        let mut hashes = std::collections::BTreeSet::new();
        for row in &rows {
            let store_path: String = row.get(0)?;
            let refs_json: String = row.get(1)?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            if let Some((hash, _)) = basename.split_once('-') {
                hashes.insert(hash.to_string());
            }
            // The refs column is index-written JSON; tolerate (skip) a
            // malformed value the same way registry rows are read.
            let refs: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
            hashes.extend(refs);
        }
        Ok(hashes.into_iter().collect())
    }

    /// Resolves one signed image by its canonical immutable object key.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, malformed signed metadata, or a
    /// duplicate object key in the authenticated catalog.
    pub async fn system_image_object_by_key(
        &self,
        registry_id: i64,
        object_key: &str,
    ) -> Result<Option<IndexedSystemImageObject>> {
        let mut matches = self
            .list_system_images(registry_id)
            .await?
            .into_iter()
            .filter_map(|image| {
                if image.delivery.is_store_backed() {
                    None
                } else if image.delivery.object_key == object_key {
                    Some(IndexedSystemImageObject::Disk(image))
                } else if image.delivery.artifact_contract.document.object_key == object_key {
                    Some(IndexedSystemImageObject::ImageInfo(image))
                } else {
                    None
                }
            });
        let found = matches.next();
        if matches.next().is_some() {
            bail!("signed image object key is ambiguous");
        }
        Ok(found)
    }

    /// Reports whether a reviewed catalog retirement has started for the registry.
    ///
    /// Once a retiring GC run is applying or complete, signed-release roots
    /// must not be re-projected by indexing: the roots were deliberately
    /// retired and the collector relies on them staying absent.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn oci_catalog_retired(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_gc_runs
                 WHERE registry_id = ?1 AND retire_registry = 1
                   AND state IN('applying', 'complete') LIMIT 1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// Find the packages whose runtime closure references `store_hash`.
    ///
    /// Returns `(name, version)` for every artifact in `registry_id` whose
    /// `refs` JSON array contains `store_hash` — the reverse of the dependency
    /// edge, i.e. "required by". Results are de-duplicated by package name
    /// (keeping the newest version seen) and sorted by name, so a package that
    /// depends on the target across several versions appears once.
    ///
    /// The `refs` column is index-written JSON; rows whose value does not parse
    /// as a string array are skipped, matching how the rest of the index reads
    /// tolerate malformed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn reverse_dependencies(
        &self,
        registry_id: i64,
        store_hash: &str,
    ) -> Result<Vec<(String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT p.name, pv.version, vp.refs
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1
             ORDER BY p.name, pv.id DESC",
                &vals![registry_id],
            )
            .await?;
        // De-duplicate by name, keeping the first (newest, by the ORDER BY)
        // version that references the target hash.
        let mut seen = std::collections::BTreeMap::new();
        for row in &rows {
            let name: String = row.get(0)?;
            let version: String = row.get(1)?;
            let refs_json: String = row.get(2)?;
            let refs: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
            if refs.iter().any(|r| r == store_hash) {
                seen.entry(name).or_insert(version);
            }
        }
        Ok(seen.into_iter().collect())
    }

    /// The store-path hash of a package's latest version on a chosen platform.
    ///
    /// Returns the basename hash prefix (text before the first `-`) of the
    /// newest version's artifact, preferring the given `platform` and otherwise
    /// falling back to whichever platform sorts first. Returns `None` when the
    /// package has no versions, no platform artifacts, or a store path with no
    /// extractable hash. This is the key used to look up the package's
    /// "required by" set via [`reverse_dependencies`](Self::reverse_dependencies).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn primary_store_hash(
        &self,
        registry_id: i64,
        name: &str,
        platform: &str,
    ) -> Result<Option<String>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.platform, vp.store_path
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1 AND p.name = ?2
               AND pv.id = (SELECT MAX(v.id) FROM package_versions v
                            WHERE v.package_id = p.id)
             ORDER BY vp.platform",
                &vals![registry_id, name],
            )
            .await?;
        let mut fallback: Option<String> = None;
        for row in &rows {
            let row_platform: String = row.get(0)?;
            let store_path: String = row.get(1)?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            let Some((hash, _)) = basename.split_once('-') else {
                continue;
            };
            if row_platform == platform {
                return Ok(Some(hash.to_string()));
            }
            fallback.get_or_insert_with(|| hash.to_string());
        }
        Ok(fallback)
    }

    /// The `info/refs` digest the current index was built from, when set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn refs_digest(&self, registry_id: i64) -> Result<Option<String>> {
        let digest: Option<Option<String>> = self
            .backend
            .query_opt(
                "SELECT refs_digest FROM registry_index WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .context("loading refs digest")?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?;
        Ok(digest.flatten())
    }

    /// Loads a stable target scope together with its authoritative ancestor closure.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or if stored scope graph data is
    /// malformed or incomplete. A syntactically invalid or unknown target
    /// returns `Ok(None)` and therefore fails authorization closed.
    pub async fn authorization_context(
        &self,
        scope_key: &str,
    ) -> Result<Option<aos_hub_model::domain::iam::AuthorizationContext>> {
        let Some(target) = aos_hub_model::domain::Scope::try_parse(scope_key) else {
            return Ok(None);
        };
        let rows = self
            .backend
            .query(
                "SELECT c.ancestor_scope_key, c.depth
                   FROM authorization_scope_ancestors c
                   JOIN authorization_scopes d ON d.scope_key = c.descendant_scope_key
                   LEFT JOIN orgs o ON o.id = d.org_id
                  WHERE c.descendant_scope_key = ?1
                    AND (d.org_id IS NULL OR o.deleted_at IS NULL)
                  ORDER BY c.depth",
                &vals![scope_key],
            )
            .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let stored = rows
            .iter()
            .map(|row| {
                let raw: String = row.get(0)?;
                let scope = aos_hub_model::domain::Scope::try_parse(&raw)
                    .context("authorization graph contains a non-canonical scope")?;
                Ok((scope, row.get::<i64>(1)?))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut expected = Vec::new();
        let mut cursor = Some(scope_key.to_string());
        let mut expected_org: Option<Option<i64>> = None;
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = cursor {
            if !seen.insert(key.clone()) {
                bail!("authorization scope parent graph contains a cycle");
            }
            let row = self
                .backend
                .query_opt(
                    "SELECT parent_scope_key, org_id FROM authorization_scopes
                      WHERE scope_key = ?1",
                    &vals![key],
                )
                .await?
                .context("authorization scope parent is missing")?;
            let parent: Option<String> = row.get(0)?;
            let org_id: Option<i64> = row.get(1)?;
            if let Some(Some(child_org)) = expected_org {
                if org_id != Some(child_org) && key != "instance" {
                    bail!("authorization scope parent crosses organization ownership");
                }
            }
            expected_org = Some(org_id);
            let parsed = aos_hub_model::domain::Scope::try_parse(&key)
                .context("authorization scope parent is non-canonical")?;
            expected.push((parsed, i64::try_from(expected.len())?));
            if expected.len() > 8 {
                bail!("authorization scope parent graph exceeds the closed topology depth");
            }
            cursor = parent;
        }
        if stored != expected {
            bail!("authorization ancestor closure does not exactly match the parent graph");
        }
        let ancestors = stored.into_iter().map(|(scope, _)| scope).collect();
        let context = aos_hub_model::domain::iam::AuthorizationContext::try_new(target, ancestors)
            .map_err(anyhow::Error::msg)?;
        Ok(Some(context))
    }

    /// Resolves a stable authorization scope to its current human path.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn authorization_scope_display_path(
        &self,
        scope_key: &str,
    ) -> Result<Option<String>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT a.kind, o.slug, p.path, r.slug, c.slug
                   FROM authorization_scopes a
                   LEFT JOIN orgs o ON o.id = a.org_id
                   LEFT JOIN projects p ON p.scope_key = a.scope_key
                   LEFT JOIN registries r ON r.scope_key = a.scope_key
                   LEFT JOIN binary_caches c ON c.scope_key = a.scope_key
                  WHERE a.scope_key = ?1 AND a.retired_at IS NULL",
                &vals![scope_key],
            )
            .await?
        else {
            return Ok(None);
        };
        let kind: String = row.get(0)?;
        let org: Option<String> = row.get(1)?;
        let project: Option<String> = row.get(2)?;
        let registry: Option<String> = row.get(3)?;
        let cache: Option<String> = row.get(4)?;
        let display = match kind.as_str() {
            "instance" => Some("instance".to_string()),
            "organization" => org,
            "project" => org
                .zip(project)
                .map(|(org, project)| format!("{org}/{project}")),
            "registry" => registry,
            "binary_cache" => cache,
            _ => None,
        };
        Ok(display)
    }

    /// Creates (or updates) the instance root admin: a user with `email` and
    /// `plaintext` password, granted [`Role::Owner`](aos_hub_model::domain::Role::Owner)
    /// at the instance-root scope (`"instance"`).
    ///
    /// Single source of truth for root bootstrap, shared by the native CLI
    /// (`aos-hub init`/`worker install`) and the worker's seal-gated
    /// `HubDb` bootstrap endpoint (RFC-0004 ch.14 Phase E), so both shells create
    /// an identical root. Idempotent: re-running resets the password and
    /// re-asserts the grant. Returns the normalized email and the user id.
    ///
    /// # Errors
    ///
    /// Returns an error if `plaintext` is empty, password hashing fails, or any
    /// database operation fails.
    pub async fn bootstrap_root(&self, email: &str, plaintext: &str) -> Result<(String, i64)> {
        let email = email.trim().to_lowercase();
        if plaintext.is_empty() {
            bail!("password must not be empty");
        }
        let user_id = self.find_or_create_user(&email).await?;
        let hash = aos_hub_model::auth::password::hash_password(plaintext)?;
        self.set_user_password(user_id, &hash).await?;
        // `Role::Owner` at `instance` carries `Permission::IamAdmin`, making this
        // a true instance administrator (can create orgs, administer the whole
        // instance) rather than a login-only account under invite-only signup.
        self.grant_membership(
            "user",
            user_id,
            aos_hub_model::domain::Scope::root().as_str(),
            aos_hub_model::domain::Role::Owner.as_str(),
        )
        .await?;
        Ok((email, user_id))
    }

    /// Whether writing `additional_bytes` more would exceed an org's byte quota.
    ///
    /// Returns `true` only when the org has a `max_bytes` cap *and*
    /// `used_bytes + additional_bytes` would exceed it. An org with no cap (or
    /// no quota row) never exceeds. The object-count cap is checked separately
    /// by the caller against [`Database::org_quota`]/[`Database::org_usage`].
    ///
    /// This is a *read-only* check and is therefore racy against concurrent
    /// writers; typed upload admission reserves atomically with
    /// [`Database::reserve_org_usage`] instead. This method is retained for
    /// read-only quota reporting.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn would_exceed_quota(&self, org_id: i64, additional_bytes: i64) -> Result<bool> {
        let quota = self.org_quota(org_id).await?;
        let Some(max_bytes) = quota.max_bytes else {
            return Ok(false);
        };
        let used = self.org_usage(org_id).await?.used_bytes;
        Ok(used.saturating_add(additional_bytes) > max_bytes)
    }

    /// The instance-root crawl policy (defaulting to allow-all when unset).
    ///
    /// Reads the `root_crawl_policy` instance-config key and parses it leniently
    /// through [`CrawlPolicy::parse_or_default`](aos_hub_model::crawl::CrawlPolicy::parse_or_default)
    /// so a malformed stored value never breaks the generated root `robots.txt`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_crawl_policy(&self) -> Result<aos_hub_model::crawl::CrawlPolicy> {
        Ok(self
            .instance_config_get("root_crawl_policy")
            .await?
            .map(|v| aos_hub_model::crawl::CrawlPolicy::parse_or_default(&v))
            .unwrap_or_default())
    }

    /// Set the instance-root crawl policy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_crawl_policy(
        &self,
        policy: aos_hub_model::crawl::CrawlPolicy,
    ) -> Result<()> {
        self.instance_config_set("root_crawl_policy", policy.as_str())
            .await
    }

    /// The operator-authored instance-root `robots.txt` override, if any.
    ///
    /// `None` means the hub serves the document generated from
    /// [`Self::root_crawl_policy`] instead of a custom body.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_robots_body(&self) -> Result<Option<String>> {
        self.instance_config_get("root_robots_body").await
    }

    /// Set or clear the instance-root `robots.txt` override.
    ///
    /// A `Some(body)` is served verbatim; a `None` clears the override (an empty
    /// `robots.txt` value is stored as the empty string and so still counts as a
    /// custom override — pass `None` to revert to the generated document).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_robots_body(&self, body: Option<&str>) -> Result<()> {
        match body {
            Some(value) => self.instance_config_set("root_robots_body", value).await,
            None => self.instance_config_delete("root_robots_body").await,
        }
    }

    /// The operator-authored instance-root `llms.txt` override, if any.
    ///
    /// `None` means the hub serves the document generated from the instance's
    /// public registries instead of a custom body.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn root_llms_body(&self) -> Result<Option<String>> {
        self.instance_config_get("root_llms_body").await
    }

    /// Set or clear the instance-root `llms.txt` override.
    ///
    /// A `Some(body)` is served verbatim; a `None` clears the override so the
    /// generated document is served instead.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn set_root_llms_body(&self, body: Option<&str>) -> Result<()> {
        match body {
            Some(value) => self.instance_config_set("root_llms_body", value).await,
            None => self.instance_config_delete("root_llms_body").await,
        }
    }

    /// Seeds one pending delivery for a debug-build fixture.
    ///
    /// The row starts `pending` with `attempts = 0` and `next_attempt_at`
    /// equal to now, so the delivery worker picks it up on its next sweep.
    /// Returns the internal delivery row id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    #[cfg(any(test, debug_assertions, feature = "do-e2e-test-support"))]
    pub async fn seed_delivery_for_test(
        &self,
        webhook_id: i64,
        event: &str,
        payload: &str,
    ) -> Result<i64> {
        anyhow::ensure!(
            aos_hub_model::webhook::is_safe_event_header_value(event),
            "webhook event is not a bounded header token"
        );
        anyhow::ensure!(
            payload.len() <= 1024 * 1024,
            "webhook delivery payload exceeds limit"
        );
        validate_json_value(payload, "webhook delivery payload")?;
        let webhook = self
            .webhook(webhook_id)
            .await?
            .context("webhook fixture does not exist")?;
        let org = self
            .org_by_id(webhook.org_id)
            .await?
            .context("webhook fixture organization does not exist")?;
        let outbox_event_id = uuid::Uuid::new_v4().simple().to_string();
        let resource_stable_id = format!("webhook:{webhook_id}");
        self.backend
            .checked_batch(&[Self::topology_event_statement(&NewTopologyEvent {
                event_id: &outbox_event_id,
                event_name: event,
                owner_scope_key: &org.stable_id,
                resource_kind: "webhook",
                resource_stable_id: &resource_stable_id,
                resource_generation_key: webhook.resource_version,
                actor_kind: "system",
                actor_id: None,
                actor_label: "delivery fixture",
                payload_json: payload,
                occurred_at: unix_now(),
            })])
            .await?;
        self.materialize_topology_events().await?;
        self.backend
            .query_opt(
                "SELECT id FROM webhook_deliveries
                  WHERE webhook_id = ?1 AND outbox_event_id = ?2",
                &vals![webhook_id, outbox_event_id],
            )
            .await?
            .context("webhook delivery fixture was not materialized")?
            .get(0)
    }

    /// List deliveries that are due: `pending` and whose `next_attempt_at` is
    /// at or before `now`, joined with their active webhook's URL and immutable
    /// signing-secret reference, oldest first.
    ///
    /// Deliveries whose webhook has since been deleted or deactivated are
    /// excluded — a disabled subscription stops receiving without leaving its
    /// queued rows stuck.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn claim_due_deliveries(
        &self,
        now: i64,
        limit: u32,
        lease_seconds: i64,
    ) -> Result<Vec<DueDelivery>> {
        anyhow::ensure!(
            (1..=100).contains(&limit),
            "delivery claim limit must be 1..=100"
        );
        anyhow::ensure!(
            lease_seconds > 0 && lease_seconds <= 300,
            "delivery lease must be 1..=300 seconds"
        );
        self.materialize_topology_events().await?;
        let rows = self
            .backend
            .query(
                "SELECT d.id, d.delivery_id, d.webhook_id, d.event, d.payload, d.attempts, w.url,
                        w.secret_version_ref, w.credential_fingerprint
             FROM webhook_deliveries d
             JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.active = 1
               AND (d.claim_token IS NULL OR d.claim_expires_at <= ?1)
               AND length(d.payload) <= ?2
             ORDER BY d.id LIMIT ?3",
                &vals![now, 1024 * 1024_i64, i64::from(limit)],
            )
            .await?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.get(0)?;
            let claim_token = uuid::Uuid::new_v4().simple().to_string();
            let claim_expires_at = now.saturating_add(lease_seconds);
            let won = self
                .backend
                .execute(
                    "UPDATE webhook_deliveries SET claim_token = ?2, claim_expires_at = ?3
                 WHERE id = ?1 AND status = 'pending'
                   AND next_attempt_at <= ?4
                   AND (claim_token IS NULL OR claim_expires_at <= ?4)
                   AND EXISTS (SELECT 1 FROM webhooks w
                                WHERE w.id = webhook_deliveries.webhook_id AND w.active = 1)",
                    &vals![id, claim_token, claim_expires_at, now],
                )
                .await?;
            if won == 1 {
                if let Some(delivery) = self.delivery_for_claim(id, &claim_token).await? {
                    claimed.push(delivery);
                }
            }
        }
        Ok(claimed)
    }

    /// Record the outcome of one delivery attempt.
    ///
    /// `status` is the new lifecycle state (`delivered`, `failed`, or
    /// `pending` for a scheduled retry), `response_code` the observed HTTP
    /// status (or `None` when the request never completed), `attempts` the new
    /// attempt count, and `next_attempt_at` the earliest retry time for a row
    /// left `pending`. `delivered_at` is stamped iff `status == "delivered"`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn mark_delivery(
        &self,
        id: i64,
        claim_token: &str,
        status: &str,
        response_code: Option<i64>,
        attempts: i64,
        next_attempt_at: Option<i64>,
    ) -> Result<()> {
        let delivered_at = (status == "delivered").then(unix_now);
        let updated = self
            .backend
            .execute(
                "UPDATE webhook_deliveries
             SET status = ?2, response_code = ?3, attempts = ?4,
                 next_attempt_at = ?5, delivered_at = ?6,
                 claim_token = NULL, claim_expires_at = NULL
             WHERE id = ?1 AND claim_token = ?7",
                &vals![
                    id,
                    status,
                    response_code,
                    attempts,
                    next_attempt_at,
                    delivered_at,
                    claim_token
                ],
            )
            .await?;
        anyhow::ensure!(
            updated == 1,
            "delivery claim was lost before outcome commit"
        );
        Ok(())
    }

    /// Count webhook deliveries grouped by lifecycle status.
    ///
    /// Returns `(pending, delivered, failed)` totals across all webhooks,
    /// powering the `/metrics` gauges.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn delivery_status_counts(&self) -> Result<(u64, u64, u64)> {
        let mut counts = [0u64; 3];
        for (slot, status) in counts.iter_mut().zip(["pending", "delivered", "failed"]) {
            *slot = self
                .backend
                .query_opt(
                    "SELECT COUNT(*) FROM webhook_deliveries WHERE status = ?1",
                    &vals![status],
                )
                .await?
                .context("count query returned no row")?
                .get::<u64>(0)?;
        }
        Ok((counts[0], counts[1], counts[2]))
    }

    /// Creates initial single-writer authority from a validated complete placement.
    ///
    /// # Errors
    ///
    /// Returns an error unless the surface has no authority and the candidate,
    /// capability pin, binding revision, and controller observations are ready.
    pub async fn create_surface_write_authority(
        &self,
        surface: SurfaceTarget,
        authority_incarnation_id: &str,
        placement_id: i64,
        expected_placement_version: i64,
        expected_write_spec_version: i64,
        binding_write_revision: i64,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        validate_key_bytes(
            authority_incarnation_id,
            "write authority incarnation id",
            64,
        )?;
        let (registry_id, cache_id) = surface.ids();
        let now = unix_now();
        let inserted = self
            .backend
            .execute(
                "INSERT INTO surface_write_authorities
             (incarnation_id, registry_id, cache_id, desired_placement_id, desired_write_spec_version,
              desired_binding_write_revision, desired_generation,
              observed_placement_id, observed_write_spec_version,
              observed_binding_write_revision, observed_generation,
              reconciliation_state, created_at, updated_at)
             SELECT ?3, p.registry_id, p.cache_id, p.id, p.write_spec_version, ?7, 1,
                    p.id, p.write_spec_version, ?7, 1, 'ready', ?8, ?8
             FROM surface_placements p
             JOIN surface_placement_observations po ON po.placement_id = p.id
             JOIN surface_placement_write_capabilities pc
               ON pc.placement_id = p.id
              AND pc.placement_write_spec_version = p.write_spec_version
              AND pc.binding_write_revision = ?7
             JOIN binding_write_revisions br
               ON br.binding_id = pc.binding_id
              AND br.revision = pc.binding_write_revision
             JOIN binding_write_observations bo
               ON bo.binding_id = br.binding_id
              AND bo.revision = br.revision
             WHERE p.id = ?4 AND (p.registry_id = ?1 OR p.cache_id = ?2)
               AND p.resource_version = ?5 AND p.write_spec_version = ?6
               AND p.kind = 'complete' AND p.desired_state = 'active'
               AND po.state = 'ready' AND po.completeness = 'complete'
               AND br.writes_supported = 1 AND bo.state = 'valid'
               AND (p.requires_conditional_writes = 0
                 OR br.conditional_writes_supported = 1)",
                &vals![
                    registry_id,
                    cache_id,
                    authority_incarnation_id,
                    placement_id,
                    expected_placement_version,
                    expected_write_spec_version,
                    binding_write_revision,
                    now
                ],
            )
            .await;
        let affected = match inserted {
            Ok(affected) => affected,
            Err(error) => {
                if let Some(existing) = self.surface_write_authority(surface).await? {
                    if existing.incarnation_id == authority_incarnation_id
                        && existing.desired_placement_id == placement_id
                        && existing.observed_placement_id == Some(placement_id)
                        && existing.desired_write_spec_version == expected_write_spec_version
                        && existing.observed_write_spec_version == Some(expected_write_spec_version)
                        && existing.desired_binding_write_revision == binding_write_revision
                        && existing.observed_binding_write_revision == Some(binding_write_revision)
                        && existing.reconciliation_state == "ready"
                    {
                        return Ok(existing);
                    }
                    return Err(SurfaceWriteAuthorityMutationFailure::new(
                        "the surface already has a different write authority",
                    )
                    .into());
                }
                return Err(error);
            }
        };
        if affected != 1 {
            return Err(SurfaceWriteAuthorityMutationFailure::new(
                "write authority requires one validated, ready, complete placement and capability pin",
            )
            .into());
        }
        self.surface_write_authority(surface)
            .await?
            .context("created write authority disappeared")
    }

    /// Returns the write authority for one surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_write_authority(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Option<SurfaceWriteAuthorityRecord>> {
        let (registry_id, cache_id) = surface.ids();
        let rows = self.backend.query(
            &format!("SELECT {WRITE_AUTHORITY_COLUMNS} FROM surface_write_authorities WHERE registry_id = ?1 OR cache_id = ?2"),
            &vals![registry_id, cache_id],
        ).await?;
        rows.first().map(row_to_surface_write_authority).transpose()
    }

    /// Confirms the currently desired authority generation after reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the generation and resource version still match
    /// and every effective-write prerequisite remains valid.
    pub async fn confirm_surface_write_authority(
        &self,
        authority_id: i64,
        expected_version: i64,
        desired_generation: i64,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        let affected = self.backend.execute(
            "UPDATE surface_write_authorities
             SET observed_placement_id = desired_placement_id,
                 observed_write_spec_version = desired_write_spec_version,
                 observed_binding_write_revision = desired_binding_write_revision,
                 observed_generation = desired_generation,
                 reconciliation_state = 'ready', reconciliation_error = NULL,
                 resource_version = resource_version + 1, updated_at = ?4
             WHERE id = ?1 AND resource_version = ?2 AND desired_generation = ?3
               AND reconciliation_state = 'pending'
               AND EXISTS (SELECT 1 FROM surface_placements p
                 JOIN surface_placement_observations po ON po.placement_id = p.id
                 JOIN surface_placement_write_capabilities pc
                   ON pc.placement_id = p.id
                  AND pc.placement_write_spec_version = p.write_spec_version
                  AND pc.binding_write_revision = surface_write_authorities.desired_binding_write_revision
                 JOIN binding_write_revisions br
                   ON br.binding_id = pc.binding_id
                  AND br.revision = pc.binding_write_revision
                 JOIN binding_write_observations bo
                   ON bo.binding_id = br.binding_id
                  AND bo.revision = br.revision
                 WHERE p.id = surface_write_authorities.desired_placement_id
                   AND p.write_spec_version = surface_write_authorities.desired_write_spec_version
                   AND p.kind = 'complete' AND p.desired_state = 'active'
                   AND po.state = 'ready' AND po.completeness = 'complete'
                   AND br.writes_supported = 1 AND bo.state = 'valid'
                   AND (p.requires_conditional_writes = 0
                     OR br.conditional_writes_supported = 1))
               AND NOT EXISTS (SELECT 1 FROM cache_write_tickets t
                 WHERE t.cache_id = surface_write_authorities.cache_id
                   AND (t.active_cache_slot = 1 OR
                     (t.state = 'completed' AND t.covered_inventory_generation IS NULL)))
               ",
            &vals![authority_id, expected_version, desired_generation, unix_now()],
        ).await?;
        if affected != 1 {
            return Err(SurfaceWriteAuthorityMutationFailure::new(
                "write authority reconciliation CAS is stale or no longer eligible",
            )
            .into());
        }
        self.surface_write_authority_by_id(authority_id)
            .await?
            .context("confirmed write authority disappeared")
    }

    /// Records a failed reconciliation for the current desired generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty message, stale generation/version, or
    /// database failure.
    pub async fn fail_surface_write_authority(
        &self,
        authority_id: i64,
        expected_version: i64,
        desired_generation: i64,
        error: &str,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        if error.trim().is_empty() || error.len() > 4 * 1024 {
            bail!("write-authority reconciliation error must contain 1-4096 UTF-8 bytes");
        }
        let affected = self
            .backend
            .execute(
                "UPDATE surface_write_authorities
             SET reconciliation_state = 'failed', reconciliation_error = ?4,
                 resource_version = resource_version + 1, updated_at = ?5
             WHERE id = ?1 AND resource_version = ?2 AND desired_generation = ?3
               AND reconciliation_state = 'pending'
               AND (observed_generation IS NULL OR desired_generation > observed_generation)",
                &vals![
                    authority_id,
                    expected_version,
                    desired_generation,
                    error,
                    unix_now()
                ],
            )
            .await?;
        if affected != 1 {
            return Err(SurfaceWriteAuthorityMutationFailure::new(
                "write authority reconciliation CAS is stale",
            )
            .into());
        }
        self.surface_write_authority_by_id(authority_id)
            .await?
            .context("failed write authority disappeared")
    }

    /// Retries a failed desired authority tuple under a new generation fence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the authority is failed at the expected version.
    pub async fn retry_surface_write_authority(
        &self,
        authority_id: i64,
        expected_version: i64,
    ) -> Result<SurfaceWriteAuthorityRecord> {
        let affected = self
            .backend
            .execute(
                "UPDATE surface_write_authorities
                 SET desired_generation = desired_generation + 1,
                     reconciliation_state = 'pending', reconciliation_error = NULL,
                     resource_version = resource_version + 1, updated_at = ?3
                 WHERE id = ?1 AND resource_version = ?2
                   AND reconciliation_state = 'failed'",
                &vals![authority_id, expected_version, unix_now()],
            )
            .await?;
        if affected != 1 {
            bail!("write authority is not failed or its resource version is stale");
        }
        self.surface_write_authority_by_id(authority_id)
            .await?
            .context("retried write authority disappeared")
    }

    /// Removes a fully reconciled authority to make the surface explicitly read-only.
    ///
    /// The observed generation is part of the delete fence so a stale plan
    /// cannot erase a newly promoted or retried writer. Placement rows remain
    /// intact and may continue serving eligible reads.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure. A stale, pending, failed, or
    /// already-removed authority returns `false`.
    pub async fn remove_surface_write_authority(
        &self,
        authority_id: i64,
        expected_incarnation_id: &str,
        expected_version: i64,
        expected_observed_generation: i64,
    ) -> Result<bool> {
        validate_key_bytes(
            expected_incarnation_id,
            "write authority incarnation id",
            64,
        )?;
        Ok(self
            .backend
            .execute(
                "DELETE FROM surface_write_authorities
                 WHERE id = ?1 AND incarnation_id = ?2 AND resource_version = ?3
                   AND reconciliation_state = 'ready'
                   AND desired_generation = ?4 AND observed_generation = ?4
                   AND desired_placement_id = observed_placement_id
                   AND desired_write_spec_version = observed_write_spec_version
                   AND desired_binding_write_revision = observed_binding_write_revision
                   AND NOT EXISTS (SELECT 1 FROM cache_write_tickets t
                     WHERE t.cache_id = surface_write_authorities.cache_id
                       AND (t.active_cache_slot = 1 OR
                         (t.state = 'completed' AND t.covered_inventory_generation IS NULL)))
                   ",
                &vals![
                    authority_id,
                    expected_incarnation_id,
                    expected_version,
                    expected_observed_generation
                ],
            )
            .await?
            == 1)
    }
}
