//! Coordination reads in the runtime capability.

use super::*;

impl Database {
    /// List a change-set's revisions in `seq` order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_revisions(&self, change_id: &str) -> Result<Vec<RevisionRow>> {
        let rows = self
            .backend
            .query(
                "SELECT id, change_id, object_type, object_id, op, old_json, new_json, seq
             FROM change_request_revisions WHERE change_id = ?1 ORDER BY seq",
                &vals![change_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(RevisionRow {
                    id: row.get(0)?,
                    change_id: row.get(1)?,
                    object_type: row.get(2)?,
                    object_id: row.get(3)?,
                    op: row.get(4)?,
                    old_json: row.get(5)?,
                    new_json: row.get(6)?,
                    seq: row.get(7)?,
                })
            })
            .collect()
    }

    /// List change-sets at or below `scope`, newest first.
    ///
    /// Uses the same stable-scope ancestor graph as [`Database::list_audit`]:
    /// a query at an org scope surfaces change-sets targeting its registries.
    /// The `instance` scope lists every live-scope change-set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_changesets(&self, scope: &str) -> Result<Vec<ChangesetRow>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {CHANGESET_COLUMNS} FROM change_requests \
                 ORDER BY created_at DESC, change_id DESC"
                ),
                &[],
            )
            .await?;
        let mut out = Vec::new();
        for row in &rows {
            let changeset = row_to_changeset(row)?;
            let covered = self
                .backend
                .query_opt(
                    "SELECT 1 FROM authorization_scope_ancestors
                      WHERE descendant_scope_key = ?1 AND ancestor_scope_key = ?2",
                    &vals![changeset.scope, scope],
                )
                .await?
                .is_some();
            if covered {
                out.push(changeset);
            }
        }
        Ok(out)
    }

    /// Lists placement-presence observations for one logical surface object.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_object_presence(
        &self,
        surface: SurfaceTarget,
        object_ref: &str,
    ) -> Result<Vec<ObjectPresenceRecord>> {
        validate_key_bytes(object_ref, "surface object key", 512)?;
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                "SELECT object.object_key, placement.name, presence.state,
                        presence.observed_hash, presence.observed_size,
                        presence.observed_at
                 FROM surface_objects object
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                 JOIN surface_placements placement
                   ON placement.id = presence.placement_id
                 WHERE (object.registry_id = ?1 OR object.cache_id = ?2)
                   AND object.object_key = ?3
                 ORDER BY placement.name, placement.id",
                &vals![registry_id, cache_id, object_ref],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(ObjectPresenceRecord {
                    object_ref: row.get(0)?,
                    placement_name: row.get(1)?,
                    state: row.get(2)?,
                    content_digest: row.get(3)?,
                    size: row.get(4)?,
                    observed_at: row.get(5)?,
                })
            })
            .collect()
    }

    /// List a principal's grants as `(scope, role)` strings, ordered by
    /// scope.
    ///
    /// These pairs feed [`aos_hub_model::domain::iam::allow`] after parsing with
    /// [`aos_hub_model::domain::Scope::parse`] and [`aos_hub_model::domain::Role::parse`].
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_memberships_for(
        &self,
        principal_kind: &str,
        principal_id: i64,
    ) -> Result<Vec<(String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT m.scope_key, m.role FROM memberships m
             JOIN authorization_scopes a ON a.scope_key = m.scope_key
             LEFT JOIN orgs o ON o.id = a.org_id
             WHERE m.principal_kind = ?1 AND m.principal_id = ?2
               AND a.retired_at IS NULL
               AND (a.org_id IS NULL OR o.deleted_at IS NULL)
               AND ((?1 = 'user' AND EXISTS (
                      SELECT 1 FROM users u
                       WHERE u.id = ?2 AND u.deleted_at IS NULL))
                 OR (?1 = 'service_account' AND EXISTS (
                      SELECT 1 FROM service_accounts s
                      JOIN orgs owner_org ON owner_org.id = s.org_id
                       WHERE s.id = ?2 AND owner_org.deleted_at IS NULL)))
             ORDER BY m.scope_key",
                &vals![principal_kind, principal_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?)))
            .collect()
    }

    /// List every membership grant at `scope_key` or one of its descendants.
    ///
    /// Returns `(principal_kind, principal_id, scope, role)` for grants whose
    /// The persisted ancestor graph defines descendants; routing slugs and
    /// string prefixes never participate in authorization hierarchy.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_memberships_under(
        &self,
        scope_prefix: &str,
    ) -> Result<Vec<(String, i64, String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT m.principal_kind, m.principal_id, m.scope_key, m.role
                   FROM memberships m
                   JOIN authorization_scope_ancestors c
                     ON c.descendant_scope_key = m.scope_key
                  WHERE c.ancestor_scope_key = ?1
                  ORDER BY m.scope_key, m.principal_kind, m.principal_id",
                &vals![scope_prefix],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .collect()
    }

    /// Resolves the authoritative placement eligible for a whole-surface read.
    ///
    /// This is used by background consumers that enumerate a complete surface
    /// (indexing, scans, and maintenance). Request-path object reads use the
    /// stricter object-evidence planner. A reconciled writer is preferred over
    /// replicas because it owns the current mutable surface. When a write
    /// authority exists, selection fails closed unless that writer is also an
    /// eligible reader; an unproven replica cannot stand in for mutable state.
    /// `read_order` orders replicas only for surfaces without a write authority.
    /// Selection is deterministic and never falls back to a resource-global
    /// binding or deployment bucket.
    ///
    /// # Errors
    ///
    /// Returns an error when no ready, complete, read-enabled placement exists
    /// or when the placement query fails.
    pub async fn reconciled_surface_reader(
        &self,
        surface: SurfaceTarget,
    ) -> Result<SurfacePlacementRecord> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query_opt(
                &format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM surface_placement_effective
                     WHERE (registry_id = ?1 OR cache_id = ?2)
                       AND effective_read_enabled = 1
                       AND (write_authority_id IS NULL OR effective_write_enabled = 1)
                     ORDER BY read_order, name, id LIMIT 1"
                ),
                &vals![registry_id, cache_id],
            )
            .await?
            .map(|row| row_to_surface_placement(&row))
            .transpose()?
            .context("surface has no reconciled read placement")
    }

    /// Resolves the sole fully reconciled write-authority placement.
    ///
    /// # Errors
    ///
    /// Returns an error when authority is absent, stale, unreconciled, not
    /// effectively writable, or on database failure.
    pub async fn reconciled_surface_writer(
        &self,
        surface: SurfaceTarget,
    ) -> Result<SurfacePlacementRecord> {
        let authority = self
            .surface_write_authority(surface)
            .await?
            .context("surface has no write authority")?;
        if authority.reconciliation_state != "ready"
            || authority.observed_placement_id != Some(authority.desired_placement_id)
            || authority.observed_generation != Some(authority.desired_generation)
            || authority.observed_write_spec_version != Some(authority.desired_write_spec_version)
            || authority.observed_binding_write_revision
                != Some(authority.desired_binding_write_revision)
        {
            bail!("surface write authority is not fully reconciled");
        }
        let placement = self
            .surface_placement(authority.desired_placement_id)
            .await?
            .context("authority placement is missing")?;
        if !placement.effective_write_enabled {
            bail!("authority placement is not write-enabled");
        }
        Ok(placement)
    }

    /// List every registry that has a mirror source, paired with the source.
    ///
    /// Used by the serve loop to find mirrors due for a scheduled full sync.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_mirror_sources(&self) -> Result<Vec<(i64, MirrorSource)>> {
        let rows = self
            .backend
            .query(
                "SELECT registry_id, upstream_url, mode, verify, schedule_secs, last_sync_at,
                    last_sync_status, last_sync_error, upstream_frontier
             FROM mirror_sources ORDER BY registry_id",
                &[],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let registry_id: i64 = row.get(0)?;
                Ok((
                    registry_id,
                    MirrorSource {
                        upstream_url: row.get(1)?,
                        mode: row.get(2)?,
                        verify: row.get(3)?,
                        schedule_secs: row.get(4)?,
                        last_sync_at: row.get(5)?,
                        last_sync_status: row.get(6)?,
                        last_sync_error: row.get(7)?,
                        upstream_frontier: row.get(8)?,
                    },
                ))
            })
            .collect()
    }

    /// Whether `registry_id` is a mirror (has a `mirror_sources` row).
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn is_mirror(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM mirror_sources WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// Lists pending write-authority generations for controller reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when `limit` cannot be represented
    /// by the database parameter type.
    pub async fn pending_surface_write_authorities(
        &self,
        limit: usize,
    ) -> Result<Vec<SurfaceWriteAuthorityRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.backend
            .query(
                &format!(
                    "SELECT {WRITE_AUTHORITY_COLUMNS} FROM surface_write_authorities
                     WHERE reconciliation_state = 'pending'
                     ORDER BY updated_at, id LIMIT ?1"
                ),
                &vals![i64::try_from(limit)?],
            )
            .await?
            .iter()
            .map(row_to_surface_write_authority)
            .collect()
    }

    /// Lists every active logical object on one registry or binary-cache surface.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn list_active_surface_objects(
        &self,
        surface: SurfaceTarget,
    ) -> Result<Vec<SurfaceObjectRecord>> {
        let (registry_id, cache_id) = surface.ids();
        self.backend
            .query(
                &format!(
                    "SELECT {SURFACE_OBJECT_COLUMNS} FROM surface_objects
                     WHERE (registry_id = ?1 OR cache_id = ?2)
                       AND lifecycle_state = 'active'
                     ORDER BY object_key, id"
                ),
                &vals![registry_id, cache_id],
            )
            .await?
            .iter()
            .map(row_to_surface_object)
            .collect()
    }

    /// Lists signed direct-delivery images belonging to verified releases.
    ///
    /// The rows come only from exact commits named by verified signed release
    /// tags. Default-branch package metadata is intentionally not consulted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed signed image metadata.
    pub async fn list_system_images(&self, registry_id: i64) -> Result<Vec<IndexedSystemImage>> {
        let rows = self
            .backend
            .query(
                "SELECT image.package_name, image.release, image.platform,
                        image.format, image.delivery, image.catalog_digest
                   FROM registry_system_images image
                   JOIN releases rel
                     ON rel.registry_id = image.registry_id
                    AND rel.semver = image.release
                    AND rel.commit_oid = image.source_commit
                    AND rel.tag_oid = image.verified_tag_oid
                   JOIN registry_index idx
                     ON idx.registry_id = image.registry_id
                    AND idx.state = 'fresh'
                  WHERE image.registry_id = ?1
                  ORDER BY image.release DESC, image.package_name,
                           image.platform, image.format",
                &vals![registry_id],
            )
            .await?;
        let mut images = Vec::new();
        for row in &rows {
            let package: String = row.get(0)?;
            let release: String = row.get(1)?;
            let platform: String = row.get(2)?;
            let format: String = row.get(3)?;
            let encoded: String = row.get(4)?;
            let catalog_digest: String = row.get(5)?;
            if catalog_digest.len() != 64 {
                bail!("indexed signed image catalog has invalid digest identity");
            }
            let stored = decode_stored_system_image(&encoded)?;
            let delivery = stored.delivery;
            delivery
                .validate(&format, &release, &platform)
                .context("validating indexed signed image delivery metadata")?;
            if !self
                .system_image_delivery_ready(registry_id, &delivery)
                .await?
            {
                continue;
            }
            images.push(IndexedSystemImage {
                package,
                release,
                platform,
                format,
                store_path: stored.store_path,
                nar_hash: stored.nar_hash,
                nar_size: stored.nar_size,
                delivery,
            });
        }
        Ok(images)
    }

    /// Lists immutable disk and image-info object keys rooted by signed releases.
    ///
    /// The returned set is the registry-image contribution to retention and GC:
    /// [`Self::tombstone_surface_object`] refuses every object in this set.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_system_image_root_keys(&self, registry_id: i64) -> Result<Vec<String>> {
        self.backend
            .query(
                "SELECT DISTINCT object.object_key
                   FROM registry_image_roots root
                   JOIN surface_objects object
                     ON object.id = root.surface_object_id
                    AND object.registry_id = root.registry_id
                  WHERE root.registry_id = ?1
                  ORDER BY object.object_key",
                &vals![registry_id],
            )
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// Lists the exact signed identities of all currently rooted image objects.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_system_image_roots(
        &self,
        registry_id: i64,
    ) -> Result<Vec<(String, String, i64)>> {
        self.backend
            .query(
                "SELECT DISTINCT object.object_key, root.expected_hash, root.expected_size
                   FROM registry_image_roots root
                   JOIN surface_objects object
                     ON object.id = root.surface_object_id
                    AND object.registry_id = root.registry_id
                  WHERE root.registry_id = ?1
                  ORDER BY object.object_key",
                &vals![registry_id],
            )
            .await?
            .iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
    }

    /// Returns whether the last good index contains a signed image catalog.
    ///
    /// The indexer uses this to disable its metadata-only incremental path:
    /// every refresh of an image-bearing registry must revalidate the exact
    /// release objects before restoring serving visibility.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn has_system_image_catalog(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM registry_system_images WHERE registry_id = ?1 LIMIT 1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// Resolve store-hash prefixes to the packages that publish them.
    ///
    /// For each hash in `hashes`, returns `(hash, name, version)` where `name`
    /// and `version` are `Some` when some package in `registry_id` publishes an
    /// artifact whose store-path hash prefix equals that hash, and `None` when
    /// the hash belongs to a store path outside this registry's package set
    /// (e.g. a stdenv closure dependency). Output order matches `hashes`.
    ///
    /// This turns the opaque `refs` closure-edge list on the package page into
    /// a legible dependency list: resolvable hashes link to their package page,
    /// unresolvable ones fall back to their narinfo permalink. Resolution runs
    /// in Rust against `store_hash_index`, so it is
    /// independent of the backend's JSON-function dialect.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn resolve_reference_names(
        &self,
        registry_id: i64,
        hashes: &[String],
    ) -> Result<Vec<ResolvedReference>> {
        let index = self.store_hash_index(registry_id).await?;
        Ok(hashes
            .iter()
            .map(|hash| match index.get(hash) {
                Some((name, version)) => (hash.clone(), Some(name.clone()), Some(version.clone())),
                None => (hash.clone(), None, None),
            })
            .collect())
    }

    /// The roster as `(key_id, public_key, status)` rows.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_roster(&self, registry_id: i64) -> Result<Vec<(String, String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT key_id, public_key, status FROM key_rosters
             WHERE registry_id = ?1 ORDER BY status, key_id",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
    }

    /// List the principals granted a role directly at one scope.
    ///
    /// Returns `(principal_kind, principal_id, role)` for the grants whose
    /// `scope` equals `scope` exactly — it does **not** expand inherited
    /// grants from ancestor scopes; that inheritance is resolved by
    /// [`aos_hub_model::domain::iam::allow`] at decision time.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_members_of_scope(&self, scope: &str) -> Result<Vec<(String, i64, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT m.principal_kind, m.principal_id, m.role FROM memberships m
             WHERE m.scope_key = ?1
               AND ((m.principal_kind = 'user' AND EXISTS (
                      SELECT 1 FROM users u
                       WHERE u.id = m.principal_id AND u.deleted_at IS NULL))
                 OR (m.principal_kind = 'service_account' AND EXISTS (
                      SELECT 1 FROM service_accounts s
                      JOIN orgs owner_org ON owner_org.id = s.org_id
                       WHERE s.id = m.principal_id AND owner_org.deleted_at IS NULL)))
             ORDER BY m.principal_kind, m.principal_id",
                &vals![scope],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .collect()
    }

    /// Resolve a principal's effective grants as parsed `(Scope, Role)`
    /// pairs ready for [`aos_hub_model::domain::iam::allow`].
    ///
    /// This is the thin domain-db bridge: it reads `memberships` via
    /// [`Database::list_memberships_for`] and parses each row into the
    /// pure domain types. Rows whose stored `role` is not one of the five
    /// known role names are skipped (forward-compatibility with a future
    /// role added by a newer writer); scopes always parse.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn effective_scopes(
        &self,
        principal: aos_hub_model::domain::Principal,
    ) -> Result<Vec<(aos_hub_model::domain::Scope, aos_hub_model::domain::Role)>> {
        let rows = self
            .list_memberships_for(principal.kind.as_str(), principal.id)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(scope, role)| {
                aos_hub_model::domain::Role::parse(&role)
                    .map(|role| (aos_hub_model::domain::Scope::parse(&scope), role))
            })
            .collect())
    }

    /// Lists stable identities for due webhook deliveries without claiming them.
    ///
    /// This is the cron-dispatch boundary: it lets a short database-only pass
    /// enqueue independent delivery jobs while each queue consumer performs
    /// the network request under the ordinary durable delivery claim.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit or database failure.
    pub async fn list_due_delivery_ids(&self, now: i64, limit: u32) -> Result<Vec<String>> {
        anyhow::ensure!(
            (1..=100).contains(&limit),
            "delivery list limit must be 1..=100"
        );
        self.backend
            .query(
                "SELECT d.delivery_id
                   FROM webhook_deliveries d
                   JOIN webhooks w ON w.id = d.webhook_id
                  WHERE d.status = 'pending' AND d.next_attempt_at <= ?1
                    AND w.active = 1
                    AND (d.claim_token IS NULL OR d.claim_expires_at <= ?1)
                    AND length(d.payload) <= ?2
                  ORDER BY d.id LIMIT ?3",
                &vals![now, 1024 * 1024_i64, i64::from(limit)],
            )
            .await?
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }

    /// Claims one due delivery by its stable queue identity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid lease, oversized persisted payload, or
    /// database failure. Returns `None` when the row is absent, not due, or
    /// already holds an unexpired claim.
    pub async fn claim_delivery_by_stable_id(
        &self,
        delivery_id: &str,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<DueDelivery>> {
        anyhow::ensure!(
            !delivery_id.is_empty() && delivery_id.len() <= 64,
            "invalid delivery id"
        );
        anyhow::ensure!(
            lease_seconds > 0 && lease_seconds <= 300,
            "delivery lease must be 1..=300 seconds"
        );
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT d.id, d.delivery_id, d.webhook_id, d.event, d.payload, d.attempts, w.url,
                    w.secret_version_ref, w.credential_fingerprint
             FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.delivery_id = ?1 AND d.status = 'pending' AND d.next_attempt_at <= ?2
               AND w.active = 1 AND (d.claim_token IS NULL OR d.claim_expires_at <= ?2)",
                &vals![delivery_id, now],
            )
            .await?
        else {
            return Ok(None);
        };
        let payload: String = row.get(4)?;
        anyhow::ensure!(
            payload.len() <= 1024 * 1024,
            "webhook delivery payload exceeds limit"
        );
        let id: i64 = row.get(0)?;
        let claim_token = uuid::Uuid::new_v4().simple().to_string();
        let won = self
            .backend
            .execute(
                "UPDATE webhook_deliveries SET claim_token = ?2, claim_expires_at = ?3
             WHERE id = ?1 AND status = 'pending'
               AND next_attempt_at <= ?4
               AND (claim_token IS NULL OR claim_expires_at <= ?4)
               AND EXISTS (SELECT 1 FROM webhooks w
                            WHERE w.id = webhook_deliveries.webhook_id AND w.active = 1)",
                &vals![id, claim_token, now.saturating_add(lease_seconds), now],
            )
            .await?;
        if won != 1 {
            return Ok(None);
        }
        self.delivery_for_claim(id, &claim_token).await
    }

    /// Lists an organization's service accounts in stable name order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_service_accounts(&self, org_id: i64) -> Result<Vec<ServiceAccountRecord>> {
        self.backend
            .query(
                "SELECT id, org_id, name, created_at FROM service_accounts
                 WHERE org_id = ?1 ORDER BY name, id",
                &vals![org_id],
            )
            .await?
            .iter()
            .map(|row| {
                Ok(ServiceAccountRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .collect()
    }

    /// Returns a write authority by id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn surface_write_authority_by_id(
        &self,
        id: i64,
    ) -> Result<Option<SurfaceWriteAuthorityRecord>> {
        let rows = self
            .backend
            .query(
                &format!(
                    "SELECT {WRITE_AUTHORITY_COLUMNS} FROM surface_write_authorities WHERE id = ?1"
                ),
                &vals![id],
            )
            .await?;
        rows.first().map(row_to_surface_write_authority).transpose()
    }

    /// List an org's bindings, ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_bindings(&self, org_id: i64) -> Result<Vec<BindingRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
             FROM bindings WHERE org_id = ?1 ORDER BY name",
                &vals![org_id],
            )
            .await?;
        rows.iter().map(row_to_binding).collect()
    }

    /// Lists bindings in one canonical owner scope by stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_bindings_by_scope(
        &self,
        owner_scope_key: &str,
    ) -> Result<Vec<BindingRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings WHERE owner_scope_key = ?1 ORDER BY stable_id",
                &vals![owner_scope_key],
            )
            .await?;
        rows.iter().map(row_to_binding).collect()
    }

    /// Lists bindings owned by or explicitly granted to one consumer scope.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_bindings_available_to_scope(
        &self,
        consumer_scope_key: &str,
    ) -> Result<Vec<BindingRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT id, org_id, name, kind, is_instance_default, stable_id, owner_scope_key,
                 local_root_path, object_bucket, object_prefix, endpoint_scheme,
                 endpoint_host_kind, endpoint_host_bytes, endpoint_port,
                 signing_region, access_mode, resource_version, created_at, updated_at
                 FROM bindings binding
                 WHERE binding.owner_scope_key = ?1
                    OR EXISTS (
                       SELECT 1 FROM binding_consumer_scopes grant_record
                       WHERE grant_record.binding_id = binding.id
                         AND grant_record.consumer_scope_key = ?1
                         AND grant_record.state = 'active'
                    )
                 ORDER BY stable_id",
                &vals![consumer_scope_key],
            )
            .await?;
        rows.iter().map(row_to_binding).collect()
    }
}
