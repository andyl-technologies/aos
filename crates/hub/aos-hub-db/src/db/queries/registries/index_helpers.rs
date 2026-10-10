//! Index helpers in the registries capability.

use super::*;

impl Database {
    pub(in crate::db) async fn apply_snapshot_transaction(
        &self,
        registry_id: i64,
        snapshot: &IndexSnapshot,
        indexed_placement_id: Option<i64>,
        image_presence: Option<(&[VerifiedRegistryImageObject], i64)>,
    ) -> Result<()> {
        match (
            &snapshot.public_catalog_commit,
            &snapshot.public_catalog_release,
        ) {
            (None, None) => {}
            (Some(commit), Some(tag))
                if snapshot
                    .releases
                    .iter()
                    .any(|release| release.semver == *tag && release.commit_oid == *commit) => {}
            _ => bail!("public catalog selection is not a verified release in this snapshot"),
        }

        self.assert_registry_index_mutation_source(registry_id, indexed_placement_id)
            .await?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("indexed registry does not exist")?;
        let prior_releases: std::collections::HashSet<String> = if registry.org_id.is_some() {
            self.list_releases(registry_id)
                .await?
                .into_iter()
                .map(|release| release.semver)
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        let indexed_at = unix_now();
        let index_digest = index_snapshot_digest(snapshot)?;
        let had_container_admin_projections = self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_release_provenance
                 WHERE registry_id = ?1 LIMIT 1",
                &vals![registry_id],
            )
            .await?
            .is_some();
        let has_container_admin_projections = snapshot
            .release_artifact_snapshots
            .iter()
            .any(|release| release.container_release.is_some());
        // An unchanged rewrite keeps the OCI mutation epoch, so the periodic
        // re-index does not invalidate provider inventories and GC plans.
        let unchanged_projection_epoch =
            if had_container_admin_projections || has_container_admin_projections {
                self.unchanged_container_release_projection_epoch(registry_id, snapshot)
                    .await?
            } else {
                None
            };
        // Assign surrogate ids client-side so the whole snapshot is one
        // self-contained batch (HubDb has no mid-batch `last_insert_rowid`). The
        // bases are read once before the batch; the indexer runs sequentially
        // per registry (main.rs), so no concurrent writer collides on them, and
        // assigning ids in insertion order preserves the `MAX(package_versions
        // .id)` "latest version" ordering the read path relies on. Leaf tables
        // (version_platforms, releases) keep implicit autoincrement — nothing
        // reads their id back.
        let mut next_package = self.max_id("packages").await?;
        let mut next_version = self.max_id("package_versions").await?;
        let mut next_channel = self.max_id("channels").await?;
        let mut image_roots: Vec<(String, String, String, i64, String)> = Vec::new();

        let mut stmts: Vec<Statement> = Vec::new();
        for table in [
            "package_documentation",
            "packages",
            "key_rosters",
            "registry_cache_stack_entries",
        ] {
            stmts.push(Statement::new(
                format!("DELETE FROM {table} WHERE registry_id = ?1"),
                vals![registry_id].to_vec(),
            ));
        }
        stmts.push(Statement::new(
            "DELETE FROM registry_image_roots WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        stmts.push(Statement::new(
            "DELETE FROM registry_system_images WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        stmts.push(Statement::new(
            "DELETE FROM oci_release_provenance WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        stmts.push(Statement::new(
            "DELETE FROM oci_release_roots WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        // Presence is placement-local evidence. Re-indexing one authoritative
        // placement invalidates only that placement's prior observations;
        // independently verified replicas remain usable.
        stmts.push(Statement::new(
            "DELETE FROM object_placements
             WHERE registry_id = ?1 AND surface_object_id IN (
               SELECT id FROM surface_objects
               WHERE registry_id = ?1 AND object_key LIKE 'images/sha256/%')
               AND (?2 IS NULL OR placement_id = ?2)",
            vals![registry_id, indexed_placement_id].to_vec(),
        ));
        stmts.push(Statement::new(
            "DELETE FROM registry_catalog_artifacts
             WHERE registry_id = ?1 AND source_revision = ?2",
            vals![registry_id, snapshot.commit].to_vec(),
        ));

        let mut package_rows = Vec::new();
        let mut version_rows = Vec::new();
        let mut platform_rows = Vec::new();
        let mut catalog_rows = Vec::new();
        for package in &snapshot.packages {
            next_package += 1;
            let package_id = next_package;
            package_rows.push(vals![
                package_id,
                registry_id,
                package.package.name,
                package.package.description,
                package.package.homepage,
                package.package.license,
                package.package.maintainer,
                package.package.sysroot,
            ]);
            for version in &package.versions {
                next_version += 1;
                let version_id = next_version;
                version_rows.push(vals![
                    version_id,
                    package_id,
                    version.version,
                    version.previous
                ]);
                for (platform, entry) in &version.platforms {
                    let images = entry
                        .images
                        .iter()
                        .map(|i| {
                            serde_json::json!({
                                "format": i.format,
                                "store_path": i.store_path,
                                "nar_hash": i.nar_hash,
                                "nar_size": i.nar_size,
                                "delivery": i.delivery,
                            })
                        })
                        .collect::<Vec<_>>();
                    platform_rows.push(vals![
                        version_id,
                        platform,
                        entry.store_path,
                        entry.nar_hash,
                        entry.nar_size,
                        entry.closure_size,
                        serde_json::to_string(&entry.references)?,
                        serde_json::Value::Array(images).to_string(),
                        entry.source_drv,
                    ]);
                    let mut catalog_artifacts = vec![("output", entry.store_path.as_str())];
                    catalog_artifacts.extend(entry.named_outputs.values().flat_map(|output| {
                        std::iter::once(("output", output.store_path.as_str())).chain(
                            output
                                .deployment
                                .iter()
                                .map(|deployment| ("output", deployment.store_path.as_str())),
                        )
                    }));
                    if !entry.source_drv.is_empty() {
                        catalog_artifacts.push(("source_derivation", entry.source_drv.as_str()));
                    }
                    for image in &entry.images {
                        catalog_artifacts.push(("image", image.store_path.as_str()));
                        if image.delivery.is_store_backed() {
                            catalog_artifacts.push((
                                "image",
                                image
                                    .delivery
                                    .artifact_contract
                                    .document
                                    .store_path
                                    .as_str(),
                            ));
                            if let Some(payload) = &image.delivery.artifact_contract.artifacts {
                                catalog_artifacts.push(("image", payload.store_path.as_str()));
                            }
                        }
                    }
                    for artifact in [
                        &entry.deployment,
                        &entry.module_documentation,
                        &entry.qualification,
                    ] {
                        if let Some(artifact) = artifact {
                            catalog_artifacts.push(("output", artifact.store_path.as_str()));
                        }
                    }
                    let mut catalog_artifacts_by_identity =
                        std::collections::BTreeMap::<(String, String), String>::new();
                    for (artifact_kind, store_path) in catalog_artifacts {
                        let store_hash = store_hash_component(store_path);
                        let identity = (artifact_kind.to_string(), store_hash.clone());
                        if let Some(existing_store_path) =
                            catalog_artifacts_by_identity.get(&identity)
                        {
                            if existing_store_path != store_path {
                                bail!(
                                    "catalog artifact kind '{}' and store hash '{}' name both '{}' and '{}'",
                                    artifact_kind,
                                    store_hash,
                                    existing_store_path,
                                    store_path
                                );
                            }
                            continue;
                        }
                        catalog_artifacts_by_identity.insert(identity, store_path.to_string());
                    }
                    for ((artifact_kind, store_hash), store_path) in catalog_artifacts_by_identity {
                        let metadata_digest = hex::encode(sha2::Sha256::digest(
                            serde_json::to_vec(&serde_json::json!({
                                "package_name": package.package.name,
                                "package_version": version.version,
                                "platform": platform,
                                "artifact_kind": artifact_kind,
                                "store_path": store_path,
                                "store_hash": store_hash,
                            }))?,
                        ));
                        catalog_rows.push(vals![
                            registry_id,
                            snapshot.commit,
                            package.package.name,
                            version.version,
                            platform,
                            artifact_kind,
                            store_path,
                            store_hash,
                            metadata_digest
                        ]);
                    }
                }
            }
        }
        // The statements own each row's parameters. Do not retain a second
        // complete copy while preparing later projections and remote SQL.
        extend_multirow_insert(
            &mut stmts,
            "INSERT INTO packages
             (id, registry_id, name, description, homepage, license, maintainer, sysroot)",
            &package_rows,
            "",
        )?;
        drop(package_rows);

        extend_multirow_insert(
            &mut stmts,
            "INSERT INTO package_versions (id, package_id, version, previous)",
            &version_rows,
            "",
        )?;
        drop(version_rows);
        extend_multirow_insert(
            &mut stmts,
            "INSERT INTO version_platforms
             (version_id, platform, store_path, nar_hash, nar_size,
              closure_size, refs, images, source_drv)",
            &platform_rows,
            "",
        )?;
        drop(platform_rows);
        extend_multirow_insert(
            &mut stmts,
            "INSERT INTO registry_catalog_artifacts
             (registry_id, source_revision, package_name, package_version,
              platform, artifact_kind, store_path, store_hash, metadata_digest)",
            &catalog_rows,
            "",
        )?;
        drop(catalog_rows);

        for release in &snapshot.releases {
            if let Some(existing) = self
                .backend
                .query_opt(
                    "SELECT tag_oid, commit_oid FROM releases
                     WHERE registry_id = ?1 AND semver = ?2",
                    &vals![registry_id, release.semver],
                )
                .await?
            {
                let existing_tag_oid: String = existing.get(0)?;
                let existing_commit_oid: String = existing.get(1)?;
                if existing_tag_oid != release.tag_oid || existing_commit_oid != release.commit_oid
                {
                    bail!(
                        "release '{}' changed stable tag/commit identity",
                        release.semver
                    );
                }
            }
            stmts.push(Statement::new(
                "INSERT INTO releases
                 (registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(registry_id, semver) DO UPDATE SET
                   signer = excluded.signer, tagged_at = excluded.tagged_at,
                   pack_present = excluded.pack_present",
                vals![
                    registry_id,
                    release.semver,
                    release.tag_oid,
                    release.commit_oid,
                    release.signer,
                    release.tagged_at,
                    release.pack_present,
                ]
                .to_vec(),
            ));
        }

        let mut image_catalog_rows = std::collections::BTreeSet::new();
        for catalog in &snapshot.release_images {
            let release = snapshot
                .releases
                .iter()
                .find(|release| release.semver == catalog.release_tag)
                .with_context(|| {
                    format!(
                        "image catalog references unknown release '{}'",
                        catalog.release_tag
                    )
                })?;
            if release.commit_oid != catalog.source_commit
                || release.tag_oid != catalog.verified_tag_oid
            {
                bail!(
                    "image catalog for release '{}' is not bound to its exact verified tag identity",
                    catalog.release_tag
                );
            }
            if catalog.catalog_digest.len() != 64
                || !catalog
                    .catalog_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("image catalog digest is not lowercase SHA-256");
            }
            for image in &catalog.images {
                if image.release != catalog.release_tag {
                    bail!(
                        "image release '{}' does not match signed tag '{}'",
                        image.release,
                        catalog.release_tag
                    );
                }
                image
                    .delivery
                    .validate(&image.format, &image.release, &image.platform)?;
                let row_identity = (
                    catalog.release_tag.clone(),
                    image.package.clone(),
                    image.platform.clone(),
                    image.format.clone(),
                );
                if !image_catalog_rows.insert(row_identity) {
                    bail!(
                        "signed release '{}' repeats image {}/{}/{}",
                        catalog.release_tag,
                        image.package,
                        image.platform,
                        image.format
                    );
                }
                if !image.delivery.is_store_backed() {
                    for (role, key, hash, size) in [
                        (
                            "disk",
                            image.delivery.object_key.as_str(),
                            image.delivery.sha256.as_str(),
                            image.delivery.byte_size,
                        ),
                        (
                            "image_info",
                            image
                                .delivery
                                .artifact_contract
                                .document
                                .object_key
                                .as_str(),
                            image.delivery.artifact_contract.document.sha256.as_str(),
                            image.delivery.artifact_contract.document.byte_size,
                        ),
                    ] {
                        let size = i64::try_from(size)
                            .context("signed image object size exceeds database range")?;
                        if let Some(existing) = self
                            .surface_object_named(SurfaceTarget::Registry(registry_id), key)
                            .await?
                        {
                            if existing.object_kind != "immutable"
                                || existing.content_hash.as_deref() != Some(hash)
                                || existing.size != Some(size)
                            {
                                bail!(
                                    "signed image object key '{}' conflicts with existing surface identity",
                                    key
                                );
                            }
                        }
                        stmts.push(Statement::new(
                            "INSERT INTO surface_objects
                             (registry_id, cache_id, object_key, object_kind,
                              partition_key, content_hash, size,
                              mutable_publication_id, created_at, updated_at)
                             VALUES (?1, NULL, ?2, 'immutable', ?3, ?4, ?5,
                                     NULL, ?6, ?6)
                             ON CONFLICT(registry_id, object_key) DO NOTHING",
                            vals![
                                registry_id,
                                key,
                                sha2::Sha256::digest(key.as_bytes()).to_vec(),
                                hash,
                                size,
                                indexed_at
                            ]
                            .to_vec(),
                        ));
                        image_roots.push((
                            catalog.release_tag.clone(),
                            key.to_string(),
                            hash.to_string(),
                            size,
                            role.to_string(),
                        ));
                    }
                }
                stmts.push(Statement::new(
                    "INSERT INTO registry_system_images
                     (registry_id, release, source_commit, verified_tag_oid,
                      catalog_digest, package_name, platform, format, delivery)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    vals![
                        registry_id,
                        catalog.release_tag,
                        catalog.source_commit,
                        catalog.verified_tag_oid,
                        catalog.catalog_digest,
                        image.package,
                        image.platform,
                        image.format,
                        encode_stored_system_image(image)?,
                    ]
                    .to_vec(),
                ));
            }
        }

        for (release, object_key, expected_hash, expected_size, role) in image_roots {
            stmts.push(Statement::new(
                "INSERT INTO registry_image_roots
                 (registry_id, release, surface_object_id, object_role,
                  expected_hash, expected_size)
                 SELECT ?1, ?2, object.id, ?6, ?4, ?5
                 FROM surface_objects object
                 JOIN releases rel ON rel.registry_id = object.registry_id
                   AND rel.semver = ?2
                 WHERE object.registry_id = ?1 AND object.object_key = ?3
                   AND object.object_kind = 'immutable'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?4 AND object.size = ?5",
                vals![
                    registry_id,
                    release,
                    object_key,
                    expected_hash,
                    expected_size,
                    role
                ]
                .to_vec(),
            ));
        }

        for release_snapshot in &snapshot.release_artifact_snapshots {
            let mut canonical_artifacts = release_snapshot.artifacts.clone();
            canonical_artifacts.sort_by(|left, right| {
                (
                    &left.package_name,
                    &left.package_version,
                    &left.platform,
                    &left.artifact_kind,
                    &left.store_path,
                    &left.store_hash,
                )
                    .cmp(&(
                        &right.package_name,
                        &right.package_version,
                        &right.platform,
                        &right.artifact_kind,
                        &right.store_path,
                        &right.store_hash,
                    ))
            });
            canonical_artifacts.dedup();
            if canonical_artifacts != release_snapshot.artifacts {
                bail!("release artifact snapshot must be canonically sorted and deduplicated");
            }
            let computed_manifest_digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(
                &canonical_artifacts,
            )?));
            if computed_manifest_digest != release_snapshot.manifest_digest {
                bail!("release artifact snapshot manifest digest does not match its artifacts");
            }
            let expected_count = i64::try_from(release_snapshot.artifacts.len())
                .context("release artifact snapshot is too large")?;
            // Snapshot rows own registry-local release membership, even when
            // two registries publish byte-identical signed releases.
            let mut snapshot_id = hex::encode(sha2::Sha256::digest(
                format!(
                    "{registry_id}\0{}\0{}\0{}\0{}",
                    release_snapshot.release_tag,
                    release_snapshot.verified_tag_oid,
                    release_snapshot.source_commit,
                    release_snapshot.manifest_digest
                )
                .as_bytes(),
            ));
            if let Some(existing) = self
                .backend
                .query_opt(
                    "SELECT ras.snapshot_id, ras.source_commit, ras.verified_tag_oid,
                            ras.manifest_digest, ras.state, ras.actual_artifact_count
                     FROM releases rel
                     JOIN release_artifact_snapshot_heads head
                       ON head.release_id = rel.id AND head.registry_id = rel.registry_id
                     JOIN release_artifact_snapshots ras
                       ON ras.snapshot_id = head.complete_artifact_snapshot_id
                      AND ras.release_id = head.release_id
                      AND ras.registry_id = head.registry_id
                     WHERE rel.registry_id = ?1 AND rel.semver = ?2",
                    &vals![registry_id, release_snapshot.release_tag],
                )
                .await?
            {
                let existing_identity = (
                    existing.get::<String>(1)?,
                    existing.get::<String>(2)?,
                    existing.get::<String>(3)?,
                    existing.get::<String>(4)?,
                    existing.get::<i64>(5)?,
                );
                if existing_identity
                    != (
                        release_snapshot.source_commit.clone(),
                        release_snapshot.verified_tag_oid.clone(),
                        release_snapshot.manifest_digest.clone(),
                        "complete".to_string(),
                        expected_count,
                    )
                {
                    bail!(
                        "release '{}' already owns a different terminal artifact snapshot",
                        release_snapshot.release_tag
                    );
                }
                // Retain preexisting IDs after validating their full content
                // identity and registry ownership. This also preserves rows
                // created before IDs included the owning registry.
                snapshot_id = existing.get(0)?;
            }
            let snapshot_started_at = unix_now();
            stmts.push(Statement::new(
                "INSERT INTO release_artifact_snapshots
                 (snapshot_id, release_id, registry_id, source_commit,
                  verified_tag_oid, verification_record_id, manifest_digest,
                  state, expected_artifact_count, actual_artifact_count,
                  started_at, completed_at)
                 SELECT ?1, rel.id, rel.registry_id, ?3, ?4, ?4, NULL,
                        'building', ?5, 0, ?7, NULL
                 FROM releases rel
                 WHERE rel.registry_id = ?2 AND rel.semver = ?6
                   AND rel.commit_oid = ?3 AND rel.tag_oid = ?4
                 ON CONFLICT DO NOTHING",
                vals![
                    snapshot_id,
                    registry_id,
                    release_snapshot.source_commit,
                    release_snapshot.verified_tag_oid,
                    expected_count,
                    release_snapshot.release_tag,
                    snapshot_started_at,
                ]
                .to_vec(),
            ));
            let mut artifact_rows = Vec::with_capacity(release_snapshot.artifacts.len());
            for artifact in &release_snapshot.artifacts {
                let metadata_digest =
                    hex::encode(sha2::Sha256::digest(serde_json::to_vec(artifact)?));
                artifact_rows.push(vals![
                    artifact.package_name,
                    artifact.package_version,
                    artifact.platform,
                    artifact.artifact_kind,
                    artifact.store_path,
                    artifact.store_hash,
                    metadata_digest,
                ]);
            }
            extend_release_artifact_inserts(&mut stmts, &snapshot_id, &artifact_rows)?;
            stmts.push(Statement::new(
                "UPDATE release_artifact_snapshots
                 SET actual_artifact_count = (SELECT COUNT(*)
                       FROM release_artifacts artifact
                       WHERE artifact.snapshot_id = release_artifact_snapshots.snapshot_id),
                     manifest_digest = ?2, state = 'complete', complete_slot = 1,
                     completed_at = ?3
                 WHERE snapshot_id = ?1 AND state = 'building'
                   AND expected_artifact_count = (SELECT COUNT(*)
                       FROM release_artifacts artifact
                       WHERE artifact.snapshot_id = release_artifact_snapshots.snapshot_id)",
                vals![
                    snapshot_id,
                    release_snapshot.manifest_digest,
                    snapshot_started_at
                ]
                .to_vec(),
            ));
            stmts.push(Statement::new(
                "INSERT INTO release_artifact_snapshot_heads
                 (release_id, registry_id, complete_artifact_snapshot_id,
                  resource_version, updated_at)
                 SELECT release_id, registry_id, snapshot_id, 1, ?2
                 FROM release_artifact_snapshots
                 WHERE snapshot_id = ?1 AND state = 'complete'
                 ON CONFLICT(release_id) DO UPDATE SET
                   complete_artifact_snapshot_id = excluded.complete_artifact_snapshot_id,
                   resource_version = release_artifact_snapshot_heads.resource_version + 1,
                   updated_at = excluded.updated_at",
                vals![snapshot_id, snapshot_started_at].to_vec(),
            ));
        }

        stmts.push(Statement::new(
            "UPDATE channels SET active = 0 WHERE registry_id = ?1",
            vals![registry_id].to_vec(),
        ));
        for channel in &snapshot.channels {
            let channel_id = if let Some(row) = self
                .backend
                .query_opt(
                    "SELECT id FROM channels WHERE registry_id = ?1 AND name = ?2",
                    &vals![registry_id, channel.name],
                )
                .await?
            {
                row.get(0)?
            } else {
                next_channel += 1;
                next_channel
            };
            stmts.push(Statement::new(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, ?3, ?4, 1)
                 ON CONFLICT(registry_id, name) DO UPDATE SET
                   frontier = excluded.frontier, active = 1",
                vals![channel_id, registry_id, channel.name, channel.frontier].to_vec(),
            ));
            for (bucket, release) in channel.partitions.iter().enumerate() {
                if let Some(release) = release {
                    stmts.push(Statement::new(
                        "INSERT INTO channel_partitions (channel_id, bucket, release)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(channel_id, bucket) DO UPDATE SET release = excluded.release",
                        vals![channel_id, bucket as i64, release].to_vec(),
                    ));
                } else {
                    stmts.push(Statement::new(
                        "DELETE FROM channel_partitions WHERE channel_id = ?1 AND bucket = ?2",
                        vals![channel_id, bucket as i64].to_vec(),
                    ));
                }
            }
        }

        for (key_id, public_key, status) in &snapshot.roster {
            stmts.push(Statement::new(
                "INSERT INTO key_rosters (registry_id, key_id, public_key, status)
                 VALUES (?1, ?2, ?3, ?4)",
                vals![registry_id, key_id, public_key, status].to_vec(),
            ));
        }
        let mut mirror_group_by_url = std::collections::BTreeMap::new();
        if let Some(stack_json) = snapshot.cache_stack.as_deref() {
            let stack = aos_registry_format::stack::StackNode::from_json(stack_json)?;
            for group in stack.mirror_groups() {
                let digest =
                    hex::encode(sha2::Sha256::digest(serde_json::to_vec(&group)?.as_slice()));
                for url in group {
                    mirror_group_by_url
                        .entry(url)
                        .or_insert_with(|| format!("mirror:{digest}"));
                }
            }
        }
        for (index, (url, priority)) in snapshot.caches.iter().enumerate() {
            let managed = self
                .backend
                .query_opt(
                    "SELECT i.cache_id, i.route_id,
                     i.route_configuration_generation, i.route_configuration_digest
                     FROM consumer_cache_publication_intents i
                     JOIN change_requests cs ON cs.change_id = i.change_id
                     WHERE i.registry_id = ?1 AND i.committed_url = ?2
                       AND cs.status = 'applied'
                     ORDER BY cs.applied_at DESC, i.change_id DESC LIMIT 1",
                    &vals![registry_id, url],
                )
                .await?;
            let (cache_id, route_id, generation, digest): (
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<String>,
            ) = match managed {
                Some(row) => (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?),
                None => (None, None, None, None),
            };
            stmts.push(Statement::new(
                "INSERT INTO registry_cache_stack_entries
                 (registry_id, stack_path, committed_url, resolved_priority,
                  mirror_group_id, cache_id, route_id,
                  route_configuration_generation, route_configuration_digest,
                  indexed_commit)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                vals![
                    registry_id,
                    format!("entry:{index}"),
                    url,
                    i64::from(*priority),
                    mirror_group_by_url.get(url).cloned(),
                    cache_id,
                    route_id,
                    generation,
                    digest,
                    snapshot.commit,
                ]
                .to_vec(),
            ));
        }

        stmts.push(Statement::new(
            "INSERT INTO registry_index
             (registry_id, state, error, last_indexed_commit, name, description, readme,
              indexed_at, refs_digest, cache_stack, generation, content_digest,
              documentation_projection_generation, support_json)
             VALUES (?1, 'fresh', NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, 1, ?10)
             ON CONFLICT(registry_id) DO UPDATE SET
                 state = 'fresh', error = NULL,
                 last_indexed_commit = excluded.last_indexed_commit,
                 name = excluded.name, description = excluded.description,
                 readme = excluded.readme,
                 support_json = excluded.support_json,
                 indexed_at = excluded.indexed_at,
                 refs_digest = excluded.refs_digest,
                 cache_stack = excluded.cache_stack,
                 generation = registry_index.generation + 1,
                 content_digest = excluded.content_digest,
                 documentation_projection_generation = 1",
            vals![
                registry_id,
                snapshot.commit,
                snapshot.name,
                snapshot.description,
                snapshot.readme,
                indexed_at,
                snapshot.refs_digest,
                snapshot.cache_stack,
                index_digest,
                snapshot.support,
            ]
            .to_vec(),
        ));
        stmts.push(Statement::new(
            "INSERT INTO registry_public_catalog_heads(registry_id, source_commit, release_tag)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(registry_id) DO UPDATE SET
               source_commit = excluded.source_commit, release_tag = excluded.release_tag",
            vals![
                registry_id,
                snapshot.public_catalog_commit,
                snapshot.public_catalog_release
            ]
            .to_vec(),
        ));
        if registry.org_id.is_some() {
            let event = aos_hub_model::webhook::WebhookEvent::IndexCompleted {
                registry: registry.slug.clone(),
                commit: snapshot.commit.clone(),
                packages: snapshot.packages.len(),
                releases: snapshot.releases.len(),
                channels: snapshot.channels.len(),
                incremental: false,
                at: indexed_at,
            };
            let dedupe_key = serde_json::to_string(&serde_json::json!([
                registry.slug.as_str(),
                snapshot.commit.as_str(),
                index_digest.as_str()
            ]))?;
            stmts.push(Self::operational_webhook_event_insert_statement(
                &registry,
                &event,
                Some(&dedupe_key),
                indexed_at,
            )?);
            for release in &snapshot.releases {
                if prior_releases.contains(&release.semver) {
                    continue;
                }
                let event = aos_hub_model::webhook::WebhookEvent::ReleasePublished {
                    registry: registry.slug.clone(),
                    semver: release.semver.clone(),
                    commit: release.commit_oid.clone(),
                    at: indexed_at,
                };
                stmts.push(Self::operational_webhook_event_insert_statement(
                    &registry, &event, None, indexed_at,
                )?);
            }
        }
        let mut checked_stmts = vec![Self::registry_index_mutation_guard(
            registry_id,
            indexed_placement_id,
        )];
        checked_stmts.extend(stmts.into_iter().map(Statement::unchecked));
        if had_container_admin_projections || has_container_admin_projections {
            checked_stmts.extend([
                Statement::new(
                    "INSERT INTO oci_registry_state
                       (registry_id, mutation_epoch, charged_bytes,
                        charged_objects, updated_at)
                     SELECT ?1, 0, 0, 0, ?2
                     WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![registry_id, indexed_at],
                )
                .unchecked(),
                oci_release_projection::container_release_projection_epoch_statement(
                    registry_id,
                    indexed_at,
                    unchanged_projection_epoch,
                ),
            ]);
        }
        if has_container_admin_projections && self.oci_catalog_retired(registry_id).await? {
            bail!("registry OCI catalog is retired; container releases cannot be re-projected");
        }
        for release in &snapshot.release_artifact_snapshots {
            if let Some(root) = &release.container_release {
                let placement_id = indexed_placement_id
                    .context("signed container release requires an exact indexed placement")?;
                checked_stmts.extend(oci_release_root_statements(
                    registry_id,
                    release,
                    root,
                    placement_id,
                    indexed_at,
                )?);
            }
        }
        if let Some((objects, observed_at)) = image_presence {
            let placement_id = indexed_placement_id
                .context("signed image presence requires an exact indexed placement")?;
            checked_stmts.extend(Self::registry_image_presence_statements(
                registry_id,
                placement_id,
                objects,
                observed_at,
            )?);
        }
        checked_stmts.extend(
            self.channel_floor_guard_statements(registry_id, &snapshot.channels)
                .await?,
        );
        self.backend.checked_batch(&checked_stmts).await?;
        for release in &snapshot.releases {
            let row = self
                .backend
                .query_opt(
                    "SELECT 1 FROM releases WHERE registry_id = ?1 AND semver = ?2
                   AND tag_oid = ?3 AND commit_oid = ?4",
                    &vals![
                        registry_id,
                        release.semver,
                        release.tag_oid,
                        release.commit_oid
                    ],
                )
                .await?;
            if row.is_none() {
                bail!(
                    "release '{}' stable identity changed during snapshot application",
                    release.semver
                );
            }
        }
        Ok(())
    }

    pub(in crate::db) async fn assert_registry_index_mutation_source(
        &self,
        registry_id: i64,
        indexed_placement_id: Option<i64>,
    ) -> Result<()> {
        if self.registry_has_active_publication(registry_id).await? {
            bail!("registry index mutation is blocked by an active publication");
        }
        let allowed = match indexed_placement_id {
            Some(placement_id) => {
                self.reconciled_surface_reader(SurfaceTarget::Registry(registry_id))
                    .await?
                    .id
                    == placement_id
            }
            None => {
                let row = self
                    .backend
                    .query_opt(
                        "SELECT COUNT(*) FROM surface_placements
                     WHERE registry_id = ?1 AND desired_state <> 'offline'",
                        &vals![registry_id],
                    )
                    .await?
                    .context("registry placement count disappeared")?;
                row.get::<i64>(0)? <= 1
            }
        };
        if !allowed {
            bail!("registry index mutation requires the authoritative placement");
        }
        Ok(())
    }

    /// Fences one index transaction against publication and source-topology changes.
    pub(in crate::db) fn registry_index_mutation_guard(
        registry_id: i64,
        indexed_placement_id: Option<i64>,
    ) -> CheckedStatement {
        let source_predicate = match indexed_placement_id {
            Some(placement_id) => Statement::new(
                "UPDATE registries SET updated_at = updated_at
                 WHERE id = ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM registry_publications publication
                     WHERE publication.registry_id = registries.id
                       AND publication.state IN ('preparing', 'writing_pointers'))
                   AND EXISTS (
                     SELECT 1 FROM surface_placement_effective selected
                     WHERE selected.id = ?2 AND selected.registry_id = registries.id
                       AND selected.effective_read_enabled = 1
                       AND (selected.write_authority_id IS NULL
                         OR selected.effective_write_enabled = 1)
                       AND NOT EXISTS (
                         SELECT 1 FROM surface_placement_effective better
                         WHERE better.registry_id = registries.id
                           AND better.effective_read_enabled = 1
                           AND (better.write_authority_id IS NULL
                             OR better.effective_write_enabled = 1)
                           AND (better.read_order < selected.read_order
                             OR (better.read_order = selected.read_order
                               AND better.name < selected.name)
                             OR (better.read_order = selected.read_order
                               AND better.name = selected.name
                               AND better.id < selected.id))))",
                vals![registry_id, placement_id],
            ),
            None => Statement::new(
                "UPDATE registries SET updated_at = updated_at
                 WHERE id = ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM registry_publications publication
                     WHERE publication.registry_id = registries.id
                       AND publication.state IN ('preparing', 'writing_pointers'))
                   AND (SELECT COUNT(*) FROM surface_placements placement
                        WHERE placement.registry_id = registries.id
                          AND placement.desired_state <> 'offline') <= 1",
                vals![registry_id],
            ),
        };
        source_predicate.expecting(1)
    }

    /// Fences one index transaction against an in-flight publication.
    pub(in crate::db) fn registry_index_publication_guard(registry_id: i64) -> CheckedStatement {
        Statement::new(
            "UPDATE registries SET updated_at = updated_at
             WHERE id = ?1 AND NOT EXISTS (
               SELECT 1 FROM registry_publications publication
               WHERE publication.registry_id = registries.id
                 AND publication.state IN ('preparing', 'writing_pointers'))",
            vals![registry_id],
        )
        .expecting(1)
    }

    /// Build the registry's store-hash → (package name, version) index.
    ///
    /// Loads every `version_platforms` row once and maps the store-path hash
    /// prefix (the basename text before the first `-`) to the owning package's
    /// name and version. When two artifacts share a hash prefix the first
    /// `ORDER BY` winner is kept; the platform triple is dropped because a
    /// dependency edge points at a store path, not a platform.
    ///
    /// This is the dialect-safe primitive the closure-browser reads:
    /// [`resolve_reference_names`](Self::resolve_reference_names) and
    /// [`reverse_dependencies`](Self::reverse_dependencies) both resolve in
    /// Rust against this map rather than relying on backend JSON functions.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(in crate::db) async fn store_hash_index(
        &self,
        registry_id: i64,
    ) -> Result<std::collections::HashMap<String, (String, String)>> {
        let rows = self
            .backend
            .query(
                "SELECT vp.store_path, p.name, pv.version
             FROM version_platforms vp
             JOIN package_versions pv ON pv.id = vp.version_id
             JOIN packages p ON p.id = pv.package_id
             WHERE p.registry_id = ?1
             ORDER BY p.name, pv.id DESC",
                &vals![registry_id],
            )
            .await?;
        let mut index = std::collections::HashMap::new();
        for row in &rows {
            let store_path: String = row.get(0)?;
            let name: String = row.get(1)?;
            let version: String = row.get(2)?;
            let basename = store_path.rsplit('/').next().unwrap_or(&store_path);
            if let Some((hash, _)) = basename.split_once('-') {
                index.entry(hash.to_string()).or_insert((name, version));
            }
        }
        Ok(index)
    }
}
