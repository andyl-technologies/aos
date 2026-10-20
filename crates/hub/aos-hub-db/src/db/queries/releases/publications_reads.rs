//! Publications reads in the releases capability.

use super::*;

impl Database {
    /// Lists the package set authenticated by one verified release tag or commit.
    ///
    /// Package membership, version, and platforms come from the immutable
    /// release-artifact snapshot. Descriptive metadata is joined from the
    /// current package catalog because release snapshots deliberately retain
    /// artifact identities rather than duplicate package prose.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_packages_at_release(
        &self,
        registry_id: i64,
        release_or_commit: &str,
    ) -> Result<Vec<PackageRow>> {
        let rows = self
            .backend
            .query(
                "WITH selected_versions AS (
                   SELECT DISTINCT artifact.package_name, artifact.package_version
                   FROM releases release
                   JOIN release_artifact_snapshot_heads head
                     ON head.release_id = release.id AND head.registry_id = release.registry_id
                   JOIN release_artifact_snapshots snapshot
                     ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                    AND snapshot.state = 'complete'
                    AND snapshot.source_commit = release.commit_oid
                    AND snapshot.verified_tag_oid = release.tag_oid
                   JOIN release_artifacts artifact ON artifact.snapshot_id = snapshot.snapshot_id
                   WHERE release.registry_id = ?1
                     AND (release.semver = ?2 OR release.commit_oid = ?2)
                     AND artifact.artifact_kind = 'output'
                 ), ranked_versions AS (
                   SELECT selected.package_name, selected.package_version,
                          ROW_NUMBER() OVER (
                            PARTITION BY selected.package_name
                            ORDER BY version.id DESC, selected.package_version DESC
                          ) AS rank
                   FROM selected_versions selected
                   LEFT JOIN packages package
                     ON package.registry_id = ?1 AND package.name = selected.package_name
                   LEFT JOIN package_versions version
                     ON version.package_id = package.id
                    AND version.version = selected.package_version
                 )
                 SELECT artifact.package_name,
                        COALESCE(package.description, ''),
                        COALESCE(package.license, ''),
                        artifact.package_version,
                        artifact.platform,
                        platform.closure_size
                 FROM releases release
                 JOIN release_artifact_snapshot_heads head
                   ON head.release_id = release.id AND head.registry_id = release.registry_id
                 JOIN release_artifact_snapshots snapshot
                   ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                  AND snapshot.state = 'complete'
                  AND snapshot.source_commit = release.commit_oid
                  AND snapshot.verified_tag_oid = release.tag_oid
                 JOIN release_artifacts artifact ON artifact.snapshot_id = snapshot.snapshot_id
                 JOIN ranked_versions selected
                   ON selected.package_name = artifact.package_name
                  AND selected.package_version = artifact.package_version
                  AND selected.rank = 1
                 LEFT JOIN packages package
                   ON package.registry_id = ?1 AND package.name = artifact.package_name
                 LEFT JOIN package_versions version
                   ON version.package_id = package.id
                  AND version.version = artifact.package_version
                 LEFT JOIN version_platforms platform
                   ON platform.version_id = version.id
                  AND platform.platform = artifact.platform
                 WHERE release.registry_id = ?1
                   AND (release.semver = ?2 OR release.commit_oid = ?2)
                   AND artifact.artifact_kind = 'output'
                 ORDER BY artifact.package_name, artifact.platform",
                &vals![registry_id, release_or_commit],
            )
            .await?;

        let mut packages = Vec::<PackageRow>::new();
        for row in &rows {
            let name: String = row.get(0)?;
            if packages.last().map(|package| package.name.as_str()) != Some(name.as_str()) {
                packages.push(PackageRow {
                    name,
                    description: row.get(1)?,
                    license: row.get(2)?,
                    latest_version: row.get(3)?,
                    closure_size: None,
                    platforms: Vec::new(),
                });
            }
            if let Some(package) = packages.last_mut() {
                let platform: String = row.get(4)?;
                if !package.platforms.contains(&platform) {
                    package.platforms.push(platform);
                }
                if package.closure_size.is_none() {
                    package.closure_size = row.get(5)?;
                }
            }
        }
        Ok(packages)
    }

    /// Counts distinct packages in every complete verified release snapshot.
    ///
    /// Releases without a complete artifact snapshot are retained with a zero
    /// count so browse pages can distinguish "no packages" from an omitted
    /// release row.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or if a count is outside `usize`.
    pub async fn list_release_package_counts(
        &self,
        registry_id: i64,
    ) -> Result<Vec<(String, usize)>> {
        let rows = self
            .backend
            .query(
                "SELECT release.semver, COUNT(DISTINCT artifact.package_name)
                   FROM releases release
                   LEFT JOIN release_artifact_snapshot_heads head
                     ON head.release_id = release.id AND head.registry_id = release.registry_id
                   LEFT JOIN release_artifact_snapshots snapshot
                     ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                    AND snapshot.state = 'complete'
                    AND snapshot.source_commit = release.commit_oid
                    AND snapshot.verified_tag_oid = release.tag_oid
                   LEFT JOIN release_artifacts artifact
                     ON artifact.snapshot_id = snapshot.snapshot_id
                    AND artifact.artifact_kind = 'output'
                  WHERE release.registry_id = ?1
                  GROUP BY release.id, release.semver
                  ORDER BY release.semver",
                &vals![registry_id],
            )
            .await?;

        rows.iter()
            .map(|row| {
                let release = row.get::<String>(0)?;
                let count = row.get::<i64>(1)?;
                Ok((
                    release,
                    usize::try_from(count).context("release package count is outside usize")?,
                ))
            })
            .collect()
    }

    /// Lists the complete signed image catalogs retained by the current index.
    ///
    /// Unlike [`Self::list_system_images`], this method does not apply live
    /// placement-readiness filtering. Index rebuilds use the immutable catalog
    /// identity and re-attest its objects against the newly selected
    /// publication before reusing it.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure, inconsistent catalog identity, or
    /// malformed signed image metadata.
    pub async fn list_release_image_snapshots(
        &self,
        registry_id: i64,
    ) -> Result<Vec<ReleaseImageSnapshot>> {
        let rows = self
            .backend
            .query(
                "SELECT image.release, image.source_commit,
                        image.verified_tag_oid, image.catalog_digest,
                        image.package_name, image.platform, image.format,
                        image.delivery
                   FROM registry_system_images image
                   JOIN releases rel
                     ON rel.registry_id = image.registry_id
                    AND rel.semver = image.release
                    AND rel.commit_oid = image.source_commit
                    AND rel.tag_oid = image.verified_tag_oid
                  WHERE image.registry_id = ?1
                  ORDER BY image.release, image.package_name,
                           image.platform, image.format",
                &vals![registry_id],
            )
            .await?;

        let mut catalogs = Vec::<ReleaseImageSnapshot>::new();
        for row in &rows {
            let release_tag: String = row.get(0)?;
            let source_commit: String = row.get(1)?;
            let verified_tag_oid: String = row.get(2)?;
            let catalog_digest: String = row.get(3)?;
            if catalog_digest.len() != 64
                || !catalog_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("indexed signed image catalog has invalid digest identity");
            }

            let starts_catalog = catalogs.last().is_none_or(|catalog| {
                catalog.release_tag != release_tag
                    || catalog.source_commit != source_commit
                    || catalog.verified_tag_oid != verified_tag_oid
                    || catalog.catalog_digest != catalog_digest
            });
            if starts_catalog {
                if catalogs
                    .last()
                    .is_some_and(|catalog| catalog.release_tag == release_tag)
                {
                    bail!("indexed release has conflicting signed image catalog identities");
                }
                catalogs.push(ReleaseImageSnapshot {
                    release_tag: release_tag.clone(),
                    source_commit: source_commit.clone(),
                    verified_tag_oid: verified_tag_oid.clone(),
                    catalog_digest: catalog_digest.clone(),
                    images: Vec::new(),
                });
            }

            let package: String = row.get(4)?;
            let platform: String = row.get(5)?;
            let format: String = row.get(6)?;
            let encoded: String = row.get(7)?;
            let stored = decode_stored_system_image(&encoded)?;
            stored
                .delivery
                .validate(&format, &release_tag, &platform)
                .context("validating indexed signed image delivery metadata")?;
            catalogs
                .last_mut()
                .context("signed image catalog grouping lost its parent row")?
                .images
                .push(IndexedSystemImage {
                    package,
                    release: release_tag,
                    platform,
                    format,
                    store_path: stored.store_path,
                    nar_hash: stored.nar_hash,
                    nar_size: stored.nar_size,
                    delivery: stored.delivery,
                });
        }
        Ok(catalogs)
    }

    /// Returns whether the last good index contains a signed container root.
    ///
    /// The indexer uses this to force exact placement revalidation on every
    /// refresh of a container-bearing registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn has_container_release_catalog(&self, registry_id: i64) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_release_roots WHERE registry_id = ?1 LIMIT 1",
                &vals![registry_id],
            )
            .await?
            .is_some())
    }

    /// List verified releases, newest first.
    ///
    /// Naturally bounded: the indexer writes at most
    /// the hub's `indexer::MAX_RELEASE_TAGS` (1024) release rows
    /// per registry, so the result set cannot grow without bound and needs no
    /// additional DB-side `LIMIT`.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_releases(&self, registry_id: i64) -> Result<Vec<ReleaseRow>> {
        let rows = self
            .backend
            .query(
                "SELECT semver, tag_oid, commit_oid, signer, tagged_at, pack_present
             FROM releases WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC",
                &vals![registry_id],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ReleaseRow {
                    semver: row.get(0)?,
                    tag_oid: row.get(1)?,
                    commit_oid: row.get(2)?,
                    signer: row.get(3)?,
                    tagged_at: row.get(4)?,
                    pack_present: row.get(5)?,
                })
            })
            .collect()
    }

    /// Lists verified releases that own a complete immutable artifact snapshot.
    ///
    /// A complete empty snapshot is returned with an empty artifact vector;
    /// releases with missing, building, or failed snapshots are excluded.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn list_retention_release_snapshots(
        &self,
        registry_id: i64,
    ) -> Result<Vec<RetentionReleaseSnapshotRecord>> {
        let rows = self
            .backend
            .query(
                "SELECT rel.id, rel.semver, rel.tag_oid, rel.tagged_at,
                        ras.snapshot_id, ras.manifest_digest,
                        rsa.package_name, rsa.package_version, rsa.platform,
                        rsa.artifact_kind, rsa.store_path, rsa.store_hash
                 FROM releases rel
                 JOIN release_artifact_snapshot_heads head
                   ON head.release_id = rel.id AND head.registry_id = rel.registry_id
                 JOIN release_artifact_snapshots ras
                   ON ras.snapshot_id = head.complete_artifact_snapshot_id
                  AND ras.release_id = head.release_id
                  AND ras.registry_id = head.registry_id
                  AND ras.state = 'complete'
                  AND ras.source_commit = rel.commit_oid
                  AND ras.verified_tag_oid = rel.tag_oid
                 LEFT JOIN release_artifacts rsa
                   ON rsa.snapshot_id = ras.snapshot_id
                  AND rsa.release_id = ras.release_id
                  AND rsa.registry_id = ras.registry_id
                 WHERE rel.registry_id = ?1
                 ORDER BY rel.id, rsa.package_name, rsa.package_version,
                          rsa.platform, rsa.artifact_kind, rsa.store_hash",
                &vals![registry_id],
            )
            .await?;
        let mut releases = Vec::<RetentionReleaseSnapshotRecord>::new();
        for row in &rows {
            let release_id: i64 = row.get(0)?;
            if releases.last().map(|release| release.release_id) != Some(release_id) {
                releases.push(RetentionReleaseSnapshotRecord {
                    release_id,
                    tag: row.get(1)?,
                    verified_tag_oid: row.get(2)?,
                    tagged_at: row.get(3)?,
                    snapshot_id: row.get(4)?,
                    manifest_digest: row.get(5)?,
                    artifacts: Vec::new(),
                });
            }
            let package_name: Option<String> = row.get(6)?;
            if let Some(package_name) = package_name {
                let release = releases
                    .last_mut()
                    .context("release snapshot grouping lost its parent row")?;
                release.artifacts.push(ReleaseSnapshotArtifact {
                    package_name,
                    package_version: row.get(7)?,
                    platform: row.get(8)?,
                    artifact_kind: row.get(9)?,
                    store_path: row.get(10)?,
                    store_hash: row.get(11)?,
                });
            }
        }
        Ok(releases)
    }
}
