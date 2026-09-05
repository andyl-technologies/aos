//! Immutable package catalogs and documentation search for release browsing.
//!
//! Indexing prepares projections by source commit and document digest. Public
//! reads join the current signed tag and completed artifact snapshot, so an
//! interrupted refresh cannot expose an unpublished catalog. JSON package
//! projections retain the complete `PackageToml` schema, including historical
//! descriptions and platform store identities. Configuration paths and search
//! tokens are projected by the bounded documentation-tree index.

use anyhow::{ensure, Context as _, Result};
use aos_registry_surface::manifest::PackageToml;
use sha2::{Digest as _, Sha256};

use super::{Database, IndexedPackageDocumentation};
use crate::backend::Statement;

/// One container index recorded by a signed release.
#[derive(Debug, Clone)]
pub struct ReleaseContainerRow {
    /// Registry release version.
    pub release: String,
    /// Registry-local OCI repository name.
    pub repository: aos_oci_types::RepositoryName,
    /// Package represented by the container.
    pub package: String,
    /// Immutable multi-platform index or manifest digest.
    pub digest: aos_oci_types::Sha256Digest,
}

impl Database {
    /// Retains the package catalog loaded from one verified Git commit.
    ///
    /// This prepares disposable browse data without changing release membership.
    /// Callers must authenticate the source tree before calling this method.
    ///
    /// # Errors
    /// Returns an error for an invalid default version, serialization failure,
    /// or database failure.
    pub(crate) async fn retain_release_browse_catalog(
        &self,
        registry_id: i64,
        source_commit: &str,
        packages: &[PackageToml],
        default_release: Option<&str>,
        documents: &[IndexedPackageDocumentation],
    ) -> Result<()> {
        if let Some(version) = default_release {
            semver::Version::parse(version).context("invalid default browsing release")?;
        }
        let packages_json = serde_json::to_string(&serde_json::to_value(packages)?)?;
        let content_digest = hex::encode(Sha256::digest(packages_json.as_bytes()));
        let package_count = i64::try_from(packages.len())?;
        let documentation_count = i64::try_from(
            packages
                .iter()
                .flat_map(|package| &package.versions)
                .flat_map(|version| version.platforms.values())
                .filter(|platform| platform.documentation.is_some())
                .count(),
        )?;
        let mut statements = vec![Statement::new(
            "INSERT INTO release_browse_catalogs
               (registry_id, source_commit, packages_json, content_digest, default_release,
                package_count, documentation_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(registry_id, source_commit) DO UPDATE SET
               packages_json = excluded.packages_json,
               content_digest = excluded.content_digest,
               default_release = excluded.default_release,
               package_count = excluded.package_count,
               documentation_count = excluded.documentation_count",
            vals![
                registry_id,
                source_commit,
                packages_json,
                content_digest,
                default_release,
                package_count,
                documentation_count
            ]
            .to_vec(),
        )];
        super::documentation_tree::extend_tree_projection(
            &mut statements,
            registry_id,
            source_commit,
            documents,
        )?;
        self.backend.batch(&statements).await?;
        Ok(())
    }

    /// Counts packages and exact documentation objects in completed catalogs.
    ///
    /// Missing projections are omitted so callers can distinguish indexing
    /// from a successfully indexed empty release.
    ///
    /// # Errors
    /// Returns an error on database failure or invalid counts.
    pub async fn release_browse_counts(
        &self,
        registry_id: i64,
    ) -> Result<Vec<(String, usize, usize)>> {
        self.backend.query(
            "SELECT rel.semver, catalog.package_count, catalog.documentation_count
             FROM releases rel JOIN release_browse_catalogs catalog
               ON catalog.registry_id = rel.registry_id AND catalog.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1",
            &vals![registry_id],
        ).await?.into_iter().map(|row| Ok((row.get(0)?,
            usize::try_from(row.get::<i64>(1)?)?, usize::try_from(row.get::<i64>(2)?)?))).collect()
    }

    /// Retains the message of an authenticated annotated release tag.
    ///
    /// # Errors
    /// Returns an error on database failure.
    pub(crate) async fn retain_release_notes(
        &self,
        registry_id: i64,
        tag_oid: &str,
        body: &str,
    ) -> Result<()> {
        self.backend
            .execute(
                "INSERT INTO release_browse_notes (registry_id, tag_oid, body)
             VALUES (?1, ?2, ?3) ON CONFLICT(registry_id, tag_oid)
             DO UPDATE SET body = excluded.body",
                &vals![registry_id, tag_oid, body],
            )
            .await?;
        Ok(())
    }

    /// Loads release notes for the current exact tag identity.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed row values.
    pub async fn release_browse_notes(
        &self,
        registry_id: i64,
        release: &str,
    ) -> Result<Option<String>> {
        self.backend
            .query_opt(
                "SELECT note.body FROM release_browse_notes note JOIN releases rel
               ON rel.registry_id = note.registry_id AND rel.tag_oid = note.tag_oid
             WHERE rel.registry_id = ?1 AND rel.semver = ?2",
                &vals![registry_id, release],
            )
            .await?
            .map(|row| row.get(0))
            .transpose()
    }

    /// Loads the browsing default from the indexed registry configuration.
    ///
    /// Preparing a newer commit does not change the preference until that
    /// commit becomes the registry's indexed generation.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed row values.
    pub async fn default_browse_release(&self, registry_id: i64) -> Result<Option<String>> {
        Ok(self
            .backend
            .query_opt(
                "SELECT catalog.default_release FROM release_browse_catalogs catalog
             JOIN registry_index current_index
               ON current_index.registry_id = catalog.registry_id
              AND current_index.last_indexed_commit = catalog.source_commit
             WHERE catalog.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .map(|row| row.get::<Option<String>>(0))
            .transpose()?
            .flatten())
    }

    /// Checks whether every published release has its browse projections.
    ///
    /// Missing rows force one full index after a schema upgrade. Empty package
    /// and documentation catalogs count as complete.
    ///
    /// # Errors
    /// Returns an error on database failure or malformed row values.
    pub(crate) async fn release_browse_projection_complete(
        &self,
        registry_id: i64,
    ) -> Result<bool> {
        let missing = self.backend.query_opt(
            "SELECT 1 FROM releases rel
             LEFT JOIN release_browse_catalogs catalog
               ON catalog.registry_id = rel.registry_id AND catalog.source_commit = rel.commit_oid
             LEFT JOIN release_browse_notes note
               ON note.registry_id = rel.registry_id AND note.tag_oid = rel.tag_oid
             LEFT JOIN release_browse_tree_nodes node
               ON node.registry_id = rel.registry_id AND node.source_commit = rel.commit_oid AND node.parent_key IS NULL
             WHERE rel.registry_id = ?1 AND (catalog.source_commit IS NULL OR note.tag_oid IS NULL OR node.node_key IS NULL)
             UNION ALL
             SELECT 1 FROM registry_index current_index
             LEFT JOIN release_browse_catalogs catalog
               ON catalog.registry_id = current_index.registry_id
              AND catalog.source_commit = current_index.last_indexed_commit
             WHERE current_index.registry_id = ?1 AND catalog.source_commit IS NULL
             LIMIT 1",
            &vals![registry_id],
        ).await?;
        Ok(missing.is_none())
    }

    /// Loads the complete package catalog for an exact published release.
    ///
    /// Returns `None` while its authenticated browse projection is unavailable.
    /// An empty vector means that the release published no packages.
    ///
    /// # Errors
    /// Returns an error on database failure, damaged projection bytes, or
    /// invalid retained package metadata.
    pub async fn release_browse_packages(
        &self,
        registry_id: i64,
        release: &str,
    ) -> Result<Option<Vec<PackageToml>>> {
        let row = self.backend.query_opt(
            "SELECT catalog.packages_json, catalog.content_digest
             FROM releases rel
             JOIN release_browse_catalogs catalog
               ON catalog.registry_id = rel.registry_id AND catalog.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1 AND rel.semver = ?2",
            &vals![registry_id, release],
        ).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let bytes: String = row.get(0)?;
        let digest: String = row.get(1)?;
        ensure!(
            hex::encode(Sha256::digest(bytes.as_bytes())) == digest,
            "release browse catalog digest mismatch"
        );
        Ok(Some(
            serde_json::from_str(&bytes).context("invalid release browse catalog")?,
        ))
    }

    /// Lists container roots from exact signed releases, independently of tags.
    ///
    /// # Errors
    /// Returns an error on database failure or invalid repository/digest data.
    pub async fn list_release_browse_containers(
        &self,
        registry_id: i64,
    ) -> Result<Vec<ReleaseContainerRow>> {
        self.backend.query(
            "SELECT rel.semver, repository.name, root.container_name, root.index_digest
             FROM oci_release_roots root JOIN releases rel
               ON rel.id = root.release_id AND rel.registry_id = root.registry_id
              AND rel.semver = root.release_tag AND rel.commit_oid = root.source_commit
              AND rel.tag_oid = root.verified_tag_oid
             JOIN oci_repositories repository
               ON repository.id = root.repository_id AND repository.registry_id = root.registry_id
              AND repository.lifecycle_state = 'active'
             JOIN oci_blobs blob ON blob.registry_id = root.registry_id AND blob.digest = root.index_digest
              AND blob.lifecycle_state = 'active'
             WHERE root.registry_id = ?1
             ORDER BY rel.semver, repository.name, root.container_name",
            &vals![registry_id],
        ).await?.into_iter().map(|row| Ok(ReleaseContainerRow {
            release: row.get(0)?,
            repository: aos_oci_types::RepositoryName::parse(&row.get::<String>(1)?)?,
            package: row.get(2)?,
            digest: aos_oci_types::Sha256Digest::parse(&row.get::<String>(3)?)?,
        })).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IndexSnapshot, ReleaseArtifactSnapshot, ReleaseRow};

    fn package(description: &str, version: &str) -> PackageToml {
        toml::from_str(&format!("[package]\nname = \"demo\"\ndescription = \"{description}\"\nlicense = \"MIT\"\nmaintainer = \"maintainer\"\n[[versions]]\nversion = \"{version}\"\n")).unwrap()
    }

    #[tokio::test]
    async fn publication_selects_its_own_branch_catalog_and_tag_notes() {
        let db = Database::open_in_memory().await.unwrap();
        let registry = db
            .register_registry("release-catalog", &[], false)
            .await
            .unwrap();
        let released = vec![package("Published on a maintenance branch", "1.9.0")];
        let head = vec![package("Unpublished main changes", "99.0.0")];
        db.retain_release_browse_catalog(registry, "branch-commit", &released, None, &[])
            .await
            .unwrap();
        db.retain_release_browse_catalog(registry, "head-commit", &head, Some("1.0.0"), &[])
            .await
            .unwrap();
        assert!(db
            .release_browse_packages(registry, "1.0.0")
            .await
            .unwrap()
            .is_none());
        let snapshot = IndexSnapshot {
            commit: "head-commit".into(),
            name: "Catalog".into(),
            refs_digest: Some("refs".into()),
            releases: vec![ReleaseRow {
                semver: "1.0.0".into(),
                tag_oid: "signed-tag".into(),
                commit_oid: "branch-commit".into(),
                signer: Some("maintainer".into()),
                tagged_at: Some(1),
                pack_present: true,
            }],
            release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
                release_tag: "1.0.0".into(),
                source_commit: "branch-commit".into(),
                verified_tag_oid: "signed-tag".into(),
                manifest_digest: hex::encode(Sha256::digest(b"[]")),
                artifacts: Vec::new(),
                container_release: None,
                documentation: Vec::new(),
            }],
            ..IndexSnapshot::default()
        };
        // Model an existing installation whose completed snapshot predates
        // registry-scoped IDs. A refresh must preserve that exact owned row.
        let mut before_artifacts = snapshot.clone();
        before_artifacts.release_artifact_snapshots.clear();
        db.apply_snapshot(registry, &before_artifacts)
            .await
            .unwrap();
        let manifest = &snapshot.release_artifact_snapshots[0].manifest_digest;
        let legacy_id = hex::encode(Sha256::digest(format!(
            "signed-tag\0branch-commit\0{manifest}"
        )));
        db.backend
            .execute(
                "INSERT INTO release_artifact_snapshots
             (snapshot_id, release_id, registry_id, source_commit, verified_tag_oid,
              verification_record_id, manifest_digest, state, complete_slot,
              expected_artifact_count, actual_artifact_count, started_at, completed_at)
             SELECT ?1, id, registry_id, commit_oid, tag_oid, tag_oid, ?2,
                    'complete', 1, 0, 0, 0, 0 FROM releases WHERE registry_id = ?3",
                &vals![legacy_id, manifest, registry],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "INSERT INTO release_artifact_snapshot_heads
             (release_id, registry_id, complete_artifact_snapshot_id, resource_version, updated_at)
             SELECT release_id, registry_id, snapshot_id, 1, 0
             FROM release_artifact_snapshots WHERE snapshot_id = ?1",
                &vals![legacy_id],
            )
            .await
            .unwrap();
        db.apply_snapshot(registry, &snapshot).await.unwrap();
        let retained: String = db.backend.query_opt(
            "SELECT complete_artifact_snapshot_id FROM release_artifact_snapshot_heads WHERE registry_id = ?1",
            &vals![registry],
        ).await.unwrap().unwrap().get(0).unwrap();
        assert_eq!(retained, legacy_id);
        let twin = db
            .register_registry("identical-release", &[], false)
            .await
            .unwrap();
        db.retain_release_browse_catalog(twin, "branch-commit", &released, None, &[])
            .await
            .unwrap();
        db.apply_snapshot(twin, &snapshot).await.unwrap();
        for owner in [registry, twin] {
            assert_eq!(
                db.documentation_tree_commit(owner, "1.0.0")
                    .await
                    .unwrap()
                    .as_deref(),
                Some("branch-commit")
            );
            db.apply_snapshot(owner, &snapshot).await.unwrap();
        }
        let published = db
            .release_browse_packages(registry, "1.0.0")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            published[0].package.description,
            "Published on a maintenance branch"
        );
        assert_eq!(
            published[0].versions[0].version, "1.9.0",
            "package versions differ from registry releases"
        );
        assert_eq!(
            db.default_browse_release(registry)
                .await
                .unwrap()
                .as_deref(),
            Some("1.0.0")
        );
        assert!(db
            .release_browse_packages(registry, "HEAD")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .release_browse_packages(registry + 1, "1.0.0")
            .await
            .unwrap()
            .is_none());
        assert!(!db
            .release_browse_projection_complete(registry)
            .await
            .unwrap());
        db.retain_release_notes(registry, "signed-tag", "Maintenance fixes")
            .await
            .unwrap();
        assert!(db
            .release_browse_projection_complete(registry)
            .await
            .unwrap());
        assert_eq!(
            db.release_browse_notes(registry, "1.0.0")
                .await
                .unwrap()
                .as_deref(),
            Some("Maintenance fixes")
        );
        assert_eq!(
            db.release_browse_counts(registry).await.unwrap(),
            vec![("1.0.0".into(), 1, 0)]
        );

        db.backend.execute("UPDATE release_browse_catalogs SET packages_json = '{}' WHERE registry_id = ?1 AND source_commit = 'branch-commit'", &vals![registry]).await.unwrap();
        assert!(db.release_browse_packages(registry, "1.0.0").await.is_err());
        db.retain_release_browse_catalog(registry, "branch-commit", &released, None, &[])
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE releases SET tag_oid = 'replacement-tag' WHERE registry_id = ?1",
                &vals![registry],
            )
            .await
            .unwrap();
        assert!(db
            .release_browse_packages(registry, "1.0.0")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .documentation_tree_commit(registry, "1.0.0")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .release_browse_notes(registry, "1.0.0")
            .await
            .unwrap()
            .is_none());
    }
}
