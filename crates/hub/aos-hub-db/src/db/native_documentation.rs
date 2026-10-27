//! Disposable native search projections pinned to authenticated release catalogs.
//!
//! Search rows are generated from the shared runtime reader during admission.
//! They cannot authenticate or replace the canonical immutable document.

use anyhow::{ensure, Context, Result};
use aos_module_docs::SearchDocument;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Database;
use crate::backend::Statement;

/// Describes one native reference's generated search projection.
#[derive(Debug, Serialize, Deserialize)]
pub struct NativeDocumentationIndex {
    /// Identifies the owning package.
    pub package: String,
    /// Identifies the exact package version.
    pub version: String,
    /// Identifies the target platform.
    pub platform: String,
    /// Identifies the signed exact document bytes.
    pub document_sha256: String,
    /// Identifies the authenticated immutable documentation root.
    pub store_path: String,
    /// Contains mechanically generated package, option, and operation entries.
    pub search: Vec<SearchDocument>,
}

/// Holds the exact native document locator selected from a completed signed release.
#[derive(Debug)]
pub struct NativeDocumentationLocator {
    /// Names the selected release.
    pub release: String,
    /// Identifies its verified commit.
    pub commit: String,
    /// Identifies its verified annotated tag.
    pub tag_oid: String,
    /// Identifies the completed immutable artifact snapshot.
    pub snapshot_id: String,
    /// Names the package.
    pub package: String,
    /// Identifies its version.
    pub version: String,
    /// Identifies its target platform.
    pub platform: String,
    /// Retains its authenticated directory locator.
    pub artifact: aos_registry_format::manifest::NativeArtifactMeta,
}

/// Couples a bounded search projection to its authenticated release identity.
#[derive(Debug)]
pub struct NativeDocumentationSearchDocument {
    /// Names the release that authenticates the projection.
    pub release: String,
    /// Identifies the release commit.
    pub commit: String,
    /// Contains the checked search projection.
    pub document: NativeDocumentationIndex,
}

impl Database {
    /// Resolves one native document by digest through a completed release snapshot.
    ///
    /// # Errors
    /// Returns an error for damaged catalogs or database failures.
    pub async fn native_documentation_locator_by_digest(
        &self,
        registry_id: i64,
        document_sha256: &str,
    ) -> Result<Option<NativeDocumentationLocator>> {
        let row = self.backend.query_opt(
            "SELECT rel.semver, rel.commit_oid, rel.tag_oid, snapshot.snapshot_id,
                    docs.package_name, docs.package_version, docs.platform, docs.store_path
             FROM release_native_documentation docs
             JOIN releases rel
               ON rel.registry_id = docs.registry_id AND rel.commit_oid = docs.source_commit
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             JOIN release_artifacts artifact
               ON artifact.snapshot_id = snapshot.snapshot_id
              AND artifact.package_name = docs.package_name
              AND artifact.package_version = docs.package_version
              AND artifact.platform = docs.platform
              AND artifact.artifact_kind = 'output' AND artifact.store_path = docs.store_path
             WHERE docs.registry_id = ?1 AND docs.document_sha256 = ?2
             ORDER BY rel.id DESC
             LIMIT 1",
            &vals![registry_id, document_sha256],
        ).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let release: String = row.get(0)?;
        let package: String = row.get(4)?;
        let version: String = row.get(5)?;
        let platform: String = row.get(6)?;
        let store_path: String = row.get(7)?;
        let catalog = self
            .release_browse_packages(registry_id, &release)
            .await?
            .context("native documentation release catalog is unavailable")?;
        let artifact = native_documentation_artifact(&catalog, &package, &version, &platform)
            .context("native documentation has no authenticated catalog locator")?;
        ensure!(
            artifact.document_sha256 == document_sha256 && artifact.store_path == store_path,
            "native documentation identity differs"
        );

        Ok(Some(NativeDocumentationLocator {
            release,
            commit: row.get(1)?,
            tag_oid: row.get(2)?,
            snapshot_id: row.get(3)?,
            package,
            version,
            platform,
            artifact: artifact.clone(),
        }))
    }

    /// Loads at most `limit` native projections from completed releases.
    ///
    /// A `None` result means the registry exceeds the caller's work budget.
    ///
    /// # Errors
    /// Returns an error for damaged catalogs, projection corruption, or database failures.
    pub async fn bounded_native_documentation_search(
        &self,
        registry_id: i64,
        limit: usize,
    ) -> Result<Option<Vec<NativeDocumentationSearchDocument>>> {
        let query_limit = i64::try_from(limit)?.saturating_add(1);
        let rows = self.backend.query(
            "SELECT rel.semver, rel.commit_oid, docs.package_name, docs.package_version,
                    docs.platform, docs.document_sha256, docs.store_path,
                    docs.search_json, docs.content_digest
             FROM release_native_documentation docs
             JOIN releases rel
               ON rel.registry_id = docs.registry_id AND rel.commit_oid = docs.source_commit
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             JOIN release_artifacts artifact
               ON artifact.snapshot_id = snapshot.snapshot_id
              AND artifact.package_name = docs.package_name
              AND artifact.package_version = docs.package_version
              AND artifact.platform = docs.platform
              AND artifact.artifact_kind = 'output' AND artifact.store_path = docs.store_path
             WHERE docs.registry_id = ?1
             ORDER BY rel.id DESC, docs.package_name, docs.package_version, docs.platform
             LIMIT ?2",
            &vals![registry_id, query_limit],
        ).await?;
        if rows.len() > limit {
            return Ok(None);
        }

        let mut catalogs = std::collections::BTreeMap::new();
        let mut documents = Vec::with_capacity(rows.len());
        for row in rows {
            let release: String = row.get(0)?;
            if !catalogs.contains_key(&release) {
                let catalog = self
                    .release_browse_packages(registry_id, &release)
                    .await?
                    .context("native documentation release catalog is unavailable")?;
                catalogs.insert(release.clone(), catalog);
            }
            let package: String = row.get(2)?;
            let version: String = row.get(3)?;
            let platform: String = row.get(4)?;
            let document_sha256: String = row.get(5)?;
            let store_path: String = row.get(6)?;
            let search_json: String = row.get(7)?;
            let content_digest: String = row.get(8)?;
            ensure!(
                hex::encode(Sha256::digest(search_json.as_bytes())) == content_digest,
                "native search projection digest differs"
            );
            let artifact = native_documentation_artifact(
                catalogs
                    .get(&release)
                    .context("release catalog disappeared")?,
                &package,
                &version,
                &platform,
            )
            .context("native search projection has no authenticated catalog locator")?;
            ensure!(
                artifact.document_sha256 == document_sha256 && artifact.store_path == store_path,
                "native search projection document identity differs"
            );
            documents.push(NativeDocumentationSearchDocument {
                release,
                commit: row.get(1)?,
                document: NativeDocumentationIndex {
                    package,
                    version,
                    platform,
                    document_sha256,
                    store_path,
                    search: serde_json::from_str(&search_json)?,
                },
            });
        }

        Ok(Some(documents))
    }

    /// Resolves native documentation only through completed authenticated releases.
    ///
    /// # Errors
    /// Returns an error for damaged catalogs or database failures.
    pub async fn native_documentation_locator(
        &self,
        registry_id: i64,
        package: &str,
        version: &str,
        platform: &str,
        release: Option<&str>,
    ) -> Result<Option<NativeDocumentationLocator>> {
        let mut releases = self.list_releases(registry_id).await?;
        let preferred = self.default_browse_release(registry_id).await?;
        if let Some(preferred) = preferred {
            releases.sort_by_key(|entry| entry.semver != preferred);
        }
        for selected in releases
            .iter()
            .filter(|entry| release.is_none_or(|release| entry.semver == release))
        {
            let Some(catalog) = self
                .release_browse_packages(registry_id, &selected.semver)
                .await?
            else {
                continue;
            };
            let Some(package) = catalog.iter().find(|entry| entry.package.name == package) else {
                continue;
            };
            for selected_version in package
                .versions
                .iter()
                .rev()
                .filter(|entry| version.is_empty() || entry.version == version)
            {
                for (selected_platform, entry) in selected_version
                    .platforms
                    .iter()
                    .filter(|(name, _)| platform.is_empty() || *name == platform)
                {
                    let Some(artifact) = &entry.module_documentation else {
                        continue;
                    };
                    let snapshot = self.backend.query_opt(
                        "SELECT snapshot.snapshot_id FROM releases rel
                         JOIN release_artifact_snapshot_heads head ON head.release_id = rel.id AND head.registry_id = rel.registry_id
                         JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                          AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid AND snapshot.state = 'complete'
                         JOIN release_artifacts artifact ON artifact.snapshot_id = snapshot.snapshot_id
                          AND artifact.package_name = ?3 AND artifact.package_version = ?4
                          AND artifact.platform = ?5 AND artifact.store_path = ?6 AND artifact.artifact_kind = 'output'
                         WHERE rel.registry_id = ?1 AND rel.semver = ?2",
                        &vals![registry_id, selected.semver, package.package.name, selected_version.version, selected_platform, artifact.store_path],
                    ).await?;
                    let Some(snapshot) = snapshot else {
                        continue;
                    };
                    return Ok(Some(NativeDocumentationLocator {
                        release: selected.semver.clone(),
                        commit: selected.commit_oid.clone(),
                        tag_oid: selected.tag_oid.clone(),
                        snapshot_id: snapshot.get(0)?,
                        package: package.package.name.clone(),
                        version: selected_version.version.clone(),
                        platform: selected_platform.clone(),
                        artifact: artifact.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Retains native search projections for one verified committed catalog.
    ///
    /// # Errors
    /// Returns an error for invalid projection serialization or database failures.
    pub async fn retain_native_documentation(
        &self,
        registry_id: i64,
        source_commit: &str,
        documents: &[NativeDocumentationIndex],
    ) -> Result<()> {
        let mut statements = vec![Statement::new(
            "DELETE FROM release_native_documentation WHERE registry_id = ?1 AND source_commit = ?2",
            vals![registry_id, source_commit].to_vec(),
        )];
        for document in documents {
            let search_json = serde_json::to_string(&document.search)?;
            let content_digest = hex::encode(Sha256::digest(search_json.as_bytes()));
            statements.push(Statement::new(
                "INSERT INTO release_native_documentation
                    (registry_id, source_commit, package_name, package_version, platform,
                     document_sha256, store_path, search_json, content_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                vals![
                    registry_id,
                    source_commit,
                    document.package,
                    document.version,
                    document.platform,
                    document.document_sha256,
                    document.store_path,
                    search_json,
                    content_digest
                ]
                .to_vec(),
            ));
        }
        self.backend.batch(&statements).await?;
        Ok(())
    }

    /// Loads native search projections from an exact completed release snapshot.
    ///
    /// # Errors
    /// Returns an error for missing catalog rows, projection corruption, or database failures.
    pub async fn native_documentation_at_release(
        &self,
        registry_id: i64,
        release: &str,
    ) -> Result<Vec<NativeDocumentationIndex>> {
        let catalog = self
            .release_browse_packages(registry_id, release)
            .await?
            .context("native documentation release catalog is unavailable")?;
        let rows = self.backend.query(
            "SELECT docs.package_name, docs.package_version, docs.platform,
                    docs.document_sha256, docs.search_json, docs.content_digest, artifact.store_path
             FROM releases rel
             JOIN release_native_documentation docs
               ON docs.registry_id = rel.registry_id AND docs.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot
               ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
              AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
              AND snapshot.state = 'complete'
             JOIN release_artifacts artifact
               ON artifact.snapshot_id = snapshot.snapshot_id
              AND artifact.package_name = docs.package_name
              AND artifact.package_version = docs.package_version
              AND artifact.platform = docs.platform
              AND artifact.artifact_kind = 'output' AND artifact.store_path = docs.store_path
             WHERE rel.registry_id = ?1 AND rel.semver = ?2
             ORDER BY docs.package_name, docs.package_version, docs.platform",
            &vals![registry_id, release],
        ).await?;
        let mut documents = Vec::new();
        for row in rows {
            let package: String = row.get(0)?;
            let version: String = row.get(1)?;
            let platform: String = row.get(2)?;
            let document_sha256: String = row.get(3)?;
            let search_json: String = row.get(4)?;
            let digest: String = row.get(5)?;
            let store_path: String = row.get(6)?;
            ensure!(
                hex::encode(Sha256::digest(search_json.as_bytes())) == digest,
                "native search projection digest differs"
            );
            let artifact = catalog
                .iter()
                .find(|entry| entry.package.name == package)
                .and_then(|entry| entry.versions.iter().find(|entry| entry.version == version))
                .and_then(|entry| entry.platforms.get(&platform))
                .and_then(|entry| entry.module_documentation.as_ref())
                .context("native search projection has no authenticated catalog locator")?;
            ensure!(
                artifact.document_sha256 == document_sha256 && artifact.store_path == store_path,
                "native search projection document identity differs"
            );
            documents.push(NativeDocumentationIndex {
                package,
                version,
                platform,
                document_sha256,
                store_path,
                search: serde_json::from_str(&search_json)?,
            });
        }
        let expected = catalog
            .iter()
            .flat_map(|package| &package.versions)
            .flat_map(|version| version.platforms.values())
            .filter(|entry| entry.module_documentation.is_some())
            .count();
        ensure!(
            documents.len() == expected,
            "native search projection is incomplete"
        );
        Ok(documents)
    }
}

fn native_documentation_artifact<'a>(
    catalog: &'a [aos_registry_format::manifest::PackageToml],
    package: &str,
    version: &str,
    platform: &str,
) -> Option<&'a aos_registry_format::manifest::NativeArtifactMeta> {
    catalog
        .iter()
        .find(|entry| entry.package.name == package)
        .and_then(|entry| entry.versions.iter().find(|entry| entry.version == version))
        .and_then(|entry| entry.platforms.get(platform))
        .and_then(|entry| entry.module_documentation.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    use crate::db::fixtures::count_queries;
    use crate::db::{IndexSnapshot, ReleaseArtifactSnapshot, ReleaseRow};

    #[tokio::test]
    async fn native_search_requires_complete_release_and_exact_projection_identity() {
        let db = Database::open_in_memory().await.unwrap();
        let registry = db
            .register_registry("native-reference", &[], false)
            .await
            .unwrap();
        let mut package: aos_registry_format::manifest::PackageToml = toml::from_str(
            r#"
[package]
name = "sample"
description = "Native sample"
license = "MIT"
maintainer = "maintainer"
[[versions]]
version = "1"
[versions.platforms.x86_64-linux]
store_path = "/nix/store/00000000000000000000000000000000-sample"
nar_hash = "sha256:aa"
nar_size = 10
closure_size = 10
source_drv = ""
source_nar_hash = ""
"#,
        )
        .unwrap();
        let locator = aos_registry_format::manifest::NativeArtifactMeta {
            store_path: "/nix/store/11111111111111111111111111111111-options".into(),
            nar_hash: format!("sha256:{}", "0".repeat(64)),
            nar_size: 512,
            references: Vec::new(),
            document_sha256: format!("sha256:{}", "1".repeat(64)),
            document_size: 100,
        };
        package.versions[0]
            .platforms
            .get_mut("x86_64-linux")
            .unwrap()
            .module_documentation = Some(locator.clone());
        let documents = vec![NativeDocumentationIndex {
            package: "sample".into(),
            version: "1".into(),
            platform: "x86_64-linux".into(),
            document_sha256: locator.document_sha256.clone(),
            store_path: locator.store_path.clone(),
            search: Vec::new(),
        }];
        db.retain_release_browse_catalog(registry, "native-commit", &[package], None)
            .await
            .unwrap();
        db.retain_native_documentation(registry, "native-commit", &documents)
            .await
            .unwrap();
        assert!(db
            .native_documentation_at_release(registry, "1.0.0")
            .await
            .is_err());

        let artifacts = vec![crate::db::ReleaseSnapshotArtifact {
            package_name: "sample".into(),
            package_version: "1".into(),
            platform: "x86_64-linux".into(),
            artifact_kind: "output".into(),
            store_path: locator.store_path,
            store_hash: "11111111111111111111111111111111".into(),
        }];
        let manifest_digest = hex::encode(Sha256::digest(serde_json::to_vec(&artifacts).unwrap()));
        let snapshot = IndexSnapshot {
            commit: "native-commit".into(),
            name: "Native reference".into(),
            releases: vec![ReleaseRow {
                semver: "1.0.0".into(),
                tag_oid: "native-tag".into(),
                commit_oid: "native-commit".into(),
                signer: Some("maintainer".into()),
                tagged_at: Some(1),
                pack_present: true,
            }],
            release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
                release_tag: "1.0.0".into(),
                source_commit: "native-commit".into(),
                verified_tag_oid: "native-tag".into(),
                manifest_digest,
                artifacts,
                container_release: None,
            }],
            ..IndexSnapshot::default()
        };
        db.apply_snapshot(registry, &snapshot).await.unwrap();

        let found = db
            .native_documentation_at_release(registry, "1.0.0")
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].package, "sample");

        let (db, queries) = count_queries(db);
        let locator = db
            .native_documentation_locator_by_digest(registry, &documents[0].document_sha256)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queries.load(Ordering::Relaxed), 2);
        assert_eq!(locator.release, "1.0.0");
        assert_eq!(locator.commit, "native-commit");

        queries.store(0, Ordering::Relaxed);
        assert!(db
            .native_documentation_locator_by_digest(registry, "sha256:missing")
            .await
            .unwrap()
            .is_none());
        assert_eq!(queries.load(Ordering::Relaxed), 1);

        queries.store(0, Ordering::Relaxed);
        let bounded = db
            .bounded_native_documentation_search(registry, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queries.load(Ordering::Relaxed), 2);
        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0].release, "1.0.0");
        assert!(db
            .bounded_native_documentation_search(registry, 0)
            .await
            .unwrap()
            .is_none());

        db.backend.execute("UPDATE release_native_documentation SET document_sha256 = 'wrong' WHERE registry_id = ?1",&vals![registry]).await.unwrap();
        assert!(db
            .native_documentation_at_release(registry, "1.0.0")
            .await
            .is_err());
        assert!(db
            .bounded_native_documentation_search(registry, 1)
            .await
            .is_err());
    }
}
