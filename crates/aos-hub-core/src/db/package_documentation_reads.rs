//! Exact release-scoped documentation references used by package browse pages.
//!
//! These reads use completed signed release snapshots and validate the retained
//! locator digest, without reading the Nix object that contains documentation.

use super::*;

impl Database {
    /// Resolves an exact package/version/platform documentation reference in a release.
    ///
    /// A release tag or commit selects its current complete authenticated snapshot.
    /// Missing historical references never fall back to the live catalog.
    ///
    /// # Errors
    /// Returns an error on database failure or inconsistent retained metadata.
    pub async fn package_documentation_locator_at_release(
        &self,
        registry_id: i64,
        release_or_commit: &str,
        package_name: &str,
        package_version: &str,
        platform: &str,
    ) -> Result<Option<PackageDocumentationLocator>> {
        let row = self
            .backend
            .query_opt(
                "SELECT ras.source_commit, documentation.package_name,
                        documentation.package_version, documentation.platform,
                        documentation.format, documentation.store_path,
                        documentation.nar_hash, documentation.nar_size,
                        documentation.document_size,
                        documentation.semantic_schema_sha256,
                        documentation.system_module_nar_hash, rel.semver,
                        ras.verified_tag_oid, ras.snapshot_id,
                        documentation.metadata_digest, documentation.document_sha256
                 FROM release_package_documentation documentation
                 JOIN release_artifacts artifact
                   ON artifact.snapshot_id = documentation.snapshot_id
                  AND artifact.release_id = documentation.release_id
                  AND artifact.registry_id = documentation.registry_id
                  AND artifact.package_name = documentation.package_name
                  AND artifact.package_version = documentation.package_version
                  AND artifact.platform = documentation.platform
                  AND artifact.artifact_kind = 'documentation'
                  AND artifact.store_path = documentation.store_path
                  AND artifact.store_hash = documentation.store_hash
                 JOIN release_artifact_snapshots ras
                   ON ras.snapshot_id = documentation.snapshot_id
                  AND ras.release_id = documentation.release_id
                  AND ras.registry_id = documentation.registry_id
                  AND ras.state = 'complete'
                 JOIN release_artifact_snapshot_heads head
                   ON head.complete_artifact_snapshot_id = ras.snapshot_id
                  AND head.release_id = ras.release_id
                  AND head.registry_id = ras.registry_id
                 JOIN releases rel
                   ON rel.id = ras.release_id AND rel.registry_id = ras.registry_id
                  AND rel.commit_oid = ras.source_commit
                  AND rel.tag_oid = ras.verified_tag_oid
                 WHERE documentation.registry_id = ?1
                   AND (rel.semver = ?2 OR rel.commit_oid = ?2)
                   AND documentation.package_name = ?3
                   AND documentation.package_version = ?4
                   AND documentation.platform = ?5
                 ORDER BY rel.tagged_at DESC, rel.semver DESC,
                          documentation.package_name,
                          documentation.package_version, documentation.platform
                 LIMIT 1",
                &vals![
                    registry_id,
                    release_or_commit,
                    package_name,
                    package_version,
                    platform
                ],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let document_sha256: String = row.get(15)?;
        let package_name: String = row.get(1)?;
        let package_version: String = row.get(2)?;
        let platform: String = row.get(3)?;
        let artifact = aos_registry_surface::manifest::DocumentationArtifactMeta {
            format: row.get(4)?,
            store_path: row.get(5)?,
            nar_hash: row.get(6)?,
            nar_size: row.get(7)?,
            document_sha256: document_sha256.to_string(),
            document_size: row.get(8)?,
            semantic_schema_sha256: row.get(9)?,
            system_module_nar_hash: row.get(10)?,
            references: Vec::new(),
        };
        let projection = ReleasePackageDocumentation {
            package_name: package_name.clone(),
            package_version: package_version.clone(),
            platform: platform.clone(),
            artifact: artifact.clone(),
        };
        let expected_digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&projection)?));
        let stored_digest: String = row.get(14)?;
        if stored_digest != expected_digest {
            bail!("release documentation metadata digest does not match its locator");
        }
        Ok(Some(PackageDocumentationLocator {
            indexed_commit: row.get(0)?,
            package_name,
            package_version,
            platform,
            artifact,
            release: Some(row.get(11)?),
            verified_tag_oid: Some(row.get(12)?),
            release_snapshot_id: Some(row.get(13)?),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn release_documentation_reference_retains_signed_digest_after_reindex() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("release-docs", "Release docs").await.unwrap();
        let registry = db
            .create_managed_registry(org, "", "main", "public", &[], false)
            .await
            .unwrap();
        let artifact = aos_registry_surface::manifest::DocumentationArtifactMeta {
            format: aos_doc_model::DOCUMENT_FORMAT.into(),
            store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-package-docs".into(),
            nar_hash: format!("sha256-{}", "A".repeat(43)),
            nar_size: 4096,
            document_sha256: "b".repeat(64),
            document_size: 2048,
            semantic_schema_sha256: "c".repeat(64),
            system_module_nar_hash: None,
            references: Vec::new(),
        };
        let documentation = ReleasePackageDocumentation {
            package_name: "package-docs".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            artifact: artifact.clone(),
        };
        let artifacts = vec![ReleaseSnapshotArtifact {
            package_name: documentation.package_name.clone(),
            package_version: documentation.package_version.clone(),
            platform: documentation.platform.clone(),
            artifact_kind: "documentation".into(),
            store_path: artifact.store_path.clone(),
            store_hash: "a".repeat(32),
        }];
        let mut snapshot = IndexSnapshot {
            commit: "c".repeat(64),
            name: "Release docs".into(),
            description: None,
            readme: None,
            caches: Vec::new(),
            roster: Vec::new(),
            packages: Vec::new(),
            package_documentation: vec![IndexedPackageDocumentation {
                options: Vec::new(),
                package_name: documentation.package_name.clone(),
                package_version: documentation.package_version.clone(),
                platform: documentation.platform.clone(),
                artifact: artifact.clone(),
                search: Vec::new(),
            }],
            releases: vec![ReleaseRow {
                semver: "1.0.0".into(),
                tag_oid: "a".repeat(64),
                commit_oid: "c".repeat(64),
                signer: None,
                tagged_at: Some(1),
                pack_present: true,
            }],
            release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
                release_tag: "1.0.0".into(),
                source_commit: "c".repeat(64),
                verified_tag_oid: "a".repeat(64),
                manifest_digest: hex::encode(sha2::Sha256::digest(
                    serde_json::to_vec(&artifacts).unwrap(),
                )),
                artifacts,
                container_release: None,
                documentation: vec![documentation],
            }],
            release_images: Vec::new(),
            channels: Vec::new(),
            refs_digest: Some("d".repeat(64)),
            cache_stack: None,
        };
        db.apply_snapshot(registry, &snapshot).await.unwrap();
        // A newer signed catalog changes the document without changing package
        // version/platform; historical browsing must retain the old identity.
        snapshot.commit = "e".repeat(64);
        snapshot.package_documentation[0].artifact.document_sha256 = "f".repeat(64);
        db.apply_snapshot(registry, &snapshot).await.unwrap();
        assert_eq!(
            db.documentation_releases_for_package(
                registry,
                "package-docs",
                "1.0.0",
                "x86_64-linux"
            )
            .await
            .unwrap(),
            vec!["1.0.0"]
        );
        assert!(db
            .documentation_releases_for_package(registry, "package-docs", "1.0.0", "aarch64-linux")
            .await
            .unwrap()
            .is_empty());
        let current = db
            .package_documentation_locator(registry, "package-docs", "1.0.0", "x86_64-linux")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.artifact.document_sha256, "f".repeat(64));
        for release in ["1.0.0".to_string(), "c".repeat(64)] {
            let historical = db
                .package_documentation_locator_at_release(
                    registry,
                    &release,
                    "package-docs",
                    "1.0.0",
                    "x86_64-linux",
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(historical.artifact.document_sha256, "b".repeat(64));
            assert_eq!(historical.release.as_deref(), Some("1.0.0"));
            assert_eq!(historical.verified_tag_oid, Some("a".repeat(64)));
            assert_eq!(historical.indexed_commit, "c".repeat(64));
        }
        for (release, version, platform) in [
            ("missing", "1.0.0", "x86_64-linux"),
            ("1.0.0", "2.0.0", "x86_64-linux"),
            ("1.0.0", "1.0.0", "aarch64-linux"),
        ] {
            assert!(db
                .package_documentation_locator_at_release(
                    registry,
                    release,
                    "package-docs",
                    version,
                    platform
                )
                .await
                .unwrap()
                .is_none());
        }
        let other = db
            .create_managed_registry(org, "", "other", "public", &[], false)
            .await
            .unwrap();
        assert!(db
            .package_documentation_locator_at_release(
                other,
                "1.0.0",
                "package-docs",
                "1.0.0",
                "x86_64-linux"
            )
            .await
            .unwrap()
            .is_none());
        db.backend.execute("UPDATE release_package_documentation SET metadata_digest = 'corrupt' WHERE registry_id = ?1", &vals![registry]).await.unwrap();
        assert!(db
            .package_documentation_locator_at_release(
                registry,
                "1.0.0",
                "package-docs",
                "1.0.0",
                "x86_64-linux"
            )
            .await
            .is_err());
    }
}
