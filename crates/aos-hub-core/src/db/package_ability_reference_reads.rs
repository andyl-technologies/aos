//! Exact authenticated reads for generated package ability references.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use super::{Database, IndexedPackageAbilityReference};
use crate::backend::Statement;

/// Exact authenticated public ability reference selected from one registry commit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PackageAbilityReferenceLocator {
    /// Registry commit that authenticated this reference.
    pub indexed_commit: String,
    /// Package name.
    pub package_name: String,
    /// Package version.
    pub package_version: String,
    /// Platform triple.
    pub platform: String,
    /// SHA-256 of the exact ability package manifest.
    pub manifest_sha256: String,
    /// Domain-separated semantic package identity.
    pub package_digest: String,
    /// Canonical generated public reference bytes.
    pub canonical_json: Vec<u8>,
}

impl Database {
    /// Replaces one complete authenticated per-commit ability projection.
    ///
    /// An explicit catalog row records successful projection even when the
    /// commit contains no ability companions. Other commits remain immutable
    /// and available to signed release selectors.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate reference identities, an
    /// oversized canonical reference, or a database failure.
    pub(crate) async fn retain_package_ability_reference_catalog(
        &self,
        registry_id: i64,
        indexed_commit: &str,
        references: &[IndexedPackageAbilityReference],
    ) -> Result<()> {
        ensure!(
            !indexed_commit.is_empty() && indexed_commit.len() <= 64,
            "ability reference catalog has an invalid commit identity"
        );
        let mut identities = BTreeSet::new();
        let mut statements = vec![
            Statement::new(
                "DELETE FROM package_ability_reference_catalogs
                 WHERE registry_id = ?1 AND indexed_commit = ?2",
                vals![registry_id, indexed_commit].to_vec(),
            ),
            Statement::new(
                "INSERT INTO package_ability_reference_catalogs
                 (registry_id, indexed_commit) VALUES (?1, ?2)",
                vals![registry_id, indexed_commit].to_vec(),
            ),
        ];
        for reference in references {
            ensure!(
                !reference.package_name.is_empty()
                    && !reference.package_version.is_empty()
                    && !reference.platform.is_empty(),
                "ability reference catalog contains an empty selection identity"
            );
            ensure!(
                !reference.canonical_json.is_empty()
                    && reference.canonical_json.len() <= aos_doc_model::MAX_ABILITY_REFERENCE_BYTES,
                "ability reference catalog contains invalid canonical bytes"
            );
            ensure!(
                identities.insert((
                    &reference.package_name,
                    &reference.package_version,
                    &reference.platform,
                )),
                "ability reference catalog repeats a package selection"
            );
            statements.push(Statement::new(
                "INSERT INTO package_ability_references
                 (registry_id, indexed_commit, package_name, package_version, platform,
                  manifest_sha256, package_digest, canonical_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                vals![
                    registry_id,
                    indexed_commit,
                    reference.package_name,
                    reference.package_version,
                    reference.platform,
                    reference.manifest_sha256,
                    reference.package_digest,
                    reference.canonical_json,
                ]
                .to_vec(),
            ));
        }
        self.backend.batch(&statements).await?;
        Ok(())
    }

    /// Reports whether HEAD and every retained release have complete projections.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub(crate) async fn package_ability_reference_projection_complete(
        &self,
        registry_id: i64,
    ) -> Result<bool> {
        let missing = self
            .backend
            .query_opt(
                "SELECT 1 FROM releases rel
                 LEFT JOIN package_ability_reference_catalogs catalog
                   ON catalog.registry_id = rel.registry_id
                  AND catalog.indexed_commit = rel.commit_oid
                 WHERE rel.registry_id = ?1 AND catalog.indexed_commit IS NULL
                 UNION ALL
                 SELECT 1 FROM registry_index current_index
                 LEFT JOIN package_ability_reference_catalogs catalog
                   ON catalog.registry_id = current_index.registry_id
                  AND catalog.indexed_commit = current_index.last_indexed_commit
                 WHERE current_index.registry_id = ?1
                   AND current_index.last_indexed_commit IS NOT NULL
                   AND catalog.indexed_commit IS NULL
                 LIMIT 1",
                &vals![registry_id],
            )
            .await?;
        Ok(missing.is_none())
    }

    /// Resolves one current authenticated package ability reference.
    ///
    /// Empty version/platform selectors choose the newest indexed package
    /// version and first platform in stable lexical order.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed indexed bytes.
    pub async fn resolve_package_ability_reference(
        &self,
        registry_id: i64,
        package_name: &str,
        package_version: &str,
        platform: &str,
    ) -> Result<Option<PackageAbilityReferenceLocator>> {
        let row = self
            .backend
            .query_opt(
                "SELECT r.indexed_commit, r.package_version, r.platform,
                        r.manifest_sha256, r.package_digest, r.canonical_json
                 FROM package_ability_references r
                 JOIN packages p ON p.registry_id = r.registry_id
                                AND p.name = r.package_name
                 JOIN package_versions v ON v.package_id = p.id
                                        AND v.version = r.package_version
                 JOIN registry_index current_index
                   ON current_index.registry_id = r.registry_id
                  AND current_index.last_indexed_commit = r.indexed_commit
                 WHERE r.registry_id = ?1 AND r.package_name = ?2
                   AND (?3 = '' OR r.package_version = ?3)
                   AND (?4 = '' OR r.platform = ?4)
                 ORDER BY v.id DESC, r.platform
                 LIMIT 1",
                &vals![registry_id, package_name, package_version, platform],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let locator = PackageAbilityReferenceLocator {
            indexed_commit: row.get(0)?,
            package_name: package_name.to_string(),
            package_version: row.get(1)?,
            platform: row.get(2)?,
            manifest_sha256: row.get(3)?,
            package_digest: row.get(4)?,
            canonical_json: row.get(5)?,
        };
        anyhow::ensure!(
            locator.canonical_json.len() <= aos_doc_model::MAX_ABILITY_REFERENCE_BYTES,
            "indexed package ability reference exceeds its size bound"
        );
        Ok(Some(locator))
    }

    /// Resolves an authenticated package ability reference at one exact commit.
    ///
    /// Empty selectors use a stable lexical order. Release-facing callers
    /// should normally resolve package/version/platform from that release's
    /// authenticated package catalog before calling this method.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed indexed bytes.
    pub async fn resolve_package_ability_reference_at_commit(
        &self,
        registry_id: i64,
        indexed_commit: &str,
        package_name: &str,
        package_version: &str,
        platform: &str,
    ) -> Result<Option<PackageAbilityReferenceLocator>> {
        let row = self
            .backend
            .query_opt(
                "SELECT indexed_commit, package_version, platform,
                        manifest_sha256, package_digest, canonical_json
                 FROM package_ability_references reference
                 WHERE reference.registry_id = ?1
                   AND reference.indexed_commit = ?2
                   AND reference.package_name = ?3
                   AND (?4 = '' OR reference.package_version = ?4)
                   AND (?5 = '' OR reference.platform = ?5)
                   AND (
                     EXISTS (
                       SELECT 1 FROM releases release
                       WHERE release.registry_id = reference.registry_id
                         AND release.commit_oid = reference.indexed_commit
                     )
                     OR EXISTS (
                       SELECT 1 FROM registry_index current_index
                       WHERE current_index.registry_id = reference.registry_id
                         AND current_index.last_indexed_commit = reference.indexed_commit
                     )
                   )
                 ORDER BY package_version DESC, platform
                 LIMIT 1",
                &vals![
                    registry_id,
                    indexed_commit,
                    package_name,
                    package_version,
                    platform
                ],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let locator = PackageAbilityReferenceLocator {
            indexed_commit: row.get(0)?,
            package_name: package_name.to_string(),
            package_version: row.get(1)?,
            platform: row.get(2)?,
            manifest_sha256: row.get(3)?,
            package_digest: row.get(4)?,
            canonical_json: row.get(5)?,
        };
        ensure!(
            locator.canonical_json.len() <= aos_doc_model::MAX_ABILITY_REFERENCE_BYTES,
            "indexed package ability reference exceeds its size bound"
        );
        Ok(Some(locator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{IndexSnapshot, IndexedPackageAbilityReference, MIGRATIONS, ReleaseRow};

    fn package() -> aos_registry_surface::manifest::PackageToml {
        aos_registry_surface::manifest::parse_package_file(
            r#"
[package]
name = "demo"
description = "ability reference fixture"
license = "MIT"
maintainer = "AOS test"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo"
closure_size = 1
source_drv = ""
source_nar_hash = ""
"#,
        )
        .expect("parse package fixture")
    }

    #[tokio::test]
    async fn snapshots_retain_and_replace_exact_reference_bytes() {
        let db = Database::open_in_memory().await.expect("open database");
        let registry_id = db
            .register_registry("ability-reference", &[], false)
            .await
            .expect("register registry");
        let canonical_json = br#"{"schema":"aos.package-ability-reference/v1"}"#.to_vec();
        let reference = IndexedPackageAbilityReference {
            package_name: "demo".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            manifest_sha256: format!("sha256:{}", "a".repeat(64)),
            package_digest: format!("sha256:{}", "b".repeat(64)),
            canonical_json: canonical_json.clone(),
        };

        db.apply_snapshot(
            registry_id,
            &IndexSnapshot {
                commit: "c".repeat(64),
                name: "Ability reference".into(),
                packages: vec![package()],
                package_ability_references: vec![reference],
                ..Default::default()
            },
        )
        .await
        .expect("apply snapshot");

        let locator = db
            .resolve_package_ability_reference(registry_id, "demo", "", "")
            .await
            .expect("resolve reference")
            .expect("reference exists");
        assert_eq!(locator.canonical_json, canonical_json);
        assert_eq!(locator.indexed_commit, "c".repeat(64));
        assert_eq!(locator.package_version, "1.0.0");
        assert_eq!(locator.platform, "x86_64-linux");
        assert!(
            db.package_ability_reference_projection_complete(registry_id)
                .await
                .expect("check complete projection")
        );

        db.apply_snapshot(
            registry_id,
            &IndexSnapshot {
                commit: "d".repeat(64),
                name: "Ability reference".into(),
                packages: vec![package()],
                releases: vec![ReleaseRow {
                    semver: "1.0.0".into(),
                    tag_oid: "e".repeat(64),
                    commit_oid: "c".repeat(64),
                    signer: Some("maintainer".into()),
                    tagged_at: Some(1),
                    pack_present: true,
                }],
                ..Default::default()
            },
        )
        .await
        .expect("replace snapshot");
        assert!(
            db.resolve_package_ability_reference(registry_id, "demo", "", "")
                .await
                .expect("resolve removed reference")
                .is_none()
        );
        assert_eq!(
            db.resolve_package_ability_reference_at_commit(
                registry_id,
                &"c".repeat(64),
                "demo",
                "1.0.0",
                "x86_64-linux",
            )
            .await
            .expect("resolve retained commit")
            .expect("retained reference")
            .canonical_json,
            canonical_json
        );
    }

    #[tokio::test]
    async fn release_catalog_refresh_and_deletion_replace_exact_commit_rows() {
        let db = Database::open_in_memory().await.expect("open database");
        let registry_id = db
            .register_registry("ability-release-reference", &[], false)
            .await
            .expect("register registry");
        let commit = "e".repeat(64);
        let mut reference = IndexedPackageAbilityReference {
            package_name: "demo".into(),
            package_version: "1.0.0".into(),
            platform: "x86_64-linux".into(),
            manifest_sha256: format!("sha256:{}", "a".repeat(64)),
            package_digest: format!("sha256:{}", "b".repeat(64)),
            canonical_json: b"old".to_vec(),
        };
        db.retain_package_ability_reference_catalog(
            registry_id,
            &commit,
            std::slice::from_ref(&reference),
        )
        .await
        .expect("retain release catalog");
        db.backend
            .execute(
                "INSERT INTO releases
                 (registry_id, semver, tag_oid, commit_oid, signer, tagged_at, pack_present)
                 VALUES (?1, '1.0.0', ?2, ?3, 'maintainer', 1, 1)",
                &vals![registry_id, "f".repeat(64), commit],
            )
            .await
            .expect("retain release identity");

        reference.canonical_json = b"new".to_vec();
        db.retain_package_ability_reference_catalog(
            registry_id,
            &commit,
            std::slice::from_ref(&reference),
        )
        .await
        .expect("refresh release catalog");
        let refreshed = db
            .resolve_package_ability_reference_at_commit(
                registry_id,
                &commit,
                "demo",
                "1.0.0",
                "x86_64-linux",
            )
            .await
            .expect("resolve refreshed release")
            .expect("refreshed reference");
        assert_eq!(refreshed.canonical_json, b"new");

        db.backend
            .execute(
                "DELETE FROM releases WHERE registry_id = ?1 AND semver = '1.0.0'",
                &vals![registry_id],
            )
            .await
            .expect("delete release identity");
        assert!(
            db.resolve_package_ability_reference_at_commit(
                registry_id,
                &"e".repeat(64),
                "demo",
                "1.0.0",
                "x86_64-linux",
            )
            .await
            .expect("resolve deleted release")
            .is_none()
        );

        db.backend
            .execute(
                "DELETE FROM package_ability_reference_catalogs
                 WHERE registry_id = ?1 AND indexed_commit = ?2",
                &vals![registry_id, commit],
            )
            .await
            .expect("delete orphaned release catalog");
    }

    #[tokio::test]
    async fn existing_production_baseline_applies_the_forward_migration() {
        let directory = tempfile::tempdir().expect("create database directory");
        let path = directory.path().join("hub.db");
        let connection = rusqlite::Connection::open(&path).expect("open baseline database");
        connection
            .execute_batch(
                "CREATE TABLE schema_version(version INTEGER NOT NULL);
                 INSERT INTO schema_version(version) VALUES (1);",
            )
            .expect("create baseline ledger");
        connection
            .execute_batch(MIGRATIONS[0])
            .expect("create production baseline");
        drop(connection);

        let db = Database::open(&path)
            .await
            .expect("migrate baseline database");
        let version: i64 = db
            .backend
            .query_opt("SELECT version FROM schema_version", &[])
            .await
            .expect("read schema version")
            .expect("schema version exists")
            .get(0)
            .expect("decode schema version");
        let reference_table = db
            .backend
            .query_opt("SELECT COUNT(*) FROM package_ability_references", &[])
            .await
            .expect("query migrated reference table");
        let catalog_table = db
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM package_ability_reference_catalogs",
                &[],
            )
            .await
            .expect("query migrated catalog table");

        assert_eq!(version, MIGRATIONS.len() as i64);
        assert!(reference_table.is_some());
        assert!(catalog_table.is_some());

        let registry_id = db
            .register_registry("migrated-ability-reference", &[], false)
            .await
            .expect("register migrated registry");
        db.backend
            .execute(
                "UPDATE registry_index SET last_indexed_commit = ?2 WHERE registry_id = ?1",
                &vals![registry_id, "a".repeat(64)],
            )
            .await
            .expect("model pre-projection index state");
        assert!(
            !db.package_ability_reference_projection_complete(registry_id)
                .await
                .expect("detect missing post-migration projection")
        );
        db.retain_package_ability_reference_catalog(registry_id, &"a".repeat(64), &[])
            .await
            .expect("retain explicit empty projection");
        assert!(
            db.package_ability_reference_projection_complete(registry_id)
                .await
                .expect("accept explicit empty projection")
        );
    }
}
