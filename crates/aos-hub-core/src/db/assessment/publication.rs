//! Inventory activation from authenticated logical release projections.
//!
//! This module consumes exact catalogs already verified by the release indexer.
//! It reads no Git object, registry URL, source archive or physical storage key.

use anyhow::{ensure, Context as _, Result};
use aos_assessment::definition::PackageScanDefinitionV1;
use aos_assessment::input::{AssessmentPolicyV1, EvaluationData};
use aos_assessment::metadata::{published_artifact_inventory, ArtifactScanBinding};
use aos_assessment::scan_inventory::ScanInventoryV1;
use aos_contract::limits::JsonLimits;
use aos_contract::Sha256Digest;
use aos_registry_surface::manifest::PackageToml;
use std::collections::BTreeSet;

use super::{AssessmentInventoryAdmission, AssessmentResource};
use crate::backend::Statement;
use crate::db::Database;

/// Reports exact declared output coverage, including legacy metadata gaps.
#[derive(Clone, Debug)]
pub struct AssessmentPublicationRefresh {
    /// Active resource, absent when no primary output has a scan declaration.
    pub resource: Option<AssessmentResource>,
    /// Number of primary outputs with exact authenticated scan declarations.
    pub declared_outputs: u32,
    /// Number of primary outputs whose metadata cannot yet describe a scan.
    pub unsupported_outputs: u32,
}

struct AssessmentPublicationProjection {
    inventory: Option<ScanInventoryV1>,
    definitions: Vec<PackageScanDefinitionV1>,
    declared_outputs: u32,
    unsupported_outputs: u32,
    guards: Vec<crate::backend::CheckedStatement>,
}

#[derive(Debug)]
struct InvalidAssessmentPublication;

impl std::fmt::Display for InvalidAssessmentPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("authenticated assessment publication projection is invalid")
    }
}

impl std::error::Error for InvalidAssessmentPublication {}

impl Database {
    /// Refreshes a registry inventory from its newest authenticated release catalog.
    ///
    /// The latest release must have a complete verified artifact snapshot; an
    /// interrupted refresh never falls back to another release. Catalogs retain
    /// published versions and platforms. Missing declarations remain explicitly
    /// unknown; package names never become inferred vulnerability identities.
    /// Activation holds the exact tag, snapshot, catalog and registry incarnation
    /// in the same transaction that changes the active inventory.
    ///
    /// # Errors
    /// Returns an error for invalid policy, incomplete/damaged publication,
    /// missing exact artifact identities, excessive catalogs or lost admission.
    pub async fn refresh_assessment_publication(
        &self,
        registry_id: i64,
        policy: &AssessmentPolicyV1,
    ) -> Result<AssessmentPublicationRefresh> {
        policy.validate()?;
        let projection = self.project_assessment_publication(registry_id).await?;
        let Some(inventory) = projection.inventory else {
            return Ok(AssessmentPublicationRefresh {
                resource: None,
                declared_outputs: projection.declared_outputs,
                unsupported_outputs: projection.unsupported_outputs,
            });
        };
        let data = EvaluationData {
            inventory,
            definitions: projection.definitions,
            upstream: vec![],
            advisory_snapshot: None,
            advisories: vec![],
            dispositions: vec![],
            history: vec![],
            policy: policy.clone(),
        };
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("assessment publication registry is absent")?;
        let guards = projection.guards;
        let declared = projection.declared_outputs;
        let unsupported = projection.unsupported_outputs;
        let previous = self.assessment_resource(registry_id).await?;
        let publication = Sha256Digest::of_canonical(
            "aos.assessment-authenticated-artifact-inventory/v1",
            &(&registry.scope_key, data.inventory.digest()?),
        )?;
        let admission = AssessmentInventoryAdmission {
            registry_id,
            partition: registry.scope_key.clone(),
            provenance_digest: publication,
            admission_digest: Sha256Digest::of_canonical(
                "aos.assessment-publication-admission/v1",
                &(publication, data.inventory.digest()?, policy.digest()?),
            )?,
            expected_resource_version: previous
                .as_ref()
                .map_or(0, |resource| resource.resource_version),
        };
        let admission_inventory = data.inventory.digest()?;
        let resource = if let Some(previous) =
            previous.filter(|resource| resource.inventory_digest == admission_inventory)
        {
            if previous.policy_digest != policy.digest()? {
                self.set_assessment_policy_fenced(
                    registry_id,
                    &registry.scope_key,
                    previous.resource_version,
                    policy,
                    &guards,
                )
                .await?
            } else {
                let mut checked = guards.to_vec();
                checked.push(Statement::new("UPDATE assessment_resources SET updated_at = updated_at WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?3 AND inventory_digest = ?4 AND policy_digest = ?5", vals![registry_id, registry.scope_key, previous.resource_version, previous.inventory_digest.to_string(), previous.policy_digest.to_string()]).expecting(1));
                self.backend.checked_batch(&checked).await?;
                previous
            }
        } else {
            self.admit_assessment_inventory_fenced(&admission, &data, &guards)
                .await?
        };
        Ok(AssessmentPublicationRefresh {
            resource: Some(resource),
            declared_outputs: declared,
            unsupported_outputs: unsupported,
        })
    }
    /// Prepares current authenticated-publication guards for an exact inventory.
    ///
    /// This reads the newest logical release and verifies its complete retained
    /// catalog without activating a resource or contacting an upstream provider.
    /// An old inventory cannot authorize work when the newest publication is
    /// absent, damaged or lacks declarations. Callers execute these statements
    /// in the same transaction as admission, quota reservation or result commit.
    /// Historical assessments remain independently readable.
    ///
    /// # Errors
    /// Returns an error for an unavailable or changed publication, mismatched
    /// inventory/policy/incarnation, malformed custody or database failure.
    pub async fn assessment_publication_fences(
        &self,
        registry_id: i64,
        partition: &str,
        inventory_digest: Sha256Digest,
        policy_digest: Sha256Digest,
    ) -> Result<Vec<crate::backend::CheckedStatement>> {
        let resource = self
            .assessment_resource(registry_id)
            .await?
            .context("assessment publication has no admitted inventory")?;
        ensure!(
            resource.partition == partition
                && resource.inventory_digest == inventory_digest
                && resource.policy_digest == policy_digest,
            "assessment publication resource changed"
        );
        let projection = self.project_assessment_publication(registry_id).await?;
        let inventory = projection
            .inventory
            .context("latest assessment publication has no declared inventory")?;
        ensure!(
            inventory.digest()? == inventory_digest,
            "latest assessment publication superseded the requested inventory"
        );
        let mut guards = projection.guards;
        guards.push(
            Statement::new(
                "UPDATE assessment_resources SET updated_at = updated_at
             WHERE registry_id = ?1 AND partition_key = ?2 AND inventory_digest = ?3
               AND policy_digest = ?4 AND inventory_revision = ?5 AND authorization_revision = ?6",
                vals![
                    registry_id,
                    partition,
                    inventory_digest.to_string(),
                    policy_digest.to_string(),
                    resource.inventory_revision,
                    resource.authorization_revision
                ],
            )
            .expecting(1),
        );
        Ok(guards)
    }

    async fn project_assessment_publication(
        &self,
        registry_id: i64,
    ) -> Result<AssessmentPublicationProjection> {
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("assessment publication registry is absent")?;
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT rel.semver, rel.commit_oid, rel.tag_oid FROM releases rel
             WHERE rel.registry_id = ?1 ORDER BY rel.tagged_at DESC, rel.semver DESC LIMIT 1",
                &vals![@slice registry_id],
            )
            .await?
        else {
            return Ok(AssessmentPublicationProjection {
                inventory: None,
                definitions: vec![],
                guards: vec![],
                declared_outputs: 0,
                unsupported_outputs: 0,
            });
        };
        let release: String = row.get(0)?;
        let commit: String = row.get(1)?;
        let tag: String = row.get(2)?;
        let catalog = self.backend.query_opt(
            "SELECT catalog.packages_json, catalog.content_digest, snapshot.snapshot_id, snapshot.manifest_digest FROM releases rel
             JOIN release_browse_catalogs catalog ON catalog.registry_id = rel.registry_id
               AND catalog.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
               AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
               AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
               AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1 AND rel.semver = ?2 AND rel.commit_oid = ?3 AND rel.tag_oid = ?4
               AND length(catalog.packages_json) <= 16777216",
            &vals![@slice registry_id, release, commit, tag],
        ).await?.context("latest assessment publication lacks a bounded complete authenticated catalog")?;
        let bytes: String = catalog.get(0)?;
        let catalog_digest: String = catalog.get(1)?;
        let snapshot_id: String = catalog.get(2)?;
        let manifest_digest: String = catalog.get(3)?;
        let artifact_rows = self
            .backend
            .query(
                "SELECT package_name, package_version, platform, store_path FROM release_artifacts
             WHERE registry_id = ?1 AND snapshot_id = ?2 AND artifact_kind = 'output' LIMIT 10001",
                &vals![@slice registry_id, snapshot_id],
            )
            .await?;
        let validated = (|| -> Result<AssessmentPublicationProjection> {
            ensure!(
                artifact_rows.len() <= 10_000,
                "assessment snapshot exceeds its output bound"
            );
            let published: BTreeSet<(String, String, String, String)> = artifact_rows
                .iter()
                .map(|row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .collect::<Result<_>>()?;
            ensure!(
                Sha256Digest::of_bytes(bytes.as_bytes()).hex() == catalog_digest,
                "assessment publication catalog digest differs from retained bytes"
            );
            let packages: Vec<PackageToml> = JsonLimits {
                max_bytes: 16 * 1024 * 1024,
                max_depth: 32,
                max_items: 400_000,
                max_string_bytes: 262_144,
            }
            .decode(bytes.as_bytes(), "authenticated assessment catalog")?;
            ensure!(
                packages.len() <= 10_000,
                "assessment publication exceeds its package bound"
            );
            let mut bindings = Vec::new();
            let mut unsupported = 0u32;
            let mut outputs = 0u32;
            for package in packages {
                for version in package.versions {
                    for (platform, artifact) in version.platforms {
                        ensure!(
                            published.contains(&(
                                package.package.name.clone(),
                                version.version.clone(),
                                platform.clone(),
                                artifact.store_path.clone(),
                            )),
                            "assessment output is absent from its exact complete artifact snapshot"
                        );
                        outputs = outputs
                            .checked_add(1)
                            .context("assessment output count overflowed")?;
                        ensure!(
                            outputs <= 10_000,
                            "assessment publication exceeds its output bound"
                        );
                        let Some(declaration) = artifact.scan_declaration(
                            &package.package.name,
                            &version.version,
                            &platform,
                        )?
                        else {
                            unsupported += 1;
                            continue;
                        };
                        let artifact_digest = Sha256Digest::parse(&format!(
                            "sha256:{}",
                            aos_registry_surface::store::canonical_digest_hex(&artifact.nar_hash)?,
                        ))?;
                        bindings.push(ArtifactScanBinding {
                            declaration,
                            artifact_digest,
                        });
                    }
                }
            }
            // Index publication takes the same registry lock. The next statement
            // observes its committed release selection after that lock is acquired.
            let guards = vec![Statement::new(
            "UPDATE registries SET updated_at = updated_at
             WHERE id = ?1 AND scope_key = ?2
               AND EXISTS(SELECT 1 FROM authorization_scopes scope
                 WHERE scope.scope_key = ?2 AND scope.retired_at IS NULL)
               AND NOT EXISTS(SELECT 1 FROM registry_publications publication
                 WHERE publication.registry_id = ?1
                   AND publication.state IN ('preparing', 'writing_pointers'))",
            vals![registry_id, registry.scope_key],
        ).expecting(1), Statement::new(
            "UPDATE release_browse_catalogs SET package_count = package_count
             WHERE registry_id = ?1 AND source_commit = ?2 AND content_digest = ?3",
            vals![registry_id, commit, catalog_digest],
        ).expecting(1), Statement::new(
            "UPDATE releases SET pack_present = pack_present
             WHERE registry_id = ?1 AND semver = ?2 AND commit_oid = ?3 AND tag_oid = ?4
               AND id = (SELECT newest.id FROM (SELECT id FROM releases
                 WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC LIMIT 1) newest)
               AND EXISTS(SELECT 1 FROM registries registry JOIN authorization_scopes scope
                 ON scope.scope_key = registry.scope_key WHERE registry.id = ?1 AND registry.scope_key = ?5
                   AND scope.retired_at IS NULL)
               AND EXISTS(SELECT 1 FROM release_browse_catalogs catalog WHERE catalog.registry_id = ?1
                 AND catalog.source_commit = ?3 AND catalog.content_digest = ?6)
               AND EXISTS(SELECT 1 FROM release_artifact_snapshot_heads head
                 JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                 WHERE head.registry_id = ?1 AND head.release_id = releases.id
                   AND snapshot.registry_id = ?1 AND snapshot.release_id = releases.id
                   AND snapshot.source_commit = ?3 AND snapshot.verified_tag_oid = ?4 AND snapshot.state = 'complete'
                   AND snapshot.snapshot_id = ?7 AND snapshot.manifest_digest = ?8)",
            vals![registry_id, release, commit, tag, registry.scope_key, catalog_digest, snapshot_id, manifest_digest],
        ).expecting(1)];
            if bindings.is_empty() {
                return Ok(AssessmentPublicationProjection {
                    inventory: None,
                    definitions: vec![],
                    guards,
                    declared_outputs: 0,
                    unsupported_outputs: unsupported,
                });
            }
            let declared = bindings.len() as u32;
            let (mut inventory, definitions) =
                published_artifact_inventory(&bindings, &registry.scope_key)?;
            if unsupported > 0 {
                inventory.coverage.basis = format!(
                "Declared components do not prove binary composition; {unsupported} published primary outputs lack scan metadata"
            );
            }
            Ok(AssessmentPublicationProjection {
                inventory: Some(inventory),
                definitions,
                declared_outputs: declared,
                unsupported_outputs: unsupported,
                guards,
            })
        })();
        validated.map_err(|error| error.context(InvalidAssessmentPublication))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::{IndexSnapshot, ReleaseArtifactSnapshot, ReleaseRow, ReleaseSnapshotArtifact};
    use aos_assessment::identity::MemberId;
    use aos_assessment::metadata::{PackageScanPublicationV1, PACKAGE_SCAN_PUBLICATION_V1};

    async fn publication_fixture(declared: bool) -> Result<(Database, i64, AssessmentPolicyV1)> {
        publication_fixture_database(Database::open_in_memory().await?, declared).await
    }

    async fn publication_fixture_database(
        db: Database,
        declared: bool,
    ) -> Result<(Database, i64, AssessmentPolicyV1)> {
        let registry = db
            .register_registry(
                &format!("assessment-publication-{}", uuid::Uuid::new_v4()),
                &[],
                false,
            )
            .await?;
        let data = super::super::scans_tests::fixture()?;
        let declaration = PackageScanPublicationV1 {
            schema: PACKAGE_SCAN_PUBLICATION_V1.into(),
            package_name: "fixture".into(),
            version: "1.2.0".into(),
            platform: "x86_64-linux".into(),
            member_id: MemberId::parse("fixture")?,
            definitions: data.definitions,
        };
        let store_path = format!("/nix/store/{}-fixture-1.2.0", "a".repeat(32));
        let mut package: PackageToml = serde_json::from_value(serde_json::json!({
            "package": {"name": "fixture", "description": "Signed scan fixture", "license": "MIT", "maintainer": "fixture"},
            "versions": [{"version": "1.2.0", "platforms": {"x86_64-linux": {
                "store_path": store_path, "nar_hash": format!("sha256:{}", "c".repeat(64)),
                "closure_size": 16, "source_drv": "", "source_nar_hash": ""
            }}}]
        }))?;
        if declared {
            package.versions[0]
                .platforms
                .get_mut("x86_64-linux")
                .context("fixture platform")?
                .scan = Some(String::from_utf8(aos_contract::canonical::to_vec(
                &declaration,
            )?)?);
        }
        db.retain_release_browse_catalog(registry, "fixture-commit", &[package], None)
            .await?;
        let artifacts = vec![ReleaseSnapshotArtifact {
            package_name: "fixture".into(),
            package_version: "1.2.0".into(),
            platform: "x86_64-linux".into(),
            artifact_kind: "output".into(),
            store_path,
            store_hash: "a".repeat(32),
        }];
        db.apply_snapshot(
            registry,
            &IndexSnapshot {
                commit: "fixture-commit".into(),
                name: "Assessment fixture".into(),
                releases: vec![ReleaseRow {
                    semver: "1.0.0".into(),
                    commit_oid: "fixture-commit".into(),
                    tag_oid: "fixture-signed-tag".into(),
                    signer: Some("fixture-publisher".into()),
                    tagged_at: Some(1),
                    pack_present: true,
                }],
                release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
                    release_tag: "1.0.0".into(),
                    source_commit: "fixture-commit".into(),
                    verified_tag_oid: "fixture-signed-tag".into(),
                    manifest_digest: Sha256Digest::of_bytes(serde_json::to_vec(&artifacts)?).hex(),
                    artifacts,
                    container_release: None,
                }],
                ..IndexSnapshot::default()
            },
        )
        .await?;
        Ok((db, registry, data.policy))
    }

    #[tokio::test]
    async fn authenticated_artifact_projection_activates_exactly_and_replays_without_revision_changes(
    ) -> Result<()> {
        let (db, registry, policy) = publication_fixture(true).await?;
        let result = db.refresh_assessment_publication(registry, &policy).await?;
        assert_eq!(result.declared_outputs, 1);
        assert_eq!(result.unsupported_outputs, 0);
        let resource = result.resource.context("activated artifact inventory")?;
        let replay = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("replayed inventory")?;
        assert_eq!(replay, resource);
        let partition = db
            .registry_by_id(registry)
            .await?
            .context("fixture registry")?
            .scope_key;
        assert_eq!(
            db.assessment_registry_for_partition(&partition).await?,
            Some(registry)
        );
        assert!(db
            .assessment_registry_for_partition("other-partition")
            .await?
            .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn catalog_tampering_and_missing_snapshot_membership_cannot_activate_inventory(
    ) -> Result<()> {
        for corrupt_catalog in [true, false] {
            let (db, registry, policy) = publication_fixture(true).await?;
            if corrupt_catalog {
                db.backend.execute("UPDATE release_browse_catalogs SET packages_json = '[]' WHERE registry_id = ?1",
                    &vals![@slice registry]).await?;
            } else {
                db.backend
                    .execute(
                        "DELETE FROM release_artifacts WHERE registry_id = ?1",
                        &vals![@slice registry],
                    )
                    .await?;
            }
            assert!(db
                .refresh_assessment_publication(registry, &policy)
                .await
                .is_err());
            assert!(db.assessment_resource(registry).await?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn legacy_outputs_remain_unassessed_without_invented_package_identities() -> Result<()> {
        let (db, registry, policy) = publication_fixture(false).await?;
        let result = db.refresh_assessment_publication(registry, &policy).await?;
        assert_eq!(result.declared_outputs, 0);
        assert_eq!(result.unsupported_outputs, 1);
        assert!(result.resource.is_none());
        assert!(db.assessment_resource(registry).await?.is_none());
        Ok(())
    }
    #[tokio::test]
    async fn installed_policy_changes_reuse_inventory_without_rewriting_immutable_admission(
    ) -> Result<()> {
        let (db, registry, mut policy) = publication_fixture(true).await?;
        let first = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("first inventory")?;
        policy.upstream_max_age_seconds /= 2;
        let changed = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("changed policy")?;
        assert_eq!(first.inventory_digest, changed.inventory_digest);
        assert_eq!(first.inventory_revision, changed.inventory_revision);
        assert_ne!(first.policy_digest, changed.policy_digest);
        assert_eq!(changed.policy_digest, policy.digest()?);
        let replay = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("replayed policy")?;
        assert_eq!(changed.resource_version, replay.resource_version);
        Ok(())
    }

    async fn qualify_publication_currentness(db: Database) -> Result<()> {
        let (db, registry, policy) = publication_fixture_database(db, true).await?;
        let resource = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("current fixture inventory")?;
        let guards = db
            .assessment_publication_fences(
                registry,
                &resource.partition,
                resource.inventory_digest,
                resource.policy_digest,
            )
            .await?;
        db.backend.checked_batch(&guards).await?;
        assert_eq!(
            db.assessment_resource(registry).await?,
            Some(resource.clone())
        );

        // A valid authenticated catalog can lose all declarations. It must not
        // borrow the old resource's authority, and its immutable history stays.
        let row = db
            .backend
            .query_opt(
                "SELECT packages_json FROM release_browse_catalogs WHERE registry_id = ?1",
                &vals![@slice registry],
            )
            .await?
            .context("fixture catalog")?;
        let original: Vec<PackageToml> = serde_json::from_str(&row.get::<String>(0)?)?;
        let mut legacy = original.clone();
        for package in &mut legacy {
            for version in &mut package.versions {
                for artifact in version.platforms.values_mut() {
                    artifact.scan = None;
                }
            }
        }
        db.retain_release_browse_catalog(registry, "fixture-commit", &legacy, None)
            .await?;
        let unassessable = db.refresh_assessment_publication(registry, &policy).await?;
        assert!(unassessable.resource.is_none());
        assert_eq!(unassessable.unsupported_outputs, 1);
        assert!(db
            .assessment_publication_fences(
                registry,
                &resource.partition,
                resource.inventory_digest,
                resource.policy_digest,
            )
            .await
            .is_err());
        let mut checked = vec![Statement::new(
            "UPDATE assessment_resources SET next_generation = next_generation + 1 WHERE registry_id = ?1",
            vals![registry],
        ).expecting(1)];
        checked.extend(guards);
        assert!(db.backend.checked_batch(&checked).await.is_err());
        assert_eq!(
            db.assessment_resource(registry).await?,
            Some(resource.clone())
        );

        db.retain_release_browse_catalog(registry, "fixture-commit", &original, None)
            .await?;
        let guards = db
            .assessment_publication_fences(
                registry,
                &resource.partition,
                resource.inventory_digest,
                resource.policy_digest,
            )
            .await?;
        // A new release without its complete snapshot must fence a previously
        // prepared proof before any inventory activation or generation effect.
        db.backend
            .execute_insert(
                "INSERT INTO releases(registry_id, semver, tag_oid, commit_oid, tagged_at)
             VALUES (?1, '2.0.0', 'new-fixture-tag', 'new-fixture-commit', 2)",
                &vals![@slice registry],
            )
            .await?;
        assert!(db.backend.checked_batch(&guards).await.is_err());
        assert!(db
            .refresh_assessment_publication(registry, &policy)
            .await
            .is_err());
        assert!(db
            .assessment_publication_fences(
                registry,
                &resource.partition,
                resource.inventory_digest,
                resource.policy_digest,
            )
            .await
            .is_err());
        assert_eq!(
            db.assessment_resource(registry).await?,
            Some(resource.clone())
        );
        let retained = db.backend.query_opt(
            "SELECT count(*) FROM assessment_subjects WHERE registry_id = ?1 AND inventory_digest = ?2",
            &vals![@slice registry, resource.inventory_digest.to_string()],
        ).await?.context("retained subject history")?;
        assert_eq!(retained.get::<u64>(0)?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn publication_replacement_fences_effects_without_erasing_retained_inventory(
    ) -> Result<()> {
        qualify_publication_currentness(Database::open_in_memory().await?).await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
    async fn publication_replacement_is_fenced_on_postgresql() -> Result<()> {
        let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
            .context("disposable PostgreSQL URL file required")?;
        let url = std::fs::read_to_string(path)?;
        let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
        qualify_publication_currentness(Database::with_backend(Box::new(backend)).await?).await
    }

    async fn qualify_inventory_reactivation(db: Database) -> Result<()> {
        use aos_assessment::input::{FreshnessMode, Profile};
        use aos_assessment_runtime::scan::{ScanLimits, ScanRequestV1, SCAN_REQUEST_V1};

        let (db, registry, mut policy) = publication_fixture_database(db, true).await?;
        let first = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("first publication inventory")?;
        let retained = db.backend.query_opt(
            "SELECT provenance_digest, admission_digest, evaluation_base_digest, inventory_revision
             FROM assessment_inventory_sets WHERE registry_id = ?1 AND inventory_digest = ?2",
            &vals![@slice registry, first.inventory_digest.to_string()],
        ).await?.context("first immutable admission")?;
        let original_admission: (String, String, String, u64) = (
            retained.get(0)?,
            retained.get(1)?,
            retained.get(2)?,
            retained.get(3)?,
        );
        let subject = db
            .assessment_status_page(registry, &[Profile::Updates], "", 100)
            .await?
            .subjects[0]
            .subject_ref
            .clone();
        let scan = db
            .request_assessment_scan(
                registry,
                &ScanRequestV1 {
                    schema: SCAN_REQUEST_V1.into(),
                    resource_scope: first.partition.clone(),
                    authorization_partition: first.partition.clone(),
                    inventory_revision: first.inventory_revision,
                    inventory_digest: first.inventory_digest,
                    policy_digest: first.policy_digest,
                    subjects: vec![subject],
                    profiles: vec![Profile::Updates],
                    freshness: FreshnessMode::Offline,
                    trigger: "manual".into(),
                    actor_ref: "fixture-authenticated-actor".into(),
                    idempotency_key: "before-reactivation".into(),
                    limits: ScanLimits::default(),
                },
            )
            .await?;
        let old_claim = db
            .claim_assessment_scan(registry, &scan.scan_id, 60)
            .await?;

        let row = db
            .backend
            .query_opt(
                "SELECT packages_json FROM release_browse_catalogs WHERE registry_id = ?1",
                &vals![@slice registry],
            )
            .await?
            .context("publication catalog")?;
        let original: Vec<PackageToml> = serde_json::from_str(&row.get::<String>(0)?)?;
        let mut replacement = original.clone();
        replacement[0].versions[0]
            .platforms
            .get_mut("x86_64-linux")
            .context("replacement fixture platform")?
            .nar_hash = format!("sha256:{}", "d".repeat(64));
        db.retain_release_browse_catalog(registry, "fixture-commit", &replacement, None)
            .await?;
        let second = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("replacement inventory")?;
        assert_ne!(second.inventory_digest, first.inventory_digest);
        assert_eq!(second.inventory_revision, first.inventory_revision + 1);
        assert!(db
            .check_assessment_scan_claim(registry, &old_claim)
            .await
            .is_err());

        // Reintroduce the exact old artifact closure under a new installed policy.
        // Its first admission remains immutable and old leases never revive.
        policy.upstream_max_age_seconds /= 2;
        db.retain_release_browse_catalog(registry, "fixture-commit", &original, None)
            .await?;
        let third = db
            .refresh_assessment_publication(registry, &policy)
            .await?
            .resource
            .context("reactivated inventory")?;
        assert_eq!(third.inventory_digest, first.inventory_digest);
        assert_eq!(third.policy_digest, policy.digest()?);
        assert_eq!(third.inventory_revision, second.inventory_revision + 1);
        assert_eq!(third.next_generation, second.next_generation);
        assert!(db
            .check_assessment_scan_claim(registry, &old_claim)
            .await
            .is_err());
        let retained = db.backend.query_opt(
            "SELECT provenance_digest, admission_digest, evaluation_base_digest, inventory_revision
             FROM assessment_inventory_sets WHERE registry_id = ?1 AND inventory_digest = ?2",
            &vals![@slice registry, first.inventory_digest.to_string()],
        ).await?.context("retained immutable first admission")?;
        assert_eq!(
            (
                retained.get::<String>(0)?,
                retained.get::<String>(1)?,
                retained.get::<String>(2)?,
                retained.get::<u64>(3)?
            ),
            original_admission
        );
        assert_eq!(
            db.refresh_assessment_publication(registry, &policy)
                .await?
                .resource,
            Some(third)
        );
        Ok(())
    }

    #[tokio::test]
    async fn inventory_reactivation_keeps_first_admission_and_monotonic_fences() -> Result<()> {
        qualify_inventory_reactivation(Database::open_in_memory().await?).await
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
    async fn inventory_reactivation_keeps_first_admission_on_postgresql() -> Result<()> {
        let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
            .context("disposable PostgreSQL URL file required")?;
        let url = std::fs::read_to_string(path)?;
        let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
        qualify_inventory_reactivation(Database::with_backend(Box::new(backend)).await?).await
    }
}
