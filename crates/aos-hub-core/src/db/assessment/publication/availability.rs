//! Bounded publication availability over current authenticated database projections.
//!
//! Missing metadata never borrows an old active inventory. Unknown outputs use
//! exact publication coordinates, with no inferred vulnerability identity.

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

use anyhow::{ensure, Context as _, Result};
use aos_assessment_runtime::publication::{
    PublicationAvailability, PublicationCommitment, PublicationContextChanged, PublicationQueryV1,
    PublicationRelease, PublicationStatusV1, UnsupportedPublicationOutput,
};
use aos_contract::{limits::JsonLimits, Sha256Digest};
use aos_registry_surface::manifest::PackageToml;

use crate::backend::{CheckedStatement, Statement};
use crate::db::Database;

use super::InvalidAssessmentPublication;

const CATALOG_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 32,
    max_items: 400_000,
    max_string_bytes: 262_144,
};

impl Database {
    /// Reads exact publication availability without acquisition or activation.
    ///
    /// All output pages bind the current publication commitment and registry
    /// incarnation. Changes reject continuation rather than combining releases.
    /// Declared inventory availability makes no claim about scan results.
    ///
    /// # Errors
    /// Returns an error for invalid selection, changed publication context,
    /// malformed commitments, unavailable persistence or response limits.
    pub async fn assessment_publication_status(
        &self,
        registry_id: i64,
        query: &PublicationQueryV1,
    ) -> Result<PublicationStatusV1> {
        PublicationQueryV1::from_slice(&serde_json::to_vec(query)?)?;
        let registry = self
            .registry_by_id(registry_id)
            .await?
            .context("assessment publication registry is absent")?;
        if query
            .resource_scope
            .as_ref()
            .is_some_and(|scope| scope != &registry.scope_key)
        {
            return Err(anyhow::anyhow!(PublicationContextChanged));
        }
        let mut guards = vec![publication_registry_guard(registry_id, &registry.scope_key)];
        let release = self
            .backend
            .query_opt(
                "SELECT semver, commit_oid, tag_oid FROM releases WHERE registry_id = ?1
                 ORDER BY tagged_at DESC, semver DESC LIMIT 1",
                &vals![@slice registry_id],
            )
            .await?;
        let mut outputs = Vec::new();
        let availability = if let Some(row) = release {
            let release = PublicationRelease {
                release: row.get(0)?,
                source_commit: row.get(1)?,
                verified_tag_oid: row.get(2)?,
            };
            self.publication_release_availability(
                registry_id,
                &registry.scope_key,
                release,
                &mut guards,
                &mut outputs,
            )
            .await?
        } else {
            guards.push(
                Statement::new(
                    "UPDATE registries SET updated_at = updated_at WHERE id = ?1 AND scope_key = ?2
                     AND NOT EXISTS(SELECT 1 FROM releases WHERE registry_id = ?1)",
                    vals![registry_id, registry.scope_key],
                )
                .expecting(1),
            );
            PublicationAvailability::NoPublication
        };
        let publication_digest = match &availability {
            PublicationAvailability::Ready { publication, .. }
            | PublicationAvailability::Unassessable { publication, .. } => {
                Some(publication.digest(&registry.scope_key)?)
            }
            _ => None,
        };
        if query.publication_digest.is_some() && query.publication_digest != publication_digest {
            return Err(anyhow::anyhow!(PublicationContextChanged));
        }
        outputs.sort_by_key(|output| output.output_ref);
        let mut page = outputs.into_iter().filter(|output| {
            query
                .after_output
                .is_none_or(|after| output.output_ref > after)
        });
        let unsupported_outputs: Vec<_> = page.by_ref().take(query.limit as usize).collect();
        let next_output = if page.next().is_some() {
            unsupported_outputs.last().map(|output| output.output_ref)
        } else {
            None
        };
        self.backend.checked_batch(&guards).await?;
        let status = PublicationStatusV1 {
            schema: "aos.assessment-publication-status/v1".into(),
            resource_scope: registry.scope_key,
            as_of: self.assessment_database_time().await?,
            availability,
            publication_digest,
            unsupported_outputs,
            next_output,
        };
        status.validate_for(query)?;
        status.to_bytes()?;
        Ok(status)
    }

    async fn publication_release_availability(
        &self,
        registry_id: i64,
        scope: &str,
        release: PublicationRelease,
        guards: &mut Vec<CheckedStatement>,
        outputs: &mut Vec<UnsupportedPublicationOutput>,
    ) -> Result<PublicationAvailability> {
        guards.push(publication_release_guard(registry_id, &release));
        let catalog = self.backend.query_opt(
            "SELECT catalog.packages_json, catalog.content_digest, snapshot.snapshot_id, snapshot.manifest_digest
             FROM releases rel JOIN release_browse_catalogs catalog
               ON catalog.registry_id = rel.registry_id AND catalog.source_commit = rel.commit_oid
             JOIN release_artifact_snapshot_heads head
               ON head.registry_id = rel.registry_id AND head.release_id = rel.id
             JOIN release_artifact_snapshots snapshot ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
               AND snapshot.registry_id = rel.registry_id AND snapshot.release_id = rel.id
               AND snapshot.source_commit = rel.commit_oid AND snapshot.verified_tag_oid = rel.tag_oid
               AND snapshot.state = 'complete'
             WHERE rel.registry_id = ?1 AND rel.semver = ?2 AND rel.commit_oid = ?3 AND rel.tag_oid = ?4
               AND length(catalog.packages_json) <= 16777216",
            &vals![@slice registry_id, release.release, release.source_commit, release.verified_tag_oid],
        ).await?;
        if let Some(row) = catalog {
            return self
                .publication_catalog_availability(registry_id, scope, release, row, guards, outputs)
                .await;
        }
        guards.push(
            Statement::new(
                "UPDATE releases SET pack_present = pack_present
                 WHERE registry_id = ?1 AND semver = ?2 AND commit_oid = ?3 AND tag_oid = ?4
                   AND NOT EXISTS(SELECT 1 FROM release_browse_catalogs catalog
                     JOIN release_artifact_snapshot_heads head
                       ON head.registry_id = ?1 AND head.release_id = releases.id
                     JOIN release_artifact_snapshots snapshot
                       ON snapshot.snapshot_id = head.complete_artifact_snapshot_id
                       AND snapshot.registry_id = ?1 AND snapshot.release_id = releases.id
                       AND snapshot.source_commit = ?3 AND snapshot.verified_tag_oid = ?4
                       AND snapshot.state = 'complete'
                     WHERE catalog.registry_id = ?1 AND catalog.source_commit = ?3
                       AND length(catalog.packages_json) <= 16777216)",
                vals![
                    registry_id,
                    release.release,
                    release.source_commit,
                    release.verified_tag_oid
                ],
            )
            .expecting(1),
        );
        Ok(PublicationAvailability::AwaitingProjection { release })
    }

    async fn publication_catalog_availability(
        &self,
        registry_id: i64,
        scope: &str,
        release: PublicationRelease,
        row: crate::value::Row,
        guards: &mut Vec<CheckedStatement>,
        outputs: &mut Vec<UnsupportedPublicationOutput>,
    ) -> Result<PublicationAvailability> {
        let bytes: String = row.get(0)?;
        let catalog_digest: String = row.get(1)?;
        let publication = PublicationCommitment {
            release: release.clone(),
            catalog_digest: Sha256Digest::parse(&format!("sha256:{catalog_digest}"))?,
            snapshot_id: row.get(2)?,
            manifest_digest: Sha256Digest::parse(&format!("sha256:{}", row.get::<String>(3)?))?,
        };
        guards.push(
            Statement::new(
                "UPDATE release_browse_catalogs SET package_count = package_count
                 WHERE registry_id = ?1 AND source_commit = ?2 AND content_digest = ?3",
                vals![registry_id, release.source_commit, catalog_digest],
            )
            .expecting(1),
        );
        let projection = if Sha256Digest::of_bytes(bytes.as_bytes()) == publication.catalog_digest {
            self.project_assessment_publication(registry_id).await
        } else {
            Err(anyhow::anyhow!(InvalidAssessmentPublication))
        };
        let projection = match projection {
            Ok(projection) => projection,
            Err(error)
                if error
                    .downcast_ref::<InvalidAssessmentPublication>()
                    .is_some() =>
            {
                return Ok(PublicationAvailability::InvalidProjection { release });
            }
            Err(error) => return Err(error),
        };
        guards.extend(projection.guards);
        let digest = publication.digest(scope)?;
        let packages: Vec<PackageToml> =
            CATALOG_LIMITS.decode(bytes.as_bytes(), "assessment publication catalog")?;
        for package in packages {
            for version in package.versions {
                for (platform, artifact) in version.platforms {
                    if artifact
                        .scan_declaration(&package.package.name, &version.version, &platform)?
                        .is_none()
                    {
                        outputs.push(UnsupportedPublicationOutput {
                            output_ref: UnsupportedPublicationOutput::reference(
                                digest,
                                &package.package.name,
                                &version.version,
                                &platform,
                                &artifact.store_path,
                            )?,
                            package_name: package.package.name.clone(),
                            version: version.version.clone(),
                            platform,
                            store_path: artifact.store_path,
                        });
                    }
                }
            }
        }
        ensure!(
            outputs.len() == projection.unsupported_outputs as usize,
            "assessment publication changed during output projection"
        );
        Ok(if let Some(inventory) = projection.inventory {
            let inventory_digest = inventory.digest()?;
            let active = self.assessment_resource(registry_id).await?;
            let active_inventory_revision = active
                .as_ref()
                .filter(|resource| {
                    resource.partition == scope && resource.inventory_digest == inventory_digest
                })
                .map(|resource| resource.inventory_revision);
            if let Some(active) = active {
                guards.push(
                    Statement::new(
                        "UPDATE assessment_resources SET updated_at = updated_at
                         WHERE registry_id = ?1 AND partition_key = ?2 AND resource_version = ?3",
                        vals![registry_id, scope, active.resource_version],
                    )
                    .expecting(1),
                );
            }
            PublicationAvailability::Ready {
                publication,
                inventory_digest,
                declared_outputs: projection.declared_outputs,
                unsupported_count: projection.unsupported_outputs,
                active_inventory_revision,
            }
        } else {
            PublicationAvailability::Unassessable {
                publication,
                unsupported_count: projection.unsupported_outputs,
            }
        })
    }
}

fn publication_registry_guard(registry_id: i64, scope: &str) -> CheckedStatement {
    Statement::new(
        "UPDATE registries SET updated_at = updated_at WHERE id = ?1 AND scope_key = ?2
         AND EXISTS(SELECT 1 FROM authorization_scopes scope WHERE scope.scope_key = ?2 AND scope.retired_at IS NULL)
         AND NOT EXISTS(SELECT 1 FROM registry_publications publication WHERE publication.registry_id = ?1
           AND publication.state IN ('preparing', 'writing_pointers'))",
        vals![registry_id, scope],
    ).expecting(1)
}

fn publication_release_guard(registry_id: i64, release: &PublicationRelease) -> CheckedStatement {
    Statement::new(
        "UPDATE releases SET pack_present = pack_present
         WHERE registry_id = ?1 AND semver = ?2 AND commit_oid = ?3 AND tag_oid = ?4
           AND id = (SELECT newest.id FROM (SELECT id FROM releases
             WHERE registry_id = ?1 ORDER BY tagged_at DESC, semver DESC LIMIT 1) newest)",
        vals![
            registry_id,
            release.release,
            release.source_commit,
            release.verified_tag_oid
        ],
    )
    .expecting(1)
}
