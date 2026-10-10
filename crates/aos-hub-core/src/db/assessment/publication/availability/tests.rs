//! Qualification of unknown publication states and exact unsupported-output pages.

use super::super::tests::{publication_fixture, publication_fixture_database};
use super::*;
use crate::db::{IndexSnapshot, ReleaseArtifactSnapshot, ReleaseRow, ReleaseSnapshotArtifact};

fn query(limit: u32) -> PublicationQueryV1 {
    PublicationQueryV1 {
        schema: "aos.assessment-publication-query/v1".into(),
        limit,
        after_output: None,
        publication_digest: None,
        resource_scope: None,
    }
}

#[tokio::test]
async fn no_publication_has_no_invented_inventory_or_scan_effects() -> Result<()> {
    let db = Database::open_in_memory().await?;
    let registry = db
        .register_registry("missing-publication", &[], false)
        .await?;
    let status = db
        .assessment_publication_status(registry, &query(100))
        .await?;
    assert_eq!(status.availability, PublicationAvailability::NoPublication);
    assert!(status.publication_digest.is_none() && status.unsupported_outputs.is_empty());
    assert!(db.assessment_resource(registry).await?.is_none());
    assert!(db
        .assessment_scan_summaries(registry, "", 100)
        .await?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn declared_inventory_availability_is_separate_from_activation_and_assessment() -> Result<()>
{
    let (db, registry, policy) = publication_fixture(true).await?;
    let pending = db
        .assessment_publication_status(registry, &query(100))
        .await?;
    assert!(matches!(
        pending.availability,
        PublicationAvailability::Ready {
            declared_outputs: 1,
            unsupported_count: 0,
            active_inventory_revision: None,
            ..
        }
    ));
    let resource = db
        .refresh_assessment_publication(registry, &policy)
        .await?
        .resource
        .context("activated fixture inventory")?;
    let active = db
        .assessment_publication_status(registry, &query(100))
        .await?;
    assert!(matches!(
        active.availability,
        PublicationAvailability::Ready {
            active_inventory_revision: Some(1),
            ..
        }
    ));
    assert_eq!(active.publication_digest, pending.publication_digest);
    assert_eq!(db.assessment_resource(registry).await?, Some(resource));
    assert!(db
        .assessment_scan_summaries(registry, "", 100)
        .await?
        .is_empty());
    Ok(())
}

async fn qualify_unknown_output_pages(db: Database) -> Result<()> {
    let (db, registry, policy) = publication_fixture_database(db, false).await?;
    let row = db
        .backend
        .query_opt(
            "SELECT packages_json FROM release_browse_catalogs WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?
        .context("legacy fixture catalog")?;
    let mut packages: Vec<PackageToml> = serde_json::from_str(&row.get::<String>(0)?)?;
    let legacy = packages[0].versions[0]
        .platforms
        .get("x86_64-linux")
        .context("legacy fixture output")?
        .clone();
    packages[0].versions[0]
        .platforms
        .insert("aarch64-linux".into(), legacy.clone());
    let artifacts: Vec<_> = ["aarch64-linux", "x86_64-linux"]
        .into_iter()
        .map(|platform| ReleaseSnapshotArtifact {
            package_name: "fixture".into(),
            package_version: "1.2.0".into(),
            platform: platform.into(),
            artifact_kind: "output".into(),
            store_path: legacy.store_path.clone(),
            store_hash: "a".repeat(32),
        })
        .collect();

    // Publish a new immutable release instead of replacing a terminal snapshot.
    // Its incomplete catalog must keep the additional output unknown.
    db.apply_snapshot(
        registry,
        &IndexSnapshot {
            commit: "fixture-commit".into(),
            name: "Availability fixture".into(),
            releases: vec![ReleaseRow {
                semver: "1.1.0".into(),
                commit_oid: "fixture-commit".into(),
                tag_oid: "fixture-signed-tag".into(),
                signer: Some("fixture-publisher".into()),
                tagged_at: Some(2),
                pack_present: true,
            }],
            release_artifact_snapshots: vec![ReleaseArtifactSnapshot {
                release_tag: "1.1.0".into(),
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
    let omitted = db
        .assessment_publication_status(registry, &query(1))
        .await?;
    assert!(matches!(
        omitted.availability,
        PublicationAvailability::InvalidProjection { .. }
    ));
    assert!(db
        .refresh_assessment_publication(registry, &policy)
        .await
        .is_err());

    db.retain_release_browse_catalog(registry, "fixture-commit", &packages, None)
        .await?;
    let first = db
        .assessment_publication_status(registry, &query(1))
        .await?;
    assert!(matches!(
        first.availability,
        PublicationAvailability::Unassessable {
            unsupported_count: 2,
            ..
        }
    ));
    assert_eq!(first.unsupported_outputs.len(), 1);
    let cursor = first.next_output.context("second legacy output page")?;
    let continuation = PublicationQueryV1 {
        after_output: Some(cursor),
        publication_digest: first.publication_digest,
        resource_scope: Some(first.resource_scope.clone()),
        ..query(1)
    };
    let second = db
        .assessment_publication_status(registry, &continuation)
        .await?;
    assert_eq!(second.unsupported_outputs.len(), 1);
    assert!(second.unsupported_outputs[0].output_ref > cursor && second.next_output.is_none());
    for page in [&first, &second] {
        PublicationStatusV1::from_slice(&page.to_bytes()?)?;
        assert_eq!(page.unsupported_outputs[0].package_name, "fixture");
        assert_eq!(page.unsupported_outputs[0].version, "1.2.0");
        assert_eq!(page.unsupported_outputs[0].store_path, legacy.store_path);
    }
    assert!(db.assessment_resource(registry).await?.is_none());
    assert!(db
        .assessment_scan_summaries(registry, "", 100)
        .await?
        .is_empty());
    let wrong_scope = PublicationQueryV1 {
        resource_scope: Some("different-incarnation".into()),
        ..continuation.clone()
    };
    assert!(db
        .assessment_publication_status(registry, &wrong_scope)
        .await
        .expect_err("wrong scope refuses continuation")
        .downcast_ref::<PublicationContextChanged>()
        .is_some());
    db.backend
        .execute(
            "UPDATE release_browse_catalogs SET packages_json = '[]' WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    let corrupt = db
        .assessment_publication_status(registry, &query(1))
        .await?;
    assert!(matches!(
        corrupt.availability,
        PublicationAvailability::InvalidProjection { .. }
    ));
    assert!(db
        .assessment_publication_status(registry, &continuation)
        .await
        .expect_err("changed projection refuses continuation")
        .downcast_ref::<PublicationContextChanged>()
        .is_some());
    db.backend
        .execute(
            "DELETE FROM release_artifact_snapshot_heads WHERE registry_id = ?1",
            &vals![@slice registry],
        )
        .await?;
    let incomplete = db
        .assessment_publication_status(registry, &query(1))
        .await?;
    assert!(matches!(
        incomplete.availability,
        PublicationAvailability::AwaitingProjection { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_output_pages_preserve_exact_context_and_unknown_transitions() -> Result<()> {
    qualify_unknown_output_pages(Database::open_in_memory().await?).await
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires AOS_ASSESSMENT_PG_URL_FILE pointing to a disposable PostgreSQL database"]
async fn unsupported_output_pages_and_unknown_transitions_work_on_postgresql() -> Result<()> {
    let path = std::env::var_os("AOS_ASSESSMENT_PG_URL_FILE")
        .context("disposable PostgreSQL URL file required")?;
    let url = std::fs::read_to_string(path)?;
    let backend = crate::backend::SqlxBackend::connect_postgres(url.trim()).await?;
    qualify_unknown_output_pages(Database::with_backend(Box::new(backend)).await?).await
}
