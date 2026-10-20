//! Change detection for the signed container-release projection.
//!
//! Every index snapshot rewrites a registry's container-release projection:
//! `oci_release_roots`, `oci_release_provenance`, and the closure-member and
//! evidence rows that cascade from provenance. Release roots and verified
//! evidence referrers are OCI GC roots, so a projection change must advance
//! the registry's OCI `mutation_epoch`. That epoch invalidates frozen GC
//! plans, provider inventories, purge fences, and container-administration
//! cursors captured before the change.
//!
//! The background re-index rewrites an unchanged projection on every pass.
//! Advancing the epoch for those passes would keep every provider inventory
//! of a registry with signed container releases permanently stale, so GC could
//! never plan. This module compares the stored projection with the one a
//! snapshot would write and lets an identical rewrite keep the epoch.
//!
//! The comparison is read before the snapshot transaction, so the epoch is
//! read first and compare-and-set inside the transaction: every writer of
//! these tables advances the epoch in the same transaction as its write, so
//! an unmoved epoch proves the compared rows are still current. A moved epoch
//! falls back to advancing it.

use std::collections::BTreeSet;

use anyhow::{Context, Result};

use super::{ContainerReleaseRootSnapshot, Database, IndexSnapshot, ReleaseArtifactSnapshot};
use crate::backend::{CheckedStatement, Statement};

/// One stored row of the container-release projection, without timestamps.
///
/// Repository ids are compared through the active repository's name, the same
/// way the snapshot statements resolve them; a row whose repository is no
/// longer active never matches, so recreating a repository advances the epoch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ProjectionRow {
    Root {
        release_tag: String,
        repository: String,
        container_name: String,
        index_digest: String,
        source_commit: String,
        verified_tag_oid: String,
        catalog_digest: String,
    },
    Provenance {
        repository: String,
        root_digest: String,
        release_tag: String,
        package_name: String,
        channel_name: Option<String>,
        signed_release_root: String,
        catalog_digest: String,
        verification: String,
    },
    ClosureMember {
        repository: String,
        root_digest: String,
        release_tag: String,
        store_path: String,
        nar_hash: String,
        nar_size: i64,
        layer_digest: String,
        is_direct: bool,
    },
    Evidence {
        repository: String,
        root_digest: String,
        release_tag: String,
        kind: String,
        digest: String,
        media_type: String,
        verification: String,
        referrer_digest: String,
    },
}

impl Database {
    /// Returns the OCI mutation epoch that an identical projection rewrite may
    /// keep, or `None` when the snapshot changes the projection.
    ///
    /// `None` is also returned for a registry without OCI mutation state; the
    /// caller then advances the epoch as for any other projection change.
    pub(super) async fn unchanged_container_release_projection_epoch(
        &self,
        registry_id: i64,
        snapshot: &IndexSnapshot,
    ) -> Result<Option<i64>> {
        // Read the epoch before the rows. A writer that commits between the
        // two reads then moves the epoch past the observed value, and the
        // compare-and-set in the snapshot transaction advances it again.
        let Some(epoch) = self
            .backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let epoch: i64 = epoch.get(0)?;

        let stored = self
            .stored_container_release_projection(registry_id)
            .await?;
        let projected = snapshot_container_release_projection(snapshot)?;
        Ok((stored == projected).then_some(epoch))
    }

    /// Reads the stored container-release projection of one registry.
    async fn stored_container_release_projection(
        &self,
        registry_id: i64,
    ) -> Result<BTreeSet<ProjectionRow>> {
        let mut rows = BTreeSet::new();

        for row in self
            .backend
            .query(
                "SELECT root.release_tag, repository.name, root.container_name,
                        root.index_digest, root.source_commit,
                        root.verified_tag_oid, root.catalog_digest
                 FROM oci_release_roots root
                 JOIN oci_repositories repository
                   ON repository.id = root.repository_id
                  AND repository.registry_id = root.registry_id
                  AND repository.lifecycle_state = 'active'
                 WHERE root.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            rows.insert(ProjectionRow::Root {
                release_tag: row.get(0)?,
                repository: row.get(1)?,
                container_name: row.get(2)?,
                index_digest: row.get(3)?,
                source_commit: row.get(4)?,
                verified_tag_oid: row.get(5)?,
                catalog_digest: row.get(6)?,
            });
        }

        for row in self
            .backend
            .query(
                "SELECT repository.name, provenance.root_digest,
                        provenance.release_tag, provenance.package_name,
                        provenance.channel_name, provenance.signed_release_root,
                        provenance.catalog_digest, provenance.verification
                 FROM oci_release_provenance provenance
                 JOIN oci_repositories repository
                   ON repository.id = provenance.repository_id
                  AND repository.registry_id = provenance.registry_id
                  AND repository.lifecycle_state = 'active'
                 WHERE provenance.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            rows.insert(ProjectionRow::Provenance {
                repository: row.get(0)?,
                root_digest: row.get(1)?,
                release_tag: row.get(2)?,
                package_name: row.get(3)?,
                channel_name: row.get(4)?,
                signed_release_root: row.get(5)?,
                catalog_digest: row.get(6)?,
                verification: row.get(7)?,
            });
        }

        for row in self
            .backend
            .query(
                "SELECT repository.name, member.root_digest, member.release_tag,
                        member.store_path, member.nar_hash, member.nar_size,
                        member.layer_digest, member.is_direct
                 FROM oci_release_closure_members member
                 JOIN oci_repositories repository
                   ON repository.id = member.repository_id
                  AND repository.registry_id = member.registry_id
                  AND repository.lifecycle_state = 'active'
                 WHERE member.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            rows.insert(ProjectionRow::ClosureMember {
                repository: row.get(0)?,
                root_digest: row.get(1)?,
                release_tag: row.get(2)?,
                store_path: row.get(3)?,
                nar_hash: row.get(4)?,
                nar_size: row.get(5)?,
                layer_digest: row.get(6)?,
                is_direct: row.get(7)?,
            });
        }

        for row in self
            .backend
            .query(
                "SELECT repository.name, evidence.root_digest, evidence.release_tag,
                        evidence.evidence_kind, evidence.digest, evidence.media_type,
                        evidence.verification, evidence.referrer_digest
                 FROM oci_release_evidence evidence
                 JOIN oci_repositories repository
                   ON repository.id = evidence.repository_id
                  AND repository.registry_id = evidence.registry_id
                  AND repository.lifecycle_state = 'active'
                 WHERE evidence.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
        {
            rows.insert(ProjectionRow::Evidence {
                repository: row.get(0)?,
                root_digest: row.get(1)?,
                release_tag: row.get(2)?,
                kind: row.get(3)?,
                digest: row.get(4)?,
                media_type: row.get(5)?,
                verification: row.get(6)?,
                referrer_digest: row.get(7)?,
            });
        }

        Ok(rows)
    }
}

/// Builds the projection rows that a snapshot's container releases write.
///
/// Values are normalized exactly as the snapshot's insert statements bind
/// them. A normalization gap can only make an unchanged projection look
/// changed, which advances the epoch; it never hides a change.
fn snapshot_container_release_projection(
    snapshot: &IndexSnapshot,
) -> Result<BTreeSet<ProjectionRow>> {
    let mut rows = BTreeSet::new();
    for release in &snapshot.release_artifact_snapshots {
        if let Some(root) = &release.container_release {
            extend_release_projection(&mut rows, release, root)?;
        }
    }
    Ok(rows)
}

fn extend_release_projection(
    rows: &mut BTreeSet<ProjectionRow>,
    release: &ReleaseArtifactSnapshot,
    root: &ContainerReleaseRootSnapshot,
) -> Result<()> {
    let root_digest = aos_oci_types::Sha256Digest::parse(&root.index_digest)
        .context("signed container release index digest is malformed")?
        .to_string();

    rows.insert(ProjectionRow::Root {
        release_tag: release.release_tag.clone(),
        repository: root.repository.clone(),
        container_name: root.container_name.clone(),
        index_digest: root_digest.clone(),
        source_commit: release.source_commit.clone(),
        verified_tag_oid: release.verified_tag_oid.clone(),
        catalog_digest: root.catalog_digest.clone(),
    });
    rows.insert(ProjectionRow::Provenance {
        repository: root.repository.clone(),
        root_digest: root_digest.clone(),
        release_tag: release.release_tag.clone(),
        package_name: root.package_name.clone(),
        channel_name: None,
        signed_release_root: release.verified_tag_oid.clone(),
        catalog_digest: format!("sha256:{}", root.catalog_digest),
        verification: "verified".to_string(),
    });

    for member in &root.closure_members {
        rows.insert(ProjectionRow::ClosureMember {
            repository: root.repository.clone(),
            root_digest: root_digest.clone(),
            release_tag: release.release_tag.clone(),
            store_path: member.store_path.clone(),
            nar_hash: member.nar_hash.clone(),
            nar_size: i64::try_from(member.nar_size)
                .context("signed closure member NAR size exceeds int64")?,
            layer_digest: aos_oci_types::Sha256Digest::parse(&member.layer_digest)
                .context("signed closure member layer digest is malformed")?
                .to_string(),
            is_direct: member.direct,
        });
    }

    for evidence in &root.evidence {
        rows.insert(ProjectionRow::Evidence {
            repository: root.repository.clone(),
            root_digest: root_digest.clone(),
            release_tag: release.release_tag.clone(),
            kind: evidence.kind.clone(),
            digest: aos_oci_types::Sha256Digest::parse(&evidence.digest)
                .context("signed container evidence digest is malformed")?
                .to_string(),
            media_type: aos_oci_types::MediaType::parse(&evidence.media_type)
                .context("signed container evidence media type is malformed")?
                .as_str()
                .to_string(),
            verification: "verified".to_string(),
            referrer_digest: aos_oci_types::Sha256Digest::parse(&evidence.referrer_digest)
                .context("signed container evidence referrer digest is malformed")?
                .to_string(),
        });
    }

    Ok(())
}

/// Builds the guarded epoch update for a snapshot that touches the
/// container-release projection.
///
/// `unchanged_since` is the epoch observed with an identical stored
/// projection. The epoch then stays put only while it still equals that
/// value; otherwise, and whenever `unchanged_since` is `None`, it advances.
/// Either way the update fails closed while a GC registry lock is held.
pub(super) fn container_release_projection_epoch_statement(
    registry_id: i64,
    indexed_at: i64,
    unchanged_since: Option<i64>,
) -> CheckedStatement {
    match unchanged_since {
        Some(epoch) => Statement::new(
            "UPDATE oci_registry_state
             SET mutation_epoch = mutation_epoch
                   + CASE WHEN mutation_epoch = ?3 THEN 0 ELSE 1 END,
                 updated_at = CASE WHEN mutation_epoch = ?3 THEN updated_at ELSE ?2 END
             WHERE registry_id = ?1
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                 WHERE registry_lock.registry_id = ?1)",
            vals![registry_id, indexed_at, epoch],
        )
        .expecting(1),
        None => Statement::new(
            "UPDATE oci_registry_state
             SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
             WHERE registry_id = ?1
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                 WHERE registry_lock.registry_id = ?1)",
            vals![registry_id, indexed_at],
        )
        .expecting(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn registry_with_epoch(epoch: i64) -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        db.register_registry("projection", &[], false)
            .await
            .unwrap();
        let registry_id = db.registry_by_slug("projection").await.unwrap().unwrap().id;
        db.backend
            .execute(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes, charged_objects, updated_at)
                 VALUES (?1, ?2, 0, 0, 1)",
                &vals![registry_id, epoch],
            )
            .await
            .unwrap();
        (db, registry_id)
    }

    async fn epoch_after(db: &Database, statement: CheckedStatement) -> i64 {
        db.backend.checked_batch(&[statement]).await.unwrap();
        db.backend
            .query_opt("SELECT mutation_epoch FROM oci_registry_state", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap()
    }

    #[tokio::test]
    async fn unchanged_projection_keeps_only_the_observed_epoch() {
        let (db, registry_id) = registry_with_epoch(7).await;

        let kept = container_release_projection_epoch_statement(registry_id, 2, Some(7));
        assert_eq!(epoch_after(&db, kept).await, 7);

        // A writer advanced the epoch after the projection was compared, so
        // the compared rows may be stale and the rewrite advances it again.
        let stale = container_release_projection_epoch_statement(registry_id, 3, Some(6));
        assert_eq!(epoch_after(&db, stale).await, 8);

        let changed = container_release_projection_epoch_statement(registry_id, 4, None);
        assert_eq!(epoch_after(&db, changed).await, 9);
    }

    #[tokio::test]
    async fn registry_without_oci_state_has_no_unchanged_epoch() {
        let db = Database::open_in_memory().await.unwrap();
        db.register_registry("projection", &[], false)
            .await
            .unwrap();
        let registry_id = db.registry_by_slug("projection").await.unwrap().unwrap().id;

        let epoch = db
            .unchanged_container_release_projection_epoch(registry_id, &IndexSnapshot::default())
            .await
            .unwrap();
        assert_eq!(epoch, None);

        let (db, registry_id) = registry_with_epoch(3).await;
        let epoch = db
            .unchanged_container_release_projection_epoch(registry_id, &IndexSnapshot::default())
            .await
            .unwrap();
        assert_eq!(epoch, Some(3));
    }
}
