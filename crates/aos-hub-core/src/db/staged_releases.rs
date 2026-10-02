//! Durable unpublished release drafts and immutable inventory revisions.
//!
//! A revision is an exact portable stage document. Lifecycle writes compare
//! the current revision in the same transaction as inventory retention writes:
//!
//! ```text
//! draft -> ready -> releasing -> released
//! draft/ready -> discarded
//! edit: revision N -> revision N+1, with N retained through its grace period
//! ```

use anyhow::{Context, Result, bail};
use aos_registry_surface::staging::StageRevision;
use sha2::{Digest as _, Sha256};

use crate::backend::CheckedStatement;

use super::{Database, Row};

/// Retains superseded or discarded inventory roots for one day.
pub const STAGED_RELEASE_GRACE_SECONDS: i64 = 86_400;

/// Persists the current draft selection and its exact revision document.
#[derive(Clone, Debug)]
pub struct StagedReleaseRecord {
    /// Registry that owns this draft.
    pub registry_id: i64,
    /// Exact immutable revision currently selected by the draft.
    pub revision: StageRevision,
    /// Durable lifecycle state.
    pub state: String,
    /// Associated ordinary upload publication, when admitted.
    pub publication_id: Option<String>,
    /// Exact published version, present only after verified finalization.
    pub released_version: Option<String>,
    /// Initial creation time as Unix seconds.
    pub created_at: i64,
    /// Last lifecycle or inventory change as Unix seconds.
    pub updated_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_registry_surface::staging::{
        STAGE_SCHEMA, StageObject, StagePointer, inventory_digest,
    };

    fn revision(number: u64, commit_digit: char) -> StageRevision {
        let inventory = vec![StageObject {
            path: format!("objects/{}/{}", "ab", "ab".repeat(31)),
            sha256: format!("sha256:{}", "1".repeat(64)),
            byte_size: 3,
            kind: "git_object".into(),
            media_type: "application/octet-stream".into(),
        }];
        StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: "candidate".into(),
            registry: "test".into(),
            revision: number,
            release_id: "2026.10.0".into(),
            source_branch: "dplecki/candidate".into(),
            commit: commit_digit.to_string().repeat(64),
            inventory_digest: inventory_digest(&inventory).unwrap(),
            inventory,
            publication: vec![StagePointer {
                path: "info/refs".into(),
                bytes: Vec::new(),
                expected_sha256: None,
            }],
            container: None,
            store_roots: Vec::new(),
        }
    }

    async fn database() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        db.register_registry("test", &[], false).await.unwrap();
        let id = db.registry_by_slug("test").await.unwrap().unwrap().id;
        db.create_registry_publication(&super::super::NewRegistryPublication {
            publication_id: "publication".into(),
            registry_id: id,
            generation: "test".into(),
            manifest_digest: "a".repeat(64),
            refs_digest: "b".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
        (db, id)
    }

    #[tokio::test]
    async fn revision_cas_preserves_superseded_roots_through_grace() {
        let (db, id) = database().await;
        let first = revision(1, 'a');
        db.upsert_staged_release(id, &first, 0, None, 10)
            .await
            .unwrap();
        db.upsert_staged_release(id, &first, 0, None, 11)
            .await
            .unwrap();

        let mut changed_retry = first.clone();
        changed_retry.commit = "b".repeat(64);
        assert!(
            db.upsert_staged_release(id, &changed_retry, 0, None, 12)
                .await
                .is_err()
        );
        assert!(
            db.upsert_staged_release(id, &first, 99, None, 12)
                .await
                .is_err()
        );

        let second = revision(2, 'b');
        db.upsert_staged_release(id, &second, 1, None, 20)
            .await
            .unwrap();
        assert!(
            db.upsert_staged_release(id, &revision(3, 'c'), 1, None, 21)
                .await
                .is_err()
        );

        let retained = db.backend.query(
            "SELECT revision, retire_after FROM staged_release_revisions WHERE registry_id = ?1 ORDER BY revision",
            &vals![id],
        ).await.unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(
            retained[0].get::<Option<i64>>(1).unwrap(),
            Some(20 + STAGED_RELEASE_GRACE_SECONDS)
        );
        assert_eq!(retained[1].get::<Option<i64>>(1).unwrap(), None);
        assert_eq!(
            db.staged_release(id, "candidate")
                .await
                .unwrap()
                .unwrap()
                .revision,
            second
        );
    }

    #[tokio::test]
    async fn release_requires_exact_indexed_commit_and_ready_publication() {
        let (db, id) = database().await;
        let stage = revision(1, 'a');
        db.upsert_staged_release(id, &stage, 0, Some("publication"), 10)
            .await
            .unwrap();
        db.begin_staged_release_finalization(id, &stage.id, 1, None, 20)
            .await
            .unwrap();

        assert!(db.complete_staged_release(id, &stage, 21).await.is_err());
        assert!(
            db.upsert_staged_release(id, &revision(2, 'b'), 1, None, 22)
                .await
                .is_err()
        );
        assert!(
            db.discard_staged_release(id, &stage.id, 1, 23)
                .await
                .is_err()
        );
        assert_eq!(
            db.staged_release(id, &stage.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            "releasing"
        );
    }

    #[tokio::test]
    async fn publication_associations_are_unique_and_survive_supersession() {
        let (db, id) = database().await;
        let first = revision(1, 'a');
        db.upsert_staged_release(id, &first, 0, None, 10)
            .await
            .unwrap();
        db.upsert_staged_release(id, &first, 1, Some("publication"), 11)
            .await
            .unwrap();

        let mut other = first.clone();
        other.id = "other".into();
        assert!(
            db.upsert_staged_release(id, &other, 0, Some("publication"), 12)
                .await
                .is_err()
        );
        assert!(db.staged_release(id, &other.id).await.unwrap().is_none());

        db.upsert_staged_release(id, &revision(2, 'b'), 1, None, 20)
            .await
            .unwrap();
        let historical_state = db
            .staged_publication_state("publication")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(historical_state, "superseded");
    }

    #[tokio::test]
    async fn discarded_stage_relinquishes_only_its_current_roots_after_grace() {
        let (db, id) = database().await;
        let first = revision(1, 'a');
        db.upsert_staged_release(id, &first, 0, None, 10)
            .await
            .unwrap();
        db.discard_staged_release(id, &first.id, 1, 20)
            .await
            .unwrap();

        let stage = db.staged_release(id, &first.id).await.unwrap().unwrap();
        assert_eq!(stage.state, "discarded");
        let deadline = db.backend.query_opt(
            "SELECT retire_after FROM staged_release_revisions WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1",
            &vals![id, first.id],
        ).await.unwrap().unwrap().get::<i64>(0).unwrap();
        assert_eq!(deadline, 20 + STAGED_RELEASE_GRACE_SECONDS);
        assert!(
            db.upsert_staged_release(id, &revision(2, 'b'), 1, None, 21)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn summary_pagination_never_loads_private_inventory_documents() {
        let (db, id) = database().await;
        let mut first = revision(1, 'a');
        first.id = "alpha".into();
        db.upsert_staged_release(id, &first, 0, None, 10)
            .await
            .unwrap();
        let mut second = first.clone();
        second.id = "beta".into();
        db.upsert_staged_release(id, &second, 0, None, 11)
            .await
            .unwrap();

        let page = db.staged_release_summaries(id, "", 1).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].stage_id, "alpha");
        assert!(page[0].revision_json.is_empty());
        assert!(page[0].missing_paths.is_empty());
        assert_eq!(page[0].total_bytes, 3);
        assert_eq!(page[0].missing_object_count, 1);

        let next = db.staged_release_summaries(id, "alpha", 1).await.unwrap();
        assert_eq!(next[0].stage_id, "beta");
    }

    #[tokio::test]
    async fn staged_releases_pointer_phase_serializes_with_draft_admission() {
        let (db, id) = database().await;
        let stage = revision(1, 'a');
        db.upsert_staged_release(id, &stage, 0, Some("publication"), 10)
            .await
            .unwrap();

        assert!(
            !db.advance_registry_publication("publication", "preparing", "writing_pointers", 11)
                .await
                .unwrap()
        );
        db.begin_staged_release_finalization(id, &stage.id, 1, None, 12)
            .await
            .unwrap();
        assert!(
            db.advance_registry_publication("publication", "preparing", "writing_pointers", 13)
                .await
                .unwrap()
        );
        assert!(
            db.fail_registry_publication("publication", 14)
                .await
                .is_err()
        );

        let (other_db, other_id) = database().await;
        assert!(
            other_db
                .advance_registry_publication("publication", "preparing", "writing_pointers", 10)
                .await
                .unwrap()
        );
        assert!(
            other_db
                .upsert_staged_release(other_id, &stage, 0, Some("publication"), 11)
                .await
                .is_err()
        );
        assert!(
            other_db
                .staged_release(other_id, &stage.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn staged_releases_admits_full_fifty_thousand_object_inventory() {
        let (db, id) = database().await;
        let mut stage = revision(1, 'a');
        stage.inventory = (0..50_000)
            .map(|index| StageObject {
                path: format!("nar/{index:064x}.nar.zst"),
                sha256: format!("sha256:{index:064x}"),
                byte_size: 1_000,
                kind: "nar".into(),
                media_type: "application/x-nix-nar".into(),
            })
            .collect();
        stage.inventory_digest = inventory_digest(&stage.inventory).unwrap();

        db.upsert_staged_release(id, &stage, 0, None, 10)
            .await
            .unwrap();

        let detail = db.staged_release(id, &stage.id).await.unwrap().unwrap();
        assert_eq!(detail.revision, stage);
        let summary = db
            .staged_release_summaries(id, "", 1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(summary.object_count, 50_000);
        assert_eq!(summary.missing_object_count, 50_000);
        assert_eq!(summary.total_bytes, 50_000_000);
        assert!(summary.revision_json.is_empty());
        assert!(summary.revision_gzip.is_empty());
        let storage = db
            .backend
            .query_opt(
                "SELECT MAX(LENGTH(payload)), COUNT(*), SUM(LENGTH(payload))
              FROM staged_release_revision_chunks WHERE registry_id = ?1 AND stage_id = ?2",
                &vals![id, stage.id],
            )
            .await
            .unwrap()
            .unwrap();
        assert!(storage.get::<i64>(0).unwrap() <= STAGED_DOCUMENT_CHUNK_BYTES as i64);
        assert!(storage.get::<i64>(1).unwrap() > 1);
        assert!(storage.get::<i64>(2).unwrap() > 2 * 1024 * 1024);
        let metadata = db
            .backend
            .query_opt(
                "SELECT document_chunks, document_bytes FROM staged_release_revisions
              WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1",
                &vals![id, stage.id],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata.get::<i64>(0).unwrap(),
            storage.get::<i64>(1).unwrap()
        );
        assert_eq!(
            metadata.get::<i64>(1).unwrap(),
            storage.get::<i64>(2).unwrap()
        );

        db.backend
            .execute(
                "UPDATE staged_release_revision_chunks SET payload = payload || ' '
              WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1 AND ordinal = 0",
                &vals![id, stage.id],
            )
            .await
            .unwrap();
        assert!(db.staged_release(id, &stage.id).await.is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn staged_releases_migrates_existing_version_two_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(super::super::MIGRATIONS[0])
                .unwrap();
            connection
                .execute_batch(super::super::MIGRATIONS[1])
                .unwrap();
            connection.execute_batch("CREATE TABLE schema_version(version INTEGER NOT NULL); INSERT INTO schema_version VALUES(2)").unwrap();
        }

        let db = Database::open(&path).await.unwrap();
        let version = db
            .backend
            .query_opt("SELECT version FROM schema_version", &[])
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(version, super::super::MIGRATIONS.len() as i64);
        db.register_registry("test", &[], false).await.unwrap();
        let id = db.registry_by_slug("test").await.unwrap().unwrap().id;
        db.upsert_staged_release(id, &revision(1, 'a'), 0, None, 10)
            .await
            .unwrap();
        assert!(db.staged_release(id, "candidate").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn staged_releases_require_complete_chunked_documents() {
        let (db, id) = database().await;
        let stage = revision(1, 'a');
        db.upsert_staged_release(id, &stage, 0, None, 10)
            .await
            .unwrap();
        assert_eq!(
            db.staged_release(id, &stage.id)
                .await
                .unwrap()
                .unwrap()
                .revision,
            stage
        );

        db.backend
            .execute(
                "UPDATE staged_release_revisions SET document_chunks = 0
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1",
                &vals![id, stage.id],
            )
            .await
            .unwrap();
        let error = db.staged_release(id, &stage.id).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid staged document chunk count")
        );

        db.backend
            .execute(
                "UPDATE staged_release_revisions SET document_chunks = 1
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1",
                &vals![id, stage.id],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "DELETE FROM staged_release_revision_chunks
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = 1",
                &vals![id, stage.id],
            )
            .await
            .unwrap();
        let error = db.staged_release(id, &stage.id).await.unwrap_err();
        assert!(error.to_string().contains("missing document chunks"));
    }
}

/// Bounds one persisted UTF-8 page below every supported provider's row cap.
///
/// Durable Object SQLite limits each string/blob and table row to 2 MiB;
/// these pages also leave room for keys and provider bridge envelopes.
/// See <https://developers.cloudflare.com/durable-objects/platform/limits/>.
const STAGED_DOCUMENT_CHUNK_BYTES: usize = 256 * 1024;

const STAGED_SELECT: &str = "SELECT stage.registry_id,
    stage.state, stage.publication_id, stage.released_version, stage.created_at, stage.updated_at,
    revision.document_chunks, revision.document_bytes, revision.document_sha256, stage.stage_id, revision.revision
  FROM staged_releases stage JOIN staged_release_revisions revision
    ON revision.registry_id = stage.registry_id AND revision.stage_id = stage.stage_id
   AND revision.revision = stage.current_revision";

impl Database {
    /// Reconstructs an exact revision from bounded ordered provider pages.
    async fn staged_record(&self, row: &Row) -> Result<StagedReleaseRecord> {
        let count = usize::try_from(row.get::<i64>(6)?)?;
        let byte_size = usize::try_from(row.get::<i64>(7)?)?;
        let registry_id: i64 = row.get(0)?;
        let stage_id: String = row.get(9)?;
        let number: i64 = row.get(10)?;
        let max = aos_registry_surface::staging::wire::MAX_DECODED_REVISION_BYTES;
        anyhow::ensure!(
            byte_size > 0 && byte_size <= max,
            "invalid staged document length"
        );
        anyhow::ensure!(
            count > 0 && count <= max / (STAGED_DOCUMENT_CHUNK_BYTES - 3) + 1,
            "invalid staged document chunk count"
        );
        let mut json = String::with_capacity(byte_size);
        let mut ordinal = 0_usize;
        while ordinal < count {
            let chunks = self
                .backend
                .query(
                    "SELECT ordinal, payload FROM staged_release_revision_chunks
                      WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3 AND ordinal >= ?4
                      ORDER BY ordinal LIMIT 4",
                    &vals![registry_id, stage_id, number, i64::try_from(ordinal)?],
                )
                .await?;
            anyhow::ensure!(
                !chunks.is_empty(),
                "staged revision is missing document chunks"
            );
            for chunk in chunks {
                anyhow::ensure!(
                    usize::try_from(chunk.get::<i64>(0)?)? == ordinal && ordinal < count,
                    "staged revision chunks are not contiguous"
                );
                let payload: String = chunk.get(1)?;
                anyhow::ensure!(
                    !payload.is_empty() && payload.len() <= STAGED_DOCUMENT_CHUNK_BYTES,
                    "invalid staged revision chunk size"
                );
                anyhow::ensure!(
                    json.len()
                        .checked_add(payload.len())
                        .is_some_and(|size| size <= byte_size),
                    "staged revision document exceeds declared length"
                );
                json.push_str(&payload);
                ordinal += 1;
            }
        }
        let extra = self
            .backend
            .query_opt(
                "SELECT ordinal FROM staged_release_revision_chunks
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3
                    AND ordinal >= ?4 LIMIT 1",
                &vals![registry_id, stage_id, number, i64::try_from(count)?],
            )
            .await?;
        anyhow::ensure!(
            extra.is_none() && json.len() == byte_size,
            "staged revision document length does not match"
        );
        let digest: String = row.get(8)?;
        anyhow::ensure!(
            hex::encode(Sha256::digest(json.as_bytes())) == digest,
            "staged revision document digest does not match"
        );
        let revision: StageRevision =
            serde_json::from_str(&json).context("invalid persisted stage revision")?;
        anyhow::ensure!(
            revision.id == stage_id && i64::try_from(revision.revision)? == number,
            "persisted stage document identity changed"
        );
        Ok(StagedReleaseRecord {
            registry_id,
            revision,
            state: row.get(1)?,
            publication_id: row.get(2)?,
            released_version: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }

    /// Lists durable accepted offsets for objects not yet completely verified.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid persisted offsets or storage failure.
    pub async fn staged_registry_partial_upload_progress(
        &self,
        publication_id: &str,
        now: i64,
    ) -> Result<Vec<u64>> {
        self.backend.query(
            "SELECT upload.hashed_size FROM registry_publication_multipart_uploads upload
               JOIN registry_publication_objects declared
                 ON declared.publication_id = upload.publication_id
                AND declared.surface_object_id = upload.surface_object_id
              WHERE upload.publication_id = ?1 AND upload.state IN('active', 'completing')
                AND upload.expires_at > ?2 AND upload.hashed_size > 0
                AND upload.hashed_size <= declared.expected_size
                AND declared.object_kind = 'immutable'
                AND EXISTS (SELECT 1 FROM registry_publication_placements required
                  WHERE required.publication_id = upload.publication_id AND required.required = 1
                    AND NOT EXISTS (SELECT 1 FROM object_placements presence
                      WHERE presence.surface_object_id = upload.surface_object_id
                        AND presence.placement_id = required.placement_id AND presence.state = 'present'
                        AND presence.observed_hash = declared.expected_hash
                        AND presence.observed_size = declared.expected_size))",
            &vals![publication_id, now],
        ).await?.iter().map(|row| Ok(u64::try_from(row.get::<i64>(0)?)?)).collect()
    }

    /// Lists obsolete draft uploads whose cleanup remains recoverable from history.
    ///
    /// # Errors
    ///
    /// Returns an error for a storage failure.
    pub async fn obsolete_staged_release_publications(
        &self,
        registry_id: i64,
        stage_id: &str,
    ) -> Result<Vec<String>> {
        self.backend.query(
            "SELECT revision.publication_id
               FROM staged_release_revisions revision JOIN registry_publications publication
                 ON publication.publication_id = revision.publication_id
              WHERE revision.registry_id = ?1 AND revision.stage_id = ?2
                AND revision.retire_after IS NOT NULL
                AND (publication.state IN('preparing', 'writing_pointers') OR EXISTS (
                  SELECT 1 FROM registry_publication_multipart_uploads upload
                   WHERE upload.publication_id = revision.publication_id AND upload.state IN('active', 'completing')))",
            &vals![registry_id, stage_id],
        ).await?.iter().map(|row| row.get(0)).collect()
    }

    /// Reads one private stage by registry and stable draft identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, corrupt persisted JSON, or storage failure.
    pub async fn staged_release(
        &self,
        registry_id: i64,
        stage_id: &str,
    ) -> Result<Option<StagedReleaseRecord>> {
        aos_registry_surface::staging::validate_stage_id(stage_id)?;
        let row = self
            .backend
            .query_opt(
                &format!("{STAGED_SELECT} WHERE stage.registry_id = ?1 AND stage.stage_id = ?2"),
                &vals![registry_id, stage_id],
            )
            .await?;
        match row {
            Some(row) => Ok(Some(self.staged_record(&row).await?)),
            None => Ok(None),
        }
    }

    /// Lists bounded draft summaries without loading their inventory documents.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid persisted scalar data or storage failure.
    pub async fn staged_release_summaries(
        &self,
        registry_id: i64,
        after: &str,
        limit: u32,
    ) -> Result<Vec<aos_proto_types::StagedRelease>> {
        self.backend.query(
            "SELECT stage.stage_id, stage.current_revision, stage.release_id,
                    stage.source_branch, stage.source_commit, stage.inventory_digest,
                    stage.object_count, stage.total_bytes, stage.state, stage.publication_id,
                    stage.released_version, stage.created_at, stage.updated_at,
                    COALESCE((SELECT SUM(inventory.byte_size)
                      FROM staged_release_objects inventory
                      JOIN registry_publication_objects declared
                        ON declared.publication_id = stage.publication_id
                       AND declared.registry_id = stage.registry_id
                       AND declared.expected_hash = inventory.sha256
                       AND declared.expected_size = inventory.byte_size
                      JOIN surface_objects object ON object.id = declared.surface_object_id
                       AND object.object_key = inventory.object_key
                     WHERE inventory.registry_id = stage.registry_id
                       AND inventory.stage_id = stage.stage_id
                       AND inventory.revision = stage.current_revision
                       AND EXISTS (SELECT 1 FROM registry_publication_placements required
                         WHERE required.publication_id = stage.publication_id AND required.required = 1)
                       AND NOT EXISTS (SELECT 1 FROM registry_publication_placements required
                         WHERE required.publication_id = stage.publication_id AND required.required = 1
                           AND NOT EXISTS (SELECT 1 FROM object_placements presence
                             WHERE presence.surface_object_id = declared.surface_object_id
                               AND presence.placement_id = required.placement_id
                               AND presence.state = 'present'
                               AND presence.observed_hash = inventory.sha256
                               AND presence.observed_size = inventory.byte_size))), 0),
                    COALESCE((SELECT COUNT(*)
                      FROM staged_release_objects inventory
                      JOIN registry_publication_objects declared
                        ON declared.publication_id = stage.publication_id
                       AND declared.registry_id = stage.registry_id
                       AND declared.expected_hash = inventory.sha256
                       AND declared.expected_size = inventory.byte_size
                      JOIN surface_objects object ON object.id = declared.surface_object_id
                       AND object.object_key = inventory.object_key
                     WHERE inventory.registry_id = stage.registry_id
                       AND inventory.stage_id = stage.stage_id
                       AND inventory.revision = stage.current_revision
                       AND EXISTS (SELECT 1 FROM registry_publication_placements required
                         WHERE required.publication_id = stage.publication_id AND required.required = 1)
                       AND NOT EXISTS (SELECT 1 FROM registry_publication_placements required
                         WHERE required.publication_id = stage.publication_id AND required.required = 1
                           AND NOT EXISTS (SELECT 1 FROM object_placements presence
                             WHERE presence.surface_object_id = declared.surface_object_id
                               AND presence.placement_id = required.placement_id
                               AND presence.state = 'present'
                               AND presence.observed_hash = inventory.sha256
                               AND presence.observed_size = inventory.byte_size))), 0)
               FROM staged_releases stage
              WHERE stage.registry_id = ?1 AND stage.stage_id > ?2
              ORDER BY stage.stage_id LIMIT ?3",
            &vals![registry_id, after, limit],
        ).await?.iter().map(|row| {
            let total_bytes = u64::try_from(row.get::<i64>(7)?)?;
            let uploaded_bytes = u64::try_from(row.get::<i64>(13)?)?;
            let verified_count = u64::try_from(row.get::<i64>(14)?)?;
            let object_count = u64::try_from(row.get::<i64>(6)?)?;
            let publication_id: Option<String> = row.get(9)?;
            let state: String = row.get(8)?;
            Ok(aos_proto_types::StagedRelease {
                stage_id: row.get(0)?,
                revision: u64::try_from(row.get::<i64>(1)?)?,
                release_id: row.get(2)?,
                source_branch: row.get(3)?,
                commit: row.get(4)?,
                inventory_digest: row.get(5)?,
                object_count,
                missing_object_count: object_count.saturating_sub(verified_count),
                total_bytes,
                uploaded_bytes,
                state: if state == "draft" && publication_id.is_some() && object_count == verified_count {
                    "ready".into()
                } else {
                    state
                },
                publication_id: publication_id.unwrap_or_default(),
                released_version: row.get::<Option<String>>(10)?.unwrap_or_default(),
                created_at: row.get(11)?,
                updated_at: row.get(12)?,
                ..Default::default()
            })
        }).collect()
    }

    /// Reads a publication's draft lifecycle without loading its inventory.
    ///
    /// Historical associations remain frozen as superseded revisions.
    ///
    /// # Errors
    ///
    /// Returns an error for storage failure.
    pub async fn staged_publication_state(&self, publication_id: &str) -> Result<Option<String>> {
        self.backend.query_opt(
            "SELECT CASE WHEN revision.revision = stage.current_revision THEN stage.state ELSE 'superseded' END
              FROM staged_release_revisions revision JOIN staged_releases stage
                ON stage.registry_id = revision.registry_id AND stage.stage_id = revision.stage_id
              WHERE revision.publication_id = ?1",
            &vals![publication_id],
        ).await?.map(|row| row.get(0)).transpose()
    }

    /// Creates or compare-and-swaps one exact draft revision and its GC roots.
    ///
    /// Equal-document retries are idempotent. Attaching an upload publication
    /// may change only an empty association on the current draft revision.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, a changed retry, a frozen lifecycle,
    /// active deletion, or storage failure.
    pub async fn upsert_staged_release(
        &self,
        registry_id: i64,
        revision: &StageRevision,
        expected_revision: u64,
        publication_id: Option<&str>,
        now: i64,
    ) -> Result<()> {
        revision.validate()?;
        super::validate_key_bytes(&revision.release_id, "staged release version", 255)?;
        super::validate_key_bytes(&revision.source_branch, "staged source branch", 255)?;
        for object in &revision.inventory {
            super::validate_key_bytes(&object.path, "staged object key", 1024)?;
            super::validate_key_bytes(&object.media_type, "staged object media type", 255)?;
        }
        for root in &revision.store_roots {
            super::validate_key_bytes(root, "staged store root", 255)?;
        }
        let number = i64::try_from(revision.revision).context("stage revision is too large")?;
        let expected = i64::try_from(expected_revision).context("stage revision is too large")?;
        let json = serde_json::to_string(revision)?;
        anyhow::ensure!(
            json.len() <= aos_registry_surface::staging::wire::MAX_DECODED_REVISION_BYTES,
            "stage document exceeds decoded byte limit"
        );
        anyhow::ensure!(
            revision.inventory.len() <= aos_registry_surface::staging::wire::MAX_REVISION_OBJECTS,
            "stage object count exceeds admission limit"
        );
        let total_bytes = revision.inventory.iter().try_fold(0_i64, |total, object| {
            total
                .checked_add(i64::try_from(object.byte_size)?)
                .context("stage byte count overflow")
        })?;
        let object_count = i64::try_from(revision.inventory.len())?;

        if let Some(existing) = self.staged_release(registry_id, &revision.id).await? {
            if existing.revision == *revision {
                if expected_revision != revision.revision
                    && expected_revision.checked_add(1) != Some(revision.revision)
                {
                    bail!("stage retry has a stale expected revision");
                }
                if existing.publication_id.as_deref() == publication_id || publication_id.is_none()
                {
                    return Ok(());
                }
                if existing.publication_id.is_some() {
                    bail!("stage revision already belongs to another publication");
                }
                self.backend.checked_batch(&[CheckedStatement::exact(
                    "UPDATE staged_releases SET publication_id = ?4, updated_at = ?5
                      WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3
                        AND publication_id IS NULL AND state IN('draft', 'ready')
                        AND EXISTS (SELECT 1 FROM registry_publications publication
                          WHERE publication.publication_id = ?4 AND publication.registry_id = ?1 AND publication.state = 'preparing')
                        AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks WHERE registry_id = ?1)
                        AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences WHERE registry_id = ?1 AND state = 'collecting')",
                    vals![registry_id, revision.id, number, publication_id, now], 1,
                ), CheckedStatement::exact(
                    "UPDATE staged_release_revisions SET publication_id = ?4
                      WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3 AND publication_id IS NULL",
                    vals![registry_id, revision.id, number, publication_id], 1,
                )]).await?;
                return Ok(());
            }
        }

        if revision.revision
            != expected_revision
                .checked_add(1)
                .context("stage revision overflow")?
        {
            bail!("new stage revision must immediately follow the expected revision");
        }
        let mut writes = Vec::new();
        // Serialize with OCI collection before admitting any new roots. The
        // collector's reviewed mutation epoch then cannot survive this draft.
        if revision.container.is_some() {
            writes.push(CheckedStatement::unchecked(
                "INSERT INTO oci_registry_state(registry_id, updated_at)
                 VALUES (?1, ?2) ON CONFLICT(registry_id) DO NOTHING",
                vals![registry_id, now],
            ));
            writes.push(CheckedStatement::exact(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
                  WHERE registry_id = ?1
                    AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks WHERE registry_id = ?1)
                    AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences WHERE registry_id = ?1 AND state = 'collecting')",
                vals![registry_id, now], 1,
            ));
        }
        let owner = hex::encode(Sha256::digest(format!(
            "aos-hub/staged-retention/v1\0{registry_id}\0{}\0{}\0{}",
            revision.id, number, revision.inventory_digest,
        )));
        for roots in revision
            .store_roots
            .chunks(super::SNAPSHOT_MAX_BOUND_PARAMETERS - 1)
        {
            let mut params = vals![owner];
            let mut placeholders = Vec::with_capacity(roots.len());
            for (index, path) in roots.iter().enumerate() {
                let hash = aos_registry_surface::store::store_path_hash(path)?;
                params.extend(vals![hash]);
                placeholders.push(format!("?{}", index + 2));
            }
            writes.push(CheckedStatement::unchecked(
                format!("UPDATE cache_gc_state SET epoch = epoch + 1, root_generation = root_generation + 1,
                    epoch_owner_token = ?1, resource_version = resource_version + 1
                  WHERE cache_id IN(SELECT cache_id FROM cache_objects WHERE store_hash IN({}))",
                    placeholders.join(", ")),
                params,
            ));
        }
        if expected_revision == 0 {
            writes.push(CheckedStatement::exact(
                "INSERT INTO staged_releases
                  (registry_id, stage_id, current_revision, state, publication_id, created_at, updated_at,
                   release_id, source_branch, source_commit, inventory_digest, object_count, total_bytes, container_repository)
                 SELECT ?1, ?2, ?3, 'draft', ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
                  WHERE (?4 IS NULL OR EXISTS (SELECT 1 FROM registry_publications publication
                    WHERE publication.publication_id = ?4 AND publication.registry_id = ?1 AND publication.state = 'preparing'))
                    AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks WHERE registry_id = ?1)
                    AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences WHERE registry_id = ?1 AND state = 'collecting')",
                vals![registry_id, revision.id, number, publication_id, now, revision.release_id,
                      revision.source_branch, revision.commit, revision.inventory_digest, object_count, total_bytes,
                      revision.container.as_ref().map(|graph| graph.repository.as_str())], 1,
            ));
        } else {
            writes.push(CheckedStatement::exact(
                "UPDATE staged_releases SET current_revision = ?4, state = 'draft',
                     publication_id = ?5, updated_at = ?6, release_id = ?7, source_branch = ?8,
                     source_commit = ?9, inventory_digest = ?10, object_count = ?11, total_bytes = ?12, container_repository = ?13
                  WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3
                    AND state IN('draft', 'ready')
                    AND (?5 IS NULL OR EXISTS (SELECT 1 FROM registry_publications publication
                      WHERE publication.publication_id = ?5 AND publication.registry_id = ?1 AND publication.state = 'preparing'))
                    AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks WHERE registry_id = ?1)
                        AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences WHERE registry_id = ?1 AND state = 'collecting')",
                vals![registry_id, revision.id, expected, number, publication_id, now,
                      revision.release_id, revision.source_branch, revision.commit,
                      revision.inventory_digest, object_count, total_bytes,
                      revision.container.as_ref().map(|graph| graph.repository.as_str())], 1,
            ));
            writes.push(CheckedStatement::exact(
                "UPDATE staged_release_revisions SET retire_after = ?4
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3 AND retire_after IS NULL",
                vals![registry_id, revision.id, expected, now.saturating_add(STAGED_RELEASE_GRACE_SECONDS)], 1,
            ));
        }
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < json.len() {
            let mut end = (offset + STAGED_DOCUMENT_CHUNK_BYTES).min(json.len());
            while !json.is_char_boundary(end) {
                end -= 1;
            }
            chunks.push(&json[offset..end]);
            offset = end;
        }
        writes.push(CheckedStatement::exact(
            "INSERT INTO staged_release_revisions (registry_id, stage_id, revision, retire_after, publication_id, document_chunks, document_bytes, document_sha256)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7)",
            vals![registry_id, revision.id, number, publication_id, i64::try_from(chunks.len())?, i64::try_from(json.len())?, hex::encode(Sha256::digest(json.as_bytes()))], 1,
        ));
        for (ordinal, payload) in chunks.into_iter().enumerate() {
            writes.push(CheckedStatement::exact(
                "INSERT INTO staged_release_revision_chunks(registry_id, stage_id, revision, ordinal, payload) VALUES(?1, ?2, ?3, ?4, ?5)",
                vals![registry_id, revision.id, number, i64::try_from(ordinal)?, payload], 1,
            ));
        }
        drop(json);
        // Bound parameters for the Worker storage bridge while admitting each
        // inventory page as one checked write rather than one call per object.
        let page_size = (super::SNAPSHOT_MAX_BOUND_PARAMETERS - 3) / 4;
        for page in revision.inventory.chunks(page_size) {
            let mut params = vals![registry_id, revision.id, number];
            let mut tuples = Vec::with_capacity(page.len());
            for (index, object) in page.iter().enumerate() {
                let hash = object
                    .sha256
                    .strip_prefix("sha256:")
                    .context("invalid stage digest")?;
                let size = i64::try_from(object.byte_size).context("stage object is too large")?;
                let first = 4 + index * 4;
                tuples.push(format!(
                    "(?{first}, ?{}, ?{}, ?{})",
                    first + 1,
                    first + 2,
                    first + 3
                ));
                params.extend(vals![object.path, hash, size, object.media_type]);
            }
            writes.push(CheckedStatement::exact(
                format!("WITH input(object_key, sha256, byte_size, media_type) AS (VALUES {})
                  INSERT INTO staged_release_objects (registry_id, stage_id, revision, object_key, sha256, byte_size, media_type)
                  SELECT ?1, ?2, ?3, input.object_key, input.sha256, input.byte_size, input.media_type
                    FROM input WHERE NOT EXISTS (SELECT 1 FROM surface_objects object
                      WHERE object.registry_id = ?1 AND object.object_key = input.object_key
                        AND (object.lifecycle_state <> 'active' OR EXISTS (
                          SELECT 1 FROM object_deletion_jobs job
                           WHERE job.surface_object_id = object.id AND job.active_slot IS NOT NULL)))
                      AND NOT EXISTS (SELECT 1 FROM oci_untracked_repair_plans repair
                        WHERE repair.registry_id = ?1 AND repair.object_key = input.object_key
                          AND repair.state IN('pending', 'claimed', 'failed'))", tuples.join(", ")),
                params, u64::try_from(page.len())?,
            ));
        }
        // A retained byte identity does not change, but its catalog version
        // fences a collector that reviewed the object before this transaction.
        // Preserve only placement evidence that was exact at the old version.
        writes.push(CheckedStatement::unchecked(
            "UPDATE cache_gc_state SET epoch = epoch + 1, root_generation = root_generation + 1,
                epoch_owner_token = ?4, resource_version = resource_version + 1
              WHERE cache_id IN(SELECT cached.cache_id FROM cache_objects cached
                JOIN surface_objects bytes ON bytes.id IN(cached.nar_surface_object_id, cached.narinfo_surface_object_id)
                JOIN staged_release_objects inventory ON inventory.object_key = bytes.object_key
                WHERE inventory.registry_id = ?1 AND inventory.stage_id = ?2 AND inventory.revision = ?3)",
            vals![registry_id, revision.id, number, owner],
        ));
        writes.push(CheckedStatement::unchecked(
            "UPDATE surface_objects SET resource_version = resource_version + 1
              WHERE registry_id = ?1 AND lifecycle_state = 'active'
                AND object_key IN(SELECT object_key FROM staged_release_objects
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3)",
            vals![registry_id, revision.id, number],
        ));
        writes.push(CheckedStatement::unchecked(
            "UPDATE object_placements SET catalog_object_resource_version = catalog_object_resource_version + 1
              WHERE registry_id = ?1 AND state = 'present'
                AND EXISTS (SELECT 1 FROM surface_objects object JOIN staged_release_objects inventory
                  ON inventory.registry_id = object.registry_id AND inventory.object_key = object.object_key
                  WHERE inventory.registry_id = ?1 AND inventory.stage_id = ?2 AND inventory.revision = ?3
                    AND object.id = object_placements.surface_object_id AND object.lifecycle_state = 'active'
                    AND object.resource_version = object_placements.catalog_object_resource_version + 1
                    AND object.content_hash = object_placements.observed_hash
                    AND object.size = object_placements.observed_size)",
            vals![registry_id, revision.id, number],
        ));
        writes.push(CheckedStatement::exact(
            "WITH RECURSIVE retained(cache_id, object_id) AS (
                SELECT cached.cache_id, cached.id FROM cache_objects cached
                  JOIN surface_objects bytes ON bytes.id IN(cached.nar_surface_object_id, cached.narinfo_surface_object_id)
                  JOIN staged_release_objects inventory ON inventory.object_key = bytes.object_key
                  WHERE inventory.registry_id = ?1 AND inventory.stage_id = ?2 AND inventory.revision = ?3
                UNION SELECT edge.cache_id, edge.referenced_cache_object_id
                  FROM retained parent JOIN cache_object_references edge
                    ON edge.cache_id = parent.cache_id AND edge.cache_object_id = parent.object_id)
             UPDATE staged_releases SET updated_at = updated_at
              WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3
                AND NOT EXISTS (SELECT 1 FROM retained root LEFT JOIN cache_objects cached
                  ON cached.cache_id = root.cache_id AND cached.id = root.object_id
                  WHERE cached.id IS NULL OR cached.lifecycle_state <> 'active'
                    OR EXISTS (SELECT 1 FROM object_deletion_jobs job WHERE job.active_slot IS NOT NULL
                      AND job.surface_object_id IN(cached.nar_surface_object_id, cached.narinfo_surface_object_id)))
                AND NOT EXISTS (SELECT 1 FROM staged_release_objects inventory JOIN surface_objects object
                  ON object.registry_id = inventory.registry_id AND object.object_key = inventory.object_key
                  WHERE inventory.registry_id = ?1 AND inventory.stage_id = ?2 AND inventory.revision = ?3
                    AND (object.lifecycle_state <> 'active' OR EXISTS (SELECT 1 FROM object_deletion_jobs job
                      WHERE job.surface_object_id = object.id AND job.active_slot IS NOT NULL)))
                AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks WHERE registry_id = ?1)
                AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences WHERE registry_id = ?1 AND state = 'collecting')
                AND NOT EXISTS (SELECT 1 FROM staged_release_objects inventory JOIN oci_untracked_repair_plans repair
                  ON repair.registry_id = inventory.registry_id AND repair.object_key = inventory.object_key
                  WHERE inventory.registry_id = ?1 AND inventory.stage_id = ?2 AND inventory.revision = ?3
                    AND repair.state IN('pending', 'claimed', 'failed'))",
            vals![registry_id, revision.id, number], 1,
        ));
        for store_path in &revision.store_roots {
            let store_hash = store_path
                .strip_prefix("/nix/store/")
                .and_then(|name| name.split_once('-'))
                .map(|(hash, _)| hash)
                .context("stage store root requires a store hash and name")?;
            writes.push(CheckedStatement::exact(
                "INSERT INTO staged_release_store_roots (registry_id, stage_id, revision, store_path, store_hash)
                 WITH RECURSIVE retained(cache_id, object_id) AS (
                   SELECT cache_id, id FROM cache_objects WHERE store_hash = ?5
                   UNION
                   SELECT edge.cache_id, edge.referenced_cache_object_id
                     FROM retained parent JOIN cache_object_references edge
                       ON edge.cache_id = parent.cache_id AND edge.cache_object_id = parent.object_id)
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE NOT EXISTS (
                   SELECT 1 FROM retained root LEFT JOIN cache_objects object
                     ON object.cache_id = root.cache_id AND object.id = root.object_id
                    WHERE (object.id IS NULL OR object.lifecycle_state <> 'active' OR EXISTS (
                       SELECT 1 FROM object_deletion_jobs job WHERE job.active_slot IS NOT NULL
                         AND job.surface_object_id IN(object.nar_surface_object_id, object.narinfo_surface_object_id))))",
                vals![registry_id, revision.id, number, store_path, store_hash], 1,
            ));
        }
        self.backend.checked_batch(&writes).await
    }

    /// Freezes one ready revision before its withheld pointers are installed.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, missing publication, or storage failure.
    pub async fn begin_staged_release_finalization(
        &self,
        registry_id: i64,
        stage_id: &str,
        revision: u64,
        timestamp: Option<&super::NewReleaseTimestampPublication>,
        now: i64,
    ) -> Result<()> {
        let revision = i64::try_from(revision)?;
        let mut writes = Vec::new();
        if let Some(timestamp) = timestamp {
            if !self.release_timestamp_matches(timestamp).await? {
                writes.push(super::release_publication::timestamp_publication_admission(
                    timestamp, now,
                )?);
            }
        }
        writes.push(CheckedStatement::exact(
            "UPDATE staged_releases SET state = 'releasing', updated_at = ?4
              WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3
                AND state IN('draft', 'ready', 'releasing') AND publication_id IS NOT NULL
                AND EXISTS (SELECT 1 FROM registry_publications publication
                  WHERE publication.publication_id = staged_releases.publication_id
                    AND publication.state IN('preparing', 'writing_pointers', 'ready'))",
            vals![registry_id, stage_id, revision, now],
            1,
        ));
        self.backend.checked_batch(&writes).await
    }

    /// Tests whether the signed release projection contains this exact candidate.
    ///
    /// Optional distribution release records are independent of Git release
    /// indexing and are not required for package-only releases.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure.
    pub async fn staged_release_is_indexed(
        &self,
        registry_id: i64,
        revision: &StageRevision,
    ) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM releases
                  WHERE registry_id = ?1 AND semver = ?2 AND commit_oid = ?3",
                &vals![registry_id, revision.release_id, revision.commit],
            )
            .await?
            .is_some())
    }

    /// Records a completed release only after its signed index names the exact commit.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, an uncommitted publication, an absent
    /// verified release, or storage failure.
    pub async fn complete_staged_release(
        &self,
        registry_id: i64,
        revision: &StageRevision,
        now: i64,
    ) -> Result<()> {
        let number = i64::try_from(revision.revision)?;
        self.backend.checked_batch(&[CheckedStatement::exact(
            "UPDATE staged_releases SET state = 'released', released_version = ?4, updated_at = ?5
              WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3 AND state = 'releasing'
                AND EXISTS (SELECT 1 FROM registry_publications publication
                  WHERE publication.publication_id = staged_releases.publication_id AND publication.state = 'ready')
                AND EXISTS (SELECT 1 FROM releases release
                  WHERE release.registry_id = ?1 AND release.semver = ?4 AND release.commit_oid = ?6)",
            vals![registry_id, revision.id, number, revision.release_id, now, revision.commit], 1,
        )]).await
    }

    /// Discards one editable revision and releases only its roots after grace.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, a frozen finalization, or storage failure.
    pub async fn discard_staged_release(
        &self,
        registry_id: i64,
        stage_id: &str,
        revision: u64,
        now: i64,
    ) -> Result<()> {
        let revision = i64::try_from(revision)?;
        self.backend.checked_batch(&[
            CheckedStatement::exact(
                "UPDATE staged_releases SET state = 'discarded', updated_at = ?4
                  WHERE registry_id = ?1 AND stage_id = ?2 AND current_revision = ?3 AND state IN('draft', 'ready')",
                vals![registry_id, stage_id, revision, now], 1,
            ),
            CheckedStatement::exact(
                "UPDATE staged_release_revisions SET retire_after = ?4
                  WHERE registry_id = ?1 AND stage_id = ?2 AND revision = ?3 AND retire_after IS NULL",
                vals![registry_id, stage_id, revision, now.saturating_add(STAGED_RELEASE_GRACE_SECONDS)], 1,
            ),
        ]).await
    }
}
