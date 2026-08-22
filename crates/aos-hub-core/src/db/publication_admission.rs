//! Bounded registry-publication manifest admission.
//!
//! Publication manifests remain invisible while `preparing`. This module uses
//! that lifecycle boundary to admit a page of logical surface objects and its
//! exact publication declarations in one checked transaction, replacing the
//! historical query/create/query/attach loop for every object.

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use sha2::{Digest as _, Sha256};

use crate::backend::CheckedStatement;

use super::{validate_key_bytes, Database};

/// Maximum manifest objects admitted by one database transaction.
pub const MAX_REGISTRY_MANIFEST_ADMISSION_BATCH: usize = 256;

/// One validated object identity in a registry publication manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationManifestObject {
    /// Surface-relative object key.
    pub object_key: String,
    /// Lowercase hexadecimal SHA-256 of the declared bytes.
    pub expected_hash: String,
    /// Exact declared byte length.
    pub expected_size: i64,
    /// `immutable` or `mutable_pointer`.
    pub object_kind: String,
}

/// Durable progress for one resumable publication-manifest admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicationManifestSessionRecord {
    /// Publication whose invisible manifest is being assembled.
    pub publication_id: String,
    /// Registry that owns the publication.
    pub registry_id: i64,
    /// Opaque ownership token required by append and seal operations.
    pub lease_token: String,
    /// Digest of the complete canonical manifest declared at begin time.
    pub manifest_digest: String,
    /// Exact number of objects expected before sealing.
    pub expected_object_count: i64,
    /// Number of objects durably accepted so far.
    pub admitted_object_count: i64,
    /// Zero-based index of the next page the server will accept.
    pub next_chunk_index: i64,
    /// `accepting` or `sealed`.
    pub state: String,
    /// Lease deadline while accepting, or `None` after sealing.
    pub lease_expires_at: Option<i64>,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
}

const MANIFEST_SESSION_LEASE_SECONDS: i64 = 15 * 60;

impl Database {
    /// Creates or resumes a bounded manifest-admission session.
    ///
    /// An unexpired exact session returns its existing token so a client that
    /// lost the begin response can resume. An expired session rotates ownership
    /// to `lease_token`; a sealed session remains replayable with its original
    /// token. A publication that already contains untracked declarations cannot
    /// be converted into the chunked protocol.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity or counts, incompatible session
    /// metadata, a publication outside `preparing`, or persistence failure.
    pub async fn begin_registry_publication_manifest_session(
        &self,
        publication_id: &str,
        registry_id: i64,
        manifest_digest: &str,
        expected_object_count: i64,
        lease_token: &str,
        now: i64,
    ) -> Result<RegistryPublicationManifestSessionRecord> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(manifest_digest, "publication manifest digest", 128)?;
        validate_key_bytes(lease_token, "publication manifest lease token", 64)?;
        if registry_id <= 0 || expected_object_count <= 0 {
            bail!("publication manifest session metadata is invalid");
        }
        let lease_expires_at = now
            .checked_add(MANIFEST_SESSION_LEASE_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("publication manifest lease overflowed"))?;
        self.backend
            .execute(
                "INSERT INTO registry_publication_manifest_sessions
                   (publication_id, registry_id, lease_token, manifest_digest,
                    expected_object_count, admitted_object_count,
                    next_chunk_index, state, lease_expires_at, created_at,
                    updated_at)
                 SELECT publication_id, registry_id, ?4, manifest_digest, ?5,
                        0, 0, 'accepting', ?6, ?7, ?7
                   FROM registry_publications publication
                  WHERE publication_id = ?1 AND registry_id = ?2
                    AND manifest_digest = ?3 AND state = 'preparing'
                    AND NOT EXISTS (SELECT 1
                      FROM registry_publication_objects object
                     WHERE object.publication_id = publication.publication_id)
                 ON CONFLICT(publication_id) DO NOTHING",
                &vals![
                    publication_id,
                    registry_id,
                    manifest_digest,
                    lease_token,
                    expected_object_count,
                    lease_expires_at,
                    now
                ],
            )
            .await?;

        let mut session = self
            .registry_publication_manifest_session(publication_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("publication cannot begin a manifest session"))?;
        if session.registry_id != registry_id
            || session.manifest_digest != manifest_digest
            || session.expected_object_count != expected_object_count
        {
            bail!("publication manifest session metadata does not match");
        }
        if session.state == "accepting" && session.lease_expires_at.is_some_and(|at| at <= now) {
            let affected = self
                .backend
                .execute(
                    "UPDATE registry_publication_manifest_sessions
                        SET lease_token = ?2, lease_expires_at = ?3,
                            updated_at = ?4, resource_version = resource_version + 1
                      WHERE publication_id = ?1 AND state = 'accepting'
                        AND lease_expires_at <= ?4 AND resource_version = ?5",
                    &vals![
                        publication_id,
                        lease_token,
                        lease_expires_at,
                        now,
                        session.resource_version
                    ],
                )
                .await?;
            if affected != 1 {
                bail!("publication manifest lease changed concurrently");
            }
            session = self
                .registry_publication_manifest_session(publication_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("publication manifest session disappeared"))?;
        }
        Ok(session)
    }

    /// Returns one durable publication-manifest session.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, malformed persisted state, or
    /// persistence failure.
    pub async fn registry_publication_manifest_session(
        &self,
        publication_id: &str,
    ) -> Result<Option<RegistryPublicationManifestSessionRecord>> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        self.backend
            .query_opt(
                "SELECT publication_id, registry_id, lease_token,
                        manifest_digest, expected_object_count,
                        admitted_object_count, next_chunk_index, state,
                        lease_expires_at, resource_version
                   FROM registry_publication_manifest_sessions
                  WHERE publication_id = ?1",
                &vals![publication_id],
            )
            .await?
            .map(|row| {
                Ok(RegistryPublicationManifestSessionRecord {
                    publication_id: row.get(0)?,
                    registry_id: row.get(1)?,
                    lease_token: row.get(2)?,
                    manifest_digest: row.get(3)?,
                    expected_object_count: row.get(4)?,
                    admitted_object_count: row.get(5)?,
                    next_chunk_index: row.get(6)?,
                    state: row.get(7)?,
                    lease_expires_at: row.get(8)?,
                    resource_version: row.get(9)?,
                })
            })
            .transpose()
    }

    /// Atomically admits the next manifest page and advances its durable receipt.
    ///
    /// Retrying an already accepted page succeeds only when its digest and
    /// object count exactly match the stored receipt. New pages must arrive in
    /// order and before the ownership lease expires.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, a stale lease, an out-of-order or
    /// conflicting retry, duplicate paths across pages, incompatible objects,
    /// an oversized page, or persistence failure.
    pub async fn append_registry_publication_manifest_chunk(
        &self,
        publication_id: &str,
        lease_token: &str,
        chunk_index: i64,
        chunk_digest: &str,
        objects: &[RegistryPublicationManifestObject],
        now: i64,
    ) -> Result<RegistryPublicationManifestSessionRecord> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(lease_token, "publication manifest lease token", 64)?;
        validate_key_bytes(chunk_digest, "publication manifest chunk digest", 128)?;
        validate_manifest_objects(objects)?;
        if chunk_index < 0 {
            bail!("publication manifest chunk index is invalid");
        }
        let session = self
            .registry_publication_manifest_session(publication_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("publication manifest session does not exist"))?;
        if session.lease_token != lease_token {
            bail!("publication manifest lease token is stale");
        }
        if chunk_index < session.next_chunk_index {
            let receipt = self
                .backend
                .query_opt(
                    "SELECT chunk_digest, object_count
                       FROM registry_publication_manifest_chunks
                      WHERE publication_id = ?1 AND chunk_index = ?2",
                    &vals![publication_id, chunk_index],
                )
                .await?
                .ok_or_else(|| anyhow::anyhow!("publication manifest receipt disappeared"))?;
            let persisted_digest: String = receipt.get(0)?;
            let persisted_count: i64 = receipt.get(1)?;
            if persisted_digest != chunk_digest || persisted_count != i64::try_from(objects.len())?
            {
                bail!("publication manifest chunk retry does not match its receipt");
            }
            return Ok(session);
        }
        if session.state != "accepting"
            || chunk_index != session.next_chunk_index
            || session.lease_expires_at.is_none_or(|at| at <= now)
        {
            bail!("publication manifest chunk is out of order or its lease expired");
        }
        let object_count = i64::try_from(objects.len())?;
        let admitted_object_count = session
            .admitted_object_count
            .checked_add(object_count)
            .ok_or_else(|| anyhow::anyhow!("publication manifest object count overflowed"))?;
        if admitted_object_count > session.expected_object_count {
            bail!("publication manifest contains more objects than declared");
        }
        let lease_expires_at = now
            .checked_add(MANIFEST_SESSION_LEASE_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("publication manifest lease overflowed"))?;

        let mut statements = Vec::with_capacity(objects.len() * 3 + 3);
        statements.push(CheckedStatement::exact(
            "UPDATE registry_publications
                SET mutation_version = mutation_version + 1
              WHERE publication_id = ?1 AND registry_id = ?2
                AND state = 'preparing'",
            vals![publication_id, session.registry_id],
            1,
        ));
        push_manifest_object_statements(
            &mut statements,
            session.registry_id,
            publication_id,
            objects,
            now,
            false,
        );
        statements.push(CheckedStatement::exact(
            "INSERT INTO registry_publication_manifest_chunks
               (publication_id, chunk_index, chunk_digest, object_count,
                accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(publication_id, chunk_index) DO NOTHING",
            vals![publication_id, chunk_index, chunk_digest, object_count, now],
            1,
        ));
        statements.push(CheckedStatement::exact(
            "UPDATE registry_publication_manifest_sessions
                SET admitted_object_count = ?4, next_chunk_index = ?3 + 1,
                    lease_expires_at = ?5, updated_at = ?6,
                    resource_version = resource_version + 1
              WHERE publication_id = ?1 AND lease_token = ?2
                AND state = 'accepting' AND next_chunk_index = ?3
                AND admitted_object_count = ?7 AND lease_expires_at > ?6
                AND expected_object_count >= ?4 AND resource_version = ?8",
            vals![
                publication_id,
                lease_token,
                chunk_index,
                admitted_object_count,
                lease_expires_at,
                now,
                session.admitted_object_count,
                session.resource_version
            ],
            1,
        ));
        self.backend.checked_batch(&statements).await?;
        self.registry_publication_manifest_session(publication_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("publication manifest session disappeared"))
    }

    /// Seals a complete manifest session against its exact publication rows.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale token, expired or incomplete session,
    /// divergent publication inventory, or persistence failure.
    pub async fn seal_registry_publication_manifest_session(
        &self,
        publication_id: &str,
        lease_token: &str,
        placement_ids: &[i64],
        now: i64,
    ) -> Result<RegistryPublicationManifestSessionRecord> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        validate_key_bytes(lease_token, "publication manifest lease token", 64)?;
        let session = self
            .registry_publication_manifest_session(publication_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("publication manifest session does not exist"))?;
        if session.lease_token != lease_token {
            bail!("publication manifest lease token is stale");
        }
        if session.state == "sealed" {
            return Ok(session);
        }
        let placement_ids = placement_ids.iter().copied().collect::<BTreeSet<_>>();
        if placement_ids.is_empty() || placement_ids.iter().any(|id| *id <= 0) {
            bail!("publication manifest has no valid required placement");
        }
        if session.lease_expires_at.is_none_or(|at| at <= now) {
            bail!("publication manifest lease expired");
        }
        let mut statements = Vec::with_capacity(placement_ids.len() + 1);
        for placement_id in placement_ids {
            statements.push(CheckedStatement::exact(
                "INSERT INTO registry_publication_placements
                   (publication_id, registry_id, placement_id, required,
                    state, observed_at)
                 SELECT publication.publication_id, publication.registry_id,
                        placement.id, 1, 'preparing', ?4
                   FROM registry_publications publication
                   JOIN surface_placements placement
                     ON placement.registry_id = publication.registry_id
                  WHERE publication.publication_id = ?1
                    AND publication.registry_id = ?2
                    AND publication.state = 'preparing'
                    AND placement.id = ?3
                 ON CONFLICT(publication_id, placement_id) DO NOTHING",
                vals![publication_id, session.registry_id, placement_id, now],
                1,
            ));
        }
        statements.push(CheckedStatement::exact(
                "UPDATE registry_publication_manifest_sessions
                    SET state = 'sealed', lease_expires_at = NULL,
                        updated_at = ?3, resource_version = resource_version + 1
                  WHERE publication_id = ?1 AND lease_token = ?2
                    AND state = 'accepting' AND lease_expires_at > ?3
                    AND admitted_object_count = expected_object_count
                    AND admitted_object_count = (SELECT COUNT(*)
                      FROM registry_publication_objects object
                     WHERE object.publication_id = ?1)
                    AND EXISTS (SELECT 1 FROM registry_publications publication
                      WHERE publication.publication_id = ?1
                        AND publication.registry_id = registry_publication_manifest_sessions.registry_id
                        AND publication.state = 'preparing'
                        AND publication.manifest_digest = registry_publication_manifest_sessions.manifest_digest)
                    AND resource_version = ?4",
                vals![publication_id, lease_token, now, session.resource_version],
                1,
            ));
        self.backend.checked_batch(&statements).await?;
        self.registry_publication_manifest_session(publication_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("publication manifest session disappeared"))
    }

    /// Admits one bounded manifest page atomically.
    ///
    /// Existing immutable identities must match exactly. A historically
    /// immutable path classified as a mutable pointer may be converted while
    /// retaining its current visible publication owner; all other conflicts
    /// fail the checked transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or duplicate input, an oversized page,
    /// a publication outside `preparing`, an incompatible existing object, or
    /// persistence failure.
    pub async fn admit_registry_publication_manifest_objects(
        &self,
        registry_id: i64,
        publication_id: &str,
        objects: &[RegistryPublicationManifestObject],
    ) -> Result<()> {
        validate_key_bytes(publication_id, "publication id", 64)?;
        if registry_id <= 0 {
            bail!("registry publication manifest page is invalid");
        }
        validate_manifest_objects(objects)?;

        let now = super::unix_now();
        let mut statements = Vec::with_capacity(objects.len() * 3 + 1);
        statements.push(CheckedStatement::exact(
            "UPDATE registry_publications
                SET mutation_version = mutation_version + 1
              WHERE publication_id = ?1 AND registry_id = ?2
                AND state = 'preparing'",
            vals![publication_id, registry_id],
            1,
        ));
        push_manifest_object_statements(
            &mut statements,
            registry_id,
            publication_id,
            objects,
            now,
            true,
        );
        self.backend.checked_batch(&statements).await
    }
}

fn validate_manifest_objects(objects: &[RegistryPublicationManifestObject]) -> Result<()> {
    if objects.is_empty() || objects.len() > MAX_REGISTRY_MANIFEST_ADMISSION_BATCH {
        bail!("registry publication manifest page is invalid");
    }
    let mut paths = BTreeSet::new();
    for object in objects {
        validate_key_bytes(&object.object_key, "surface object key", 512)?;
        if !paths.insert(object.object_key.as_str())
            || object.expected_hash.len() != 64
            || !object
                .expected_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || object.expected_size < 0
            || !matches!(object.object_kind.as_str(), "immutable" | "mutable_pointer")
        {
            bail!("registry publication manifest object is invalid");
        }
    }
    Ok(())
}

fn push_manifest_object_statements(
    statements: &mut Vec<CheckedStatement>,
    registry_id: i64,
    publication_id: &str,
    objects: &[RegistryPublicationManifestObject],
    now: i64,
    idempotent: bool,
) {
    for object in objects {
        if object.object_kind == "mutable_pointer" {
            statements.push(CheckedStatement::unchecked(
                "UPDATE surface_objects
                        SET object_kind = 'mutable_pointer', partition_key = NULL,
                            mutable_publication_id = COALESCE(
                              (SELECT state.current_publication_id
                                 FROM registry_publication_state state
                                WHERE state.registry_id = ?1), ?2),
                            updated_at = ?6, resource_version = resource_version + 1
                      WHERE registry_id = ?1 AND cache_id IS NULL
                        AND object_key = ?3 AND lifecycle_state = 'active'
                        AND object_kind = 'immutable'
                        AND mutable_publication_id IS NULL
                        AND EXISTS (SELECT 1 FROM registry_publications publication
                          WHERE publication.publication_id = ?2
                            AND publication.registry_id = ?1
                            AND publication.state = 'preparing')",
                vals![
                    registry_id,
                    publication_id,
                    object.object_key.as_str(),
                    object.expected_hash.as_str(),
                    object.expected_size,
                    now
                ],
            ));
        }
        let partition_key = (object.object_kind == "immutable")
            .then(|| Sha256::digest(object.object_key.as_bytes()).to_vec());
        statements.push(CheckedStatement::unchecked(
            "INSERT INTO surface_objects
                   (registry_id, cache_id, object_key, object_kind,
                    partition_key, content_hash, size, mutable_publication_id,
                    created_at, updated_at)
                 SELECT ?1, NULL, ?3, ?4, ?7, ?5, ?6,
                        CASE WHEN ?4 = 'mutable_pointer' THEN ?2 ELSE NULL END,
                        ?8, ?8
                   FROM registries registry
                  WHERE registry.id = ?1
                    AND EXISTS (SELECT 1 FROM registry_publications publication
                      WHERE publication.publication_id = ?2
                        AND publication.registry_id = ?1
                        AND publication.state = 'preparing')
                 ON CONFLICT(registry_id, object_key) DO NOTHING",
            vals![
                registry_id,
                publication_id,
                object.object_key.as_str(),
                object.object_kind.as_str(),
                object.expected_hash.as_str(),
                object.expected_size,
                partition_key,
                now
            ],
        ));
        let conflict = if idempotent {
            "DO UPDATE SET object_kind = excluded.object_kind, expected_hash = excluded.expected_hash, expected_size = excluded.expected_size"
        } else {
            "DO NOTHING"
        };
        statements.push(CheckedStatement::exact(
            format!(
                "INSERT INTO registry_publication_objects
                   (publication_id, registry_id, surface_object_id,
                    object_kind, expected_hash, expected_size)
                 SELECT publication.publication_id, publication.registry_id,
                        object.id, ?4, ?5, ?6
                   FROM registry_publications publication
                   JOIN surface_objects object
                     ON object.registry_id = publication.registry_id
                    AND object.cache_id IS NULL AND object.object_key = ?3
                  WHERE publication.publication_id = ?2
                    AND publication.registry_id = ?1
                    AND publication.state = 'preparing'
                    AND object.lifecycle_state = 'active'
                    AND object.object_kind = ?4
                    AND (?4 = 'mutable_pointer'
                      OR (object.content_hash = ?5 AND object.size = ?6))
                 ON CONFLICT(publication_id, surface_object_id) {conflict}"
            ),
            vals![
                registry_id,
                publication_id,
                object.object_key.as_str(),
                object.object_kind.as_str(),
                object.expected_hash.as_str(),
                object.expected_size
            ],
            1,
        ));
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::{NewRegistryPublication, SurfaceTarget};

    #[cfg(feature = "query-timing")]
    use crate::backend::{QueryTimings, SqlxBackend, TimingBackend};

    #[tokio::test]
    async fn manifest_pages_are_atomic_and_idempotent() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("manifest-page", &[], false)
            .await
            .unwrap();
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: "publication-page-test".into(),
            registry_id,
            generation: "generation-page-test".into(),
            manifest_digest: "a".repeat(64),
            refs_digest: "b".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
        let objects = vec![
            RegistryPublicationManifestObject {
                object_key: "objects/aa/one".into(),
                expected_hash: "c".repeat(64),
                expected_size: 10,
                object_kind: "immutable".into(),
            },
            RegistryPublicationManifestObject {
                object_key: "HEAD".into(),
                expected_hash: "d".repeat(64),
                expected_size: 20,
                object_kind: "mutable_pointer".into(),
            },
        ];

        db.admit_registry_publication_manifest_objects(
            registry_id,
            "publication-page-test",
            &objects,
        )
        .await
        .unwrap();
        db.admit_registry_publication_manifest_objects(
            registry_id,
            "publication-page-test",
            &objects,
        )
        .await
        .unwrap();
        assert_eq!(
            db.registry_publication_upload_objects("publication-page-test")
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            db.list_active_surface_objects(SurfaceTarget::Registry(registry_id))
                .await
                .unwrap()
                .len(),
            2
        );

        let conflicting = [RegistryPublicationManifestObject {
            object_key: "objects/aa/one".into(),
            expected_hash: "e".repeat(64),
            expected_size: 10,
            object_kind: "immutable".into(),
        }];
        assert!(db
            .admit_registry_publication_manifest_objects(
                registry_id,
                "publication-page-test",
                &conflicting,
            )
            .await
            .is_err());
        let object = db
            .surface_object_named(SurfaceTarget::Registry(registry_id), "objects/aa/one")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(object.content_hash, Some("c".repeat(64)));
    }

    #[tokio::test]
    async fn manifest_session_resumes_exact_chunks_and_fences_ownership() {
        let db = Database::open_in_memory().await.unwrap();
        let registry_id = db
            .register_registry("manifest-session", &[], false)
            .await
            .unwrap();
        let publication_id = "publication-manifest-session";
        let manifest_digest = "a".repeat(64);
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: publication_id.into(),
            registry_id,
            generation: "generation-manifest-session".into(),
            manifest_digest: manifest_digest.clone(),
            refs_digest: "b".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();

        let session = db
            .begin_registry_publication_manifest_session(
                publication_id,
                registry_id,
                &manifest_digest,
                2,
                "lease-one",
                100,
            )
            .await
            .unwrap();
        assert_eq!(session.next_chunk_index, 0);
        assert_eq!(session.admitted_object_count, 0);

        let immutable = [RegistryPublicationManifestObject {
            object_key: "objects/aa/one".into(),
            expected_hash: "c".repeat(64),
            expected_size: 10,
            object_kind: "immutable".into(),
        }];
        let session = db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-one",
                0,
                &"d".repeat(64),
                &immutable,
                101,
            )
            .await
            .unwrap();
        assert_eq!(session.next_chunk_index, 1);
        assert_eq!(session.admitted_object_count, 1);

        let replay = db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-one",
                0,
                &"d".repeat(64),
                &immutable,
                102,
            )
            .await
            .unwrap();
        assert_eq!(replay, session);
        assert!(db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-one",
                0,
                &"e".repeat(64),
                &immutable,
                102,
            )
            .await
            .is_err());
        assert!(db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-one",
                1,
                &"f".repeat(64),
                &immutable,
                103,
            )
            .await
            .is_err());
        assert_eq!(
            db.registry_publication_manifest_session(publication_id)
                .await
                .unwrap()
                .unwrap()
                .next_chunk_index,
            1
        );

        let reclaimed = db
            .begin_registry_publication_manifest_session(
                publication_id,
                registry_id,
                &manifest_digest,
                2,
                "lease-two",
                2_000,
            )
            .await
            .unwrap();
        assert_eq!(reclaimed.lease_token, "lease-two");
        assert!(db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-one",
                1,
                &"f".repeat(64),
                &[RegistryPublicationManifestObject {
                    object_key: "HEAD".into(),
                    expected_hash: "e".repeat(64),
                    expected_size: 20,
                    object_kind: "mutable_pointer".into(),
                }],
                2_001,
            )
            .await
            .is_err());
        let complete = db
            .append_registry_publication_manifest_chunk(
                publication_id,
                "lease-two",
                1,
                &"f".repeat(64),
                &[RegistryPublicationManifestObject {
                    object_key: "HEAD".into(),
                    expected_hash: "e".repeat(64),
                    expected_size: 20,
                    object_kind: "mutable_pointer".into(),
                }],
                2_001,
            )
            .await
            .unwrap();
        assert_eq!(complete.admitted_object_count, 2);
        assert_eq!(
            db.registry_publication_upload_objects(publication_id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[cfg(feature = "query-timing")]
    #[tokio::test]
    async fn manifest_page_crosses_the_backend_in_one_atomic_batch() {
        let timings = QueryTimings::new();
        let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
        let db = Database::with_backend(Box::new(TimingBackend::new(backend, timings.clone())))
            .await
            .unwrap();
        let registry_id = db
            .register_registry("manifest-backend-batch", &[], false)
            .await
            .unwrap();
        let publication_id = "publication-manifest-backend-batch";
        let manifest_digest = "a".repeat(64);
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: publication_id.into(),
            registry_id,
            generation: "generation-manifest-backend-batch".into(),
            manifest_digest: manifest_digest.clone(),
            refs_digest: "b".repeat(64),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
        let object_count = 64_i64;
        db.begin_registry_publication_manifest_session(
            publication_id,
            registry_id,
            &manifest_digest,
            object_count,
            "lease-batch",
            100,
        )
        .await
        .unwrap();
        let objects = (0..object_count)
            .map(|index| RegistryPublicationManifestObject {
                object_key: format!("objects/aa/{index:04}"),
                expected_hash: format!("{index:064x}"),
                expected_size: index + 1,
                object_kind: "immutable".into(),
            })
            .collect::<Vec<_>>();

        let before = timings.spans().len();
        db.append_registry_publication_manifest_chunk(
            publication_id,
            "lease-batch",
            0,
            &"c".repeat(64),
            &objects,
            101,
        )
        .await
        .unwrap();
        let spans = timings.spans();
        let operations = spans[before..]
            .iter()
            .map(|span| span.op)
            .collect::<Vec<_>>();

        assert_eq!(operations, ["query", "checked_batch", "query"]);
    }
}
