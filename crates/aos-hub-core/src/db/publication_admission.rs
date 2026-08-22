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

impl Database {
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
        if registry_id <= 0
            || objects.is_empty()
            || objects.len() > MAX_REGISTRY_MANIFEST_ADMISSION_BATCH
        {
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
            statements.push(CheckedStatement::exact(
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
                 ON CONFLICT(publication_id, surface_object_id) DO UPDATE SET
                   object_kind = excluded.object_kind,
                   expected_hash = excluded.expected_hash,
                   expected_size = excluded.expected_size",
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
        self.backend.checked_batch(&statements).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::db::{NewRegistryPublication, SurfaceTarget};

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
}
