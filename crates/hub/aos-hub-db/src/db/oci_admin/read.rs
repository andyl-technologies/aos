//! Registry-scoped OCI administration projections.

use anyhow::{bail, Context, Result};
use aos_oci_types::{
    Annotations, Descriptor, ManifestReference, MediaType, Platform, RepositoryName, Sha256Digest,
    Tag,
};

use super::cursor::{finish_page, page_context, validate_page_size};
use super::{
    OciAdminClosureMemberRecord, OciAdminEvidenceRecord, OciAdminLayerRecord,
    OciAdminManifestRecord, OciAdminPage, OciAdminPlatformRecord, OciAdminProvenanceRecord,
    OciAdminPublicationRecord, OciAdminReferrerRecord, OciAdminRepositoryRecord,
    OciAdminTagHistoryRecord, OciAdminTagRecord, OciRepositoryListFilter, OciRetentionPolicyRecord,
    OciTagListFilter,
};
use crate::db::Database;
use crate::value::Row;

const REPOSITORY_ADMIN_COLUMNS: &str = "repository.id, repository.registry_id,
    repository.name, metadata.description, registry.visibility,
    repository.lifecycle_state, repository.resource_version,
    metadata.resource_version,
    (SELECT COUNT(*) FROM oci_repository_objects manifest_link
      WHERE manifest_link.repository_id = repository.id
        AND manifest_link.object_kind = 'manifest'),
    (SELECT COALESCE(SUM(blob.byte_size), 0)
       FROM oci_repository_objects byte_link JOIN oci_blobs blob
         ON blob.registry_id = byte_link.registry_id
        AND blob.digest = byte_link.digest
      WHERE byte_link.repository_id = repository.id),
    (SELECT COALESCE(SUM(CASE WHEN
          (SELECT COUNT(*) FROM oci_repository_objects shared_link
            WHERE shared_link.registry_id = unique_link.registry_id
              AND shared_link.digest = unique_link.digest) = 1
        THEN blob.byte_size ELSE 0 END), 0)
       FROM oci_repository_objects unique_link JOIN oci_blobs blob
         ON blob.registry_id = unique_link.registry_id
        AND blob.digest = unique_link.digest
      WHERE unique_link.repository_id = repository.id),
    (SELECT COUNT(*) FROM oci_tags tag
      WHERE tag.repository_id = repository.id),
    repository.created_at,
    CASE WHEN repository.updated_at > metadata.updated_at
      THEN repository.updated_at ELSE metadata.updated_at END";

const PUBLICATION_ADMIN_COLUMNS: &str = "publication.id, repository.name,
    publication.target_tag, publication.root_digest, publication.catalog_digest,
    publication.release_tag, publication.confirmation_hash,
    publication.topology_digest, publication.required_placement_count,
    publication.source_kind, publication.state, publication.expires_at,
    publication.created_at, publication.committed_at, publication.resource_version";

impl Database {
    /// Lists active repositories within exactly one registry.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale or mismatched cursor,
    /// absent registry, malformed persisted data, or database failure.
    pub async fn list_oci_admin_repositories(
        &self,
        registry_id: i64,
        filter: &OciRepositoryListFilter,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminRepositoryRecord>> {
        let sql_limit = validate_page_size(limit)?;
        validate_repository_filter(filter)?;
        let selector = format!(
            "repository.list\0{}\0{}",
            filter.repository_prefix.as_deref().unwrap_or("*"),
            filter.lifecycle_state.as_deref().unwrap_or("*")
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = match context.after_primary.as_deref() {
            Some(after) => {
                self.backend
                    .query(
                        &format!(
                            "SELECT {REPOSITORY_ADMIN_COLUMNS}
                             FROM oci_repositories repository
                             JOIN registries registry ON registry.id = repository.registry_id
                             JOIN oci_repository_metadata metadata
                               ON metadata.repository_id = repository.id
                              AND metadata.registry_id = repository.registry_id
                             WHERE repository.registry_id = ?1
                               AND (?2 IS NULL OR substr(repository.name, 1, length(?2)) = ?2)
                               AND (?3 IS NULL OR repository.lifecycle_state = ?3)
                               AND repository.name > ?4
                             ORDER BY repository.name LIMIT ?5"
                        ),
                        &vals![
                            registry_id,
                            filter.repository_prefix.as_deref(),
                            filter.lifecycle_state.as_deref(),
                            after,
                            sql_limit
                        ],
                    )
                    .await?
            }
            None => {
                self.backend
                    .query(
                        &format!(
                            "SELECT {REPOSITORY_ADMIN_COLUMNS}
                             FROM oci_repositories repository
                             JOIN registries registry ON registry.id = repository.registry_id
                             JOIN oci_repository_metadata metadata
                               ON metadata.repository_id = repository.id
                              AND metadata.registry_id = repository.registry_id
                             WHERE repository.registry_id = ?1
                               AND (?2 IS NULL OR substr(repository.name, 1, length(?2)) = ?2)
                               AND (?3 IS NULL OR repository.lifecycle_state = ?3)
                             ORDER BY repository.name LIMIT ?4"
                        ),
                        &vals![
                            registry_id,
                            filter.repository_prefix.as_deref(),
                            filter.lifecycle_state.as_deref(),
                            sql_limit
                        ],
                    )
                    .await?
            }
        };
        let items = rows
            .iter()
            .map(row_to_admin_repository)
            .collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.name.as_str().to_string(), String::new())
        })
    }

    /// Returns one active repository from exactly one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_repository(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
    ) -> Result<Option<OciAdminRepositoryRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {REPOSITORY_ADMIN_COLUMNS}
                     FROM oci_repositories repository
                     JOIN registries registry ON registry.id = repository.registry_id
                     JOIN oci_repository_metadata metadata
                       ON metadata.repository_id = repository.id
                      AND metadata.registry_id = repository.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'"
                ),
                &vals![registry_id, repository.as_str()],
            )
            .await?
            .as_ref()
            .map(row_to_admin_repository)
            .transpose()
    }

    /// Lists current tags from a registry-bound repository.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale or mismatched cursor,
    /// absent registry, malformed persisted data, or database failure.
    pub async fn list_oci_admin_tags(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        filter: &OciTagListFilter,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminTagRecord>> {
        let sql_limit = validate_page_size(limit)?;
        validate_tag_filter(filter)?;
        let selector = format!(
            "tag.list\0{}\0{}\0{}",
            repository.as_str(),
            filter.tag_prefix.as_deref().unwrap_or("*"),
            filter.ownership_kind.as_deref().unwrap_or("*")
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = match context.after_primary.as_deref() {
            Some(after) => {
                self.backend
                    .query(
                        "SELECT tag.name, tag.digest, link.media_type, tag.source_kind,
                                (SELECT root.release_tag FROM oci_release_roots root
                                  WHERE root.registry_id = tag.registry_id
                                    AND root.repository_id = tag.repository_id
                                    AND root.index_digest = tag.digest
                                  ORDER BY root.release_tag LIMIT 1),
                                CASE WHEN tag.source_kind = 'channel' THEN tag.name ELSE NULL END,
                                tag.resource_version, tag.created_at, tag.updated_at
                         FROM oci_tags tag JOIN oci_repositories repository
                           ON repository.id = tag.repository_id
                          AND repository.registry_id = tag.registry_id
                         JOIN oci_repository_objects link
                           ON link.registry_id = tag.registry_id
                          AND link.repository_id = tag.repository_id
                          AND link.digest = tag.digest
                         WHERE repository.registry_id = ?1 AND repository.name = ?2
                           AND repository.lifecycle_state = 'active'
                           AND (?3 IS NULL OR substr(tag.name, 1, length(?3)) = ?3)
                           AND (?4 IS NULL OR tag.source_kind = ?4) AND tag.name > ?5
                         ORDER BY tag.name LIMIT ?6",
                        &vals![
                            registry_id,
                            repository.as_str(),
                            filter.tag_prefix.as_deref(),
                            filter.ownership_kind.as_deref(),
                            after,
                            sql_limit
                        ],
                    )
                    .await?
            }
            None => {
                self.backend
                    .query(
                        "SELECT tag.name, tag.digest, link.media_type, tag.source_kind,
                                (SELECT root.release_tag FROM oci_release_roots root
                                  WHERE root.registry_id = tag.registry_id
                                    AND root.repository_id = tag.repository_id
                                    AND root.index_digest = tag.digest
                                  ORDER BY root.release_tag LIMIT 1),
                                CASE WHEN tag.source_kind = 'channel' THEN tag.name ELSE NULL END,
                                tag.resource_version, tag.created_at, tag.updated_at
                         FROM oci_tags tag JOIN oci_repositories repository
                           ON repository.id = tag.repository_id
                          AND repository.registry_id = tag.registry_id
                         JOIN oci_repository_objects link
                           ON link.registry_id = tag.registry_id
                          AND link.repository_id = tag.repository_id
                          AND link.digest = tag.digest
                         WHERE repository.registry_id = ?1 AND repository.name = ?2
                           AND repository.lifecycle_state = 'active'
                           AND (?3 IS NULL OR substr(tag.name, 1, length(?3)) = ?3)
                           AND (?4 IS NULL OR tag.source_kind = ?4)
                         ORDER BY tag.name LIMIT ?5",
                        &vals![
                            registry_id,
                            repository.as_str(),
                            filter.tag_prefix.as_deref(),
                            filter.ownership_kind.as_deref(),
                            sql_limit
                        ],
                    )
                    .await?
            }
        };
        let items = rows.iter().map(row_to_tag).collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.name.as_str().to_string(), String::new())
        })
    }

    /// Resolves one exact tag without accepting a repository id as authority.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn resolve_oci_admin_tag(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        tag: &Tag,
    ) -> Result<Option<OciAdminTagRecord>> {
        self.backend
            .query_opt(
                "SELECT tag.name, tag.digest, link.media_type, tag.source_kind,
                        (SELECT root.release_tag FROM oci_release_roots root
                          WHERE root.registry_id = tag.registry_id
                            AND root.repository_id = tag.repository_id
                            AND root.index_digest = tag.digest
                          ORDER BY root.release_tag LIMIT 1),
                        CASE WHEN tag.source_kind = 'channel' THEN tag.name ELSE NULL END,
                        tag.resource_version, tag.created_at, tag.updated_at
                 FROM oci_tags tag JOIN oci_repositories repository
                   ON repository.id = tag.repository_id
                  AND repository.registry_id = tag.registry_id
                 JOIN oci_repository_objects link
                   ON link.registry_id = tag.registry_id
                  AND link.repository_id = tag.repository_id
                  AND link.digest = tag.digest
                 WHERE repository.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active' AND tag.name = ?3",
                &vals![registry_id, repository.as_str(), tag.as_str()],
            )
            .await?
            .as_ref()
            .map(row_to_tag)
            .transpose()
    }

    /// Lists immutable history for all tags or one selected tag.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale or mismatched cursor,
    /// malformed persisted data, or database failure.
    pub async fn list_oci_admin_tag_history(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        tag: Option<&Tag>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminTagHistoryRecord>> {
        let sql_limit = validate_page_size(limit)?;
        let selector = format!(
            "tag.history\0{}\0{}",
            repository.as_str(),
            tag.map(Tag::as_str).unwrap_or("*")
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = if let Some(after_time) = context.after_primary.as_deref() {
            let after_time = after_time
                .parse::<i64>()
                .context("OCI tag-history cursor time is malformed")?;
            let after_id = context
                .after_secondary
                .as_deref()
                .context("OCI tag-history cursor id is absent")?;
            self.backend
                .query(
                    "SELECT history.id, history.name, history.prior_digest,
                            history.next_digest, history.source_kind,
                            history.actor_id, history.tag_resource_version,
                            history.changed_at
                     FROM oci_tag_history history JOIN oci_repositories repository
                       ON repository.id = history.repository_id
                      AND repository.registry_id = history.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND (?3 IS NULL OR history.name = ?3)
                       AND (history.changed_at < ?4 OR
                         (history.changed_at = ?4 AND history.id < ?5))
                     ORDER BY history.changed_at DESC, history.id DESC LIMIT ?6",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        tag.map(Tag::as_str),
                        after_time,
                        after_id,
                        sql_limit
                    ],
                )
                .await?
        } else {
            self.backend
                .query(
                    "SELECT history.id, history.name, history.prior_digest,
                            history.next_digest, history.source_kind,
                            history.actor_id, history.tag_resource_version,
                            history.changed_at
                     FROM oci_tag_history history JOIN oci_repositories repository
                       ON repository.id = history.repository_id
                      AND repository.registry_id = history.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND (?3 IS NULL OR history.name = ?3)
                     ORDER BY history.changed_at DESC, history.id DESC LIMIT ?4",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        tag.map(Tag::as_str),
                        sql_limit
                    ],
                )
                .await?
        };
        let items = rows
            .iter()
            .map(row_to_tag_history)
            .collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.changed_at.to_string(), item.id.clone())
        })
    }

    /// Returns one repository-bound manifest or index by digest or tag.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_manifest(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        reference: &ManifestReference,
    ) -> Result<Option<OciAdminManifestRecord>> {
        let Some(repository) = self.oci_repository(registry_id, repository).await? else {
            return Ok(None);
        };
        let Some(manifest) = self
            .oci_manifest_for_repository(repository.id, reference)
            .await?
        else {
            return Ok(None);
        };
        let counts = self
            .backend
            .query_opt(
                "SELECT SUM(CASE WHEN edge_role = 'layer' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN edge_role = 'child' THEN 1 ELSE 0 END)
                 FROM oci_descriptor_edges
                 WHERE registry_id = ?1 AND manifest_digest = ?2",
                &vals![registry_id, manifest.digest.to_string()],
            )
            .await?
            .context("OCI manifest edge counts disappeared")?;
        Ok(Some(OciAdminManifestRecord {
            digest: manifest.digest,
            media_type: manifest.media_type,
            byte_size: manifest.byte_size,
            artifact_type: manifest.artifact_type,
            subject_digest: manifest.subject_digest,
            config_digest: manifest.config_digest,
            annotations: manifest.annotations,
            layer_count: checked_u32(
                counts.get::<Option<i64>>(0)?.unwrap_or(0),
                "OCI manifest layer count",
            )?,
            child_count: checked_u32(
                counts.get::<Option<i64>>(1)?.unwrap_or(0),
                "OCI manifest child count",
            )?,
            created_at: manifest.created_at,
        }))
    }

    /// Lists runnable platforms beneath one repository-bound root.
    ///
    /// A direct image manifest produces one row; an image index produces one
    /// row per child descriptor. Artifact manifests produce no platform rows.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale cursor, non-runnable root,
    /// malformed persisted data, or database failure.
    pub async fn list_oci_admin_platforms(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminPlatformRecord>> {
        let sql_limit = validate_page_size(limit)?;
        let selector = format!("platform.list\0{}\0{root_digest}", repository.as_str());
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = match context.after_primary.as_deref() {
            Some(after) => {
                self.backend
                    .query(
                        "SELECT projection.root_digest, projection.manifest_digest,
                                manifest.media_type, manifest.byte_size,
                                projection.config_digest, projection.operating_system,
                                projection.architecture, projection.variant,
                                projection.os_version, projection.os_features_json,
                                projection.aos_system, projection.compressed_byte_size,
                                projection.unpacked_byte_size, projection.layer_count,
                                projection.config_json
                         FROM oci_image_config_projections projection
                         JOIN oci_repositories repository
                           ON repository.id = projection.repository_id
                          AND repository.registry_id = projection.registry_id
                         JOIN oci_manifests manifest
                           ON manifest.registry_id = projection.registry_id
                          AND manifest.digest = projection.manifest_digest
                         WHERE projection.registry_id = ?1 AND repository.name = ?2
                           AND repository.lifecycle_state = 'active'
                           AND projection.root_digest = ?3
                           AND projection.manifest_digest > ?4
                         ORDER BY projection.manifest_digest LIMIT ?5",
                        &vals![
                            registry_id,
                            repository.as_str(),
                            root_digest.to_string(),
                            after,
                            sql_limit
                        ],
                    )
                    .await?
            }
            None => {
                self.backend
                    .query(
                        "SELECT projection.root_digest, projection.manifest_digest,
                                manifest.media_type, manifest.byte_size,
                                projection.config_digest, projection.operating_system,
                                projection.architecture, projection.variant,
                                projection.os_version, projection.os_features_json,
                                projection.aos_system, projection.compressed_byte_size,
                                projection.unpacked_byte_size, projection.layer_count,
                                projection.config_json
                         FROM oci_image_config_projections projection
                         JOIN oci_repositories repository
                           ON repository.id = projection.repository_id
                          AND repository.registry_id = projection.registry_id
                         JOIN oci_manifests manifest
                           ON manifest.registry_id = projection.registry_id
                          AND manifest.digest = projection.manifest_digest
                         WHERE projection.registry_id = ?1 AND repository.name = ?2
                           AND repository.lifecycle_state = 'active'
                           AND projection.root_digest = ?3
                         ORDER BY projection.manifest_digest LIMIT ?4",
                        &vals![
                            registry_id,
                            repository.as_str(),
                            root_digest.to_string(),
                            sql_limit
                        ],
                    )
                    .await?
            }
        };
        let items = rows
            .iter()
            .map(row_to_platform)
            .collect::<Result<Vec<_>>>()?;

        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.manifest_digest.to_string(), String::new())
        })
    }

    /// Returns one exact platform beneath a repository-bound root.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_platform(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        platform: &Platform,
    ) -> Result<Option<OciAdminPlatformRecord>> {
        platform.validate()?;
        let os_features_json = serde_json::to_string(&platform.os_features)
            .context("encoding OCI platform OS features selector")?;
        self.backend
            .query_opt(
                "SELECT projection.root_digest, projection.manifest_digest,
                        manifest.media_type, manifest.byte_size,
                        projection.config_digest, projection.operating_system,
                        projection.architecture, projection.variant,
                        projection.os_version, projection.os_features_json,
                        projection.aos_system, projection.compressed_byte_size,
                        projection.unpacked_byte_size, projection.layer_count,
                        projection.config_json
                 FROM oci_image_config_projections projection
                 JOIN oci_repositories repository
                   ON repository.id = projection.repository_id
                  AND repository.registry_id = projection.registry_id
                 JOIN oci_manifests manifest
                   ON manifest.registry_id = projection.registry_id
                  AND manifest.digest = projection.manifest_digest
                 WHERE projection.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'
                   AND projection.root_digest = ?3
                   AND projection.operating_system = ?4
                   AND projection.architecture = ?5
                   AND ((?6 IS NULL AND projection.variant IS NULL)
                     OR projection.variant = ?6)
                   AND ((?7 IS NULL AND projection.os_version IS NULL)
                     OR projection.os_version = ?7)
                   AND projection.os_features_json = ?8",
                &vals![
                    registry_id,
                    repository.as_str(),
                    root_digest.to_string(),
                    platform.os,
                    platform.architecture,
                    platform.variant.as_deref(),
                    platform.os_version.as_deref(),
                    os_features_json
                ],
            )
            .await?
            .as_ref()
            .map(row_to_platform)
            .transpose()
    }

    /// Lists ordered layer or artifact-payload descriptors for one manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale cursor, malformed
    /// persisted data, or database failure.
    pub async fn list_oci_admin_layers(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminLayerRecord>> {
        let sql_limit = validate_page_size(limit)?;
        let selector = format!(
            "layer.list\0{}\0{root_digest}\0{manifest_digest}",
            repository.as_str()
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = if let Some(after_ordinal) = context.after_primary.as_deref() {
            let after_ordinal = after_ordinal
                .parse::<i64>()
                .context("OCI layer cursor ordinal is malformed")?;
            self.backend
                .query(
                    "SELECT layer.root_digest, layer.manifest_digest, layer.ordinal,
                            layer.digest, layer.media_type, layer.compressed_byte_size,
                            layer.unpacked_byte_size,
                            (SELECT COUNT(DISTINCT shared.repository_id)
                               FROM oci_repository_objects shared
                              WHERE shared.registry_id = layer.registry_id
                                AND shared.digest = layer.digest),
                            layer.diff_id, layer.closure_group
                     FROM oci_release_layers layer
                     JOIN oci_repositories repository
                       ON repository.id = layer.repository_id
                      AND repository.registry_id = layer.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND layer.root_digest = ?3 AND layer.manifest_digest = ?4
                       AND layer.ordinal > ?5
                     ORDER BY layer.ordinal LIMIT ?6",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        root_digest.to_string(),
                        manifest_digest.to_string(),
                        after_ordinal,
                        sql_limit
                    ],
                )
                .await?
        } else {
            self.backend
                .query(
                    "SELECT layer.root_digest, layer.manifest_digest, layer.ordinal,
                            layer.digest, layer.media_type, layer.compressed_byte_size,
                            layer.unpacked_byte_size,
                            (SELECT COUNT(DISTINCT shared.repository_id)
                               FROM oci_repository_objects shared
                              WHERE shared.registry_id = layer.registry_id
                                AND shared.digest = layer.digest),
                            layer.diff_id, layer.closure_group
                     FROM oci_release_layers layer
                     JOIN oci_repositories repository
                       ON repository.id = layer.repository_id
                      AND repository.registry_id = layer.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND layer.root_digest = ?3 AND layer.manifest_digest = ?4
                     ORDER BY layer.ordinal LIMIT ?5",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        root_digest.to_string(),
                        manifest_digest.to_string(),
                        sql_limit
                    ],
                )
                .await?
        };
        let items = rows.iter().map(row_to_layer).collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.ordinal.to_string(), String::new())
        })
    }

    /// Returns one exact layer within a repository-bound manifest.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_layer(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        layer_digest: Sha256Digest,
    ) -> Result<Option<OciAdminLayerRecord>> {
        self.backend
            .query_opt(
                "SELECT layer.root_digest, layer.manifest_digest, layer.ordinal,
                        layer.digest, layer.media_type, layer.compressed_byte_size,
                        layer.unpacked_byte_size,
                        (SELECT COUNT(DISTINCT shared.repository_id)
                           FROM oci_repository_objects shared
                          WHERE shared.registry_id = layer.registry_id
                            AND shared.digest = layer.digest),
                        layer.diff_id, layer.closure_group
                 FROM oci_release_layers layer JOIN oci_repositories repository
                   ON repository.id = layer.repository_id
                  AND repository.registry_id = layer.registry_id
                 WHERE layer.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'
                   AND layer.root_digest = ?3 AND layer.manifest_digest = ?4
                   AND layer.digest = ?5
                 ORDER BY layer.root_digest LIMIT 1",
                &vals![
                    registry_id,
                    repository.as_str(),
                    root_digest.to_string(),
                    manifest_digest.to_string(),
                    layer_digest.to_string()
                ],
            )
            .await?
            .as_ref()
            .map(row_to_layer)
            .transpose()
    }

    /// Lists referrer descriptors for one exact repository subject.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale cursor, malformed
    /// persisted data, or database failure.
    pub async fn list_oci_admin_referrers(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        subject: Sha256Digest,
        artifact_type: Option<MediaType>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminReferrerRecord>> {
        let sql_limit = validate_page_size(limit)?;
        let selector = format!(
            "referrer.list\0{}\0{subject}\0{}",
            repository.as_str(),
            artifact_type.map(MediaType::as_str).unwrap_or("*")
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = if let Some(after) = context.after_primary.as_deref() {
            self.backend
                .query(
                    "SELECT manifest.media_type, manifest.digest,
                            manifest.byte_size, manifest.artifact_type,
                            manifest.annotations_json, manifest.subject_digest,
                            CASE WHEN EXISTS (SELECT 1 FROM oci_release_evidence evidence
                              WHERE evidence.registry_id = manifest.registry_id
                                AND evidence.repository_id = repository.id
                                AND evidence.referrer_digest = manifest.digest
                                AND evidence.verification = 'verified')
                              THEN 'verified' ELSE 'unverified' END,
                            manifest.created_at
                     FROM oci_manifests manifest
                     JOIN oci_repository_objects link
                       ON link.registry_id = manifest.registry_id
                      AND link.digest = manifest.digest
                     JOIN oci_repositories repository
                       ON repository.id = link.repository_id
                      AND repository.registry_id = link.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND manifest.subject_digest = ?3
                       AND manifest.artifact_type IS NOT NULL
                       AND (?4 IS NULL OR manifest.artifact_type = ?4)
                       AND manifest.digest > ?5
                     ORDER BY manifest.digest LIMIT ?6",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        subject.to_string(),
                        artifact_type.map(MediaType::as_str),
                        after,
                        sql_limit
                    ],
                )
                .await?
        } else {
            self.backend
                .query(
                    "SELECT manifest.media_type, manifest.digest,
                            manifest.byte_size, manifest.artifact_type,
                            manifest.annotations_json, manifest.subject_digest,
                            CASE WHEN EXISTS (SELECT 1 FROM oci_release_evidence evidence
                              WHERE evidence.registry_id = manifest.registry_id
                                AND evidence.repository_id = repository.id
                                AND evidence.referrer_digest = manifest.digest
                                AND evidence.verification = 'verified')
                              THEN 'verified' ELSE 'unverified' END,
                            manifest.created_at
                     FROM oci_manifests manifest
                     JOIN oci_repository_objects link
                       ON link.registry_id = manifest.registry_id
                      AND link.digest = manifest.digest
                     JOIN oci_repositories repository
                       ON repository.id = link.repository_id
                      AND repository.registry_id = link.registry_id
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                       AND repository.lifecycle_state = 'active'
                       AND manifest.subject_digest = ?3
                       AND manifest.artifact_type IS NOT NULL
                       AND (?4 IS NULL OR manifest.artifact_type = ?4)
                     ORDER BY manifest.digest LIMIT ?5",
                    &vals![
                        registry_id,
                        repository.as_str(),
                        subject.to_string(),
                        artifact_type.map(MediaType::as_str),
                        sql_limit
                    ],
                )
                .await?
        };
        let items = rows
            .iter()
            .map(row_to_referrer)
            .collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.descriptor.digest.to_string(), String::new())
        })
    }

    /// Lists secret-free durable publication summaries for one registry.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale cursor, malformed
    /// persisted data, or database failure.
    pub async fn list_oci_admin_publications(
        &self,
        registry_id: i64,
        repository: Option<&RepositoryName>,
        state: Option<&str>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminPublicationRecord>> {
        let sql_limit = validate_page_size(limit)?;
        if state.is_some_and(|state| {
            !matches!(
                state,
                "preparing" | "committing" | "ready" | "aborted" | "failed"
            )
        }) {
            bail!("OCI publication state filter is invalid");
        }
        let selector = format!(
            "publication.list\0{}\0{}",
            repository.map(RepositoryName::as_str).unwrap_or("*"),
            state.unwrap_or("*")
        );
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = if let Some(after_time) = context.after_primary.as_deref() {
            let after_time = after_time
                .parse::<i64>()
                .context("OCI publication cursor time is malformed")?;
            let after_id = context
                .after_secondary
                .as_deref()
                .context("OCI publication cursor id is absent")?;
            self.backend
                .query(
                    &format!(
                        "SELECT {PUBLICATION_ADMIN_COLUMNS}
                         FROM oci_publication_sessions publication
                         JOIN oci_repositories repository
                           ON repository.id = publication.repository_id
                          AND repository.registry_id = publication.registry_id
                         WHERE publication.registry_id = ?1
                           AND (?2 IS NULL OR repository.name = ?2)
                           AND (?3 IS NULL OR publication.state = ?3)
                           AND (publication.created_at < ?4 OR
                             (publication.created_at = ?4 AND publication.id < ?5))
                         ORDER BY publication.created_at DESC, publication.id DESC LIMIT ?6"
                    ),
                    &vals![
                        registry_id,
                        repository.map(RepositoryName::as_str),
                        state,
                        after_time,
                        after_id,
                        sql_limit
                    ],
                )
                .await?
        } else {
            self.backend
                .query(
                    &format!(
                        "SELECT {PUBLICATION_ADMIN_COLUMNS}
                         FROM oci_publication_sessions publication
                         JOIN oci_repositories repository
                           ON repository.id = publication.repository_id
                          AND repository.registry_id = publication.registry_id
                         WHERE publication.registry_id = ?1
                           AND (?2 IS NULL OR repository.name = ?2)
                           AND (?3 IS NULL OR publication.state = ?3)
                         ORDER BY publication.created_at DESC, publication.id DESC LIMIT ?4"
                    ),
                    &vals![
                        registry_id,
                        repository.map(RepositoryName::as_str),
                        state,
                        sql_limit
                    ],
                )
                .await?
        };
        let items = rows
            .iter()
            .map(row_to_publication)
            .collect::<Result<Vec<_>>>()?;
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.created_at.to_string(), item.id.clone())
        })
    }

    /// Returns one secret-free publication summary from exactly one registry.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_publication(
        &self,
        registry_id: i64,
        publication_id: &str,
    ) -> Result<Option<OciAdminPublicationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {PUBLICATION_ADMIN_COLUMNS}
                     FROM oci_publication_sessions publication
                     JOIN oci_repositories repository
                       ON repository.id = publication.repository_id
                      AND repository.registry_id = publication.registry_id
                     WHERE publication.registry_id = ?1 AND publication.id = ?2"
                ),
                &vals![registry_id, publication_id],
            )
            .await?
            .as_ref()
            .map(row_to_publication)
            .transpose()
    }

    /// Lists signed release identities that publish one exact repository root.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, stale cursor, malformed
    /// persisted data, or database failure.
    pub async fn list_oci_admin_release_provenance(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<OciAdminPage<OciAdminProvenanceRecord>> {
        let sql_limit = validate_page_size(limit)?;
        let selector = format!("provenance.list\0{}\0{root_digest}", repository.as_str());
        let context = page_context(self, registry_id, &selector, cursor).await?;
        let rows = self
            .backend
            .query(
                "SELECT repository.name, provenance.root_digest,
                        provenance.package_name, provenance.release_tag,
                        COALESCE(provenance.channel_name,
                          (SELECT tag.name FROM oci_tags tag
                           WHERE tag.repository_id = provenance.repository_id
                             AND tag.registry_id = provenance.registry_id
                             AND tag.digest = provenance.root_digest
                             AND tag.source_kind = 'channel'
                           ORDER BY tag.name LIMIT 1)),
                        provenance.signed_release_root,
                        provenance.catalog_digest, provenance.verification,
                        provenance.verified_at, repository.id
                 FROM oci_release_provenance provenance
                 JOIN oci_repositories repository
                   ON repository.id = provenance.repository_id
                  AND repository.registry_id = provenance.registry_id
                 WHERE provenance.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'
                   AND provenance.root_digest = ?3
                   AND (?4 IS NULL OR provenance.release_tag > ?4)
                 ORDER BY provenance.release_tag LIMIT ?5",
                &vals![
                    registry_id,
                    repository.as_str(),
                    root_digest.to_string(),
                    context.after_primary.as_deref(),
                    sql_limit
                ],
            )
            .await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(
                self.hydrate_oci_admin_provenance(registry_id, root_digest, row)
                    .await?,
            );
        }
        finish_page(items, limit, registry_id, &selector, &context, |item| {
            (item.release.clone(), String::new())
        })
    }

    /// Returns signed source provenance for one exact release and root.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_release_provenance(
        &self,
        registry_id: i64,
        repository: &RepositoryName,
        root_digest: Sha256Digest,
        release_tag: &str,
    ) -> Result<Option<OciAdminProvenanceRecord>> {
        let Some(row) = self
            .backend
            .query_opt(
                "SELECT repository.name, provenance.root_digest,
                        provenance.package_name, provenance.release_tag,
                        COALESCE(provenance.channel_name,
                          (SELECT tag.name FROM oci_tags tag
                           WHERE tag.repository_id = provenance.repository_id
                             AND tag.registry_id = provenance.registry_id
                             AND tag.digest = provenance.root_digest
                             AND tag.source_kind = 'channel'
                           ORDER BY tag.name LIMIT 1)),
                        provenance.signed_release_root,
                        provenance.catalog_digest, provenance.verification,
                        provenance.verified_at, repository.id
                 FROM oci_release_provenance provenance
                 JOIN oci_repositories repository
                   ON repository.id = provenance.repository_id
                  AND repository.registry_id = provenance.registry_id
                 WHERE provenance.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'
                   AND provenance.root_digest = ?3
                   AND provenance.release_tag = ?4",
                &vals![
                    registry_id,
                    repository.as_str(),
                    root_digest.to_string(),
                    release_tag
                ],
            )
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(
            self.hydrate_oci_admin_provenance(registry_id, root_digest, &row)
                .await?,
        ))
    }

    async fn hydrate_oci_admin_provenance(
        &self,
        registry_id: i64,
        root_digest: Sha256Digest,
        row: &Row,
    ) -> Result<OciAdminProvenanceRecord> {
        let repository_id: i64 = row.get(9)?;
        let release_tag: String = row.get(3)?;
        let closure_members = self
            .backend
            .query(
                "SELECT store_path, nar_hash, nar_size, layer_digest, is_direct
                 FROM oci_release_closure_members
                 WHERE registry_id = ?1 AND repository_id = ?2 AND root_digest = ?3
                   AND release_tag = ?4
                 ORDER BY store_path",
                &vals![
                    registry_id,
                    repository_id,
                    root_digest.to_string(),
                    release_tag
                ],
            )
            .await?
            .iter()
            .map(row_to_closure_member)
            .collect::<Result<Vec<_>>>()?;
        let evidence = self
            .backend
            .query(
                "SELECT evidence_kind, digest, media_type, verification, referrer_digest
                 FROM oci_release_evidence
                 WHERE registry_id = ?1 AND repository_id = ?2 AND root_digest = ?3
                   AND release_tag = ?4
                 ORDER BY evidence_kind",
                &vals![
                    registry_id,
                    repository_id,
                    root_digest.to_string(),
                    release_tag
                ],
            )
            .await?
            .iter()
            .map(row_to_evidence)
            .collect::<Result<Vec<_>>>()?;
        row_to_provenance(row, closure_members, evidence)
    }

    /// Returns the configured registry retention policy, when present.
    ///
    /// Absence is distinct from a policy with zero values and lets the service
    /// display instance defaults without pretending they are persisted.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_admin_retention_policy(
        &self,
        registry_id: i64,
    ) -> Result<Option<OciRetentionPolicyRecord>> {
        self.backend
            .query_opt(
                "SELECT policy.registry_id, policy.untagged_grace_seconds,
                        policy.deleted_tag_history_seconds,
                        policy.recent_manual_tag_revisions,
                        policy.retain_referrers, policy.resource_version, policy.updated_at
                 FROM oci_retention_policies policy JOIN registries registry
                   ON registry.id = policy.registry_id
                 WHERE policy.registry_id = ?1",
                &vals![registry_id],
            )
            .await?
            .as_ref()
            .map(row_to_retention)
            .transpose()
    }
}

fn row_to_admin_repository(row: &Row) -> Result<OciAdminRepositoryRecord> {
    Ok(OciAdminRepositoryRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        name: RepositoryName::parse(&row.get::<String>(2)?)?,
        description: row.get(3)?,
        inherited_visibility: row.get(4)?,
        lifecycle_state: row.get(5)?,
        resource_version: row.get(6)?,
        metadata_resource_version: row.get(7)?,
        manifest_count: checked_u64(row.get(8)?, "OCI repository manifest count")?,
        compressed_byte_size: checked_u64(row.get(9)?, "OCI repository compressed size")?,
        unique_byte_size: checked_u64(row.get(10)?, "OCI repository unique size")?,
        tag_count: checked_u64(row.get(11)?, "OCI repository tag count")?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn row_to_tag(row: &Row) -> Result<OciAdminTagRecord> {
    Ok(OciAdminTagRecord {
        name: Tag::parse(&row.get::<String>(0)?)?,
        digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        media_type: MediaType::parse(&row.get::<String>(2)?)?,
        ownership_kind: row.get(3)?,
        release: row.get(4)?,
        channel: row.get(5)?,
        resource_version: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn row_to_tag_history(row: &Row) -> Result<OciAdminTagHistoryRecord> {
    Ok(OciAdminTagHistoryRecord {
        id: row.get(0)?,
        name: Tag::parse(&row.get::<String>(1)?)?,
        prior_digest: row
            .get::<Option<String>>(2)?
            .map(|digest| Sha256Digest::parse(&digest))
            .transpose()?,
        next_digest: row
            .get::<Option<String>>(3)?
            .map(|digest| Sha256Digest::parse(&digest))
            .transpose()?,
        source_kind: row.get(4)?,
        actor_id: row.get(5)?,
        resource_version: row.get(6)?,
        changed_at: row.get(7)?,
    })
}

fn row_to_platform(row: &Row) -> Result<OciAdminPlatformRecord> {
    let os_features = serde_json::from_str::<Vec<String>>(&row.get::<String>(9)?)
        .context("decoding persisted OCI platform OS features")?;
    let platform = Platform {
        os: row.get::<String>(5)?,
        architecture: row.get::<String>(6)?,
        variant: row.get(7)?,
        os_version: row.get(8)?,
        os_features,
        features: Vec::new(),
    };
    platform.validate()?;
    Ok(OciAdminPlatformRecord {
        root_digest: Sha256Digest::parse(&row.get::<String>(0)?)?,
        manifest_digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        media_type: MediaType::parse(&row.get::<String>(2)?)?,
        byte_size: checked_u64(row.get(3)?, "OCI platform manifest byte size")?,
        platform,
        config_digest: Sha256Digest::parse(&row.get::<String>(4)?)?,
        aos_system: row.get(10)?,
        compressed_byte_size: checked_u64(row.get(11)?, "OCI platform compressed size")?,
        unpacked_byte_size: checked_u64(row.get(12)?, "OCI platform unpacked size")?,
        layer_count: checked_u32(row.get(13)?, "OCI platform layer count")?,
        config_json: row.get(14)?,
    })
}

fn row_to_layer(row: &Row) -> Result<OciAdminLayerRecord> {
    let descriptor = Descriptor {
        digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
        media_type: MediaType::parse(&row.get::<String>(4)?)?,
        size: checked_u64(row.get(5)?, "OCI layer byte size")?,
        urls: Vec::new(),
        annotations: Annotations::default(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    descriptor.validate()?;
    Ok(OciAdminLayerRecord {
        root_digest: Sha256Digest::parse(&row.get::<String>(0)?)?,
        manifest_digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        ordinal: checked_u32(row.get(2)?, "OCI layer ordinal")?,
        descriptor,
        unpacked_byte_size: checked_u64(row.get(6)?, "OCI layer unpacked size")?,
        shared_repository_count: checked_u64(row.get(7)?, "OCI layer sharing count")?,
        diff_id: Sha256Digest::parse(&row.get::<String>(8)?)?,
        closure_group: row.get(9)?,
    })
}

fn row_to_referrer(row: &Row) -> Result<OciAdminReferrerRecord> {
    let descriptor = Descriptor {
        media_type: MediaType::parse(&row.get::<String>(0)?)?,
        digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        size: checked_u64(row.get(2)?, "OCI referrer byte size")?,
        artifact_type: row
            .get::<Option<String>>(3)?
            .map(|media_type| MediaType::parse(&media_type))
            .transpose()?,
        annotations: parse_annotations(&row.get::<String>(4)?)?,
        urls: Vec::new(),
        data: None,
        platform: None,
    };
    descriptor.validate()?;
    Ok(OciAdminReferrerRecord {
        subject_digest: Sha256Digest::parse(
            &row.get::<Option<String>>(5)?
                .context("OCI referrer has no subject digest")?,
        )?,
        descriptor,
        verification: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn row_to_publication(row: &Row) -> Result<OciAdminPublicationRecord> {
    Ok(OciAdminPublicationRecord {
        id: row.get(0)?,
        repository: RepositoryName::parse(&row.get::<String>(1)?)?,
        target_tag: row
            .get::<Option<String>>(2)?
            .map(|tag| Tag::parse(&tag))
            .transpose()?,
        root_digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
        catalog_digest: Sha256Digest::parse(&row.get::<String>(4)?)?,
        release_tag: row.get(5)?,
        confirmation_hash: Sha256Digest::parse(&row.get::<String>(6)?)?,
        topology_digest: Sha256Digest::parse(&row.get::<String>(7)?)?,
        required_placement_count: checked_u32(row.get(8)?, "OCI publication placement count")?,
        source_kind: row.get(9)?,
        state: row.get(10)?,
        expires_at: row.get(11)?,
        created_at: row.get(12)?,
        committed_at: row.get(13)?,
        resource_version: row.get(14)?,
    })
}

fn row_to_provenance(
    row: &Row,
    closure_members: Vec<OciAdminClosureMemberRecord>,
    evidence: Vec<OciAdminEvidenceRecord>,
) -> Result<OciAdminProvenanceRecord> {
    Ok(OciAdminProvenanceRecord {
        repository: RepositoryName::parse(&row.get::<String>(0)?)?,
        root_digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        package: row.get(2)?,
        release: row.get(3)?,
        channel: row.get(4)?,
        signed_release_root: row.get(5)?,
        catalog_digest: Sha256Digest::parse(&row.get::<String>(6)?)?,
        verification: row.get(7)?,
        closure_members,
        evidence,
        verified_at: row.get(8)?,
    })
}

fn row_to_closure_member(row: &Row) -> Result<OciAdminClosureMemberRecord> {
    Ok(OciAdminClosureMemberRecord {
        store_path: row.get(0)?,
        nar_hash: row.get(1)?,
        nar_size: checked_u64(row.get(2)?, "OCI closure member NAR size")?,
        layer_digest: Sha256Digest::parse(&row.get::<String>(3)?)?,
        direct: row.get(4)?,
    })
}

fn row_to_evidence(row: &Row) -> Result<OciAdminEvidenceRecord> {
    Ok(OciAdminEvidenceRecord {
        kind: row.get(0)?,
        digest: Sha256Digest::parse(&row.get::<String>(1)?)?,
        media_type: MediaType::parse(&row.get::<String>(2)?)?,
        verification: row.get(3)?,
        referrer_digest: Sha256Digest::parse(&row.get::<String>(4)?)?,
    })
}

fn row_to_retention(row: &Row) -> Result<OciRetentionPolicyRecord> {
    Ok(OciRetentionPolicyRecord {
        registry_id: row.get(0)?,
        untagged_grace_seconds: checked_u64(row.get(1)?, "OCI retention grace")?,
        deleted_tag_history_seconds: checked_u64(row.get(2)?, "OCI deleted tag history age")?,
        recent_manual_tag_revisions: checked_u32(row.get(3)?, "OCI recent manual revisions")?,
        retain_referrers: row.get(4)?,
        resource_version: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn validate_repository_filter(filter: &OciRepositoryListFilter) -> Result<()> {
    if filter.repository_prefix.as_ref().is_some_and(|prefix| {
        prefix.len() > 128 || prefix.bytes().any(|byte| byte.is_ascii_control())
    }) || filter
        .lifecycle_state
        .as_deref()
        .is_some_and(|state| !matches!(state, "active" | "deleting" | "deleted"))
    {
        bail!("OCI repository list filter is invalid");
    }
    Ok(())
}

fn validate_tag_filter(filter: &OciTagListFilter) -> Result<()> {
    if filter.tag_prefix.as_ref().is_some_and(|prefix| {
        prefix.len() > 128 || prefix.bytes().any(|byte| byte.is_ascii_control())
    }) || filter
        .ownership_kind
        .as_deref()
        .is_some_and(|kind| !matches!(kind, "manual" | "release" | "channel"))
    {
        bail!("OCI tag list filter is invalid");
    }
    Ok(())
}

fn parse_annotations(json: &str) -> Result<Annotations> {
    let annotations =
        serde_json::from_str::<Annotations>(json).context("decoding persisted OCI annotations")?;
    annotations.validate()?;
    Ok(annotations)
}

fn checked_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("persisted {label} is negative"))
}

fn checked_u32(value: i64, label: &str) -> Result<u32> {
    u32::try_from(value).with_context(|| format!("persisted {label} is outside u32"))
}
