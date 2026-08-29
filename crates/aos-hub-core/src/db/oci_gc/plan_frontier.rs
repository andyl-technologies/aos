//! Bounded reverse-topological OCI GC candidate frontier selection.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use aos_oci_types::{MediaType, Sha256Digest};

use super::plan_model::{
    canonical_digest, EffectivePolicy, FrozenCandidate, FrozenRoot, PlanBlocker,
};
use super::{OCI_GC_MAX_CANDIDATES, OCI_GC_MAX_OBJECTS};
use crate::db::Database;

impl Database {
    /// Adds only the policy-retained tag-history roots to the bounded mark set.
    pub(super) async fn collect_oci_gc_history_roots(
        &self,
        registry_id: i64,
        policy: &EffectivePolicy,
        now: i64,
        roots: &mut BTreeSet<FrozenRoot>,
    ) -> Result<()> {
        let history_seconds = i64::try_from(policy.deleted_tag_history_seconds)
            .context("OCI tag-history retention exceeds int64")?;
        let cutoff = now.saturating_sub(history_seconds);
        let rows = self
            .backend
            .query(
                "SELECT repository_id, name, prior_digest, next_digest,
                        source_kind, changed_at, id
                 FROM oci_tag_history history WHERE registry_id = ?1
                   AND (history.changed_at >= ?2
                     OR (history.source_kind = 'manual' AND
                       (SELECT COUNT(*) FROM oci_tag_history newer
                        WHERE newer.repository_id = history.repository_id
                          AND newer.name = history.name
                          AND newer.source_kind = 'manual'
                          AND (newer.changed_at > history.changed_at
                            OR (newer.changed_at = history.changed_at
                              AND newer.id >= history.id))) <= ?3))
                 ORDER BY repository_id, name, changed_at DESC, id DESC
                 LIMIT ?4",
                &vals![
                    registry_id,
                    cutoff,
                    i64::from(policy.recent_manual_tag_revisions),
                    i64::try_from(OCI_GC_MAX_OBJECTS + 1)?
                ],
            )
            .await?;
        if rows.len() > OCI_GC_MAX_OBJECTS {
            bail!("retained OCI tag history exceeds the object bound");
        }
        let mut manual_seen: BTreeMap<(i64, String), u32> = BTreeMap::new();
        for row in &rows {
            let repository_id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let source_kind: String = row.get(4)?;
            let changed_at: i64 = row.get(5)?;
            let history_id: String = row.get(6)?;
            let recent_by_age = changed_at >= cutoff;
            let recent_manual = if source_kind == "manual" {
                let count = manual_seen
                    .entry((repository_id, name.clone()))
                    .or_default();
                *count += 1;
                *count <= policy.recent_manual_tag_revisions
            } else {
                false
            };
            if !(recent_by_age || recent_manual) {
                continue;
            }
            for digest in [row.get::<Option<String>>(2)?, row.get::<Option<String>>(3)?]
                .into_iter()
                .flatten()
            {
                roots.insert(FrozenRoot {
                    kind: "tag_history".into(),
                    digest: canonical_digest(digest)?,
                    source_id: history_id.clone(),
                    // History retains the registry-global bytes and closure.
                    // The original repository link may be removed independently.
                    repository_id: None,
                });
            }
        }
        Ok(())
    }

    /// Selects one bounded frontier whose members have no active inbound edge.
    pub(super) async fn collect_oci_gc_candidates(
        &self,
        registry_id: i64,
        policy: &EffectivePolicy,
        now: i64,
        live: &BTreeSet<String>,
        blockers: &mut Vec<PlanBlocker>,
    ) -> Result<Vec<FrozenCandidate>> {
        let grace = i64::try_from(policy.untagged_grace_seconds)
            .context("OCI untagged grace exceeds int64")?;
        let cutoff = now.saturating_sub(grace);
        const CANDIDATE_SCAN_PAGE: usize = 100;
        let mut candidates = Vec::new();
        let mut cursor: Option<String> = None;
        'pages: loop {
            let rows = self
                .backend
                .query(
                    "SELECT stored_blob.digest, stored_blob.media_type,
                            stored_blob.byte_size, object.object_key,
                            object.id, object.resource_version,
                            stored_blob.unreferenced_since, object.content_hash, object.size
                     FROM oci_blobs stored_blob JOIN surface_objects object
                       ON object.id = stored_blob.surface_object_id
                      AND object.registry_id = stored_blob.registry_id
                     WHERE stored_blob.registry_id = ?1
                       AND stored_blob.lifecycle_state = 'active'
                       AND object.lifecycle_state = 'active'
                       AND stored_blob.unreferenced_since IS NOT NULL
                       AND stored_blob.unreferenced_since <= ?2
                       AND (?3 IS NULL OR stored_blob.digest > ?3)
                       AND NOT EXISTS (SELECT 1 FROM oci_descriptor_edges inbound
                         JOIN oci_blobs source
                           ON source.registry_id = inbound.registry_id
                          AND source.digest = inbound.manifest_digest
                          AND source.lifecycle_state = 'active'
                         WHERE inbound.registry_id = stored_blob.registry_id
                           AND inbound.target_digest = stored_blob.digest)
                       AND NOT EXISTS (SELECT 1 FROM oci_manifests inbound_manifest
                         JOIN oci_blobs source
                           ON source.registry_id = inbound_manifest.registry_id
                          AND source.digest = inbound_manifest.digest
                          AND source.lifecycle_state = 'active'
                         WHERE inbound_manifest.registry_id = stored_blob.registry_id
                           AND (inbound_manifest.config_digest = stored_blob.digest
                             OR inbound_manifest.subject_digest = stored_blob.digest))
                     ORDER BY stored_blob.digest LIMIT ?4",
                    &vals![
                        registry_id,
                        cutoff,
                        cursor.as_deref(),
                        i64::try_from(CANDIDATE_SCAN_PAGE + 1)?
                    ],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let digest = canonical_digest(row.get(0)?)?;
                cursor = Some(digest.clone());
                if live.contains(&digest) {
                    continue;
                }
                let parsed_digest = Sha256Digest::parse(&digest)?;
                let object_key: String = row.get(3)?;
                let blob_size: i64 = row.get(2)?;
                let identity_exact = object_key == crate::db::oci_blob_object_key(parsed_digest)
                    && row.get::<String>(7)? == parsed_digest.encoded()
                    && row.get::<i64>(8)? == blob_size;
                if !identity_exact {
                    blockers.push(PlanBlocker {
                        kind: "catalog_identity_conflict",
                        digest: Some(parsed_digest),
                        detail: "blob and surface-object key/hash/size identity disagree".into(),
                    });
                    continue;
                }
                let repository_rows = self
                    .backend
                    .query(
                        "SELECT repository.id, repository.name
                         FROM oci_repository_objects link JOIN oci_repositories repository
                           ON repository.id = link.repository_id
                          AND repository.registry_id = link.registry_id
                         WHERE link.registry_id = ?1 AND link.digest = ?2
                         ORDER BY repository.name, repository.id LIMIT ?3",
                        &vals![registry_id, digest, i64::try_from(OCI_GC_MAX_OBJECTS + 1)?],
                    )
                    .await?;
                if repository_rows.len() > OCI_GC_MAX_OBJECTS {
                    bail!("OCI GC candidate repository set exceeds the object bound");
                }
                let repositories = repository_rows
                    .iter()
                    .map(|repository| Ok((repository.get(0)?, repository.get(1)?)))
                    .collect::<Result<Vec<_>>>()?;
                let byte_size = u64::try_from(row.get::<i64>(2)?)
                    .context("persisted OCI candidate size is negative")?;
                let unreferenced_since: i64 = row.get(6)?;
                candidates.push(FrozenCandidate {
                    digest,
                    media_type: MediaType::parse(&row.get::<String>(1)?)?.as_str().into(),
                    byte_size,
                    object_key,
                    surface_object_id: row.get(4)?,
                    catalog_object_resource_version: row.get(5)?,
                    repositories,
                    eligible_at: unreferenced_since.saturating_add(grace),
                });
                if candidates.len() == OCI_GC_MAX_CANDIDATES {
                    break 'pages;
                }
            }
            if rows.len() <= CANDIDATE_SCAN_PAGE {
                break;
            }
        }
        Ok(candidates)
    }
}
