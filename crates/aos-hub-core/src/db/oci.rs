//! Registry-owned OCI catalog persistence.
//!
//! Immutable bytes stay on the registry surface under
//! `oci/blobs/sha256/<hex>`. This module stores only their exact identity,
//! repository authorization links, bounded manifest projections, ordered
//! descriptor edges, and mutable tag pointers. Reads always begin with an
//! exact registry and repository; a registry-wide digest is never sufficient
//! authority to expose deduplicated content.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use aos_oci_types::{
    to_canonical_json, Annotations, Descriptor, ImageIndex, ImageManifest, ManifestReference,
    MediaType, Platform, RepositoryName, Sha256Digest, Tag,
};
use uuid::Uuid;

use crate::backend::{CheckedStatement, Statement};
use crate::value::Row;

use super::{
    portable_relational_id, ContainerReleaseDescriptorRole, Database,
    VerifiedContainerReleaseDescriptor,
};

const OCI_REPOSITORY_COLUMNS: &str = "id, registry_id, name, visibility,
    lifecycle_state, resource_version, created_at, updated_at";
const OCI_BLOB_COLUMNS: &str = "blob.registry_id, blob.digest, blob.byte_size,
    blob.media_type, blob.surface_object_id, object.object_key,
    blob.lifecycle_state, blob.created_at, blob.updated_at";
const OCI_MANIFEST_COLUMNS: &str = "manifest.registry_id, manifest.digest,
    manifest.media_type, manifest.byte_size, manifest.artifact_type,
    manifest.subject_digest, manifest.config_digest, manifest.platform_os,
    manifest.platform_architecture, manifest.platform_variant,
    manifest.annotations_json, manifest.descriptor_count, blob.surface_object_id,
    object.object_key, manifest.created_at";

/// Maximum tags returned by one Distribution page.
pub const OCI_MAX_TAG_PAGE: u32 = 1_000;

/// Maximum referrer descriptors returned in one response.
pub const OCI_MAX_REFERRERS: u32 = 1_000;

/// Returns the canonical registry-surface key for an OCI content digest.
#[must_use]
pub fn oci_blob_object_key(digest: Sha256Digest) -> String {
    format!("oci/blobs/sha256/{}", digest.encoded())
}

fn validate_catalog(input: &IndexOciRepositoryCatalog) -> Result<()> {
    if input.observed_at <= 0 {
        bail!("OCI catalog observation time must be positive");
    }
    if !matches!(input.source_kind.as_str(), "manual" | "release" | "channel") {
        bail!("invalid OCI tag source '{}'", input.source_kind);
    }
    if input.actor_id.is_empty()
        || input.actor_id.len() > 128
        || input.actor_id.chars().any(char::is_control)
    {
        bail!("OCI catalog actor identity is malformed");
    }
    if input.objects.is_empty()
        || input.objects.len() > aos_oci_types::limits::MAX_REACHABLE_DESCRIPTORS
    {
        bail!("OCI catalog object count is outside the admitted bounds");
    }
    let mut objects = BTreeMap::new();
    for object in &input.objects {
        object.descriptor.validate()?;
        if objects
            .insert(object.descriptor.digest, &object.descriptor)
            .is_some()
        {
            bail!("OCI catalog contains a duplicate digest");
        }
        match (&object.projection, object.descriptor.media_type) {
            (Some(OciCatalogProjection::Manifest(manifest)), media_type)
                if media_type.is_image_manifest() =>
            {
                manifest.validate()?;
                object.descriptor.verify(&to_canonical_json(manifest)?)?;
            }
            (Some(OciCatalogProjection::Index(index)), media_type)
                if media_type.is_image_index() =>
            {
                index.validate()?;
                object.descriptor.verify(&to_canonical_json(index)?)?;
            }
            (Some(_), _) => bail!("OCI projection media type conflicts with its descriptor"),
            (None, media_type) if media_type.is_image_manifest() || media_type.is_image_index() => {
                bail!("OCI manifest and index objects require bounded projections")
            }
            (None, _) => {}
        }
    }
    let root = objects
        .get(&input.root_digest)
        .context("OCI root digest is absent from the object set")?;
    if !root.media_type.is_image_manifest() && !root.media_type.is_image_index() {
        bail!("OCI root must identify a manifest or index");
    }
    let mut graph = BTreeMap::<Sha256Digest, Vec<Sha256Digest>>::new();
    let mut referrers = BTreeMap::<Sha256Digest, Vec<Sha256Digest>>::new();
    for object in &input.objects {
        let descriptors = match &object.projection {
            Some(OciCatalogProjection::Manifest(manifest)) => manifest_descriptors(manifest),
            Some(OciCatalogProjection::Index(index)) => index_descriptors(index),
            None => Vec::new(),
        };
        for descriptor in &descriptors {
            let target = objects.get(&descriptor.digest).with_context(|| {
                format!("OCI descriptor target {} is absent", descriptor.digest)
            })?;
            if target.media_type != descriptor.media_type || target.size != descriptor.size {
                bail!(
                    "OCI descriptor target {} has conflicting identity",
                    descriptor.digest
                );
            }
        }
        let dependencies = match &object.projection {
            Some(OciCatalogProjection::Manifest(manifest)) => {
                let mut dependencies = vec![manifest.config.digest];
                dependencies.extend(manifest.layers.iter().map(|layer| layer.digest));
                if manifest.artifact_type.is_none() {
                    dependencies.extend(manifest.subject.iter().map(|subject| subject.digest));
                } else if let Some(subject) = &manifest.subject {
                    referrers
                        .entry(subject.digest)
                        .or_default()
                        .push(object.descriptor.digest);
                }
                dependencies
            }
            Some(OciCatalogProjection::Index(index)) => index
                .manifests
                .iter()
                .chain(index.subject.iter())
                .map(|descriptor| descriptor.digest)
                .collect(),
            None => Vec::new(),
        };
        graph.insert(object.descriptor.digest, dependencies);
    }
    for (subject, manifests) in referrers {
        graph.entry(subject).or_default().extend(manifests);
    }

    let mut visiting = BTreeSet::new();
    let mut reached = BTreeSet::new();
    validate_graph_from(input.root_digest, 0, &graph, &mut visiting, &mut reached)?;
    if reached.len() != objects.len() {
        bail!("OCI catalog contains objects unreachable from its root or referrers");
    }
    Ok(())
}

fn validate_graph_from(
    digest: Sha256Digest,
    depth: usize,
    graph: &BTreeMap<Sha256Digest, Vec<Sha256Digest>>,
    visiting: &mut BTreeSet<Sha256Digest>,
    reached: &mut BTreeSet<Sha256Digest>,
) -> Result<()> {
    if depth > aos_oci_types::limits::MAX_DESCRIPTOR_GRAPH_DEPTH {
        bail!(
            "OCI descriptor graph exceeds depth {}",
            aos_oci_types::limits::MAX_DESCRIPTOR_GRAPH_DEPTH
        );
    }
    if visiting.contains(&digest) {
        bail!("OCI descriptor graph contains a cycle at {digest}");
    }
    if reached.contains(&digest) {
        return Ok(());
    }

    visiting.insert(digest);
    if let Some(targets) = graph.get(&digest) {
        for target in targets {
            validate_graph_from(*target, depth + 1, graph, visiting, reached)?;
        }
    }
    visiting.remove(&digest);
    reached.insert(digest);
    Ok(())
}

fn extend_oci_object_statements(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    object: &OciCatalogObject,
) -> Result<()> {
    let digest = object.descriptor.digest;
    let encoded = digest.encoded();
    let wire = digest.to_string();
    let key = oci_blob_object_key(digest);
    let size = i64::try_from(object.descriptor.size).context("OCI object size exceeds int64")?;
    let object_kind = if object.descriptor.media_type.is_image_manifest()
        || object.descriptor.media_type.is_image_index()
    {
        "manifest"
    } else {
        "blob"
    };
    statements.push(
        Statement::new(
            "INSERT INTO oci_blobs
               (registry_id, digest, byte_size, media_type, surface_object_id,
                quota_bytes, lifecycle_state, created_at, updated_at)
             SELECT ?1, ?2, ?3, ?4, object.id, ?3, 'active', ?5, ?5
             FROM surface_objects object
             JOIN object_placements presence
               ON presence.surface_object_id = object.id
              AND presence.registry_id = object.registry_id
              AND presence.placement_id = ?6
             WHERE object.registry_id = ?1 AND object.object_key = ?7
               AND object.object_kind = 'immutable'
               AND object.lifecycle_state = 'active'
               AND object.content_hash = ?8 AND object.size = ?3
               AND presence.state = 'present'
               AND presence.observed_hash = ?8 AND presence.observed_size = ?3
               AND presence.etag IS NOT NULL
             ON CONFLICT(registry_id, digest) DO NOTHING",
            vals![
                input.registry_id,
                wire,
                size,
                object.descriptor.media_type.as_str(),
                input.observed_at,
                input.placement_id,
                key,
                encoded
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_repository_objects
               (repository_id, registry_id, digest, object_kind, linked_at)
             SELECT repository.id, repository.registry_id, ?3, ?4, ?5
             FROM oci_repositories repository
             JOIN oci_blobs blob
               ON blob.registry_id = repository.registry_id AND blob.digest = ?3
             WHERE repository.registry_id = ?1 AND repository.name = ?2
             ON CONFLICT(repository_id, digest) DO NOTHING",
            vals![
                input.registry_id,
                input.repository.as_str(),
                digest.to_string(),
                object_kind,
                input.observed_at
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    Ok(())
}

fn extend_oci_projection_statements(
    statements: &mut Vec<CheckedStatement>,
    registry_id: i64,
    object: &Descriptor,
    projection: &OciCatalogProjection,
    now: i64,
) -> Result<i64> {
    let (artifact_type, subject, config, annotations, edges) = match projection {
        OciCatalogProjection::Manifest(manifest) => (
            manifest.artifact_type,
            manifest
                .subject
                .as_ref()
                .map(|descriptor| descriptor.digest),
            Some(manifest.config.digest),
            &manifest.annotations,
            manifest_edges(manifest),
        ),
        OciCatalogProjection::Index(index) => (
            None,
            index.subject.as_ref().map(|descriptor| descriptor.digest),
            None,
            &index.annotations,
            index_edges(index),
        ),
    };
    let size = i64::try_from(object.size).context("OCI manifest size exceeds int64")?;
    let descriptor_count = i64::try_from(edges.len()).context("OCI edge count exceeds int64")?;
    let platform = object.platform.as_ref();
    statements.push(
        Statement::new(
            "INSERT INTO oci_manifests
               (registry_id, digest, media_type, byte_size, schema_version,
                artifact_type, subject_digest, config_digest, platform_os,
                platform_architecture, platform_variant, annotations_json,
                descriptor_count, created_at)
             SELECT ?1, ?2, ?3, ?4, 2, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13
             FROM oci_blobs blob
             WHERE blob.registry_id = ?1 AND blob.digest = ?2
               AND blob.media_type = ?3 AND blob.byte_size = ?4
             ON CONFLICT(registry_id, digest) DO NOTHING",
            vals![
                registry_id,
                object.digest.to_string(),
                object.media_type.as_str(),
                size,
                artifact_type.map(MediaType::as_str),
                subject.map(|digest| digest.to_string()),
                config.map(|digest| digest.to_string()),
                platform.map(|platform| platform.os.as_str()),
                platform.map(|platform| platform.architecture.as_str()),
                platform.and_then(|platform| platform.variant.as_deref()),
                serde_json::to_string(annotations)?,
                descriptor_count,
                now
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    for edge in &edges {
        let size = i64::try_from(edge.descriptor.size).context("OCI edge size exceeds int64")?;
        statements.push(
            Statement::new(
                "INSERT INTO oci_descriptor_edges
                   (registry_id, manifest_digest, edge_role, ordinal,
                    target_digest, media_type, byte_size, platform_os,
                    platform_architecture, platform_variant, annotations_json)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
                 FROM oci_manifests manifest
                 JOIN oci_blobs target
                   ON target.registry_id = manifest.registry_id
                  AND target.digest = ?5 AND target.media_type = ?6
                  AND target.byte_size = ?7
                 WHERE manifest.registry_id = ?1 AND manifest.digest = ?2
                 ON CONFLICT(registry_id, manifest_digest, edge_role, ordinal)
                 DO NOTHING",
                vals![
                    registry_id,
                    object.digest.to_string(),
                    edge.role,
                    edge.ordinal,
                    edge.descriptor.digest.to_string(),
                    edge.descriptor.media_type.as_str(),
                    size,
                    edge.descriptor
                        .platform
                        .as_ref()
                        .map(|platform| platform.os.as_str()),
                    edge.descriptor
                        .platform
                        .as_ref()
                        .map(|platform| platform.architecture.as_str()),
                    edge.descriptor
                        .platform
                        .as_ref()
                        .and_then(|platform| platform.variant.as_deref()),
                    serde_json::to_string(&edge.descriptor.annotations)?
                ]
                .to_vec(),
            )
            .unchecked(),
        );
    }
    Ok(descriptor_count)
}

fn extend_catalog_identity_guards(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    manifest_count: i64,
    edge_count: i64,
) -> Result<()> {
    for objects in input.objects.chunks(8) {
        let mut sql = String::from(
            "UPDATE oci_repositories
             SET resource_version = resource_version + 1, updated_at = ?1
             WHERE registry_id = ?2 AND name = ?3 AND visibility = 'inherit'",
        );
        let mut params = vals![
            input.observed_at,
            input.registry_id,
            input.repository.as_str()
        ]
        .to_vec();
        for object in objects {
            let size = i64::try_from(object.descriptor.size)
                .context("OCI identity-guard size exceeds int64")?;
            let start = params.len() + 1;
            sql.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM oci_repository_objects link
                   JOIN oci_blobs blob
                     ON blob.registry_id = link.registry_id
                    AND blob.digest = link.digest
                   JOIN object_placements presence
                     ON presence.surface_object_id = blob.surface_object_id
                    AND presence.registry_id = blob.registry_id
                   WHERE link.repository_id = oci_repositories.id
                     AND link.digest = ?{start}
                     AND blob.media_type = ?{}
                     AND blob.byte_size = ?{}
                     AND presence.placement_id = ?{}
                     AND presence.state = 'present'
                     AND presence.observed_hash = ?{}
                     AND presence.observed_size = ?{}
                     AND presence.etag IS NOT NULL)",
                start + 1,
                start + 2,
                start + 3,
                start + 4,
                start + 5
            ));
            params.extend(vals![
                object.descriptor.digest.to_string(),
                object.descriptor.media_type.as_str(),
                size,
                input.placement_id,
                object.descriptor.digest.encoded(),
                size
            ]);
        }
        statements.push(Statement::new(sql, params).expecting(1));
    }
    if let Some(tag) = &input.tag {
        statements.push(
            Statement::new(
                "UPDATE oci_repositories
                 SET resource_version = resource_version + 1, updated_at = ?1
                 WHERE registry_id = ?2 AND name = ?3
                   AND EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.repository_id = oci_repositories.id
                       AND tag.name = ?4 AND tag.digest = ?5)",
                vals![
                    input.observed_at,
                    input.registry_id,
                    input.repository.as_str(),
                    tag.as_str(),
                    input.root_digest.to_string()
                ]
                .to_vec(),
            )
            .expecting(1),
        );
    }
    statements.push(
        Statement::new(
            "UPDATE oci_registry_state
             SET mutation_epoch = mutation_epoch + 1,
                 charged_bytes = (SELECT COALESCE(SUM(byte_size), 0)
                   FROM oci_blobs WHERE registry_id = ?1),
                 charged_objects = (SELECT COUNT(*)
                   FROM oci_blobs WHERE registry_id = ?1),
                 updated_at = ?2
             WHERE registry_id = ?1
               AND (SELECT COUNT(*) FROM oci_manifests
                 WHERE registry_id = ?1) >= ?3
               AND (SELECT COUNT(*) FROM oci_descriptor_edges
                 WHERE registry_id = ?1) >= ?4",
            vals![
                input.registry_id,
                input.observed_at,
                manifest_count,
                edge_count
            ]
            .to_vec(),
        )
        .expecting(1),
    );
    Ok(())
}

fn extend_projection_identity_guards(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    object: &OciCatalogObject,
    projection: &OciCatalogProjection,
) -> Result<()> {
    let size = i64::try_from(object.descriptor.size)
        .context("OCI manifest identity-guard size exceeds int64")?;
    let (artifact_type, subject, config, annotations, edges) = match projection {
        OciCatalogProjection::Manifest(manifest) => (
            manifest.artifact_type,
            manifest
                .subject
                .as_ref()
                .map(|descriptor| descriptor.digest),
            Some(manifest.config.digest),
            &manifest.annotations,
            manifest_edges(manifest),
        ),
        OciCatalogProjection::Index(index) => (
            None,
            index.subject.as_ref().map(|descriptor| descriptor.digest),
            None,
            &index.annotations,
            index_edges(index),
        ),
    };
    let descriptor_count = i64::try_from(edges.len()).context("OCI edge count exceeds int64")?;
    let platform = object.descriptor.platform.as_ref();
    statements.push(
        Statement::new(
            "UPDATE oci_repositories
             SET resource_version = resource_version + 1, updated_at = ?1
             WHERE registry_id = ?2 AND name = ?3
               AND EXISTS (SELECT 1 FROM oci_manifests manifest
                 WHERE manifest.registry_id = ?2 AND manifest.digest = ?4
                   AND manifest.media_type = ?5 AND manifest.byte_size = ?6
                   AND ((manifest.artifact_type IS NULL AND ?7 IS NULL)
                     OR manifest.artifact_type = ?7)
                   AND ((manifest.subject_digest IS NULL AND ?8 IS NULL)
                     OR manifest.subject_digest = ?8)
                   AND ((manifest.config_digest IS NULL AND ?9 IS NULL)
                     OR manifest.config_digest = ?9)
                   AND ((manifest.platform_os IS NULL AND ?10 IS NULL)
                     OR manifest.platform_os = ?10)
                   AND ((manifest.platform_architecture IS NULL AND ?11 IS NULL)
                     OR manifest.platform_architecture = ?11)
                   AND ((manifest.platform_variant IS NULL AND ?12 IS NULL)
                     OR manifest.platform_variant = ?12)
                   AND manifest.annotations_json = ?13
                   AND manifest.descriptor_count = ?14
                   AND (SELECT COUNT(*) FROM oci_descriptor_edges edge
                     WHERE edge.registry_id = manifest.registry_id
                       AND edge.manifest_digest = manifest.digest) = ?14)",
            vals![
                input.observed_at,
                input.registry_id,
                input.repository.as_str(),
                object.descriptor.digest.to_string(),
                object.descriptor.media_type.as_str(),
                size,
                artifact_type.map(MediaType::as_str),
                subject.map(|digest| digest.to_string()),
                config.map(|digest| digest.to_string()),
                platform.map(|platform| platform.os.as_str()),
                platform.map(|platform| platform.architecture.as_str()),
                platform.and_then(|platform| platform.variant.as_deref()),
                serde_json::to_string(annotations)?,
                descriptor_count
            ]
            .to_vec(),
        )
        .expecting(1),
    );
    for edge in edges {
        let edge_size = i64::try_from(edge.descriptor.size)
            .context("OCI edge identity-guard size exceeds int64")?;
        statements.push(
            Statement::new(
                "UPDATE oci_repositories
                 SET resource_version = resource_version + 1, updated_at = ?1
                 WHERE registry_id = ?2 AND name = ?3
                   AND EXISTS (SELECT 1 FROM oci_descriptor_edges edge
                     WHERE edge.registry_id = ?2 AND edge.manifest_digest = ?4
                       AND edge.edge_role = ?5 AND edge.ordinal = ?6
                       AND edge.target_digest = ?7 AND edge.media_type = ?8
                       AND edge.byte_size = ?9
                       AND ((edge.platform_os IS NULL AND ?10 IS NULL)
                         OR edge.platform_os = ?10)
                       AND ((edge.platform_architecture IS NULL AND ?11 IS NULL)
                         OR edge.platform_architecture = ?11)
                       AND ((edge.platform_variant IS NULL AND ?12 IS NULL)
                         OR edge.platform_variant = ?12)
                       AND edge.annotations_json = ?13)",
                vals![
                    input.observed_at,
                    input.registry_id,
                    input.repository.as_str(),
                    object.descriptor.digest.to_string(),
                    edge.role,
                    edge.ordinal,
                    edge.descriptor.digest.to_string(),
                    edge.descriptor.media_type.as_str(),
                    edge_size,
                    edge.descriptor
                        .platform
                        .as_ref()
                        .map(|platform| platform.os.as_str()),
                    edge.descriptor
                        .platform
                        .as_ref()
                        .map(|platform| platform.architecture.as_str()),
                    edge.descriptor
                        .platform
                        .as_ref()
                        .and_then(|platform| platform.variant.as_deref()),
                    serde_json::to_string(&edge.descriptor.annotations)?
                ]
                .to_vec(),
            )
            .expecting(1),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ProjectedEdge<'a> {
    role: &'static str,
    ordinal: u32,
    descriptor: &'a Descriptor,
}

fn manifest_descriptors(manifest: &ImageManifest) -> Vec<&Descriptor> {
    let mut descriptors = Vec::with_capacity(
        manifest
            .layers
            .len()
            .saturating_add(1)
            .saturating_add(usize::from(manifest.subject.is_some())),
    );
    descriptors.push(&manifest.config);
    descriptors.extend(&manifest.layers);
    if let Some(subject) = &manifest.subject {
        descriptors.push(subject);
    }
    descriptors
}

fn index_descriptors(index: &ImageIndex) -> Vec<&Descriptor> {
    let mut descriptors = Vec::with_capacity(
        index
            .manifests
            .len()
            .saturating_add(usize::from(index.subject.is_some())),
    );
    descriptors.extend(&index.manifests);
    if let Some(subject) = &index.subject {
        descriptors.push(subject);
    }
    descriptors
}

fn manifest_edges(manifest: &ImageManifest) -> Vec<ProjectedEdge<'_>> {
    let mut edges = Vec::with_capacity(manifest_descriptors(manifest).len());
    edges.push(ProjectedEdge {
        role: "config",
        ordinal: 0,
        descriptor: &manifest.config,
    });
    let role = if manifest.artifact_type.is_some() {
        "payload"
    } else {
        "layer"
    };
    for (ordinal, descriptor) in manifest.layers.iter().enumerate() {
        if let Ok(ordinal) = u32::try_from(ordinal) {
            edges.push(ProjectedEdge {
                role,
                ordinal,
                descriptor,
            });
        }
    }
    if let Some(subject) = &manifest.subject {
        edges.push(ProjectedEdge {
            role: "subject",
            ordinal: 0,
            descriptor: subject,
        });
    }
    edges
}

fn index_edges(index: &ImageIndex) -> Vec<ProjectedEdge<'_>> {
    let mut edges = Vec::with_capacity(index_descriptors(index).len());
    for (ordinal, descriptor) in index.manifests.iter().enumerate() {
        if let Ok(ordinal) = u32::try_from(ordinal) {
            edges.push(ProjectedEdge {
                role: "child",
                ordinal,
                descriptor,
            });
        }
    }
    if let Some(subject) = &index.subject {
        edges.push(ProjectedEdge {
            role: "subject",
            ordinal: 0,
            descriptor: subject,
        });
    }
    edges
}

/// One OCI repository local to an AOS registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRepositoryRecord {
    /// Portable relational id.
    pub id: i64,
    /// Owning AOS registry id.
    pub registry_id: i64,
    /// Canonical repository name within the registry authority.
    pub name: RepositoryName,
    /// `inherit`; container repositories share their AOS registry visibility.
    pub visibility: String,
    /// `active`, `deleting`, or `deleted`.
    pub lifecycle_state: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last mutation time in Unix seconds.
    pub updated_at: i64,
}

/// One immutable OCI object linked to a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciBlobRecord {
    /// Owning AOS registry id.
    pub registry_id: i64,
    /// Exact OCI digest.
    pub digest: Sha256Digest,
    /// Exact stored byte length.
    pub byte_size: u64,
    /// Exact admitted media type.
    pub media_type: MediaType,
    /// Backing logical surface-object id.
    pub surface_object_id: i64,
    /// Canonical registry-surface object key.
    pub object_key: String,
    /// `active`, `tombstoned`, or `deleting`.
    pub lifecycle_state: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
    /// Last lifecycle mutation time in Unix seconds.
    pub updated_at: i64,
}

/// Bounded projection of one exact OCI manifest or index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciManifestRecord {
    /// Owning AOS registry id.
    pub registry_id: i64,
    /// Digest of the exact stored JSON bytes.
    pub digest: Sha256Digest,
    /// Exact manifest or index media type.
    pub media_type: MediaType,
    /// Exact stored byte length.
    pub byte_size: u64,
    /// Artifact payload type for an artifact manifest.
    pub artifact_type: Option<MediaType>,
    /// Referred manifest digest for an artifact.
    pub subject_digest: Option<Sha256Digest>,
    /// Runnable-image or artifact config digest.
    pub config_digest: Option<Sha256Digest>,
    /// Optional platform projected from a signed catalog.
    pub platform: Option<Platform>,
    /// Ordered validated OCI annotations.
    pub annotations: Annotations,
    /// Number of directly projected descriptors.
    pub descriptor_count: u32,
    /// Backing logical surface-object id.
    pub surface_object_id: i64,
    /// Canonical registry-surface object key.
    pub object_key: String,
    /// Creation time in Unix seconds.
    pub created_at: i64,
}

/// One ordered descriptor edge projected from a manifest or index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciDescriptorEdgeRecord {
    /// `config`, `layer`, `child`, `subject`, or `payload`.
    pub role: String,
    /// Stable ordinal within the role.
    pub ordinal: u32,
    /// Exact target descriptor.
    pub descriptor: Descriptor,
}

/// One mutable tag pointer within a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTagRecord {
    /// Case-sensitive tag.
    pub name: Tag,
    /// Current manifest or index digest.
    pub digest: Sha256Digest,
    /// `manual`, `release`, or `channel`.
    pub source_kind: String,
    /// Optimistic-concurrency version.
    pub resource_version: i64,
    /// Last mutation time in Unix seconds.
    pub updated_at: i64,
}

/// Bounded parsed form of one exact manifest object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciCatalogProjection {
    /// OCI or Docker image manifest.
    Manifest(ImageManifest),
    /// OCI image index or Docker manifest list.
    Index(ImageIndex),
}

/// One exact object included in a repository catalog admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciCatalogObject {
    /// Descriptor verified against the physical surface bytes.
    pub descriptor: Descriptor,
    /// Required bounded projection for manifests and indexes.
    pub projection: Option<OciCatalogProjection>,
}

/// One closed repository graph to expose from already-verified surface bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexOciRepositoryCatalog {
    /// Owning AOS registry id.
    pub registry_id: i64,
    /// Placement whose exact presence evidence authorizes admission.
    pub placement_id: i64,
    /// Registry-local repository name.
    pub repository: RepositoryName,
    /// Complete closed graph, including configs and layers.
    pub objects: Vec<OciCatalogObject>,
    /// Root manifest or index digest.
    pub root_digest: Sha256Digest,
    /// Optional tag moved to the root after all links exist.
    pub tag: Option<Tag>,
    /// `manual`, `release`, or `channel`.
    pub source_kind: String,
    /// Stable actor label written to tag history.
    pub actor_id: String,
    /// Positive physical-observation time in Unix seconds.
    pub observed_at: i64,
}

impl Database {
    /// Returns an active OCI repository by its exact registry-local name.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_repository(
        &self,
        registry_id: i64,
        name: &RepositoryName,
    ) -> Result<Option<OciRepositoryRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_REPOSITORY_COLUMNS} FROM oci_repositories
                     WHERE registry_id = ?1 AND name = ?2
                       AND lifecycle_state = 'active'"
                ),
                &vals![registry_id, name.as_str()],
            )
            .await?
            .as_ref()
            .map(row_to_oci_repository)
            .transpose()
    }

    /// Resolves one repository-linked blob without consulting registry-wide
    /// content first.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_blob_for_repository(
        &self,
        repository_id: i64,
        digest: Sha256Digest,
    ) -> Result<Option<OciBlobRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_BLOB_COLUMNS}
                     FROM oci_repository_objects link
                     JOIN oci_blobs blob
                       ON blob.registry_id = link.registry_id
                      AND blob.digest = link.digest
                     JOIN surface_objects object
                       ON object.id = blob.surface_object_id
                      AND object.registry_id = blob.registry_id
                     WHERE link.repository_id = ?1 AND link.digest = ?2
                       AND blob.lifecycle_state = 'active'
                       AND object.lifecycle_state = 'active'"
                ),
                &vals![repository_id, digest.to_string()],
            )
            .await?
            .as_ref()
            .map(row_to_oci_blob)
            .transpose()
    }

    /// Returns the exact physical observation admitting one signed descriptor.
    ///
    /// The result carries both object-inventory and placement-observation
    /// versions. Signed-root application rechecks those versions inside its
    /// transaction, closing the interval between sidecar validation and root
    /// visibility.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when `byte_size` cannot be
    /// represented by the portable SQL integer contract.
    pub async fn oci_release_descriptor_placement(
        &self,
        repository_id: i64,
        placement_id: i64,
        role: ContainerReleaseDescriptorRole,
        descriptor: &Descriptor,
    ) -> Result<Option<VerifiedContainerReleaseDescriptor>> {
        let byte_size = i64::try_from(descriptor.size).context("OCI object size exceeds int64")?;
        self.backend
            .query_opt(
                "SELECT object.id, object.resource_version,
                        selected.resource_version,
                        selected_observation.observation_version,
                        presence.observed_inventory_generation,
                        presence.observed_at, presence.etag
                 FROM oci_repository_objects link
                 JOIN oci_blobs blob
                   ON blob.registry_id = link.registry_id
                  AND blob.digest = link.digest
                 JOIN surface_objects object
                   ON object.id = blob.surface_object_id
                  AND object.registry_id = blob.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 JOIN surface_placements selected
                   ON selected.id = presence.placement_id
                  AND selected.registry_id = presence.registry_id
                 JOIN surface_placement_observations selected_observation
                   ON selected_observation.placement_id = selected.id
                 WHERE link.repository_id = ?1 AND link.digest = ?2
                   AND presence.placement_id = ?3
                   AND blob.byte_size = ?4 AND blob.media_type = ?5
                   AND blob.lifecycle_state = 'active'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?6 AND object.size = ?4
                   AND presence.state = 'present'
                   AND presence.observed_hash = ?6
                   AND presence.observed_size = ?4
                   AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version",
                &vals![
                    repository_id,
                    descriptor.digest.to_string(),
                    placement_id,
                    byte_size,
                    descriptor.media_type.as_str(),
                    descriptor.digest.encoded()
                ],
            )
            .await?
            .map(|row| {
                Ok(VerifiedContainerReleaseDescriptor {
                    role,
                    digest: descriptor.digest.to_string(),
                    media_type: descriptor.media_type.as_str().to_string(),
                    byte_size: descriptor.size,
                    surface_object_id: row.get(0)?,
                    object_resource_version: row.get(1)?,
                    placement_id,
                    placement_resource_version: row.get(2)?,
                    placement_observation_version: row.get(3)?,
                    observed_inventory_generation: row.get(4)?,
                    observed_at: row.get(5)?,
                    strong_etag: row.get(6)?,
                })
            })
            .transpose()
    }

    /// Returns whether a repository-linked object retains exact evidence on a
    /// particular physical placement.
    ///
    /// Signed release-root admission uses this check to bind its catalog
    /// snapshot to independently observed bytes rather than trusting a logical
    /// repository link alone.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or when `byte_size` cannot be
    /// represented by the portable SQL integer contract.
    pub async fn oci_repository_object_has_placement(
        &self,
        repository_id: i64,
        digest: Sha256Digest,
        placement_id: i64,
        byte_size: u64,
        media_type: MediaType,
    ) -> Result<bool> {
        let byte_size = i64::try_from(byte_size).context("OCI object size exceeds int64")?;
        Ok(self
            .backend
            .query_opt(
                "SELECT 1
                 FROM oci_repository_objects link
                 JOIN oci_blobs blob
                   ON blob.registry_id = link.registry_id
                  AND blob.digest = link.digest
                 JOIN surface_objects object
                   ON object.id = blob.surface_object_id
                  AND object.registry_id = blob.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 WHERE link.repository_id = ?1 AND link.digest = ?2
                   AND presence.placement_id = ?3
                   AND blob.byte_size = ?4 AND blob.media_type = ?5
                   AND blob.lifecycle_state = 'active'
                   AND object.lifecycle_state = 'active'
                   AND object.content_hash = ?6 AND object.size = ?4
                   AND presence.state = 'present'
                   AND presence.observed_hash = ?6
                   AND presence.observed_size = ?4
                   AND presence.etag IS NOT NULL
                   AND presence.catalog_object_resource_version = object.resource_version",
                &vals![
                    repository_id,
                    digest.to_string(),
                    placement_id,
                    byte_size,
                    media_type.as_str(),
                    digest.encoded()
                ],
            )
            .await?
            .is_some())
    }

    /// Resolves a manifest or index by exact digest or repository tag.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_manifest_for_repository(
        &self,
        repository_id: i64,
        reference: &ManifestReference,
    ) -> Result<Option<OciManifestRecord>> {
        let (digest, tag) = match reference {
            ManifestReference::Digest(digest) => (Some(digest.to_string()), None),
            ManifestReference::Tag(tag) => (None, Some(tag.as_str().to_string())),
        };
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_MANIFEST_COLUMNS}
                     FROM oci_repository_objects link
                     JOIN oci_manifests manifest
                       ON manifest.registry_id = link.registry_id
                      AND manifest.digest = link.digest
                     JOIN oci_blobs blob
                       ON blob.registry_id = manifest.registry_id
                      AND blob.digest = manifest.digest
                     JOIN surface_objects object
                       ON object.id = blob.surface_object_id
                      AND object.registry_id = blob.registry_id
                     LEFT JOIN oci_tags tag
                       ON tag.repository_id = link.repository_id
                      AND tag.registry_id = link.registry_id
                      AND tag.digest = link.digest AND tag.name = ?3
                     WHERE link.repository_id = ?1
                       AND ((?2 IS NOT NULL AND link.digest = ?2)
                         OR (?3 IS NOT NULL AND tag.name = ?3))
                       AND blob.lifecycle_state = 'active'
                       AND object.lifecycle_state = 'active'"
                ),
                &vals![repository_id, digest, tag],
            )
            .await?
            .as_ref()
            .map(row_to_oci_manifest)
            .transpose()
    }

    /// Lists a deterministic page of tags after an optional exclusive cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested page is too large, or on database
    /// failure or malformed persisted data.
    pub async fn oci_tags(
        &self,
        repository_id: i64,
        limit: u32,
        last: Option<&Tag>,
    ) -> Result<Vec<OciTagRecord>> {
        if limit == 0 || limit > OCI_MAX_TAG_PAGE {
            bail!("OCI tag page size must be between 1 and {OCI_MAX_TAG_PAGE}");
        }
        self.backend
            .query(
                "SELECT name, digest, source_kind, resource_version, updated_at
                 FROM oci_tags
                 WHERE repository_id = ?1 AND (?2 IS NULL OR name > ?2)
                 ORDER BY name LIMIT ?3",
                &vals![repository_id, last.map(Tag::as_str), limit],
            )
            .await?
            .iter()
            .map(row_to_oci_tag)
            .collect()
    }

    /// Reports whether another tag follows the supplied exclusive cursor.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_tag_follows(&self, repository_id: i64, last: &Tag) -> Result<bool> {
        Ok(!self
            .backend
            .query(
                "SELECT name FROM oci_tags
                 WHERE repository_id = ?1 AND name > ?2
                 ORDER BY name LIMIT 1",
                &vals![repository_id, last.as_str()],
            )
            .await?
            .is_empty())
    }

    /// Lists ordered descriptor edges for one repository-linked manifest.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_descriptor_edges(
        &self,
        repository_id: i64,
        digest: Sha256Digest,
    ) -> Result<Vec<OciDescriptorEdgeRecord>> {
        self.backend
            .query(
                "SELECT edge.edge_role, edge.ordinal, edge.target_digest,
                        edge.media_type, edge.byte_size, edge.platform_os,
                        edge.platform_architecture, edge.platform_variant,
                        edge.annotations_json
                 FROM oci_descriptor_edges edge
                 JOIN oci_repository_objects link
                   ON link.registry_id = edge.registry_id
                  AND link.digest = edge.manifest_digest
                 WHERE link.repository_id = ?1 AND edge.manifest_digest = ?2
                 ORDER BY CASE edge.edge_role
                   WHEN 'config' THEN 0 WHEN 'layer' THEN 1
                   WHEN 'payload' THEN 2 WHEN 'child' THEN 3 ELSE 4 END,
                   edge.ordinal",
                &vals![repository_id, digest.to_string()],
            )
            .await?
            .iter()
            .map(row_to_oci_edge)
            .collect()
    }

    /// Lists repository-scoped OCI referrer-manifest descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_referrers(
        &self,
        repository_id: i64,
        subject: Sha256Digest,
        artifact_type: Option<MediaType>,
    ) -> Result<Vec<Descriptor>> {
        self.backend
            .query(
                "SELECT manifest.media_type, manifest.digest,
                        manifest.byte_size, manifest.artifact_type,
                        manifest.annotations_json
                 FROM oci_manifests manifest
                 JOIN oci_repository_objects link
                   ON link.registry_id = manifest.registry_id
                  AND link.digest = manifest.digest
                 WHERE link.repository_id = ?1
                   AND manifest.subject_digest = ?2
                   AND manifest.artifact_type IS NOT NULL
                   AND (?3 IS NULL OR manifest.artifact_type = ?3)
                 ORDER BY manifest.digest LIMIT ?4",
                &vals![
                    repository_id,
                    subject.to_string(),
                    artifact_type.map(MediaType::as_str),
                    OCI_MAX_REFERRERS
                ],
            )
            .await?
            .iter()
            .map(|row| {
                let media_type = parse_media_type(row.get::<String>(0)?)?;
                let digest = parse_digest(row.get::<String>(1)?)?;
                let size = parse_size(row.get::<i64>(2)?)?;
                let artifact_type = row
                    .get::<Option<String>>(3)?
                    .map(parse_media_type)
                    .transpose()?;
                let annotations = parse_annotations(&row.get::<String>(4)?)?;
                let descriptor = Descriptor {
                    media_type,
                    digest,
                    size,
                    urls: Vec::new(),
                    annotations,
                    data: None,
                    artifact_type,
                    platform: None,
                };
                descriptor.validate()?;
                Ok(descriptor)
            })
            .collect()
    }

    /// Atomically indexes one closed repository graph whose immutable bytes
    /// and exact placement presence were already verified.
    ///
    /// Repository links and bounded projections are written before the tag is
    /// moved. Checked identity guards roll the whole transaction back when any
    /// expected surface object, placement observation, descriptor target, or
    /// root is missing or conflicts.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or open graphs, absent exact placement
    /// evidence, conflicting immutable identity, or database failure.
    pub async fn index_oci_repository_catalog(
        &self,
        input: &IndexOciRepositoryCatalog,
    ) -> Result<OciRepositoryRecord> {
        validate_catalog(input)?;
        let now = input.observed_at;
        let repository_id = portable_relational_id(Uuid::new_v4());
        let mut statements = Vec::<CheckedStatement>::new();
        statements.push(
            Statement::new(
                "INSERT INTO oci_repositories
                   (id, registry_id, name, visibility, lifecycle_state,
                    resource_version, created_at, updated_at)
                 SELECT ?1, ?2, ?3, 'inherit', 'active', 1, ?4, ?4
                 WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_repositories
                     WHERE registry_id = ?2 AND name = ?3)",
                vals![
                    repository_id,
                    input.registry_id,
                    input.repository.as_str(),
                    now
                ]
                .to_vec(),
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "INSERT INTO oci_registry_state
                   (registry_id, mutation_epoch, charged_bytes,
                    charged_objects, updated_at)
                 SELECT ?1, 0, 0, 0, ?2
                 WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                 ON CONFLICT(registry_id) DO NOTHING",
                vals![input.registry_id, now].to_vec(),
            )
            .unchecked(),
        );

        let mut manifest_count = 0_i64;
        let mut edge_count = 0_i64;
        for object in &input.objects {
            extend_oci_object_statements(&mut statements, input, object)?;
        }
        for object in &input.objects {
            if let Some(projection) = &object.projection {
                manifest_count += 1;
                edge_count += extend_oci_projection_statements(
                    &mut statements,
                    input.registry_id,
                    &object.descriptor,
                    projection,
                    now,
                )?;
                extend_projection_identity_guards(&mut statements, input, object, projection)?;
            }
        }
        if let Some(tag) = &input.tag {
            statements.push(
                Statement::new(
                    "INSERT INTO oci_tag_history
                       (id, repository_id, registry_id, name, prior_digest,
                        next_digest, source_kind, actor_id, changed_at)
                     SELECT ?1, repository.id, repository.registry_id, ?4,
                            current.digest, ?5, ?6, ?7, ?8
                     FROM oci_repositories repository
                     LEFT JOIN oci_tags current
                       ON current.repository_id = repository.id AND current.name = ?4
                     WHERE repository.registry_id = ?2 AND repository.name = ?3
                       AND (current.digest IS NULL OR current.digest <> ?5)",
                    vals![
                        Uuid::new_v4().simple().to_string(),
                        input.registry_id,
                        input.repository.as_str(),
                        tag.as_str(),
                        input.root_digest.to_string(),
                        input.source_kind,
                        input.actor_id,
                        now
                    ]
                    .to_vec(),
                )
                .unchecked(),
            );
            statements.push(
                Statement::new(
                    "INSERT INTO oci_tags
                       (repository_id, registry_id, name, digest, source_kind,
                        resource_version, updated_at)
                     SELECT repository.id, repository.registry_id, ?3, ?4, ?5, 1, ?6
                     FROM oci_repositories repository
                     JOIN oci_repository_objects root
                       ON root.repository_id = repository.id
                      AND root.digest = ?4 AND root.object_kind = 'manifest'
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                     ON CONFLICT(repository_id, name) DO UPDATE SET
                       digest = excluded.digest, source_kind = excluded.source_kind,
                       resource_version = oci_tags.resource_version + 1,
                       updated_at = excluded.updated_at",
                    vals![
                        input.registry_id,
                        input.repository.as_str(),
                        tag.as_str(),
                        input.root_digest.to_string(),
                        input.source_kind,
                        now
                    ]
                    .to_vec(),
                )
                .unchecked(),
            );
        }
        extend_catalog_identity_guards(&mut statements, input, manifest_count, edge_count)?;
        self.backend.checked_batch(&statements).await?;
        self.oci_repository(input.registry_id, &input.repository)
            .await?
            .context("indexed OCI repository disappeared")
    }
}

fn row_to_oci_repository(row: &Row) -> Result<OciRepositoryRecord> {
    Ok(OciRepositoryRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        name: RepositoryName::parse(&row.get::<String>(2)?)?,
        visibility: row.get(3)?,
        lifecycle_state: row.get(4)?,
        resource_version: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn row_to_oci_blob(row: &Row) -> Result<OciBlobRecord> {
    Ok(OciBlobRecord {
        registry_id: row.get(0)?,
        digest: parse_digest(row.get(1)?)?,
        byte_size: parse_size(row.get(2)?)?,
        media_type: parse_media_type(row.get(3)?)?,
        surface_object_id: row.get(4)?,
        object_key: row.get(5)?,
        lifecycle_state: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn row_to_oci_manifest(row: &Row) -> Result<OciManifestRecord> {
    let os = row.get::<Option<String>>(7)?;
    let architecture = row.get::<Option<String>>(8)?;
    let variant = row.get::<Option<String>>(9)?;
    let platform = match (os, architecture) {
        (Some(os), Some(architecture)) => {
            let platform = Platform {
                architecture,
                os,
                os_version: None,
                os_features: Vec::new(),
                variant,
                features: Vec::new(),
            };
            platform.validate()?;
            Some(platform)
        }
        (None, None) if variant.is_none() => None,
        _ => bail!("persisted OCI platform projection is incomplete"),
    };
    let descriptor_count = u32::try_from(row.get::<i64>(11)?)
        .context("persisted OCI descriptor count is outside u32")?;
    Ok(OciManifestRecord {
        registry_id: row.get(0)?,
        digest: parse_digest(row.get(1)?)?,
        media_type: parse_media_type(row.get(2)?)?,
        byte_size: parse_size(row.get(3)?)?,
        artifact_type: row
            .get::<Option<String>>(4)?
            .map(parse_media_type)
            .transpose()?,
        subject_digest: row
            .get::<Option<String>>(5)?
            .map(parse_digest)
            .transpose()?,
        config_digest: row
            .get::<Option<String>>(6)?
            .map(parse_digest)
            .transpose()?,
        platform,
        annotations: parse_annotations(&row.get::<String>(10)?)?,
        descriptor_count,
        surface_object_id: row.get(12)?,
        object_key: row.get(13)?,
        created_at: row.get(14)?,
    })
}

fn row_to_oci_edge(row: &Row) -> Result<OciDescriptorEdgeRecord> {
    let os = row.get::<Option<String>>(5)?;
    let architecture = row.get::<Option<String>>(6)?;
    let variant = row.get::<Option<String>>(7)?;
    let platform = match (os, architecture) {
        (Some(os), Some(architecture)) => Some(Platform {
            architecture,
            os,
            os_version: None,
            os_features: Vec::new(),
            variant,
            features: Vec::new(),
        }),
        (None, None) if variant.is_none() => None,
        _ => bail!("persisted OCI edge platform is incomplete"),
    };
    let descriptor = Descriptor {
        media_type: parse_media_type(row.get(3)?)?,
        digest: parse_digest(row.get(2)?)?,
        size: parse_size(row.get(4)?)?,
        urls: Vec::new(),
        annotations: parse_annotations(&row.get::<String>(8)?)?,
        data: None,
        artifact_type: None,
        platform,
    };
    descriptor.validate()?;
    Ok(OciDescriptorEdgeRecord {
        role: row.get(0)?,
        ordinal: u32::try_from(row.get::<i64>(1)?)
            .context("persisted OCI edge ordinal is outside u32")?,
        descriptor,
    })
}

fn row_to_oci_tag(row: &Row) -> Result<OciTagRecord> {
    Ok(OciTagRecord {
        name: Tag::parse(&row.get::<String>(0)?)?,
        digest: parse_digest(row.get(1)?)?,
        source_kind: row.get(2)?,
        resource_version: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn parse_digest(value: String) -> Result<Sha256Digest> {
    Sha256Digest::parse(&value).map_err(Into::into)
}

fn parse_media_type(value: String) -> Result<MediaType> {
    MediaType::parse(&value).map_err(Into::into)
}

fn parse_size(value: i64) -> Result<u64> {
    u64::try_from(value).context("persisted OCI byte size is negative")
}

fn parse_annotations(value: &str) -> Result<Annotations> {
    let annotations =
        serde_json::from_str::<Annotations>(value).context("decoding persisted OCI annotations")?;
    annotations.validate()?;
    Ok(annotations)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn descriptor(media_type: MediaType, bytes: &[u8]) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(bytes),
            size: u64::try_from(bytes.len()).unwrap(),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn catalog_fixture(registry_id: i64, placement_id: i64) -> IndexOciRepositoryCatalog {
        let config = descriptor(MediaType::OciImageConfig, b"{}");
        let layer = descriptor(MediaType::OciLayerGzip, b"fixture-layer");
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: None,
            config: config.clone(),
            layers: vec![layer.clone()],
            subject: None,
            annotations: Annotations::new(),
        };
        let manifest_bytes = to_canonical_json(&manifest).unwrap();
        let mut manifest_descriptor = descriptor(MediaType::OciImageManifest, &manifest_bytes);
        manifest_descriptor.platform = Some(Platform::linux_amd64());
        IndexOciRepositoryCatalog {
            registry_id,
            placement_id,
            repository: RepositoryName::parse("aos").unwrap(),
            // Input order is deliberately root-first. Admission must not rely
            // on a producer topologically sorting the closed descriptor set.
            objects: vec![
                OciCatalogObject {
                    descriptor: manifest_descriptor.clone(),
                    projection: Some(OciCatalogProjection::Manifest(manifest)),
                },
                OciCatalogObject {
                    descriptor: config,
                    projection: None,
                },
                OciCatalogObject {
                    descriptor: layer,
                    projection: None,
                },
            ],
            root_digest: manifest_descriptor.digest,
            tag: Some(Tag::parse("latest").unwrap()),
            source_kind: "release".to_string(),
            actor_id: "test:release".to_string(),
            observed_at: 1_700_000_000,
        }
    }

    async fn catalog_database() -> (Database, i64, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org_id = db.create_org("oci-catalog", "OCI Catalog").await.unwrap();
        let registry_id = db
            .create_managed_registry(org_id, "", "containers", "public", &[], false)
            .await
            .unwrap();
        let owner = db.org_by_id(org_id).await.unwrap().unwrap();
        let binding_id = db
            .create_topology_binding(
                Some(org_id),
                "oci-catalog-binding",
                &owner.stable_id,
                "oci-catalog",
                "r2",
                None,
                Some("fixture-bucket"),
                Some("oci"),
                Some("https"),
                Some("dns"),
                Some(b"storage.example.invalid"),
                Some(443),
                Some("auto"),
                Some("private"),
            )
            .await
            .unwrap();
        let placement = db
            .create_surface_placement(&crate::db::NewSurfacePlacementSpec {
                surface: crate::db::SurfaceTarget::Registry(registry_id),
                name: "primary".to_string(),
                binding_id,
                prefix: "oci".to_string(),
                kind: "complete".to_string(),
                desired_state: "active".to_string(),
                hash_range: None,
                desired_read_enabled: true,
                read_order: 0,
                requires_conditional_writes: false,
            })
            .await
            .unwrap();
        db.observe_surface_placement(placement.id, "ready", "complete", 1)
            .await
            .unwrap();
        (db, registry_id, placement.id)
    }

    async fn record_catalog_bytes(db: &Database, input: &IndexOciRepositoryCatalog) {
        for object in &input.objects {
            let surface = db
                .create_surface_object(&crate::db::SetSurfaceObject {
                    surface: crate::db::SurfaceTarget::Registry(input.registry_id),
                    object_key: oci_blob_object_key(object.descriptor.digest),
                    content_hash: Some(object.descriptor.digest.encoded()),
                    size: Some(i64::try_from(object.descriptor.size).unwrap()),
                    object_kind: "immutable".to_string(),
                    mutable_publication_id: None,
                })
                .await
                .unwrap();
            db.backend
                .execute(
                    "INSERT INTO object_placements
                       (surface_object_id, cache_id, registry_id, placement_id,
                        state, observed_hash, observed_size, etag,
                        observed_inventory_generation, observed_at,
                        catalog_object_resource_version)
                     VALUES (?1, NULL, ?2, ?3, 'present', ?4, ?5, ?6, 1, ?7, ?8)",
                    &vals![
                        surface.id,
                        input.registry_id,
                        input.placement_id,
                        object.descriptor.digest.encoded(),
                        i64::try_from(object.descriptor.size).unwrap(),
                        format!("\"fixture-{}\"", object.descriptor.digest.encoded()),
                        input.observed_at,
                        surface.resource_version
                    ],
                )
                .await
                .unwrap();
        }
    }

    #[test]
    fn blob_keys_are_canonical_and_algorithm_free() {
        let digest = Sha256Digest::digest(b"layer");
        assert_eq!(
            oci_blob_object_key(digest),
            format!("oci/blobs/sha256/{}", digest.encoded())
        );
        assert!(!oci_blob_object_key(digest).contains(':'));
    }

    #[test]
    fn catalog_rejects_orphans_and_projection_identity_drift() {
        let mut catalog = catalog_fixture(1, 1);
        let orphan = descriptor(MediaType::OciLayerGzip, b"orphan");
        catalog.objects.push(OciCatalogObject {
            descriptor: orphan,
            projection: None,
        });
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("unreachable"));

        let mut catalog = catalog_fixture(1, 1);
        let root = catalog.objects.first_mut().unwrap();
        root.descriptor.size += 1;
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("size mismatch"));
    }

    #[tokio::test]
    async fn catalog_admission_is_atomic_repository_scoped_and_queryable() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let catalog = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &catalog).await;

        let repository = db.index_oci_repository_catalog(&catalog).await.unwrap();
        assert_eq!(repository.name.as_str(), "aos");
        let manifest = db
            .oci_manifest_for_repository(
                repository.id,
                &ManifestReference::Tag(Tag::parse("latest").unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(manifest.digest, catalog.root_digest);
        assert_eq!(manifest.descriptor_count, 2);
        assert_eq!(manifest.platform, Some(Platform::linux_amd64()));
        assert!(db
            .oci_repository_object_has_placement(
                repository.id,
                manifest.digest,
                placement_id,
                manifest.byte_size,
                manifest.media_type,
            )
            .await
            .unwrap());
        let verified = db
            .oci_release_descriptor_placement(
                repository.id,
                placement_id,
                ContainerReleaseDescriptorRole::PlatformManifest,
                &catalog.objects[0].descriptor,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified.digest, manifest.digest.to_string());
        assert_eq!(verified.byte_size, manifest.byte_size);
        assert_eq!(verified.placement_id, placement_id);
        assert!(verified.placement_observation_version > 0);
        let edges = db
            .oci_descriptor_edges(repository.id, manifest.digest)
            .await
            .unwrap();
        assert_eq!(
            edges
                .iter()
                .map(|edge| edge.role.as_str())
                .collect::<Vec<_>>(),
            ["config", "layer"]
        );
        assert_eq!(
            db.oci_tags(repository.id, 100, None).await.unwrap().len(),
            1
        );

        // Replaying the same signed catalog creates no duplicate immutable
        // objects, links, projections, or tag-history event.
        db.index_oci_repository_catalog(&catalog).await.unwrap();
        for table in [
            "oci_blobs",
            "oci_repository_objects",
            "oci_manifests",
            "oci_descriptor_edges",
            "oci_tags",
            "oci_tag_history",
        ] {
            let count: i64 = db
                .backend
                .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
                .await
                .unwrap()
                .unwrap()
                .get(0)
                .unwrap();
            let expected = match table {
                "oci_blobs" | "oci_repository_objects" => 3,
                "oci_descriptor_edges" => 2,
                _ => 1,
            };
            assert_eq!(count, expected, "unexpected rows in {table}");
        }

        let unknown = RepositoryName::parse("private/other").unwrap();
        assert!(db
            .oci_repository(registry_id, &unknown)
            .await
            .unwrap()
            .is_none());
        let root_blob = db
            .oci_blob_for_repository(repository.id, catalog.root_digest)
            .await
            .unwrap();
        assert!(root_blob.is_some());

        db.backend
            .execute(
                "UPDATE oci_manifests SET platform_architecture = 'arm64'
                 WHERE registry_id = ?1 AND digest = ?2",
                &vals![registry_id, catalog.root_digest.to_string()],
            )
            .await
            .unwrap();
        assert!(db.index_oci_repository_catalog(&catalog).await.is_err());
        let drifted = db
            .oci_manifest_for_repository(
                repository.id,
                &ManifestReference::Digest(catalog.root_digest),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(drifted.platform, Some(Platform::linux_arm64()));

        let mut absent = catalog;
        absent.repository = unknown.clone();
        absent.placement_id += 1_000;
        assert!(db.index_oci_repository_catalog(&absent).await.is_err());
        assert!(db
            .oci_repository(registry_id, &unknown)
            .await
            .unwrap()
            .is_none());
    }
}
