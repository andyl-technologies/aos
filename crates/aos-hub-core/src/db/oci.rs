//! Registry-owned OCI catalog persistence.
//!
//! Immutable bytes stay on the registry surface under
//! `oci/blobs/sha256/<hex>`. This module stores only their exact identity,
//! repository authorization links, bounded manifest projections, ordered
//! descriptor edges, and mutable tag pointers. Reads always begin with an
//! exact registry and repository; a registry-wide digest is never sufficient
//! authority to expose deduplicated content.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{bail, Context, Result};
use aos_oci_types::{
    Annotations, Descriptor, ImageConfig, ImageIndex, ImageManifest, ManifestReference, MediaType,
    Platform, RepositoryName, Sha256Digest, Tag,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::backend::{CheckedStatement, Statement};
use crate::value::Row;

use super::{
    portable_relational_id, ContainerReleaseDescriptorRole, Database,
    VerifiedContainerReleaseDescriptor,
};

#[path = "oci_publication.rs"]
mod publication;
#[path = "oci_upload.rs"]
mod upload;

pub use publication::*;
pub use upload::*;

const OCI_REPOSITORY_COLUMNS: &str = "id, registry_id, name, visibility,
    lifecycle_state, resource_version, created_at, updated_at";
const OCI_BLOB_COLUMNS: &str = "stored_blob.registry_id, stored_blob.digest,
    stored_blob.byte_size, link.media_type, stored_blob.surface_object_id,
    object.object_key, stored_blob.lifecycle_state, stored_blob.created_at,
    stored_blob.updated_at";
const OCI_MANIFEST_COLUMNS: &str = "manifest.registry_id, manifest.digest,
    manifest.media_type, manifest.byte_size, manifest.artifact_type,
    manifest.subject_digest, manifest.config_digest, manifest.platform_os,
    manifest.platform_architecture, manifest.platform_variant,
    manifest.platform_os_version, manifest.platform_os_features_json,
    manifest.annotations_json, manifest.descriptor_count,
    stored_blob.surface_object_id, object.object_key, manifest.created_at";
const OCI_MANIFEST_REFERENCE_PREDICATE: &str = "((link.digest = ?2 AND ?2 IS NOT NULL)
                         OR (tag.name = ?3 AND ?3 IS NOT NULL))";
const OCI_UPLOAD_COLUMNS: &str = "id, registry_id, repository_id, publication_id,
    quota_reservation_id, writer_id, token_id, expected_digest, expected_size,
    maximum_size, uploaded_size, staging_placement_id,
    staging_placement_resource_version, staging_binding_id,
    staging_binding_write_revision, final_digest, materialization_placement_id,
    materialization_placement_resource_version, materialization_binding_id,
    materialization_binding_write_revision, sha256_state_version, sha256_h0,
    sha256_h1, sha256_h2, sha256_h3, sha256_h4, sha256_h5, sha256_h6,
    sha256_h7, sha256_total_bytes, sha256_tail_hex, state, expires_at, created_at,
    finished_at, cleanup_state, cleanup_finished_at, resource_version";
const OCI_PUBLICATION_COLUMNS: &str = "id, registry_id, repository_id, writer_id,
    token_id, target_tag, expected_tag_version, expected_tag_digest, root_digest,
    catalog_digest, release_tag, sidecar_sha256, confirmation_hash, topology_digest,
    required_placement_count, source_kind, state, idempotency_key,
    commit_idempotency_key, abort_idempotency_key, expires_at, created_at,
    committed_at, resource_version";

/// Maximum tags returned by one Distribution page.
pub const OCI_MAX_TAG_PAGE: u32 = 1_000;

/// Maximum referrer descriptors returned in one response.
pub const OCI_MAX_REFERRERS: u32 = 1_000;

/// Current portable resumable SHA-256 state encoding.
pub const OCI_SHA256_STATE_VERSION: u32 = 1;

/// Maximum lifetime accepted for an upload or publication session.
pub const OCI_MAX_SESSION_SECONDS: i64 = 24 * 60 * 60;

/// Returns the canonical registry-surface key for an OCI content digest.
#[must_use]
pub fn oci_blob_object_key(digest: Sha256Digest) -> String {
    format!("oci/blobs/sha256/{}", digest.encoded())
}

/// Computes the stable digest of one frozen closed catalog declaration.
///
/// This hashes descriptor identities and bounded parsed projections, not the
/// manifest bytes themselves; each descriptor's digest already commits to
/// those exact (possibly noncanonical) bytes.
///
/// # Errors
///
/// Returns an error for an empty/oversized declaration, malformed descriptor
/// or projection, or canonical serialization failure.
pub fn oci_catalog_declaration_digest(
    root_digest: Sha256Digest,
    objects: &[OciCatalogObject],
) -> Result<Sha256Digest> {
    if objects.is_empty() || objects.len() > aos_oci_types::limits::MAX_REACHABLE_DESCRIPTORS {
        bail!("OCI catalog declaration count is outside admitted bounds");
    }
    let mut ordered = objects.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|object| object.descriptor.digest);
    let mut declaration = b"aos-hub/oci-catalog-declaration/v1\0".to_vec();
    declaration.extend_from_slice(root_digest.to_string().as_bytes());
    declaration.push(0);
    for object in ordered {
        object.descriptor.validate()?;
        let descriptor = aos_oci_types::to_canonical_json(&object.descriptor)?;
        declaration.extend_from_slice(
            &u64::try_from(descriptor.len())
                .context("OCI descriptor declaration length exceeds u64")?
                .to_be_bytes(),
        );
        declaration.extend_from_slice(&descriptor);
        let projection = match &object.projection {
            Some(OciCatalogProjection::Manifest {
                document, platform, ..
            }) => {
                document.validate()?;
                let projection = serde_json::json!({
                    "document": document,
                    "platform": platform,
                });
                aos_oci_types::to_canonical_json(&projection)?
            }
            Some(OciCatalogProjection::Index(index)) => {
                index.validate()?;
                aos_oci_types::to_canonical_json(index)?
            }
            None => Vec::new(),
        };
        declaration.extend_from_slice(
            &u64::try_from(projection.len())
                .context("OCI projection declaration length exceeds u64")?
                .to_be_bytes(),
        );
        declaration.extend_from_slice(&projection);
    }
    Ok(Sha256Digest::digest(&declaration))
}

/// Computes the confirmation hash shown for one publication plan.
#[must_use]
pub fn oci_publication_confirmation_hash(publication: &OciPublicationRecord) -> Sha256Digest {
    oci_publication_confirmation_hash_fields(
        &publication.id,
        publication.registry_id,
        publication.repository_id,
        publication.root_digest,
        publication.catalog_digest,
        publication.release_tag.as_deref(),
        publication.sidecar_sha256_hex.as_deref(),
        publication.target_tag.as_ref(),
        publication.expected_tag_version,
        publication.expected_tag_digest,
        publication.topology_digest,
        &publication.source_kind,
    )
}

/// Computes the stable digest of a complete required-placement capability set.
///
/// # Errors
///
/// Returns an error for an empty set, duplicate/invalid placements, malformed
/// capability fingerprints, or an oversized placement count.
pub fn oci_publication_topology_digest(
    placements: &[OciPublicationRequiredPlacement],
) -> Result<Sha256Digest> {
    if placements.is_empty() || placements.len() > 1_000 {
        bail!("OCI publication required placement count is outside admitted bounds");
    }
    let mut ordered = placements.to_vec();
    ordered.sort_by_key(|placement| placement.placement_id);
    let mut prior = None;
    let mut identity = b"aos-hub/oci-publication-topology/v1\0".to_vec();
    for placement in ordered {
        if placement.placement_id <= 0
            || placement.placement_resource_version < 1
            || placement.placement_write_spec_version < 1
            || placement.placement_observation_version < 1
            || placement.binding_id <= 0
            || placement.binding_write_revision < 1
            || placement.revision_fingerprint.is_empty()
            || placement.revision_fingerprint.len() > 128
            || placement.capability_fingerprint.is_empty()
            || placement.capability_fingerprint.len() > 128
            || prior == Some(placement.placement_id)
        {
            bail!("OCI publication required placement declaration is malformed");
        }
        prior = Some(placement.placement_id);
        for number in [
            placement.placement_id,
            placement.placement_resource_version,
            placement.placement_write_spec_version,
            placement.placement_observation_version,
            placement.binding_id,
            placement.binding_write_revision,
        ] {
            identity.extend_from_slice(&number.to_be_bytes());
        }
        for fingerprint in [
            placement.revision_fingerprint,
            placement.capability_fingerprint,
        ] {
            identity.extend_from_slice(fingerprint.as_bytes());
            identity.push(0);
        }
    }
    Ok(Sha256Digest::digest(&identity))
}

#[allow(clippy::too_many_arguments)]
fn oci_publication_confirmation_hash_fields(
    publication_id: &str,
    registry_id: i64,
    repository_id: i64,
    root_digest: Sha256Digest,
    catalog_digest: Sha256Digest,
    release_tag: Option<&str>,
    sidecar_sha256_hex: Option<&str>,
    target_tag: Option<&Tag>,
    expected_tag_version: Option<i64>,
    expected_tag_digest: Option<Sha256Digest>,
    topology_digest: Sha256Digest,
    source_kind: &str,
) -> Sha256Digest {
    let mut identity = b"aos-hub/oci-publication-confirmation/v1\0".to_vec();
    let registry_id = registry_id.to_string();
    let repository_id = repository_id.to_string();
    let root_digest = root_digest.to_string();
    let catalog_digest = catalog_digest.to_string();
    let topology_digest = topology_digest.to_string();
    for field in [
        publication_id,
        registry_id.as_str(),
        repository_id.as_str(),
        root_digest.as_str(),
        catalog_digest.as_str(),
        release_tag.unwrap_or(""),
        sidecar_sha256_hex.unwrap_or(""),
        target_tag.map(Tag::as_str).unwrap_or(""),
        topology_digest.as_str(),
        source_kind,
    ] {
        identity.extend_from_slice(field.as_bytes());
        identity.push(0);
    }
    identity.extend_from_slice(&expected_tag_version.unwrap_or(0).to_be_bytes());
    identity.extend_from_slice(
        expected_tag_digest
            .map(|digest| digest.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    Sha256Digest::digest(&identity)
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
            (
                Some(OciCatalogProjection::Manifest {
                    document,
                    platform,
                    image_config,
                }),
                media_type,
            ) if media_type.is_image_manifest() => {
                document.validate()?;
                match (document.artifact_type, platform) {
                    (None, Some(platform)) => platform.validate()?,
                    (Some(_), None) => {}
                    (None, None) => bail!("runnable OCI manifest requires its config platform"),
                    (Some(_), Some(_)) => bail!("OCI artifact manifest cannot carry a platform"),
                }
                if let Some(image_config) = image_config {
                    let config = ImageConfig::from_json(image_config.config_json.as_bytes())?;
                    let config_platform = config.platform();
                    if Sha256Digest::digest(image_config.config_json.as_bytes())
                        != document.config.digest
                        || platform.as_ref() != Some(&config_platform)
                        || config.rootfs.diff_ids.len() != document.layers.len()
                        || image_config.layers.len() != document.layers.len()
                        || config
                            .rootfs
                            .diff_ids
                            .iter()
                            .zip(&image_config.layers)
                            .any(|(diff_id, layer)| diff_id != &layer.diff_id)
                    {
                        bail!("OCI image administration projection conflicts with its config");
                    }
                }
            }
            (Some(OciCatalogProjection::Index(index)), media_type)
                if media_type.is_image_index() =>
            {
                index.validate()?;
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
    for object in &input.objects {
        let descriptors = match &object.projection {
            Some(OciCatalogProjection::Manifest { document, .. }) => manifest_descriptors(document),
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
            Some(OciCatalogProjection::Manifest { document, .. }) => {
                let mut dependencies = vec![document.config.digest];
                dependencies.extend(document.layers.iter().map(|layer| layer.digest));
                dependencies.extend(document.subject.iter().map(|subject| subject.digest));
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
    for object in &input.objects {
        let Some(OciCatalogProjection::Index(index)) = &object.projection else {
            continue;
        };
        for child in &index.manifests {
            let target = input
                .objects
                .iter()
                .find(|candidate| candidate.descriptor.digest == child.digest)
                .context("OCI index child projection is absent")?;
            if let Some(OciCatalogProjection::Manifest { platform, .. }) = &target.projection {
                if child.platform.as_ref() != platform.as_ref() {
                    bail!(
                        "OCI index platform for {} conflicts with its exact image config",
                        child.digest
                    );
                }
            }
        }
    }

    let mut visiting = BTreeSet::new();
    let mut reached = BTreeSet::new();
    validate_graph_from(input.root_digest, 0, &graph, &mut visiting, &mut reached)?;
    loop {
        let mut admitted_referrer = false;
        for object in &input.objects {
            if reached.contains(&object.descriptor.digest) {
                continue;
            }
            let Some(OciCatalogProjection::Manifest { document, .. }) = &object.projection else {
                continue;
            };
            let Some(subject) = &document.subject else {
                continue;
            };
            if document.artifact_type.is_none() || !reached.contains(&subject.digest) {
                continue;
            }
            validate_graph_from(
                object.descriptor.digest,
                0,
                &graph,
                &mut visiting,
                &mut reached,
            )?;
            admitted_referrer = true;
        }
        if !admitted_referrer {
            break;
        }
    }
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
    // Quota ownership is scoped to the immutable registry digest, not to one
    // catalog request. A concurrent catalog replay therefore observes the same
    // reservation instead of charging a second random owner. An upload claim
    // wins the opposite race and makes catalog admission retry after upload
    // completion, where the already-charged blob is reused.
    let (quota_id, quota_owner) = catalog_quota_identity(input.registry_id, digest);
    statements.extend([
        Statement::new(
            "INSERT INTO oci_quota_reservations
               (id, registry_id, org_id, owner_kind, owner_id,
                reserved_bytes, reserved_objects, state, created_at, updated_at)
             SELECT ?1, registry.id, registry.org_id, 'catalog', ?5,
                    ?3, 1, 'pending', ?4, ?4
             FROM registries registry
             WHERE registry.id = ?2
               AND NOT EXISTS (SELECT 1 FROM oci_blobs stored_blob
                 WHERE stored_blob.registry_id = ?2 AND stored_blob.digest = ?6)
               AND NOT EXISTS (SELECT 1 FROM oci_blob_claims claim
                 WHERE claim.registry_id = ?2 AND claim.digest = ?6)
             ON CONFLICT(id) DO NOTHING",
            vals![
                quota_id,
                input.registry_id,
                size,
                input.observed_at,
                quota_owner,
                wire
            ],
        )
        .unchecked(),
        Statement::new(
            "UPDATE oci_quota_reservations SET state = 'reserved', updated_at = ?2
             WHERE id = ?1 AND state = 'pending'
               AND EXISTS (SELECT 1 FROM org_usage quota_usage
                 WHERE quota_usage.org_id = oci_quota_reservations.org_id
                   AND ((SELECT max_bytes FROM org_quotas
                          WHERE org_id = quota_usage.org_id) IS NULL
                     OR quota_usage.used_bytes + oci_quota_reservations.reserved_bytes
                        <= (SELECT max_bytes FROM org_quotas
                            WHERE org_id = quota_usage.org_id))
                   AND ((SELECT max_objects FROM org_quotas
                          WHERE org_id = quota_usage.org_id) IS NULL
                     OR quota_usage.object_count + oci_quota_reservations.reserved_objects
                        <= (SELECT max_objects FROM org_quotas
                            WHERE org_id = quota_usage.org_id)))",
            vals![quota_id, input.observed_at],
        )
        .unchecked(),
        Statement::new(
            "UPDATE org_usage
             SET used_bytes = used_bytes + (SELECT reserved_bytes
                   FROM oci_quota_reservations WHERE id = ?1 AND state = 'reserved'),
                 object_count = object_count + (SELECT reserved_objects
                   FROM oci_quota_reservations WHERE id = ?1 AND state = 'reserved'),
                 updated_at = ?2
             WHERE org_id = (SELECT org_id FROM oci_quota_reservations
               WHERE id = ?1 AND state = 'reserved')",
            vals![quota_id, input.observed_at],
        )
        .unchecked(),
    ]);
    statements.push(
        Statement::new(
            "INSERT INTO oci_blobs
               (registry_id, digest, byte_size, media_type, surface_object_id,
                quota_bytes, lifecycle_state, created_at, updated_at,
                unreferenced_since)
             SELECT ?1, ?2, ?3, ?4, object.id, ?3, 'active', ?5, ?5, ?5
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
               AND NOT EXISTS (SELECT 1 FROM oci_blob_claims claim
                 WHERE claim.registry_id = ?1 AND claim.digest = ?2)
               AND (EXISTS (SELECT 1 FROM oci_blobs existing
                      WHERE existing.registry_id = ?1 AND existing.digest = ?2)
                 OR EXISTS (SELECT 1 FROM oci_quota_reservations reservation
                      WHERE reservation.id = ?9 AND reservation.state = 'reserved'))
             ON CONFLICT(registry_id, digest) DO NOTHING",
            vals![
                input.registry_id,
                wire,
                size,
                "application/octet-stream",
                input.observed_at,
                input.placement_id,
                key,
                encoded,
                quota_id
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "UPDATE oci_quota_reservations SET state = 'committed', updated_at = ?2
             WHERE id = ?1 AND state = 'reserved'
               AND EXISTS (SELECT 1 FROM oci_blobs stored_blob
                 WHERE stored_blob.registry_id = ?3 AND stored_blob.digest = ?4
                   AND stored_blob.byte_size = ?5)",
            vals![quota_id, input.observed_at, input.registry_id, wire, size],
        )
        .unchecked(),
    );
    // Catalog linkage is not itself a retention root. A tag, signed root,
    // lease, upload, or in-flight publication clears this timestamp; an
    // untagged direct admission starts its conservative grace immediately.
    statements.push(
        Statement::new(
            "INSERT INTO oci_repository_objects
               (repository_id, registry_id, digest, object_kind, media_type, linked_at)
             SELECT repository.id, repository.registry_id, ?3, ?4, ?5, ?6
             FROM oci_repositories repository
             JOIN oci_blobs stored_blob
               ON stored_blob.registry_id = repository.registry_id
              AND stored_blob.digest = ?3
             WHERE repository.registry_id = ?1 AND repository.name = ?2
             ON CONFLICT(repository_id, digest) DO NOTHING",
            vals![
                input.registry_id,
                input.repository.as_str(),
                digest.to_string(),
                object_kind,
                object.descriptor.media_type.as_str(),
                input.observed_at
            ]
            .to_vec(),
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "UPDATE oci_repository_objects
             SET object_kind = ?4, media_type = ?5, linked_at = ?6
             WHERE repository_id = (SELECT id FROM oci_repositories
               WHERE registry_id = ?1 AND name = ?2)
               AND digest = ?3
               AND media_type = 'application/octet-stream'",
            vals![
                input.registry_id,
                input.repository.as_str(),
                digest.to_string(),
                object_kind,
                object.descriptor.media_type.as_str(),
                input.observed_at
            ],
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
    let (artifact_type, subject, config, annotations, edges, platform) = match projection {
        OciCatalogProjection::Manifest {
            document, platform, ..
        } => (
            document.artifact_type,
            document
                .subject
                .as_ref()
                .map(|descriptor| descriptor.digest),
            Some(document.config.digest),
            &document.annotations,
            manifest_edges(document),
            platform.as_ref(),
        ),
        OciCatalogProjection::Index(index) => (
            None,
            index.subject.as_ref().map(|descriptor| descriptor.digest),
            None,
            &index.annotations,
            index_edges(index),
            None,
        ),
    };
    let size = i64::try_from(object.size).context("OCI manifest size exceeds int64")?;
    let descriptor_count = i64::try_from(edges.len()).context("OCI edge count exceeds int64")?;
    let platform_os_features_json = serde_json::to_string(
        platform
            .map(|platform| platform.os_features.as_slice())
            .unwrap_or_default(),
    )?;
    statements.push(
        Statement::new(
            "INSERT INTO oci_manifests
               (registry_id, digest, media_type, byte_size, schema_version,
                artifact_type, subject_digest, config_digest, platform_os,
                platform_architecture, platform_variant, platform_os_version,
                platform_os_features_json, annotations_json, descriptor_count,
                created_at)
             SELECT ?1, ?2, ?3, ?4, 2, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15
             FROM oci_blobs stored_blob
             WHERE stored_blob.registry_id = ?1 AND stored_blob.digest = ?2
               AND stored_blob.byte_size = ?4
             ON CONFLICT(registry_id, digest) DO UPDATE SET
               platform_os_version = excluded.platform_os_version,
               platform_os_features_json = excluded.platform_os_features_json",
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
                platform.and_then(|platform| platform.os_version.as_deref()),
                platform_os_features_json,
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
        let edge_os_features_json = serde_json::to_string(
            edge.descriptor
                .platform
                .as_ref()
                .map(|platform| platform.os_features.as_slice())
                .unwrap_or_default(),
        )?;
        statements.push(
            Statement::new(
                "INSERT INTO oci_descriptor_edges
                   (registry_id, manifest_digest, edge_role, ordinal,
                    target_digest, media_type, byte_size, platform_os,
                    platform_architecture, platform_variant,
                    platform_os_version, platform_os_features_json,
                    annotations_json)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13
                 FROM oci_manifests manifest
                 JOIN oci_blobs target
                   ON target.registry_id = manifest.registry_id
                  AND target.digest = ?5 AND target.byte_size = ?7
                 WHERE manifest.registry_id = ?1 AND manifest.digest = ?2
                 ON CONFLICT(registry_id, manifest_digest, edge_role, ordinal)
                 DO UPDATE SET
                   platform_os_version = excluded.platform_os_version,
                   platform_os_features_json = excluded.platform_os_features_json",
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
                    edge.descriptor
                        .platform
                        .as_ref()
                        .and_then(|platform| platform.os_version.as_deref()),
                    edge_os_features_json,
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
                   JOIN oci_blobs stored_blob
                     ON stored_blob.registry_id = link.registry_id
                    AND stored_blob.digest = link.digest
                   JOIN object_placements presence
                     ON presence.surface_object_id = stored_blob.surface_object_id
                    AND presence.registry_id = stored_blob.registry_id
                   WHERE link.repository_id = oci_repositories.id
                     AND link.digest = ?{start}
                     AND link.media_type = ?{}
                     AND stored_blob.byte_size = ?{}
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
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                 WHERE registry_lock.registry_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                 WHERE purge.registry_id = ?1 AND purge.state = 'collecting')
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
    let (artifact_type, subject, config, annotations, edges, platform) = match projection {
        OciCatalogProjection::Manifest {
            document, platform, ..
        } => (
            document.artifact_type,
            document
                .subject
                .as_ref()
                .map(|descriptor| descriptor.digest),
            Some(document.config.digest),
            &document.annotations,
            manifest_edges(document),
            platform.as_ref(),
        ),
        OciCatalogProjection::Index(index) => (
            None,
            index.subject.as_ref().map(|descriptor| descriptor.digest),
            None,
            &index.annotations,
            index_edges(index),
            None,
        ),
    };
    let descriptor_count = i64::try_from(edges.len()).context("OCI edge count exceeds int64")?;
    let platform_os_features_json = serde_json::to_string(
        platform
            .map(|platform| platform.os_features.as_slice())
            .unwrap_or_default(),
    )?;
    statements.push(
        Statement::new(
            "UPDATE oci_repositories
             SET resource_version = resource_version + 1, updated_at = ?1
             WHERE registry_id = ?2 AND name = ?3
               AND EXISTS (SELECT 1 FROM oci_manifests manifest
                 WHERE manifest.registry_id = ?2 AND manifest.digest = ?4
                   AND manifest.media_type = ?5 AND manifest.byte_size = ?6
                   AND (manifest.artifact_type = ?7
                     OR (manifest.artifact_type IS NULL AND ?7 IS NULL))
                   AND (manifest.subject_digest = ?8
                     OR (manifest.subject_digest IS NULL AND ?8 IS NULL))
                   AND (manifest.config_digest = ?9
                     OR (manifest.config_digest IS NULL AND ?9 IS NULL))
                   AND (manifest.platform_os = ?10
                     OR (manifest.platform_os IS NULL AND ?10 IS NULL))
                   AND (manifest.platform_architecture = ?11
                     OR (manifest.platform_architecture IS NULL AND ?11 IS NULL))
                   AND (manifest.platform_variant = ?12
                     OR (manifest.platform_variant IS NULL AND ?12 IS NULL))
                   AND (manifest.platform_os_version = ?13
                     OR (manifest.platform_os_version IS NULL AND ?13 IS NULL))
                   AND manifest.platform_os_features_json = ?14
                   AND manifest.annotations_json = ?15
                   AND manifest.descriptor_count = ?16
                   AND (SELECT COUNT(*) FROM oci_descriptor_edges edge
                     WHERE edge.registry_id = manifest.registry_id
                       AND edge.manifest_digest = manifest.digest) = ?16)",
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
                platform.and_then(|platform| platform.os_version.as_deref()),
                platform_os_features_json,
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
        let edge_os_features_json = serde_json::to_string(
            edge.descriptor
                .platform
                .as_ref()
                .map(|platform| platform.os_features.as_slice())
                .unwrap_or_default(),
        )?;
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
                       AND (edge.platform_os = ?10
                         OR (edge.platform_os IS NULL AND ?10 IS NULL))
                       AND (edge.platform_architecture = ?11
                         OR (edge.platform_architecture IS NULL AND ?11 IS NULL))
                       AND (edge.platform_variant = ?12
                         OR (edge.platform_variant IS NULL AND ?12 IS NULL))
                       AND (edge.platform_os_version = ?13
                         OR (edge.platform_os_version IS NULL AND ?13 IS NULL))
                       AND edge.platform_os_features_json = ?14
                       AND edge.annotations_json = ?15)",
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
                    edge.descriptor
                        .platform
                        .as_ref()
                        .and_then(|platform| platform.os_version.as_deref()),
                    edge_os_features_json,
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

fn projection_from_records(
    manifest: &OciManifestRecord,
    edges: &[OciDescriptorEdgeRecord],
) -> Result<OciCatalogProjection> {
    let subject = edges
        .iter()
        .find(|edge| edge.role == "subject")
        .map(|edge| edge.descriptor.clone());
    if subject.as_ref().map(|descriptor| descriptor.digest) != manifest.subject_digest {
        bail!("persisted OCI subject projection conflicts with its descriptor edge");
    }
    if manifest.media_type.is_image_index() {
        let manifests = edges
            .iter()
            .filter(|edge| edge.role == "child")
            .map(|edge| edge.descriptor.clone())
            .collect();
        let index = ImageIndex {
            schema_version: 2,
            media_type: Some(manifest.media_type),
            artifact_type: None,
            manifests,
            subject,
            annotations: manifest.annotations.clone(),
        };
        index.validate()?;
        return Ok(OciCatalogProjection::Index(index));
    }

    let config = edges
        .iter()
        .find(|edge| edge.role == "config")
        .map(|edge| edge.descriptor.clone())
        .context("persisted OCI manifest lacks its config descriptor edge")?;
    if Some(config.digest) != manifest.config_digest {
        bail!("persisted OCI config projection conflicts with its descriptor edge");
    }
    let layer_role = if manifest.artifact_type.is_some() {
        "payload"
    } else {
        "layer"
    };
    let layers = edges
        .iter()
        .filter(|edge| edge.role == layer_role)
        .map(|edge| edge.descriptor.clone())
        .collect();
    let projected = ImageManifest {
        schema_version: 2,
        media_type: Some(manifest.media_type),
        artifact_type: manifest.artifact_type,
        config,
        layers,
        subject,
        annotations: manifest.annotations.clone(),
    };
    projected.validate()?;
    Ok(OciCatalogProjection::Manifest {
        document: projected,
        platform: manifest.platform.clone(),
        image_config: None,
    })
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
    /// Reserved manifest-local platform field.
    ///
    /// OCI platforms belong to the parent index descriptor and are exposed on
    /// [`OciDescriptorEdgeRecord::descriptor`], so new admissions leave this
    /// field absent even when an index child descriptor has a platform.
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

/// One verified layer measurement paired with an image-config DiffID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLayerProjection {
    /// Independently observed uncompressed tar byte length.
    pub unpacked_byte_size: u64,
    /// Exact uncompressed content digest from the image configuration.
    pub diff_id: Sha256Digest,
    /// Signed closure grouping, empty until a release-root snapshot supplies it.
    pub closure_group: String,
}

/// Exact runnable-image configuration projected during catalog admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciImageConfigProjection {
    /// Exact bounded configuration JSON bytes as UTF-8.
    pub config_json: String,
    /// Canonical AOS/Nix system selector.
    pub aos_system: String,
    /// Layer measurements in manifest descriptor order.
    pub layers: Vec<OciLayerProjection>,
}

/// One legacy runnable root awaiting exact-byte administration reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAdminProjectionReconciliationRoot {
    /// Owning repository id.
    pub repository_id: i64,
    /// Registry-local repository name.
    pub repository: RepositoryName,
    /// Exact direct manifest or image-index root descriptor.
    pub root: Descriptor,
}

/// Bounded parsed form of one exact manifest object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciCatalogProjection {
    /// OCI or Docker image manifest.
    Manifest {
        /// Bounded parsed manifest projection.
        document: ImageManifest,
        /// Exact config-derived platform for runnable images; absent for artifacts.
        platform: Option<Platform>,
        /// Exact image configuration and layer measurements for runnable images.
        image_config: Option<OciImageConfigProjection>,
    },
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

fn validate_session_identity(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("OCI {label} is malformed");
    }
    Ok(())
}

fn validate_session_times(now: i64, expires_at: i64) -> Result<()> {
    if now <= 0 || expires_at <= now || expires_at - now > OCI_MAX_SESSION_SECONDS {
        bail!("OCI session expiry is outside the allowed window");
    }
    Ok(())
}

fn checked_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("OCI {label} exceeds int64"))
}

fn reservation_id(owner_id: &str) -> String {
    format!("q-{owner_id}")
}

fn catalog_quota_identity(registry_id: i64, digest: Sha256Digest) -> (String, String) {
    let owner = format!("catalog:{registry_id}:{digest}");
    (reservation_id(&owner), owner)
}

fn validate_sha_progress(state: &OciSha256State, uploaded_size: u64) -> Result<()> {
    state.validate()?;
    if state.total_bytes != uploaded_size {
        bail!("OCI SHA-256 total does not equal uploaded size");
    }
    Ok(())
}

fn build_oci_catalog_statements(
    input: &IndexOciRepositoryCatalog,
) -> Result<Vec<CheckedStatement>> {
    validate_catalog(input)?;
    let now = input.observed_at;
    let repository_id = portable_relational_id(Uuid::new_v4());
    let mut statements = Vec::<CheckedStatement>::new();
    statements.push(
        Statement::new(
            "UPDATE registries SET updated_at = updated_at
             WHERE id = ?1
               AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                 WHERE registry_lock.registry_id = ?1)
               AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                 WHERE purge.registry_id = ?1 AND purge.state = 'collecting')",
            vals![input.registry_id],
        )
        .expecting(1),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_repositories
               (id, registry_id, name, visibility, lifecycle_state,
                resource_version, created_at, updated_at)
             SELECT ?1, ?2, ?3, 'inherit', 'active', 1, ?4, ?4
             WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?2)
               AND NOT EXISTS (SELECT 1 FROM oci_repositories
                 WHERE registry_id = ?2 AND name = ?3)
             ON CONFLICT(registry_id, name) DO NOTHING",
            vals![
                repository_id,
                input.registry_id,
                input.repository.as_str(),
                now
            ],
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
            vals![input.registry_id, now],
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_repository_metadata
               (repository_id, registry_id, description, resource_version, updated_at)
             SELECT repository.id, repository.registry_id, '', 1, ?3
             FROM oci_repositories repository
             WHERE repository.registry_id = ?1 AND repository.name = ?2
             ON CONFLICT(repository_id) DO NOTHING",
            vals![input.registry_id, input.repository.as_str(), now],
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "INSERT INTO org_usage (org_id, used_bytes, object_count, updated_at)
             SELECT registry.org_id, 0, 0, ?2 FROM registries registry
             WHERE registry.id = ?1
             ON CONFLICT(org_id) DO NOTHING",
            vals![input.registry_id, now],
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
    for object in &input.objects {
        match &object.projection {
            Some(OciCatalogProjection::Manifest {
                document,
                platform: Some(platform),
                image_config: Some(image_config),
            }) => extend_oci_admin_manifest_projection(
                &mut statements,
                input,
                &object.descriptor,
                document,
                platform,
                image_config,
            )?,
            Some(OciCatalogProjection::Manifest {
                platform: Some(_),
                image_config: None,
                ..
            }) => extend_existing_oci_admin_manifest_projection(
                &mut statements,
                input,
                object.descriptor.digest,
            ),
            _ => {}
        }
    }
    for object in &input.objects {
        if let Some(OciCatalogProjection::Index(index)) = &object.projection {
            extend_oci_admin_index_projection(
                &mut statements,
                input,
                object.descriptor.digest,
                index,
            );
        }
    }
    if let Some(tag) = &input.tag {
        let tag_history_id = Uuid::new_v4().simple().to_string();
        statements.push(
            Statement::new(
                "UPDATE oci_repositories SET resource_version = resource_version
                 WHERE registry_id = ?1 AND name = ?2
                   AND NOT EXISTS (SELECT 1 FROM oci_tags current
                     WHERE current.repository_id = oci_repositories.id
                       AND current.name = ?3
                       AND current.source_kind IN('release', 'channel')
                       AND (?4 = 'manual' OR current.digest <> ?5))",
                vals![
                    input.registry_id,
                    input.repository.as_str(),
                    tag.as_str(),
                    input.source_kind,
                    input.root_digest.to_string()
                ],
            )
            .expecting(1),
        );
        statements.push(
            Statement::new(
                "INSERT INTO oci_tag_history
                   (id, repository_id, registry_id, name, prior_digest,
                    next_digest, source_kind, actor_id, changed_at,
                    tag_resource_version)
                 SELECT ?1, repository.id, repository.registry_id, ?4,
                        current.digest, ?5, ?6, ?7, ?8,
                        (SELECT COUNT(*) + 1 FROM oci_tag_history prior
                         WHERE prior.repository_id = repository.id
                           AND prior.name = ?4)
                 FROM oci_repositories repository
                 LEFT JOIN oci_tags current
                   ON current.repository_id = repository.id AND current.name = ?4
                 WHERE repository.registry_id = ?2 AND repository.name = ?3
                   AND (current.digest IS NULL OR current.digest <> ?5)",
                vals![
                    tag_history_id.clone(),
                    input.registry_id,
                    input.repository.as_str(),
                    tag.as_str(),
                    input.root_digest.to_string(),
                    input.source_kind,
                    input.actor_id,
                    now
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "INSERT INTO oci_tags
                   (repository_id, registry_id, name, digest, source_kind,
                    resource_version, updated_at, created_at)
                 SELECT repository.id, repository.registry_id, ?3, ?4, ?5, 1, ?6, ?6
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
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_blobs
                 SET unreferenced_since = COALESCE(unreferenced_since, ?4),
                     updated_at = ?4
                 WHERE registry_id = ?1
                   AND digest = (SELECT prior_digest FROM oci_tag_history WHERE id = ?2)
                   AND digest <> ?3 AND lifecycle_state = 'active'
                   AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.registry_id = ?1 AND tag.digest = oci_blobs.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                     WHERE root.registry_id = ?1 AND root.index_digest = oci_blobs.digest)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_evidence evidence
                     WHERE evidence.registry_id = ?1
                       AND evidence.referrer_digest = oci_blobs.digest
                       AND evidence.verification = 'verified')",
                vals![
                    input.registry_id,
                    tag_history_id,
                    input.root_digest.to_string(),
                    now
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "UPDATE oci_blobs SET unreferenced_since = NULL, updated_at = ?3
                 WHERE registry_id = ?1 AND digest = ?2 AND lifecycle_state = 'active'",
                vals![input.registry_id, input.root_digest.to_string(), now],
            )
            .expecting(1),
        );
    }
    extend_catalog_identity_guards(&mut statements, input, manifest_count, edge_count)?;
    Ok(statements)
}

fn extend_oci_admin_manifest_projection(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    manifest_descriptor: &Descriptor,
    document: &ImageManifest,
    platform: &Platform,
    image_config: &OciImageConfigProjection,
) -> Result<()> {
    if document.layers.len() != image_config.layers.len() {
        bail!("OCI administration layer projection count conflicts with its manifest");
    }
    let compressed_byte_size =
        document
            .layers
            .iter()
            .try_fold(document.config.size, |sum, layer| {
                sum.checked_add(layer.size)
                    .context("OCI image compressed byte size exceeds u64")
            })?;
    let unpacked_byte_size = image_config.layers.iter().try_fold(0_u64, |sum, layer| {
        sum.checked_add(layer.unpacked_byte_size)
            .context("OCI image unpacked byte size exceeds u64")
    })?;
    let layer_count =
        i64::try_from(document.layers.len()).context("OCI layer count exceeds int64")?;
    let os_features_json = serde_json::to_string(&platform.os_features)
        .context("encoding OCI platform OS features")?;
    statements.push(
        Statement::new(
            "INSERT INTO oci_image_config_projections
               (registry_id, repository_id, root_digest, manifest_digest,
                config_digest, operating_system, architecture, variant,
                os_version, os_features_json, aos_system,
                compressed_byte_size, unpacked_byte_size, layer_count,
                config_json, verified_at)
             SELECT repository.registry_id, repository.id, ?3, ?3, ?4, ?5,
                    ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
             FROM oci_repositories repository
             WHERE repository.registry_id = ?1 AND repository.name = ?2
               AND repository.lifecycle_state = 'active'
             ON CONFLICT(repository_id, root_digest, manifest_digest) DO UPDATE SET
               config_digest = excluded.config_digest,
               operating_system = excluded.operating_system,
               architecture = excluded.architecture, variant = excluded.variant,
               os_version = excluded.os_version,
               os_features_json = excluded.os_features_json,
               aos_system = excluded.aos_system,
               compressed_byte_size = excluded.compressed_byte_size,
               unpacked_byte_size = excluded.unpacked_byte_size,
               layer_count = excluded.layer_count,
               config_json = excluded.config_json, verified_at = excluded.verified_at",
            vals![
                input.registry_id,
                input.repository.as_str(),
                manifest_descriptor.digest.to_string(),
                document.config.digest.to_string(),
                platform.os,
                platform.architecture,
                platform.variant.as_deref(),
                platform.os_version.as_deref(),
                os_features_json,
                image_config.aos_system,
                checked_u64(compressed_byte_size, "image compressed size")?,
                checked_u64(unpacked_byte_size, "image unpacked size")?,
                layer_count,
                image_config.config_json,
                input.observed_at
            ],
        )
        .expecting(1),
    );
    for (ordinal, (descriptor, projection)) in
        document.layers.iter().zip(&image_config.layers).enumerate()
    {
        statements.push(
            Statement::new(
                "INSERT INTO oci_release_layers
                   (registry_id, repository_id, root_digest, manifest_digest,
                    ordinal, digest, media_type, compressed_byte_size,
                    unpacked_byte_size, diff_id, closure_group, verified_at)
                 SELECT repository.registry_id, repository.id, ?3, ?3, ?4,
                        ?5, ?6, ?7, ?8, ?9, ?10, ?11
                 FROM oci_repositories repository
                 WHERE repository.registry_id = ?1 AND repository.name = ?2
                   AND repository.lifecycle_state = 'active'
                 ON CONFLICT(repository_id, root_digest, manifest_digest, ordinal)
                 DO UPDATE SET digest = excluded.digest,
                   media_type = excluded.media_type,
                   compressed_byte_size = excluded.compressed_byte_size,
                   unpacked_byte_size = excluded.unpacked_byte_size,
                   diff_id = excluded.diff_id,
                   closure_group = excluded.closure_group,
                   verified_at = excluded.verified_at",
                vals![
                    input.registry_id,
                    input.repository.as_str(),
                    manifest_descriptor.digest.to_string(),
                    i64::try_from(ordinal).context("OCI layer ordinal exceeds int64")?,
                    descriptor.digest.to_string(),
                    descriptor.media_type.as_str(),
                    checked_u64(descriptor.size, "layer compressed size")?,
                    checked_u64(projection.unpacked_byte_size, "layer unpacked size")?,
                    projection.diff_id.to_string(),
                    projection.closure_group,
                    input.observed_at
                ],
            )
            .expecting(1),
        );
    }
    statements.push(
        Statement::new(
            "DELETE FROM oci_admin_projection_reconciliations
             WHERE registry_id = ?1
               AND repository_id = (SELECT id FROM oci_repositories
                 WHERE registry_id = ?1 AND name = ?2)
               AND root_digest = ?3 AND manifest_digest = ?3",
            vals![
                input.registry_id,
                input.repository.as_str(),
                manifest_descriptor.digest.to_string()
            ],
        )
        .unchecked(),
    );
    Ok(())
}

fn extend_oci_admin_index_projection(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    root_digest: Sha256Digest,
    index: &ImageIndex,
) {
    for child in &index.manifests {
        statements.push(
            Statement::new(
                "INSERT INTO oci_image_config_projections
                   (registry_id, repository_id, root_digest, manifest_digest,
                    config_digest, operating_system, architecture, variant,
                    os_version, os_features_json, aos_system,
                    compressed_byte_size, unpacked_byte_size, layer_count,
                    config_json, verified_at)
                 SELECT projection.registry_id, projection.repository_id, ?3,
                        projection.manifest_digest, projection.config_digest,
                        projection.operating_system, projection.architecture,
                        projection.variant, projection.os_version,
                        projection.os_features_json, projection.aos_system,
                        projection.compressed_byte_size,
                        projection.unpacked_byte_size, projection.layer_count,
                        projection.config_json, ?5
                 FROM oci_image_config_projections projection
                 JOIN oci_repositories repository
                   ON repository.id = projection.repository_id
                  AND repository.registry_id = projection.registry_id
                 WHERE projection.registry_id = ?1 AND repository.name = ?2
                   AND projection.root_digest = ?4
                   AND projection.manifest_digest = ?4
                 ON CONFLICT(repository_id, root_digest, manifest_digest)
                 DO UPDATE SET verified_at = excluded.verified_at",
                vals![
                    input.registry_id,
                    input.repository.as_str(),
                    root_digest.to_string(),
                    child.digest.to_string(),
                    input.observed_at
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "INSERT INTO oci_release_layers
                   (registry_id, repository_id, root_digest, manifest_digest,
                    ordinal, digest, media_type, compressed_byte_size,
                    unpacked_byte_size, diff_id, closure_group, verified_at)
                 SELECT layer.registry_id, layer.repository_id, ?3,
                        layer.manifest_digest, layer.ordinal, layer.digest,
                        layer.media_type, layer.compressed_byte_size,
                        layer.unpacked_byte_size, layer.diff_id,
                        layer.closure_group, ?5
                 FROM oci_release_layers layer JOIN oci_repositories repository
                   ON repository.id = layer.repository_id
                  AND repository.registry_id = layer.registry_id
                 WHERE layer.registry_id = ?1 AND repository.name = ?2
                   AND layer.root_digest = ?4 AND layer.manifest_digest = ?4
                 ON CONFLICT(repository_id, root_digest, manifest_digest, ordinal)
                 DO UPDATE SET verified_at = excluded.verified_at",
                vals![
                    input.registry_id,
                    input.repository.as_str(),
                    root_digest.to_string(),
                    child.digest.to_string(),
                    input.observed_at
                ],
            )
            .unchecked(),
        );
        statements.push(
            Statement::new(
                "DELETE FROM oci_admin_projection_reconciliations
                 WHERE registry_id = ?1
                   AND repository_id = (SELECT id FROM oci_repositories
                     WHERE registry_id = ?1 AND name = ?2)
                   AND root_digest = ?3 AND manifest_digest = ?4",
                vals![
                    input.registry_id,
                    input.repository.as_str(),
                    root_digest.to_string(),
                    child.digest.to_string()
                ],
            )
            .unchecked(),
        );
    }
}

fn extend_existing_oci_admin_manifest_projection(
    statements: &mut Vec<CheckedStatement>,
    input: &IndexOciRepositoryCatalog,
    manifest_digest: Sha256Digest,
) {
    statements.push(
        Statement::new(
            "INSERT INTO oci_image_config_projections
               (registry_id, repository_id, root_digest, manifest_digest,
                config_digest, operating_system, architecture, variant,
                os_version, os_features_json, aos_system,
                compressed_byte_size, unpacked_byte_size, layer_count,
                config_json, verified_at)
             SELECT source.registry_id, target.id, ?3, ?3,
                    source.config_digest, source.operating_system,
                    source.architecture, source.variant, source.os_version,
                    source.os_features_json, source.aos_system,
                    source.compressed_byte_size, source.unpacked_byte_size,
                    source.layer_count, source.config_json, ?4
             FROM oci_repositories target
             JOIN oci_image_config_projections source
               ON source.registry_id = target.registry_id
              AND source.root_digest = ?3 AND source.manifest_digest = ?3
              AND source.repository_id = (SELECT MIN(candidate.repository_id)
                FROM oci_image_config_projections candidate
                WHERE candidate.registry_id = target.registry_id
                  AND candidate.root_digest = ?3 AND candidate.manifest_digest = ?3)
             WHERE target.registry_id = ?1 AND target.name = ?2
               AND target.lifecycle_state = 'active'
             ON CONFLICT(repository_id, root_digest, manifest_digest)
             DO UPDATE SET verified_at = excluded.verified_at",
            vals![
                input.registry_id,
                input.repository.as_str(),
                manifest_digest.to_string(),
                input.observed_at
            ],
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "INSERT INTO oci_release_layers
               (registry_id, repository_id, root_digest, manifest_digest,
                ordinal, digest, media_type, compressed_byte_size,
                unpacked_byte_size, diff_id, closure_group, verified_at)
             SELECT source.registry_id, target.id, ?3, ?3, source.ordinal,
                    source.digest, source.media_type,
                    source.compressed_byte_size, source.unpacked_byte_size,
                    source.diff_id, source.closure_group, ?4
             FROM oci_repositories target JOIN oci_release_layers source
               ON source.registry_id = target.registry_id
              AND source.root_digest = ?3 AND source.manifest_digest = ?3
              AND source.repository_id = (SELECT MIN(candidate.repository_id)
                FROM oci_release_layers candidate
                WHERE candidate.registry_id = target.registry_id
                  AND candidate.root_digest = ?3 AND candidate.manifest_digest = ?3)
             WHERE target.registry_id = ?1 AND target.name = ?2
               AND target.lifecycle_state = 'active'
             ON CONFLICT(repository_id, root_digest, manifest_digest, ordinal)
             DO UPDATE SET verified_at = excluded.verified_at",
            vals![
                input.registry_id,
                input.repository.as_str(),
                manifest_digest.to_string(),
                input.observed_at
            ],
        )
        .unchecked(),
    );
    statements.push(
        Statement::new(
            "DELETE FROM oci_admin_projection_reconciliations
             WHERE registry_id = ?1
               AND repository_id = (SELECT id FROM oci_repositories
                 WHERE registry_id = ?1 AND name = ?2)
               AND root_digest = ?3 AND manifest_digest = ?3",
            vals![
                input.registry_id,
                input.repository.as_str(),
                manifest_digest.to_string()
            ],
        )
        .unchecked(),
    );
}

impl Database {
    /// Lists legacy runnable roots awaiting exact-byte projection reconciliation.
    ///
    /// Rows remain pending until catalog admission atomically persists the
    /// complete config, platform, and layer projection. No partial projection
    /// is returned through the administration read model.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid limit, malformed persisted identity, or
    /// database failure.
    pub async fn pending_oci_admin_projection_roots(
        &self,
        registry_id: i64,
        limit: u32,
    ) -> Result<Vec<OciAdminProjectionReconciliationRoot>> {
        if limit == 0 || limit > 250 {
            bail!("OCI administration reconciliation limit is outside 1..=250");
        }
        let rows = self
            .backend
            .query(
                "SELECT reconciliation.repository_id, repository.name,
                        reconciliation.root_digest, manifest.media_type,
                        manifest.byte_size
                 FROM oci_admin_projection_reconciliations reconciliation
                 JOIN oci_repositories repository
                   ON repository.id = reconciliation.repository_id
                  AND repository.registry_id = reconciliation.registry_id
                 JOIN oci_manifests manifest
                   ON manifest.registry_id = reconciliation.registry_id
                  AND manifest.digest = reconciliation.root_digest
                 WHERE reconciliation.registry_id = ?1
                   AND repository.lifecycle_state = 'active'
                   AND reconciliation.state IN('pending', 'failed')
                 GROUP BY reconciliation.repository_id, repository.name,
                          reconciliation.root_digest, manifest.media_type,
                          manifest.byte_size
                 ORDER BY repository.name, reconciliation.root_digest LIMIT ?2",
                &vals![registry_id, i64::from(limit)],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let root = Descriptor {
                    digest: parse_digest(row.get::<String>(2)?)?,
                    media_type: parse_media_type(row.get::<String>(3)?)?,
                    size: parse_size(row.get::<i64>(4)?)?,
                    urls: Vec::new(),
                    annotations: Annotations::new(),
                    data: None,
                    artifact_type: None,
                    platform: None,
                };
                root.validate()?;
                Ok(OciAdminProjectionReconciliationRoot {
                    repository_id: row.get(0)?,
                    repository: RepositoryName::parse(&row.get::<String>(1)?)?,
                    root,
                })
            })
            .collect()
    }

    /// Records a failed exact-byte reconciliation attempt without hiding it.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timestamp or database failure.
    pub async fn mark_oci_admin_projection_reconciliation_failed(
        &self,
        registry_id: i64,
        repository_id: i64,
        root_digest: Sha256Digest,
        error: &str,
        now: i64,
    ) -> Result<()> {
        if now <= 0 {
            bail!("OCI administration reconciliation timestamp is invalid");
        }
        self.backend
            .execute(
                "UPDATE oci_admin_projection_reconciliations
                 SET state = 'failed', attempts = attempts + 1,
                     last_error = ?4, updated_at = ?5
                 WHERE registry_id = ?1 AND repository_id = ?2
                   AND root_digest = ?3",
                &vals![
                    registry_id,
                    repository_id,
                    root_digest.to_string(),
                    error,
                    now
                ],
            )
            .await?;
        Ok(())
    }

    /// Returns whether the active repository root was admitted from the exact
    /// signed release sidecar indexed for this registry.
    ///
    /// This is the authorization bridge between Git release verification and
    /// OCI publication. It deliberately requires the live release row, its
    /// immutable root record, and the registry-bound active repository rather
    /// than trusting a caller-supplied release document.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed release or sidecar identity, or on
    /// database failure.
    pub async fn oci_signed_release_root_exists(
        &self,
        registry_id: i64,
        repository_id: i64,
        release_tag: &str,
        index_digest: Sha256Digest,
        sidecar_sha256_hex: &str,
    ) -> Result<bool> {
        validate_session_identity(release_tag, "release tag", 255)?;
        if sidecar_sha256_hex.len() != 64
            || !sidecar_sha256_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("OCI release sidecar digest is not lowercase SHA-256");
        }
        Ok(self
            .backend
            .query_opt(
                "SELECT 1
                 FROM oci_release_roots root
                 JOIN releases release
                   ON release.id = root.release_id
                  AND release.registry_id = root.registry_id
                  AND release.semver = root.release_tag
                  AND release.commit_oid = root.source_commit
                  AND release.tag_oid = root.verified_tag_oid
                  AND release.pack_present = 1
                 JOIN oci_repositories repository
                   ON repository.id = root.repository_id
                  AND repository.registry_id = root.registry_id
                  AND repository.lifecycle_state = 'active'
                 WHERE root.registry_id = ?1 AND root.repository_id = ?2
                   AND root.release_tag = ?3 AND root.index_digest = ?4
                   AND root.catalog_digest = ?5
                 LIMIT 1",
                &vals![
                    registry_id,
                    repository_id,
                    release_tag,
                    index_digest.to_string(),
                    sidecar_sha256_hex
                ],
            )
            .await?
            .is_some())
    }

    /// Creates or returns the active repository targeted by an authorized push.
    ///
    /// Distribution clients commonly create a repository by pushing its first
    /// blob or manifest. Authorization happens before this method is called;
    /// the insert therefore bootstraps only empty catalog state and never makes
    /// content or a tag visible.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timestamp, an absent owning registry,
    /// a deleted repository with the same name, or database failure.
    pub async fn ensure_oci_repository(
        &self,
        registry_id: i64,
        name: &RepositoryName,
        now: i64,
    ) -> Result<OciRepositoryRecord> {
        if now <= 0 {
            bail!("OCI repository creation timestamp is invalid");
        }
        if let Some(repository) = self.oci_repository(registry_id, name).await? {
            return Ok(repository);
        }

        let repository_id = portable_relational_id(Uuid::new_v4());
        self.backend
            .checked_batch(&[
                Statement::new(
                    "INSERT INTO oci_repositories
                   (id, registry_id, name, visibility, lifecycle_state,
                    resource_version, created_at, updated_at)
                 SELECT ?1, registry.id, ?3, 'inherit', 'active', 1, ?4, ?4
                 FROM registries registry
                 WHERE registry.id = ?2
                   AND NOT EXISTS (SELECT 1 FROM oci_repositories existing
                     WHERE existing.registry_id = registry.id
                       AND existing.name = ?3)
                 ON CONFLICT(registry_id, name) DO NOTHING",
                    vals![repository_id, registry_id, name.as_str(), now],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO oci_repository_metadata
                       (repository_id, registry_id, description,
                        resource_version, updated_at)
                     SELECT repository.id, repository.registry_id, '', 1, ?3
                     FROM oci_repositories repository
                     WHERE repository.registry_id = ?1 AND repository.name = ?2
                     ON CONFLICT(repository_id) DO NOTHING",
                    vals![registry_id, name.as_str(), now],
                )
                .unchecked(),
                Statement::new(
                    "INSERT INTO oci_registry_state
                       (registry_id, mutation_epoch, charged_bytes,
                        charged_objects, updated_at)
                     SELECT ?1, 0, 0, 0, ?2
                     WHERE EXISTS (SELECT 1 FROM registries WHERE id = ?1)
                     ON CONFLICT(registry_id) DO NOTHING",
                    vals![registry_id, now],
                )
                .unchecked(),
                Statement::new(
                    "UPDATE oci_registry_state
                     SET mutation_epoch = mutation_epoch + 1, updated_at = ?2
                     WHERE registry_id = ?1
                       AND NOT EXISTS (SELECT 1 FROM oci_gc_registry_locks registry_lock
                         WHERE registry_lock.registry_id = ?1)
                       AND NOT EXISTS (SELECT 1 FROM oci_registry_purge_fences purge
                         WHERE purge.registry_id = ?1 AND purge.state = 'collecting')",
                    vals![registry_id, now],
                )
                .expecting(1),
            ])
            .await
            .context("creating OCI repository for first push")?;
        self.oci_repository(registry_id, name)
            .await?
            .context("new OCI repository did not become active")
    }

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

    /// Returns an active OCI repository by its portable relational id.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted data.
    pub async fn oci_repository_by_id(
        &self,
        repository_id: i64,
    ) -> Result<Option<OciRepositoryRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_REPOSITORY_COLUMNS} FROM oci_repositories
                     WHERE id = ?1 AND lifecycle_state = 'active'"
                ),
                &vals![repository_id],
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
                     JOIN oci_blobs stored_blob
                       ON stored_blob.registry_id = link.registry_id
                      AND stored_blob.digest = link.digest
                     JOIN surface_objects object
                       ON object.id = stored_blob.surface_object_id
                      AND object.registry_id = stored_blob.registry_id
                     WHERE link.repository_id = ?1 AND link.digest = ?2
                       AND stored_blob.lifecycle_state = 'active'
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
                 JOIN oci_blobs stored_blob
                   ON stored_blob.registry_id = link.registry_id
                  AND stored_blob.digest = link.digest
                 JOIN surface_objects object
                   ON object.id = stored_blob.surface_object_id
                  AND object.registry_id = stored_blob.registry_id
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
                   AND stored_blob.byte_size = ?4 AND link.media_type = ?5
                   AND stored_blob.lifecycle_state = 'active'
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
                 JOIN oci_blobs stored_blob
                   ON stored_blob.registry_id = link.registry_id
                  AND stored_blob.digest = link.digest
                 JOIN surface_objects object
                   ON object.id = stored_blob.surface_object_id
                  AND object.registry_id = stored_blob.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = object.id
                  AND presence.registry_id = object.registry_id
                 WHERE link.repository_id = ?1 AND link.digest = ?2
                   AND presence.placement_id = ?3
                   AND stored_blob.byte_size = ?4 AND link.media_type = ?5
                   AND stored_blob.lifecycle_state = 'active'
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
                     JOIN oci_blobs stored_blob
                       ON stored_blob.registry_id = manifest.registry_id
                      AND stored_blob.digest = manifest.digest
                     JOIN surface_objects object
                       ON object.id = stored_blob.surface_object_id
                      AND object.registry_id = stored_blob.registry_id
                     LEFT JOIN oci_tags tag
                       ON tag.repository_id = link.repository_id
                      AND tag.registry_id = link.registry_id
                      AND tag.digest = link.digest AND tag.name = ?3
                     WHERE link.repository_id = ?1
                       AND {OCI_MANIFEST_REFERENCE_PREDICATE}
                       AND stored_blob.lifecycle_state = 'active'
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
                        edge.platform_os_version,
                        edge.platform_os_features_json, edge.annotations_json
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

    /// Expands several signed repository roots into their complete bounded
    /// descriptor closure and parsed manifest/index projections.
    ///
    /// Callers pass the release index plus every signed evidence-referrer root;
    /// traversal follows config, layer/payload, child, and subject edges and
    /// deduplicates shared content. Each returned descriptor is verified against
    /// the admitted repository identity. Exact placement evidence can then be
    /// frozen with [`Database::oci_release_descriptor_placement`].
    ///
    /// # Errors
    ///
    /// Returns an error for no roots, an absent/conflicting repository object,
    /// malformed persisted projection, graph bounds overflow, or database
    /// failure.
    pub async fn oci_repository_closed_graph(
        &self,
        repository_id: i64,
        roots: &[Descriptor],
    ) -> Result<Vec<OciCatalogObject>> {
        if roots.is_empty() || roots.len() > aos_oci_types::limits::MAX_REACHABLE_DESCRIPTORS {
            bail!("OCI repository graph root count is outside admitted bounds");
        }
        let mut queued = BTreeMap::<Sha256Digest, Descriptor>::new();
        let mut pending = VecDeque::new();
        for root in roots {
            root.validate()?;
            if let Some(existing) = queued.insert(root.digest, root.clone()) {
                if existing.media_type != root.media_type || existing.size != root.size {
                    bail!("OCI repository graph root has conflicting descriptor identity");
                }
            } else {
                pending.push_back(root.digest);
            }
        }
        let mut objects = Vec::new();
        while let Some(digest) = pending.pop_front() {
            if objects.len() >= aos_oci_types::limits::MAX_REACHABLE_DESCRIPTORS {
                bail!("OCI repository graph exceeds admitted object count");
            }
            let descriptor = queued
                .get(&digest)
                .cloned()
                .context("queued OCI descriptor disappeared")?;
            let blob = self
                .oci_blob_for_repository(repository_id, digest)
                .await?
                .context("OCI repository graph object is absent")?;
            if blob.byte_size != descriptor.size || blob.media_type != descriptor.media_type {
                bail!("OCI repository graph object has conflicting descriptor identity");
            }
            let projection = if descriptor.media_type.is_image_manifest()
                || descriptor.media_type.is_image_index()
            {
                let manifest = self
                    .oci_manifest_for_repository(
                        repository_id,
                        &ManifestReference::Digest(descriptor.digest),
                    )
                    .await?
                    .context("OCI repository graph manifest projection is absent")?;
                let edges = self
                    .oci_descriptor_edges(repository_id, descriptor.digest)
                    .await?;
                let projection = projection_from_records(&manifest, &edges)?;
                for edge in edges {
                    if let Some(existing) = queued.get(&edge.descriptor.digest) {
                        if existing.media_type != edge.descriptor.media_type
                            || existing.size != edge.descriptor.size
                        {
                            bail!("OCI repository graph edge has conflicting identity");
                        }
                    } else {
                        pending.push_back(edge.descriptor.digest);
                        queued.insert(edge.descriptor.digest, edge.descriptor);
                    }
                }
                Some(projection)
            } else {
                None
            };
            objects.push(OciCatalogObject {
                descriptor,
                projection,
            });
        }
        objects.sort_by_key(|object| object.descriptor.digest);
        Ok(objects)
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
        let statements = build_oci_catalog_statements(input)?;
        self.backend.checked_batch(&statements).await?;
        self.oci_repository(input.registry_id, &input.repository)
            .await?
            .context("indexed OCI repository disappeared")
    }
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
    let os_version = row.get::<Option<String>>(10)?;
    let os_features = serde_json::from_str::<Vec<String>>(&row.get::<String>(11)?)
        .context("decoding persisted OCI manifest OS features")?;
    let platform = match (os, architecture) {
        (Some(os), Some(architecture)) => {
            let platform = Platform {
                architecture,
                os,
                os_version,
                os_features,
                variant,
                features: Vec::new(),
            };
            platform.validate()?;
            Some(platform)
        }
        (None, None) if variant.is_none() && os_version.is_none() && os_features.is_empty() => None,
        _ => bail!("persisted OCI platform projection is incomplete"),
    };
    let descriptor_count = u32::try_from(row.get::<i64>(13)?)
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
        annotations: parse_annotations(&row.get::<String>(12)?)?,
        descriptor_count,
        surface_object_id: row.get(14)?,
        object_key: row.get(15)?,
        created_at: row.get(16)?,
    })
}

fn row_to_oci_edge(row: &Row) -> Result<OciDescriptorEdgeRecord> {
    let os = row.get::<Option<String>>(5)?;
    let architecture = row.get::<Option<String>>(6)?;
    let variant = row.get::<Option<String>>(7)?;
    let os_version = row.get::<Option<String>>(8)?;
    let os_features = serde_json::from_str::<Vec<String>>(&row.get::<String>(9)?)
        .context("decoding persisted OCI edge OS features")?;
    let platform = match (os, architecture) {
        (Some(os), Some(architecture)) => Some(Platform {
            architecture,
            os,
            os_version,
            os_features,
            variant,
            features: Vec::new(),
        }),
        (None, None) if variant.is_none() && os_version.is_none() && os_features.is_empty() => None,
        _ => bail!("persisted OCI edge platform is incomplete"),
    };
    let descriptor = Descriptor {
        media_type: parse_media_type(row.get(3)?)?,
        digest: parse_digest(row.get(2)?)?,
        size: parse_size(row.get(4)?)?,
        urls: Vec::new(),
        annotations: parse_annotations(&row.get::<String>(10)?)?,
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
    use crate::db::{
        ApplyOciAdminMutation, OciManualTagMutationOperation, PlanOciManualTagMutation,
    };

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
        let layer = descriptor(MediaType::OciLayerGzip, b"fixture-layer");
        let diff_id = Sha256Digest::digest(b"fixture-unpacked-layer");
        let config_json = format!(
            "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"os.version\":\"6.8\",\"os.features\":[\"seccomp\",\"cgroupsv2\"],\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{diff_id}\"]}}}}"
        );
        let platform = ImageConfig::from_json(config_json.as_bytes())
            .unwrap()
            .platform();
        let config = descriptor(MediaType::OciImageConfig, config_json.as_bytes());
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: None,
            config: config.clone(),
            layers: vec![layer.clone()],
            subject: None,
            annotations: Annotations::new(),
        };
        let manifest_bytes = aos_oci_types::to_canonical_json(&manifest).unwrap();
        let manifest_descriptor = descriptor(MediaType::OciImageManifest, &manifest_bytes);
        IndexOciRepositoryCatalog {
            registry_id,
            placement_id,
            repository: RepositoryName::parse("aos").unwrap(),
            // Input order is deliberately root-first. Admission must not rely
            // on a producer topologically sorting the closed descriptor set.
            objects: vec![
                OciCatalogObject {
                    descriptor: manifest_descriptor.clone(),
                    projection: Some(OciCatalogProjection::Manifest {
                        document: manifest,
                        platform: Some(platform),
                        image_config: Some(OciImageConfigProjection {
                            config_json,
                            aos_system: "x86_64-linux".to_string(),
                            layers: vec![OciLayerProjection {
                                unpacked_byte_size: b"fixture-unpacked-layer".len() as u64,
                                diff_id,
                                closure_group: String::new(),
                            }],
                        }),
                    }),
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

    fn platform_index_catalog(
        child: &IndexOciRepositoryCatalog,
        platform: Platform,
        tag: &str,
        observed_at: i64,
    ) -> IndexOciRepositoryCatalog {
        let mut child_manifest = child.objects[0].clone();
        child_manifest.descriptor.platform = Some(platform);
        let index = ImageIndex {
            schema_version: 2,
            media_type: Some(MediaType::OciImageIndex),
            artifact_type: None,
            manifests: vec![child_manifest.descriptor.clone()],
            subject: None,
            annotations: Annotations::new(),
        };
        let bytes = aos_oci_types::to_canonical_json(&index).unwrap();
        let root = descriptor(MediaType::OciImageIndex, &bytes);
        let mut objects = vec![OciCatalogObject {
            descriptor: root.clone(),
            projection: Some(OciCatalogProjection::Index(index)),
        }];
        objects.push(child_manifest);
        objects.extend(child.objects.iter().skip(1).cloned());
        IndexOciRepositoryCatalog {
            registry_id: child.registry_id,
            placement_id: child.placement_id,
            repository: child.repository.clone(),
            objects,
            root_digest: root.digest,
            tag: Some(Tag::parse(tag).unwrap()),
            source_kind: "manual".to_string(),
            actor_id: "test:index".to_string(),
            observed_at,
        }
    }

    fn catalog_platform(catalog: &IndexOciRepositoryCatalog) -> Platform {
        match &catalog.objects[0].projection {
            Some(OciCatalogProjection::Manifest {
                platform: Some(platform),
                ..
            }) => platform.clone(),
            _ => panic!("catalog fixture root must carry an exact platform"),
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
        let credential = db
            .set_binding_credential_revision(
                binding_id,
                "write",
                "secret://test/oci-catalog-write/v1",
                0,
                &"0".repeat(64),
                "test",
            )
            .await
            .unwrap();
        db.validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
        let revision = db
            .create_binding_write_revision(&crate::db::NewBindingWriteRevision {
                binding_id,
                write_credential_generation: credential.generation,
                writes_supported: true,
                conditional_writes_supported: true,
                revision_fingerprint: "oci-catalog-write-revision".to_string(),
                capability_fingerprint: "oci-catalog-write-capability".to_string(),
            })
            .await
            .unwrap();
        db.observe_binding_write_revision(binding_id, revision.revision, "valid", None, None)
            .await
            .unwrap();
        let state = db.binding_write_state(binding_id).await.unwrap().unwrap();
        db.set_current_binding_write_revision(
            binding_id,
            revision.revision,
            state.resource_version,
        )
        .await
        .unwrap();
        db.bind_surface_placement_write_capability(placement.id, revision.revision)
            .await
            .unwrap();
        (db, registry_id, placement.id)
    }

    #[tokio::test]
    async fn first_uploaded_object_evidence_seeds_registry_state_once() {
        let (db, registry_id, placement_id) = catalog_database().await;
        assert!(db
            .backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .is_none());

        let digest = Sha256Digest::digest(b"first uploaded object");
        assert!(db
            .record_oci_uploaded_object(
                registry_id,
                placement_id + 10_000,
                digest,
                21,
                "\"first-upload\"",
                1_700_000_001,
            )
            .await
            .is_err());
        assert!(db
            .backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .is_none());

        let evidence = db
            .record_oci_uploaded_object(
                registry_id,
                placement_id,
                digest,
                21,
                "\"first-upload\"",
                1_700_000_001,
            )
            .await
            .unwrap();
        assert_eq!(evidence.placement_id, placement_id);
        assert_eq!(
            db.record_oci_uploaded_object(
                registry_id,
                placement_id,
                digest,
                21,
                "\"first-upload\"",
                1_700_000_001,
            )
            .await
            .unwrap(),
            evidence
        );
        let mutation_epoch: i64 = db
            .backend
            .query_opt(
                "SELECT mutation_epoch FROM oci_registry_state WHERE registry_id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(mutation_epoch, 1, "exact replay must not move the epoch");
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

    async fn freeze_publication_graph(
        db: &Database,
        mut publication: OciPublicationRecord,
        repository_id: i64,
        placement_id: i64,
        graph: &[OciCatalogObject],
        now: i64,
    ) -> OciPublicationRecord {
        for object in graph {
            let evidence = db
                .oci_release_descriptor_placement(
                    repository_id,
                    placement_id,
                    ContainerReleaseDescriptorRole::Index,
                    &object.descriptor,
                )
                .await
                .unwrap()
                .unwrap();
            let projection_json = object
                .projection
                .as_ref()
                .map(|projection| match projection {
                    OciCatalogProjection::Manifest {
                        document, platform, ..
                    } => serde_json::to_string(&serde_json::json!({
                        "document": document,
                        "platform": platform,
                    })),
                    OciCatalogProjection::Index(index) => serde_json::to_string(index),
                })
                .transpose()
                .unwrap();
            publication = db
                .add_oci_publication_object(
                    &AddOciPublicationObject {
                        publication_id: publication.id.clone(),
                        writer_id: publication.writer_id.clone(),
                        token_id: publication.token_id.clone(),
                        expected_resource_version: publication.resource_version,
                        descriptor: object.descriptor.clone(),
                        object_kind: if object.descriptor.media_type.is_image_manifest()
                            || object.descriptor.media_type.is_image_index()
                        {
                            "manifest".to_string()
                        } else {
                            "blob".to_string()
                        },
                        object_key: oci_blob_object_key(object.descriptor.digest),
                        projection_json,
                        surface_object_id: evidence.surface_object_id,
                        placement_id,
                        object_resource_version: evidence.object_resource_version,
                        placement_resource_version: evidence.placement_resource_version,
                        placement_observation_version: evidence.placement_observation_version,
                        observed_inventory_generation: evidence.observed_inventory_generation,
                        observed_etag: evidence.strong_etag,
                        observed_at: evidence.observed_at,
                    },
                    now,
                )
                .await
                .unwrap();
        }
        publication
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
    fn catalog_quota_identity_fits_widened_contract_at_max_registry_and_digest() {
        let digest = Sha256Digest::parse(&format!("sha256:{}", "f".repeat(64))).unwrap();
        let (reservation, owner) = catalog_quota_identity(i64::MAX, digest);

        assert_eq!(
            owner,
            format!("catalog:{}:sha256:{}", i64::MAX, "f".repeat(64))
        );
        assert_eq!(reservation, format!("q-{owner}"));
        assert!(owner.len() > 64 && owner.len() <= 128);
        assert!(reservation.len() > 64 && reservation.len() <= 128);
    }

    #[test]
    fn catalog_sql_translates_reserved_aliases_and_nullable_projection_identity() {
        let child = catalog_fixture(7, 11);
        let platform = catalog_platform(&child);
        let catalog = platform_index_catalog(&child, platform, "portable-sql", 1_700_000_001);
        let statements = build_oci_catalog_statements(&catalog).unwrap();

        for statement in &statements {
            assert!(
                !statement.statement.sql.contains("oci_blobs blob"),
                "reserved MariaDB alias survived in source SQL: {}",
                statement.statement.sql
            );
            let mysql = crate::dialect::Dialect::Mysql
                .translate(&statement.statement.sql)
                .unwrap();
            assert!(
                !mysql.sql.contains("oci_blobs blob"),
                "reserved MariaDB alias survived translation: {}",
                mysql.sql
            );
            assert!(
                !statement.statement.sql.contains("org_usage usage")
                    && !statement.statement.sql.contains(" usage."),
                "reserved MariaDB quota alias survived in source SQL: {}",
                statement.statement.sql
            );
            assert!(
                !mysql.sql.contains("org_usage usage") && !mysql.sql.contains(" usage."),
                "reserved MariaDB quota alias survived translation: {}",
                mysql.sql
            );
        }

        let repository_insert = statements
            .iter()
            .find(|statement| {
                statement
                    .statement
                    .sql
                    .starts_with("INSERT INTO oci_repositories")
            })
            .expect("catalog repository insert");
        assert!(repository_insert
            .statement
            .sql
            .contains("ON CONFLICT(registry_id, name) DO NOTHING"));
        let mysql = crate::dialect::Dialect::Mysql
            .translate(&repository_insert.statement.sql)
            .unwrap();
        assert!(mysql.sql.starts_with("INSERT IGNORE INTO oci_repositories"));

        let identity = statements
            .iter()
            .find(|statement| {
                statement
                    .statement
                    .sql
                    .contains("manifest.artifact_type = ?7")
            })
            .expect("manifest projection identity guard");
        let postgres = crate::dialect::Dialect::Postgres
            .translate(&identity.statement.sql)
            .unwrap();
        for (column, parameter) in [
            ("artifact_type", 7),
            ("subject_digest", 8),
            ("config_digest", 9),
            ("platform_os", 10),
            ("platform_architecture", 11),
            ("platform_variant", 12),
        ] {
            let equality = format!("manifest.{column} = ${parameter}");
            let null_check = format!("manifest.{column} IS NULL AND ${parameter} IS NULL");
            assert!(postgres.sql.contains(&equality), "{}", postgres.sql);
            assert!(postgres.sql.contains(&null_check), "{}", postgres.sql);
            assert!(
                postgres.sql.find(&equality) < postgres.sql.find(&null_check),
                "PostgreSQL must infer ${parameter} from typed equality first: {}",
                postgres.sql
            );
        }
    }

    #[test]
    fn manifest_reference_predicate_types_nullable_parameters_before_null_checks() {
        let postgres = crate::dialect::Dialect::Postgres
            .translate(OCI_MANIFEST_REFERENCE_PREDICATE)
            .unwrap();

        for (equality, null_check) in [
            ("link.digest = $2", "$2 IS NOT NULL"),
            ("tag.name = $3", "$3 IS NOT NULL"),
        ] {
            assert!(postgres.sql.contains(equality), "{}", postgres.sql);
            assert!(postgres.sql.contains(null_check), "{}", postgres.sql);
            assert!(
                postgres.sql.find(equality) < postgres.sql.find(null_check),
                "PostgreSQL must infer nullable reference parameters from typed equality first: {}",
                postgres.sql
            );
        }
    }

    #[tokio::test]
    async fn authorized_first_push_bootstraps_one_empty_repository() {
        let (db, registry_id, _) = catalog_database().await;
        let name = RepositoryName::parse("first/push").unwrap();
        assert!(db
            .oci_repository(registry_id, &name)
            .await
            .unwrap()
            .is_none());

        let created = db
            .ensure_oci_repository(registry_id, &name, 1_700_000_000)
            .await
            .unwrap();
        let repeated = db
            .ensure_oci_repository(registry_id, &name, 1_700_000_001)
            .await
            .unwrap();
        assert_eq!(created, repeated);
        let admin = db
            .oci_admin_repository(registry_id, &name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin.name, name);
        assert_eq!(admin.description, "");
        assert_eq!(admin.manifest_count, 0);

        db.backend
            .execute(
                "UPDATE oci_repositories SET lifecycle_state = 'deleted'
                 WHERE id = ?1",
                &vals![created.id],
            )
            .await
            .unwrap();
        let error = db
            .ensure_oci_repository(registry_id, &name, 1_700_000_002)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("did not become active"));
    }

    #[test]
    fn catalog_rejects_orphans_but_accepts_exact_noncanonical_manifest_bytes() {
        let mut catalog = catalog_fixture(1, 1);
        let orphan = descriptor(MediaType::OciLayerGzip, b"orphan");
        catalog.objects.push(OciCatalogObject {
            descriptor: orphan,
            projection: None,
        });
        let error = validate_catalog(&catalog).unwrap_err();
        assert!(format!("{error:#}").contains("unreachable"));

        let mut catalog = catalog_fixture(1, 1);
        let noncanonical = br#"{
          "layers" : [{"size":13,"digest":"sha256:4e87345a12343ec2a3d652036467a98a75a6d18f06995429a5f63ce59e22f14e","mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}],
          "config" : {"digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2,"mediaType":"application/vnd.oci.image.config.v1+json"},
          "mediaType" : "application/vnd.oci.image.manifest.v1+json",
          "schemaVersion" : 2
        }"#;
        let root = catalog.objects.first_mut().unwrap();
        root.descriptor.digest = Sha256Digest::digest(noncanonical);
        root.descriptor.size = u64::try_from(noncanonical.len()).unwrap();
        catalog.root_digest = root.descriptor.digest;
        assert!(validate_catalog(&catalog).is_ok());

        let mut catalog = catalog_fixture(1, 1);
        let subject = catalog.objects[0].descriptor.clone();
        let empty = descriptor(MediaType::OciEmptyJson, b"{}");
        let payload = descriptor(MediaType::SpdxJson, br#"{"spdxVersion":"SPDX-2.3"}"#);
        let artifact = ImageManifest {
            schema_version: 2,
            media_type: Some(MediaType::OciImageManifest),
            artifact_type: Some(MediaType::SpdxJson),
            config: empty.clone(),
            layers: vec![payload.clone()],
            subject: Some(subject),
            annotations: Annotations::new(),
        };
        let artifact_bytes = aos_oci_types::to_canonical_json(&artifact).unwrap();
        let artifact_descriptor = descriptor(MediaType::OciImageManifest, &artifact_bytes);
        catalog.objects.extend([
            OciCatalogObject {
                descriptor: artifact_descriptor,
                projection: Some(OciCatalogProjection::Manifest {
                    document: artifact,
                    platform: None,
                    image_config: None,
                }),
            },
            OciCatalogObject {
                descriptor: empty,
                projection: None,
            },
            OciCatalogObject {
                descriptor: payload,
                projection: None,
            },
        ]);
        assert!(validate_catalog(&catalog).is_ok());
    }

    #[test]
    fn portable_sha256_resumes_across_block_and_tail_boundaries() {
        let mut state = OciSha256State::initial();
        state.update(&vec![b'a'; 63]).unwrap();
        assert_eq!(state.tail_hex.len(), 126);
        state.update(b"bc").unwrap();
        assert_eq!(state.tail_hex, "63");

        let mut expected_bytes = vec![b'a'; 63];
        expected_bytes.extend_from_slice(b"bc");
        assert_eq!(
            state.final_digest().unwrap(),
            Sha256Digest::digest(&expected_bytes)
        );

        let mut abc = OciSha256State::initial();
        abc.update(b"a").unwrap();
        abc.update(b"bc").unwrap();
        assert_eq!(
            abc.final_digest().unwrap().to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        for length in [0_usize, 1, 55, 56, 63, 64, 65, 127, 128, 129, 4097] {
            let bytes = (0..length)
                .map(|index| u8::try_from((index * 31 + 7) % 251).unwrap())
                .collect::<Vec<_>>();
            for chunk_size in [1_usize, 3, 17, 63, 64, 65, 127, 1024] {
                let mut resumed = OciSha256State::initial();
                for chunk in bytes.chunks(chunk_size) {
                    resumed.update(chunk).unwrap();
                }
                assert_eq!(
                    resumed.final_digest().unwrap(),
                    Sha256Digest::digest(&bytes),
                    "length={length}, chunk_size={chunk_size}"
                );
            }
        }
    }

    #[tokio::test]
    async fn catalog_admission_is_atomic_repository_scoped_and_queryable() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let catalog = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &catalog).await;

        let org_id: i64 = db
            .backend
            .query_opt(
                "SELECT org_id FROM registries WHERE id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        let catalog_bytes = catalog
            .objects
            .iter()
            .map(|object| i64::try_from(object.descriptor.size).unwrap())
            .sum::<i64>();
        let catalog_objects = i64::try_from(catalog.objects.len()).unwrap();
        db.set_org_quota(
            org_id,
            &crate::db::OrgQuota {
                max_bytes: Some(catalog_bytes - 1),
                max_objects: Some(catalog_objects),
                max_registries: None,
                max_tokens: None,
            },
        )
        .await
        .unwrap();
        assert!(db.index_oci_repository_catalog(&catalog).await.is_err());
        assert!(db
            .oci_repository(registry_id, &catalog.repository)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            db.org_usage(org_id).await.unwrap(),
            crate::db::OrgUsage::default()
        );
        let reservation_count: i64 = db
            .backend
            .query_opt("SELECT COUNT(*) FROM oci_quota_reservations", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(reservation_count, 0);
        let tag_count: i64 = db
            .backend
            .query_opt("SELECT COUNT(*) FROM oci_tags", &[])
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        assert_eq!(tag_count, 0);

        db.set_org_quota(
            org_id,
            &crate::db::OrgQuota {
                max_bytes: Some(catalog_bytes),
                max_objects: Some(catalog_objects),
                max_registries: None,
                max_tokens: None,
            },
        )
        .await
        .unwrap();

        let repository = db.index_oci_repository_catalog(&catalog).await.unwrap();
        let charged = db.org_usage(org_id).await.unwrap();
        assert_eq!(charged.used_bytes, catalog_bytes);
        assert_eq!(charged.object_count, catalog_objects);
        for object in &catalog.objects {
            let (expected_id, expected_owner) =
                catalog_quota_identity(registry_id, object.descriptor.digest);
            let reservation = db
                .backend
                .query_opt(
                    "SELECT id, owner_id, state FROM oci_quota_reservations
                     WHERE registry_id = ?1 AND owner_kind = 'catalog'
                       AND owner_id = ?2",
                    &vals![registry_id, expected_owner],
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reservation.get::<String>(0).unwrap(), expected_id);
            assert_eq!(reservation.get::<String>(1).unwrap(), expected_owner);
            assert_eq!(reservation.get::<String>(2).unwrap(), "committed");
        }
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
        assert_eq!(
            manifest.platform.as_ref().unwrap().os_version.as_deref(),
            Some("6.8")
        );
        assert_eq!(
            manifest.platform.as_ref().unwrap().os_features,
            vec!["seccomp".to_string(), "cgroupsv2".to_string()]
        );
        let admin_repository = db
            .oci_admin_repository(registry_id, &catalog.repository)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_repository.manifest_count, 1);
        assert_eq!(
            admin_repository.compressed_byte_size,
            u64::try_from(catalog_bytes).unwrap()
        );
        assert_eq!(
            admin_repository.unique_byte_size,
            admin_repository.compressed_byte_size
        );
        let platforms = db
            .list_oci_admin_platforms(
                registry_id,
                &catalog.repository,
                catalog.root_digest,
                10,
                None,
            )
            .await
            .unwrap();
        assert_eq!(platforms.items.len(), 1);
        let platform = &platforms.items[0];
        assert_eq!(platform.aos_system, "x86_64-linux");
        assert_eq!(platform.platform.os_version.as_deref(), Some("6.8"));
        assert_eq!(
            platform.platform.os_features,
            vec!["seccomp".to_string(), "cgroupsv2".to_string()]
        );
        assert_eq!(platform.layer_count, 1);
        assert!(platform.config_json.contains("diff_ids"));
        assert!(db
            .oci_admin_platform(
                registry_id,
                &catalog.repository,
                catalog.root_digest,
                &platform.platform,
            )
            .await
            .unwrap()
            .is_some());
        assert!(db
            .oci_admin_platform(
                registry_id,
                &catalog.repository,
                catalog.root_digest,
                &Platform::linux_amd64(),
            )
            .await
            .unwrap()
            .is_none());
        let layers = db
            .list_oci_admin_layers(
                registry_id,
                &catalog.repository,
                catalog.root_digest,
                manifest.digest,
                10,
                None,
            )
            .await
            .unwrap();
        assert_eq!(layers.items.len(), 1);
        assert_eq!(layers.items[0].shared_repository_count, 1);
        assert_eq!(
            layers.items[0].diff_id,
            Sha256Digest::digest(b"fixture-unpacked-layer")
        );
        assert_eq!(
            layers.items[0].unpacked_byte_size,
            b"fixture-unpacked-layer".len() as u64
        );
        let manual_tag = Tag::parse("manual").unwrap();
        let set_plan = db
            .plan_oci_manual_tag_mutation(&PlanOciManualTagMutation {
                registry_id,
                repository: catalog.repository.clone(),
                tag: manual_tag.clone(),
                operation: OciManualTagMutationOperation::Set,
                target_digest: Some(manifest.digest),
                expected_digest: None,
                expected_resource_version: None,
                actor_id: "test:admin-tag".to_string(),
                idempotency_key: "plan-set-manual".to_string(),
                now: catalog.observed_at + 1,
            })
            .await
            .unwrap();
        let set = db
            .apply_oci_admin_mutation(&ApplyOciAdminMutation {
                mutation_id: set_plan.id,
                actor_id: "test:admin-tag".to_string(),
                idempotency_key: "apply-set-manual".to_string(),
                confirmation_hash: set_plan.confirmation_hash,
                now: catalog.observed_at + 2,
            })
            .await
            .unwrap()
            .tag
            .unwrap();
        assert_eq!(set.digest, manifest.digest);
        let unset_plan = db
            .plan_oci_manual_tag_mutation(&PlanOciManualTagMutation {
                registry_id,
                repository: catalog.repository.clone(),
                tag: manual_tag.clone(),
                operation: OciManualTagMutationOperation::Unset,
                target_digest: None,
                expected_digest: Some(set.digest),
                expected_resource_version: Some(set.resource_version),
                actor_id: "test:admin-tag".to_string(),
                idempotency_key: "plan-unset-manual".to_string(),
                now: catalog.observed_at + 3,
            })
            .await
            .unwrap();
        let deletion = db
            .apply_oci_admin_mutation(&ApplyOciAdminMutation {
                mutation_id: unset_plan.id,
                actor_id: "test:admin-tag".to_string(),
                idempotency_key: "apply-unset-manual".to_string(),
                confirmation_hash: unset_plan.confirmation_hash,
                now: catalog.observed_at + 4,
            })
            .await
            .unwrap()
            .deletion
            .unwrap();
        assert_eq!(deletion.tag, Some(manual_tag));
        assert_eq!(deletion.resource_version, 2);
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
        db.backend
            .execute(
                "INSERT INTO oci_admin_projection_reconciliations(
                   registry_id, repository_id, root_digest, manifest_digest,
                   config_digest, state, attempts, updated_at)
                 VALUES(?1, ?2, ?3, ?3, ?4, 'pending', 0, ?5)",
                &vals![
                    registry_id,
                    repository.id,
                    manifest.digest.to_string(),
                    manifest.config_digest.unwrap().to_string(),
                    catalog.observed_at
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            db.pending_oci_admin_projection_roots(registry_id, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        // Replaying the same signed catalog creates no duplicate immutable
        // objects, links, projections, or tag-history event.
        db.index_oci_repository_catalog(&catalog).await.unwrap();
        assert!(db
            .pending_oci_admin_projection_roots(registry_id, 10)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.org_usage(org_id).await.unwrap(), charged);
        for table in [
            "oci_blobs",
            "oci_repository_objects",
            "oci_manifests",
            "oci_descriptor_edges",
            "oci_image_config_projections",
            "oci_release_layers",
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
                "oci_tag_history" => 3,
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
                "UPDATE oci_manifests SET annotations_json = '{\"drift\":\"yes\"}'
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
        assert_eq!(drifted.annotations.get("drift"), Some("yes"));

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

    #[tokio::test]
    async fn index_platform_must_match_persisted_config_projection() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let child = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &child).await;
        let repository = db.index_oci_repository_catalog(&child).await.unwrap();
        let child_digest = child.root_digest;
        let exact_platform = catalog_platform(&child);
        assert_eq!(
            db.oci_manifest_for_repository(
                repository.id,
                &ManifestReference::Digest(child_digest),
            )
            .await
            .unwrap()
            .unwrap()
            .platform,
            Some(exact_platform.clone())
        );

        let amd64 = platform_index_catalog(
            &child,
            exact_platform.clone(),
            "amd64",
            child.observed_at + 1,
        );
        let mut amd64_root = amd64.clone();
        amd64_root.objects.truncate(1);
        record_catalog_bytes(&db, &amd64_root).await;
        db.index_oci_repository_catalog(&amd64).await.unwrap();
        let amd64_edges = db
            .oci_descriptor_edges(repository.id, amd64.root_digest)
            .await
            .unwrap();
        assert_eq!(amd64_edges[0].descriptor.digest, child_digest);
        assert_eq!(
            amd64_edges[0].descriptor.platform,
            Some(exact_platform.clone())
        );

        let mut wrong_os = exact_platform.clone();
        wrong_os.os = "windows".to_string();
        let mut wrong_architecture = exact_platform.clone();
        wrong_architecture.architecture = "arm64".to_string();
        let mut wrong_variant = exact_platform.clone();
        wrong_variant.variant = Some("v8".to_string());
        let mut wrong_os_version = exact_platform.clone();
        wrong_os_version.os_version = Some("6.9".to_string());
        let mut wrong_os_features = exact_platform;
        wrong_os_features.os_features.reverse();

        for (platform, tag) in [
            (wrong_os, "wrong-os"),
            (wrong_architecture, "wrong-architecture"),
            (wrong_variant, "wrong-variant"),
            (wrong_os_version, "wrong-os-version"),
            (wrong_os_features, "wrong-os-features"),
        ] {
            let mismatched = platform_index_catalog(&child, platform, tag, child.observed_at + 2);
            assert!(validate_catalog(&mismatched).is_err());
        }
    }

    #[tokio::test]
    async fn upload_retries_quota_and_expiry_are_transactional() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let catalog = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &catalog).await;
        let repository = db.index_oci_repository_catalog(&catalog).await.unwrap();
        let placement = db.surface_placement(placement_id).await.unwrap().unwrap();
        let write_revision = db
            .placement_publication_write_revision(placement_id)
            .await
            .unwrap()
            .unwrap();
        let org_id: i64 = db
            .backend
            .query_opt(
                "SELECT org_id FROM registries WHERE id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        let catalog_bytes = catalog
            .objects
            .iter()
            .map(|object| i64::try_from(object.descriptor.size).unwrap())
            .sum::<i64>();
        let catalog_objects = i64::try_from(catalog.objects.len()).unwrap();
        db.set_org_quota(
            org_id,
            &crate::db::OrgQuota {
                max_bytes: Some(catalog_bytes + 2),
                max_objects: Some(catalog_objects + 10),
                max_registries: None,
                max_tokens: None,
            },
        )
        .await
        .unwrap();
        let now = catalog.observed_at + 10;
        let pending_digest = Sha256Digest::digest(b"pending");
        let pending = db
            .record_oci_uploaded_object(
                registry_id,
                placement_id,
                pending_digest,
                7,
                "pending-etag",
                now,
            )
            .await
            .unwrap();
        assert_eq!(
            db.oci_pending_uploaded_object_evidence(registry_id, placement_id, pending_digest, 7,)
                .await
                .unwrap(),
            Some(pending)
        );
        assert!(db
            .oci_pending_uploaded_object_evidence(registry_id, placement_id, pending_digest, 8,)
            .await
            .unwrap()
            .is_none());

        let begin = BeginOciUpload {
            registry_id,
            repository_id: repository.id,
            publication_id: None,
            writer_id: "writer:test".to_string(),
            token_id: "token:test".to_string(),
            idempotency_key: "upload-retry".to_string(),
            expected_digest: None,
            expected_size: None,
            maximum_size: 100,
            now,
            expires_at: now + 60,
        };
        let upload = db.begin_oci_upload(&begin).await.unwrap();
        assert_eq!(db.begin_oci_upload(&begin).await.unwrap(), upload);

        let mut oversized_state = OciSha256State::initial();
        oversized_state.update(b"abc").unwrap();
        let oversized = AppendOciUploadChunk {
            upload_id: upload.id.clone(),
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            expected_resource_version: upload.resource_version,
            staging_placement_id: placement_id,
            staging_placement_resource_version: 1,
            staging_binding_id: placement.binding_id,
            staging_binding_write_revision: write_revision.revision,
            chunk: OciUploadChunkRecord {
                ordinal: 0,
                byte_offset: 0,
                byte_size: 3,
                digest: Sha256Digest::digest(b"abc"),
                staging_object_key: "oci/uploads/test/chunk-0".to_string(),
                created_at: now + 1,
            },
            next_sha256: oversized_state,
            now: now + 1,
        };
        assert!(db.append_oci_upload_chunk(&oversized).await.is_err());
        assert!(db.oci_upload_chunks(&upload.id).await.unwrap().is_empty());

        let mut state = OciSha256State::initial();
        state.update(b"ab").unwrap();
        let append = AppendOciUploadChunk {
            chunk: OciUploadChunkRecord {
                byte_size: 2,
                digest: Sha256Digest::digest(b"ab"),
                ..oversized.chunk.clone()
            },
            next_sha256: state,
            ..oversized
        };
        let advanced = db.append_oci_upload_chunk(&append).await.unwrap();
        assert_eq!(advanced.uploaded_size, 2);
        assert_eq!(db.append_oci_upload_chunk(&append).await.unwrap(), advanced);
        let chunks = db.oci_upload_chunks(&upload.id).await.unwrap();
        assert_eq!(chunks, vec![append.chunk]);

        let cancelled = db
            .cancel_oci_upload(
                &advanced.id,
                &advanced.writer_id,
                &advanced.token_id,
                advanced.resource_version,
                now + 2,
            )
            .await
            .unwrap();
        assert_eq!(cancelled.state, "cancelled");
        let usage = db.org_usage(org_id).await.unwrap();
        assert_eq!(usage.used_bytes, catalog_bytes);
        assert_eq!(usage.object_count, catalog_objects);

        let mut deduplicated = begin.clone();
        deduplicated.idempotency_key = "upload-existing".to_string();
        deduplicated.expected_digest = Some(catalog.root_digest);
        let deduplicated = db.begin_oci_upload(&deduplicated).await.unwrap();
        let first_claim = db
            .claim_oci_upload(&ClaimOciUpload {
                upload_id: deduplicated.id.clone(),
                writer_id: deduplicated.writer_id.clone(),
                token_id: deduplicated.token_id.clone(),
                expected_resource_version: deduplicated.resource_version,
                materialization_placement_id: placement_id,
                materialization_placement_resource_version: 1,
                materialization_binding_id: placement.binding_id,
                materialization_binding_write_revision: write_revision.revision,
                digest: catalog.root_digest,
                now: now + 3,
                lease_expires_at: now + 903,
            })
            .await
            .unwrap();
        assert_eq!(first_claim, OciBlobClaimOutcome::AlreadyPresent);
        let deduplicated = db
            .oci_upload(
                &deduplicated.id,
                &deduplicated.writer_id,
                &deduplicated.token_id,
                now + 3,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deduplicated.state, "completing");
        assert_eq!(
            db.claim_oci_upload(&ClaimOciUpload {
                upload_id: deduplicated.id.clone(),
                writer_id: deduplicated.writer_id.clone(),
                token_id: deduplicated.token_id.clone(),
                expected_resource_version: deduplicated.resource_version,
                materialization_placement_id: placement_id,
                materialization_placement_resource_version: 1,
                materialization_binding_id: placement.binding_id,
                materialization_binding_write_revision: write_revision.revision,
                digest: catalog.root_digest,
                now: now + 4,
                lease_expires_at: now + 904,
            })
            .await
            .unwrap(),
            OciBlobClaimOutcome::AlreadyPresent
        );
        assert!(db
            .cancel_oci_upload(
                &deduplicated.id,
                &deduplicated.writer_id,
                &deduplicated.token_id,
                deduplicated.resource_version,
                now + 5,
            )
            .await
            .is_err());

        let mut expiring = begin;
        expiring.idempotency_key = "upload-expiry".to_string();
        expiring.now = now + 100;
        expiring.expires_at = now + 101;
        let expiring = db.begin_oci_upload(&expiring).await.unwrap();
        db.expire_oci_upload(&expiring.id, now + 101).await.unwrap();
        let expired = db
            .oci_upload(
                &expiring.id,
                &expiring.writer_id,
                &expiring.token_id,
                now + 101,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.state, "failed");
    }

    #[tokio::test]
    async fn concurrent_uploads_charge_one_shared_digest_once() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let catalog = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &catalog).await;
        let repository = db.index_oci_repository_catalog(&catalog).await.unwrap();
        let placement = db.surface_placement(placement_id).await.unwrap().unwrap();
        let write_revision = db
            .placement_publication_write_revision(placement_id)
            .await
            .unwrap()
            .unwrap();
        let org_id: i64 = db
            .backend
            .query_opt(
                "SELECT org_id FROM registries WHERE id = ?1",
                &vals![registry_id],
            )
            .await
            .unwrap()
            .unwrap()
            .get(0)
            .unwrap();
        let baseline = db.org_usage(org_id).await.unwrap();
        let OciCatalogProjection::Manifest {
            document, platform, ..
        } = catalog.objects[0].projection.as_ref().unwrap()
        else {
            panic!("catalog root must be a manifest projection");
        };
        let mut document = document.clone();
        document
            .annotations
            .insert(
                "org.opencontainers.image.revision".to_string(),
                "concurrent-manifest-admission".to_string(),
            )
            .unwrap();
        let bytes = aos_oci_types::to_canonical_json(&document).unwrap();
        let root = descriptor(MediaType::OciImageManifest, &bytes);
        let digest = root.digest;
        let mut admitted_catalog = catalog.clone();
        admitted_catalog.objects[0] = OciCatalogObject {
            descriptor: root,
            projection: Some(OciCatalogProjection::Manifest {
                document,
                platform: platform.clone(),
                image_config: None,
            }),
        };
        admitted_catalog.root_digest = digest;
        admitted_catalog.tag = Some(Tag::parse("concurrent").unwrap());
        admitted_catalog.source_kind = "manual".to_string();
        admitted_catalog.observed_at = catalog.observed_at + 20;
        let now = catalog.observed_at + 10;
        let evidence = db
            .record_oci_uploaded_object(
                registry_id,
                placement_id,
                digest,
                bytes.len() as u64,
                "shared-digest-etag",
                now,
            )
            .await
            .unwrap();

        let mut uploads = Vec::new();
        for attempt in ["first", "second"] {
            let writer = format!("writer:{attempt}");
            let token = format!("token:{attempt}");
            let upload = db
                .begin_oci_upload(&BeginOciUpload {
                    registry_id,
                    repository_id: repository.id,
                    publication_id: None,
                    writer_id: writer.clone(),
                    token_id: token.clone(),
                    idempotency_key: format!("shared-digest-{attempt}"),
                    expected_digest: Some(digest),
                    expected_size: Some(bytes.len() as u64),
                    maximum_size: 1024,
                    now,
                    expires_at: now + 60,
                })
                .await
                .unwrap();
            let mut state = OciSha256State::initial();
            state.update(&bytes).unwrap();
            let upload = db
                .append_oci_upload_chunk(&AppendOciUploadChunk {
                    upload_id: upload.id.clone(),
                    writer_id: writer,
                    token_id: token,
                    expected_resource_version: upload.resource_version,
                    staging_placement_id: placement_id,
                    staging_placement_resource_version: placement.resource_version,
                    staging_binding_id: placement.binding_id,
                    staging_binding_write_revision: write_revision.revision,
                    chunk: OciUploadChunkRecord {
                        ordinal: 0,
                        byte_offset: 0,
                        byte_size: bytes.len() as u64,
                        digest,
                        staging_object_key: format!("oci/uploads/{attempt}/chunk-0"),
                        created_at: now,
                    },
                    next_sha256: state,
                    now,
                })
                .await
                .unwrap();
            uploads.push(upload);
        }

        let claim = |upload: &OciUploadRecord| ClaimOciUpload {
            upload_id: upload.id.clone(),
            writer_id: upload.writer_id.clone(),
            token_id: upload.token_id.clone(),
            expected_resource_version: upload.resource_version,
            materialization_placement_id: placement_id,
            materialization_placement_resource_version: placement.resource_version,
            materialization_binding_id: placement.binding_id,
            materialization_binding_write_revision: write_revision.revision,
            digest,
            now: now + 1,
            lease_expires_at: now + 61,
        };
        assert_eq!(
            db.claim_oci_upload(&claim(&uploads[0])).await.unwrap(),
            OciBlobClaimOutcome::Claimed
        );
        assert_eq!(
            db.claim_oci_upload(&claim(&uploads[1])).await.unwrap(),
            OciBlobClaimOutcome::InProgress
        );

        let first = db
            .oci_upload(
                &uploads[0].id,
                &uploads[0].writer_id,
                &uploads[0].token_id,
                now + 1,
            )
            .await
            .unwrap()
            .unwrap();
        db.complete_oci_upload(&CompleteOciUpload {
            upload_id: first.id.clone(),
            writer_id: first.writer_id.clone(),
            token_id: first.token_id.clone(),
            expected_resource_version: first.resource_version,
            digest,
            byte_size: bytes.len() as u64,
            surface_object_id: evidence.surface_object_id,
            placement_id,
            now: now + 2,
        })
        .await
        .unwrap();

        assert_eq!(
            db.claim_oci_upload(&claim(&uploads[1])).await.unwrap(),
            OciBlobClaimOutcome::AlreadyPresent
        );
        let second = db
            .oci_upload(
                &uploads[1].id,
                &uploads[1].writer_id,
                &uploads[1].token_id,
                now + 2,
            )
            .await
            .unwrap()
            .unwrap();
        db.complete_oci_upload(&CompleteOciUpload {
            upload_id: second.id.clone(),
            writer_id: second.writer_id.clone(),
            token_id: second.token_id.clone(),
            expected_resource_version: second.resource_version,
            digest,
            byte_size: bytes.len() as u64,
            surface_object_id: evidence.surface_object_id,
            placement_id,
            now: now + 3,
        })
        .await
        .unwrap();

        db.index_oci_repository_catalog(&admitted_catalog)
            .await
            .unwrap();

        let usage = db.org_usage(org_id).await.unwrap();
        assert_eq!(usage.used_bytes - baseline.used_bytes, bytes.len() as i64);
        assert_eq!(usage.object_count - baseline.object_count, 1);
    }

    #[tokio::test]
    async fn publication_freezes_exact_graph_and_commits_atomically() {
        let (db, registry_id, placement_id) = catalog_database().await;
        let catalog = catalog_fixture(registry_id, placement_id);
        record_catalog_bytes(&db, &catalog).await;
        let repository = db.index_oci_repository_catalog(&catalog).await.unwrap();
        let root = catalog.objects[0].descriptor.clone();
        let graph = db
            .oci_repository_closed_graph(repository.id, &[root])
            .await
            .unwrap();
        assert_eq!(graph.len(), catalog.objects.len());
        let catalog_digest = oci_catalog_declaration_digest(catalog.root_digest, &graph).unwrap();
        let release_tag = "1.0.0";
        let source_commit = "0123456789abcdef0123456789abcdef01234567";
        let verified_tag_oid = "fedcba9876543210fedcba9876543210fedcba98";
        let sidecar_sha256_hex = Sha256Digest::digest(b"signed container release").encoded();
        db.backend
            .execute(
                "INSERT INTO releases
                   (id, registry_id, semver, tag_oid, commit_oid, signer,
                    tagged_at, pack_present)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'test signer', ?6, 1)",
                &vals![
                    91_001_i64,
                    registry_id,
                    release_tag,
                    verified_tag_oid,
                    source_commit,
                    catalog.observed_at
                ],
            )
            .await
            .unwrap();
        let signed_root_insert = "INSERT INTO oci_release_roots
               (registry_id, release_id, release_tag, repository_id,
                container_name, index_digest, source_commit, verified_tag_oid,
                catalog_digest, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
        let signed_root_values = vals![
            registry_id,
            91_001_i64,
            release_tag,
            repository.id,
            catalog.repository.as_str(),
            catalog.root_digest.to_string(),
            source_commit,
            verified_tag_oid,
            sidecar_sha256_hex,
            catalog.observed_at
        ];
        db.backend
            .execute(signed_root_insert, &signed_root_values)
            .await
            .unwrap();
        assert!(db
            .oci_signed_release_root_exists(
                registry_id,
                repository.id,
                release_tag,
                catalog.root_digest,
                &sidecar_sha256_hex,
            )
            .await
            .unwrap());
        let placement = db.surface_placement(placement_id).await.unwrap().unwrap();
        let revision = db
            .placement_publication_write_revision(placement_id)
            .await
            .unwrap()
            .unwrap();
        let now = catalog.observed_at + 100;
        let begin = BeginOciPublication {
            registry_id,
            repository_id: repository.id,
            writer_id: "writer:release".to_string(),
            token_id: "token:release".to_string(),
            target_tag: Some(Tag::parse(release_tag).unwrap()),
            expected_tag_version: None,
            expected_tag_digest: None,
            root_digest: catalog.root_digest,
            catalog_digest,
            release_tag: Some(release_tag.to_string()),
            sidecar_sha256_hex: Some(sidecar_sha256_hex.clone()),
            required_placements: vec![OciPublicationRequiredPlacement {
                placement_id,
                placement_resource_version: placement.resource_version,
                placement_write_spec_version: placement.write_spec_version,
                placement_observation_version: placement.observation_version.unwrap(),
                binding_id: revision.binding_id,
                binding_write_revision: revision.revision,
                revision_fingerprint: revision.revision_fingerprint,
                capability_fingerprint: revision.capability_fingerprint,
            }],
            source_kind: "release".to_string(),
            idempotency_key: "release-publication".to_string(),
            now,
            expires_at: now + 60,
        };
        let mut publication = db.begin_oci_publication(&begin).await.unwrap();
        assert_eq!(
            oci_publication_confirmation_hash(&publication),
            publication.confirmation_hash
        );
        let mut changed_release_identity = publication.clone();
        changed_release_identity.sidecar_sha256_hex =
            Some(Sha256Digest::digest(b"different signed sidecar").encoded());
        assert_ne!(
            oci_publication_confirmation_hash(&changed_release_identity),
            publication.confirmation_hash
        );
        publication = freeze_publication_graph(
            &db,
            publication,
            repository.id,
            placement_id,
            &graph,
            now + 1,
        )
        .await;
        let frozen = db
            .oci_publication_catalog(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                "release:test",
                now + 2,
            )
            .await
            .unwrap();
        assert_eq!(
            oci_catalog_declaration_digest(frozen.root_digest, &frozen.objects).unwrap(),
            catalog_digest
        );
        db.backend
            .execute(
                "DELETE FROM oci_release_roots
                 WHERE registry_id = ?1 AND repository_id = ?2
                   AND release_tag = ?3",
                &vals![registry_id, repository.id, release_tag],
            )
            .await
            .unwrap();
        assert!(db
            .commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .is_err());
        assert_eq!(
            db.oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                now + 2,
            )
            .await
            .unwrap()
            .unwrap()
            .state,
            "preparing"
        );
        db.backend
            .execute(signed_root_insert, &signed_root_values)
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE surface_placement_observations SET state = 'degraded'
                 WHERE placement_id = ?1",
                &vals![placement_id],
            )
            .await
            .unwrap();
        assert!(
            db.commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .is_err(),
            "one degraded required placement must keep the tag invisible"
        );
        assert!(!db
            .oci_tags(repository.id, 100, None)
            .await
            .unwrap()
            .iter()
            .any(|tag| tag.name.as_str() == release_tag));
        db.backend
            .execute(
                "UPDATE surface_placement_observations SET state = 'ready'
                 WHERE placement_id = ?1",
                &vals![placement_id],
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE surface_placements SET resource_version = resource_version + 1
                 WHERE id = ?1",
                &vals![placement_id],
            )
            .await
            .unwrap();
        assert!(
            db.commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .is_err(),
            "writer-critical topology revision drift must invalidate the frozen plan"
        );
        db.backend
            .execute(
                "UPDATE surface_placements SET resource_version = resource_version - 1
                 WHERE id = ?1",
                &vals![placement_id],
            )
            .await
            .unwrap();
        let ready = db
            .commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .unwrap();
        assert_eq!(ready.state, "ready");
        assert_eq!(
            db.commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:release",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .unwrap(),
            ready
        );
        assert!(
            db.commit_oci_publication(
                &publication.id,
                &publication.writer_id,
                &publication.token_id,
                publication.resource_version,
                "commit:different",
                publication.confirmation_hash,
                &frozen,
                now + 2,
            )
            .await
            .is_err(),
            "a different commit idempotency key must conflict"
        );

        let mut abort_begin = begin.clone();
        abort_begin.target_tag = None;
        abort_begin.idempotency_key = "abort-publication".to_string();
        let aborting = db.begin_oci_publication(&abort_begin).await.unwrap();
        let aborted = db
            .abort_oci_publication(
                &aborting.id,
                &aborting.writer_id,
                &aborting.token_id,
                aborting.resource_version,
                "abort:release",
                now + 3,
            )
            .await
            .unwrap();
        assert_eq!(aborted.state, "aborted");
        assert_eq!(
            db.abort_oci_publication(
                &aborting.id,
                &aborting.writer_id,
                &aborting.token_id,
                aborting.resource_version,
                "abort:release",
                now + 3,
            )
            .await
            .unwrap(),
            aborted
        );
        assert!(db
            .abort_oci_publication(
                &aborting.id,
                &aborting.writer_id,
                &aborting.token_id,
                aborting.resource_version,
                "abort:different",
                now + 3,
            )
            .await
            .is_err());
        let mut other_owner = abort_begin.clone();
        other_owner.writer_id = "writer:other-owner".to_string();
        other_owner.token_id = "token:other-owner".to_string();
        assert!(
            db.begin_oci_publication(&other_owner).await.is_ok(),
            "Begin idempotency keys are scoped to the stable writer owner"
        );

        let mut channel_begin = begin.clone();
        channel_begin.target_tag = Some(Tag::parse("stable").unwrap());
        channel_begin.source_kind = "channel".to_string();
        channel_begin.idempotency_key = "channel-publication".to_string();
        assert!(
            db.begin_oci_publication(&channel_begin).await.is_err(),
            "a channel publication must not begin before signed partitions converge"
        );
        let channel_id = 92_001_i64;
        db.backend
            .execute(
                "INSERT INTO channels (id, registry_id, name, frontier, active)
                 VALUES (?1, ?2, 'stable', ?3, 1)",
                &vals![channel_id, registry_id, release_tag],
            )
            .await
            .unwrap();
        for bucket in 0..256_i64 {
            db.backend
                .execute(
                    "INSERT INTO channel_partitions (channel_id, bucket, release)
                     VALUES (?1, ?2, ?3)",
                    &vals![channel_id, bucket, release_tag],
                )
                .await
                .unwrap();
        }
        let channel = db.begin_oci_publication(&channel_begin).await.unwrap();
        let channel =
            freeze_publication_graph(&db, channel, repository.id, placement_id, &graph, now + 4)
                .await;
        let channel_catalog = db
            .oci_publication_catalog(
                &channel.id,
                &channel.writer_id,
                &channel.token_id,
                "channel:test",
                now + 5,
            )
            .await
            .unwrap();
        db.backend
            .execute(
                "UPDATE channel_partitions SET release = '0.9.0'
                 WHERE channel_id = (SELECT id FROM channels
                   WHERE registry_id = ?1 AND name = 'stable') AND bucket = 0",
                &vals![registry_id],
            )
            .await
            .unwrap();
        assert!(
            db.commit_oci_publication(
                &channel.id,
                &channel.writer_id,
                &channel.token_id,
                channel.resource_version,
                "commit:channel",
                channel.confirmation_hash,
                &channel_catalog,
                now + 5,
            )
            .await
            .is_err(),
            "partition drift after Begin must keep the channel tag invisible"
        );
        assert!(!db
            .oci_tags(repository.id, 100, None)
            .await
            .unwrap()
            .iter()
            .any(|tag| tag.name.as_str() == "stable"));
        db.backend
            .execute(
                "UPDATE channel_partitions SET release = ?2
                 WHERE channel_id = (SELECT id FROM channels
                   WHERE registry_id = ?1 AND name = 'stable') AND bucket = 0",
                &vals![registry_id, release_tag],
            )
            .await
            .unwrap();
        let raced = db
            .compare_and_swap_oci_manual_tag(&CasOciManualTag {
                repository_id: repository.id,
                tag: Tag::parse("stable").unwrap(),
                digest: catalog.root_digest,
                expected_resource_version: None,
                actor_id: "test:tag-race".to_string(),
                now: now + 5,
            })
            .await
            .unwrap();
        assert!(
            db.commit_oci_publication(
                &channel.id,
                &channel.writer_id,
                &channel.token_id,
                channel.resource_version,
                "commit:channel",
                channel.confirmation_hash,
                &channel_catalog,
                now + 5,
            )
            .await
            .is_err(),
            "a tag created after Begin must win the compare-and-swap race"
        );
        let moved = db
            .compare_and_swap_oci_manual_tag(&CasOciManualTag {
                repository_id: repository.id,
                tag: Tag::parse("stable").unwrap(),
                digest: catalog.root_digest,
                expected_resource_version: Some(raced.resource_version),
                actor_id: "test:tag-race-move".to_string(),
                now: now + 6,
            })
            .await
            .unwrap();
        db.delete_oci_manual_tag(
            repository.id,
            &Tag::parse("stable").unwrap(),
            moved.resource_version,
            "test:tag-race-cleanup",
            now + 7,
        )
        .await
        .unwrap();
        let transition_versions = db
            .backend
            .query(
                "SELECT tag_resource_version FROM oci_tag_history
                 WHERE repository_id = ?1 AND name = 'stable'
                 ORDER BY tag_resource_version",
                &vals![repository.id],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<i64>(0).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(transition_versions, [1, 2, 3]);
        assert!(
            db.commit_oci_publication(
                &channel.id,
                &channel.writer_id,
                &channel.token_id,
                channel.resource_version - 1,
                "commit:channel",
                channel.confirmation_hash,
                &channel_catalog,
                now + 5,
            )
            .await
            .is_err(),
            "a stale publication version must not advance a channel tag"
        );
        let channel_ready = db
            .commit_oci_publication(
                &channel.id,
                &channel.writer_id,
                &channel.token_id,
                channel.resource_version,
                "commit:channel",
                channel.confirmation_hash,
                &channel_catalog,
                now + 5,
            )
            .await
            .unwrap();
        assert_eq!(channel_ready.state, "ready");
        assert_eq!(channel_ready.source_kind, "channel");
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
