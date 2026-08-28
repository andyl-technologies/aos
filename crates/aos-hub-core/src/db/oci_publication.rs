//! Durable OCI verified-publication transactions and manual catalog mutation.
//!
//! Publications freeze a complete descriptor graph with exact placement
//! evidence, bind review confirmation to the declared graph and tag CAS, and
//! expose catalog, tag history, and mutation epoch in one atomic commit.

use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FrozenManifestProjection {
    document: ImageManifest,
    platform: Option<Platform>,
}

fn canonical_publication_json<T: serde::Serialize>(value: &T, label: &str) -> Result<String> {
    String::from_utf8(aos_oci_types::to_canonical_json(value)?)
        .with_context(|| format!("canonical {label} is not UTF-8"))
}

fn canonical_publication_projection(input: &AddOciPublicationObject) -> Result<Option<String>> {
    let projection = match input.descriptor.media_type {
        media_type if media_type.is_image_manifest() => {
            if input.object_kind != "manifest" {
                bail!("OCI manifest publication object has the wrong object kind");
            }
            let manifest = serde_json::from_str::<FrozenManifestProjection>(
                input
                    .projection_json
                    .as_deref()
                    .context("OCI publication manifest projection is absent")?,
            )
            .context("decoding OCI publication manifest projection")?;
            manifest.document.validate()?;
            if let Some(platform) = &manifest.platform {
                platform.validate()?;
            }
            Some(canonical_publication_json(
                &manifest,
                "OCI manifest projection",
            )?)
        }
        media_type if media_type.is_image_index() => {
            if input.object_kind != "manifest" {
                bail!("OCI index publication object has the wrong object kind");
            }
            let index = serde_json::from_str::<ImageIndex>(
                input
                    .projection_json
                    .as_deref()
                    .context("OCI publication index projection is absent")?,
            )
            .context("decoding OCI publication index projection")?;
            index.validate()?;
            Some(canonical_publication_json(&index, "OCI index projection")?)
        }
        _ => {
            if input.object_kind != "blob" || input.projection_json.is_some() {
                bail!("OCI blob publication object has a parsed projection");
            }
            None
        }
    };
    Ok(projection)
}

/// Durable verified-publication state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciPublicationRecord {
    /// Stable publication id.
    pub id: String,
    /// Owning registry id.
    pub registry_id: i64,
    /// Destination repository id.
    pub repository_id: i64,
    /// Stable writer owner.
    pub writer_id: String,
    /// Authentication token/session owner.
    pub token_id: String,
    /// Optional target tag.
    pub target_tag: Option<Tag>,
    /// Expected current tag version; absent means the tag must not exist.
    pub expected_tag_version: Option<i64>,
    /// Optional expected current tag digest paired with its version.
    pub expected_tag_digest: Option<Sha256Digest>,
    /// Declared graph root.
    pub root_digest: Sha256Digest,
    /// Digest of the frozen catalog declaration.
    pub catalog_digest: Sha256Digest,
    /// Signed release tag that authenticated this publication, when present.
    pub release_tag: Option<String>,
    /// Lowercase SHA-256 of the exact signed container-release sidecar.
    pub sidecar_sha256_hex: Option<String>,
    /// User-visible confirmation hash binding this exact plan.
    pub confirmation_hash: Sha256Digest,
    /// Digest of the complete frozen required-placement capability set.
    pub topology_digest: Sha256Digest,
    /// Number of placements required to make the publication visible.
    pub required_placement_count: i64,
    /// `manual`, `release`, or `channel`.
    pub source_kind: String,
    /// Publication lifecycle state.
    pub state: String,
    /// Retry identity.
    pub idempotency_key: String,
    /// Retry identity that won the commit transition, when committed.
    pub commit_idempotency_key: Option<String>,
    /// Retry identity that won the abort transition, when aborted.
    pub abort_idempotency_key: Option<String>,
    /// Nonterminal expiry time.
    pub expires_at: i64,
    /// Creation time.
    pub created_at: i64,
    /// Commit time.
    pub committed_at: Option<i64>,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// Parameters for opening a verified publication transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginOciPublication {
    /// Owning registry id.
    pub registry_id: i64,
    /// Destination repository id.
    pub repository_id: i64,
    /// Stable writer owner.
    pub writer_id: String,
    /// Authentication token/session owner.
    pub token_id: String,
    /// Optional target tag.
    pub target_tag: Option<Tag>,
    /// Expected current tag version; absent requires tag absence.
    pub expected_tag_version: Option<i64>,
    /// Optional expected current tag digest.
    pub expected_tag_digest: Option<Sha256Digest>,
    /// Declared graph root.
    pub root_digest: Sha256Digest,
    /// Digest of the canonical declaration, not of manifest bytes.
    pub catalog_digest: Sha256Digest,
    /// Signed release tag, required only for release publication.
    pub release_tag: Option<String>,
    /// Lowercase SHA-256 of the exact signed sidecar, required for releases.
    pub sidecar_sha256_hex: Option<String>,
    /// Complete required placement set selected before any object is frozen.
    pub required_placements: Vec<OciPublicationRequiredPlacement>,
    /// `manual`, `release`, or `channel`.
    pub source_kind: String,
    /// Writer retry identity.
    pub idempotency_key: String,
    /// Positive current Unix time.
    pub now: i64,
    /// Expiry bounded by [`OCI_MAX_SESSION_SECONDS`].
    pub expires_at: i64,
}

/// One writer-critical placement capability frozen by publication begin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciPublicationRequiredPlacement {
    /// Exact placement database identity.
    pub placement_id: i64,
    /// Placement optimistic-concurrency version.
    pub placement_resource_version: i64,
    /// Writer-critical placement configuration version.
    pub placement_write_spec_version: i64,
    /// Latest ready/complete observation version.
    pub placement_observation_version: i64,
    /// Storage binding supplying the admitted write capability.
    pub binding_id: i64,
    /// Immutable binding-local write revision.
    pub binding_write_revision: i64,
    /// Fingerprint of the entire immutable write revision.
    pub revision_fingerprint: String,
    /// Fingerprint of capability semantics.
    pub capability_fingerprint: String,
}

/// One object and exact placement evidence frozen into a publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOciPublicationObject {
    /// Publication id.
    pub publication_id: String,
    /// Required writer owner.
    pub writer_id: String,
    /// Required token owner.
    pub token_id: String,
    /// Expected publication version.
    pub expected_resource_version: i64,
    /// Exact descriptor.
    pub descriptor: Descriptor,
    /// `blob` or `manifest`.
    pub object_kind: String,
    /// Canonical immutable object key.
    pub object_key: String,
    /// Bounded parsed projection serialized as JSON, never reserialized bytes.
    pub projection_json: Option<String>,
    /// Exact observed surface-object id.
    pub surface_object_id: i64,
    /// Exact observed placement id.
    pub placement_id: i64,
    /// Surface-object inventory version.
    pub object_resource_version: i64,
    /// Placement configuration version.
    pub placement_resource_version: i64,
    /// Placement observation version.
    pub placement_observation_version: i64,
    /// Inventory generation carrying the observation.
    pub observed_inventory_generation: i64,
    /// Strong observed etag.
    pub observed_etag: String,
    /// Physical observation time.
    pub observed_at: i64,
}

/// Manual-tag compare-and-swap request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasOciManualTag {
    /// Repository id.
    pub repository_id: i64,
    /// Case-sensitive tag.
    pub tag: Tag,
    /// New repository-linked manifest digest.
    pub digest: Sha256Digest,
    /// Expected current version; absent requires tag absence.
    pub expected_resource_version: Option<i64>,
    /// Stable actor recorded in history.
    pub actor_id: String,
    /// Positive current Unix time.
    pub now: i64,
}
impl Database {
    /// Opens or idempotently returns a verified publication transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed ownership/session data, invalid source
    /// kind or tag precondition, absent repository, idempotency conflict, or
    /// database failure.
    pub async fn begin_oci_publication(
        &self,
        input: &BeginOciPublication,
    ) -> Result<OciPublicationRecord> {
        validate_session_identity(&input.writer_id, "writer id", 128)?;
        validate_session_identity(&input.token_id, "token id", 128)?;
        validate_session_identity(&input.idempotency_key, "idempotency key", 128)?;
        validate_session_times(input.now, input.expires_at)?;
        if !matches!(input.source_kind.as_str(), "manual" | "release" | "channel") {
            bail!("OCI publication source must be manual, release, or channel");
        }
        match (
            input.source_kind.as_str(),
            input.release_tag.as_deref(),
            input.sidecar_sha256_hex.as_deref(),
        ) {
            ("manual", None, None) => {}
            ("release" | "channel", Some(release_tag), Some(sidecar_sha256_hex)) => {
                validate_session_identity(release_tag, "release tag", 255)?;
                if sidecar_sha256_hex.len() != 64
                    || !sidecar_sha256_hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    bail!("OCI release sidecar digest is not lowercase SHA-256");
                }
            }
            _ => bail!("OCI publication signed-release identity is incomplete"),
        }
        if input.expected_tag_digest.is_some() && input.expected_tag_version.is_none() {
            bail!("OCI publication tag digest requires an expected version");
        }
        if input.target_tag.is_none()
            && (input.expected_tag_version.is_some() || input.expected_tag_digest.is_some())
        {
            bail!("untagged OCI publication cannot carry a tag precondition");
        }
        match (input.source_kind.as_str(), input.target_tag.as_ref()) {
            ("release", Some(tag)) if Some(tag.as_str()) != input.release_tag.as_deref() => {
                bail!("OCI release publication tag must equal the signed release identity");
            }
            ("channel", Some(tag)) if Some(tag.as_str()) != input.release_tag.as_deref() => {}
            ("channel", _) => {
                bail!("OCI channel publication requires a distinct channel target tag");
            }
            _ => {}
        }
        if input.source_kind == "release"
            && (input.expected_tag_version.is_some() || input.expected_tag_digest.is_some())
        {
            bail!("OCI signed release tags are immutable and require an absent target");
        }
        let topology_digest = oci_publication_topology_digest(&input.required_placements)?;
        let required_placement_count = i64::try_from(input.required_placements.len())
            .context("OCI publication required placement count exceeds int64")?;
        let publication_id = Uuid::new_v4().simple().to_string();
        let confirmation_hash = oci_publication_confirmation_hash_fields(
            &publication_id,
            input.registry_id,
            input.repository_id,
            input.root_digest,
            input.catalog_digest,
            input.release_tag.as_deref(),
            input.sidecar_sha256_hex.as_deref(),
            input.target_tag.as_ref(),
            input.expected_tag_version,
            input.expected_tag_digest,
            topology_digest,
            &input.source_kind,
        );
        let mut statements = vec![Statement::new(
            "INSERT INTO oci_publication_sessions
               (id, registry_id, repository_id, writer_id, token_id, target_tag,
                expected_tag_version, expected_tag_digest, root_digest,
                catalog_digest, release_tag, sidecar_sha256, confirmation_hash,
                topology_digest, required_placement_count, source_kind, state,
                idempotency_key, commit_idempotency_key, abort_idempotency_key,
                expires_at, created_at, committed_at, resource_version)
             SELECT ?1, repository.registry_id, repository.id, ?4, ?5, ?6,
                    ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                    'preparing', ?17, NULL, NULL, ?18, ?19, NULL, 1
             FROM oci_repositories repository
             WHERE repository.id = ?2 AND repository.registry_id = ?3
               AND repository.lifecycle_state = 'active'
               AND (?16 = 'manual' OR EXISTS (SELECT 1
                 FROM oci_release_roots root JOIN releases release
                   ON release.id = root.release_id
                  AND release.registry_id = root.registry_id
                  AND release.semver = root.release_tag
                  AND release.commit_oid = root.source_commit
                  AND release.tag_oid = root.verified_tag_oid
                  AND release.pack_present = 1
                 WHERE root.registry_id = ?3 AND root.repository_id = ?2
                   AND root.release_tag = ?11 AND root.index_digest = ?9
                   AND root.catalog_digest = ?12))
               AND (?16 <> 'channel' OR EXISTS (SELECT 1 FROM channels channel
                 WHERE channel.registry_id = ?3 AND channel.name = ?6
                   AND channel.active = 1 AND channel.frontier = ?11
                   AND (SELECT COUNT(*) FROM channel_partitions partition
                     WHERE partition.channel_id = channel.id) = 256
                   AND NOT EXISTS (SELECT 1 FROM channel_partitions partition
                     WHERE partition.channel_id = channel.id
                       AND partition.release <> ?11)))
               AND NOT EXISTS (SELECT 1 FROM oci_publication_sessions current
                 WHERE current.registry_id = ?3 AND current.writer_id = ?4
                   AND current.idempotency_key = ?17)",
            vals![
                publication_id,
                input.repository_id,
                input.registry_id,
                input.writer_id,
                input.token_id,
                input.target_tag.as_ref().map(Tag::as_str),
                input.expected_tag_version,
                input.expected_tag_digest.map(|digest| digest.to_string()),
                input.root_digest.to_string(),
                input.catalog_digest.to_string(),
                input.release_tag,
                input.sidecar_sha256_hex,
                confirmation_hash.to_string(),
                topology_digest.to_string(),
                required_placement_count,
                input.source_kind,
                input.idempotency_key,
                input.expires_at,
                input.now
            ],
        )
        .expecting(1)];
        for placement in &input.required_placements {
            statements.push(
                Statement::new(
                    "INSERT INTO oci_publication_required_placements
                       (publication_id, registry_id, placement_id,
                        placement_resource_version, placement_write_spec_version,
                        placement_observation_version, binding_id,
                        binding_write_revision, revision_fingerprint,
                        capability_fingerprint)
                     SELECT publication.id, publication.registry_id, placement.id,
                            placement.resource_version, placement.write_spec_version,
                            observation.observation_version, revision.binding_id,
                            revision.revision, revision.revision_fingerprint,
                            revision.capability_fingerprint
                     FROM oci_publication_sessions publication
                     JOIN surface_placement_effective placement
                       ON placement.id = ?2 AND placement.registry_id = publication.registry_id
                     JOIN surface_placement_observations observation
                       ON observation.placement_id = placement.id
                     JOIN surface_placement_write_capabilities capability
                       ON capability.placement_id = placement.id
                      AND capability.placement_write_spec_version = placement.write_spec_version
                     JOIN binding_write_revisions revision
                       ON revision.binding_id = capability.binding_id
                      AND revision.revision = capability.binding_write_revision
                     JOIN binding_write_observations write_observation
                       ON write_observation.binding_id = revision.binding_id
                      AND write_observation.revision = revision.revision
                     JOIN binding_credential_revisions credential
                       ON credential.binding_id = revision.binding_id
                      AND credential.purpose = revision.write_credential_purpose
                      AND credential.generation = revision.write_credential_generation
                     WHERE publication.id = ?1 AND placement.kind = 'complete'
                       AND placement.desired_state = 'active' AND placement.state = 'ready'
                       AND placement.completeness = 'complete'
                       AND placement.resource_version = ?3
                       AND placement.write_spec_version = ?4
                       AND observation.observation_version = ?5
                       AND revision.binding_id = ?6 AND revision.revision = ?7
                       AND revision.revision_fingerprint = ?8
                       AND revision.capability_fingerprint = ?9
                       AND revision.writes_supported = 1
                       AND write_observation.state = 'valid'
                       AND credential.validation_state = 'valid'
                       AND (placement.requires_conditional_writes = 0
                         OR revision.conditional_writes_supported = 1)",
                    vals![
                        publication_id,
                        placement.placement_id,
                        placement.placement_resource_version,
                        placement.placement_write_spec_version,
                        placement.placement_observation_version,
                        placement.binding_id,
                        placement.binding_write_revision,
                        placement.revision_fingerprint,
                        placement.capability_fingerprint
                    ],
                )
                .expecting(1),
            );
        }
        statements.push(
            Statement::new(
                "UPDATE oci_publication_sessions SET resource_version = resource_version
                 WHERE id = ?1 AND topology_digest = ?2
                   AND required_placement_count = ?3
                   AND (SELECT COUNT(*) FROM oci_publication_required_placements required
                     WHERE required.publication_id = oci_publication_sessions.id) = ?3
                   AND NOT EXISTS (SELECT 1 FROM surface_placement_effective placement
                     WHERE placement.registry_id = oci_publication_sessions.registry_id
                       AND placement.kind = 'complete'
                       AND placement.desired_state = 'active' AND placement.state = 'ready'
                       AND placement.completeness = 'complete'
                       AND EXISTS (SELECT 1
                         FROM surface_placement_write_capabilities capability
                         JOIN binding_write_revisions revision
                           ON revision.binding_id = capability.binding_id
                          AND revision.revision = capability.binding_write_revision
                         JOIN binding_write_observations write_observation
                           ON write_observation.binding_id = revision.binding_id
                          AND write_observation.revision = revision.revision
                         JOIN binding_credential_revisions credential
                           ON credential.binding_id = revision.binding_id
                          AND credential.purpose = revision.write_credential_purpose
                          AND credential.generation = revision.write_credential_generation
                         WHERE capability.placement_id = placement.id
                           AND capability.placement_write_spec_version = placement.write_spec_version
                           AND revision.writes_supported = 1
                           AND write_observation.state = 'valid'
                           AND credential.validation_state = 'valid'
                           AND (placement.requires_conditional_writes = 0
                             OR revision.conditional_writes_supported = 1))
                       AND NOT EXISTS (SELECT 1
                         FROM oci_publication_required_placements required
                         WHERE required.publication_id = oci_publication_sessions.id
                           AND required.placement_id = placement.id))",
                vals![
                    publication_id,
                    topology_digest.to_string(),
                    required_placement_count
                ],
            )
            .expecting(1),
        );
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_publication_by_idempotency(
                    input.registry_id,
                    &input.writer_id,
                    &input.idempotency_key,
                )
                .await?
            {
                if existing.repository_id == input.repository_id
                    && existing.token_id == input.token_id
                    && existing.target_tag == input.target_tag
                    && existing.expected_tag_version == input.expected_tag_version
                    && existing.expected_tag_digest == input.expected_tag_digest
                    && existing.root_digest == input.root_digest
                    && existing.catalog_digest == input.catalog_digest
                    && existing.release_tag == input.release_tag
                    && existing.sidecar_sha256_hex == input.sidecar_sha256_hex
                    && existing.topology_digest == topology_digest
                    && existing.required_placement_count == required_placement_count
                    && existing.source_kind == input.source_kind
                {
                    return Ok(existing);
                }
                bail!("OCI publication idempotency key conflicts with another request");
            }
            return Err(error).context("opening OCI publication");
        }
        self.oci_publication(
            &publication_id,
            &input.writer_id,
            &input.token_id,
            input.now,
        )
        .await?
        .context("new OCI publication disappeared")
    }

    /// Returns a publication only to its exact writer and token owner.
    ///
    /// # Errors
    ///
    /// Returns an error on database failure or malformed persisted state.
    pub async fn oci_publication(
        &self,
        publication_id: &str,
        writer_id: &str,
        token_id: &str,
        now: i64,
    ) -> Result<Option<OciPublicationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_PUBLICATION_COLUMNS} FROM oci_publication_sessions
                     WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                       AND (state IN('ready', 'aborted', 'failed') OR expires_at > ?4)"
                ),
                &vals![publication_id, writer_id, token_id, now],
            )
            .await?
            .as_ref()
            .map(row_to_oci_publication)
            .transpose()
    }

    async fn oci_publication_by_idempotency(
        &self,
        registry_id: i64,
        writer_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<OciPublicationRecord>> {
        self.backend
            .query_opt(
                &format!(
                    "SELECT {OCI_PUBLICATION_COLUMNS} FROM oci_publication_sessions
                     WHERE registry_id = ?1 AND writer_id = ?2
                       AND idempotency_key = ?3"
                ),
                &vals![registry_id, writer_id, idempotency_key],
            )
            .await?
            .as_ref()
            .map(row_to_oci_publication)
            .transpose()
    }

    /// Freezes one descriptor and exact physical placement into a publication.
    /// Exact retries are idempotent; identity or placement drift is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed descriptor/projection/evidence, stale
    /// ownership/version, absent exact physical bytes, or database failure.
    pub async fn add_oci_publication_object(
        &self,
        input: &AddOciPublicationObject,
        now: i64,
    ) -> Result<OciPublicationRecord> {
        input.descriptor.validate()?;
        if input.expected_resource_version < 1
            || now <= 0
            || !matches!(input.object_kind.as_str(), "blob" | "manifest")
            || input.object_key != oci_blob_object_key(input.descriptor.digest)
            || input
                .projection_json
                .as_ref()
                .is_some_and(|value| value.len() > 1_048_576)
            || input.observed_etag.is_empty()
        {
            bail!("OCI publication object declaration is malformed");
        }
        let projection_json = canonical_publication_projection(input)?;
        let size = checked_u64(input.descriptor.size, "publication object size")?;
        let digest = input.descriptor.digest.to_string();
        let descriptor_json =
            canonical_publication_json(&input.descriptor, "OCI publication descriptor")?;
        let statements = vec![
            Statement::new(
                "INSERT INTO oci_publication_objects
                   (publication_id, registry_id, digest, media_type, byte_size,
                    object_kind, object_key, descriptor_json, projection_json)
                 SELECT publication.id, publication.registry_id, ?4, ?5, ?6,
                        ?7, ?8, ?9, ?10
                 FROM oci_publication_sessions publication
                 WHERE publication.id = ?1 AND publication.writer_id = ?2
                   AND publication.token_id = ?3 AND publication.state = 'preparing'
                   AND publication.expires_at > ?11
                   AND publication.resource_version = ?12
                 ON CONFLICT(publication_id, digest) DO NOTHING",
                vals![
                    input.publication_id,
                    input.writer_id,
                    input.token_id,
                    digest,
                    input.descriptor.media_type.as_str(),
                    size,
                    input.object_kind,
                    input.object_key,
                    descriptor_json,
                    projection_json,
                    now,
                    input.expected_resource_version
                ],
            )
            .unchecked(),
            Statement::new(
                "INSERT INTO oci_publication_object_placements
                   (publication_id, digest, registry_id, surface_object_id,
                    placement_id, object_resource_version,
                    placement_resource_version, placement_observation_version,
                    observed_inventory_generation, observed_size, observed_etag,
                    observed_at)
                 SELECT publication.id, object.digest, publication.registry_id,
                        surface.id, placement.id, surface.resource_version,
                        placement.resource_version, observation.observation_version,
                        presence.observed_inventory_generation,
                        presence.observed_size, presence.etag, presence.observed_at
                 FROM oci_publication_sessions publication
                 JOIN oci_publication_objects object
                   ON object.publication_id = publication.id AND object.digest = ?4
                 JOIN surface_objects surface ON surface.id = ?5
                   AND surface.registry_id = publication.registry_id
                 JOIN object_placements presence
                   ON presence.surface_object_id = surface.id
                  AND presence.registry_id = surface.registry_id
                  AND presence.placement_id = ?6
                 JOIN surface_placements placement ON placement.id = presence.placement_id
                   AND placement.registry_id = publication.registry_id
                 JOIN surface_placement_observations observation
                   ON observation.placement_id = placement.id
                 WHERE publication.id = ?1 AND publication.writer_id = ?2
                   AND publication.token_id = ?3 AND publication.state = 'preparing'
                   AND publication.expires_at > ?7
                   AND publication.resource_version = ?8
                   AND EXISTS (SELECT 1 FROM oci_publication_required_placements required
                     WHERE required.publication_id = publication.id
                       AND required.placement_id = placement.id
                       AND required.placement_resource_version = placement.resource_version
                       AND required.placement_observation_version = observation.observation_version)
                   AND surface.object_key = object.object_key
                   AND surface.content_hash = ?9 AND surface.size = object.byte_size
                   AND surface.object_kind = 'immutable'
                   AND surface.lifecycle_state = 'active'
                   AND surface.resource_version = ?10
                   AND placement.resource_version = ?11
                   AND observation.observation_version = ?12
                   AND presence.observed_inventory_generation = ?13
                   AND presence.observed_hash = ?9
                   AND presence.observed_size = object.byte_size
                   AND presence.etag = ?14 AND presence.observed_at = ?15
                   AND presence.state = 'present'
                   AND presence.catalog_object_resource_version = surface.resource_version
                 ON CONFLICT(publication_id, digest, placement_id) DO NOTHING",
                vals![
                    input.publication_id,
                    input.writer_id,
                    input.token_id,
                    digest,
                    input.surface_object_id,
                    input.placement_id,
                    now,
                    input.expected_resource_version,
                    input.descriptor.digest.encoded(),
                    input.object_resource_version,
                    input.placement_resource_version,
                    input.placement_observation_version,
                    input.observed_inventory_generation,
                    input.observed_etag,
                    input.observed_at
                ],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_publication_sessions SET resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'preparing' AND expires_at > ?4
                   AND resource_version = ?5
                   AND EXISTS (SELECT 1 FROM oci_publication_objects object
                     WHERE object.publication_id = oci_publication_sessions.id
                       AND object.digest = ?6 AND object.media_type = ?7
                       AND object.byte_size = ?8 AND object.object_kind = ?9
                       AND object.object_key = ?10
                       AND object.descriptor_json = ?11
                       AND ((object.projection_json IS NULL AND ?12 IS NULL)
                         OR object.projection_json = ?12))
                   AND EXISTS (SELECT 1 FROM oci_publication_object_placements evidence
                     WHERE evidence.publication_id = oci_publication_sessions.id
                       AND evidence.digest = ?6 AND evidence.placement_id = ?13
                       AND evidence.surface_object_id = ?14
                       AND evidence.object_resource_version = ?15
                       AND evidence.placement_resource_version = ?16
                       AND evidence.placement_observation_version = ?17
                       AND evidence.observed_inventory_generation = ?18
                       AND evidence.observed_size = ?8
                       AND evidence.observed_etag = ?19
                       AND evidence.observed_at = ?20)",
                vals![
                    input.publication_id,
                    input.writer_id,
                    input.token_id,
                    now,
                    input.expected_resource_version,
                    digest,
                    input.descriptor.media_type.as_str(),
                    size,
                    input.object_kind,
                    input.object_key,
                    descriptor_json,
                    projection_json,
                    input.placement_id,
                    input.surface_object_id,
                    input.object_resource_version,
                    input.placement_resource_version,
                    input.placement_observation_version,
                    input.observed_inventory_generation,
                    input.observed_etag,
                    input.observed_at
                ],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if self.publication_object_matches(input).await?
                && self.publication_placement_matches(input).await?
            {
                if let Some(existing) = self
                    .oci_publication(
                        &input.publication_id,
                        &input.writer_id,
                        &input.token_id,
                        now,
                    )
                    .await?
                {
                    return Ok(existing);
                }
            }
            return Err(error).context("freezing OCI publication object");
        }
        self.oci_publication(
            &input.publication_id,
            &input.writer_id,
            &input.token_id,
            now,
        )
        .await?
        .context("advanced OCI publication disappeared")
    }

    async fn publication_object_matches(&self, input: &AddOciPublicationObject) -> Result<bool> {
        let projection_json = canonical_publication_projection(input)?;
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_publication_objects WHERE publication_id = ?1
                   AND digest = ?2 AND media_type = ?3 AND byte_size = ?4
                   AND object_kind = ?5 AND object_key = ?6
                   AND descriptor_json = ?7
                   AND ((projection_json IS NULL AND ?8 IS NULL) OR projection_json = ?8)",
                &vals![
                    input.publication_id,
                    input.descriptor.digest.to_string(),
                    input.descriptor.media_type.as_str(),
                    checked_u64(input.descriptor.size, "publication object size")?,
                    input.object_kind,
                    input.object_key,
                    canonical_publication_json(&input.descriptor, "OCI publication descriptor")?,
                    projection_json
                ],
            )
            .await?
            .is_some())
    }

    async fn publication_placement_matches(&self, input: &AddOciPublicationObject) -> Result<bool> {
        Ok(self
            .backend
            .query_opt(
                "SELECT 1 FROM oci_publication_object_placements
                 WHERE publication_id = ?1 AND digest = ?2 AND placement_id = ?3
                   AND surface_object_id = ?4 AND object_resource_version = ?5
                   AND placement_resource_version = ?6
                   AND placement_observation_version = ?7
                   AND observed_inventory_generation = ?8
                   AND observed_size = ?9 AND observed_etag = ?10
                   AND observed_at = ?11",
                &vals![
                    input.publication_id,
                    input.descriptor.digest.to_string(),
                    input.placement_id,
                    input.surface_object_id,
                    input.object_resource_version,
                    input.placement_resource_version,
                    input.placement_observation_version,
                    input.observed_inventory_generation,
                    checked_u64(input.descriptor.size, "publication object size")?,
                    input.observed_etag,
                    input.observed_at
                ],
            )
            .await?
            .is_some())
    }

    /// Reconstructs the exact frozen catalog declaration for commit.
    ///
    /// Every required placement must have been frozen for every object. The
    /// returned actor/time are commit metadata; descriptors and projections
    /// come exclusively from the durable declaration and are rehashed against
    /// the publication's `catalog_digest`.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership/expiry, malformed frozen JSON,
    /// incomplete selected-placement evidence, catalog digest mismatch, or
    /// database failure.
    pub async fn oci_publication_catalog(
        &self,
        publication_id: &str,
        writer_id: &str,
        token_id: &str,
        actor_id: &str,
        now: i64,
    ) -> Result<IndexOciRepositoryCatalog> {
        validate_session_identity(actor_id, "catalog actor", 128)?;
        if now <= 0 {
            bail!("OCI publication catalog commit metadata is invalid");
        }
        let publication = self
            .oci_publication(publication_id, writer_id, token_id, now)
            .await?
            .context("OCI publication does not exist, is expired, or ownership changed")?;
        if !matches!(publication.state.as_str(), "preparing" | "ready") {
            bail!("OCI publication is not available for catalog reconstruction");
        }
        let repository_row = self
            .backend
            .query_opt(
                "SELECT name FROM oci_repositories WHERE id = ?1
                   AND registry_id = ?2 AND lifecycle_state = 'active'",
                &vals![publication.repository_id, publication.registry_id],
            )
            .await?
            .context("OCI publication repository disappeared")?;
        let repository = RepositoryName::parse(&repository_row.get::<String>(0)?)?;
        let placement_id: i64 = self
            .backend
            .query_opt(
                "SELECT MIN(placement_id) FROM oci_publication_required_placements
                 WHERE publication_id = ?1",
                &vals![publication_id],
            )
            .await?
            .context("OCI publication required placement set disappeared")?
            .get::<Option<i64>>(0)?
            .context("OCI publication required placement set is empty")?;
        let rows = self
            .backend
            .query(
                "SELECT object.descriptor_json, object.projection_json
                 FROM oci_publication_objects object
                 WHERE object.publication_id = ?1
                   AND (SELECT COUNT(*) FROM oci_publication_object_placements evidence
                     JOIN oci_publication_required_placements required
                       ON required.publication_id = evidence.publication_id
                      AND required.placement_id = evidence.placement_id
                     WHERE evidence.publication_id = object.publication_id
                       AND evidence.digest = object.digest) = ?2
                 ORDER BY object.digest",
                &vals![publication_id, publication.required_placement_count],
            )
            .await?;
        let declared_count: i64 = self
            .backend
            .query_opt(
                "SELECT COUNT(*) FROM oci_publication_objects WHERE publication_id = ?1",
                &vals![publication_id],
            )
            .await?
            .context("OCI publication object count disappeared")?
            .get(0)?;
        if i64::try_from(rows.len()).context("OCI publication row count exceeds int64")?
            != declared_count
        {
            bail!("OCI publication required placements do not cover the complete graph");
        }
        let mut objects = Vec::with_capacity(rows.len());
        for row in rows {
            let descriptor: Descriptor = serde_json::from_str(&row.get::<String>(0)?)
                .context("decoding frozen OCI publication descriptor")?;
            descriptor.validate()?;
            let projection_json = row.get::<Option<String>>(1)?;
            let projection = if descriptor.media_type.is_image_manifest() {
                let manifest = serde_json::from_str::<FrozenManifestProjection>(
                    projection_json
                        .as_deref()
                        .context("frozen OCI manifest projection is absent")?,
                )
                .context("decoding frozen OCI manifest projection")?;
                manifest.document.validate()?;
                if let Some(platform) = &manifest.platform {
                    platform.validate()?;
                }
                Some(OciCatalogProjection::Manifest {
                    document: manifest.document,
                    platform: manifest.platform,
                })
            } else if descriptor.media_type.is_image_index() {
                let index = serde_json::from_str::<ImageIndex>(
                    projection_json
                        .as_deref()
                        .context("frozen OCI index projection is absent")?,
                )
                .context("decoding frozen OCI index projection")?;
                index.validate()?;
                Some(OciCatalogProjection::Index(index))
            } else {
                if projection_json.is_some() {
                    bail!("frozen OCI blob unexpectedly has a parsed projection");
                }
                None
            };
            objects.push(OciCatalogObject {
                descriptor,
                projection,
            });
        }
        if oci_catalog_declaration_digest(publication.root_digest, &objects)?
            != publication.catalog_digest
        {
            bail!("frozen OCI publication catalog digest is invalid");
        }
        Ok(IndexOciRepositoryCatalog {
            registry_id: publication.registry_id,
            placement_id,
            repository,
            objects,
            root_digest: publication.root_digest,
            tag: publication.target_tag,
            source_kind: publication.source_kind,
            actor_id: actor_id.to_string(),
            observed_at: now,
        })
    }

    /// Aborts a preparing publication and cancels all of its nonterminal
    /// uploads, releasing their quota reservations in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for stale ownership/version, a committing or ready
    /// publication, or database failure.
    pub async fn abort_oci_publication(
        &self,
        publication_id: &str,
        writer_id: &str,
        token_id: &str,
        expected_resource_version: i64,
        idempotency_key: &str,
        now: i64,
    ) -> Result<OciPublicationRecord> {
        validate_session_identity(idempotency_key, "abort idempotency key", 128)?;
        if expected_resource_version < 1 || now <= 0 {
            bail!("OCI publication abort metadata is invalid");
        }
        if let Some(existing) = self
            .oci_publication(publication_id, writer_id, token_id, now)
            .await?
        {
            if existing.state == "aborted" {
                if existing.abort_idempotency_key.as_deref() == Some(idempotency_key) {
                    return Ok(existing);
                }
                bail!("OCI publication was aborted by a different idempotency key");
            }
        }
        let statements = vec![
            Statement::new(
                "UPDATE org_usage SET
                   used_bytes = CASE WHEN used_bytes - COALESCE((SELECT SUM(reserved_bytes)
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE upload.publication_id = ?1 AND reservation.state = 'reserved'), 0)
                     < 0 THEN 0 ELSE used_bytes - COALESCE((SELECT SUM(reserved_bytes)
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE upload.publication_id = ?1 AND reservation.state = 'reserved'), 0) END,
                   object_count = CASE WHEN object_count - COALESCE((SELECT SUM(reserved_objects)
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE upload.publication_id = ?1 AND reservation.state = 'reserved'), 0)
                     < 0 THEN 0 ELSE object_count - COALESCE((SELECT SUM(reserved_objects)
                     FROM oci_quota_reservations reservation JOIN oci_upload_sessions upload
                       ON upload.quota_reservation_id = reservation.id
                     WHERE upload.publication_id = ?1 AND reservation.state = 'reserved'), 0) END,
                   updated_at = ?5
                 WHERE org_id = (SELECT registry.org_id FROM oci_publication_sessions publication
                   JOIN registries registry ON registry.id = publication.registry_id
                   WHERE publication.id = ?1 AND publication.writer_id = ?2
                     AND publication.token_id = ?3 AND publication.state = 'preparing'
                     AND publication.resource_version = ?4)",
                vals![
                    publication_id,
                    writer_id,
                    token_id,
                    expected_resource_version,
                    now
                ],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_quota_reservations SET state = 'released', updated_at = ?2
                 WHERE state = 'reserved' AND id IN (SELECT upload.quota_reservation_id
                   FROM oci_upload_sessions upload WHERE upload.publication_id = ?1
                     AND upload.state IN('active', 'completing'))",
                vals![publication_id, now],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_upload_sessions SET state = 'cancelled', finished_at = ?2,
                    resource_version = resource_version + 1
                 WHERE publication_id = ?1 AND state IN('active', 'completing')",
                vals![publication_id, now],
            )
            .unchecked(),
            Statement::new(
                "DELETE FROM oci_blob_claims WHERE upload_id IN
                   (SELECT id FROM oci_upload_sessions WHERE publication_id = ?1)",
                vals![publication_id],
            )
            .unchecked(),
            Statement::new(
                "UPDATE oci_publication_sessions SET state = 'aborted',
                    abort_idempotency_key = ?5,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'preparing' AND resource_version = ?4",
                vals![
                    publication_id,
                    writer_id,
                    token_id,
                    expected_resource_version,
                    idempotency_key
                ],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            if let Some(existing) = self
                .oci_publication(publication_id, writer_id, token_id, now)
                .await?
            {
                if existing.state == "aborted"
                    && existing.abort_idempotency_key.as_deref() == Some(idempotency_key)
                {
                    return Ok(existing);
                }
            }
            return Err(error).context("aborting OCI publication");
        }
        self.oci_publication(publication_id, writer_id, token_id, now)
            .await?
            .context("aborted OCI publication disappeared")
    }

    /// Moves or creates a manual tag under an explicit compare-and-swap
    /// precondition and records immutable history.
    ///
    /// Tags created by signed release/channel publication are immutable to this
    /// API. An operator must publish another signed root instead.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed actor/time, stale/absent precondition,
    /// signed-tag mutation, absent repository manifest, or database failure.
    pub async fn compare_and_swap_oci_manual_tag(
        &self,
        input: &CasOciManualTag,
    ) -> Result<OciTagRecord> {
        validate_session_identity(&input.actor_id, "tag actor", 128)?;
        if input.now <= 0
            || input
                .expected_resource_version
                .is_some_and(|version| version < 1)
        {
            bail!("OCI tag compare-and-swap metadata is invalid");
        }
        let history_id = Uuid::new_v4().simple().to_string();
        let mut statements = vec![Statement::new(
            "INSERT INTO oci_tag_history
                   (id, repository_id, registry_id, name, prior_digest,
                    next_digest, source_kind, actor_id, changed_at)
                 SELECT ?1, repository.id, repository.registry_id, ?3,
                        current.digest, ?4, 'manual', ?5, ?6
                 FROM oci_repositories repository LEFT JOIN oci_tags current
                   ON current.repository_id = repository.id AND current.name = ?3
                 WHERE repository.id = ?2 AND repository.lifecycle_state = 'active'
                   AND EXISTS (SELECT 1 FROM oci_repository_objects link
                     WHERE link.repository_id = repository.id AND link.digest = ?4
                       AND link.object_kind = 'manifest')
                   AND ((?7 IS NULL AND current.name IS NULL)
                     OR (?7 IS NOT NULL AND current.resource_version = ?7
                       AND current.source_kind = 'manual'))",
            vals![
                history_id,
                input.repository_id,
                input.tag.as_str(),
                input.digest.to_string(),
                input.actor_id,
                input.now,
                input.expected_resource_version
            ],
        )
        .expecting(1)];
        let tag_mutation = if let Some(expected) = input.expected_resource_version {
            Statement::new(
                "UPDATE oci_tags SET digest = ?3, source_kind = 'manual',
                    resource_version = resource_version + 1, updated_at = ?4
                 WHERE repository_id = ?1 AND name = ?2
                   AND resource_version = ?5 AND source_kind = 'manual'",
                vals![
                    input.repository_id,
                    input.tag.as_str(),
                    input.digest.to_string(),
                    input.now,
                    expected
                ],
            )
            .expecting(1)
        } else {
            Statement::new(
                "INSERT INTO oci_tags
                   (repository_id, registry_id, name, digest, source_kind,
                    resource_version, updated_at)
                 SELECT repository.id, repository.registry_id, ?2, ?3,
                        'manual', 1, ?4
                 FROM oci_repositories repository
                 WHERE repository.id = ?1 AND NOT EXISTS (SELECT 1 FROM oci_tags
                   WHERE repository_id = ?1 AND name = ?2)",
                vals![
                    input.repository_id,
                    input.tag.as_str(),
                    input.digest.to_string(),
                    input.now
                ],
            )
            .expecting(1)
        };
        statements.push(tag_mutation);
        statements.push(
            Statement::new(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
                    updated_at = ?3
                 WHERE registry_id = (SELECT registry_id FROM oci_repositories WHERE id = ?1)
                   AND EXISTS (SELECT 1 FROM oci_tags WHERE repository_id = ?1
                     AND name = ?2 AND digest = ?4 AND source_kind = 'manual')",
                vals![
                    input.repository_id,
                    input.tag.as_str(),
                    input.now,
                    input.digest.to_string()
                ],
            )
            .expecting(1),
        );
        if let Err(error) = self.backend.checked_batch(&statements).await {
            let current = self
                .backend
                .query_opt(
                    "SELECT name, digest, source_kind, resource_version, updated_at
                     FROM oci_tags WHERE repository_id = ?1 AND name = ?2",
                    &vals![input.repository_id, input.tag.as_str()],
                )
                .await?;
            let replayed = current
                .as_ref()
                .map(row_to_oci_tag)
                .transpose()?
                .filter(|tag| {
                    tag.digest == input.digest
                        && tag.source_kind == "manual"
                        && tag.updated_at == input.now
                        && tag.resource_version
                            == input
                                .expected_resource_version
                                .and_then(|version| version.checked_add(1))
                                .unwrap_or(1)
                });
            let history = self
                .backend
                .query_opt(
                    "SELECT 1 FROM oci_tag_history WHERE repository_id = ?1
                       AND name = ?2 AND next_digest = ?3 AND source_kind = 'manual'
                       AND actor_id = ?4 AND changed_at = ?5",
                    &vals![
                        input.repository_id,
                        input.tag.as_str(),
                        input.digest.to_string(),
                        input.actor_id,
                        input.now
                    ],
                )
                .await?
                .is_some();
            if history {
                if let Some(replayed) = replayed {
                    return Ok(replayed);
                }
            }
            return Err(error).context("updating OCI manual tag");
        }
        self.backend
            .query_opt(
                "SELECT name, digest, source_kind, resource_version, updated_at
                 FROM oci_tags WHERE repository_id = ?1 AND name = ?2",
                &vals![input.repository_id, input.tag.as_str()],
            )
            .await?
            .as_ref()
            .map(row_to_oci_tag)
            .transpose()?
            .context("updated OCI tag disappeared")
    }

    /// Deletes one manual tag under an exact version precondition and records
    /// immutable history.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed actor/time/version, a missing/stale tag,
    /// signed release/channel ownership, or database failure.
    pub async fn delete_oci_manual_tag(
        &self,
        repository_id: i64,
        tag: &Tag,
        expected_resource_version: i64,
        actor_id: &str,
        now: i64,
    ) -> Result<()> {
        validate_session_identity(actor_id, "tag actor", 128)?;
        if expected_resource_version < 1 || now <= 0 {
            bail!("OCI tag deletion metadata is invalid");
        }
        let statements = vec![
            Statement::new(
                "INSERT INTO oci_tag_history
                   (id, repository_id, registry_id, name, prior_digest,
                    next_digest, source_kind, actor_id, changed_at)
                 SELECT ?1, tag.repository_id, tag.registry_id, tag.name,
                        tag.digest, NULL, 'manual', ?5, ?6
                 FROM oci_tags tag WHERE tag.repository_id = ?2 AND tag.name = ?3
                   AND tag.resource_version = ?4 AND tag.source_kind = 'manual'",
                vals![
                    Uuid::new_v4().simple().to_string(),
                    repository_id,
                    tag.as_str(),
                    expected_resource_version,
                    actor_id,
                    now
                ],
            )
            .expecting(1),
            Statement::new(
                "DELETE FROM oci_tags WHERE repository_id = ?1 AND name = ?2
                   AND resource_version = ?3 AND source_kind = 'manual'",
                vals![repository_id, tag.as_str(), expected_resource_version],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
                    updated_at = ?3
                 WHERE registry_id = (SELECT registry_id FROM oci_repositories WHERE id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_tags
                     WHERE repository_id = ?1 AND name = ?2)",
                vals![repository_id, tag.as_str(), now],
            )
            .expecting(1),
        ];
        if let Err(error) = self.backend.checked_batch(&statements).await {
            let absent = self
                .backend
                .query_opt(
                    "SELECT 1 FROM oci_tags WHERE repository_id = ?1 AND name = ?2",
                    &vals![repository_id, tag.as_str()],
                )
                .await?
                .is_none();
            let replayed = self
                .backend
                .query_opt(
                    "SELECT 1 FROM oci_tag_history WHERE repository_id = ?1
                       AND name = ?2 AND next_digest IS NULL
                       AND source_kind = 'manual' AND actor_id = ?3 AND changed_at = ?4",
                    &vals![repository_id, tag.as_str(), actor_id, now],
                )
                .await?
                .is_some();
            if absent && replayed {
                return Ok(());
            }
            return Err(error).context("deleting OCI manual tag");
        }
        Ok(())
    }

    /// Removes an untagged manifest association from one repository.
    ///
    /// Signed roots and all tags must be removed through their owning workflow;
    /// this operation never deletes registry-wide immutable bytes or projections.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is tagged, retained by a signed root,
    /// absent, or on database failure.
    pub async fn delete_oci_repository_manifest(
        &self,
        repository_id: i64,
        digest: Sha256Digest,
        now: i64,
    ) -> Result<()> {
        if now <= 0 {
            bail!("OCI manifest deletion time must be positive");
        }
        let statements = vec![
            Statement::new(
                "DELETE FROM oci_repository_objects
                 WHERE repository_id = ?1 AND digest = ?2 AND object_kind = 'manifest'
                   AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.repository_id = ?1 AND tag.digest = ?2)
                   AND NOT EXISTS (SELECT 1 FROM oci_release_roots root
                     WHERE root.repository_id = ?1 AND root.index_digest = ?2)",
                vals![repository_id, digest.to_string()],
            )
            .expecting(1),
            Statement::new(
                "UPDATE oci_registry_state SET mutation_epoch = mutation_epoch + 1,
                    updated_at = ?3
                 WHERE registry_id = (SELECT registry_id FROM oci_repositories WHERE id = ?1)
                   AND NOT EXISTS (SELECT 1 FROM oci_repository_objects
                     WHERE repository_id = ?1 AND digest = ?2)",
                vals![repository_id, digest.to_string(), now],
            )
            .expecting(1),
        ];
        self.backend.checked_batch(&statements).await
    }
}
fn row_to_oci_publication(row: &Row) -> Result<OciPublicationRecord> {
    Ok(OciPublicationRecord {
        id: row.get(0)?,
        registry_id: row.get(1)?,
        repository_id: row.get(2)?,
        writer_id: row.get(3)?,
        token_id: row.get(4)?,
        target_tag: row
            .get::<Option<String>>(5)?
            .as_deref()
            .map(Tag::parse)
            .transpose()?,
        expected_tag_version: row.get(6)?,
        expected_tag_digest: row
            .get::<Option<String>>(7)?
            .map(parse_digest)
            .transpose()?,
        root_digest: parse_digest(row.get(8)?)?,
        catalog_digest: parse_digest(row.get(9)?)?,
        release_tag: row.get(10)?,
        sidecar_sha256_hex: row.get(11)?,
        confirmation_hash: parse_digest(row.get(12)?)?,
        topology_digest: parse_digest(row.get(13)?)?,
        required_placement_count: row.get(14)?,
        source_kind: row.get(15)?,
        state: row.get(16)?,
        idempotency_key: row.get(17)?,
        commit_idempotency_key: row.get(18)?,
        abort_idempotency_key: row.get(19)?,
        expires_at: row.get(20)?,
        created_at: row.get(21)?,
        committed_at: row.get(22)?,
        resource_version: row.get(23)?,
    })
}
impl Database {
    /// Atomically commits a frozen publication and exposes its complete closed
    /// repository graph and optional tag in the same transaction.
    ///
    /// Every frozen placement fence is rechecked before catalog writes begin;
    /// tag CAS, repository links/projections, tag history, mutation epoch, and
    /// the publication's `ready` transition therefore share one commit point.
    ///
    /// # Errors
    ///
    /// Returns an error for ownership/version drift, expiry, tag CAS failure,
    /// a publication/catalog identity mismatch, an incomplete or changed graph,
    /// absent placement evidence, or database failure.
    pub async fn commit_oci_publication(
        &self,
        publication_id: &str,
        writer_id: &str,
        token_id: &str,
        expected_resource_version: i64,
        idempotency_key: &str,
        confirmation_hash: Sha256Digest,
        catalog: &IndexOciRepositoryCatalog,
        now: i64,
    ) -> Result<OciPublicationRecord> {
        validate_catalog(catalog)?;
        validate_session_identity(idempotency_key, "commit idempotency key", 128)?;
        if expected_resource_version < 1 || now <= 0 || catalog.observed_at != now {
            bail!("OCI publication commit metadata is invalid");
        }
        let publication = self
            .oci_publication(publication_id, writer_id, token_id, now)
            .await?
            .context("OCI publication does not exist, is expired, or ownership changed")?;
        let repository = self
            .oci_repository(catalog.registry_id, &catalog.repository)
            .await?
            .context("OCI publication repository does not exist")?;
        if publication.registry_id != catalog.registry_id
            || publication.repository_id != repository.id
            || publication.root_digest != catalog.root_digest
            || publication.target_tag != catalog.tag
            || publication.source_kind != catalog.source_kind
        {
            bail!("OCI publication identity conflicts with its catalog");
        }
        if publication.confirmation_hash != confirmation_hash
            || oci_publication_confirmation_hash(&publication) != confirmation_hash
        {
            bail!("OCI publication confirmation hash is invalid");
        }
        if oci_catalog_declaration_digest(catalog.root_digest, &catalog.objects)?
            != publication.catalog_digest
        {
            bail!("OCI publication catalog declaration digest changed");
        }
        if publication.state == "ready" {
            if publication.commit_idempotency_key.as_deref() == Some(idempotency_key) {
                return Ok(publication);
            }
            bail!("OCI publication was committed by a different idempotency key");
        }
        if publication.state != "preparing"
            || publication.resource_version != expected_resource_version
        {
            bail!("OCI publication version or state is stale");
        }
        let object_count = i64::try_from(catalog.objects.len())
            .context("OCI publication object count exceeds int64")?;
        let expected_next_version = expected_resource_version
            .checked_add(1)
            .context("OCI publication version overflow")?;
        let mut statements = vec![Statement::new(
            "UPDATE oci_publication_sessions SET state = 'committing',
                    commit_idempotency_key = ?14,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'preparing' AND expires_at > ?4
                   AND resource_version = ?5 AND registry_id = ?6
                   AND repository_id = ?7 AND root_digest = ?8
                   AND ((target_tag IS NULL AND ?9 IS NULL) OR target_tag = ?9)
                   AND source_kind = ?10
                   AND (SELECT COUNT(*) FROM oci_publication_objects object
                     WHERE object.publication_id = oci_publication_sessions.id) = ?11
                   AND (SELECT COUNT(*) FROM oci_publication_required_placements required
                     WHERE required.publication_id = oci_publication_sessions.id) =
                       oci_publication_sessions.required_placement_count
                   AND NOT EXISTS (SELECT 1 FROM oci_publication_objects object
                     WHERE object.publication_id = oci_publication_sessions.id
                       AND (SELECT COUNT(*) FROM oci_publication_object_placements evidence
                         JOIN oci_publication_required_placements required
                           ON required.publication_id = evidence.publication_id
                          AND required.placement_id = evidence.placement_id
                         WHERE evidence.publication_id = object.publication_id
                           AND evidence.digest = object.digest) <>
                         oci_publication_sessions.required_placement_count)
                   AND NOT EXISTS (SELECT 1
                     FROM oci_publication_object_placements evidence
                     JOIN oci_publication_objects declared
                      ON declared.publication_id = evidence.publication_id
                      AND declared.digest = evidence.digest
                     JOIN oci_publication_required_placements required
                       ON required.publication_id = evidence.publication_id
                      AND required.placement_id = evidence.placement_id
                     LEFT JOIN surface_objects object
                       ON object.id = evidence.surface_object_id
                      AND object.registry_id = evidence.registry_id
                     LEFT JOIN object_placements presence
                       ON presence.surface_object_id = evidence.surface_object_id
                      AND presence.registry_id = evidence.registry_id
                      AND presence.placement_id = evidence.placement_id
                     LEFT JOIN surface_placement_effective placement
                       ON placement.id = evidence.placement_id
                      AND placement.registry_id = evidence.registry_id
                     LEFT JOIN surface_placement_observations observation
                       ON observation.placement_id = evidence.placement_id
                     LEFT JOIN surface_placement_write_capabilities capability
                       ON capability.placement_id = placement.id
                      AND capability.placement_write_spec_version = placement.write_spec_version
                     LEFT JOIN binding_write_revisions revision
                       ON revision.binding_id = capability.binding_id
                      AND revision.revision = capability.binding_write_revision
                     LEFT JOIN binding_write_observations write_observation
                       ON write_observation.binding_id = revision.binding_id
                      AND write_observation.revision = revision.revision
                     LEFT JOIN binding_credential_revisions credential
                       ON credential.binding_id = revision.binding_id
                      AND credential.purpose = revision.write_credential_purpose
                      AND credential.generation = revision.write_credential_generation
                     WHERE evidence.publication_id = oci_publication_sessions.id AND (
                       object.id IS NULL OR object.object_key <> declared.object_key
                       OR presence.surface_object_id IS NULL OR placement.id IS NULL
                       OR observation.placement_id IS NULL OR revision.binding_id IS NULL
                       OR write_observation.binding_id IS NULL OR credential.binding_id IS NULL
                       OR object.content_hash <> SUBSTR(evidence.digest, 8)
                       OR object.size <> declared.byte_size
                       OR object.lifecycle_state <> 'active'
                       OR object.resource_version <> evidence.object_resource_version
                       OR presence.state <> 'present'
                       OR presence.observed_hash <> SUBSTR(evidence.digest, 8)
                       OR presence.observed_size <> declared.byte_size
                       OR presence.etag <> evidence.observed_etag
                       OR presence.observed_at <> evidence.observed_at
                       OR presence.observed_inventory_generation <>
                          evidence.observed_inventory_generation
                       OR presence.catalog_object_resource_version <>
                          evidence.object_resource_version
                       OR placement.resource_version <>
                          evidence.placement_resource_version
                       OR placement.write_spec_version <>
                          required.placement_write_spec_version
                       OR placement.state <> 'ready'
                       OR placement.completeness <> 'complete'
                       OR placement.desired_state <> 'active'
                       OR observation.observation_version <>
                          evidence.placement_observation_version
                       OR required.placement_resource_version <>
                          evidence.placement_resource_version
                       OR required.placement_observation_version <>
                          evidence.placement_observation_version
                       OR revision.binding_id <> required.binding_id
                       OR revision.revision <> required.binding_write_revision
                       OR revision.revision_fingerprint <> required.revision_fingerprint
                       OR revision.capability_fingerprint <> required.capability_fingerprint
                       OR revision.writes_supported <> 1
                       OR write_observation.state <> 'valid'
                       OR credential.validation_state <> 'valid'
                       OR (placement.requires_conditional_writes = 1
                         AND revision.conditional_writes_supported <> 1)))
                   AND NOT EXISTS (SELECT 1 FROM surface_placement_effective placement
                     WHERE placement.registry_id = oci_publication_sessions.registry_id
                       AND placement.kind = 'complete'
                       AND placement.desired_state = 'active' AND placement.state = 'ready'
                       AND placement.completeness = 'complete'
                       AND EXISTS (SELECT 1
                         FROM surface_placement_write_capabilities capability
                         JOIN binding_write_revisions revision
                           ON revision.binding_id = capability.binding_id
                          AND revision.revision = capability.binding_write_revision
                         JOIN binding_write_observations write_observation
                           ON write_observation.binding_id = revision.binding_id
                          AND write_observation.revision = revision.revision
                         JOIN binding_credential_revisions credential
                           ON credential.binding_id = revision.binding_id
                          AND credential.purpose = revision.write_credential_purpose
                          AND credential.generation = revision.write_credential_generation
                         WHERE capability.placement_id = placement.id
                           AND capability.placement_write_spec_version = placement.write_spec_version
                           AND revision.writes_supported = 1
                           AND write_observation.state = 'valid'
                           AND credential.validation_state = 'valid'
                           AND (placement.requires_conditional_writes = 0
                             OR revision.conditional_writes_supported = 1))
                       AND NOT EXISTS (SELECT 1 FROM oci_publication_required_placements required
                         WHERE required.publication_id = oci_publication_sessions.id
                           AND required.placement_id = placement.id))
                   AND (?10 <> 'channel' OR EXISTS (SELECT 1 FROM channels channel
                     WHERE channel.registry_id = oci_publication_sessions.registry_id
                       AND channel.name = oci_publication_sessions.target_tag
                       AND channel.active = 1
                       AND channel.frontier = oci_publication_sessions.release_tag
                       AND (SELECT COUNT(*) FROM channel_partitions partition
                         WHERE partition.channel_id = channel.id) = 256
                       AND NOT EXISTS (SELECT 1 FROM channel_partitions partition
                         WHERE partition.channel_id = channel.id
                           AND partition.release <> oci_publication_sessions.release_tag)))
                   AND ((?9 IS NULL)
                     OR (?12 IS NULL AND NOT EXISTS (SELECT 1 FROM oci_tags tag
                       WHERE tag.repository_id = ?7 AND tag.name = ?9))
                     OR (?12 IS NOT NULL AND EXISTS (SELECT 1 FROM oci_tags tag
                       WHERE tag.repository_id = ?7 AND tag.name = ?9
                         AND tag.resource_version = ?12
                         AND (?13 IS NULL OR tag.digest = ?13))))",
            vals![
                publication_id,
                writer_id,
                token_id,
                now,
                expected_resource_version,
                publication.registry_id,
                publication.repository_id,
                publication.root_digest.to_string(),
                publication.target_tag.as_ref().map(Tag::as_str),
                publication.source_kind,
                object_count,
                publication.expected_tag_version,
                publication
                    .expected_tag_digest
                    .map(|digest| digest.to_string()),
                idempotency_key
            ],
        )
        .expecting(1)];
        if matches!(publication.source_kind.as_str(), "release" | "channel") {
            let release_tag = publication
                .release_tag
                .as_deref()
                .context("release publication lost its signed release tag")?;
            let sidecar_sha256_hex = publication
                .sidecar_sha256_hex
                .as_deref()
                .context("release publication lost its signed sidecar digest")?;
            statements.insert(
                0,
                Statement::new(
                    "UPDATE oci_release_roots
                     SET publication_fence = publication_fence + 1
                     WHERE registry_id = ?1 AND repository_id = ?2
                       AND release_tag = ?3 AND index_digest = ?4
                       AND catalog_digest = ?5
                       AND EXISTS (SELECT 1 FROM releases release
                         WHERE release.id = oci_release_roots.release_id
                           AND release.registry_id = oci_release_roots.registry_id
                           AND release.semver = oci_release_roots.release_tag
                           AND release.commit_oid = oci_release_roots.source_commit
                           AND release.tag_oid = oci_release_roots.verified_tag_oid
                           AND release.pack_present = 1)
                       AND EXISTS (SELECT 1 FROM oci_repositories repository
                         WHERE repository.id = oci_release_roots.repository_id
                           AND repository.registry_id = oci_release_roots.registry_id
                           AND repository.lifecycle_state = 'active')",
                    vals![
                        publication.registry_id,
                        publication.repository_id,
                        release_tag,
                        publication.root_digest.to_string(),
                        sidecar_sha256_hex
                    ],
                )
                .expecting(1),
            );
        }
        for object in &catalog.objects {
            let size = checked_u64(object.descriptor.size, "publication object size")?;
            let object_kind = if object.descriptor.media_type.is_image_manifest()
                || object.descriptor.media_type.is_image_index()
            {
                "manifest"
            } else {
                "blob"
            };
            let projection_json = object
                .projection
                .as_ref()
                .map(|projection| match projection {
                    OciCatalogProjection::Manifest { document, platform } => {
                        aos_oci_types::to_canonical_json(&FrozenManifestProjection {
                            document: document.clone(),
                            platform: platform.clone(),
                        })
                    }
                    OciCatalogProjection::Index(index) => aos_oci_types::to_canonical_json(index),
                })
                .transpose()?
                .map(String::from_utf8)
                .transpose()
                .context("canonical OCI publication projection is not UTF-8")?;
            statements.push(
                Statement::new(
                    "UPDATE oci_publication_sessions SET resource_version = resource_version
                     WHERE id = ?1 AND state = 'committing' AND resource_version = ?2
                       AND EXISTS (SELECT 1 FROM oci_publication_objects object
                         JOIN oci_publication_object_placements evidence
                           ON evidence.publication_id = object.publication_id
                          AND evidence.digest = object.digest
                         WHERE object.publication_id = oci_publication_sessions.id
                           AND object.digest = ?3 AND object.media_type = ?4
                           AND object.byte_size = ?5 AND object.object_kind = ?6
                           AND object.object_key = ?7
                           AND ((object.projection_json IS NULL AND ?9 IS NULL)
                             OR object.projection_json = ?9)
                           AND evidence.placement_id = ?8)",
                    vals![
                        publication_id,
                        expected_next_version,
                        object.descriptor.digest.to_string(),
                        object.descriptor.media_type.as_str(),
                        size,
                        object_kind,
                        oci_blob_object_key(object.descriptor.digest),
                        catalog.placement_id,
                        projection_json
                    ],
                )
                .expecting(1),
            );
        }
        statements.extend(build_oci_catalog_statements(catalog)?);
        statements.push(
            Statement::new(
                "UPDATE oci_publication_sessions SET state = 'ready', committed_at = ?4,
                    resource_version = resource_version + 1
                 WHERE id = ?1 AND writer_id = ?2 AND token_id = ?3
                   AND state = 'committing' AND resource_version = ?5
                   AND EXISTS (SELECT 1 FROM oci_repository_objects link
                     WHERE link.repository_id = oci_publication_sessions.repository_id
                       AND link.digest = oci_publication_sessions.root_digest
                       AND link.object_kind = 'manifest')
                   AND (target_tag IS NULL OR EXISTS (SELECT 1 FROM oci_tags tag
                     WHERE tag.repository_id = oci_publication_sessions.repository_id
                       AND tag.name = oci_publication_sessions.target_tag
                       AND tag.digest = oci_publication_sessions.root_digest
                       AND tag.source_kind = oci_publication_sessions.source_kind))",
                vals![
                    publication_id,
                    writer_id,
                    token_id,
                    now,
                    expected_next_version
                ],
            )
            .expecting(1),
        );
        self.backend
            .checked_batch(&statements)
            .await
            .context("committing OCI publication")?;
        self.oci_publication(publication_id, writer_id, token_id, now)
            .await?
            .context("committed OCI publication disappeared")
    }
}
