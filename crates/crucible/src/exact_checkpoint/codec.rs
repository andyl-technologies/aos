//! Canonical v9 checkpoint envelope, manifest, and shape verification.

use super::*;

pub(super) fn authenticate_repository_manifest(
    repository: &ExactCheckpointRepositoryBinding,
    closure: &ExactCheckpointClosureRecord,
    production_identity: ContentHash,
    manifest_bytes: &[u8],
) -> Result<(), ExactCheckpointRelationError> {
    let manifest_id = ContentId::for_bytes(
        ObjectKind::DeviceState,
        MANIFEST_SCHEMA_VERSION,
        manifest_bytes,
    );
    let inventory_matches = closure.objects.len() == repository.objects.len()
        && closure
            .objects
            .iter()
            .zip(&repository.objects)
            .all(|(closure, repository)| {
                (closure.identity, closure.length) == (repository.identity, repository.length)
            });
    if repository.production_identity != production_identity
        || repository.scenario != closure.scenario
        || repository.configuration != closure.configuration
        || repository.manifest_id != manifest_id
        || repository.manifest_bytes != u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX)
        || !inventory_matches
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct RepositoryRootBody {
    pub(super) production_identity: ContentHash,
    pub(super) scenario: ContentHash,
    pub(super) configuration: ContentHash,
    pub(super) manifest_bytes: u64,
    pub(super) object_count: u64,
    pub(super) object_bytes: u64,
    pub(super) index_count: u32,
}

pub(super) struct RepositoryRootChildren {
    pub(super) manifest: ContentId,
    pub(super) indexes: Vec<ContentId>,
}

pub(super) fn decode_root_body(
    bytes: &[u8],
) -> Result<RepositoryRootBody, ExactCheckpointRelationError> {
    if bytes.len() != ROOT_BODY_BYTES {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let hash = |range: std::ops::Range<usize>| {
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes[range]);
        ContentHash { bytes: value }
    };
    Ok(RepositoryRootBody {
        production_identity: hash(0..32),
        scenario: hash(32..64),
        configuration: hash(64..96),
        manifest_bytes: decode_u64(&bytes[96..104])?,
        object_count: decode_u64(&bytes[104..112])?,
        object_bytes: decode_u64(&bytes[112..120])?,
        index_count: u32::from_be_bytes(
            bytes[120..124]
                .try_into()
                .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?,
        ),
    })
}

pub(super) fn decode_root_children(
    envelope: &ContentEnvelope,
    index_count: u32,
) -> Result<RepositoryRootChildren, ExactCheckpointRelationError> {
    let count = usize::try_from(index_count)
        .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
    if !matches!(envelope.children().len(), length if length == count.saturating_add(1) || length == count.saturating_add(3))
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let mut manifest = None;
    let mut promotion_source = None;
    let mut promotion_evidence = None;
    let mut indexes = vec![None; count];
    for child in envelope.children() {
        match child.role() {
            MANIFEST_ROLE => {
                if child.id().kind() != ObjectKind::DeviceState
                    || child.id().schema_version() != MANIFEST_SCHEMA_VERSION
                    || manifest.replace(child.id()).is_some()
                {
                    return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
                }
            }
            PROMOTION_SOURCE_ROLE => {
                if ExactCheckpointId::try_from(child.id()).is_err()
                    || promotion_source.replace(child.id()).is_some()
                {
                    return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
                }
            }
            PROMOTION_EVIDENCE_ROLE => {
                if child.id().kind() != ObjectKind::Observation
                    || child.id().schema_version() != PROMOTION_EVIDENCE_SCHEMA_VERSION
                    || promotion_evidence.replace(child.id()).is_some()
                {
                    return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
                }
            }
            role => {
                let suffix = role
                    .strip_prefix(INDEX_ROLE_PREFIX)
                    .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?;
                let index = usize::from_str_radix(suffix, 16)
                    .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
                if suffix.len() != 8
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    || index >= indexes.len()
                    || index_role(index).as_deref() != Some(role)
                    || indexes[index].replace(child.id()).is_some()
                    || child.id().kind() != ObjectKind::ExactManifest
                    || child.id().schema_version() != INDEX_SCHEMA_VERSION
                {
                    return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
                }
            }
        }
    }
    if promotion_source.is_some() != promotion_evidence.is_some() {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    Ok(RepositoryRootChildren {
        manifest: manifest.ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?,
        indexes: indexes
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?,
    })
}

pub(super) fn decode_index_page(
    envelope: &ContentEnvelope,
) -> Result<Vec<(ContentHash, ContentId, u64)>, ExactCheckpointRelationError> {
    let bytes = envelope.body();
    if bytes.len() < 12 || bytes.get(..8) != Some(INDEX_MAGIC) {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let count = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?,
    ) as usize;
    let expected = 12_usize
        .checked_add(
            count
                .checked_mul(40)
                .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?,
        )
        .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?;
    if count == 0
        || count > INDEX_PAGE_OBJECTS
        || bytes.len() != expected
        || envelope.children().len() != count
    {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| ExactCheckpointRelationError::RepositoryRootMismatch)?;
    let mut children = envelope.children().iter();
    let mut previous = None;
    let (records, remainder) = bytes[12..].as_chunks::<40>();
    if !remainder.is_empty() {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    for record in records {
        let mut identity_bytes = [0_u8; 32];
        identity_bytes.copy_from_slice(&record[..32]);
        let identity = ContentHash {
            bytes: identity_bytes,
        };
        let length = decode_u64(&record[32..40])?;
        let child = children
            .next()
            .ok_or(ExactCheckpointRelationError::RepositoryRootMismatch)?;
        if previous.is_some_and(|prior| prior >= identity)
            || child.role() != object_role(identity)
            || child.id().kind() != ObjectKind::DeviceState
            || child.id().schema_version() != OBJECT_SCHEMA_VERSION
        {
            return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
        }
        previous = Some(identity);
        result.push((identity, child.id(), length));
    }
    if children.next().is_some() {
        return Err(ExactCheckpointRelationError::RepositoryRootMismatch);
    }
    Ok(result)
}

fn decode_u64(bytes: &[u8]) -> Result<u64, ExactCheckpointRelationError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        ExactCheckpointRelationError::RepositoryRootMismatch
    })?))
}

pub(super) fn index_role(index: usize) -> Option<String> {
    u32::try_from(index)
        .ok()
        .map(|index| format!("{INDEX_ROLE_PREFIX}{index:08x}"))
}

pub(super) fn object_role(identity: ContentHash) -> String {
    format!("{OBJECT_ROLE_PREFIX}{}", identity.to_hex())
}

pub(super) fn exact_checkpoint_closure_identity(
    closure: &mut ExactCheckpointClosureRecord,
) -> Result<ContentHash, ExactCheckpointRelationError> {
    let claimed_identity = closure.identity;
    closure.identity = ContentHash::default();
    let encoded_length = exact_checkpoint_closure_encoded_length(closure)?;
    let encoded = exact_checkpoint_closure_bytes(closure, encoded_length);
    closure.identity = claimed_identity;
    let bytes = encoded?;
    Ok(ContentHash::from_canonical_hex_bytes(
        CLOSURE_DOMAIN,
        &bytes,
    ))
}

pub(super) fn exact_checkpoint_closure_bytes(
    closure: &ExactCheckpointClosureRecord,
    encoded_length: usize,
) -> Result<Vec<u8>, ExactCheckpointRelationError> {
    let maximum = MANIFEST_MAGIC
        .len()
        .checked_add(MAX_EXACT_CHECKPOINT_MANIFEST_BYTES)
        .ok_or(ExactCheckpointRelationError::ManifestTooLarge)?;
    if encoded_length > maximum || encoded_length < MANIFEST_MAGIC.len() {
        return Err(ExactCheckpointRelationError::ManifestTooLarge);
    }
    let mut writer = BoundedManifestWriter::new(encoded_length)?;
    if ciborium::ser::into_writer(closure, &mut writer).is_err() {
        return Err(if writer.resource_exhausted {
            ExactCheckpointRelationError::ResourceExhausted
        } else {
            ExactCheckpointRelationError::CanonicalEncoding
        });
    }
    if writer.bytes.len() != encoded_length {
        return Err(ExactCheckpointRelationError::CanonicalEncoding);
    }
    Ok(writer.bytes)
}

struct BoundedManifestWriter {
    bytes: Vec<u8>,
    limit: usize,
    resource_exhausted: bool,
}

impl BoundedManifestWriter {
    fn new(limit: usize) -> Result<Self, ExactCheckpointRelationError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limit)
            .map_err(|_| ExactCheckpointRelationError::ResourceExhausted)?;
        bytes.extend_from_slice(MANIFEST_MAGIC);
        Ok(Self {
            bytes,
            limit,
            resource_exhausted: false,
        })
    }
}

impl std::io::Write for BoundedManifestWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(total) = self.bytes.len().checked_add(bytes.len()) else {
            self.resource_exhausted = true;
            return Err(std::io::Error::other("exact-checkpoint manifest overflow"));
        };
        if total > self.limit {
            self.resource_exhausted = true;
            return Err(std::io::Error::other(
                "exact-checkpoint manifest allocation refused",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn exact_checkpoint_closure_encoded_length(
    closure: &ExactCheckpointClosureRecord,
) -> Result<usize, ExactCheckpointRelationError> {
    let mut counter = ManifestLengthWriter {
        length: MANIFEST_MAGIC.len(),
    };
    ciborium::ser::into_writer(closure, &mut counter)
        .map_err(|_| ExactCheckpointRelationError::CanonicalEncoding)?;
    Ok(counter.length)
}

#[cfg(test)]
pub(super) fn exact_checkpoint_closure_test_bytes(
    closure: &ExactCheckpointClosureRecord,
) -> Result<Vec<u8>, ExactCheckpointRelationError> {
    let encoded_length = exact_checkpoint_closure_encoded_length(closure)?;
    exact_checkpoint_closure_bytes(closure, encoded_length)
}

#[cfg(test)]
pub(super) fn assign_exact_checkpoint_closure_identity(
    closure: &mut ExactCheckpointClosureRecord,
) -> Result<(), ExactCheckpointRelationError> {
    closure.identity = exact_checkpoint_closure_identity(closure)?;
    Ok(())
}

struct ManifestLengthWriter {
    length: usize,
}

impl std::io::Write for ManifestLengthWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .filter(|length| *length <= MANIFEST_MAGIC.len() + MAX_EXACT_CHECKPOINT_MANIFEST_BYTES)
            .ok_or_else(|| std::io::Error::other("exact-checkpoint manifest overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn exact_checkpoint_target_manifest_identity(
    configuration: ContentHash,
    fault_checkpoint: ContentHash,
    target: &ExactCheckpointTargetRecord,
) -> ContentHash {
    let base = ContentHash::from_canonical_material(
        TARGET_DOMAIN,
        &format!(
            "configuration={}\nimmutable_backing={}\nnode={}\ncounter={}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\ndevice_state={}",
            configuration.to_hex(),
            target.immutable_backing.to_hex(),
            target.node,
            target.counter,
            target.scheduler_time,
            target.snapshot.to_hex(),
            fault_checkpoint.to_hex(),
            target.overlay.identity.to_hex(),
            target.exact_ram.device.identity.to_hex(),
        ),
    );
    let mut material = format!(
        "target={}\nparent_closure={}\ndevice_sha256={}",
        base.to_hex(),
        target
            .exact_ram
            .parent_closure
            .map_or_else(String::new, ContentHash::to_hex),
        target.exact_ram.device_content_sha256.to_hex(),
    );
    for (index, layer) in target.exact_ram.layers.iter().enumerate() {
        let parent = layer.parent.map_or_else(String::new, |identity| {
            format!(
                "{}/{}/{}",
                identity.checkpoint.to_hex(),
                identity.target.to_hex(),
                identity.frontier.to_hex(),
            )
        });
        let _ = write!(
            material,
            "\nlayer.{index}.kind={}\nlayer.{index}.checkpoint={}\nlayer.{index}.target={}\nlayer.{index}.frontier={}\nlayer.{index}.parent={}\nlayer.{index}.topology={}\nlayer.{index}.regions={}\nlayer.{index}.records={}\nlayer.{index}.sha256={}\nlayer.{index}.artifact={}\nlayer.{index}.length={}",
            match layer.kind {
                ExactCheckpointRamKind::Direct => "direct",
                ExactCheckpointRamKind::Delta => "delta",
            },
            layer.identity.checkpoint.to_hex(),
            layer.identity.target.to_hex(),
            layer.identity.frontier.to_hex(),
            parent,
            layer.topology.to_hex(),
            layer.ram_regions,
            layer.ram_records,
            layer.content_sha256.to_hex(),
            layer.artifact.identity.to_hex(),
            layer.artifact.length,
        );
    }
    ContentHash::from_canonical_material(RAM_TARGET_DOMAIN, &material)
}

pub(super) fn validate_closure_structure(
    closure: &ExactCheckpointClosureRecord,
) -> Result<(), ExactCheckpointRelationError> {
    if !strictly_sorted(&closure.signal_artifacts)
        || closure
            .event_log_segments
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != closure.event_log_segments.len()
        || !closure
            .targets
            .windows(2)
            .all(|pair| pair[0].node < pair[1].node)
        || !closure
            .failed_host_io
            .windows(2)
            .all(|pair| pair[0].node < pair[1].node)
        || !closure
            .node_generations
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || !closure
            .node_service_states
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
        || closure.targets.iter().any(|target| target.node.is_empty())
        || closure
            .failed_host_io
            .iter()
            .any(|failed| failed.node.is_empty())
        || closure
            .node_generations
            .iter()
            .any(|(node, generation)| node.is_empty() || *generation == 0)
        || closure
            .node_service_states
            .iter()
            .any(|(node, state)| node.is_empty() || !matches!(state, 1..=3))
        || !closure
            .objects
            .windows(2)
            .all(|pair| pair[0].identity < pair[1].identity)
        || closure.objects.iter().any(|object| object.length == 0)
        || manifest_object_identities(closure)
            != closure
                .objects
                .iter()
                .map(|object| object.identity)
                .collect()
    {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    for target in &closure.targets {
        if target.overlay.length == 0 {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }
        validate_sparse_artifact(&target.overlay)?;
        validate_artifact_object_lengths(&target.overlay, &closure.objects)?;
        validate_exact_ram(&target.exact_ram)?;
        validate_artifact_object_lengths(&target.exact_ram.device, &closure.objects)?;
        for layer in &target.exact_ram.layers {
            validate_artifact_object_lengths(&layer.artifact, &closure.objects)?;
        }
    }
    Ok(())
}

pub(super) fn manifest_object_identities(
    closure: &ExactCheckpointClosureRecord,
) -> std::collections::BTreeSet<ContentHash> {
    let mut identities = std::collections::BTreeSet::from([
        closure.schedule,
        closure.scheduler,
        closure.trigger_state,
        closure.assertion_state,
        closure.lifecycle_state,
        closure.fault_checkpoint,
    ]);
    identities.extend(closure.event_log_segments.iter().copied());
    identities.extend(closure.signal_artifacts.iter().copied());
    identities.extend(
        closure
            .failed_host_io
            .iter()
            .map(|failed| failed.checkpoint),
    );
    for target in &closure.targets {
        identities.insert(target.snapshot);
        identities.extend(artifact_object_identities(&target.overlay));
        identities.extend(artifact_object_identities(&target.exact_ram.device));
        for layer in &target.exact_ram.layers {
            identities.extend(artifact_object_identities(&layer.artifact));
        }
    }
    identities
}

fn artifact_object_identities(
    artifact: &ExactCheckpointArtifactRecord,
) -> impl Iterator<Item = ContentHash> + '_ {
    artifact.chunks.iter().copied().chain(
        artifact
            .extents
            .iter()
            .flat_map(|extent| extent.chunks.iter().copied()),
    )
}

pub(super) fn validate_artifact_object_lengths(
    artifact: &ExactCheckpointArtifactRecord,
    objects: &[ExactCheckpointObjectRecord],
) -> Result<(), ExactCheckpointRelationError> {
    if artifact.sparse {
        for extent in &artifact.extents {
            for (offset, identity) in extent.chunks.iter().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
                let logical_chunk = extent
                    .start_chunk
                    .checked_add(offset)
                    .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
                require_artifact_object_length(
                    objects,
                    *identity,
                    logical_artifact_chunk_length(artifact.length, logical_chunk)?,
                )?;
            }
        }
    } else {
        for (logical_chunk, identity) in artifact.chunks.iter().enumerate() {
            let logical_chunk = u64::try_from(logical_chunk)
                .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
            require_artifact_object_length(
                objects,
                *identity,
                logical_artifact_chunk_length(artifact.length, logical_chunk)?,
            )?;
        }
    }

    Ok(())
}

fn require_artifact_object_length(
    objects: &[ExactCheckpointObjectRecord],
    identity: ContentHash,
    expected: u64,
) -> Result<(), ExactCheckpointRelationError> {
    let index = objects
        .binary_search_by_key(&identity, |object| object.identity)
        .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
    if objects[index].length != expected {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }

    Ok(())
}

fn logical_artifact_chunk_length(
    artifact_length: u64,
    logical_chunk: u64,
) -> Result<u64, ExactCheckpointRelationError> {
    let offset = logical_chunk
        .checked_mul(ARTIFACT_CHUNK_BYTES)
        .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
    let remaining = artifact_length
        .checked_sub(offset)
        .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
    let length = remaining.min(ARTIFACT_CHUNK_BYTES);
    if length == 0 {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }

    Ok(length)
}

fn validate_exact_ram(
    checkpoint: &ExactCheckpointRamRecord,
) -> Result<(), ExactCheckpointRelationError> {
    let Some(first) = checkpoint.layers.first() else {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    };
    if checkpoint.layers.len() > MAX_EXACT_CHECKPOINT_RAM_LAYERS
        || first.kind != ExactCheckpointRamKind::Direct
        || first.parent.is_some()
        || (checkpoint.layers.len() > 1) != checkpoint.parent_closure.is_some()
    {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    if checkpoint.device.length == 0 {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    validate_dense_artifact(&checkpoint.device)?;
    for (index, layer) in checkpoint.layers.iter().enumerate() {
        validate_dense_artifact(&layer.artifact)?;
        if layer.ram_regions == 0 || layer.artifact.length == 0 || layer.topology != first.topology
        {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }
        if index > 0 {
            let parent = &checkpoint.layers[index - 1];
            if layer.kind != ExactCheckpointRamKind::Delta || layer.parent != Some(parent.identity)
            {
                return Err(ExactCheckpointRelationError::InvalidStructure);
            }
        }
    }
    Ok(())
}

fn validate_dense_artifact(
    artifact: &ExactCheckpointArtifactRecord,
) -> Result<(), ExactCheckpointRelationError> {
    if artifact.sparse || !artifact.extents.is_empty() {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    let chunks = u64::try_from(artifact.chunks.len())
        .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
    let minimum = chunks
        .saturating_sub(1)
        .checked_mul(ARTIFACT_CHUNK_BYTES)
        .and_then(|bytes| bytes.checked_add(u64::from(chunks != 0)))
        .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
    let maximum = chunks
        .checked_mul(ARTIFACT_CHUNK_BYTES)
        .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
    if artifact.length < minimum || artifact.length > maximum {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    Ok(())
}

fn validate_sparse_artifact(
    artifact: &ExactCheckpointArtifactRecord,
) -> Result<(), ExactCheckpointRelationError> {
    if !artifact.sparse || !artifact.chunks.is_empty() {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    let logical_chunks = artifact.length.div_ceil(ARTIFACT_CHUNK_BYTES);
    let mut prior_end = 0_u64;
    for (index, extent) in artifact.extents.iter().enumerate() {
        let count = u64::try_from(extent.chunks.len())
            .map_err(|_| ExactCheckpointRelationError::InvalidStructure)?;
        let end = extent
            .start_chunk
            .checked_add(count)
            .ok_or(ExactCheckpointRelationError::InvalidStructure)?;
        if count == 0
            || extent.start_chunk >= logical_chunks
            || end > logical_chunks
            || (index != 0 && extent.start_chunk <= prior_end)
        {
            return Err(ExactCheckpointRelationError::InvalidStructure);
        }
        prior_end = end;
    }
    let mut material = Vec::new();
    ciborium::ser::into_writer(
        &SparseArtifactIdentityMaterial {
            length: artifact.length,
            extents: &artifact.extents,
        },
        &mut material,
    )
    .map_err(|_| ExactCheckpointRelationError::CanonicalEncoding)?;
    let identity = ContentHash::from_canonical_hex_bytes(SPARSE_ARTIFACT_DOMAIN, &material);
    if artifact.identity != identity {
        return Err(ExactCheckpointRelationError::InvalidStructure);
    }
    Ok(())
}

#[derive(Serialize)]
pub(super) struct SparseArtifactIdentityMaterial<'a> {
    pub(super) length: u64,
    pub(super) extents: &'a [ExactCheckpointArtifactExtent],
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(super) const fn is_false(value: &bool) -> bool {
    !*value
}
