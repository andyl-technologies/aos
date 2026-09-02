//! Canonical sparse-overlay capture, authentication, and reconstruction.

use super::*;
use std::os::unix::fs::FileExt;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactExtent {
    pub(super) start_chunk: u64,
    #[serde(deserialize_with = "decode::deserialize_vec")]
    pub(super) chunks: Vec<ContentHash>,
}

impl ArtifactExtent {
    pub(super) fn end_chunk(&self) -> Option<u64> {
        self.start_chunk
            .checked_add(u64::try_from(self.chunks.len()).ok()?)
    }
}

#[derive(serde::Serialize)]
struct SparseArtifactIdentityMaterial<'a> {
    length: u64,
    extents: &'a [ArtifactExtent],
}

/// Stages only allocated, nonzero logical chunks from one paused overlay.
///
/// The filesystem must support `SEEK_DATA`/`SEEK_HOLE`; failing closed keeps
/// capture work proportional to changed state instead of silently scanning the
/// complete virtual disk. Omitted chunks have the canonical meaning of zeroes.
pub(crate) fn stage_sparse_checkpoint_artifact_chunks_with_boundary(
    source: &Path,
    object_directory: &Path,
    role: &str,
    current_artifact_bytes: u64,
    resource_limits: FaultResourceLimits,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    boundary()?;
    let source_file = File::open(source).map_err(|error| {
        store_error(format!(
            "open stopped sparse exact-checkpoint {role} {}: {error}",
            source.display()
        ))
    })?;
    let source_length = source_file
        .metadata()
        .map_err(|error| {
            store_error(format!(
                "inspect stopped sparse exact-checkpoint {role} {}: {error}",
                source.display()
            ))
        })?
        .len();
    resource_limits
        .reserve(
            "fat_checkpoint_bytes",
            current_artifact_bytes,
            source_length,
        )
        .map_err(scheduler_resource_limit)?;

    boundary()?;
    fs::create_dir_all(object_directory).map_err(|error| {
        store_error(format!(
            "create staged sparse exact-checkpoint {role} chunk directory {}: {error}",
            object_directory.display()
        ))
    })?;

    let logical_chunks = source_length.div_ceil(ARTIFACT_CHUNK_BYTES_U64);
    let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
    let mut extents = Vec::<ArtifactExtent>::new();
    let mut cursor = 0_u64;
    let mut prior_chunk = None;
    while cursor < source_length {
        boundary()?;
        let data = match rustix::fs::seek(&source_file, rustix::fs::SeekFrom::Data(cursor)) {
            Ok(data) => data,
            Err(rustix::io::Errno::NXIO) => break,
            Err(error) => {
                return Err(store_error(format!(
                    "discover stopped sparse exact-checkpoint {role} data extents: {error}"
                )));
            }
        };
        if data >= source_length {
            break;
        }
        let hole =
            rustix::fs::seek(&source_file, rustix::fs::SeekFrom::Hole(data)).map_err(|error| {
                store_error(format!(
                    "discover stopped sparse exact-checkpoint {role} hole extents: {error}"
                ))
            })?;
        if hole <= data {
            return Err(store_error(format!(
                "stopped sparse exact-checkpoint {role} returned a non-advancing extent"
            )));
        }

        let first_chunk = data / ARTIFACT_CHUNK_BYTES_U64;
        let end_chunk = hole.min(source_length).div_ceil(ARTIFACT_CHUNK_BYTES_U64);
        for chunk_index in first_chunk..end_chunk {
            if prior_chunk == Some(chunk_index) {
                continue;
            }
            boundary()?;
            let offset = chunk_index
                .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
                .ok_or_else(|| store_error("sparse checkpoint chunk offset overflow"))?;
            let chunk_length =
                usize::try_from(ARTIFACT_CHUNK_BYTES_U64.min(source_length.saturating_sub(offset)))
                    .map_err(|error| {
                        store_error(format!("convert sparse chunk length: {error}"))
                    })?;
            source_file
                .read_exact_at(&mut buffer[..chunk_length], offset)
                .map_err(|error| {
                    store_error(format!(
                        "read stopped sparse exact-checkpoint {role} chunk {chunk_index}: {error}"
                    ))
                })?;
            prior_chunk = Some(chunk_index);
            if buffer[..chunk_length].iter().all(|byte| *byte == 0) {
                continue;
            }

            let identity = hash_bytes_with_boundary(&buffer[..chunk_length], boundary)?;
            persist_object_with_boundary(
                object_directory,
                identity,
                &buffer[..chunk_length],
                boundary,
            )?;
            match extents.last_mut() {
                Some(extent) if extent.end_chunk() == Some(chunk_index) => {
                    extent.chunks.push(identity);
                }
                _ => extents.push(ArtifactExtent {
                    start_chunk: chunk_index,
                    chunks: vec![identity],
                }),
            }
        }
        cursor = hole.min(source_length);
    }
    if extents
        .last()
        .and_then(ArtifactExtent::end_chunk)
        .is_some_and(|end| end > logical_chunks)
    {
        return Err(store_error(
            "stopped sparse exact-checkpoint extent exceeds its logical length",
        ));
    }
    let observed_length = source_file
        .metadata()
        .map_err(|error| store_error(format!("reinspect sparse checkpoint artifact: {error}")))?
        .len();
    if observed_length != source_length {
        return Err(store_error(format!(
            "stopped exact-checkpoint {role} changed length while it was staged"
        )));
    }
    let identity = sparse_artifact_identity(source_length, &extents)?;
    sync_directory(object_directory)?;

    Ok(ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::ChunkStore(object_directory.to_path_buf()),
        identity,
        length: source_length,
        chunks: Vec::new(),
        sparse: true,
        extents,
    })
}

pub(super) fn sparse_artifact_identity(
    length: u64,
    extents: &[ArtifactExtent],
) -> Result<ContentHash, SchedulerError> {
    let mut material = Vec::new();
    ciborium::ser::into_writer(
        &SparseArtifactIdentityMaterial { length, extents },
        &mut material,
    )
    .map_err(|_| store_error("encode sparse exact-checkpoint artifact identity"))?;
    if material.len() > MAX_MANIFEST_BYTES {
        return Err(store_error(
            "sparse exact-checkpoint artifact identity exceeds its size limit",
        ));
    }
    Ok(ContentHash::from_canonical_hex_bytes(
        "crucible.production-exact-sparse-artifact.v1",
        &material,
    ))
}

// crucible-lint: allow stringly-error -- the private shape validator returns bounded diagnostics that its typed lifecycle or store boundary immediately wraps.
pub(super) fn validate_sparse_artifact_shape(artifact: &ArtifactManifest) -> Result<(), String> {
    if !artifact.sparse || !artifact.chunks.is_empty() {
        return Err(String::from(
            "sparse checkpoint artifact also names dense chunks",
        ));
    }
    let logical_chunks = artifact.length.div_ceil(ARTIFACT_CHUNK_BYTES_U64);
    let mut prior_end = 0_u64;
    for (index, extent) in artifact.extents.iter().enumerate() {
        let end = extent
            .end_chunk()
            .ok_or_else(|| String::from("sparse artifact extent geometry overflows"))?;
        if extent.chunks.is_empty()
            || extent.start_chunk >= logical_chunks
            || end > logical_chunks
            || (index != 0 && extent.start_chunk <= prior_end)
        {
            return Err(String::from(
                "closure manifest contains invalid sparse artifact geometry",
            ));
        }
        prior_end = end;
    }
    Ok(())
}

pub(super) fn validate_sparse_artifact_manifest(
    directory: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), LifecycleApiError> {
    validate_sparse_artifact_shape(manifest).map_err(loop_factory_error)?;
    for extent in &manifest.extents {
        for (offset, identity) in extent.chunks.iter().enumerate() {
            let offset = u64::try_from(offset)
                .map_err(|_| loop_factory_error("sparse artifact chunk index overflow"))?;
            let chunk_index = extent
                .start_chunk
                .checked_add(offset)
                .ok_or_else(|| loop_factory_error("sparse artifact chunk index overflow"))?;
            validate_sparse_chunk(directory, manifest.length, chunk_index, *identity)?;
        }
    }
    let observed = sparse_artifact_identity(manifest.length, &manifest.extents)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    if observed != manifest.identity {
        return Err(loop_factory_error(
            "sparse checkpoint artifact failed manifest authentication",
        ));
    }
    Ok(())
}

pub(super) fn validate_sparse_artifact_manifest_with_scheduler_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_sparse_artifact_shape(manifest).map_err(store_error)?;
    for extent in &manifest.extents {
        for (offset, identity) in extent.chunks.iter().enumerate() {
            boundary()?;
            let offset = u64::try_from(offset)
                .map_err(|error| store_error(format!("convert sparse chunk index: {error}")))?;
            let chunk_index = extent
                .start_chunk
                .checked_add(offset)
                .ok_or_else(|| store_error("sparse artifact chunk index overflow"))?;
            validate_sparse_chunk(directory, manifest.length, chunk_index, *identity)
                .map_err(|error| store_error(error.to_string()))?;
        }
    }
    boundary()?;
    if sparse_artifact_identity(manifest.length, &manifest.extents)? != manifest.identity {
        return Err(store_error(
            "sparse checkpoint artifact failed manifest authentication",
        ));
    }
    Ok(())
}

pub(super) fn validate_sparse_artifact_manifest_with_lifecycle_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    validate_sparse_artifact_shape(manifest).map_err(loop_factory_error)?;
    for extent in &manifest.extents {
        for (offset, identity) in extent.chunks.iter().enumerate() {
            boundary()?;
            let offset = u64::try_from(offset)
                .map_err(|_| loop_factory_error("sparse artifact chunk index overflow"))?;
            let chunk_index = extent
                .start_chunk
                .checked_add(offset)
                .ok_or_else(|| loop_factory_error("sparse artifact chunk index overflow"))?;
            validate_sparse_chunk_geometry(directory, manifest.length, chunk_index, *identity)?;
            validate_file_hash_with_lifecycle_boundary(
                &object_path(directory, *identity),
                *identity,
                boundary,
            )?;
        }
    }
    boundary()?;
    let observed = sparse_artifact_identity(manifest.length, &manifest.extents)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    if observed != manifest.identity {
        return Err(loop_factory_error(
            "sparse checkpoint artifact failed manifest authentication",
        ));
    }
    Ok(())
}

fn validate_sparse_chunk(
    directory: &Path,
    artifact_length: u64,
    chunk_index: u64,
    identity: ContentHash,
) -> Result<(), LifecycleApiError> {
    validate_sparse_chunk_geometry(directory, artifact_length, chunk_index, identity)?;
    let path = object_path(directory, identity);
    validate_file_hash(&path, identity).map_err(|error| loop_factory_error(error.to_string()))
}

fn validate_sparse_chunk_geometry(
    directory: &Path,
    artifact_length: u64,
    chunk_index: u64,
    identity: ContentHash,
) -> Result<(), LifecycleApiError> {
    let path = object_path(directory, identity);
    let offset = chunk_index
        .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
        .ok_or_else(|| loop_factory_error("sparse artifact chunk offset overflow"))?;
    let expected_length = ARTIFACT_CHUNK_BYTES_U64.min(artifact_length.saturating_sub(offset));
    let observed_length = fs::metadata(&path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect sparse checkpoint chunk {}: {error}",
                path.display()
            ))
        })?
        .len();
    if expected_length == 0 || observed_length != expected_length {
        return Err(loop_factory_error(
            "sparse checkpoint artifact has invalid chunk geometry",
        ));
    }
    Ok(())
}

pub(super) fn materialize_sparse_checkpoint_artifact(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
    destination: &mut File,
) -> Result<(), LifecycleApiError> {
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    validate_sparse_artifact_manifest(directory, &manifest)?;
    for extent in &artifact.extents {
        for (index, identity) in extent.chunks.iter().enumerate() {
            let index = u64::try_from(index)
                .map_err(|_| loop_factory_error("sparse artifact chunk index overflow"))?;
            let chunk_index = extent
                .start_chunk
                .checked_add(index)
                .ok_or_else(|| loop_factory_error("sparse artifact chunk index overflow"))?;
            let offset = chunk_index
                .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
                .ok_or_else(|| loop_factory_error("sparse artifact chunk offset overflow"))?;
            destination.seek(SeekFrom::Start(offset)).map_err(|error| {
                loop_factory_error(format!("seek sparse checkpoint destination: {error}"))
            })?;
            let mut source = File::open(object_path(directory, *identity)).map_err(|error| {
                loop_factory_error(format!("open sparse checkpoint chunk: {error}"))
            })?;
            std::io::copy(&mut source, destination).map_err(|error| {
                loop_factory_error(format!("write sparse checkpoint chunk: {error}"))
            })?;
        }
    }
    destination
        .set_len(artifact.length)
        .map_err(|error| loop_factory_error(format!("size sparse checkpoint destination: {error}")))
}

pub(super) fn stream_sparse_artifact_bytes(
    directory: &Path,
    manifest: &ArtifactManifest,
    destination: &mut impl Write,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let mut logical_chunk = 0_u64;
    let zeroes = vec![0_u8; ARTIFACT_CHUNK_BYTES];
    for extent in &manifest.extents {
        while logical_chunk < extent.start_chunk {
            boundary()?;
            let offset = logical_chunk
                .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
                .ok_or_else(|| loop_factory_error("sparse artifact chunk offset overflow"))?;
            let length = usize::try_from(
                ARTIFACT_CHUNK_BYTES_U64.min(manifest.length.saturating_sub(offset)),
            )
            .map_err(|_| loop_factory_error("sparse artifact chunk length overflow"))?;
            destination.write_all(&zeroes[..length]).map_err(|error| {
                loop_factory_error(format!("write sparse checkpoint hole: {error}"))
            })?;
            logical_chunk = logical_chunk.saturating_add(1);
        }
        for identity in &extent.chunks {
            boundary()?;
            let mut source = File::open(object_path(directory, *identity)).map_err(|error| {
                loop_factory_error(format!("open sparse checkpoint chunk: {error}"))
            })?;
            std::io::copy(&mut source, destination).map_err(|error| {
                loop_factory_error(format!("stream sparse checkpoint chunk: {error}"))
            })?;
            logical_chunk = logical_chunk.saturating_add(1);
        }
    }
    let logical_chunks = manifest.length.div_ceil(ARTIFACT_CHUNK_BYTES_U64);
    while logical_chunk < logical_chunks {
        boundary()?;
        let offset = logical_chunk
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .ok_or_else(|| loop_factory_error("sparse artifact chunk offset overflow"))?;
        let length =
            usize::try_from(ARTIFACT_CHUNK_BYTES_U64.min(manifest.length.saturating_sub(offset)))
                .map_err(|_| loop_factory_error("sparse artifact chunk length overflow"))?;
        destination.write_all(&zeroes[..length]).map_err(|error| {
            loop_factory_error(format!("write sparse checkpoint hole: {error}"))
        })?;
        logical_chunk = logical_chunk.saturating_add(1);
    }
    boundary()
}
