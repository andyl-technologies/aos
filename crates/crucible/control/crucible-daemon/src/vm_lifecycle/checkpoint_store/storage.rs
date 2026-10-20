//! Authenticated checkpoint object persistence, streaming, and hashing.

use super::*;
use std::os::unix::fs::MetadataExt as _;

#[cfg(test)]
std::thread_local! {
    static CHECKPOINT_PAYLOAD_BYTES_READ: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn record_checkpoint_payload_read(bytes: usize) {
    CHECKPOINT_PAYLOAD_BYTES_READ.with(|observed| {
        observed.set(
            observed
                .get()
                .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX)),
        );
    });
}

#[cfg(not(test))]
fn record_checkpoint_payload_read(_bytes: usize) {}

#[cfg(test)]
pub(super) fn persist_object(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
) -> Result<(), SchedulerError> {
    persist_object_with_boundary(directory, expected, bytes, &mut || Ok(()))
}

pub(super) fn persist_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    if hash_bytes_with_boundary(bytes, boundary)? != expected {
        return Err(store_error(
            "checkpoint object content hash mismatch before persistence",
        ));
    }
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint object: {error}")))?;
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        staging
            .write_all(chunk)
            .map_err(|error| store_error(format!("write staged checkpoint object: {error}")))?;
    }
    boundary()?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => sync_directory(staging_directory),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

pub(super) fn persist_file_object_with_boundary(
    directory: &Path,
    expected: ContentHash,
    source: &Path,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(source, expected, boundary)?;
    let destination = object_path(directory, expected);
    if destination.exists() {
        return sync_existing_object_with_boundary(&destination, expected, boundary);
    }
    let staging_directory = destination
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    fs::create_dir_all(staging_directory)
        .map_err(|error| store_error(format!("create checkpoint object prefix: {error}")))?;
    let mut staging = tempfile::Builder::new()
        .prefix(".object-")
        .tempfile_in(staging_directory)
        .map_err(|error| store_error(format!("stage checkpoint file object: {error}")))?;
    let source_length = fs::metadata(source)
        .map_err(|error| store_error(format!("inspect checkpoint file object: {error}")))?
        .len();
    let source_file = File::open(source)
        .map_err(|error| store_error(format!("open checkpoint file object: {error}")))?;
    copy_sparse_authenticated_with_boundary(
        source_file,
        staging.as_file_mut(),
        source_length,
        expected,
        boundary,
    )?;
    staging
        .as_file()
        .sync_all()
        .map_err(|error| store_error(format!("flush staged checkpoint object: {error}")))?;
    match staging.persist_noclobber(&destination) {
        Ok(_) => {
            validate_file_hash_with_boundary(&destination, expected, boundary)?;
            sync_directory(staging_directory)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            sync_existing_object_with_boundary(&destination, expected, boundary)
        }
        Err(error) => Err(store_error(format!(
            "publish checkpoint object {}: {}",
            expected.to_hex(),
            error.error
        ))),
    }
}

pub(super) fn sync_existing_object_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, boundary)?;
    boundary()?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| store_error(format!("flush checkpoint object: {error}")))?;
    let parent = path
        .parent()
        .ok_or_else(|| store_error("checkpoint object path has no parent directory"))?;
    sync_directory(parent)
}

#[cfg(test)]
pub(super) fn artifact_manifest(
    artifact: &ProductionCheckpointArtifact,
) -> Result<ArtifactManifest, SchedulerError> {
    artifact_manifest_with_boundary(artifact, &mut || Ok(()))
}

pub(super) fn artifact_manifest_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ArtifactManifest, SchedulerError> {
    boundary()?;
    if artifact.sparse || !artifact.chunks.is_empty() {
        return Ok(ArtifactManifest {
            identity: artifact.identity,
            length: artifact.length,
            chunks: artifact.chunks.clone(),
            sparse: artifact.sparse,
            extents: artifact.extents.clone(),
        });
    }
    #[cfg(any(test, feature = "test-support"))]
    let path = match &artifact.source {
        ProductionCheckpointArtifactSource::File(path) => path,
        ProductionCheckpointArtifactSource::ChunkStore(_)
        | ProductionCheckpointArtifactSource::RetainedChunkStore(_) => {
            return Err(store_error(
                "chunk-store artifact is missing its canonical chunk sequence",
            ));
        }
    };
    #[cfg(not(any(test, feature = "test-support")))]
    return Err(store_error(
        "chunk-store artifact is missing its canonical chunk sequence",
    ));
    #[cfg(any(test, feature = "test-support"))]
    {
        validate_file_hash_with_boundary(path, artifact.identity, boundary)?;
        let observed_length = fs::metadata(path)
            .map_err(|error| store_error(format!("inspect checkpoint artifact: {error}")))?
            .len();
        if observed_length != artifact.length {
            return Err(store_error(
                "checkpoint artifact length changed before persistence",
            ));
        }
        let mut file = File::open(path)
            .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
        let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
        let mut chunks = Vec::new();
        loop {
            boundary()?;
            let mut filled = 0;
            while filled < buffer.len() {
                boundary()?;
                let read = file
                    .read(&mut buffer[filled..])
                    .map_err(|error| store_error(format!("read checkpoint artifact: {error}")))?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 {
                break;
            }
            chunks.push(hash_bytes_with_boundary(&buffer[..filled], boundary)?);
            if filled < buffer.len() {
                break;
            }
        }
        Ok(ArtifactManifest {
            identity: artifact.identity,
            length: artifact.length,
            chunks,
            sparse: false,
            extents: Vec::new(),
        })
    }
}

#[cfg(test)]
pub(super) fn persist_chunked_artifact(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
) -> Result<(), SchedulerError> {
    persist_chunked_artifact_with_boundary(directory, manifest, artifact, &mut || Ok(()))
}

pub(super) fn persist_chunked_artifact_with_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    match &artifact.source {
        ProductionCheckpointArtifactSource::RetainedChunkStore(lease)
            if lease.directory == directory && !manifest.sparse =>
        {
            validate_retained_dense_artifact_lease(lease, manifest, artifact, boundary)?;
            return Ok(());
        }
        ProductionCheckpointArtifactSource::RetainedChunkStore(lease) => {
            let source = &lease.directory;
            validate_artifact_manifest_with_scheduler_boundary(source, manifest, boundary)?;
            for chunk in artifact_object_identities(manifest) {
                boundary()?;
                let source_path = object_path(source, chunk);
                let destination = object_path(directory, chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object_with_boundary(directory, chunk, &source_path, boundary)?;
                }
            }
        }
        ProductionCheckpointArtifactSource::ChunkStore(source) => {
            validate_artifact_manifest_with_scheduler_boundary(source, manifest, boundary)?;
            for chunk in artifact_object_identities(manifest) {
                boundary()?;
                let source_path = object_path(source, chunk);
                let destination = object_path(directory, chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object_with_boundary(directory, chunk, &source_path, boundary)?;
                }
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        ProductionCheckpointArtifactSource::File(path) => {
            if manifest.sparse {
                return Err(store_error(
                    "sparse checkpoint artifact must originate in a staged chunk store",
                ));
            }
            let mut file = File::open(path)
                .map_err(|error| store_error(format!("open checkpoint artifact: {error}")))?;
            let mut buffer = vec![0_u8; ARTIFACT_CHUNK_BYTES];
            for expected in &manifest.chunks {
                boundary()?;
                let mut filled = 0;
                while filled < buffer.len() {
                    boundary()?;
                    let read = file.read(&mut buffer[filled..]).map_err(|error| {
                        store_error(format!("read checkpoint artifact chunk: {error}"))
                    })?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                if filled == 0 || ContentHash::from_bytes(&buffer[..filled]) != *expected {
                    return Err(store_error(
                        "checkpoint artifact chunk changed before persistence",
                    ));
                }
                persist_object_with_boundary(directory, *expected, &buffer[..filled], boundary)?;
            }
            let mut trailing = [0_u8; 1];
            boundary()?;
            if file
                .read(&mut trailing)
                .map_err(|error| store_error(format!("finish checkpoint artifact: {error}")))?
                != 0
            {
                return Err(store_error(
                    "checkpoint artifact grew while it was being persisted",
                ));
            }
        }
    }
    boundary()?;
    validate_artifact_manifest_with_scheduler_boundary(directory, manifest, boundary)
}

/// Checks the immutable-object geometry covered by a retained publication lease.
///
/// The closure was fully authenticated before its artifact source acquired the
/// `RetainedChunkStore` variant. Child publication therefore checks object
/// identity names, types, and lengths without rereading inherited RAM bytes.
fn validate_retained_dense_artifact_lease(
    lease: &RetainedChunkStoreLease,
    manifest: &ArtifactManifest,
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    if artifact.identity != manifest.identity
        || artifact.length != manifest.length
        || artifact.chunks != manifest.chunks
        || artifact.sparse
        || manifest.sparse
        || !artifact.extents.is_empty()
        || !manifest.extents.is_empty()
    {
        return Err(store_error(
            "retained checkpoint artifact differs from its authenticated lease",
        ));
    }
    let expected_chunks = manifest.length.div_ceil(ARTIFACT_CHUNK_BYTES_U64);
    if u64::try_from(manifest.chunks.len()).ok() != Some(expected_chunks) {
        return Err(store_error(
            "retained checkpoint artifact has invalid dense chunk geometry",
        ));
    }
    for (index, identity) in manifest.chunks.iter().enumerate() {
        boundary()?;
        let index = u64::try_from(index)
            .map_err(|error| store_error(format!("convert retained chunk index: {error}")))?;
        let offset = index
            .checked_mul(ARTIFACT_CHUNK_BYTES_U64)
            .ok_or_else(|| store_error("retained chunk offset overflow"))?;
        let expected_length = manifest
            .length
            .saturating_sub(offset)
            .min(ARTIFACT_CHUNK_BYTES_U64);
        let observed = retained_checkpoint_object(&object_path(&lease.directory, *identity))
            .map_err(|error| {
                store_error(format!(
                    "inspect retained checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?;
        if observed.length != expected_length || lease.objects.get(identity) != Some(&observed) {
            return Err(store_error(
                "retained checkpoint object changed after authentication",
            ));
        }
    }
    boundary()?;
    Ok(())
}

fn retained_checkpoint_object(path: &Path) -> Result<RetainedCheckpointObject, std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::other(
            "retained checkpoint object is not a regular file",
        ));
    }
    Ok(RetainedCheckpointObject {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

fn retained_artifact_fields_match(
    artifact: &ProductionCheckpointArtifact,
    manifest: &ArtifactManifest,
) -> bool {
    artifact.identity == manifest.identity
        && artifact.length == manifest.length
        && artifact.chunks == manifest.chunks
        && artifact.sparse == manifest.sparse
        && artifact.extents == manifest.extents
}

fn snapshot_retained_objects(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<BTreeMap<ContentHash, RetainedCheckpointObject>, SchedulerError> {
    let mut objects = BTreeMap::new();
    for identity in artifact_object_identities(manifest) {
        boundary()?;
        let observed =
            retained_checkpoint_object(&object_path(directory, identity)).map_err(|error| {
                store_error(format!(
                    "lease authenticated checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?;
        objects.insert(identity, observed);
    }
    Ok(objects)
}

pub(super) fn snapshot_retained_objects_with_lifecycle_boundary(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<BTreeMap<ContentHash, RetainedCheckpointObject>, LifecycleApiError> {
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    let mut objects = BTreeMap::new();
    for identity in artifact_object_identities(&manifest) {
        boundary()?;
        let observed =
            retained_checkpoint_object(&object_path(directory, identity)).map_err(|error| {
                loop_factory_error(format!(
                    "inspect authenticated checkpoint object {}: {error}",
                    identity.to_hex()
                ))
            })?;
        objects.insert(identity, observed);
    }
    Ok(objects)
}

pub(super) fn install_lifecycle_authenticated_retained_artifact(
    artifact: &mut ProductionCheckpointArtifact,
    directory: PathBuf,
    before: BTreeMap<ContentHash, RetainedCheckpointObject>,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let objects =
        snapshot_retained_objects_with_lifecycle_boundary(&directory, artifact, boundary)?;
    if before != objects {
        return Err(loop_factory_error(
            "checkpoint objects changed while their retained lease was authenticated",
        ));
    }
    artifact.source =
        ProductionCheckpointArtifactSource::RetainedChunkStore(Arc::new(RetainedChunkStoreLease {
            directory,
            objects,
        }));
    Ok(())
}

fn authenticate_retained_artifact_from_manifest(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    let before = snapshot_retained_objects(directory, manifest, boundary)?;
    validate_artifact_manifest_with_scheduler_boundary(directory, manifest, boundary)?;
    let objects = snapshot_retained_objects(directory, manifest, boundary)?;
    if before != objects {
        return Err(store_error(
            "checkpoint objects changed while their retained lease was authenticated",
        ));
    }
    Ok(ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::RetainedChunkStore(Arc::new(
            RetainedChunkStoreLease {
                directory: directory.to_path_buf(),
                objects,
            },
        )),
        identity: manifest.identity,
        length: manifest.length,
        chunks: manifest.chunks.clone(),
        sparse: manifest.sparse,
        extents: manifest.extents.clone(),
    })
}

pub(super) fn install_retained_artifact_from_manifest(
    existing: &ProductionCheckpointArtifact,
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    if let ProductionCheckpointArtifactSource::RetainedChunkStore(lease) = &existing.source
        && lease.directory == directory
        && retained_artifact_fields_match(existing, manifest)
        && !manifest.sparse
    {
        validate_retained_dense_artifact_lease(lease, manifest, existing, boundary)?;
        return Ok(existing.clone());
    }
    authenticate_retained_artifact_from_manifest(directory, manifest, boundary)
}

pub(super) fn retained_exact_ram_from_manifest(
    manifest: &ExactRamManifest,
    directory: &Path,
    existing: &ProductionExactRamCheckpoint,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ProductionExactRamCheckpoint, SchedulerError> {
    if manifest.layers.len() != existing.layers.len() {
        return Err(store_error(
            "exact RAM layer count changed while installing retained leases",
        ));
    }
    let layers = manifest
        .layers
        .iter()
        .zip(&existing.layers)
        .map(|(layer, existing)| {
            Ok(ProductionExactRamLayer {
                kind: layer.kind,
                identity: layer.identity,
                parent: layer.parent,
                topology: layer.topology,
                ram_regions: layer.ram_regions,
                ram_records: layer.ram_records,
                content_sha256: layer.content_sha256,
                artifact: install_retained_artifact_from_manifest(
                    &existing.artifact,
                    directory,
                    &layer.artifact,
                    boundary,
                )?,
            })
        })
        .collect::<Result<Vec<_>, SchedulerError>>()?;
    ProductionExactRamCheckpoint::new(
        manifest.parent_closure,
        manifest.device_content_sha256,
        install_retained_artifact_from_manifest(
            &existing.device_artifact,
            directory,
            &manifest.device,
            boundary,
        )?,
        layers,
    )
}

pub(in crate::vm_lifecycle) fn validate_chunked_artifact(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
) -> Result<ContentHash, LifecycleApiError> {
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    validate_artifact_manifest(directory, &manifest)?;
    Ok(manifest.identity)
}

pub(in crate::vm_lifecycle) fn validate_retained_chunked_artifact_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ContentHash, LifecycleApiError> {
    let ProductionCheckpointArtifactSource::RetainedChunkStore(lease) = &artifact.source else {
        return Err(loop_factory_error(
            "checkpoint artifact has no retained authentication capability",
        ));
    };
    if artifact.sparse {
        let manifest = ArtifactManifest {
            identity: artifact.identity,
            length: artifact.length,
            chunks: artifact.chunks.clone(),
            sparse: true,
            extents: artifact.extents.clone(),
        };
        validate_sparse_artifact_shape(&manifest).map_err(loop_factory_error)?;
    } else {
        let expected_chunks = artifact.length.div_ceil(ARTIFACT_CHUNK_BYTES_U64);
        if !artifact.extents.is_empty()
            || u64::try_from(artifact.chunks.len()).ok() != Some(expected_chunks)
        {
            return Err(loop_factory_error(
                "retained checkpoint artifact has invalid dense chunk geometry",
            ));
        }
    }
    let observed =
        snapshot_retained_objects_with_lifecycle_boundary(&lease.directory, artifact, boundary)?;
    if observed != lease.objects {
        return Err(loop_factory_error(
            "retained checkpoint object changed after authentication",
        ));
    }
    Ok(artifact.identity)
}

pub(super) fn validate_artifact_manifest_with_lifecycle_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    if manifest.sparse {
        return validate_sparse_artifact_manifest_with_lifecycle_boundary(
            directory, manifest, boundary,
        );
    }
    let mut reader =
        ChunkSequenceReader::new_with_lifecycle_boundary(directory, &manifest.chunks, boundary)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    loop {
        boundary()?;
        let read = reader.read(&mut buffer).map_err(|error| {
            loop_factory_error(format!("read chunked checkpoint artifact: {error}"))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(loop_factory_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

pub(super) fn validate_artifact_manifest(
    directory: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), LifecycleApiError> {
    if manifest.sparse {
        validate_sparse_artifact_manifest(directory, manifest)?;
        return Ok(());
    }
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)?;
    let observed = ContentHash::from_reader(&mut reader).map_err(|error| {
        loop_factory_error(format!("read chunked checkpoint artifact: {error}"))
    })?;
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(loop_factory_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

pub(super) fn validate_artifact_manifest_with_scheduler_boundary(
    directory: &Path,
    manifest: &ArtifactManifest,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    if manifest.sparse {
        validate_sparse_artifact_manifest_with_scheduler_boundary(directory, manifest, boundary)?;
        return Ok(());
    }
    let mut reader =
        ChunkSequenceReader::new_with_scheduler_boundary(directory, &manifest.chunks, boundary)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    loop {
        boundary()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read chunked checkpoint artifact: {error}")))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if reader.bytes_read != manifest.length || observed != manifest.identity {
        return Err(store_error(
            "chunked checkpoint artifact failed length or content authentication",
        ));
    }
    Ok(())
}

pub(in crate::vm_lifecycle) fn stream_checkpoint_artifact_with_boundary(
    artifact: &ProductionCheckpointArtifact,
    destination: &mut impl Write,
    role: &str,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    match &artifact.source {
        #[cfg(any(test, feature = "test-support"))]
        ProductionCheckpointArtifactSource::File(source) => {
            let reader = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            match copy_authenticated_with_boundary(
                reader,
                destination,
                artifact.length,
                artifact.identity,
                boundary,
            ) {
                Ok(()) => Ok(()),
                Err(AuthenticatedCopyError::Io(error)) => Err(loop_factory_error(format!(
                    "stream exact checkpoint {role} {}: {error}",
                    source.display()
                ))),
                Err(AuthenticatedCopyError::Boundary(error)) => Err(error),
            }
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) if !artifact.sparse => {
            stream_chunked_checkpoint_artifact_with_boundary(
                directory,
                &artifact.chunks,
                artifact.length,
                artifact.identity,
                destination,
                role,
                boundary,
            )
        }
        ProductionCheckpointArtifactSource::RetainedChunkStore(lease) if !artifact.sparse => {
            stream_chunked_checkpoint_artifact_with_boundary(
                &lease.directory,
                &artifact.chunks,
                artifact.length,
                artifact.identity,
                destination,
                role,
                boundary,
            )
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            let manifest = ArtifactManifest {
                identity: artifact.identity,
                length: artifact.length,
                chunks: artifact.chunks.clone(),
                sparse: artifact.sparse,
                extents: artifact.extents.clone(),
            };
            validate_sparse_artifact_manifest_with_lifecycle_boundary(
                directory, &manifest, boundary,
            )?;
            stream_sparse_artifact_bytes(directory, &manifest, destination, boundary)
        }
        ProductionCheckpointArtifactSource::RetainedChunkStore(lease) => {
            let manifest = ArtifactManifest {
                identity: artifact.identity,
                length: artifact.length,
                chunks: artifact.chunks.clone(),
                sparse: artifact.sparse,
                extents: artifact.extents.clone(),
            };
            validate_sparse_artifact_manifest_with_lifecycle_boundary(
                &lease.directory,
                &manifest,
                boundary,
            )?;
            stream_sparse_artifact_bytes(&lease.directory, &manifest, destination, boundary)
        }
    }
}

pub(super) fn stream_chunked_checkpoint_artifact_with_boundary(
    directory: &Path,
    chunks: &[ContentHash],
    length: u64,
    identity: ContentHash,
    destination: &mut impl Write,
    role: &str,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let reader = ChunkSequenceReader::new_with_lifecycle_boundary(directory, chunks, boundary)?;
    match copy_authenticated_with_boundary(reader, destination, length, identity, boundary) {
        Ok(()) => Ok(()),
        Err(AuthenticatedCopyError::Io(error)) => Err(loop_factory_error(format!(
            "stream chunked exact checkpoint {role} from {}: {error}",
            directory.display()
        ))),
        Err(AuthenticatedCopyError::Boundary(error)) => Err(error),
    }
}

mod copy;

use copy::{AuthenticatedCopyError, ChunkSequenceReader};
pub(super) use copy::{
    copy_authenticated_with_boundary, copy_sparse_authenticated_with_boundary,
    read_bounded_file_with_scheduler_boundary,
};

mod file_io;

pub(super) use file_io::{
    hash_bytes_with_boundary, persist_file_bytes_with_boundary, read_object, validate_file_hash,
    validate_file_hash_with_boundary, validate_file_hash_with_lifecycle_boundary,
};

#[cfg(test)]
mod tests;
