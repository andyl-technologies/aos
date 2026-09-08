//! Authenticated checkpoint object persistence, streaming, and hashing.

use super::*;

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
    let ProductionCheckpointArtifactSource::File(path) = &artifact.source else {
        return Err(store_error(
            "chunk-store artifact is missing its canonical chunk sequence",
        ));
    };
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
        ProductionCheckpointArtifactSource::ChunkStore(source) => {
            validate_artifact_manifest(source, manifest)
                .map_err(|error| store_error(error.to_string()))?;
            for chunk in artifact_object_identities(manifest) {
                boundary()?;
                let source_path = object_path(source, chunk);
                let destination = object_path(directory, chunk);
                if source_path != destination && !destination.exists() {
                    persist_file_object_with_boundary(directory, chunk, &source_path, boundary)?;
                }
            }
        }
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
    let mut reader = ChunkSequenceReader::new(directory, &manifest.chunks)
        .map_err(|error| store_error(error.to_string()))?;
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

pub(in crate::vm_lifecycle) fn materialize_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &Path,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let parent = destination.parent().ok_or_else(|| {
        loop_factory_error(format!(
            "exact checkpoint {role} destination has no parent directory"
        ))
    })?;
    let mut staging = tempfile::Builder::new()
        .prefix(".artifact-")
        .tempfile_in(parent)
        .map_err(|error| {
            loop_factory_error(format!(
                "stage exact checkpoint {role} under {}: {error}",
                parent.display()
            ))
        })?;

    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let source_file = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_sparse_authenticated(
                source_file,
                staging.as_file_mut(),
                artifact.length,
                artifact.identity,
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "materialize exact checkpoint {role} {} as {}: {error}",
                    source.display(),
                    destination.display()
                ))
            })?;
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            if artifact.sparse {
                materialize_sparse_checkpoint_artifact(directory, artifact, staging.as_file_mut())?;
            } else {
                let reader = ChunkSequenceReader::new(directory, &artifact.chunks)?;
                copy_sparse_authenticated(
                    reader,
                    staging.as_file_mut(),
                    artifact.length,
                    artifact.identity,
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "materialize exact checkpoint {role} {}: {error}",
                        destination.display()
                    ))
                })?;
            }
        }
    }
    staging.as_file().sync_all().map_err(|error| {
        loop_factory_error(format!(
            "flush exact checkpoint {role} {}: {error}",
            destination.display()
        ))
    })?;
    staging.persist_noclobber(destination).map_err(|error| {
        loop_factory_error(format!(
            "publish exact checkpoint {role} {}: {}",
            destination.display(),
            error.error
        ))
    })?;
    sync_directory(parent).map_err(|error| loop_factory_error(error.to_string()))
}

pub(in crate::vm_lifecycle) fn stream_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    match &artifact.source {
        ProductionCheckpointArtifactSource::File(source) => {
            let reader = File::open(source).map_err(|error| {
                loop_factory_error(format!(
                    "open exact checkpoint {role} {}: {error}",
                    source.display()
                ))
            })?;
            copy_authenticated(reader, destination, artifact.length, artifact.identity).map_err(
                |error| {
                    loop_factory_error(format!(
                        "stream exact checkpoint {role} {}: {error}",
                        source.display()
                    ))
                },
            )
        }
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            stream_stored_checkpoint_artifact(directory, artifact, destination, role)
        }
    }
}

pub(super) fn stream_stored_checkpoint_artifact(
    directory: &Path,
    artifact: &ProductionCheckpointArtifact,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    if !artifact.sparse {
        return stream_chunked_checkpoint_artifact(
            directory,
            &artifact.chunks,
            artifact.length,
            artifact.identity,
            destination,
            role,
        );
    }
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    validate_sparse_artifact_manifest(directory, &manifest)?;
    stream_sparse_artifact_bytes(directory, &manifest, destination, &mut || Ok(()))
}

pub(super) fn stream_chunked_checkpoint_artifact(
    directory: &Path,
    chunks: &[ContentHash],
    length: u64,
    identity: ContentHash,
    destination: &mut impl Write,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let reader = ChunkSequenceReader::new(directory, chunks)?;
    copy_authenticated(reader, destination, length, identity).map_err(|error| {
        loop_factory_error(format!(
            "stream chunked exact checkpoint {role} from {}: {error}",
            directory.display()
        ))
    })
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
    let reader = ChunkSequenceReader::new(directory, chunks)?;
    match copy_authenticated_with_boundary(reader, destination, length, identity, boundary) {
        Ok(()) => Ok(()),
        Err(AuthenticatedCopyError::Io(error)) => Err(loop_factory_error(format!(
            "stream chunked exact checkpoint {role} from {}: {error}",
            directory.display()
        ))),
        Err(AuthenticatedCopyError::Boundary(error)) => Err(error),
    }
}

pub(super) fn stream_replay_artifact(
    artifact: &ProductionExactCheckpointReplayArtifact,
    destination: &mut impl Write,
) -> Result<(), LifecycleApiError> {
    if !artifact.sparse {
        return stream_chunked_checkpoint_artifact(
            &artifact.object_directory,
            &artifact.chunks,
            artifact.length,
            artifact.identity,
            destination,
            artifact.role,
        );
    }
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    validate_sparse_artifact_manifest(&artifact.object_directory, &manifest)?;
    stream_sparse_artifact_bytes(
        &artifact.object_directory,
        &manifest,
        destination,
        &mut || Ok(()),
    )
}

pub(super) fn stream_replay_artifact_with_boundary(
    artifact: &ProductionExactCheckpointReplayArtifact,
    destination: &mut impl Write,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    if !artifact.sparse {
        return stream_chunked_checkpoint_artifact_with_boundary(
            &artifact.object_directory,
            &artifact.chunks,
            artifact.length,
            artifact.identity,
            destination,
            artifact.role,
            boundary,
        );
    }
    boundary()?;
    let manifest = ArtifactManifest {
        identity: artifact.identity,
        length: artifact.length,
        chunks: artifact.chunks.clone(),
        sparse: artifact.sparse,
        extents: artifact.extents.clone(),
    };
    validate_sparse_artifact_manifest_with_lifecycle_boundary(
        &artifact.object_directory,
        &manifest,
        boundary,
    )?;
    stream_sparse_artifact_bytes(&artifact.object_directory, &manifest, destination, boundary)
}

pub(super) enum AuthenticatedCopyError<E> {
    Io(std::io::Error),
    Boundary(E),
}

pub(super) fn copy_authenticated(
    source: impl Read,
    destination: &mut impl Write,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut boundary = || Ok::<(), std::convert::Infallible>(());
    match copy_authenticated_with_boundary(
        source,
        destination,
        expected_length,
        expected_identity,
        &mut boundary,
    ) {
        Ok(()) => Ok(()),
        Err(AuthenticatedCopyError::Io(error)) => Err(error),
        Err(AuthenticatedCopyError::Boundary(never)) => match never {},
    }
}

pub(super) fn copy_authenticated_with_boundary<E>(
    mut source: impl Read,
    destination: &mut impl Write,
    expected_length: u64,
    expected_identity: ContentHash,
    boundary: &mut (impl FnMut() -> Result<(), E> + ?Sized),
) -> Result<(), AuthenticatedCopyError<E>> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
        let read = source
            .read(&mut buffer)
            .map_err(AuthenticatedCopyError::Io)?;
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            ))
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            ))
        })?;
        if copied > expected_length {
            return Err(AuthenticatedCopyError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            )));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        destination
            .write_all(bytes)
            .map_err(AuthenticatedCopyError::Io)?;
        boundary().map_err(AuthenticatedCopyError::Boundary)?;
    }
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if copied != expected_length || observed != expected_identity {
        return Err(AuthenticatedCopyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed length or content authentication",
        )));
    }
    boundary().map_err(AuthenticatedCopyError::Boundary)?;
    Ok(())
}

pub(super) fn copy_sparse_authenticated(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
) -> Result<(), std::io::Error> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length is not representable",
            )
        })?;
        copied = copied.checked_add(read_u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint copy length overflowed",
            )
        })?;
        if copied > expected_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact exceeds its declared length",
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint sparse extent is not representable",
                )
            })?;
            destination.seek(SeekFrom::Current(offset))?;
        } else {
            destination.write_all(bytes)?;
        }
    }
    if copied != expected_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "checkpoint artifact is shorter than its declared length",
        ));
    }
    destination.set_len(expected_length)?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint artifact failed content authentication while streaming",
        ));
    }
    Ok(())
}

pub(super) fn copy_sparse_authenticated_with_boundary(
    mut source: impl Read,
    destination: &mut File,
    expected_length: u64,
    expected_identity: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut copied = 0_u64;
    loop {
        boundary()?;
        let read = source
            .read(&mut buffer)
            .map_err(|error| store_error(format!("read checkpoint sparse extent: {error}")))?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length is not representable",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        copied = copied
            .checked_add(read_u64)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint copy length overflowed",
                )
            })
            .map_err(|error| store_error(error.to_string()))?;
        if copied > expected_length {
            return Err(store_error(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint artifact exceeds its declared length",
                )
                .to_string(),
            ));
        }
        let bytes = &buffer[..read];
        hasher.update(bytes);
        if bytes.iter().all(|byte| *byte == 0) {
            let offset = i64::try_from(read)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "checkpoint sparse extent is not representable",
                    )
                })
                .map_err(|error| store_error(error.to_string()))?;
            destination
                .seek(SeekFrom::Current(offset))
                .map_err(|error| store_error(format!("seek sparse checkpoint extent: {error}")))?;
        } else {
            destination
                .write_all(bytes)
                .map_err(|error| store_error(format!("write checkpoint extent: {error}")))?;
        }
    }
    if copied != expected_length {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "checkpoint artifact is shorter than its declared length",
            )
            .to_string(),
        ));
    }
    destination
        .set_len(expected_length)
        .map_err(|error| store_error(format!("size sparse checkpoint extent: {error}")))?;
    let observed = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if observed != expected_identity {
        return Err(store_error(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "checkpoint artifact failed content authentication while streaming",
            )
            .to_string(),
        ));
    }
    boundary()?;
    Ok(())
}

pub(super) struct ChunkSequenceReader {
    directory: PathBuf,
    chunks: Vec<ContentHash>,
    index: usize,
    current: Option<File>,
    bytes_read: u64,
}

impl ChunkSequenceReader {
    fn new(directory: &Path, chunks: &[ContentHash]) -> Result<Self, LifecycleApiError> {
        for (index, identity) in chunks.iter().enumerate() {
            let path = object_path(directory, *identity);
            let length = fs::metadata(&path)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "inspect checkpoint chunk {}: {error}",
                        path.display()
                    ))
                })?
                .len();
            let expected = if index + 1 == chunks.len() {
                1..=ARTIFACT_CHUNK_BYTES_U64
            } else {
                ARTIFACT_CHUNK_BYTES_U64..=ARTIFACT_CHUNK_BYTES_U64
            };
            if !expected.contains(&length) {
                return Err(loop_factory_error(
                    "checkpoint artifact has invalid chunk geometry",
                ));
            }
            validate_file_hash(&path, *identity)
                .map_err(|error| loop_factory_error(error.to_string()))?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            chunks: chunks.to_vec(),
            index: 0,
            current: None,
            bytes_read: 0,
        })
    }
}

impl std::io::Read for ChunkSequenceReader {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            if self.current.is_none() {
                let Some(identity) = self.chunks.get(self.index).copied() else {
                    return Ok(0);
                };
                self.current = Some(File::open(object_path(&self.directory, identity))?);
            }
            let read = self
                .current
                .as_mut()
                .map_or(Ok(0), |file| file.read(buffer))?;
            if read != 0 {
                self.bytes_read = self
                    .bytes_read
                    .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
                return Ok(read);
            }
            self.current = None;
            self.index = self.index.saturating_add(1);
        }
    }
}

pub(super) fn read_bounded_file_with_scheduler_boundary(
    path: &Path,
    limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<Vec<u8>, SchedulerError> {
    boundary()?;
    let mut file =
        File::open(path).map_err(|error| store_error(format!("open checkpoint file: {error}")))?;
    let length = file
        .metadata()
        .map_err(|error| store_error(format!("inspect checkpoint file: {error}")))?
        .len();
    if length > limit {
        return Err(store_error(format!(
            "checkpoint file length {length} exceeds limit {limit}"
        )));
    }
    let length = usize::try_from(length)
        .map_err(|_| store_error("checkpoint file length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| store_error(format!("reserve checkpoint file bytes: {error}")))?;
    bytes.resize(length, 0);
    for chunk in bytes.chunks_mut(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.read_exact(chunk)
            .map_err(|error| store_error(format!("read checkpoint file: {error}")))?;
    }
    boundary()?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| store_error(format!("finish checkpoint file read: {error}")))?
        != 0
    {
        return Err(store_error("checkpoint file grew while it was read"));
    }
    boundary()?;
    Ok(bytes)
}

pub(super) fn persist_file_bytes_with_boundary(
    path: &Path,
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            store_error(format!(
                "create checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        file.write_all(chunk).map_err(|error| {
            store_error(format!(
                "write checkpoint object {}: {error}",
                path.display()
            ))
        })?;
    }
    boundary()?;
    file.sync_all().map_err(|error| {
        store_error(format!(
            "flush checkpoint object {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn read_object(
    root: &Path,
    expected: ContentHash,
    budget: &mut CheckpointReadBudget,
    role_limit: u64,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<Vec<u8>, LifecycleApiError> {
    boundary()?;
    let path = object_path(root, expected);
    let size = fs::metadata(&path)
        .map_err(|error| {
            loop_factory_error(format!(
                "inspect checkpoint object {}: {error}",
                path.display()
            ))
        })?
        .len();
    if size > role_limit {
        return Err(loop_factory_error(format!(
            "checkpoint object {} exceeds its role-specific byte limit {}",
            expected.to_hex(),
            role_limit
        )));
    }
    let bytes = budget.read_identity(expected, size, || {
        read_bounded_file_with_boundary(&path, size, boundary)
    })?;
    boundary()?;
    if hash_bytes_with_lifecycle_boundary(&bytes, boundary)? != expected {
        return Err(loop_factory_error(format!(
            "checkpoint object {} failed content authentication",
            expected.to_hex()
        )));
    }
    Ok(bytes)
}

pub(super) fn validate_file_hash(path: &Path, expected: ContentHash) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, &mut || Ok(()))
}

pub(super) fn validate_file_hash_with_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<(), SchedulerError> {
    boundary()?;
    let mut file = File::open(path).map_err(|error| {
        store_error(format!(
            "open checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        boundary()?;
        let read = file.read(&mut buffer).map_err(|error| {
            store_error(format!(
                "hash checkpoint object {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let actual = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if actual != expected {
        return Err(store_error(format!(
            "checkpoint object {} changed before persistence",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_file_hash_with_lifecycle_boundary(
    path: &Path,
    expected: ContentHash,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    let mut file = File::open(path).map_err(|error| {
        loop_factory_error(format!(
            "open checkpoint object {}: {error}",
            path.display()
        ))
    })?;
    let mut buffer = vec![0_u8; SPARSE_COPY_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        boundary()?;
        let read = file.read(&mut buffer).map_err(|error| {
            loop_factory_error(format!(
                "hash checkpoint object {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let actual = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    if actual != expected {
        return Err(loop_factory_error(format!(
            "checkpoint object {} failed content authentication",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn hash_bytes_with_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ContentHash, SchedulerError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

pub(super) fn hash_bytes_with_lifecycle_boundary(
    bytes: &[u8],
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ContentHash, LifecycleApiError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in bytes.chunks(SPARSE_COPY_BUFFER_BYTES) {
        boundary()?;
        hasher.update(chunk);
    }
    boundary()?;
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}
