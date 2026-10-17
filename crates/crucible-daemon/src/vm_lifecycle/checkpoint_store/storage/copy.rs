//! Bounded dense, sparse, and chunk-sequence authenticated copying.

use super::*;

pub(in crate::vm_lifecycle::checkpoint_store) enum AuthenticatedCopyError<E> {
    Io(std::io::Error),
    Boundary(E),
}

pub(in crate::vm_lifecycle::checkpoint_store) fn copy_authenticated_with_boundary<E>(
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

pub(in crate::vm_lifecycle::checkpoint_store) fn copy_sparse_authenticated_with_boundary(
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

pub(in crate::vm_lifecycle::checkpoint_store) struct ChunkSequenceReader {
    directory: PathBuf,
    chunks: Vec<ContentHash>,
    index: usize,
    current: Option<File>,
    pub(super) bytes_read: u64,
}

impl ChunkSequenceReader {
    pub(super) fn new(directory: &Path, chunks: &[ContentHash]) -> Result<Self, LifecycleApiError> {
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

    pub(super) fn new_with_lifecycle_boundary(
        directory: &Path,
        chunks: &[ContentHash],
        boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    ) -> Result<Self, LifecycleApiError> {
        for (index, identity) in chunks.iter().enumerate() {
            boundary()?;
            let path = object_path(directory, *identity);
            let length = fs::metadata(&path)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "inspect checkpoint chunk {}: {error}",
                        path.display()
                    ))
                })?
                .len();
            if !valid_chunk_length(index, chunks.len(), length) {
                return Err(loop_factory_error(
                    "checkpoint artifact has invalid chunk geometry",
                ));
            }
            validate_file_hash_with_lifecycle_boundary(&path, *identity, boundary)?;
        }
        boundary()?;
        Ok(Self::unopened(directory, chunks))
    }

    pub(super) fn new_with_scheduler_boundary(
        directory: &Path,
        chunks: &[ContentHash],
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<Self, SchedulerError> {
        for (index, identity) in chunks.iter().enumerate() {
            boundary()?;
            let path = object_path(directory, *identity);
            let length = fs::metadata(&path)
                .map_err(|error| {
                    store_error(format!(
                        "inspect checkpoint chunk {}: {error}",
                        path.display()
                    ))
                })?
                .len();
            if !valid_chunk_length(index, chunks.len(), length) {
                return Err(store_error(
                    "checkpoint artifact has invalid chunk geometry",
                ));
            }
            validate_file_hash_with_boundary(&path, *identity, boundary)?;
        }
        boundary()?;
        Ok(Self::unopened(directory, chunks))
    }

    fn unopened(directory: &Path, chunks: &[ContentHash]) -> Self {
        Self {
            directory: directory.to_path_buf(),
            chunks: chunks.to_vec(),
            index: 0,
            current: None,
            bytes_read: 0,
        }
    }
}

fn valid_chunk_length(index: usize, chunk_count: usize, length: u64) -> bool {
    if index + 1 == chunk_count {
        (1..=ARTIFACT_CHUNK_BYTES_U64).contains(&length)
    } else {
        length == ARTIFACT_CHUNK_BYTES_U64
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
            record_checkpoint_payload_read(read);
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

pub(in crate::vm_lifecycle::checkpoint_store) fn read_bounded_file_with_scheduler_boundary(
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
