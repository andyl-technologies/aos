//! Bounded file persistence, reads, and content authentication.

use super::*;

pub(in crate::vm_lifecycle::checkpoint_store) fn persist_file_bytes_with_boundary(
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

pub(in crate::vm_lifecycle::checkpoint_store) fn read_object(
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

pub(in crate::vm_lifecycle::checkpoint_store) fn validate_file_hash(
    path: &Path,
    expected: ContentHash,
) -> Result<(), SchedulerError> {
    validate_file_hash_with_boundary(path, expected, &mut || Ok(()))
}

pub(in crate::vm_lifecycle::checkpoint_store) fn validate_file_hash_with_boundary(
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
        record_checkpoint_payload_read(read);
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

pub(in crate::vm_lifecycle::checkpoint_store) fn validate_file_hash_with_lifecycle_boundary(
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
        record_checkpoint_payload_read(read);
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

pub(in crate::vm_lifecycle::checkpoint_store) fn hash_bytes_with_boundary(
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

pub(in crate::vm_lifecycle::checkpoint_store) fn hash_bytes_with_lifecycle_boundary(
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
