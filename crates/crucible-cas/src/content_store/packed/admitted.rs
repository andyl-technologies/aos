//! Original-admitted Packed fields, startup, and retained constructor credit.
//!
//! The graph supplies the guard bound to this exact exclusive Packed root.
//! Its saved original owns retained fields and controls before allocation;
//! checked startup never invokes the ordinary unmetered initializer.

use super::*;
use crate::content_store::{StorePhysicalQuotaGuard, batch, checked_reader};
use crate::owned_decode::{DecodeBudget, ResourceLoan};

pub(in crate::content_store) struct Admitted {
    pub(in crate::content_store) backend: PackedBlobBackend,
    pub(in crate::content_store) resources: ResourceLoan,
}

#[repr(C)]
struct BackendAllocation {
    _strong: usize,
    _weak: usize,
    _backend: PackedBlobBackend,
}

pub(in crate::content_store) fn open(
    name: &str,
    root: &Path,
    target_pack_bytes: u64,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
    admin_control_bytes: u64,
) -> Result<Admitted, StoreError> {
    if !(MIN_TARGET_PACK_BYTES..=MAX_PACK_BYTES).contains(&target_pack_bytes) {
        return Err(StoreError::InvalidComposition {
            reason: "packed target size is outside the admitted bounds",
        });
    }
    guard.verify()?;
    let original = DecodeBudget::for_store(Arc::clone(&guard)).map_err(|source| {
        StoreError::DecodeAdmission {
            source,
            custody: None,
        }
    })?;
    let boundary = &mut || Ok(());
    checked_reader::check(&original, boundary)?;

    let root_bytes = root.as_os_str().len();
    let packs_bytes = root_bytes
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(PACK_DIRECTORY.len()))
        .ok_or(StoreError::Quota)?;
    let admin_bytes = root_bytes
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(ADMIN_DIRECTORY.len()))
        .ok_or(StoreError::Quota)?;
    let heap_bytes = name
        .len()
        .checked_add(root_bytes)
        .and_then(|bytes| bytes.checked_add(packs_bytes))
        .and_then(|bytes| bytes.checked_add(admin_bytes))
        .ok_or(StoreError::Quota)?;
    let bytes = (std::mem::size_of::<BackendAllocation>() as u64)
        .checked_add(admin_control_bytes)
        .and_then(|bytes| bytes.checked_add(heap_bytes as u64))
        .ok_or(StoreError::Quota)?;
    let resources = guard.reserve_resources(0, bytes)?;

    let mut owned_name = String::new();
    owned_name
        .try_reserve_exact(name.len())
        .map_err(|error| batch::allocation_under(&original, error))?;
    owned_name.push_str(name);
    let mut owned_root = PathBuf::new();
    owned_root
        .try_reserve_exact(root_bytes)
        .map_err(|error| batch::allocation_under(&original, error))?;
    owned_root.push(root);
    let mut packs = PathBuf::new();
    packs
        .try_reserve_exact(packs_bytes)
        .map_err(|error| batch::allocation_under(&original, error))?;
    packs.push(root);
    packs.push(PACK_DIRECTORY);
    let mut admin = PathBuf::new();
    admin
        .try_reserve_exact(admin_bytes)
        .map_err(|error| batch::allocation_under(&original, error))?;
    admin.push(root);
    admin.push(ADMIN_DIRECTORY);
    let configuration = configuration_binding(name, root, target_pack_bytes);
    let admitted = Admitted {
        backend: PackedBlobBackend {
            name: owned_name,
            root: owned_root,
            packs,
            admin,
            target_pack_bytes,
            configuration,
        },
        resources,
    };

    checked_reader::check(&original, boundary)?;
    create_directories(&admitted.backend.packs, &original, boundary)?;
    create_directories(&admitted.backend.admin, &original, boundary)?;
    initialize(&admitted.backend, &original, boundary)?;
    checked_reader::check(&original, boundary)?;
    Ok(admitted)
}

fn create_directories(
    path: &Path,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    // Borrow ancestors instead of copying their path buffers. The format does
    // not impose a new pathname/depth limit; actual capacity is prepaid.
    let capacity = path
        .ancestors()
        .count()
        .checked_add(1)
        .ok_or(StoreError::Quota)?;
    let _credit = original
        .reserve_scratch_array::<&Path>(capacity)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut missing = Vec::new();
    missing
        .try_reserve_exact(capacity)
        .map_err(|error| batch::allocation_under(original, error))?;
    let mut existing = path;
    loop {
        checked_reader::check(original, boundary)?;
        match inspect_path(existing, false, original) {
            Ok(metadata) if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir() => break,
            Ok(_) => {
                return Err(StoreError::StreamIo {
                    operation: "create-packed-directory",
                    source: io::ErrorKind::AlreadyExists.into(),
                });
            }
            Err(StoreError::StreamIo { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                missing.push(existing);
                existing = existing
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
            }
            Err(error) => return Err(error),
        }
        checked_reader::check(original, boundary)?;
    }
    checked_reader::check(original, boundary)?;
    if missing.is_empty() {
        return Ok(());
    }

    for directory in missing.iter().rev() {
        checked_reader::check(original, boundary)?;
        let result =
            checked_io::with_native_path(directory, original, "create-packed-directory", |path| {
                rustix::fs::mkdirat(rustix::fs::CWD, path, Mode::from_raw_mode(0o777)).map_err(
                    |source| StoreError::StreamIo {
                        operation: "create-packed-directory",
                        source: source.into(),
                    },
                )
            });
        match result {
            Ok(()) => {}
            Err(StoreError::StreamIo { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                checked_reader::check(original, boundary)?;
                let metadata = inspect_path(directory, false, original)?;
                checked_reader::check(original, boundary)?;
                if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir() {
                    return Err(StoreError::StreamIo {
                        operation: "create-packed-directory",
                        source: io::ErrorKind::AlreadyExists.into(),
                    });
                }
            }
            Err(error) => return Err(error),
        }
        checked_reader::check(original, boundary)?;
    }
    // Preserve the ordinary helper's child-first sync order, then the exact
    // ancestor observed before creation. Each actual descriptor has custody.
    for directory in &missing {
        checked_io::sync_directory(directory, original, boundary)?;
    }
    checked_io::sync_directory(existing, original, boundary)
}

fn inspect_path(
    path: &Path,
    nofollow: bool,
    original: &DecodeBudget,
) -> Result<rustix::fs::Stat, StoreError> {
    checked_io::with_native_path(path, original, "inspect-packed-directory", |native| {
        rustix::fs::statat(
            rustix::fs::CWD,
            native,
            if nofollow {
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW
            } else {
                rustix::fs::AtFlags::empty()
            },
        )
        .map_err(|source| StoreError::StreamIo {
            operation: "inspect-packed-directory",
            source: source.into(),
        })
    })
}

fn initialize(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let _lifecycle =
        checked_io::create_lock(backend, LIFECYCLE_LOCK_FILE, false, original, boundary)?;
    let _state = checked_io::create_lock(backend, STATE_LOCK_FILE, false, original, boundary)?;
    let path = checked_io::path(&backend.admin, INDEX_FILE, original)?;
    checked_reader::check(original, boundary)?;
    let metadata = inspect_path(path.as_path(), true, original);
    checked_reader::check(original, boundary)?;
    match metadata {
        Ok(metadata) if rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file() => {
            let index = index_snapshot::IndexSnapshot::load(backend, original, boundary)?;
            validate_packs(backend, &index, original, boundary)
        }
        Ok(_) => Err(StoreError::InvalidComposition {
            reason: "packed index path is not a regular file",
        }),
        Err(StoreError::StreamIo { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            let instance = new_instance(backend, original, boundary)?;
            let initial = index_snapshot::EncodedIndex::empty(backend, instance, original)?;
            checked_publication::initialize_index(backend, original, &initial, boundary)
        }
        Err(error) => Err(error),
    }
}

fn new_instance(
    backend: &PackedBlobBackend,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<[u8; 32], StoreError> {
    let source = checked_io::open_file(
        Path::new("/dev/urandom"),
        OFlags::RDONLY,
        "read-packed-instance-randomness",
        original,
        boundary,
    )?;
    let mut random = [0_u8; 32];
    checked_io::read_exact_at(source.file(), &mut random, 0, original, boundary)?;
    let ordinal = INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = blake3::Hasher::new();
    hasher.update(INSTANCE_DOMAIN);
    hasher.update(backend.root.as_os_str().as_bytes());
    hasher.update(&std::process::id().to_be_bytes());
    hasher.update(&ordinal.to_be_bytes());
    hasher.update(&random);
    checked_reader::check(original, boundary)?;
    Ok(*hasher.finalize().as_bytes())
}

fn validate_packs(
    backend: &PackedBlobBackend,
    index: &index_snapshot::IndexSnapshot,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    maintenance::validate(
        backend,
        index,
        &mut index_io::Operation {
            original: Some(original),
            boundary,
        },
    )
}

#[cfg(test)]
mod tests;
