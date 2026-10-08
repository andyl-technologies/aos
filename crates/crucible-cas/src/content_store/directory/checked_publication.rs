//! Conditional file publication with retained original failures and durability.

use super::*;
use crate::content_store::checked_reader;
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Reports observed object visibility and directory durability for a batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectoryPublicationOutcome {
    /// Number of successful new conditional hard links in this operation.
    pub published_objects: u8,
    /// Number of input objects authenticated and covered by a successful sync.
    pub durable_objects: u8,
    /// Indicates unconfirmed visibility or directory durability after publication.
    pub durability_uncertain: bool,
}

/// Retains filesystem work, cleanup, and publication evidence together.
pub struct DirectoryScopeError {
    body: Box<Failure>,
    _credit: DecodeScratch,
}

struct Failure {
    work: Option<StoreError>,
    cleanup: Option<StoreError>,
    outcome: DirectoryPublicationOutcome,
    _diagnostic: Option<DecodeScratch>,
}

impl DirectoryScopeError {
    /// Borrows the first original work failure, if work failed.
    #[must_use]
    pub fn work_failure(&self) -> Option<&StoreError> {
        self.body.work.as_ref()
    }

    /// Borrows an independently failed staging cleanup, if cleanup failed.
    #[must_use]
    pub fn cleanup_failure(&self) -> Option<&StoreError> {
        self.body.cleanup.as_ref()
    }

    /// Returns the observed outcome while its original causes remain owned.
    #[must_use]
    pub fn outcome(&self) -> DirectoryPublicationOutcome {
        self.body.outcome
    }
}

impl std::fmt::Debug for DirectoryScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectoryScopeError")
            .field("work", &self.body.work)
            .field("cleanup", &self.body.cleanup)
            .field("outcome", &self.body.outcome)
            .finish()
    }
}

impl std::fmt::Display for DirectoryScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "checked directory scope failed ({:?})",
            self.body.outcome
        )
    }
}

impl std::error::Error for DirectoryScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.work_failure()
            .or_else(|| self.cleanup_failure())
            .map(|error| error as _)
    }
}

pub(in crate::content_store) struct Accepted<T> {
    value: T,
    outcome: DirectoryPublicationOutcome,
    diagnostic: Option<DecodeScratch>,
    credit: DecodeScratch,
}

impl<T> Accepted<T> {
    pub(in crate::content_store) fn value(&self) -> &T {
        &self.value
    }

    pub(in crate::content_store) fn release_diagnostic(&mut self) {
        self.diagnostic = None;
    }

    pub(in crate::content_store) fn check(
        mut self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        match check(&mut self.value) {
            Ok(()) => Ok(self),
            Err(error) => {
                let Self {
                    value,
                    outcome,
                    diagnostic,
                    credit,
                } = self;
                drop(value);
                Err(scope_error(Some(error), None, outcome, diagnostic, credit))
            }
        }
    }
}

fn scope_error(
    work: Option<StoreError>,
    cleanup: Option<StoreError>,
    outcome: DirectoryPublicationOutcome,
    diagnostic: Option<DecodeScratch>,
    credit: DecodeScratch,
) -> StoreError {
    StoreError::DirectoryScope {
        source: DirectoryScopeError {
            body: Box::new(Failure {
                work,
                cleanup,
                outcome,
                _diagnostic: diagnostic,
            }),
            _credit: credit,
        },
    }
}

#[derive(Default)]
struct Progress {
    outcome: DirectoryPublicationOutcome,
    cleanup: Option<StoreError>,
    cleanup_only: bool,
}

pub(super) fn publish(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    objects: &[(ContentId, BlobHandle)],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<PutBatchReceipt, StoreError> {
    checked_reader::check(original, boundary)?;
    if objects.len() > 64 {
        return Err(StoreError::Quota);
    }
    let receipt_credit = batch::admit_receipts(original, objects.len(), backend.name.len())?;
    let operation_bytes =
        DirectoryBlobBackend::quota_resource_costs(&backend.root)?.operation_bytes;
    let credit = original
        .reserve_scratch_bytes(std::mem::size_of::<Failure>() as u64)
        .map_err(|error| batch::admission_under(original, error))?;
    let diagnostic = original
        .reserve_scratch_bytes(operation_bytes)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut progress = Progress::default();
    let result = (|| {
        let mut check = || checked_reader::check(original, boundary);
        let _lock = lock_inventory(backend, original, &mut check)?;
        let mut state = load_state(backend, &mut check, &mut progress)?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(objects.len())
            .map_err(|error| batch::allocation_under(original, error))?;
        for (id, source) in objects {
            check()?;
            publish_one(
                backend,
                original,
                *id,
                source,
                &mut state,
                &mut progress,
                &mut check,
            )?;
            receipts.push(directory_receipt(
                &backend.name,
                *id,
                source.logical_length(),
            ));
            check()?;
        }
        check()?;
        Ok(receipts)
    })();
    match result {
        Ok(receipts) => Ok(PutBatchReceipt::new_directory(
            Accepted {
                value: receipts,
                outcome: progress.outcome,
                diagnostic: Some(diagnostic),
                credit,
            },
            receipt_credit,
            original.clone(),
        )),
        Err(error) => {
            let work = if progress.cleanup_only {
                None
            } else {
                Some(error)
            };
            Err(scope_error(
                work,
                progress.cleanup,
                progress.outcome,
                Some(diagnostic),
                credit,
            ))
        }
    }
}

fn publish_one(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    state: &mut DirectoryInventoryState,
    progress: &mut Progress,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    check()?;
    let path = super::checked::object_path(backend, original, id)?;
    let directory = path.parent().ok_or(StoreError::InvalidComposition {
        reason: "object path has no containing directory",
    })?;
    ensure_directory(directory, original, check)?;
    match fs::metadata(&path) {
        Ok(_) => {
            authenticate_source(original, id, source, check)?;
            authenticate_stored(backend, original, id, check)?;
            sync(directory, check)?;
            progress.outcome.durable_objects += 1;
            check()?;
            return Ok(());
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspect-object", &path, source)),
    }
    check()?;
    state.generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
    persist_state(backend, *state, check, progress)?;
    let (staging_path, mut staging) = staging(directory, ".staging", check)?;
    let result = (|| {
        copy_checked(original, id, source, &mut staging, &staging_path, check)?;
        check()?;
        staging
            .sync_all()
            .map_err(|source| io_error("sync-object-staging", &staging_path, source))?;
        check()?;
        match fs::hard_link(&staging_path, &path) {
            Ok(()) => {
                progress.outcome.published_objects += 1;
                progress.outcome.durability_uncertain = true;
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                authenticate_stored(backend, original, id, check)?;
            }
            Err(source) => {
                // Remote filesystems can report an interrupted or failed link
                // after applying it. This scope cannot certify nonpublication.
                progress.outcome.durability_uncertain = true;
                return Err(io_error("publish-object", &path, source));
            }
        }
        check()?;
        sync(directory, check)?;
        progress.outcome.durable_objects += 1;
        progress.outcome.durability_uncertain = false;
        check()
    })();
    drop(staging);
    let removal = remove_staging(&staging_path);
    match (result, removal) {
        (Err(work), Err(failure)) => {
            progress.cleanup = Some(failure);
            Err(work)
        }
        (Err(work), Ok(())) => Err(work),
        (Ok(()), Err(failure)) => {
            progress.cleanup_only = true;
            progress.cleanup = Some(failure);
            Err(StoreError::Unavailable)
        }
        (Ok(()), Ok(())) => check(),
    }
}

fn authenticate_source(
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut sink = io::sink();
    copy_checked(original, id, source, &mut sink, Path::new(""), check)
}

fn authenticate_stored(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    id: ContentId,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let source = super::checked::lookup(backend, original, id, None, check)?;
    authenticate_source(original, id, &source, check)
}

fn copy_checked(
    original: &DecodeBudget,
    id: ContentId,
    source: &BlobHandle,
    sink: &mut dyn Write,
    path: &Path,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    check()?;
    let mut reader = BlobSource::open_with_boundary(source, original, check)?;
    let source_account = reader.original_account().clone();
    let credit = source_account
        .reserve_scratch_bytes(64 * 1024)
        .map_err(|error| batch::admission_under(&source_account, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(64 * 1024)
        .map_err(|error| batch::allocation_under(&source_account, error))?;
    bytes.resize(64 * 1024, 0);
    // A full handle and its audited reader authenticate these exact output
    // bytes at EOF. A range reader authenticates hidden bytes as well, so its
    // underlying identity alone cannot authorize publishing the exposed range.
    let mut hasher = (source.authenticated_id != Some(id)
        || reader.full_eof_identity() != Some(id))
    .then(|| content_hasher(id.kind(), id.schema_version(), source.logical_length()));
    let mut length = 0_u64;
    loop {
        check()?;
        let read = reader.read_with_boundary(&mut bytes, check)?;
        if read == 0 {
            break;
        }
        length = length.checked_add(read as u64).ok_or(StoreError::Quota)?;
        if length > source.logical_length() {
            return Err(StoreError::Corrupt { id });
        }
        if let Some(hasher) = &mut hasher {
            hasher.update(&bytes[..read]);
        }
        let mut written = 0;
        while written < read {
            check()?;
            match sink.write(&bytes[written..read]) {
                Ok(0) => {
                    return Err(io_error(
                        "write-object-staging",
                        path,
                        io::Error::from(io::ErrorKind::WriteZero),
                    ));
                }
                Ok(count) => written += count,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => return Err(io_error("write-object-staging", path, source)),
            }
            check()?;
        }
    }
    if length != source.logical_length()
        || hasher.is_some_and(|hasher| *hasher.finalize().as_bytes() != id.digest())
    {
        return Err(StoreError::Corrupt { id });
    }
    check()?;
    drop(bytes);
    drop(credit);
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn remove_staging(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-object-staging", path, source)),
    }
}

fn sync(path: &Path, check: &mut dyn FnMut() -> Result<(), StoreError>) -> Result<(), StoreError> {
    check()?;
    let directory =
        File::open(path).map_err(|source| io_error("open-directory-for-sync", path, source))?;
    check()?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync-directory", path, source))?;
    Ok(())
}

fn ensure_directory(
    path: &Path,
    original: &DecodeBudget,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let count = path.ancestors().count();
    let _credit = original
        .reserve_scratch_array::<&Path>(count)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(count)
        .map_err(|error| batch::allocation_under(original, error))?;
    ancestors.extend(
        path.ancestors()
            .filter(|ancestor| !ancestor.as_os_str().is_empty()),
    );
    for directory in ancestors.into_iter().rev() {
        check()?;
        match fs::metadata(directory) {
            Ok(metadata) if metadata.is_dir() => continue,
            Ok(_) => {
                return Err(io_error(
                    "create-directory",
                    directory,
                    io::Error::from(io::ErrorKind::AlreadyExists),
                ));
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect-directory", directory, source)),
        }
        check()?;
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create-directory", directory, source)),
        }
        sync(directory, check)?;
        sync(
            directory
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
            check,
        )?;
    }
    check()
}

fn staging(
    directory: &Path,
    prefix: &str,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(PathBuf, File), StoreError> {
    loop {
        check()?;
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("{prefix}-{}-{ordinal}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create-object-staging", &path, source)),
        }
    }
}

fn lock_inventory(
    backend: &DirectoryBlobBackend,
    original: &DecodeBudget,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<File, StoreError> {
    let directory = backend.inventory_admin_directory();
    ensure_directory(&directory, original, check)?;
    let path = directory.join(INVENTORY_LOCK_FILE);
    check()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| io_error("open-inventory-lock", &path, source))?;
    loop {
        check()?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                check()?;
                return Ok(file);
            }
            Err(source)
                if source == rustix::io::Errno::WOULDBLOCK || source == rustix::io::Errno::INTR =>
            {
                std::thread::yield_now();
            }
            Err(source) => {
                return Err(io_error(
                    "lock-inventory",
                    &path,
                    io::Error::from_raw_os_error(source.raw_os_error()),
                ));
            }
        }
    }
}

fn load_state(
    backend: &DirectoryBlobBackend,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    progress: &mut Progress,
) -> Result<DirectoryInventoryState, StoreError> {
    let path = backend
        .inventory_admin_directory()
        .join(INVENTORY_STATE_FILE);
    check()?;
    match File::open(&path) {
        Ok(mut file) => {
            let mut bytes = [0_u8; MAX_INVENTORY_STATE_BYTES as usize + 1];
            let mut length = 0;
            while length < bytes.len() {
                check()?;
                match file.read(&mut bytes[length..]) {
                    Ok(0) => break,
                    Ok(count) => length += count,
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                    Err(source) => return Err(io_error("read-inventory-state", &path, source)),
                }
            }
            check()?;
            parse_inventory_state(&bytes[..length])
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            check()?;
            let state = DirectoryInventoryState {
                instance: new_instance(&backend.root, check)?,
                generation: 1,
            };
            check()?;
            persist_state(backend, state, check, progress)?;
            Ok(state)
        }
        Err(source) => Err(io_error("read-inventory-state", &path, source)),
    }
}

fn new_instance(
    root: &Path,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<[u8; 32], StoreError> {
    let ordinal = INVENTORY_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = Path::new("/dev/urandom");
    check()?;
    let mut file = File::open(path)
        .map_err(|source| io_error("read-inventory-instance-randomness", path, source))?;
    let mut random = [0_u8; 32];
    let mut offset = 0;
    while offset < random.len() {
        check()?;
        match file.read(&mut random[offset..]) {
            Ok(0) => {
                return Err(io_error(
                    "read-inventory-instance-randomness",
                    path,
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                ));
            }
            Ok(count) => offset += count,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(io_error("read-inventory-instance-randomness", path, source));
            }
        }
    }
    check()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.directory-inventory-instance.v1");
    hasher.update(root.as_os_str().as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    hasher.update(&random);
    Ok(*hasher.finalize().as_bytes())
}

fn persist_state(
    backend: &DirectoryBlobBackend,
    state: DirectoryInventoryState,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    progress: &mut Progress,
) -> Result<(), StoreError> {
    let directory = backend.inventory_admin_directory();
    let path = directory.join(INVENTORY_STATE_FILE);
    let bytes = inventory_state_bytes(state);
    let (staging_path, mut file) = staging(&directory, ".inventory-state-staging", check)?;
    let result = (|| {
        let mut written = 0;
        while written < bytes.len() {
            check()?;
            match file.write(&bytes[written..]) {
                Ok(0) => {
                    return Err(io_error(
                        "write-inventory-state-staging",
                        &staging_path,
                        io::Error::from(io::ErrorKind::WriteZero),
                    ));
                }
                Ok(count) => written += count,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(io_error(
                        "write-inventory-state-staging",
                        &staging_path,
                        source,
                    ));
                }
            }
        }
        check()?;
        file.sync_all()
            .map_err(|source| io_error("sync-inventory-state-staging", &staging_path, source))?;
        check()?;
        fs::rename(&staging_path, &path)
            .map_err(|source| io_error("publish-inventory-state", &path, source))?;
        sync(&directory, check)
    })();
    drop(file);
    match (result, remove_staging(&staging_path)) {
        (Err(work), Err(failure)) => {
            progress.cleanup = Some(failure);
            Err(work)
        }
        (Err(work), Ok(())) => Err(work),
        (Ok(()), Err(failure)) => {
            progress.cleanup_only = true;
            progress.cleanup = Some(failure);
            Err(StoreError::Unavailable)
        }
        (Ok(()), Ok(())) => check(),
    }
}
