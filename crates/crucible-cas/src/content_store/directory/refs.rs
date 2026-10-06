//! Durable filesystem-backed mutable references and shared directory durability helpers.

use super::*;

/// Durable authoritative ref backend using flock and atomic replacement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirectoryRefBackend {
    pub(super) root: PathBuf,
}

impl DirectoryRefBackend {
    /// Creates a quota-bound ref facade with admitted operation and fence loans.
    ///
    /// # Errors
    /// Refuses unavailable authority or insufficient original resources.
    pub fn new_with_physical_quota(
        root: impl Into<PathBuf>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
    ) -> Result<Arc<dyn MutableRefBackend>, StoreError> {
        let root = root.into();
        guard.verify()?;
        let resources = guard.reserve_resources(
            0,
            std::mem::size_of::<QuotaDirectoryRefs>() as u64
                + 2 * std::mem::size_of::<usize>() as u64
                + root.capacity() as u64,
        )?;
        Ok(Arc::new(QuotaDirectoryRefs {
            child: Self::new(root),
            guard,
            _resources: resources,
        }))
    }

    /// Creates a ref backend rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the authoritative ref root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn ref_path(&self, name: &RefName) -> PathBuf {
        self.root.join("refs").join(name.as_str())
    }

    pub(super) fn lock_path(&self, name: &RefName) -> PathBuf {
        let digest = blake3::hash(name.as_str().as_bytes()).to_hex();
        self.root.join("locks").join(digest.as_str())
    }

    fn acquire_lock(&self, name: &RefName, operation: FlockOperation) -> Result<File, StoreError> {
        let path = self.lock_path(name);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "ref lock has no containing directory",
        })?;
        create_dir_all_durable(directory)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-ref-lock",
                path: path.clone(),
                source,
            })?;
        flock(&file, operation).map_err(|source| StoreError::Io {
            operation: "lock-ref",
            path,
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Ok(file)
    }

    pub(super) fn read_unlocked(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let path = self.ref_path(name);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "read-ref",
                    path,
                    source,
                });
            }
        };
        let mut bytes = Vec::new();
        file.take(MAX_REF_RECORD_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| StoreError::Io {
                operation: "read-ref",
                path,
                source,
            })?;
        if u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)? > MAX_REF_RECORD_BYTES {
            return Err(StoreError::InvalidId);
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| StoreError::InvalidId)?;
        let record = value.strip_suffix('\n').ok_or(StoreError::InvalidId)?;
        if record.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(StoreError::InvalidId);
        }
        ContentId::parse(record).map(Some)
    }

    fn publish_ref(&self, name: &RefName, next: ContentId) -> Result<(), StoreError> {
        let path = self.ref_path(name);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "ref path has no containing directory",
        })?;
        create_dir_all_durable(directory)?;
        let (staging_path, mut staging) = loop {
            let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
            let staging_path =
                directory.join(format!(".ref-staging-{}-{ordinal}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging_path)
            {
                Ok(staging) => break (staging_path, staging),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "create-ref-staging",
                        path: staging_path,
                        source,
                    });
                }
            }
        };
        let record = format!("{}\n", next.encode());
        staging
            .write_all(record.as_bytes())
            .and_then(|()| staging.sync_all())
            .map_err(|source| StoreError::Io {
                operation: "write-ref-staging",
                path: staging_path.clone(),
                source,
            })?;
        fs::rename(&staging_path, &path).map_err(|source| StoreError::Io {
            operation: "publish-ref",
            path: path.clone(),
            source,
        })?;
        sync_directory(directory)
    }
}

impl MutableRefBackend for DirectoryRefBackend {
    fn capabilities(&self) -> RefBackendCapabilities {
        RefBackendCapabilities { durable: true }
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard>, StoreError> {
        let lock = self.acquire_ref_publication_lock(FlockOperation::LockShared)?;
        Ok(Box::new(DirectoryRefPublicationGuard { _lock: lock }))
    }

    fn compare_remove(
        &self,
        name: &RefName,
        expected: ContentId,
    ) -> Result<RefRemoveOutcome, StoreError> {
        let _inventory_lock = self.acquire_ref_inventory_lock(FlockOperation::LockExclusive)?;
        let mut inventory_state = self.load_or_create_ref_inventory_state()?;
        let _lock = if is_reader_claim(name) {
            None
        } else {
            Some(self.acquire_lock(name, FlockOperation::LockExclusive)?)
        };
        match self.read_unlocked(name)? {
            None => Ok(RefRemoveOutcome::AlreadyAbsent),
            Some(current) if current != expected => {
                Ok(RefRemoveOutcome::Conflict { expected, current })
            }
            Some(_) => {
                self.advance_ref_inventory_state(&mut inventory_state)?;
                let path = self.ref_path(name);
                fs::remove_file(&path).map_err(|source| StoreError::Io {
                    operation: "retire-ref",
                    path: path.clone(),
                    source,
                })?;
                let directory = path.parent().ok_or(StoreError::InvalidComposition {
                    reason: "ref retirement has no directory",
                })?;
                sync_directory(directory)?;
                Ok(RefRemoveOutcome::Removed)
            }
        }
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let _inventory_lock = self.acquire_ref_inventory_lock(FlockOperation::LockShared)?;
        let _lock = if is_reader_claim(name) {
            None
        } else {
            Some(self.acquire_lock(name, FlockOperation::LockShared)?)
        };
        self.read_unlocked(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        let _inventory_lock = self.acquire_ref_inventory_lock(FlockOperation::LockShared)?;
        ref_admin::scan_ref_namespace(self, namespace, after, limit)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let _inventory_lock = self.acquire_ref_inventory_lock(FlockOperation::LockExclusive)?;
        let mut inventory_state = self.load_or_create_ref_inventory_state()?;
        let _lock = if is_reader_claim(name) {
            None
        } else {
            Some(self.acquire_lock(name, FlockOperation::LockExclusive)?)
        };
        let current = self.read_unlocked(name)?;
        if current != expected {
            return Ok(RefCasOutcome::Conflict { expected, current });
        }
        self.advance_ref_inventory_state(&mut inventory_state)?;
        self.publish_ref(name, next)?;
        Ok(RefCasOutcome::Advanced { next })
    }
}

// Reader claims already serialize through the namespace inventory lock. Their
// unique names never need persistent per-name lock files after retirement.
fn is_reader_claim(name: &RefName) -> bool {
    name.as_str().starts_with("ram-readers/")
}

struct DirectoryRefPublicationGuard {
    _lock: File,
}

impl RefPublicationGuard for DirectoryRefPublicationGuard {}

/// Keeps ref namespace authority and resources behind the existing directory format.
struct QuotaDirectoryRefs {
    child: DirectoryRefBackend,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
    _resources: Arc<dyn Send + Sync>,
}

impl QuotaDirectoryRefs {
    fn operation_resources(&self) -> Result<Arc<dyn Send + Sync>, StoreError> {
        self.guard.verify()?;
        // Inventory/name locks, record/staging files and directory fsync can
        // overlap. Paths and bounded 256-byte records have geometric headroom.
        let bytes = (self.child.root.as_os_str().len() as u64)
            .checked_add(1024)
            .and_then(|bytes| bytes.checked_mul(32))
            .and_then(|bytes| bytes.checked_add(4096))
            .ok_or(StoreError::Quota)?;
        self.guard.reserve_resources(6, bytes)
    }
}

impl MutableRefBackend for QuotaDirectoryRefs {
    fn capabilities(&self) -> RefBackendCapabilities {
        self.child.capabilities()
    }

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard>, StoreError> {
        let _construction = self.operation_resources()?;
        let resources = self
            .guard
            .reserve_resources(1, std::mem::size_of::<QuotaRefPublicationGuard>() as u64)?;
        Ok(Box::new(QuotaRefPublicationGuard {
            _child: self.child.acquire_publication_guard()?,
            _guard: self.guard.clone(),
            _resources: resources,
        }))
    }

    fn compare_remove(
        &self,
        name: &RefName,
        expected: ContentId,
    ) -> Result<RefRemoveOutcome, StoreError> {
        let _resources = self.operation_resources()?;
        self.child.compare_remove(name, expected)
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let _resources = self.operation_resources()?;
        self.child.read_ref(name)
    }

    fn scan_refs(
        &self,
        namespace: &RefName,
        after: Option<&RefName>,
        limit: usize,
    ) -> Result<RefScanPage, StoreError> {
        validate_ref_scan_basis(namespace, after, limit)?;
        let _resources = self.operation_resources()?;
        // Only the smallest limit+1 names are retained by the ordered scan;
        // this covers both B-tree nodes and the resulting bounded vector.
        let _candidates = self.guard.reserve_resources(
            0,
            (limit as u64 + 1)
                .checked_mul(4096)
                .ok_or(StoreError::Quota)?,
        )?;
        let _lock = self
            .child
            .acquire_ref_inventory_lock(FlockOperation::LockShared)?;
        ref_admin::scan_ref_namespace_with_quota(
            &self.child,
            namespace,
            after,
            limit,
            Some(self.guard.as_ref()),
        )
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let _resources = self.operation_resources()?;
        self.child.compare_exchange(name, expected, next)
    }
}

struct QuotaRefPublicationGuard {
    _child: Box<dyn RefPublicationGuard>,
    _guard: Arc<dyn StorePhysicalQuotaGuard>,
    _resources: Arc<dyn Send + Sync>,
}

impl RefPublicationGuard for QuotaRefPublicationGuard {}

pub(in crate::content_store) fn directory_receipt(
    name: &str,
    id: ContentId,
    logical_length: u64,
) -> PutReceipt {
    PutReceipt::one(
        id,
        PlacementReceipt {
            backend: name.to_owned(),
            durable: true,
            logical_length,
        },
    )
}

pub(super) fn open_pinned_object(
    path: &Path,
    id: ContentId,
) -> Result<(Arc<File>, u64), StoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(StoreError::NotFound { id });
        }
        Err(source) => {
            return Err(StoreError::Io {
                operation: "open-object",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let logical_length = file
        .metadata()
        .map_err(|source| StoreError::Io {
            operation: "inspect-object",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    Ok((Arc::new(file), logical_length))
}

pub(in crate::content_store) fn sync_directory(path: &Path) -> Result<(), StoreError> {
    let directory = File::open(path).map_err(|source| StoreError::Io {
        operation: "open-directory-for-sync",
        path: path.to_path_buf(),
        source,
    })?;
    directory.sync_all().map_err(|source| StoreError::Io {
        operation: "sync-directory",
        path: path.to_path_buf(),
        source,
    })
}

pub(in crate::content_store) fn create_dir_all_durable(path: &Path) -> Result<(), StoreError> {
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match fs::metadata(existing) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(StoreError::Io {
                    operation: "create-directory",
                    path: existing.to_path_buf(),
                    source: io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "path component is not a directory",
                    ),
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                missing.push(existing.to_path_buf());
                existing = existing
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-directory",
                    path: existing.to_path_buf(),
                    source,
                });
            }
        }
    }

    if missing.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|source| StoreError::Io {
        operation: "create-directory",
        path: path.to_path_buf(),
        source,
    })?;
    for directory in &missing {
        sync_directory(directory)?;
    }
    sync_directory(existing)
}

pub(super) fn encode_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
