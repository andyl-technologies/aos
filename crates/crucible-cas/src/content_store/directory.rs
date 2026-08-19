//! Crash-safe directory leaves for immutable objects and authoritative refs.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, flock};

use super::*;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Durable loose-object directory backend.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirectoryBlobBackend {
    name: String,
    root: PathBuf,
}

impl DirectoryBlobBackend {
    /// Creates a directory backend rooted at `root`.
    #[must_use]
    pub fn new(name: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            root: root.into(),
        }
    }

    /// Returns the physical loose-object root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, id: ContentId) -> PathBuf {
        let digest = encode_digest(id.digest());
        self.root
            .join(id.kind().as_str())
            .join(id.schema_version().to_string())
            .join(&digest[..2])
            .join(digest)
    }

    fn read_full(&self, id: ContentId) -> Result<Vec<u8>, StoreError> {
        let path = self.object_path(id);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound { id });
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "open-object",
                    path,
                    source,
                });
            }
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| StoreError::Io {
                operation: "read-object",
                path,
                source,
            })?;
        validate_bytes(id, &bytes)?;
        Ok(bytes)
    }

    fn create_staging(&self, directory: &Path) -> Result<(PathBuf, File), StoreError> {
        loop {
            let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".staging-{}-{ordinal}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "create-object-staging",
                        path,
                        source,
                    });
                }
            }
        }
    }
}

impl ImmutableBlobBackend for DirectoryBlobBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            range_read: true,
            conditional_create: true,
            streaming_put: false,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_full(id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        slice_range(self.read_full(id)?, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        validate_bytes(id, bytes)?;
        let path = self.object_path(id);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "object path has no containing directory",
        })?;
        create_dir_all_durable(directory)?;

        if path.exists() {
            self.read_full(id)?;
            sync_directory(directory)?;
            return Ok(directory_receipt(&self.name, id, bytes.len()));
        }

        let (staging_path, mut staging) = self.create_staging(directory)?;
        let publish_result = (|| {
            staging.write_all(bytes).map_err(|source| StoreError::Io {
                operation: "write-object-staging",
                path: staging_path.clone(),
                source,
            })?;
            staging.sync_all().map_err(|source| StoreError::Io {
                operation: "sync-object-staging",
                path: staging_path.clone(),
                source,
            })?;

            match fs::hard_link(&staging_path, &path) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    self.read_full(id)?;
                }
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "publish-object",
                        path: path.clone(),
                        source,
                    });
                }
            }
            sync_directory(directory)?;
            Ok(())
        })();

        let remove_result = fs::remove_file(&staging_path);
        if let Err(source) = remove_result
            && source.kind() != io::ErrorKind::NotFound
            && publish_result.is_ok()
        {
            return Err(StoreError::Io {
                operation: "remove-object-staging",
                path: staging_path,
                source,
            });
        }
        publish_result?;
        Ok(directory_receipt(&self.name, id, bytes.len()))
    }
}

/// Durable authoritative ref backend using flock and atomic replacement.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirectoryRefBackend {
    root: PathBuf,
}

impl DirectoryRefBackend {
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

    fn ref_path(&self, name: &RefName) -> PathBuf {
        self.root.join("refs").join(name.as_str())
    }

    fn lock_path(&self, name: &RefName) -> PathBuf {
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

    fn read_unlocked(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let path = self.ref_path(name);
        let value = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "read-ref",
                    path,
                    source,
                });
            }
        };
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
    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let _lock = self.acquire_lock(name, FlockOperation::LockShared)?;
        self.read_unlocked(name)
    }

    fn compare_exchange(
        &self,
        name: &RefName,
        expected: Option<ContentId>,
        next: ContentId,
    ) -> Result<RefCasOutcome, StoreError> {
        let _lock = self.acquire_lock(name, FlockOperation::LockExclusive)?;
        let current = self.read_unlocked(name)?;
        if current != expected {
            return Ok(RefCasOutcome::Conflict { expected, current });
        }
        self.publish_ref(name, next)?;
        Ok(RefCasOutcome::Advanced { next })
    }
}

fn directory_receipt(name: &str, id: ContentId, logical_length: usize) -> PutReceipt {
    PutReceipt::one(
        id,
        PlacementReceipt {
            backend: name.to_owned(),
            durable: true,
            logical_length: logical_length as u64,
        },
    )
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
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

fn create_dir_all_durable(path: &Path) -> Result<(), StoreError> {
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

fn encode_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
