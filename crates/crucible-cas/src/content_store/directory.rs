//! Crash-safe directory leaves for immutable objects and authoritative refs.
//!
//! Loose objects and administrative inventory state use this on-disk layout:
//!
//! ```text
//! <blob-root>/<kind>/<schema-version>/<digest-prefix>/<digest>
//! <blob-root>/.inventory-admin/lock
//! <blob-root>/.inventory-admin/state-v1
//! <ref-root>/refs/<validated RefName>
//! <ref-root>/.ref-admin/lock
//! <ref-root>/.ref-admin/publication-lock
//! <ref-root>/.ref-admin/state-v1
//! ```
//!
//! `state-v1` is canonical UTF-8 text. It contains `version`, a persistent
//! random backend `instance`, a monotonic `generation`, and a BLAKE3 checksum
//! over the preceding fields under the
//! `crucible.content-store.directory-inventory-state.v1` domain. Ref inventory
//! state uses the same field grammar under the registered
//! `crucible.content-store.directory-ref-inventory-state.v1` domain.
//! Cooperating object puts, ref replacements, and administrative enumeration
//! serialize on their corresponding lock. Repository transactions also retain
//! a shared `publication-lock` from before their first immutable child write
//! through their final ref comparison; ref inventory takes the exclusive side.
//! Neither root may be mutated by an uncooperating process. State readers reject
//! input larger than 256 bytes before retaining more input.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, flock};

use super::admin::{InventoryCounter, persistent_inventory_generation};
use super::*;

mod ref_admin;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);
static INVENTORY_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

const INVENTORY_ADMIN_DIRECTORY: &str = ".inventory-admin";
const INVENTORY_LOCK_FILE: &str = "lock";
const INVENTORY_STATE_FILE: &str = "state-v1";
const INVENTORY_STATE_DOMAIN: &str = "crucible.content-store.directory-inventory-state.v1";
const MAX_INVENTORY_STATE_BYTES: u64 = 256;
const MAX_REF_RECORD_BYTES: u64 = 256;

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

    pub(super) fn object_path(&self, id: ContentId) -> PathBuf {
        let digest = encode_digest(id.digest());
        self.root
            .join(id.kind().as_str())
            .join(id.schema_version().to_string())
            .join(&digest[..2])
            .join(digest)
    }

    fn read_handle(
        &self,
        id: ContentId,
        range: Option<ByteRange>,
    ) -> Result<BlobHandle, StoreError> {
        let path = self.object_path(id);
        let (file, logical_length) = open_pinned_object(&path, id)?;
        let range = range.unwrap_or(ByteRange {
            offset: 0,
            length: logical_length,
        });
        validate_range(logical_length, range)?;
        let source: Arc<dyn BlobSource> = Arc::new(DirectoryBlobSource {
            file,
            id,
            logical_length,
            range,
        });
        if range.offset == 0 && range.length == logical_length {
            Ok(BlobHandle::authenticated(id, source))
        } else {
            Ok(BlobHandle::integrity_checked(id, source))
        }
    }

    pub(super) fn create_staging(&self, directory: &Path) -> Result<(PathBuf, File), StoreError> {
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

    fn inventory_admin_directory(&self) -> PathBuf {
        self.root.join(INVENTORY_ADMIN_DIRECTORY)
    }

    pub(super) fn acquire_inventory_lock(&self) -> Result<File, StoreError> {
        let directory = self.inventory_admin_directory();
        create_dir_all_durable(&directory)?;
        let path = directory.join(INVENTORY_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-inventory-lock",
                path: path.clone(),
                source,
            })?;
        flock(&file, FlockOperation::LockExclusive).map_err(|source| StoreError::Io {
            operation: "lock-inventory",
            path,
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Ok(file)
    }

    pub(super) fn load_or_create_inventory_state(
        &self,
    ) -> Result<DirectoryInventoryState, StoreError> {
        let directory = self.inventory_admin_directory();
        let path = directory.join(INVENTORY_STATE_FILE);
        match File::open(&path) {
            Ok(file) => read_inventory_state(file, &path),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let state = DirectoryInventoryState {
                    instance: new_inventory_instance(&self.root)?,
                    generation: 1,
                };
                persist_inventory_state(&directory, &path, state)?;
                Ok(state)
            }
            Err(source) => Err(StoreError::Io {
                operation: "read-inventory-state",
                path,
                source,
            }),
        }
    }

    pub(super) fn advance_inventory_state(
        &self,
        state: &mut DirectoryInventoryState,
    ) -> Result<(), StoreError> {
        state.generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
        let directory = self.inventory_admin_directory();
        let path = directory.join(INVENTORY_STATE_FILE);
        persist_inventory_state(&directory, &path, *state)
    }
}

impl ImmutableBlobBackend for DirectoryBlobBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            durable: true,
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: false,
            planned_delete: false,
        }
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_handle(id, None) {
            Ok(handle) => {
                validate_source(id, &handle)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_handle(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let _inventory_lock = self.acquire_inventory_lock()?;
        let mut inventory_state = self.load_or_create_inventory_state()?;
        self.advance_inventory_state(&mut inventory_state)?;
        let path = self.object_path(id);
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "object path has no containing directory",
        })?;
        create_dir_all_durable(directory)?;

        if path.exists() {
            source.verified_as(id)?;
            if !self.contains(id)? {
                return Err(StoreError::NotFound { id });
            }
            sync_directory(directory)?;
            return Ok(directory_receipt(&self.name, id, source.logical_length()));
        }

        let (staging_path, mut staging) = self.create_staging(directory)?;
        let publish_result = (|| {
            let authenticated_length = copy_source(id, source, &mut staging)?;
            staging.sync_all().map_err(|source| StoreError::Io {
                operation: "sync-object-staging",
                path: staging_path.clone(),
                source,
            })?;

            match fs::hard_link(&staging_path, &path) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    if !self.contains(id)? {
                        return Err(StoreError::NotFound { id });
                    }
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
            Ok(authenticated_length)
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
        let authenticated_length = publish_result?;
        Ok(directory_receipt(&self.name, id, authenticated_length))
    }
}

impl BlobStoreAdmin for DirectoryBlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lock = self.acquire_inventory_lock()?;
        let state = self.load_or_create_inventory_state()?;
        Ok(Box::new(DirectoryBlobInventoryFence {
            backend: self,
            _lock: lock,
            state,
        }))
    }
}

#[derive(Clone, Copy)]
pub(super) struct DirectoryInventoryState {
    pub(super) instance: [u8; 32],
    pub(super) generation: u64,
}

struct DirectoryBlobInventoryFence<'a> {
    backend: &'a DirectoryBlobBackend,
    _lock: File,
    state: DirectoryInventoryState,
}

impl BlobInventoryFence for DirectoryBlobInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let generation = persistent_inventory_generation(
            &self.backend.name,
            self.state.instance,
            self.state.generation,
        )?;
        let mut inventory = InventoryCounter::new(generation);
        visit_directory_inventory(&self.backend.root, visitor, &mut inventory)?;
        Ok(inventory.finish(self.backend.name.clone()))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.backend.advance_inventory_state(&mut self.state)?;
        let path = self.backend.object_path(id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "planned loose-object candidate is not a regular file",
                });
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(PlannedDeleteDisposition::AlreadyAbsent);
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "inspect-delete-candidate",
                    path,
                    source,
                });
            }
        }
        fs::remove_file(&path).map_err(|source| StoreError::Io {
            operation: "remove-planned-object",
            path: path.clone(),
            source,
        })?;
        let directory = path.parent().ok_or(StoreError::InvalidComposition {
            reason: "planned loose-object candidate has no parent directory",
        })?;
        sync_directory(directory)?;
        Ok(PlannedDeleteDisposition::Deleted)
    }
}

fn visit_directory_inventory(
    root: &Path,
    visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    inventory: &mut InventoryCounter,
) -> Result<(), StoreError> {
    for kind_entry in read_directory_entries(root, "read-inventory-root")? {
        let kind_entry = inventory_directory_entry(kind_entry, root, "read-inventory-root")?;
        let kind_path = kind_entry.path();
        let kind_name = path_name(&kind_path)?;
        if kind_name == INVENTORY_ADMIN_DIRECTORY {
            require_directory(&kind_path)?;
            continue;
        }
        let kind = ObjectKind::parse(kind_name).ok_or(StoreError::InvalidComposition {
            reason: "inventory contains an unknown object-kind directory",
        })?;
        require_directory(&kind_path)?;

        for version_entry in read_directory_entries(&kind_path, "read-inventory-kind")? {
            let version_entry =
                inventory_directory_entry(version_entry, &kind_path, "read-inventory-kind")?;
            let version_path = version_entry.path();
            require_directory(&version_path)?;
            let version_name = path_name(&version_path)?;
            let version = version_name
                .parse::<u32>()
                .ok()
                .filter(|version| version.to_string() == version_name)
                .ok_or(StoreError::InvalidComposition {
                    reason: "inventory contains a noncanonical schema-version directory",
                })?;

            for prefix_entry in read_directory_entries(&version_path, "read-inventory-version")? {
                let prefix_entry = inventory_directory_entry(
                    prefix_entry,
                    &version_path,
                    "read-inventory-version",
                )?;
                let prefix_path = prefix_entry.path();
                require_directory(&prefix_path)?;
                let prefix = path_name(&prefix_path)?;
                if prefix.len() != 2 || !prefix.bytes().all(is_lower_hex) {
                    return Err(StoreError::InvalidComposition {
                        reason: "inventory contains a noncanonical digest-prefix directory",
                    });
                }

                for object_entry in read_directory_entries(&prefix_path, "read-inventory-prefix")? {
                    let object_entry = inventory_directory_entry(
                        object_entry,
                        &prefix_path,
                        "read-inventory-prefix",
                    )?;
                    let object_path = object_entry.path();
                    let metadata =
                        fs::symlink_metadata(&object_path).map_err(|source| StoreError::Io {
                            operation: "inspect-inventory-object",
                            path: object_path.clone(),
                            source,
                        })?;
                    if !metadata.file_type().is_file() {
                        return Err(StoreError::InvalidComposition {
                            reason: "inventory object is not a regular file",
                        });
                    }
                    let digest = path_name(&object_path)?;
                    if digest.len() != 64
                        || !digest.bytes().all(is_lower_hex)
                        || !digest.starts_with(prefix)
                    {
                        return Err(StoreError::InvalidComposition {
                            reason: "inventory contains a noncanonical object digest",
                        });
                    }
                    let id =
                        ContentId::parse(&format!("{}.{}.{}", kind.as_str(), version, digest))?;
                    let record = BlobInventoryRecord::new(id, metadata.len());
                    inventory.push(record)?;
                    visitor(record)?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn inventory_directory_entry(
    entry: io::Result<fs::DirEntry>,
    directory: &Path,
    operation: &'static str,
) -> Result<fs::DirEntry, StoreError> {
    entry.map_err(|source| StoreError::Io {
        operation,
        path: directory.to_path_buf(),
        source,
    })
}

pub(super) fn read_directory_entries(
    path: &Path,
    operation: &'static str,
) -> Result<fs::ReadDir, StoreError> {
    fs::read_dir(path).map_err(|source| StoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

pub(super) fn require_directory(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| StoreError::Io {
        operation: "inspect-inventory-directory",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(StoreError::InvalidComposition {
            reason: "inventory path component is not a directory",
        })
    }
}

pub(super) fn path_name(path: &Path) -> Result<&str, StoreError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or(StoreError::InvalidComposition {
            reason: "inventory path component is not canonical UTF-8",
        })
}

pub(super) fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn new_inventory_instance(root: &Path) -> Result<[u8; 32], StoreError> {
    let ordinal = INVENTORY_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let random_path = Path::new("/dev/urandom");
    let mut random = [0_u8; 32];
    File::open(random_path)
        .and_then(|mut source| source.read_exact(&mut random))
        .map_err(|source| StoreError::Io {
            operation: "read-inventory-instance-randomness",
            path: random_path.to_path_buf(),
            source,
        })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.content-store.directory-inventory-instance.v1");
    hasher.update(root.as_os_str().as_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    hasher.update(&random);
    Ok(*hasher.finalize().as_bytes())
}

fn inventory_state_material(state: DirectoryInventoryState) -> String {
    format!(
        "version=1\ninstance={}\ngeneration={}\n",
        encode_digest(state.instance),
        state.generation
    )
}

fn inventory_state_bytes(state: DirectoryInventoryState) -> Vec<u8> {
    let material = inventory_state_material(state);
    let mut hasher = blake3::Hasher::new();
    hasher.update(INVENTORY_STATE_DOMAIN.as_bytes());
    hasher.update(material.as_bytes());
    format!(
        "{material}checksum={}\n",
        encode_digest(*hasher.finalize().as_bytes())
    )
    .into_bytes()
}

fn read_inventory_state(file: File, path: &Path) -> Result<DirectoryInventoryState, StoreError> {
    let mut bytes = Vec::new();
    file.take(MAX_INVENTORY_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            operation: "read-inventory-state",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)? > MAX_INVENTORY_STATE_BYTES {
        return Err(StoreError::InvalidComposition {
            reason: "directory inventory state exceeds its byte limit",
        });
    }
    parse_inventory_state(&bytes)
}

fn parse_inventory_state(bytes: &[u8]) -> Result<DirectoryInventoryState, StoreError> {
    let text = std::str::from_utf8(bytes).map_err(|_| StoreError::InvalidComposition {
        reason: "directory inventory state is not UTF-8",
    })?;
    let mut lines = text.lines();
    if lines.next() != Some("version=1") {
        return Err(StoreError::InvalidComposition {
            reason: "directory inventory state has the wrong version",
        });
    }
    let instance = lines
        .next()
        .and_then(|line| line.strip_prefix("instance="))
        .and_then(decode_digest)
        .ok_or(StoreError::InvalidComposition {
            reason: "directory inventory state has an invalid instance",
        })?;
    let generation = lines
        .next()
        .and_then(|line| line.strip_prefix("generation="))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(StoreError::InvalidComposition {
            reason: "directory inventory state has an invalid generation",
        })?;
    let checksum = lines
        .next()
        .and_then(|line| line.strip_prefix("checksum="))
        .and_then(decode_digest)
        .ok_or(StoreError::InvalidComposition {
            reason: "directory inventory state has an invalid checksum",
        })?;
    if lines.next().is_some() {
        return Err(StoreError::InvalidComposition {
            reason: "directory inventory state has trailing fields",
        });
    }
    let state = DirectoryInventoryState {
        instance,
        generation,
    };
    let material = inventory_state_material(state);
    let mut hasher = blake3::Hasher::new();
    hasher.update(INVENTORY_STATE_DOMAIN.as_bytes());
    hasher.update(material.as_bytes());
    if checksum != *hasher.finalize().as_bytes() {
        return Err(StoreError::InvalidComposition {
            reason: "directory inventory state checksum does not match",
        });
    }
    if bytes != inventory_state_bytes(state) {
        return Err(StoreError::InvalidComposition {
            reason: "directory inventory state is not canonical",
        });
    }
    Ok(state)
}

fn persist_inventory_state(
    directory: &Path,
    path: &Path,
    state: DirectoryInventoryState,
) -> Result<(), StoreError> {
    let bytes = inventory_state_bytes(state);
    let (staging_path, mut staging) = loop {
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staging_path = directory.join(format!(
            ".inventory-state-staging-{}-{ordinal}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
        {
            Ok(staging) => break (staging_path, staging),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "create-inventory-state-staging",
                    path: staging_path,
                    source,
                });
            }
        }
    };
    let result = (|| {
        staging
            .write_all(&bytes)
            .and_then(|()| staging.sync_all())
            .map_err(|source| StoreError::Io {
                operation: "write-inventory-state-staging",
                path: staging_path.clone(),
                source,
            })?;
        fs::rename(&staging_path, path).map_err(|source| StoreError::Io {
            operation: "publish-inventory-state",
            path: path.to_path_buf(),
            source,
        })?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging_path);
    }
    result
}

struct DirectoryBlobSource {
    file: Arc<File>,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
}

impl BlobSource for DirectoryBlobSource {
    fn logical_length(&self) -> u64 {
        self.range.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(AuthenticatingFileReader::new(
            self.file.clone(),
            self.id,
            self.logical_length,
            self.range,
        )))
    }
}

struct AuthenticatingFileReader {
    file: Arc<File>,
    id: ContentId,
    logical_length: u64,
    range: ByteRange,
    scan_offset: u64,
    output_offset: u64,
    hasher: blake3::Hasher,
    finalized: bool,
}

impl AuthenticatingFileReader {
    fn new(file: Arc<File>, id: ContentId, logical_length: u64, range: ByteRange) -> Self {
        Self {
            file,
            id,
            logical_length,
            range,
            scan_offset: 0,
            output_offset: 0,
            hasher: content_hasher(id.kind(), id.schema_version(), logical_length),
            finalized: false,
        }
    }

    fn scan_until(&mut self, target: u64) -> io::Result<()> {
        let mut buffer = [0_u8; 64 * 1024];
        while self.scan_offset < target {
            let remaining = target - self.scan_offset;
            let limit = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| invalid_object_data())?;
            let read = read_at_retry(&self.file, &mut buffer[..limit], self.scan_offset)?;
            if read == 0 {
                return Err(invalid_object_data());
            }
            self.hasher.update(&buffer[..read]);
            self.scan_offset += read as u64;
        }
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<()> {
        self.scan_until(self.logical_length)?;
        let mut extra = [0_u8; 1];
        if read_at_retry(&self.file, &mut extra, self.logical_length)? != 0
            || *self.hasher.finalize().as_bytes() != self.id.digest()
        {
            return Err(invalid_object_data());
        }
        self.finalized = true;
        Ok(())
    }
}

impl Read for AuthenticatingFileReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.finalized {
            return Ok(0);
        }
        self.scan_until(self.range.offset)?;
        if self.output_offset < self.range.length {
            let remaining = self.range.length - self.output_offset;
            let limit = usize::try_from(remaining.min(output.len() as u64))
                .map_err(|_| invalid_object_data())?;
            let read = read_at_retry(
                &self.file,
                &mut output[..limit],
                self.range.offset + self.output_offset,
            )?;
            if read == 0 {
                return Err(invalid_object_data());
            }
            self.hasher.update(&output[..read]);
            self.scan_offset += read as u64;
            self.output_offset += read as u64;
            return Ok(read);
        }
        self.finalize()?;
        Ok(0)
    }
}

fn read_at_retry(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    loop {
        match file.read_at(buffer, offset) {
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn invalid_object_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "content authentication failed")
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

    fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard + '_>, StoreError> {
        let lock = self.acquire_ref_publication_lock(FlockOperation::LockShared)?;
        Ok(Box::new(DirectoryRefPublicationGuard { _lock: lock }))
    }

    fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
        let _inventory_lock = self.acquire_ref_inventory_lock(FlockOperation::LockShared)?;
        let _lock = self.acquire_lock(name, FlockOperation::LockShared)?;
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
        let _lock = self.acquire_lock(name, FlockOperation::LockExclusive)?;
        let current = self.read_unlocked(name)?;
        if current != expected {
            return Ok(RefCasOutcome::Conflict { expected, current });
        }
        self.advance_ref_inventory_state(&mut inventory_state)?;
        self.publish_ref(name, next)?;
        Ok(RefCasOutcome::Advanced { next })
    }
}

struct DirectoryRefPublicationGuard {
    _lock: File,
}

impl RefPublicationGuard for DirectoryRefPublicationGuard {}

pub(super) fn directory_receipt(name: &str, id: ContentId, logical_length: u64) -> PutReceipt {
    PutReceipt::one(
        id,
        PlacementReceipt {
            backend: name.to_owned(),
            durable: true,
            logical_length,
        },
    )
}

fn open_pinned_object(path: &Path, id: ContentId) -> Result<(Arc<File>, u64), StoreError> {
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

pub(super) fn sync_directory(path: &Path) -> Result<(), StoreError> {
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

pub(super) fn create_dir_all_durable(path: &Path) -> Result<(), StoreError> {
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
