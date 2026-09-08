//! Restart-safe aggregate logical quota around one owned physical leaf.
//!
//! The wrapper serializes cooperating puts and administrative deletion through
//! one durable state lock. Every child mutation is preceded by a dirty state
//! record; restart repairs a dirty record by streaming the exclusively owned
//! child's inventory before admitting more work. The graph builder transfers
//! the child's administrative capability into this wrapper, so GC cannot
//! bypass quota reclamation accounting.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};

use super::directory::{create_dir_all_durable, sync_directory};
use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobStoreAdmin, ByteRange, ContentId, ImmutableBlobBackend, PlannedDeleteDisposition,
    PutReceipt, StoreError, StoreGraphConfigurationId,
};

const QUOTA_STATE_MAGIC: &[u8; 8] = b"CRUCQ001";
const QUOTA_STATE_BYTES: u64 = 89;
const QUOTA_STATE_CHECKSUM_DOMAIN: &[u8] = b"crucible.content-store.logical-quota-state.v1";
const QUOTA_BINDING_DOMAIN: &[u8] = b"crucible.content-store.logical-quota-binding.v1";
const QUOTA_LOCK_FILE: &str = "quota.lock";
const QUOTA_STATE_FILE: &str = "quota.state";
const QUOTA_STATE_STAGING_FILE: &str = "quota.state.staging";

/// Maximum physical inventory entries one quota recovery may inspect.
pub(super) const MAXIMUM_LOGICAL_QUOTA_OBJECTS: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuotaState {
    binding: [u8; 32],
    objects: u64,
    logical_bytes: u64,
    dirty: bool,
}

/// Aggregate logical quota and administrative owner for one physical leaf.
pub(super) struct LogicalQuotaStore {
    name: String,
    state_root: PathBuf,
    maximum_objects: u64,
    maximum_logical_bytes: u64,
    binding: [u8; 32],
    child: Arc<dyn ImmutableBlobBackend>,
    child_admin: Arc<dyn BlobStoreAdmin>,
}

impl LogicalQuotaStore {
    /// Opens one quota boundary and repairs an interrupted child mutation.
    pub(super) fn open(
        name: impl Into<String>,
        state_root: PathBuf,
        maximum_objects: u64,
        maximum_logical_bytes: u64,
        configuration: StoreGraphConfigurationId,
        child: Arc<dyn ImmutableBlobBackend>,
        child_admin: Arc<dyn BlobStoreAdmin>,
    ) -> Result<Self, StoreError> {
        if maximum_objects == 0
            || maximum_objects > MAXIMUM_LOGICAL_QUOTA_OBJECTS
            || maximum_logical_bytes == 0
        {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota requires nonzero object and byte limits",
            });
        }
        let name = name.into();
        let binding = quota_binding(&name, configuration, maximum_objects, maximum_logical_bytes)?;
        let store = Self {
            name,
            state_root,
            maximum_objects,
            maximum_logical_bytes,
            binding,
            child,
            child_admin,
        };
        let _lock = store.acquire_state_lock()?;
        store.load_or_recover_state(true)?;
        Ok(store)
    }

    fn acquire_state_lock(&self) -> Result<File, StoreError> {
        create_dir_all_durable(&self.state_root)?;
        let path = self.state_root.join(QUOTA_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open-logical-quota-lock",
                path: path.clone(),
                source,
            })?;
        flock(&file, FlockOperation::LockExclusive).map_err(|source| StoreError::Io {
            operation: "lock-logical-quota",
            path,
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        Ok(file)
    }

    fn load_or_recover_state(&self, reconcile_clean: bool) -> Result<QuotaState, StoreError> {
        sync_directory(&self.state_root)?;
        let path = self.state_root.join(QUOTA_STATE_FILE);
        let state = match open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => read_quota_state(File::from(descriptor), &path)?,
            Err(source) if source == rustix::io::Errno::NOENT => {
                return self.recover_state_from_child();
            }
            Err(source) => {
                return Err(StoreError::Io {
                    operation: "open-logical-quota-state",
                    path,
                    source: std::io::Error::from_raw_os_error(source.raw_os_error()),
                });
            }
        };
        if state.binding != self.binding {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota state belongs to another graph configuration",
            });
        }
        self.validate_usage(state.objects, state.logical_bytes)?;
        if state.dirty || reconcile_clean {
            self.recover_state_from_child()
        } else {
            Ok(state)
        }
    }

    fn recover_state_from_child(&self) -> Result<QuotaState, StoreError> {
        let mut fence = self.child_admin.acquire_inventory_fence()?;
        let mut objects = 0_u64;
        let mut logical_bytes = 0_u64;
        let summary = fence.visit_inventory(&mut |record| {
            objects = objects.checked_add(1).ok_or(StoreError::Quota)?;
            logical_bytes = logical_bytes
                .checked_add(record.logical_length())
                .ok_or(StoreError::Quota)?;
            self.validate_usage(objects, logical_bytes)
        })?;
        if summary.backend() != self.child.name()
            || summary.objects() != objects
            || summary.logical_bytes() != logical_bytes
        {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota child inventory summary is inconsistent",
            });
        }
        let state = QuotaState {
            binding: self.binding,
            objects,
            logical_bytes,
            dirty: false,
        };
        self.persist_state(state)?;
        Ok(state)
    }

    fn validate_usage(&self, objects: u64, logical_bytes: u64) -> Result<(), StoreError> {
        if objects > self.maximum_objects || logical_bytes > self.maximum_logical_bytes {
            Err(StoreError::Quota)
        } else {
            Ok(())
        }
    }

    fn persist_state(&self, state: QuotaState) -> Result<(), StoreError> {
        let path = self.state_root.join(QUOTA_STATE_FILE);
        let staging_path = self.state_root.join(QUOTA_STATE_STAGING_FILE);
        let result = (|| {
            let descriptor = open(
                &staging_path,
                OFlags::WRONLY
                    | OFlags::CREATE
                    | OFlags::TRUNC
                    | OFlags::CLOEXEC
                    | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|source| StoreError::Io {
                operation: "create-logical-quota-state-staging",
                path: staging_path.clone(),
                source: std::io::Error::from_raw_os_error(source.raw_os_error()),
            })?;
            let mut staging = File::from(descriptor);
            staging
                .write_all(&quota_state_bytes(state))
                .and_then(|()| staging.sync_all())
                .map_err(|source| StoreError::Io {
                    operation: "write-logical-quota-state-staging",
                    path: staging_path.clone(),
                    source,
                })?;
            fs::rename(&staging_path, &path).map_err(|source| StoreError::Io {
                operation: "publish-logical-quota-state",
                path: path.clone(),
                source,
            })?;
            sync_directory(&self.state_root)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        result
    }

    fn dirty_state(&self, state: QuotaState) -> Result<(), StoreError> {
        self.persist_state(QuotaState {
            dirty: true,
            ..state
        })
    }

    fn rewrite_receipt(&self, mut receipt: PutReceipt) -> PutReceipt {
        for placement in &mut receipt.placements {
            placement.backend.clone_from(&self.name);
        }
        receipt
    }
}

impl ImmutableBlobBackend for LogicalQuotaStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.child.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let _lock = self.acquire_state_lock()?;
        let state = self.load_or_recover_state(false)?;
        if self.child.contains(id)? {
            return self
                .child
                .put_if_absent(id, source)
                .map(|receipt| self.rewrite_receipt(receipt));
        }

        let next_objects = state.objects.checked_add(1).ok_or(StoreError::Quota)?;
        let next_logical_bytes = state
            .logical_bytes
            .checked_add(source.logical_length())
            .ok_or(StoreError::Quota)?;
        self.validate_usage(next_objects, next_logical_bytes)?;
        self.dirty_state(state)?;

        let put = self.child.put_if_absent(id, source);
        let present = self.child.contains(id);
        let (next_state, committed) = match present {
            Ok(true) => {
                let logical_length = self.child.read(id, None)?.logical_length();
                let objects = state.objects.checked_add(1).ok_or(StoreError::Quota)?;
                let logical_bytes = state
                    .logical_bytes
                    .checked_add(logical_length)
                    .ok_or(StoreError::Quota)?;
                self.validate_usage(objects, logical_bytes)?;
                (
                    QuotaState {
                        binding: self.binding,
                        objects,
                        logical_bytes,
                        dirty: false,
                    },
                    true,
                )
            }
            Ok(false) => (state, false),
            Err(error) => return Err(error),
        };
        self.persist_state(next_state)?;
        match (put, committed) {
            (Ok(receipt), true) => Ok(self.rewrite_receipt(receipt)),
            (Err(error), _) => Err(error),
            (Ok(_), false) => Err(StoreError::Corrupt { id }),
        }
    }
}

impl BlobStoreAdmin for LogicalQuotaStore {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let lock = self.acquire_state_lock()?;
        let state = self.load_or_recover_state(false)?;
        let child = self.child_admin.acquire_inventory_fence()?;
        Ok(Box::new(LogicalQuotaInventoryFence {
            store: self,
            _lock: lock,
            state,
            child,
        }))
    }
}

struct LogicalQuotaInventoryFence<'a> {
    store: &'a LogicalQuotaStore,
    _lock: File,
    state: QuotaState,
    child: Box<dyn BlobInventoryFence + 'a>,
}

impl BlobInventoryFence for LogicalQuotaInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let summary = self.child.visit_inventory(visitor)?;
        if summary.backend() != self.store.child.name()
            || summary.objects() != self.state.objects
            || summary.logical_bytes() != self.state.logical_bytes
        {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota accounting differs from child inventory",
            });
        }
        Ok(BlobInventorySummary::new(
            self.store.name.clone(),
            summary.generation(),
            summary.objects(),
            summary.logical_bytes(),
        ))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.store.dirty_state(self.state)?;
        let logical_length = match self.store.child.read(id, None) {
            Ok(handle) => Some(handle.logical_length()),
            Err(StoreError::NotFound { .. }) => None,
            Err(error) => return Err(error),
        };
        let disposition = self.child.delete_candidate(id)?;
        if disposition == PlannedDeleteDisposition::AlreadyAbsent {
            self.recover_state_from_fenced_child()?;
            return Ok(disposition);
        }
        let logical_length = logical_length.ok_or(StoreError::InvalidComposition {
            reason: "logical quota deleted an object absent before deletion",
        })?;
        self.state.objects =
            self.state
                .objects
                .checked_sub(1)
                .ok_or(StoreError::InvalidComposition {
                    reason: "logical quota object accounting underflow",
                })?;
        self.state.logical_bytes = self.state.logical_bytes.checked_sub(logical_length).ok_or(
            StoreError::InvalidComposition {
                reason: "logical quota byte accounting underflow",
            },
        )?;
        self.state.dirty = false;
        self.store.persist_state(self.state)?;
        Ok(disposition)
    }
}

impl LogicalQuotaInventoryFence<'_> {
    fn recover_state_from_fenced_child(&mut self) -> Result<(), StoreError> {
        let mut objects = 0_u64;
        let mut logical_bytes = 0_u64;
        let summary = self.child.visit_inventory(&mut |record| {
            objects = objects.checked_add(1).ok_or(StoreError::Quota)?;
            logical_bytes = logical_bytes
                .checked_add(record.logical_length())
                .ok_or(StoreError::Quota)?;
            self.store.validate_usage(objects, logical_bytes)
        })?;
        if summary.backend() != self.store.child.name()
            || summary.objects() != objects
            || summary.logical_bytes() != logical_bytes
        {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota child inventory summary is inconsistent",
            });
        }
        self.state = QuotaState {
            binding: self.store.binding,
            objects,
            logical_bytes,
            dirty: false,
        };
        self.store.persist_state(self.state)
    }
}

fn quota_binding(
    name: &str,
    configuration: StoreGraphConfigurationId,
    maximum_objects: u64,
    maximum_logical_bytes: u64,
) -> Result<[u8; 32], StoreError> {
    let name_length = u64::try_from(name.len()).map_err(|_| StoreError::Quota)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(QUOTA_BINDING_DOMAIN);
    hasher.update(&name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&configuration.as_bytes());
    hasher.update(&maximum_objects.to_be_bytes());
    hasher.update(&maximum_logical_bytes.to_be_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn quota_state_bytes(state: QuotaState) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(QUOTA_STATE_BYTES as usize);
    bytes.extend_from_slice(QUOTA_STATE_MAGIC);
    bytes.extend_from_slice(&state.binding);
    bytes.extend_from_slice(&state.objects.to_be_bytes());
    bytes.extend_from_slice(&state.logical_bytes.to_be_bytes());
    bytes.push(u8::from(state.dirty));
    let mut hasher = blake3::Hasher::new();
    hasher.update(QUOTA_STATE_CHECKSUM_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

fn read_quota_state(mut file: File, path: &Path) -> Result<QuotaState, StoreError> {
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(QUOTA_STATE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| StoreError::Io {
            operation: "read-logical-quota-state",
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).map_err(|_| StoreError::Quota)? != QUOTA_STATE_BYTES
        || &bytes[..8] != QUOTA_STATE_MAGIC
    {
        return Err(StoreError::InvalidComposition {
            reason: "logical quota state has an invalid framing",
        });
    }
    let checksum_start = bytes.len() - 32;
    let mut hasher = blake3::Hasher::new();
    hasher.update(QUOTA_STATE_CHECKSUM_DOMAIN);
    hasher.update(&bytes[..checksum_start]);
    if hasher.finalize().as_bytes() != &bytes[checksum_start..] {
        return Err(StoreError::InvalidComposition {
            reason: "logical quota state checksum does not match",
        });
    }
    let binding = bytes[8..40]
        .try_into()
        .map_err(|_| StoreError::InvalidComposition {
            reason: "logical quota state binding is malformed",
        })?;
    let objects = u64::from_be_bytes(bytes[40..48].try_into().map_err(|_| {
        StoreError::InvalidComposition {
            reason: "logical quota object accounting is malformed",
        }
    })?);
    let logical_bytes = u64::from_be_bytes(bytes[48..56].try_into().map_err(|_| {
        StoreError::InvalidComposition {
            reason: "logical quota byte accounting is malformed",
        }
    })?);
    let dirty = match bytes[56] {
        0 => false,
        1 => true,
        _ => {
            return Err(StoreError::InvalidComposition {
                reason: "logical quota state has an invalid dirty flag",
            });
        }
    };
    Ok(QuotaState {
        binding,
        objects,
        logical_bytes,
        dirty,
    })
}

#[cfg(test)]
pub(super) fn mark_quota_state_dirty(root: &Path) -> Result<(), StoreError> {
    let path = root.join(QUOTA_STATE_FILE);
    let descriptor = open(
        &path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| StoreError::Io {
        operation: "open-test-logical-quota-state",
        path: path.clone(),
        source: std::io::Error::from_raw_os_error(source.raw_os_error()),
    })?;
    let mut state = read_quota_state(File::from(descriptor), &path)?;
    state.dirty = true;
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|source| StoreError::Io {
            operation: "open-test-logical-quota-state-for-write",
            path: path.clone(),
            source,
        })?;
    file.write_all(&quota_state_bytes(state))
        .and_then(|()| file.sync_all())
        .map_err(|source| StoreError::Io {
            operation: "write-test-logical-quota-state",
            path: path.clone(),
            source,
        })?;
    sync_directory(root)
}
