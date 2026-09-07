//! Generation-fenced administration for one strongly consistent S3 blob namespace.

use std::collections::{BTreeMap, btree_map::Entry};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak,
};

use super::*;
use crate::content_store::admin::{InventoryCounter, persistent_inventory_generation};
use crate::content_store::{
    BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary, BlobStoreAdmin,
    MAX_S3_OBJECT_LIST_ITEMS, PlannedDeleteDisposition, StoreS3ConditionalWriteOutcome,
    StoreS3ObjectVersion, StoreS3StrongCasClient, StoreS3VersionedObjectMetadata,
};

const INVENTORY_STATE_MAGIC: &[u8] = b"crucible.content-store.s3-object-inventory-state.v1\0";
const INVENTORY_STATE_CHECKSUM_DOMAIN: &[u8] =
    b"crucible.content-store.s3-object-inventory-state-checksum.v1";
const INVENTORY_STATE_SUFFIX: &str = "object-admin/state-v1";
const MAX_LIVE_BLOB_NAMESPACES: usize = 1_024;

/// Maximum committed objects visited by one fenced S3 inventory.
pub const MAX_S3_COMMITTED_OBJECT_VISITS: u64 = 65_536;

/// Outcome of one provider-enforced conditional committed-object deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreS3ConditionalDeleteOutcome {
    /// The exact version precondition held and the key is now absent.
    Deleted,
    /// The exact version precondition did not hold.
    PreconditionFailed,
}

/// Strong committed-object administration admitted separately from ordinary S3 I/O.
///
/// Implementations MUST provide strongly consistent ordered listing and
/// versioned metadata. Conditional deletion MUST atomically compare the exact
/// provider version and MUST NOT delete a different object generation. The
/// admitted bucket MUST be unversioned and retain no delete markers or
/// noncurrent versions: listing and deletion cover the current object
/// namespace, so historical provider versions would escape physical inventory
/// and reclamation.
pub trait StoreS3BlobAdminClient: StoreS3StrongCasClient {
    /// Reads exact metadata for one committed object.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, availability, or protocol error.
    fn head_versioned_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoreS3VersionedObjectMetadata>, StoreError>;

    /// Conditionally deletes one exact provider object version.
    ///
    /// # Errors
    ///
    /// Returns a classified backend error without deleting a mismatched version.
    fn delete_object_if_version(
        &self,
        bucket: &str,
        key: &str,
        expected: &StoreS3ObjectVersion,
    ) -> Result<StoreS3ConditionalDeleteOutcome, StoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BlobNamespaceKey {
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
}

pub(super) struct S3BlobLifecycle {
    backend_name: String,
    maximum_logical_object_bytes: u64,
    administrative: bool,
    publication: RwLock<()>,
    state: Mutex<()>,
}

static BLOB_NAMESPACE_LIFECYCLES: OnceLock<
    Mutex<BTreeMap<BlobNamespaceKey, Weak<S3BlobLifecycle>>>,
> = OnceLock::new();

pub(super) struct S3BlobAdministration {
    client: Arc<dyn StoreS3BlobAdminClient>,
}

pub(super) fn admit_blob_namespace(
    backend_name: &str,
    endpoint: &StoreS3EndpointId,
    bucket: &str,
    prefix: &str,
    maximum_logical_object_bytes: u64,
    administrative: bool,
) -> Result<Arc<S3BlobLifecycle>, StoreError> {
    let key = BlobNamespaceKey {
        endpoint: endpoint.clone(),
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
    };
    let registry = BLOB_NAMESPACE_LIFECYCLES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock().map_err(|_| StoreError::Poisoned {
        operation: "admit-S3-blob-administration-lifecycle",
    })?;
    registry.retain(|_, lifecycle| lifecycle.strong_count() != 0);
    if !registry.contains_key(&key) && registry.len() >= MAX_LIVE_BLOB_NAMESPACES {
        return Err(StoreError::Quota);
    }
    let lifecycle = match registry.entry(key) {
        Entry::Occupied(mut entry) => match entry.get().upgrade() {
            Some(lifecycle)
                if lifecycle.backend_name == backend_name
                    && lifecycle.maximum_logical_object_bytes == maximum_logical_object_bytes
                    && lifecycle.administrative == administrative =>
            {
                lifecycle
            }
            Some(_) => {
                return Err(StoreError::InvalidComposition {
                    reason: "S3 blob administration namespace has conflicting identity, bounds, or mode",
                });
            }
            None => {
                let lifecycle = Arc::new(S3BlobLifecycle {
                    backend_name: backend_name.to_string(),
                    maximum_logical_object_bytes,
                    administrative,
                    publication: RwLock::new(()),
                    state: Mutex::new(()),
                });
                entry.insert(Arc::downgrade(&lifecycle));
                lifecycle
            }
        },
        Entry::Vacant(entry) => {
            let lifecycle = Arc::new(S3BlobLifecycle {
                backend_name: backend_name.to_string(),
                maximum_logical_object_bytes,
                administrative,
                publication: RwLock::new(()),
                state: Mutex::new(()),
            });
            entry.insert(Arc::downgrade(&lifecycle));
            lifecycle
        }
    };
    Ok(lifecycle)
}

impl S3BlobAdministration {
    pub(super) fn new(
        endpoint: &StoreS3EndpointId,
        client: Arc<dyn StoreS3BlobAdminClient>,
    ) -> Result<Self, StoreError> {
        if client.endpoint_id() != endpoint {
            return Err(StoreError::Unauthorized);
        }
        Ok(Self { client })
    }

    fn state_key(backend: &S3BlobBackend) -> String {
        if backend.prefix.is_empty() {
            INVENTORY_STATE_SUFFIX.to_string()
        } else {
            format!("{}/{}", backend.prefix, INVENTORY_STATE_SUFFIX)
        }
    }

    fn load_state(&self, backend: &S3BlobBackend) -> Result<Option<InventoryState>, StoreError> {
        let key = Self::state_key(backend);
        self.client
            .get_small_versioned_object(&backend.bucket, &key, 4 * 1024)?
            .map(|object| {
                let (instance, generation) = decode_inventory_state(object.bytes())?;
                Ok(InventoryState {
                    instance,
                    generation,
                    version: object.version().clone(),
                })
            })
            .transpose()
    }

    fn load_or_create_state(&self, backend: &S3BlobBackend) -> Result<InventoryState, StoreError> {
        if let Some(state) = self.load_state(backend)? {
            return Ok(state);
        }
        let instance = new_inventory_instance()?;
        let generation = 1;
        let bytes = Arc::<[u8]>::from(encode_inventory_state(instance, generation));
        let key = Self::state_key(backend);
        match self
            .client
            .put_small_if_absent(&backend.bucket, &key, bytes)?
        {
            StoreS3ConditionalWriteOutcome::Committed(version) => {
                let state = self.load_state(backend)?.ok_or(StoreError::Incompatible)?;
                if state.instance != instance
                    || state.generation != generation
                    || state.version != version
                {
                    return Err(StoreError::Incompatible);
                }
                Ok(state)
            }
            StoreS3ConditionalWriteOutcome::PreconditionFailed => {
                self.load_state(backend)?.ok_or(StoreError::Incompatible)
            }
        }
    }

    fn advance_state(&self, backend: &S3BlobBackend) -> Result<InventoryState, StoreError> {
        let current = self.load_or_create_state(backend)?;
        let generation = current.generation.checked_add(1).ok_or(StoreError::Quota)?;
        let bytes = Arc::<[u8]>::from(encode_inventory_state(current.instance, generation));
        let key = Self::state_key(backend);
        match self.client.replace_small_if_version(
            &backend.bucket,
            &key,
            &current.version,
            bytes,
        )? {
            StoreS3ConditionalWriteOutcome::Committed(version) => {
                let state = self.load_state(backend)?.ok_or(StoreError::Incompatible)?;
                if state.instance != current.instance
                    || state.generation != generation
                    || state.version != version
                {
                    return Err(StoreError::Incompatible);
                }
                Ok(state)
            }
            StoreS3ConditionalWriteOutcome::PreconditionFailed => Err(StoreError::Incompatible),
        }
    }
}

impl S3BlobBackend {
    /// Validates and constructs an S3 leaf with separate committed-object administration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when ordinary configuration, endpoint binding,
    /// or process-wide administrative namespace admission fails.
    // crucible-lint: allow rust-allow -- the constructor keeps every independently authenticated S3 namespace and bound explicit.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_admin(
        name: impl Into<String>,
        endpoint: StoreS3EndpointId,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        maximum_logical_object_bytes: u64,
        multipart_part_bytes: u64,
        client: Arc<dyn StoreS3Client>,
        admin_client: Arc<dyn StoreS3BlobAdminClient>,
    ) -> Result<Self, StoreError> {
        Self::new_inner(
            name,
            endpoint,
            bucket,
            prefix,
            maximum_logical_object_bytes,
            multipart_part_bytes,
            client,
            Some(admin_client),
        )
    }

    pub(super) fn acquire_admin_publication_guard(
        &self,
    ) -> Result<Option<RwLockReadGuard<'_, ()>>, StoreError> {
        self.administration
            .as_ref()
            .map(|_administration| {
                self.lifecycle
                    .publication
                    .read()
                    .map_err(|_| StoreError::Poisoned {
                        operation: "acquire-S3-blob-publication-guard",
                    })
            })
            .transpose()
    }

    pub(super) fn advance_admin_generation(&self) -> Result<(), StoreError> {
        let Some(administration) = &self.administration else {
            return Ok(());
        };
        let _state = self
            .lifecycle
            .state
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "advance-S3-blob-inventory-state",
            })?;
        administration.advance_state(self)?;
        Ok(())
    }
}

impl BlobStoreAdmin for S3BlobBackend {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let administration =
            self.administration
                .as_ref()
                .ok_or(StoreError::InvalidComposition {
                    reason: "S3 blob backend has no committed-object administration capability",
                })?;
        let publication = self
            .lifecycle
            .publication
            .write()
            .map_err(|_| StoreError::Poisoned {
                operation: "acquire-S3-blob-inventory-publication-fence",
            })?;
        let state = self
            .lifecycle
            .state
            .lock()
            .map_err(|_| StoreError::Poisoned {
                operation: "acquire-S3-blob-inventory-state-fence",
            })?;
        let inventory = administration.load_or_create_state(self)?;
        Ok(Box::new(S3BlobInventoryFence {
            backend: self,
            administration,
            _publication: publication,
            _state: state,
            inventory,
        }))
    }
}

struct S3BlobInventoryFence<'a> {
    backend: &'a S3BlobBackend,
    administration: &'a S3BlobAdministration,
    _publication: RwLockWriteGuard<'a, ()>,
    _state: MutexGuard<'a, ()>,
    inventory: InventoryState,
}

impl S3BlobInventoryFence<'_> {
    fn visit_objects(
        &self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        let object_prefix = self.backend.object_prefix();
        let mut scan = self
            .administration
            .client
            .begin_small_object_scan(&self.backend.bucket, &object_prefix)?;
        let generation = persistent_inventory_generation(
            &self.backend.name,
            self.inventory.instance,
            self.inventory.generation,
        )?;
        let mut counter = InventoryCounter::new(generation);
        let mut visited = 0_u64;
        let mut pages = 0_u64;
        let mut prior_key = None;
        loop {
            pages = pages.checked_add(1).ok_or(StoreError::Quota)?;
            if pages > MAX_S3_COMMITTED_OBJECT_VISITS.saturating_add(1) {
                return Err(StoreError::Quota);
            }
            let page = scan.next_page(MAX_S3_OBJECT_LIST_ITEMS)?;
            let (keys, next) = page.into_parts();
            for key in keys {
                if prior_key.as_ref().is_some_and(|prior| &key <= prior) {
                    return Err(StoreError::Incompatible);
                }
                visited = visited.checked_add(1).ok_or(StoreError::Quota)?;
                if visited > MAX_S3_COMMITTED_OBJECT_VISITS {
                    return Err(StoreError::Quota);
                }
                prior_key = Some(key.clone());
                let id = key
                    .strip_prefix(&object_prefix)
                    .ok_or(StoreError::Incompatible)
                    .and_then(|suffix| {
                        ContentId::parse(suffix).map_err(|_| StoreError::Incompatible)
                    })?;
                if self.backend.key(id) != key {
                    return Err(StoreError::Incompatible);
                }
                let metadata = scan
                    .head_versioned_object(&key)?
                    .ok_or(StoreError::Incompatible)?;
                if metadata.logical_length() > self.backend.maximum_logical_object_bytes {
                    return Err(StoreError::Corrupt { id });
                }
                let record = BlobInventoryRecord::new(id, metadata.logical_length());
                counter.push(record)?;
                visitor(record)?;
            }
            if next.is_none() {
                break;
            }
        }
        let after = self
            .administration
            .load_state(self.backend)?
            .ok_or(StoreError::Incompatible)?;
        if after != self.inventory {
            return Err(StoreError::Incompatible);
        }
        Ok(counter.finish(self.backend.name.clone()))
    }
}

impl BlobInventoryFence for S3BlobInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.visit_objects(visitor)
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let key = self.backend.key(id);
        let Some(metadata) = self
            .administration
            .client
            .head_versioned_object(&self.backend.bucket, &key)?
        else {
            return Ok(PlannedDeleteDisposition::AlreadyAbsent);
        };
        if metadata.logical_length() > self.backend.maximum_logical_object_bytes {
            return Err(StoreError::Corrupt { id });
        }
        self.inventory = self.administration.advance_state(self.backend)?;
        match self.administration.client.delete_object_if_version(
            &self.backend.bucket,
            &key,
            metadata.version(),
        )? {
            StoreS3ConditionalDeleteOutcome::Deleted => {
                if self
                    .administration
                    .client
                    .head_versioned_object(&self.backend.bucket, &key)?
                    .is_some()
                {
                    return Err(StoreError::Incompatible);
                }
                Ok(PlannedDeleteDisposition::Deleted)
            }
            StoreS3ConditionalDeleteOutcome::PreconditionFailed => Err(StoreError::Incompatible),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InventoryState {
    instance: [u8; 32],
    generation: u64,
    version: StoreS3ObjectVersion,
}

fn encode_inventory_state(instance: [u8; 32], generation: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INVENTORY_STATE_MAGIC.len() + 32 + 8 + 32);
    bytes.extend_from_slice(INVENTORY_STATE_MAGIC);
    bytes.extend_from_slice(&instance);
    bytes.extend_from_slice(&generation.to_be_bytes());
    let mut checksum = blake3::Hasher::new();
    checksum.update(INVENTORY_STATE_CHECKSUM_DOMAIN);
    checksum.update(&bytes);
    bytes.extend_from_slice(checksum.finalize().as_bytes());
    bytes
}

fn decode_inventory_state(bytes: &[u8]) -> Result<([u8; 32], u64), StoreError> {
    let material_length = INVENTORY_STATE_MAGIC.len() + 32 + 8;
    if bytes.len() != material_length + 32 || !bytes.starts_with(INVENTORY_STATE_MAGIC) {
        return Err(StoreError::Incompatible);
    }
    let instance: [u8; 32] = bytes[INVENTORY_STATE_MAGIC.len()..INVENTORY_STATE_MAGIC.len() + 32]
        .try_into()
        .map_err(|_| StoreError::Incompatible)?;
    let generation = u64::from_be_bytes(
        bytes[INVENTORY_STATE_MAGIC.len() + 32..material_length]
            .try_into()
            .map_err(|_| StoreError::Incompatible)?,
    );
    if generation == 0 {
        return Err(StoreError::Incompatible);
    }
    let mut checksum = blake3::Hasher::new();
    checksum.update(INVENTORY_STATE_CHECKSUM_DOMAIN);
    checksum.update(&bytes[..material_length]);
    if checksum.finalize().as_bytes() != &bytes[material_length..] {
        return Err(StoreError::Incompatible);
    }
    Ok((instance, generation))
}

fn new_inventory_instance() -> Result<[u8; 32], StoreError> {
    let path = Path::new("/dev/urandom");
    let mut instance = [0_u8; 32];
    File::open(path)
        .and_then(|mut source| source.read_exact(&mut instance))
        .map_err(|source| StoreError::Io {
            operation: "read-S3-object-inventory-instance-randomness",
            path: path.to_path_buf(),
            source,
        })?;
    Ok(instance)
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- unit fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn inventory_state_codec_is_exact_and_checksum_bound() {
        let instance = [0xa5; 32];
        let bytes = encode_inventory_state(instance, u64::MAX);
        assert_eq!(
            decode_inventory_state(&bytes).expect("canonical inventory state"),
            (instance, u64::MAX)
        );

        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            decode_inventory_state(&corrupt),
            Err(StoreError::Incompatible)
        ));
        assert!(matches!(
            decode_inventory_state(&encode_inventory_state(instance, 0)),
            Err(StoreError::Incompatible)
        ));
    }
}
