//! Complete production-checkpoint roots over the campaign immutable store.

use super::*;
use std::io::{self, Read};

use crucible::SchedulerOperationalFailureClass;
use crucible_api::{
    LifecycleApiError, ProductionExactCheckpointClosure, ProductionExactCheckpointObject,
    ProductionExactCheckpointSource,
};
use crucible_cas::content_store::BlobSource;

const PRODUCTION_MANIFEST_ROLE: &str = "production-manifest";
const PRODUCTION_INDEX_ROLE_PREFIX: &str = "production-object-index-";
const PRODUCTION_OBJECT_ROLE_PREFIX: &str = "object-";
const PRODUCTION_INDEX_SCHEMA: &str = "crucible.executor.production-checkpoint-index";
const PRODUCTION_INDEX_SCHEMA_VERSION: u32 = 1;
const PRODUCTION_MANIFEST_SCHEMA_VERSION: u32 = 4;
const PRODUCTION_OBJECT_SCHEMA_VERSION: u32 = 5;
const PRODUCTION_ROOT_BODY_BYTES: usize = 124;
const PRODUCTION_INDEX_MAGIC: &[u8; 8] = b"CRUCPIDX";
const PRODUCTION_INDEX_PAGE_OBJECTS: usize = 4_096;
const MAX_PRODUCTION_INDEX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PRODUCTION_ROOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PRODUCTION_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const PRODUCTION_OBJECT_IDENTITY_BYTES: u64 = 32;

#[derive(Clone, Copy)]
struct ProductionObjectPlacement {
    object: ProductionExactCheckpointObject,
    content: ContentId,
}

/// No-write preparation of one complete multi-node production checkpoint root.
pub struct PreparedProductionExactCheckpoint {
    root: ExactCheckpointId,
    root_source: BlobHandle,
    manifest_id: ContentId,
    manifest_source: BlobHandle,
    source: Arc<dyn ProductionExactCheckpointSource>,
    objects: Vec<ProductionObjectPlacement>,
    indexes: Vec<(ContentId, BlobHandle)>,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    object_bytes: u64,
    cancellation: Option<ExecutionCancellation>,
}

impl fmt::Debug for PreparedProductionExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProductionExactCheckpoint")
            .field("root", &self.root)
            .field("production_identity", &self.production_identity)
            .field("scenario", &self.scenario)
            .field("configuration", &self.configuration)
            .field("objects", &self.objects.len())
            .field("object_bytes", &self.object_bytes)
            .finish()
    }
}

impl PreparedProductionExactCheckpoint {
    /// Returns the durable root identity that must be staged before publication.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the production-store closure identity wrapped by this root.
    #[must_use]
    pub const fn production_identity(&self) -> ContentHash {
        self.production_identity
    }

    /// Returns the exact scenario named by the production manifest.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact modeled configuration named by the production manifest.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the number of deduplicated production objects.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Returns the aggregate declared bytes of deduplicated production objects.
    #[must_use]
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }
}

/// Durable placement evidence for one complete production exact root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionExactCheckpointPublication {
    root: ExactCheckpointId,
    manifest: ContentId,
    indexes: u64,
    objects: u64,
}

impl ProductionExactCheckpointPublication {
    /// Returns the durably placed complete exact root.
    #[must_use]
    pub const fn root(self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the durably placed canonical production manifest identity.
    #[must_use]
    pub const fn manifest(self) -> ContentId {
        self.manifest
    }

    /// Returns the number of durably placed index pages.
    #[must_use]
    pub const fn index_count(self) -> u64 {
        self.indexes
    }

    /// Returns the number of durably placed production objects.
    #[must_use]
    pub const fn object_count(self) -> u64 {
        self.objects
    }
}

/// Authenticated CAS-backed source for one complete production checkpoint.
///
/// Root, manifest, index pages, object identities, and declared lengths have
/// been authenticated. A production-store installer must still apply the
/// exact scenario-aware semantic validator before launching QEMU.
pub struct LoadedProductionExactCheckpoint {
    root: ExactCheckpointId,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest: Vec<u8>,
    objects: Vec<ProductionExactCheckpointObject>,
    placements: Vec<ContentId>,
    backend: Arc<dyn ImmutableBlobBackend>,
}

impl LoadedProductionExactCheckpoint {
    /// Returns the complete campaign exact-checkpoint root.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the wrapped production-store closure identity.
    #[must_use]
    pub const fn production_identity(&self) -> ContentHash {
        self.production_identity
    }

    /// Returns the exact scenario declared by the production closure.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact modeled configuration declared by the production closure.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }
}

impl ProductionExactCheckpointSource for LoadedProductionExactCheckpoint {
    fn identity(&self) -> ContentHash {
        self.production_identity
    }

    fn scenario(&self) -> ContentHash {
        self.scenario
    }

    fn configuration(&self) -> ContentHash {
        self.configuration
    }

    fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    fn objects(&self) -> &[ProductionExactCheckpointObject] {
        &self.objects
    }

    fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        let index = self
            .objects
            .binary_search_by_key(&identity, |object| object.identity())
            .map_err(|_| LifecycleApiError::LoopFactory {
                message: String::from("production checkpoint object is not in the exact root"),
            })?;
        let object = self.objects[index];
        let content = self.placements[index];
        let handle = self
            .backend
            .read(content, None)
            .map_err(lifecycle_store_error)?;
        if handle.logical_length() != object.length() {
            return Err(LifecycleApiError::LoopFactory {
                message: String::from("production checkpoint CAS object length changed"),
            });
        }
        handle.open().map_err(lifecycle_store_error)
    }
}

impl ExactCheckpointStore {
    /// Authenticates and prepares one complete production closure without writes.
    ///
    /// Every production object is streamed through both its native BLAKE3
    /// identity and its typed CAS identity. Bounded index pages make the full
    /// child graph visible to generic closure walkers without depending on one
    /// flat envelope's child ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error when a source object changes, an identity or length is
    /// inconsistent, aggregate arithmetic overflows, an index/root envelope
    /// exceeds its bound, or the source cannot be reopened.
    pub fn prepare_production_closure(
        &self,
        closure: ProductionExactCheckpointClosure,
    ) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
        self.prepare_production_closure_inner(closure, None)
    }

    pub(super) fn prepare_production_closure_with_cancellation(
        &self,
        closure: ProductionExactCheckpointClosure,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
        self.prepare_production_closure_inner(closure, Some(cancellation.clone()))
    }

    fn prepare_production_closure_inner(
        &self,
        closure: ProductionExactCheckpointClosure,
        cancellation: Option<ExecutionCancellation>,
    ) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
        if let Some(cancellation) = cancellation.as_ref() {
            closure
                .validate_complete_with_boundary(&mut || {
                    if cancellation.is_canceled() {
                        return Err(LifecycleApiError::AttemptOperational {
                            class: SchedulerOperationalFailureClass::Canceled,
                            message: String::from("checkpoint authentication canceled"),
                        });
                    }
                    Ok(())
                })
                .map_err(map_production_lifecycle_error)?;
        } else {
            closure.validate_complete()?;
        }
        let production_identity = closure.identity();
        let scenario = closure.scenario();
        let configuration = closure.configuration();
        let source: Arc<dyn ProductionExactCheckpointSource> = Arc::new(closure);
        prepare_production_source_with_cancellation(
            source,
            production_identity,
            scenario,
            configuration,
            self.maximum_checkpoint_bytes,
            cancellation,
        )
    }

    /// Publishes all production objects, index pages, manifest, and root.
    ///
    /// The caller must durably stage [`PreparedProductionExactCheckpoint::root`]
    /// before this operation. The root is written last; a failed earlier put
    /// can leave only unreachable immutable content for GC.
    ///
    /// # Errors
    ///
    /// Returns a store, source-authentication, or durable-receipt error. Exact
    /// retry with the same preparation is idempotent.
    pub fn publish_production_closure(
        &self,
        prepared: &PreparedProductionExactCheckpoint,
    ) -> Result<ProductionExactCheckpointPublication, ExactCheckpointStoreError> {
        check_cancellation(prepared.cancellation.as_ref())?;
        validate_production_checkpoint_bytes(
            prepared.manifest_source.logical_length(),
            prepared.object_bytes,
            self.maximum_checkpoint_bytes,
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.manifest_id, &prepared.manifest_source)
                .map_err(map_checkpoint_store_error)?,
            prepared.manifest_id,
            prepared.manifest_source.logical_length(),
        )?;
        for placement in &prepared.objects {
            check_cancellation(prepared.cancellation.as_ref())?;
            let source = portable_object_handle(
                Arc::clone(&prepared.source),
                placement.object,
                prepared.cancellation.clone(),
            );
            require_durable_receipt(
                self.backend
                    .put_if_absent(placement.content, &source)
                    .map_err(production_object_put_error)?,
                placement.content,
                placement.object.length(),
            )?;
        }
        for (identity, source) in &prepared.indexes {
            check_cancellation(prepared.cancellation.as_ref())?;
            require_durable_receipt(
                self.backend
                    .put_if_absent(*identity, source)
                    .map_err(map_checkpoint_store_error)?,
                *identity,
                source.logical_length(),
            )?;
        }
        require_durable_receipt(
            {
                check_cancellation(prepared.cancellation.as_ref())?;
                self.backend
                    .put_if_absent(prepared.root.content_id(), &prepared.root_source)
                    .map_err(map_checkpoint_store_error)?
            },
            prepared.root.content_id(),
            prepared.root_source.logical_length(),
        )?;
        Ok(ProductionExactCheckpointPublication {
            root: prepared.root,
            manifest: prepared.manifest_id,
            indexes: u64::try_from(prepared.indexes.len())
                .map_err(|_| invalid_root("production index count is not representable"))?,
            objects: u64::try_from(prepared.objects.len())
                .map_err(|_| invalid_root("production object count is not representable"))?,
        })
    }

    /// Loads one complete production root as a bounded portable source.
    ///
    /// This authenticates the v4 root, manifest object, exact ordered index
    /// page set, every raw-identity-to-CAS mapping, object count, and aggregate
    /// declared bytes. Object bodies remain lazy and are independently checked
    /// when a production-store installer consumes them.
    ///
    /// # Errors
    ///
    /// Returns an error for absence, corrupt bytes, incompatible schemas,
    /// missing or extra pages/children, noncanonical order, count/length
    /// mismatch, or arithmetic and allocation bounds.
    pub fn load_production_closure(
        &self,
        root: ExactCheckpointId,
    ) -> Result<LoadedProductionExactCheckpoint, ExactCheckpointStoreError> {
        let root_handle = self.backend.read(root.content_id(), None)?;
        if root_handle.logical_length() > MAX_PRODUCTION_ROOT_BYTES {
            return Err(ExactCheckpointStoreError::ArtifactLimit {
                artifact: "production-root",
                length: root_handle.logical_length(),
                maximum: MAX_PRODUCTION_ROOT_BYTES,
            });
        }
        let root_bytes = root_handle.read_all(MAX_PRODUCTION_ROOT_BYTES)?;
        let envelope = ContentEnvelope::from_canonical_bytes(&root_bytes)?;
        if envelope.schema_name() != EXACT_CHECKPOINT_ROOT_SCHEMA
            || envelope.schema_version() != EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
            || envelope.content_id(ObjectKind::ExactManifest) != root.content_id()
        {
            return Err(invalid_root(
                "incompatible production root schema or identity",
            ));
        }
        let body = decode_production_root_body(envelope.body())?;
        validate_production_checkpoint_bytes(
            body.manifest_bytes,
            body.object_bytes,
            self.maximum_checkpoint_bytes,
        )?;
        validate_production_object_inventory_bound(body.manifest_bytes, body.object_count)?;
        validate_production_index_geometry(body.object_count, body.index_count)?;
        let (manifest_id, index_ids) =
            decode_production_root_children(&envelope, body.index_count)?;

        let manifest_handle = self.backend.read(manifest_id, None)?;
        if manifest_handle.logical_length() != body.manifest_bytes
            || manifest_handle.logical_length() > MAX_PRODUCTION_MANIFEST_BYTES
        {
            return Err(invalid_root("production manifest length mismatch"));
        }
        let manifest = manifest_handle.read_all(MAX_PRODUCTION_MANIFEST_BYTES)?;

        let expected_objects = usize::try_from(body.object_count)
            .map_err(|_| invalid_root("production object count is not representable"))?;
        let mut objects = Vec::new();
        let mut placements = Vec::new();
        objects
            .try_reserve_exact(expected_objects)
            .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
        placements
            .try_reserve_exact(expected_objects)
            .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
        let mut object_bytes = 0_u64;
        let mut previous = None;
        let index_total = index_ids.len();
        for (index_ordinal, index_id) in index_ids.into_iter().enumerate() {
            let handle = self.backend.read(index_id, None)?;
            if handle.logical_length() > MAX_PRODUCTION_INDEX_BYTES {
                return Err(ExactCheckpointStoreError::ArtifactLimit {
                    artifact: "production-index",
                    length: handle.logical_length(),
                    maximum: MAX_PRODUCTION_INDEX_BYTES,
                });
            }
            let bytes = handle.read_all(MAX_PRODUCTION_INDEX_BYTES)?;
            let index = ContentEnvelope::from_canonical_bytes(&bytes)?;
            if index.schema_name() != PRODUCTION_INDEX_SCHEMA
                || index.schema_version() != PRODUCTION_INDEX_SCHEMA_VERSION
                || index.content_id(ObjectKind::ExactManifest) != index_id
            {
                return Err(invalid_root("production index schema or identity mismatch"));
            }
            let page = decode_index_page(&index)?;
            if index_ordinal + 1 != index_total && page.len() != PRODUCTION_INDEX_PAGE_OBJECTS {
                return Err(invalid_root("non-final production index page is not full"));
            }
            for placement in page {
                if previous.is_some_and(|prior| prior >= placement.object.identity()) {
                    return Err(invalid_root("production objects are not globally sorted"));
                }
                let object_source = self.backend.read(placement.content, None)?;
                if object_source.logical_length() != placement.object.length() {
                    return Err(invalid_root("production object declared length mismatch"));
                }
                previous = Some(placement.object.identity());
                object_bytes = object_bytes
                    .checked_add(placement.object.length())
                    .ok_or_else(|| invalid_root("production object byte count overflow"))?;
                objects.push(placement.object);
                placements.push(placement.content);
            }
        }
        if objects.len() != expected_objects || object_bytes != body.object_bytes {
            return Err(invalid_root(
                "production object count or byte total mismatch",
            ));
        }

        Ok(LoadedProductionExactCheckpoint {
            root,
            production_identity: body.production_identity,
            scenario: body.scenario,
            configuration: body.configuration,
            manifest,
            objects,
            placements,
            backend: Arc::clone(&self.backend),
        })
    }
}

#[cfg(test)]
fn prepare_production_source(
    source: Arc<dyn ProductionExactCheckpointSource>,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    maximum_checkpoint_bytes: u64,
) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
    prepare_production_source_with_cancellation(
        source,
        production_identity,
        scenario,
        configuration,
        maximum_checkpoint_bytes,
        None,
    )
}

fn prepare_production_source_with_cancellation(
    source: Arc<dyn ProductionExactCheckpointSource>,
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    maximum_checkpoint_bytes: u64,
    cancellation: Option<ExecutionCancellation>,
) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
    check_cancellation(cancellation.as_ref())?;
    let manifest_bytes = source.manifest();
    if manifest_bytes.len() as u64 > MAX_PRODUCTION_MANIFEST_BYTES {
        return Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "production-manifest",
            length: manifest_bytes.len() as u64,
            maximum: MAX_PRODUCTION_MANIFEST_BYTES,
        });
    }
    let mut owned_manifest = Vec::new();
    owned_manifest
        .try_reserve_exact(manifest_bytes.len())
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    owned_manifest.extend_from_slice(manifest_bytes);
    check_cancellation(cancellation.as_ref())?;
    let mut manifest_source = BlobHandle::from_bytes(owned_manifest);
    if let Some(cancellation) = cancellation.as_ref() {
        manifest_source = cancellation_blob_handle(manifest_source, cancellation.clone());
    }
    let manifest_id = ContentId::for_source(
        ObjectKind::DeviceState,
        PRODUCTION_MANIFEST_SCHEMA_VERSION,
        &manifest_source,
    )
    .map_err(map_checkpoint_store_error)?;

    let mut objects = Vec::new();
    objects
        .try_reserve_exact(source.objects().len())
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    let mut object_bytes = 0_u64;
    for object in source.objects() {
        check_cancellation(cancellation.as_ref())?;
        object_bytes = object_bytes
            .checked_add(object.length())
            .ok_or_else(|| invalid_root("production object byte count overflow"))?;
        let handle = portable_object_handle(Arc::clone(&source), *object, cancellation.clone());
        let content = production_object_content_id(&handle)?;
        objects.push(ProductionObjectPlacement {
            object: *object,
            content,
        });
    }
    validate_production_checkpoint_bytes(
        manifest_source.logical_length(),
        object_bytes,
        maximum_checkpoint_bytes,
    )?;
    validate_production_object_inventory_bound(
        manifest_source.logical_length(),
        u64::try_from(objects.len())
            .map_err(|_| invalid_root("production object count is not representable"))?,
    )?;

    let mut indexes = Vec::new();
    let index_capacity = objects.len().div_ceil(PRODUCTION_INDEX_PAGE_OBJECTS);
    indexes
        .try_reserve_exact(index_capacity)
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    for page in objects.chunks(PRODUCTION_INDEX_PAGE_OBJECTS) {
        check_cancellation(cancellation.as_ref())?;
        let envelope = encode_index_page(page)?;
        let bytes = envelope.canonical_bytes();
        let id = envelope.content_id(ObjectKind::ExactManifest);
        let mut source = BlobHandle::from_bytes(bytes);
        if let Some(cancellation) = cancellation.as_ref() {
            source = cancellation_blob_handle(source, cancellation.clone());
        }
        indexes.push((id, source));
    }
    let index_count = u32::try_from(indexes.len())
        .map_err(|_| invalid_root("production index count exceeds root representation"))?;
    let body = encode_production_root_body(ProductionRootBody {
        production_identity,
        scenario,
        configuration,
        manifest_bytes: manifest_source.logical_length(),
        object_count: u64::try_from(objects.len())
            .map_err(|_| invalid_root("production object count is not representable"))?,
        object_bytes,
        index_count,
    });
    let mut children = BTreeSet::new();
    children.insert(ContentChild::new(PRODUCTION_MANIFEST_ROLE, manifest_id)?);
    for (index, (identity, _)) in indexes.iter().enumerate() {
        children.insert(ContentChild::new(index_role(index)?, *identity)?);
    }
    let root_envelope = ContentEnvelope::new(
        EXACT_CHECKPOINT_ROOT_SCHEMA,
        EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
        children,
        body,
    )?;
    let root = ExactCheckpointId::try_from(root_envelope.content_id(ObjectKind::ExactManifest))
        .map_err(|_| invalid_root("production root identity"))?;
    let mut root_source = BlobHandle::from_bytes(root_envelope.canonical_bytes());
    if let Some(cancellation) = cancellation.as_ref() {
        root_source = cancellation_blob_handle(root_source, cancellation.clone());
    }
    Ok(PreparedProductionExactCheckpoint {
        root,
        root_source,
        manifest_id,
        manifest_source,
        source,
        objects,
        indexes,
        production_identity,
        scenario,
        configuration,
        object_bytes,
        cancellation,
    })
}

fn encode_index_page(
    placements: &[ProductionObjectPlacement],
) -> Result<ContentEnvelope, ExactCheckpointStoreError> {
    if placements.is_empty() || placements.len() > PRODUCTION_INDEX_PAGE_OBJECTS {
        return Err(invalid_root(
            "production index page has an invalid object count",
        ));
    }
    let mut body =
        Vec::with_capacity(PRODUCTION_INDEX_MAGIC.len() + 4 + placements.len().saturating_mul(40));
    body.extend_from_slice(PRODUCTION_INDEX_MAGIC);
    body.extend_from_slice(
        &u32::try_from(placements.len())
            .map_err(|_| invalid_root("production index page count is not representable"))?
            .to_be_bytes(),
    );
    let mut children = BTreeSet::new();
    let mut previous = None;
    for placement in placements {
        if previous.is_some_and(|prior| prior >= placement.object.identity()) {
            return Err(invalid_root(
                "production index input is not strictly sorted",
            ));
        }
        previous = Some(placement.object.identity());
        body.extend_from_slice(&placement.object.identity().bytes);
        body.extend_from_slice(&placement.object.length().to_be_bytes());
        children.insert(ContentChild::new(
            object_role(placement.object.identity()),
            placement.content,
        )?);
    }
    ContentEnvelope::new(
        PRODUCTION_INDEX_SCHEMA,
        PRODUCTION_INDEX_SCHEMA_VERSION,
        children,
        body,
    )
    .map_err(Into::into)
}

fn decode_index_page(
    envelope: &ContentEnvelope,
) -> Result<Vec<ProductionObjectPlacement>, ExactCheckpointStoreError> {
    let bytes = envelope.body();
    if bytes.len() < 12 || &bytes[..8] != PRODUCTION_INDEX_MAGIC {
        return Err(invalid_root("production index body framing is invalid"));
    }
    let count = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| invalid_root("production index count is invalid"))?,
    ) as usize;
    if count == 0 || count > PRODUCTION_INDEX_PAGE_OBJECTS {
        return Err(invalid_root("production index object count is invalid"));
    }
    let expected = 12_usize
        .checked_add(
            count
                .checked_mul(40)
                .ok_or_else(|| invalid_root("production index body length overflow"))?,
        )
        .ok_or_else(|| invalid_root("production index body length overflow"))?;
    if bytes.len() != expected || envelope.children().len() != count {
        return Err(invalid_root(
            "production index body or child count mismatch",
        ));
    }
    let mut placements = Vec::new();
    placements
        .try_reserve_exact(count)
        .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
    let mut children = envelope.children().iter();
    let mut previous = None;
    for record in bytes[12..].chunks_exact(40) {
        let mut raw = [0_u8; 32];
        raw.copy_from_slice(&record[..32]);
        let identity = ContentHash { bytes: raw };
        let length = u64::from_be_bytes(
            record[32..40]
                .try_into()
                .map_err(|_| invalid_root("production object length is invalid"))?,
        );
        if previous.is_some_and(|prior| prior >= identity) {
            return Err(invalid_root("production index records are not sorted"));
        }
        previous = Some(identity);
        let child = children
            .next()
            .ok_or_else(|| invalid_root("production index child is missing"))?;
        if child.role() != object_role(identity)
            || child.id().kind() != ObjectKind::DeviceState
            || child.id().schema_version() != PRODUCTION_OBJECT_SCHEMA_VERSION
        {
            return Err(invalid_root("production index child binding is invalid"));
        }
        placements.push(ProductionObjectPlacement {
            object: ProductionExactCheckpointObject::new(identity, length),
            content: child.id(),
        });
    }
    if children.next().is_some() {
        return Err(invalid_root("production index contains an extra child"));
    }
    Ok(placements)
}

#[derive(Clone, Copy)]
struct ProductionRootBody {
    production_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest_bytes: u64,
    object_count: u64,
    object_bytes: u64,
    index_count: u32,
}

fn encode_production_root_body(body: ProductionRootBody) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PRODUCTION_ROOT_BODY_BYTES);
    bytes.extend_from_slice(&body.production_identity.bytes);
    bytes.extend_from_slice(&body.scenario.bytes);
    bytes.extend_from_slice(&body.configuration.bytes);
    bytes.extend_from_slice(&body.manifest_bytes.to_be_bytes());
    bytes.extend_from_slice(&body.object_count.to_be_bytes());
    bytes.extend_from_slice(&body.object_bytes.to_be_bytes());
    bytes.extend_from_slice(&body.index_count.to_be_bytes());
    bytes
}

fn decode_production_root_body(
    bytes: &[u8],
) -> Result<ProductionRootBody, ExactCheckpointStoreError> {
    if bytes.len() != PRODUCTION_ROOT_BODY_BYTES {
        return Err(invalid_root("production root body length mismatch"));
    }
    let hash = |range: std::ops::Range<usize>| {
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes[range]);
        ContentHash { bytes: value }
    };
    Ok(ProductionRootBody {
        production_identity: hash(0..32),
        scenario: hash(32..64),
        configuration: hash(64..96),
        manifest_bytes: u64::from_be_bytes(
            bytes[96..104]
                .try_into()
                .map_err(|_| invalid_root("production manifest length is invalid"))?,
        ),
        object_count: u64::from_be_bytes(
            bytes[104..112]
                .try_into()
                .map_err(|_| invalid_root("production object count is invalid"))?,
        ),
        object_bytes: u64::from_be_bytes(
            bytes[112..120]
                .try_into()
                .map_err(|_| invalid_root("production object bytes are invalid"))?,
        ),
        index_count: u32::from_be_bytes(
            bytes[120..124]
                .try_into()
                .map_err(|_| invalid_root("production index count is invalid"))?,
        ),
    })
}

fn decode_production_root_children(
    envelope: &ContentEnvelope,
    index_count: u32,
) -> Result<(ContentId, Vec<ContentId>), ExactCheckpointStoreError> {
    let expected = usize::try_from(index_count)
        .map_err(|_| invalid_root("production index count is not representable"))?;
    if envelope.children().len() != expected.saturating_add(1) {
        return Err(invalid_root("production root child count mismatch"));
    }
    let mut manifest = None;
    let mut indexes = vec![None; expected];
    for child in envelope.children() {
        if child.role() == PRODUCTION_MANIFEST_ROLE {
            if manifest.replace(child.id()).is_some()
                || child.id().kind() != ObjectKind::DeviceState
                || child.id().schema_version() != PRODUCTION_MANIFEST_SCHEMA_VERSION
            {
                return Err(invalid_root("production manifest child is invalid"));
            }
            continue;
        }
        let suffix = child
            .role()
            .strip_prefix(PRODUCTION_INDEX_ROLE_PREFIX)
            .ok_or_else(|| invalid_root("production root contains an unknown child role"))?;
        let index = usize::from_str_radix(suffix, 16)
            .map_err(|_| invalid_root("production index child role is invalid"))?;
        if suffix.len() != 8
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || index >= indexes.len()
            || index_role(index)? != child.role()
            || indexes[index].replace(child.id()).is_some()
            || child.id().kind() != ObjectKind::ExactManifest
            || child.id().schema_version() != PRODUCTION_INDEX_SCHEMA_VERSION
        {
            return Err(invalid_root("production index child binding is invalid"));
        }
    }
    let manifest = manifest.ok_or_else(|| invalid_root("production manifest child is missing"))?;
    let indexes = indexes
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid_root("production index child sequence is incomplete"))?;
    Ok((manifest, indexes))
}

fn validate_production_checkpoint_bytes(
    manifest_bytes: u64,
    object_bytes: u64,
    maximum: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let length = manifest_bytes
        .checked_add(object_bytes)
        .ok_or_else(|| invalid_root("production checkpoint byte count overflow"))?;
    if length == 0 || length > maximum {
        return Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "production-closure",
            length,
            maximum,
        });
    }
    Ok(())
}

fn validate_production_index_geometry(
    object_count: u64,
    index_count: u32,
) -> Result<(), ExactCheckpointStoreError> {
    let page = u64::try_from(PRODUCTION_INDEX_PAGE_OBJECTS)
        .map_err(|_| invalid_root("production index page size is not representable"))?;
    let expected = if object_count == 0 {
        0
    } else {
        object_count
            .checked_add(page - 1)
            .ok_or_else(|| invalid_root("production index count overflow"))?
            / page
    };
    if expected != u64::from(index_count) {
        return Err(invalid_root(
            "production index page geometry is not canonical",
        ));
    }
    Ok(())
}

fn validate_production_object_inventory_bound(
    manifest_bytes: u64,
    object_count: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let minimum_manifest_bytes = object_count
        .checked_mul(PRODUCTION_OBJECT_IDENTITY_BYTES)
        .ok_or_else(|| invalid_root("production object inventory byte count overflow"))?;
    if minimum_manifest_bytes > manifest_bytes {
        return Err(invalid_root(
            "production object count exceeds the manifest-derived bound",
        ));
    }
    Ok(())
}

fn index_role(index: usize) -> Result<String, ExactCheckpointStoreError> {
    let index = u32::try_from(index)
        .map_err(|_| invalid_root("production index ordinal is not representable"))?;
    Ok(format!("{PRODUCTION_INDEX_ROLE_PREFIX}{index:08x}"))
}

fn object_role(identity: ContentHash) -> String {
    format!("{PRODUCTION_OBJECT_ROLE_PREFIX}{}", identity.to_hex())
}

fn portable_object_handle(
    source: Arc<dyn ProductionExactCheckpointSource>,
    object: ProductionExactCheckpointObject,
    cancellation: Option<ExecutionCancellation>,
) -> BlobHandle {
    BlobHandle::new(Arc::new(PortableObjectBlobSource {
        source,
        object,
        cancellation,
    }))
}

fn production_object_content_id(
    source: &BlobHandle,
) -> Result<ContentId, ExactCheckpointStoreError> {
    match ContentId::for_source(
        ObjectKind::DeviceState,
        PRODUCTION_OBJECT_SCHEMA_VERSION,
        source,
    ) {
        Ok(identity) => Ok(identity),
        Err(StoreError::StreamIo { source, .. }) if is_checkpoint_cancellation_io(&source) => {
            Err(ExactCheckpointStoreError::Canceled)
        }
        Err(StoreError::StreamIo { source, .. }) if source.kind() == io::ErrorKind::InvalidData => {
            Err(invalid_root(
                "production object failed native identity authentication",
            ))
        }
        Err(error) => Err(error.into()),
    }
}

fn production_object_put_error(error: StoreError) -> ExactCheckpointStoreError {
    match error {
        StoreError::StreamIo { source, .. } if is_checkpoint_cancellation_io(&source) => {
            ExactCheckpointStoreError::Canceled
        }
        StoreError::StreamIo { source, .. } if source.kind() == io::ErrorKind::InvalidData => {
            invalid_root("production object changed after preparation")
        }
        error => error.into(),
    }
}

struct PortableObjectBlobSource {
    source: Arc<dyn ProductionExactCheckpointSource>,
    object: ProductionExactCheckpointObject,
    cancellation: Option<ExecutionCancellation>,
}

impl BlobSource for PortableObjectBlobSource {
    fn logical_length(&self) -> u64 {
        self.object.length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        check_cancellation_store(self.cancellation.as_ref())?;
        let source = self
            .source
            .open_object(self.object.identity())
            .map_err(|error| StoreError::StreamIo {
                operation: "open-production-checkpoint-object",
                source: io::Error::other(error.to_string()),
            })?;
        Ok(Box::new(NativeIdentityReader {
            source,
            expected: self.object.identity(),
            length: self.object.length(),
            observed: 0,
            hasher: blake3::Hasher::new(),
            finished: false,
            cancellation: self.cancellation.clone(),
        }))
    }
}

struct NativeIdentityReader {
    source: Box<dyn Read + Send>,
    expected: ContentHash,
    length: u64,
    observed: u64,
    hasher: blake3::Hasher,
    finished: bool,
    cancellation: Option<ExecutionCancellation>,
}

impl Read for NativeIdentityReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.finished {
            return Ok(0);
        }
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        let limit = buffer.len().min(CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES);
        let count = self.source.read(&mut buffer[..limit])?;
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        if count == 0 {
            self.finished = true;
            let observed = ContentHash {
                bytes: *self.hasher.finalize().as_bytes(),
            };
            if self.observed != self.length || observed != self.expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "production checkpoint object failed native identity authentication",
                ));
            }
            return Ok(0);
        }
        self.observed = self
            .observed
            .checked_add(u64::try_from(count).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "object length is not representable",
                )
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object length overflow"))?;
        if self.observed > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "production checkpoint object exceeded its declared length",
            ));
        }
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

fn check_cancellation(
    cancellation: Option<&ExecutionCancellation>,
) -> Result<(), ExactCheckpointStoreError> {
    if cancellation.is_some_and(ExecutionCancellation::is_canceled) {
        return Err(ExactCheckpointStoreError::Canceled);
    }
    Ok(())
}

fn check_cancellation_store(
    cancellation: Option<&ExecutionCancellation>,
) -> Result<(), StoreError> {
    if cancellation.is_some_and(ExecutionCancellation::is_canceled) {
        return Err(StoreError::StreamIo {
            operation: "open-canceled-production-checkpoint-object",
            source: checkpoint_cancellation_io(),
        });
    }
    Ok(())
}

fn map_production_lifecycle_error(error: LifecycleApiError) -> ExactCheckpointStoreError {
    match error {
        LifecycleApiError::AttemptOperational {
            class: SchedulerOperationalFailureClass::Canceled,
            ..
        } => ExactCheckpointStoreError::Canceled,
        error => ExactCheckpointStoreError::Production(error),
    }
}

fn lifecycle_store_error(error: StoreError) -> LifecycleApiError {
    LifecycleApiError::LoopFactory {
        message: format!("read production checkpoint CAS object: {error}"),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- content-addressed fixtures require exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    use crucible_cas::content_store::{
        BackendCapabilities, ByteRange, MemoryBlobBackend, PlacementReceipt,
    };

    struct MemoryProductionSource {
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        bytes: BTreeMap<ContentHash, Arc<[u8]>>,
    }

    impl ProductionExactCheckpointSource for MemoryProductionSource {
        fn identity(&self) -> ContentHash {
            ContentHash::from_bytes(b"memory production closure")
        }

        fn scenario(&self) -> ContentHash {
            ContentHash::from_bytes(b"memory production scenario")
        }

        fn configuration(&self) -> ContentHash {
            ContentHash::from_bytes(b"memory production configuration")
        }

        fn manifest(&self) -> &[u8] {
            &self.manifest
        }

        fn objects(&self) -> &[ProductionExactCheckpointObject] {
            &self.objects
        }

        fn open_object(
            &self,
            identity: ContentHash,
        ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
            let bytes =
                self.bytes
                    .get(&identity)
                    .ok_or_else(|| LifecycleApiError::LoopFactory {
                        message: String::from("test production object is missing"),
                    })?;
            Ok(Box::new(Cursor::new(Arc::clone(bytes))))
        }
    }

    struct DurableMemoryBackend {
        memory: MemoryBlobBackend,
    }

    struct ChangingProductionSource {
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl ProductionExactCheckpointSource for ChangingProductionSource {
        fn identity(&self) -> ContentHash {
            ContentHash::from_bytes(b"changing production closure")
        }

        fn scenario(&self) -> ContentHash {
            ContentHash::from_bytes(b"changing production scenario")
        }

        fn configuration(&self) -> ContentHash {
            ContentHash::from_bytes(b"changing production configuration")
        }

        fn manifest(&self) -> &[u8] {
            &self.manifest
        }

        fn objects(&self) -> &[ProductionExactCheckpointObject] {
            &self.objects
        }

        fn open_object(
            &self,
            _identity: ContentHash,
        ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
            let bytes = self
                .bytes
                .lock()
                .map_err(|_| LifecycleApiError::LoopFactory {
                    message: String::from("changing source lock is poisoned"),
                })?
                .clone();
            Ok(Box::new(Cursor::new(bytes)))
        }
    }

    impl DurableMemoryBackend {
        fn new() -> Self {
            Self {
                memory: MemoryBlobBackend::new("production-root-test", 64 * 1024 * 1024),
            }
        }

        fn object_count(&self) -> usize {
            self.memory
                .object_count()
                .expect("count production objects")
        }
    }

    impl ImmutableBlobBackend for DurableMemoryBackend {
        fn name(&self) -> &str {
            "durable-production-root-test"
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
            self.memory.contains(id)
        }

        fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
            self.memory.read(id, range)
        }

        fn put_if_absent(
            &self,
            id: ContentId,
            source: &BlobHandle,
        ) -> Result<PutReceipt, StoreError> {
            let receipt = self.memory.put_if_absent(id, source)?;
            Ok(PutReceipt {
                id: receipt.id,
                placements: vec![PlacementReceipt {
                    backend: String::from(self.name()),
                    durable: true,
                    logical_length: source.logical_length(),
                }],
            })
        }
    }

    #[test]
    fn production_root_round_trips_more_than_one_index_page() {
        let source = memory_source(PRODUCTION_INDEX_PAGE_OBJECTS + 1);
        let first = source.objects[0].identity();
        let last = source
            .objects
            .last()
            .expect("source has objects")
            .identity();
        let expected_first = source.bytes[&first].to_vec();
        let expected_last = source.bytes[&last].to_vec();
        let source: Arc<dyn ProductionExactCheckpointSource> = Arc::new(source);
        let production_identity = ContentHash::from_bytes(b"production-closure");
        let scenario = ContentHash::from_bytes(b"production-scenario");
        let configuration = ContentHash::from_bytes(b"production-configuration");
        let backend = Arc::new(DurableMemoryBackend::new());
        let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit production store");

        let prepared = prepare_production_source(
            source,
            production_identity,
            scenario,
            configuration,
            64 * 1024 * 1024,
        )
        .expect("prepare production closure");

        assert_eq!(prepared.root().content_id().schema_version(), 4);
        assert_eq!(prepared.indexes.len(), 2);
        assert_eq!(backend.object_count(), 0);
        let root = prepared.root();
        let prepared = PreparedAttemptCheckpoint::Production(Box::new(prepared));
        let publication = store
            .publish_attempt_checkpoint(&prepared)
            .expect("publish production closure");
        let AttemptCheckpointPublication::Production(publication) = publication else {
            panic!("production preparation must return a production receipt")
        };
        assert_eq!(publication.root(), root);
        assert_eq!(publication.index_count(), 2);
        assert_eq!(
            publication.object_count(),
            u64::try_from(PRODUCTION_INDEX_PAGE_OBJECTS + 1).expect("fixture count fits")
        );

        let loaded = store
            .load_production_closure(root)
            .expect("load production closure");
        assert_eq!(loaded.production_identity(), production_identity);
        assert_eq!(loaded.scenario(), scenario);
        assert_eq!(loaded.configuration(), configuration);
        assert_eq!(loaded.objects().len(), PRODUCTION_INDEX_PAGE_OBJECTS + 1);
        let mut observed = Vec::new();
        loaded
            .copy_object_to(first, &mut observed)
            .expect("copy first indexed object");
        assert_eq!(observed, expected_first);
        observed.clear();
        loaded
            .copy_object_to(last, &mut observed)
            .expect("copy last indexed object");
        assert_eq!(observed, expected_last);
    }

    #[test]
    fn native_object_identity_mismatch_is_rejected_before_any_write() {
        let expected = ContentHash::from_bytes(b"expected");
        let source = MemoryProductionSource {
            manifest: b"production manifest".to_vec(),
            objects: vec![ProductionExactCheckpointObject::new(expected, 8)],
            bytes: BTreeMap::from([(expected, Arc::from(&b"changed!"[..]))]),
        };
        let backend = Arc::new(DurableMemoryBackend::new());
        let _store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit production store");

        let result = prepare_production_source(
            Arc::new(source),
            ContentHash::from_bytes(b"closure"),
            ContentHash::from_bytes(b"scenario"),
            ContentHash::from_bytes(b"configuration"),
            64 * 1024 * 1024,
        );

        assert!(matches!(
            result,
            Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "production object failed native identity authentication"
            })
        ));
        assert_eq!(backend.object_count(), 0);
    }

    #[test]
    fn aggregate_production_bytes_are_admitted_before_any_write() {
        let source = memory_source(1);
        let aggregate = u64::try_from(source.manifest.len()).expect("manifest length fits")
            + source.objects[0].length();
        let backend = Arc::new(DurableMemoryBackend::new());
        let _store = ExactCheckpointStore::new(backend.clone(), aggregate - 1)
            .expect("admit bounded production store");

        let result = prepare_production_source(
            Arc::new(source),
            ContentHash::from_bytes(b"closure"),
            ContentHash::from_bytes(b"scenario"),
            ContentHash::from_bytes(b"configuration"),
            aggregate - 1,
        );

        assert!(matches!(
            result,
            Err(ExactCheckpointStoreError::ArtifactLimit {
                artifact: "production-closure",
                length,
                maximum,
            }) if length == aggregate && maximum == aggregate - 1
        ));
        assert_eq!(backend.object_count(), 0);
    }

    #[test]
    fn production_root_v4_has_a_stable_canonical_identity() {
        let prepared = prepare_production_source(
            Arc::new(memory_source(2)),
            ContentHash::from_bytes(b"golden closure"),
            ContentHash::from_bytes(b"golden scenario"),
            ContentHash::from_bytes(b"golden configuration"),
            64 * 1024 * 1024,
        )
        .expect("prepare golden production root");

        assert_eq!(
            prepared.root().content_id().encode(),
            "exact-manifest.4.fb6e0a2e28e3c5f0b0f5a89aeb9192fd6e48da929f60d085f66b3470bfabab97"
        );
    }

    #[test]
    fn production_root_rejects_object_count_above_the_manifest_derived_bound() {
        let manifest = BlobHandle::from_bytes(vec![0_u8; 32]);
        let manifest_id = ContentId::for_bytes(
            ObjectKind::DeviceState,
            PRODUCTION_MANIFEST_SCHEMA_VERSION,
            &[0_u8; 32],
        );
        let index_id = ContentId::for_bytes(
            ObjectKind::ExactManifest,
            PRODUCTION_INDEX_SCHEMA_VERSION,
            b"unread index",
        );
        let mut children = BTreeSet::new();
        children.insert(
            ContentChild::new(PRODUCTION_MANIFEST_ROLE, manifest_id).expect("bind manifest child"),
        );
        children.insert(
            ContentChild::new(index_role(0).expect("derive first index role"), index_id)
                .expect("bind index child"),
        );
        let root_envelope = ContentEnvelope::new(
            EXACT_CHECKPOINT_ROOT_SCHEMA,
            EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
            children,
            encode_production_root_body(ProductionRootBody {
                production_identity: ContentHash::from_bytes(b"oversized inventory"),
                scenario: ContentHash::from_bytes(b"inventory scenario"),
                configuration: ContentHash::from_bytes(b"inventory configuration"),
                manifest_bytes: manifest.logical_length(),
                object_count: 2,
                object_bytes: 0,
                index_count: 1,
            }),
        )
        .expect("encode oversized inventory root");
        let root = ExactCheckpointId::try_from(root_envelope.content_id(ObjectKind::ExactManifest))
            .expect("type oversized inventory root");
        let backend = Arc::new(DurableMemoryBackend::new());
        backend
            .put_if_absent(
                root.content_id(),
                &BlobHandle::from_bytes(root_envelope.canonical_bytes()),
            )
            .expect("publish root fixture");
        let store =
            ExactCheckpointStore::new(backend, 64 * 1024 * 1024).expect("admit production store");

        let result = store.load_production_closure(root);

        assert!(matches!(
            result,
            Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "production object count exceeds the manifest-derived bound"
            })
        ));
    }

    #[test]
    fn changed_object_after_preparation_never_publishes_the_root() {
        let original = b"original".to_vec();
        let identity = ContentHash::from_bytes(&original);
        let bytes = Arc::new(Mutex::new(original));
        let source = ChangingProductionSource {
            manifest: vec![0x4d; 64],
            objects: vec![ProductionExactCheckpointObject::new(identity, 8)],
            bytes: Arc::clone(&bytes),
        };
        let backend = Arc::new(DurableMemoryBackend::new());
        let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit production store");
        let prepared = prepare_production_source(
            Arc::new(source),
            ContentHash::from_bytes(b"closure"),
            ContentHash::from_bytes(b"scenario"),
            ContentHash::from_bytes(b"configuration"),
            64 * 1024 * 1024,
        )
        .expect("prepare stable source");
        *bytes.lock().expect("changing source lock remains healthy") = b"modified".to_vec();

        let result = store.publish_production_closure(&prepared);

        assert!(matches!(
            result,
            Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "production object changed after preparation"
            })
        ));
        assert!(
            !backend
                .contains(prepared.root().content_id())
                .expect("inspect root absence")
        );
    }

    fn memory_source(count: usize) -> MemoryProductionSource {
        let mut bytes: BTreeMap<ContentHash, Arc<[u8]>> = BTreeMap::new();
        for index in 0..count {
            let object = format!("production-object-{index:08x}").into_bytes();
            bytes.insert(ContentHash::from_bytes(&object), Arc::from(object));
        }
        let objects = bytes
            .iter()
            .map(|(identity, bytes)| {
                ProductionExactCheckpointObject::new(
                    *identity,
                    u64::try_from(bytes.len()).expect("fixture object length fits"),
                )
            })
            .collect();
        MemoryProductionSource {
            manifest: vec![0x4d; count.saturating_mul(32).saturating_add(256)],
            objects,
            bytes,
        }
    }
}
