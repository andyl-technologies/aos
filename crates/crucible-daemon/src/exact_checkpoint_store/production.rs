//! Complete production-checkpoint roots over the campaign immutable store.

use super::*;
use std::collections::BTreeSet;
use std::io::{self, Read};
#[cfg(feature = "destructive-recovery-faults")]
use std::sync::atomic::{AtomicBool, Ordering};

use crucible::SchedulerOperationalFailureClass;
use crucible_api::{
    DecodedProductionExactCheckpoint, LifecycleApiError, PreparedProductionReplayOraclePromotion,
    ProductionExactCheckpointClosure, ProductionExactCheckpointObject,
    ProductionExactCheckpointRetirement, decode_authenticated_production_exact_checkpoint,
    retire_production_exact_checkpoint_catalog,
};
use crucible_cas::content_store::BlobSource;

const PRODUCTION_MANIFEST_ROLE: &str = "production-manifest";
const PRODUCTION_PROMOTION_SOURCE_ROLE: &str = "replay-oracle-source";
const PRODUCTION_PROMOTION_EVIDENCE_ROLE: &str = "replay-oracle-evidence";
const PRODUCTION_CHOICE_CLOSURE_ROLE: &str = "checkpoint-choice-closure";
const PRODUCTION_INDEX_ROLE_PREFIX: &str = "production-object-index-";
const PRODUCTION_OBJECT_ROLE_PREFIX: &str = "object-";
const PRODUCTION_INDEX_SCHEMA: &str = "crucible.executor.production-checkpoint-index";
const PRODUCTION_INDEX_SCHEMA_VERSION: u32 = 1;
const PRODUCTION_MANIFEST_SCHEMA_VERSION: u32 = 4;
const PRODUCTION_OBJECT_SCHEMA_VERSION: u32 = 5;
const PRODUCTION_PROMOTION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const PRODUCTION_CHOICE_CLOSURE_SCHEMA_VERSION: u32 = 1;
const PRODUCTION_ROOT_BODY_BYTES: usize = 124;
const PRODUCTION_INDEX_MAGIC: &[u8; 8] = b"CRUCPIDX";
const PRODUCTION_INDEX_PAGE_OBJECTS: usize = 4_096;
const MAX_PRODUCTION_INDEX_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_PRODUCTION_ROOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PRODUCTION_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PRODUCTION_PROMOTION_EVIDENCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PRODUCTION_CHOICE_CLOSURE_BYTES: u64 = 128 * 1024 * 1024;
const PRODUCTION_OBJECT_IDENTITY_BYTES: u64 = 32;
const REPLAY_ORACLE_EVIDENCE_MAGIC: &[u8] = b"crucible.production-replay-oracle.v1\0";
#[cfg(feature = "destructive-recovery-faults")]
const DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_TRIGGER";
#[cfg(feature = "destructive-recovery-faults")]
const EXACT_CAPTURE_ENOSPC_TRIGGER: &str = "crucible.destructive-recovery.exact-capture-enospc";
#[cfg(feature = "destructive-recovery-faults")]
static EXACT_CAPTURE_ENOSPC_INJECTED: AtomicBool = AtomicBool::new(false);

trait ProductionExactCheckpointPublicationSource: Send + Sync {
    fn manifest(&self) -> &[u8];
    fn objects(&self) -> &[ProductionExactCheckpointObject];
    fn open_object(&self, identity: ContentHash)
    -> Result<Box<dyn Read + Send>, LifecycleApiError>;
}

impl ProductionExactCheckpointPublicationSource for ProductionExactCheckpointClosure {
    fn manifest(&self) -> &[u8] {
        self.manifest()
    }

    fn objects(&self) -> &[ProductionExactCheckpointObject] {
        self.objects()
    }

    fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        self.open_object(identity)
    }
}

#[derive(Clone, Copy)]
struct ProductionObjectPlacement {
    object: ProductionExactCheckpointObject,
    content: ContentId,
}

struct ProductionRepositoryReuse {
    backend: Arc<dyn ImmutableBlobBackend>,
    placements: Vec<ContentId>,
}

/// No-write preparation of one complete multi-node production checkpoint root.
pub struct PreparedProductionExactCheckpoint {
    root: ExactCheckpointId,
    root_source: BlobHandle,
    manifest_id: ContentId,
    manifest_source: BlobHandle,
    source: Arc<dyn ProductionExactCheckpointPublicationSource>,
    objects: Vec<ProductionObjectPlacement>,
    indexes: Vec<(ContentId, BlobHandle)>,
    reuse_backend: Option<Arc<dyn ImmutableBlobBackend>>,
    production_identity: ContentHash,
    promotion_source: Option<ExactCheckpointId>,
    promotion_evidence: Option<(ContentId, BlobHandle)>,
    choice_closure: (ContentId, BlobHandle),
    scenario: ContentHash,
    configuration: ContentHash,
    object_bytes: u64,
    cancellation: Option<ExecutionCancellation>,
    native_retirement: Option<ProductionExactCheckpointRetirement>,
}

impl fmt::Debug for PreparedProductionExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProductionExactCheckpoint")
            .field("root", &self.root)
            .field("production_identity", &self.production_identity)
            .field("promotion_source", &self.promotion_source)
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

    pub(crate) fn promotion_evidence_id(&self) -> Option<ContentId> {
        self.promotion_evidence
            .as_ref()
            .map(|(identity, _)| *identity)
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

    /// Retires the redundant attempt-local native source after CAS publication.
    ///
    /// This operation is idempotent. The caller must have stopped the QEMU
    /// lifecycle and must retain exclusive ownership of the semantic worker's
    /// run-state root.
    ///
    /// # Errors
    ///
    /// Returns an exact native-retirement error when the catalog namespace is
    /// inconsistent or its durable rename/removal cannot complete.
    pub fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        if let Some(retirement) = &self.native_retirement {
            retire_production_exact_checkpoint_catalog(retirement)?;
        }
        Ok(())
    }

    pub(crate) fn native_retirement(&self) -> Option<ProductionExactCheckpointRetirement> {
        self.native_retirement.clone()
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
    root_envelope: Vec<u8>,
    index_pages: Vec<Vec<u8>>,
    production_identity: ContentHash,
    promotion_source: Option<ExactCheckpointId>,
    promotion_evidence_id: Option<ContentId>,
    promotion_evidence: Option<Vec<u8>>,
    choice_closure: Vec<u8>,
    scenario: ContentHash,
    configuration: ContentHash,
    manifest: Vec<u8>,
    objects: Vec<ProductionExactCheckpointObject>,
    placements: Vec<ContentId>,
    backend: Arc<dyn ImmutableBlobBackend>,
    cancellation: Option<ExecutionCancellation>,
}

impl LoadedProductionExactCheckpoint {
    /// Returns the root-authenticated bounded choice records captured at pause.
    pub(crate) fn choice_closure(&self) -> &[u8] {
        &self.choice_closure
    }
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

    /// Returns the raw root authenticated by this replay-oracle replacement.
    #[must_use]
    pub const fn promotion_source(&self) -> Option<ExactCheckpointId> {
        self.promotion_source
    }

    pub(crate) fn promotion_evidence(&self) -> Option<&[u8]> {
        self.promotion_evidence.as_deref()
    }

    pub(crate) const fn promotion_evidence_id(&self) -> Option<ContentId> {
        self.promotion_evidence_id
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

    pub(crate) fn metadata_bytes(&self) -> Result<u64, ExactCheckpointStoreError> {
        self.index_pages.iter().try_fold(
            u64::try_from(self.root_envelope.len())
                .ok()
                .and_then(|bytes| {
                    u64::try_from(self.manifest.len())
                        .ok()
                        .and_then(|manifest| bytes.checked_add(manifest))
                })
                .ok_or_else(|| invalid_root("production metadata byte count overflow"))?,
            |total, page| {
                u64::try_from(page.len())
                    .ok()
                    .and_then(|bytes| total.checked_add(bytes))
                    .ok_or_else(|| invalid_root("production metadata byte count overflow"))
            },
        )
    }

    /// Returns the complete authenticated byte cost needed to restore this root.
    ///
    /// This cost includes the root envelope, manifest, index pages, and every
    /// authenticated object in the restore closure. Campaign debug admission
    /// uses it to choose the cheapest retained exact state.
    ///
    /// # Errors
    ///
    /// Returns an error when the complete byte count overflows.
    pub fn authenticated_restore_bytes(&self) -> Result<u64, ExactCheckpointStoreError> {
        self.objects
            .iter()
            .try_fold(self.metadata_bytes()?, |total, object| {
                total
                    .checked_add(object.length())
                    .ok_or_else(|| invalid_root("production restore byte count overflow"))
            })
    }

    /// Returns the root, its named children, and every indexed production object.
    ///
    /// # Errors
    ///
    /// Returns an error if the already loaded root envelope cannot be decoded.
    pub(crate) fn retained_content_ids(
        &self,
    ) -> Result<BTreeSet<ContentId>, ExactCheckpointStoreError> {
        let envelope = ContentEnvelope::from_canonical_bytes(&self.root_envelope)?;
        let mut retained = BTreeSet::from([self.root.content_id()]);
        retained.extend(envelope.children().iter().map(ContentChild::id));
        retained.extend(self.placements.iter().copied());
        Ok(retained)
    }

    fn authenticate_repository(
        &self,
    ) -> Result<
        crucible::exact_checkpoint::ExactCheckpointRepositoryBinding,
        ExactCheckpointStoreError,
    > {
        let observed_objects = self
            .objects
            .iter()
            .zip(&self.placements)
            .map(|(object, content)| (*content, object.length()))
            .collect::<Vec<_>>();
        crucible::exact_checkpoint::authenticate_exact_checkpoint_repository(
            self.root,
            &self.root_envelope,
            &self.index_pages,
            &observed_objects,
        )
        .map_err(|_| invalid_root("production repository relation authentication failed"))
    }

    fn authenticate_closure(
        &self,
        owned_byte_limit: u64,
    ) -> Result<crucible::exact_checkpoint::ExactCheckpointClosureBinding, ExactCheckpointStoreError>
    {
        let repository = self.authenticate_repository()?;
        crucible::exact_checkpoint::authenticate_exact_checkpoint_closure(
            repository,
            &self.manifest,
            owned_byte_limit,
        )
        .map_err(|error| {
            use crucible::exact_checkpoint::ExactCheckpointRelationError;

            let reason = match error {
                ExactCheckpointRelationError::InvalidStructure => {
                    "production closure has invalid canonical structure"
                }
                ExactCheckpointRelationError::ManifestTooLarge => {
                    "production closure exceeds its canonical byte bound"
                }
                ExactCheckpointRelationError::RootMismatch => {
                    "production closure root authentication failed"
                }
                ExactCheckpointRelationError::RepositoryRootMismatch => {
                    "production closure repository root authentication failed"
                }
                ExactCheckpointRelationError::TargetMembership => {
                    "production closure target membership authentication failed"
                }
                ExactCheckpointRelationError::TargetManifestMismatch => {
                    "production closure target manifest authentication failed"
                }
                ExactCheckpointRelationError::CanonicalEncoding => {
                    "production closure canonical serialization failed"
                }
                ExactCheckpointRelationError::ResourceExhausted => {
                    "production closure verification resource bound exceeded"
                }
            };
            invalid_root(reason)
        })
    }

    pub(crate) fn decode_semantic_checkpoint(
        self: &Arc<Self>,
        source: &crucible::ScenarioDefForm,
        cancellation: &ExecutionCancellation,
    ) -> Result<DecodedProductionExactCheckpoint, ExactCheckpointStoreError> {
        let byte_limit = source
            .plan()
            .fault_signals()
            .resource_limits()
            .fat_checkpoint_bytes;
        check_cancellation(Some(cancellation))?;
        let closure = self.authenticate_closure(byte_limit)?;
        let loaded = Arc::clone(self);
        let open_cancellation = cancellation.clone();
        let boundary_cancellation = cancellation.clone();
        let open = Arc::new(move |identity| {
            check_cancellation(Some(&open_cancellation))
                .map_err(|error| io::Error::other(error.to_string()))?;
            loaded
                .open_object(identity)
                .map_err(|error| io::Error::other(error.to_string()))
        });
        let scenario = source.scenario_def();
        let decoded = decode_authenticated_production_exact_checkpoint(
            closure,
            self.production_identity,
            &scenario,
            source,
            byte_limit,
            move || {
                check_cancellation(Some(&boundary_cancellation))
                    .map_err(|error| io::Error::other(error.to_string()))
            },
            open,
        )
        .map_err(|_| invalid_root("production semantic checkpoint authentication failed"))?;
        check_cancellation(Some(cancellation))?;
        Ok(decoded)
    }

    pub(crate) fn authenticate_replay_oracle_promotion(
        &self,
        raw: &Self,
    ) -> Result<(), ExactCheckpointStoreError> {
        if self.promotion_source != Some(raw.root)
            || self.production_identity != raw.production_identity
            || self.scenario != raw.scenario
            || self.configuration != raw.configuration
            || self.manifest != raw.manifest
            || self.objects != raw.objects
            || self.choice_closure != raw.choice_closure
        {
            return Err(invalid_root(
                "replay-oracle replacement changed its production closure",
            ));
        }
        let evidence = self
            .promotion_evidence
            .as_deref()
            .ok_or_else(|| invalid_root("replay-oracle replacement has no evidence"))?;
        authenticate_replay_oracle_evidence(evidence, raw.production_identity)
    }
}

fn authenticate_replay_oracle_evidence(
    evidence: &[u8],
    source: ContentHash,
) -> Result<(), ExactCheckpointStoreError> {
    let mut remaining = evidence
        .strip_prefix(REPLAY_ORACLE_EVIDENCE_MAGIC)
        .ok_or_else(|| invalid_root("replay-oracle evidence has another schema"))?;
    let source_bytes = take_evidence_bytes(&mut remaining, 32)?;
    if source_bytes != source.bytes {
        return Err(invalid_root("replay-oracle evidence names another closure"));
    }
    let count_bytes = take_evidence_bytes(&mut remaining, 4)?;
    let count = u32::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| invalid_root("replay-oracle evidence count is malformed"))?,
    );
    if count == 0 {
        return Err(invalid_root("replay-oracle evidence has no targets"));
    }
    let mut previous_node: Option<Vec<u8>> = None;
    for _ in 0..count {
        let node_bytes = take_evidence_bytes(&mut remaining, 4)?;
        let node_length = usize::try_from(u32::from_be_bytes(
            node_bytes
                .try_into()
                .map_err(|_| invalid_root("replay-oracle node length is malformed"))?,
        ))
        .map_err(|_| invalid_root("replay-oracle node length is not representable"))?;
        let node = take_evidence_bytes(&mut remaining, node_length)?;
        if node.is_empty()
            || std::str::from_utf8(node).is_err()
            || previous_node
                .as_deref()
                .is_some_and(|previous| previous >= node)
        {
            return Err(invalid_root(
                "replay-oracle evidence node inventory is not canonical",
            ));
        }
        previous_node = Some(node.to_vec());
        let _snapshot = take_evidence_bytes(&mut remaining, 32)?;
        let _target_manifest = take_evidence_bytes(&mut remaining, 32)?;
        let _runtime = take_evidence_bytes(&mut remaining, 32)?;
    }
    if !remaining.is_empty() {
        return Err(invalid_root("replay-oracle evidence has trailing bytes"));
    }
    Ok(())
}

fn take_evidence_bytes<'a>(
    remaining: &mut &'a [u8],
    count: usize,
) -> Result<&'a [u8], ExactCheckpointStoreError> {
    let (taken, rest) = remaining
        .split_at_checked(count)
        .ok_or_else(|| invalid_root("replay-oracle evidence is truncated"))?;
    *remaining = rest;
    Ok(taken)
}

impl ProductionExactCheckpointPublicationSource for LoadedProductionExactCheckpoint {
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
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(LifecycleApiError::AttemptOperational {
                class: SchedulerOperationalFailureClass::Canceled,
                message: String::from("production checkpoint installation canceled"),
            });
        }
        let mut handle = self
            .backend
            .read(content, None)
            .map_err(lifecycle_store_error)?;
        if self
            .cancellation
            .as_ref()
            .is_some_and(ExecutionCancellation::is_canceled)
        {
            return Err(LifecycleApiError::AttemptOperational {
                class: SchedulerOperationalFailureClass::Canceled,
                message: String::from("production checkpoint installation canceled"),
            });
        }
        if let Some(cancellation) = self.cancellation.as_ref() {
            handle = cancellation_blob_handle(handle, cancellation.clone());
        }
        if handle.logical_length() != object.length() {
            return Err(LifecycleApiError::LoopFactory {
                message: String::from("production checkpoint CAS object length changed"),
            });
        }
        handle.open().map_err(production_lifecycle_error)
    }
}

impl ExactCheckpointStore {
    fn require_reuse_backend(
        &self,
        backend: &Arc<dyn ImmutableBlobBackend>,
    ) -> Result<(), ExactCheckpointStoreError> {
        if !Arc::ptr_eq(&self.backend, backend) {
            return Err(invalid_root(
                "replay-oracle promotion source belongs to another backend",
            ));
        }
        Ok(())
    }

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
        let choices = crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty()
            .to_canonical_bytes()
            .map_err(|_| invalid_root("empty choice closure could not be encoded"))?;
        self.prepare_production_closure_inner(closure, choices, None)
    }

    pub(super) fn prepare_production_closure_with_cancellation(
        &self,
        closure: ProductionExactCheckpointClosure,
        choice_closure: Vec<u8>,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
        self.prepare_production_closure_inner(closure, choice_closure, Some(cancellation.clone()))
    }

    pub(super) fn prepare_production_closure_inner(
        &self,
        closure: ProductionExactCheckpointClosure,
        choice_closure: Vec<u8>,
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
        let native_retirement = Some(closure.native_retirement());
        let source: Arc<dyn ProductionExactCheckpointPublicationSource> = Arc::new(closure);
        prepare_production_source_with_cancellation(ProductionSourcePreparation {
            source,
            production_identity,
            scenario,
            configuration,
            maximum_checkpoint_bytes: self.maximum_checkpoint_bytes,
            cancellation,
            native_retirement,
            promotion_source: None,
            promotion_evidence: None,
            choice_closure,
            reuse: None,
        })
    }

    /// Wraps one no-write replay-oracle replacement as a campaign exact root.
    ///
    /// The input type can only be created by consuming every repository-backed
    /// restore admission and applying one source-bound matching check per live
    /// node. The authenticated object placements are reused on the same CAS
    /// backend; this operation regenerates only bounded metadata and writes
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns an error when a regenerated snapshot changes, an object identity
    /// or length is inconsistent, aggregate arithmetic overflows, an index or
    /// root exceeds its bound, or the source belongs to another backend.
    pub(crate) fn prepare_production_replay_oracle_promotion_with_cancellation(
        &self,
        raw: ExactCheckpointId,
        source: Arc<LoadedProductionExactCheckpoint>,
        promotion: PreparedProductionReplayOraclePromotion,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedProductionExactCheckpoint, ExactCheckpointStoreError> {
        let production_identity = promotion.promoted();
        if source.root() != raw || promotion.source() != source.production_identity() {
            return Err(invalid_root(
                "replay-oracle promotion names another repository source",
            ));
        }
        self.require_reuse_backend(&source.backend)?;
        source.authenticate_closure(self.maximum_checkpoint_bytes)?;
        let scenario = source.scenario();
        let configuration = source.configuration();
        let promotion_evidence = promotion.evidence().to_vec();
        let choice_closure = source.choice_closure.clone();
        let reuse = ProductionRepositoryReuse {
            backend: Arc::clone(&source.backend),
            placements: source.placements.clone(),
        };
        let source: Arc<dyn ProductionExactCheckpointPublicationSource> = source;
        prepare_production_source_with_cancellation(ProductionSourcePreparation {
            source,
            production_identity,
            scenario,
            configuration,
            maximum_checkpoint_bytes: self.maximum_checkpoint_bytes,
            cancellation: Some(cancellation.clone()),
            native_retirement: None,
            promotion_source: Some(raw),
            promotion_evidence: Some(promotion_evidence),
            choice_closure,
            reuse: Some(reuse),
        })
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
        if let Some(backend) = &prepared.reuse_backend {
            self.require_reuse_backend(backend)?;
        } else {
            require_durable_receipt(
                self.backend
                    .put_if_absent(prepared.manifest_id, &prepared.manifest_source)
                    .map_err(map_checkpoint_store_error)?,
                prepared.manifest_id,
                prepared.manifest_source.logical_length(),
            )?;
        }
        #[cfg(feature = "destructive-recovery-faults")]
        inject_exact_capture_enospc()?;
        for placement in &prepared.objects {
            check_cancellation(prepared.cancellation.as_ref())?;
            if prepared.reuse_backend.is_some() {
                continue;
            }
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
            if prepared.reuse_backend.is_some() {
                continue;
            }
            require_durable_receipt(
                self.backend
                    .put_if_absent(*identity, source)
                    .map_err(map_checkpoint_store_error)?,
                *identity,
                source.logical_length(),
            )?;
        }
        if let Some((identity, source)) = &prepared.promotion_evidence {
            check_cancellation(prepared.cancellation.as_ref())?;
            require_durable_receipt(
                self.backend
                    .put_if_absent(*identity, source)
                    .map_err(map_checkpoint_store_error)?,
                *identity,
                source.logical_length(),
            )?;
        }
        check_cancellation(prepared.cancellation.as_ref())?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.choice_closure.0, &prepared.choice_closure.1)
                .map_err(map_checkpoint_store_error)?,
            prepared.choice_closure.0,
            prepared.choice_closure.1.logical_length(),
        )?;
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
    /// This authenticates the v5 root, manifest object, exact ordered index
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
        self.load_production_closure_inner(root, None)
    }

    /// Authenticates checkpoint metadata and inventories every retained object.
    ///
    /// Replay-oracle promotion can name an earlier root, so the inventory also
    /// follows that source chain while enforcing a finite depth bound.
    ///
    /// # Errors
    ///
    /// Returns an error when any root is incomplete or malformed, or the
    /// promotion chain exceeds its bound.
    pub(crate) fn authenticated_production_closure_ids(
        &self,
        root: ExactCheckpointId,
    ) -> Result<BTreeSet<ContentId>, ExactCheckpointStoreError> {
        const MAX_PROMOTION_ROOTS: usize = 1024;

        let mut pending = vec![root];
        let mut visited = BTreeSet::new();
        let mut retained = BTreeSet::new();

        while let Some(current) = pending.pop() {
            if !visited.insert(current) {
                continue;
            }
            if visited.len() > MAX_PROMOTION_ROOTS {
                return Err(invalid_root(
                    "production promotion source chain is too deep",
                ));
            }

            let loaded = self.load_production_closure(current)?;
            retained.extend(loaded.retained_content_ids()?);
            if let Some(source) = loaded.promotion_source() {
                pending.push(source);
            }
        }

        Ok(retained)
    }

    /// Loads one complete production root under an execution cancellation signal.
    ///
    /// The returned portable source retains the same signal, so subsequent
    /// semantic installation also observes cancellation between bounded CAS
    /// reads.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::load_production_closure`], or
    /// [`ExactCheckpointStoreError::Canceled`] after cancellation wins.
    pub(crate) fn load_production_closure_with_cancellation(
        &self,
        root: ExactCheckpointId,
        cancellation: &ExecutionCancellation,
    ) -> Result<LoadedProductionExactCheckpoint, ExactCheckpointStoreError> {
        self.load_production_closure_inner(root, Some(cancellation.clone()))
    }

    fn load_production_closure_inner(
        &self,
        root: ExactCheckpointId,
        cancellation: Option<ExecutionCancellation>,
    ) -> Result<LoadedProductionExactCheckpoint, ExactCheckpointStoreError> {
        check_cancellation(cancellation.as_ref())?;
        let mut root_handle = self.backend.read(root.content_id(), None)?;
        check_cancellation(cancellation.as_ref())?;
        if let Some(cancellation) = cancellation.as_ref() {
            root_handle = cancellation_blob_handle(root_handle, cancellation.clone());
        }
        if root_handle.logical_length() > MAX_PRODUCTION_ROOT_BYTES {
            return Err(ExactCheckpointStoreError::ArtifactLimit {
                artifact: "production-root",
                length: root_handle.logical_length(),
                maximum: MAX_PRODUCTION_ROOT_BYTES,
            });
        }
        let root_bytes = root_handle
            .read_all(MAX_PRODUCTION_ROOT_BYTES)
            .map_err(map_checkpoint_store_error)?;
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
        let (manifest_id, index_ids, promotion_source, promotion_evidence_id, choice_id) =
            decode_production_root_children(&envelope, body.index_count)?;

        let mut choice_handle = self.backend.read(choice_id, None)?;
        if let Some(cancellation) = cancellation.as_ref() {
            choice_handle = cancellation_blob_handle(choice_handle, cancellation.clone());
        }
        if choice_handle.logical_length() == 0
            || choice_handle.logical_length() > MAX_PRODUCTION_CHOICE_CLOSURE_BYTES
        {
            return Err(invalid_root("checkpoint choice closure length is invalid"));
        }
        let choice_closure = choice_handle
            .read_all(MAX_PRODUCTION_CHOICE_CLOSURE_BYTES)
            .map_err(map_checkpoint_store_error)?;
        crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(
            &choice_closure,
        )
        .map_err(|_| invalid_root("checkpoint choice closure is malformed"))?;

        let promotion_evidence = if let Some(identity) = promotion_evidence_id {
            let mut handle = self.backend.read(identity, None)?;
            if let Some(cancellation) = cancellation.as_ref() {
                handle = cancellation_blob_handle(handle, cancellation.clone());
            }
            if handle.logical_length() == 0
                || handle.logical_length() > MAX_PRODUCTION_PROMOTION_EVIDENCE_BYTES
            {
                return Err(invalid_root("replay-oracle evidence length is invalid"));
            }
            Some(
                handle
                    .read_all(MAX_PRODUCTION_PROMOTION_EVIDENCE_BYTES)
                    .map_err(map_checkpoint_store_error)?,
            )
        } else {
            None
        };
        if promotion_source.is_some() != promotion_evidence.is_some() {
            return Err(invalid_root(
                "replay-oracle source and evidence children must appear together",
            ));
        }

        check_cancellation(cancellation.as_ref())?;
        let mut manifest_handle = self.backend.read(manifest_id, None)?;
        check_cancellation(cancellation.as_ref())?;
        if let Some(cancellation) = cancellation.as_ref() {
            manifest_handle = cancellation_blob_handle(manifest_handle, cancellation.clone());
        }
        if manifest_handle.logical_length() != body.manifest_bytes
            || manifest_handle.logical_length() > MAX_PRODUCTION_MANIFEST_BYTES
        {
            return Err(invalid_root("production manifest length mismatch"));
        }
        let manifest = manifest_handle
            .read_all(MAX_PRODUCTION_MANIFEST_BYTES)
            .map_err(map_checkpoint_store_error)?;

        let expected_objects = usize::try_from(body.object_count)
            .map_err(|_| invalid_root("production object count is not representable"))?;
        let mut objects = Vec::new();
        let mut placements = Vec::new();
        let mut index_pages = Vec::new();
        objects
            .try_reserve_exact(expected_objects)
            .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
        placements
            .try_reserve_exact(expected_objects)
            .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
        index_pages
            .try_reserve_exact(index_ids.len())
            .map_err(|_| ExactCheckpointStoreError::Store(StoreError::Quota))?;
        let mut object_bytes = 0_u64;
        let mut previous = None;
        let index_total = index_ids.len();
        for (index_ordinal, index_id) in index_ids.into_iter().enumerate() {
            check_cancellation(cancellation.as_ref())?;
            let mut handle = self.backend.read(index_id, None)?;
            check_cancellation(cancellation.as_ref())?;
            if let Some(cancellation) = cancellation.as_ref() {
                handle = cancellation_blob_handle(handle, cancellation.clone());
            }
            if handle.logical_length() > MAX_PRODUCTION_INDEX_BYTES {
                return Err(ExactCheckpointStoreError::ArtifactLimit {
                    artifact: "production-index",
                    length: handle.logical_length(),
                    maximum: MAX_PRODUCTION_INDEX_BYTES,
                });
            }
            let bytes = handle
                .read_all(MAX_PRODUCTION_INDEX_BYTES)
                .map_err(map_checkpoint_store_error)?;
            let index = ContentEnvelope::from_canonical_bytes(&bytes)?;
            if index.schema_name() != PRODUCTION_INDEX_SCHEMA
                || index.schema_version() != PRODUCTION_INDEX_SCHEMA_VERSION
                || index.content_id(ObjectKind::ExactManifest) != index_id
            {
                return Err(invalid_root("production index schema or identity mismatch"));
            }
            let page = decode_index_page(&index)?;
            index_pages.push(bytes);
            if index_ordinal + 1 != index_total && page.len() != PRODUCTION_INDEX_PAGE_OBJECTS {
                return Err(invalid_root("non-final production index page is not full"));
            }
            for placement in page {
                check_cancellation(cancellation.as_ref())?;
                if previous.is_some_and(|prior| prior >= placement.object.identity()) {
                    return Err(invalid_root("production objects are not globally sorted"));
                }
                let object_source = self.backend.read(placement.content, None)?;
                check_cancellation(cancellation.as_ref())?;
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
            root_envelope: root_bytes,
            index_pages,
            production_identity: body.production_identity,
            promotion_source,
            promotion_evidence_id,
            promotion_evidence,
            choice_closure,
            scenario: body.scenario,
            configuration: body.configuration,
            manifest,
            objects,
            placements,
            backend: Arc::clone(&self.backend),
            cancellation,
        })
    }
}

#[cfg(feature = "destructive-recovery-faults")]
fn inject_exact_capture_enospc() -> Result<(), ExactCheckpointStoreError> {
    let requested = std::env::var_os(DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT).as_deref()
        == Some(std::ffi::OsStr::new(EXACT_CAPTURE_ENOSPC_TRIGGER));
    if !requested || EXACT_CAPTURE_ENOSPC_INJECTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    Err(ExactCheckpointStoreError::Store(StoreError::Io {
        operation: "fault-injected production exact-capture publication",
        path: std::path::PathBuf::from("<fault-injected-exact-capture>"),
        source: io::Error::from_raw_os_error(rustix::io::Errno::NOSPC.raw_os_error()),
    }))
}

mod publication_format;

use publication_format::*;

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- content-addressed fixtures require exact failure localization.
    #![allow(clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    mod choice_closure;

    use crucible_api::build_authenticated_production_checkpoint_codec_fixture;
    use crucible_campaign::{AttemptId, CampaignLineageId};
    use crucible_cas::content_store::{
        BackendCapabilities, ByteRange, DirectoryBlobBackend, MemoryBlobBackend, PlacementReceipt,
    };

    struct MemoryProductionSource {
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        bytes: BTreeMap<ContentHash, Arc<[u8]>>,
    }

    impl ProductionExactCheckpointPublicationSource for MemoryProductionSource {
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

    struct CountingDirectoryBackend {
        directory: DirectoryBlobBackend,
        reads: AtomicUsize,
        puts: AtomicUsize,
    }

    impl CountingDirectoryBackend {
        fn new(root: &std::path::Path) -> Self {
            Self {
                directory: DirectoryBlobBackend::new("repository-promotion-test", root),
                reads: AtomicUsize::new(0),
                puts: AtomicUsize::new(0),
            }
        }

        fn reset_counts(&self) {
            self.reads.store(0, Ordering::Relaxed);
            self.puts.store(0, Ordering::Relaxed);
        }
    }

    impl ImmutableBlobBackend for CountingDirectoryBackend {
        fn name(&self) -> &str {
            self.directory.name()
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.directory.capabilities()
        }

        fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
            self.directory.contains(id)
        }

        fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.directory.read(id, range)
        }

        fn put_if_absent(
            &self,
            id: ContentId,
            source: &BlobHandle,
        ) -> Result<PutReceipt, StoreError> {
            self.puts.fetch_add(1, Ordering::Relaxed);
            self.directory.put_if_absent(id, source)
        }
    }

    struct ChangingProductionSource {
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl ProductionExactCheckpointPublicationSource for ChangingProductionSource {
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
        let source: Arc<dyn ProductionExactCheckpointPublicationSource> = Arc::new(source);
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

        assert_eq!(prepared.root().content_id().schema_version(), 5);
        assert_eq!(prepared.indexes.len(), 2);
        assert_eq!(backend.object_count(), 0);
        let root = prepared.root();
        let publication = store
            .publish_production_closure(&prepared)
            .expect("publish production closure");
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

        let loaded = store
            .load_attempt_checkpoint(root)
            .expect("load representation-independent attempt checkpoint");
        assert_eq!(loaded.root(), root);
        assert_eq!(loaded.scenario(), scenario);
        assert_eq!(loaded.configuration(), configuration);
    }

    #[test]
    fn repository_backed_promotion_reuses_the_durable_raw_closure() {
        let temporary = tempfile::tempdir().expect("create repository promotion fixture");
        let backend = Arc::new(CountingDirectoryBackend::new(temporary.path()));
        let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit repository promotion store");
        let production_identity = ContentHash::from_bytes(b"repository promotion closure");
        let scenario = ContentHash::from_bytes(b"repository promotion scenario");
        let configuration = ContentHash::from_bytes(b"repository promotion configuration");
        let raw = prepare_production_source(
            Arc::new(memory_source(2)),
            production_identity,
            scenario,
            configuration,
            64 * 1024 * 1024,
        )
        .expect("prepare raw repository closure");
        let raw = store
            .publish_production_closure(&raw)
            .expect("publish raw repository closure")
            .root();
        let cancellation = ExecutionCancellation::default();
        let loaded = Arc::new(
            store
                .load_production_closure_with_cancellation(raw, &cancellation)
                .expect("load raw repository closure"),
        );

        let node = b"node-0";
        let mut evidence = Vec::new();
        evidence.extend_from_slice(REPLAY_ORACLE_EVIDENCE_MAGIC);
        evidence.extend_from_slice(&production_identity.bytes);
        evidence.extend_from_slice(&1_u32.to_be_bytes());
        evidence.extend_from_slice(
            &u32::try_from(node.len())
                .expect("fixture node length fits")
                .to_be_bytes(),
        );
        evidence.extend_from_slice(node);
        evidence.extend_from_slice(&[0x31; 32]);
        evidence.extend_from_slice(&[0x32; 32]);
        evidence.extend_from_slice(&[0x33; 32]);

        let source: Arc<dyn ProductionExactCheckpointPublicationSource> = loaded.clone();
        backend.reset_counts();
        let promoted = prepare_production_source_with_cancellation(ProductionSourcePreparation {
            source,
            production_identity,
            scenario,
            configuration,
            maximum_checkpoint_bytes: 64 * 1024 * 1024,
            cancellation: Some(cancellation),
            native_retirement: None,
            promotion_source: Some(raw),
            promotion_evidence: Some(evidence),
            choice_closure: loaded.choice_closure().to_vec(),
            reuse: Some(ProductionRepositoryReuse {
                backend: Arc::clone(&loaded.backend),
                placements: loaded.placements.clone(),
            }),
        })
        .expect("prepare repository-backed replay promotion");
        assert_eq!(backend.reads.load(Ordering::Relaxed), 0);

        let other_backend = Arc::new(CountingDirectoryBackend::new(temporary.path()));
        let other_store = ExactCheckpointStore::new(other_backend.clone(), 64 * 1024 * 1024)
            .expect("admit separate repository store");
        assert!(matches!(
            other_store.require_reuse_backend(&loaded.backend),
            Err(ExactCheckpointStoreError::InvalidRoot { .. })
        ));
        assert!(matches!(
            other_store.publish_production_closure(&promoted),
            Err(ExactCheckpointStoreError::InvalidRoot { .. })
        ));
        assert_eq!(other_backend.puts.load(Ordering::Relaxed), 0);

        let promoted = store
            .publish_production_closure(&promoted)
            .expect("publish repository-backed replay promotion")
            .root();
        assert_eq!(backend.reads.load(Ordering::Relaxed), 0);
        assert_eq!(backend.puts.load(Ordering::Relaxed), 3);
        let promoted = store
            .load_production_closure(promoted)
            .expect("load repository-backed replay promotion");

        assert_eq!(promoted.promotion_source(), Some(raw));
        promoted
            .authenticate_replay_oracle_promotion(&loaded)
            .expect("authenticate unchanged repository promotion source");
    }

    #[test]
    fn production_load_rejects_execution_cancellation() {
        let source = memory_source(1);
        let backend = Arc::new(DurableMemoryBackend::new());
        let store =
            ExactCheckpointStore::new(backend, 64 * 1024 * 1024).expect("admit production store");
        let prepared = prepare_production_source(
            Arc::new(source),
            ContentHash::from_bytes(b"cancellable production closure"),
            ContentHash::from_bytes(b"cancellable production scenario"),
            ContentHash::from_bytes(b"cancellable production configuration"),
            64 * 1024 * 1024,
        )
        .expect("prepare cancellable production closure");
        let root = prepared.root();
        store
            .publish_production_closure(&prepared)
            .expect("publish cancellable production closure");
        let cancellation = ExecutionCancellation::default();
        store
            .load_production_closure_with_cancellation(root, &cancellation)
            .expect("load production root before cancellation");

        cancellation.cancel_for_test();
        assert!(matches!(
            store.load_production_closure_with_cancellation(root, &cancellation),
            Err(ExactCheckpointStoreError::Canceled)
        ));
    }

    #[cfg(feature = "destructive-recovery-faults")]
    #[test]
    fn production_exact_capture_enospc_restart_retries_root_last_publication() {
        const CHILD_ENVIRONMENT: &str = "CRUCIBLE_DESTRUCTIVE_RECOVERY_EXACT_CAPTURE_ENOSPC_CHILD";
        const TEST_NAME: &str = "exact_checkpoint_store::production::tests::production_exact_capture_enospc_restart_retries_root_last_publication";

        if std::env::var_os(CHILD_ENVIRONMENT).is_none() {
            let child =
                std::process::Command::new(std::env::current_exe().expect("current test binary"))
                    .arg("--exact")
                    .arg(TEST_NAME)
                    .arg("--nocapture")
                    .env(CHILD_ENVIRONMENT, "1")
                    .env(
                        DESTRUCTIVE_RECOVERY_TRIGGER_ENVIRONMENT,
                        EXACT_CAPTURE_ENOSPC_TRIGGER,
                    )
                    .output()
                    .expect("run exact-capture ENOSPC child");
            assert!(
                child.status.success(),
                "exact-capture ENOSPC child failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr),
            );
            return;
        }

        let source = memory_source(2);
        let production_identity = ContentHash::from_bytes(b"enospc production closure");
        let scenario = ContentHash::from_bytes(b"enospc production scenario");
        let configuration = ContentHash::from_bytes(b"enospc production configuration");
        let backend = Arc::new(DurableMemoryBackend::new());
        let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit faulting production store");

        EXACT_CAPTURE_ENOSPC_INJECTED.store(true, Ordering::SeqCst);
        let prior_identity = ContentHash::from_bytes(b"prior durable production closure");
        let prior = prepare_production_source(
            Arc::new(memory_source(1)),
            prior_identity,
            ContentHash::from_bytes(b"prior durable production scenario"),
            ContentHash::from_bytes(b"prior durable production configuration"),
            64 * 1024 * 1024,
        )
        .expect("prepare prior production closure");
        let prior_publication = store
            .publish_production_closure(&prior)
            .expect("publish prior production closure");
        EXACT_CAPTURE_ENOSPC_INJECTED.store(false, Ordering::SeqCst);

        let prepared = prepare_production_source(
            Arc::new(source),
            production_identity,
            scenario,
            configuration,
            64 * 1024 * 1024,
        )
        .expect("prepare production closure before injected ENOSPC");

        let error = store
            .publish_production_closure(&prepared)
            .expect_err("the configured durable put must fail with ENOSPC");
        let ExactCheckpointStoreError::Store(StoreError::Io { source, .. }) = error else {
            panic!("faulting store must preserve the ENOSPC I/O classification");
        };
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::NOSPC.raw_os_error())
        );
        assert!(
            !backend
                .contains(prepared.root().content_id())
                .expect("inspect unpublished production root")
        );
        assert!(
            backend
                .contains(prepared.manifest_id)
                .expect("inspect staged production manifest")
        );
        let retained_prior = store
            .load_production_closure(prior_publication.root())
            .expect("authenticate prior production closure after ENOSPC");
        assert_eq!(retained_prior.production_identity(), prior_identity);

        drop(store);
        let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
            .expect("reopen production store after capacity recovery");
        let publication = reopened
            .publish_production_closure(&prepared)
            .expect("retry identical root-last publication after capacity recovery");
        let loaded = reopened
            .load_production_closure(publication.root())
            .expect("authenticate production closure after retry");

        assert_eq!(loaded.production_identity(), production_identity);
        assert_eq!(loaded.scenario(), scenario);
        assert_eq!(loaded.configuration(), configuration);
    }

    #[test]
    fn production_exact_capture_cancellation_after_preparation_stops_before_first_write() {
        let source: Arc<dyn ProductionExactCheckpointPublicationSource> =
            Arc::new(memory_source(2));
        let backend = Arc::new(DurableMemoryBackend::new());
        let store = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
            .expect("admit cancellable production store");
        let cancellation = ExecutionCancellation::default();
        let prepared = prepare_production_source_with_cancellation(ProductionSourcePreparation {
            source,
            production_identity: ContentHash::from_bytes(b"canceled production closure"),
            scenario: ContentHash::from_bytes(b"canceled production scenario"),
            configuration: ContentHash::from_bytes(b"canceled production configuration"),
            maximum_checkpoint_bytes: 64 * 1024 * 1024,
            cancellation: Some(cancellation.clone()),
            native_retirement: None,
            promotion_source: None,
            promotion_evidence: None,
            choice_closure: crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty()
                .to_canonical_bytes()
                .expect("encode empty checkpoint choices"),
            reuse: None,
        })
        .expect("prepare production closure before cancellation");

        cancellation.cancel_for_test();
        assert!(matches!(
            store.publish_production_closure(&prepared),
            Err(ExactCheckpointStoreError::Canceled)
        ));
        assert_eq!(backend.object_count(), 0);
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
    fn production_root_v5_has_a_stable_canonical_identity() {
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
            "exact-manifest.5.fda03aae94e21d84722b0cf1446d28b4f7c7407b67feed6eef52ba0a5462dde2"
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

    #[test]
    fn raw_root_without_authenticated_source_pair_cannot_resume() {
        let temporary = tempfile::tempdir().expect("create raw fixture root");
        let fixture = build_authenticated_production_checkpoint_codec_fixture(
            &temporary.path().join("native-source"),
        )
        .expect("build self-consistent raw closure");
        let backend = Arc::new(DurableMemoryBackend::new());
        let store =
            ExactCheckpointStore::new(backend, 1024 * 1024 * 1024).expect("admit production store");
        let prepared = store
            .prepare_production_closure(fixture.closure().clone())
            .expect("prepare raw root");
        let checkpoint = prepared.root();
        store
            .publish_production_closure(&prepared)
            .expect("publish raw root");

        let result = crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
            &store,
            checkpoint,
            fixture.source(),
            fixture.configuration(),
            None,
            &crate::ExecutionCancellation::default(),
        );

        assert!(matches!(
            result,
            Err(crate::ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
                checkpoint: rejected,
            }) if rejected == checkpoint
        ));
        assert!(!temporary.path().join("resume-install").exists());
    }

    #[test]
    fn live_replay_promotion_claim_is_scoped_to_one_execution() {
        let backend = Arc::new(DurableMemoryBackend::new());
        let store = ExactCheckpointStore::new(backend.clone(), 1024 * 1024)
            .expect("admit production store");
        let root = ExactCheckpointId::try_from(ContentId::for_bytes(
            ObjectKind::ExactManifest,
            EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
            b"live replay promotion root",
        ))
        .expect("type replay promotion root");
        let evidence = ContentId::for_bytes(
            ObjectKind::Observation,
            PRODUCTION_PROMOTION_EVIDENCE_SCHEMA_VERSION,
            b"live replay comparison evidence",
        );
        let key = AttemptExecutionKey::new(
            CampaignLineageId::parse(&format!(
                "crucible.campaign.lineage@campaign-fact.1.{}",
                "61".repeat(32)
            ))
            .expect("lineage identity"),
            AttemptId::parse(&format!(
                "crucible.campaign.attempt@campaign-fact.9.{}",
                "62".repeat(32)
            ))
            .expect("attempt identity"),
        );
        let first_execution = ExecutionId::from_bytes([0x63; 16]).expect("first execution");
        let second_execution = ExecutionId::from_bytes([0x64; 16]).expect("second execution");
        store
            .retain_live_replay_promotion(key, first_execution, root, evidence)
            .expect("retain live replay result");

        let inspection = store
            .acquire_live_replay_promotion(key, first_execution, root, evidence)
            .expect("acquire boundary-inspection claim")
            .expect("boundary-inspection claim is available");
        assert!(
            store
                .acquire_live_replay_promotion(key, first_execution, root, evidence)
                .expect("inspect concurrent claim during boundary validation")
                .is_none()
        );
        drop(inspection);

        let reconcile = store
            .acquire_live_replay_promotion(key, first_execution, root, evidence)
            .expect("acquire reconcile claim after boundary inspection")
            .expect("released boundary claim is available to reconcile");
        reconcile.commit().expect("commit reconcile claim");
        assert!(
            store
                .acquire_live_replay_promotion(key, first_execution, root, evidence)
                .expect("inspect spent replay claim")
                .is_none()
        );
        assert!(
            store
                .retain_live_replay_promotion(key, first_execution, root, evidence)
                .is_err()
        );

        // Identical immutable bytes can result from a later pause. Its
        // distinct execution may reconcile once without reviving the first.
        store
            .retain_live_replay_promotion(key, second_execution, root, evidence)
            .expect("retain same root for later execution");
        store
            .acquire_live_replay_promotion(key, second_execution, root, evidence)
            .expect("acquire later execution")
            .expect("later execution has its own claim")
            .commit()
            .expect("consume later execution claim");
        assert!(
            store
                .acquire_live_replay_promotion(key, first_execution, root, evidence)
                .expect("inspect first execution")
                .is_none()
        );

        let reopened =
            ExactCheckpointStore::new(backend, 1024 * 1024).expect("reopen production store");
        assert!(
            reopened
                .acquire_live_replay_promotion(key, first_execution, root, evidence)
                .expect("inspect reopened replay claim")
                .is_none()
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
