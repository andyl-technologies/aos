//! Durable content-addressed publication of exact QEMU checkpoints.
//!
//! A complete production checkpoint uses a version-five storage root around
//! one canonical version-nine production closure and bounded index pages. The
//! root version belongs to this CAS envelope and is independent of the runtime
//! restore protocol version:
//!
//! ```text
//! ExactCheckpointRootV5
//!   production-manifest -> ProductionExactCheckpointClosureV9
//!   checkpoint-choice-closure -> bounded owned replay selections
//!   production-object-index-* -> ProductionCheckpointIndexV1
//!     object-<native-hash> -> opaque typed production object
//! ```
//!
//! Index pages expose every immutable child to generic closure walkers without
//! depending on one flat envelope's child ceiling. Native production hashes,
//! CAS identities, lengths, exact scenario/configuration, and aggregate bounds
//! are all authenticated before the root is published last.
//!
//! Noncurrent roots are rejected. Only canonical production roots
//! enter publication, loading, pinning, or runtime restoration.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};

use crucible::ContentHash;
use crucible_api::ProductionExactCheckpointClosure;
pub use crucible_campaign::ExactCheckpointId;
use crucible_campaign::{
    AuthenticatedFindingExactCheckpoint, CampaignExecutorStore, CampaignHash, ConfigurationId,
    FindingExactCheckpointAuthenticationError, FindingExactCheckpointAuthenticator,
    ScenarioArtifactId, ScenarioDefId,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope, ContentEnvelopeError};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, PutReceipt, StoreError,
};
use thiserror::Error;

use crate::ExecutionCancellation;

const CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES: usize = 1024 * 1024;

/// Canonical schema name of the child-bearing exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA: &str = "crucible.executor.exact-checkpoint-root";
/// Content-ID and envelope version of the complete production exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION: u32 = 5;

mod production;
pub use production::{
    LoadedProductionExactCheckpoint, PreparedProductionExactCheckpoint,
    ProductionExactCheckpointPublication,
};

/// Attempt-owned production closure awaiting no-write immutable-store preparation.
pub struct CapturedAttemptCheckpoint {
    closure: ProductionExactCheckpointClosure,
    choice_closure: Option<Vec<u8>>,
}

impl fmt::Debug for CapturedAttemptCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedAttemptCheckpoint")
            .field("identity", &self.closure.identity())
            .field("scenario", &self.closure.scenario())
            .field("configuration", &self.closure.configuration())
            .field("objects", &self.closure.objects().len())
            .finish()
    }
}

impl CapturedAttemptCheckpoint {
    pub(crate) fn from_production_closure(capture: ProductionExactCheckpointClosure) -> Self {
        Self {
            closure: capture,
            choice_closure: None,
        }
    }

    pub(crate) fn with_choice_closure(mut self, bytes: Vec<u8>) -> Self {
        self.choice_closure = Some(bytes);
        self
    }

    fn choice_closure_bytes(&self) -> Result<Vec<u8>, ExactCheckpointStoreError> {
        match &self.choice_closure {
            Some(bytes) => Ok(bytes.clone()),
            None => crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::empty()
                .to_canonical_bytes()
                .map_err(|_| invalid_root("empty choice closure could not be encoded")),
        }
    }

    /// Returns the semantic scenario authenticated by this capture.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        self.closure.scenario()
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        self.closure.configuration()
    }

    pub(crate) fn into_closure(self) -> ProductionExactCheckpointClosure {
        self.closure
    }
}

/// No-write-prepared exact capture ready for durable root staging.
#[derive(Debug)]
pub struct PreparedAttemptCheckpoint(PreparedProductionExactCheckpoint);

impl PreparedAttemptCheckpoint {
    /// Returns the exact root that must be staged before immutable publication.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        self.0.root()
    }

    /// Returns the semantic scenario authenticated by this preparation.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        self.0.scenario()
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        self.0.configuration()
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        self.0.native_retirement()
    }

    pub(crate) fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        self.0.retire_native_source()
    }
}

/// Exact checkpoint returned by an execution before immutable publication.
///
/// The internal prepared form is deliberately opaque. Only the pool-owned
/// handoff can mint proof that the exact root was durably staged while QEMU was
/// still live; an external execution model may return only a captured value.
#[derive(Debug)]
pub struct AttemptCheckpointResult(AttemptCheckpointResultState);

#[derive(Debug)]
pub(crate) enum AttemptCheckpointResultState {
    Captured(Box<CapturedAttemptCheckpoint>),
    Prepared(Box<PreparedAttemptCheckpoint>),
}

impl AttemptCheckpointResult {
    /// Returns the semantic scenario authenticated by this checkpoint result.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        match &self.0 {
            AttemptCheckpointResultState::Captured(checkpoint) => checkpoint.scenario(),
            AttemptCheckpointResultState::Prepared(checkpoint) => checkpoint.scenario(),
        }
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        match &self.0 {
            AttemptCheckpointResultState::Captured(checkpoint) => checkpoint.configuration(),
            AttemptCheckpointResultState::Prepared(checkpoint) => checkpoint.configuration(),
        }
    }

    pub(crate) fn from_prepared(checkpoint: PreparedAttemptCheckpoint) -> Self {
        Self(AttemptCheckpointResultState::Prepared(Box::new(checkpoint)))
    }

    pub(crate) fn into_state(self) -> AttemptCheckpointResultState {
        self.0
    }
}

impl From<CapturedAttemptCheckpoint> for AttemptCheckpointResult {
    fn from(checkpoint: CapturedAttemptCheckpoint) -> Self {
        Self(AttemptCheckpointResultState::Captured(Box::new(checkpoint)))
    }
}

/// Durable immutable store for exact QEMU checkpoint closures.
pub struct ExactCheckpointStore {
    backend: Arc<dyn ImmutableBlobBackend>,
    maximum_checkpoint_bytes: u64,
    live_replay_promotions: Mutex<BTreeMap<ExactCheckpointId, LiveReplayPromotionState>>,
}

#[derive(Clone, Copy)]
enum LiveReplayPromotionState {
    Available(ContentId),
    Claimed(ContentId),
    Spent,
}

pub(crate) struct LiveReplayPromotionClaim<'a> {
    store: &'a ExactCheckpointStore,
    root: ExactCheckpointId,
    evidence: ContentId,
    committed: bool,
}

impl LiveReplayPromotionClaim<'_> {
    pub(crate) const fn evidence(&self) -> ContentId {
        self.evidence
    }

    pub(crate) fn commit(mut self) -> Result<(), ExactCheckpointStoreError> {
        let mut promotions = self
            .store
            .live_replay_promotions
            .lock()
            .map_err(|_| invalid_root("live replay-promotion registry is poisoned"))?;
        match promotions.get(&self.root).copied() {
            Some(LiveReplayPromotionState::Claimed(evidence)) if evidence == self.evidence => {
                promotions.insert(self.root, LiveReplayPromotionState::Spent);
                self.committed = true;
                Ok(())
            }
            _ => Err(invalid_root("live replay-promotion claim was lost")),
        }
    }
}

impl Drop for LiveReplayPromotionClaim<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Ok(mut promotions) = self.store.live_replay_promotions.lock()
            && matches!(
                promotions.get(&self.root),
                Some(LiveReplayPromotionState::Claimed(evidence)) if *evidence == self.evidence
            )
        {
            promotions.insert(
                self.root,
                LiveReplayPromotionState::Available(self.evidence),
            );
        }
    }
}

impl ExactCheckpointStore {
    /// Admits a durable streaming immutable backend and checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointStoreError::UnsupportedBackend`] unless the
    /// backend is durable and supports streaming reads, streaming puts, and
    /// conditional creation. A zero checkpoint ceiling is rejected.
    pub fn new(
        backend: Arc<dyn ImmutableBlobBackend>,
        maximum_checkpoint_bytes: u64,
    ) -> Result<Self, ExactCheckpointStoreError> {
        if maximum_checkpoint_bytes == 0 {
            return Err(ExactCheckpointStoreError::InvalidLimit);
        }
        let capabilities = backend.capabilities();
        for (available, capability) in [
            (capabilities.durable, "durable"),
            (capabilities.streaming_read, "streaming-read"),
            (capabilities.streaming_put, "streaming-put"),
            (capabilities.conditional_create, "conditional-create"),
        ] {
            if !available {
                return Err(ExactCheckpointStoreError::UnsupportedBackend { capability });
            }
        }
        Ok(Self {
            backend,
            maximum_checkpoint_bytes,
            live_replay_promotions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the configured aggregate per-checkpoint byte ceiling.
    #[must_use]
    pub const fn maximum_checkpoint_bytes(&self) -> u64 {
        self.maximum_checkpoint_bytes
    }

    pub(crate) fn retain_live_replay_promotion(
        &self,
        root: ExactCheckpointId,
        evidence: ContentId,
    ) -> Result<(), ExactCheckpointStoreError> {
        let mut promotions = self
            .live_replay_promotions
            .lock()
            .map_err(|_| invalid_root("live replay-promotion registry is poisoned"))?;
        match promotions.get(&root) {
            None => {
                promotions.insert(root, LiveReplayPromotionState::Available(evidence));
                Ok(())
            }
            Some(LiveReplayPromotionState::Available(expected)) if *expected == evidence => Ok(()),
            Some(LiveReplayPromotionState::Available(_)) => {
                Err(invalid_root("live replay-promotion evidence changed"))
            }
            Some(LiveReplayPromotionState::Claimed(_)) => {
                Err(invalid_root("live replay-promotion is already claimed"))
            }
            Some(LiveReplayPromotionState::Spent) => {
                Err(invalid_root("live replay-promotion is already spent"))
            }
        }
    }

    pub(crate) fn acquire_live_replay_promotion(
        &self,
        root: ExactCheckpointId,
        evidence: ContentId,
    ) -> Result<Option<LiveReplayPromotionClaim<'_>>, ExactCheckpointStoreError> {
        let mut promotions = self
            .live_replay_promotions
            .lock()
            .map_err(|_| invalid_root("live replay-promotion registry is poisoned"))?;
        match promotions.get(&root).copied() {
            Some(LiveReplayPromotionState::Available(expected)) if expected == evidence => {
                promotions.insert(root, LiveReplayPromotionState::Claimed(evidence));
                Ok(Some(LiveReplayPromotionClaim {
                    store: self,
                    root,
                    evidence,
                    committed: false,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Authenticates either accepted attempt capture without immutable writes.
    ///
    /// # Errors
    ///
    /// Returns the corresponding single-node or production preparation error.
    pub fn prepare_attempt_checkpoint(
        &self,
        capture: &CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, ExactCheckpointStoreError> {
        let choices = capture.choice_closure_bytes()?;
        self.prepare_production_closure_inner(capture.closure.clone(), choices, None)
            .map(PreparedAttemptCheckpoint)
    }

    /// Authenticates and prepares a capture under one execution cancellation signal.
    ///
    /// Complete large-object reads observe `cancellation` between at-most-one-
    /// MiB chunks. The prepared streams retain the same signal so publication
    /// cannot continue silently after cancellation wins.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointStoreError::Canceled`] when cancellation wins,
    /// or a production preparation error.
    pub(crate) fn prepare_attempt_checkpoint_with_cancellation(
        &self,
        capture: &CapturedAttemptCheckpoint,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedAttemptCheckpoint, ExactCheckpointStoreError> {
        if cancellation.is_canceled() {
            return Err(ExactCheckpointStoreError::Canceled);
        }
        let choices = capture.choice_closure_bytes()?;
        self.prepare_production_closure_with_cancellation(
            capture.closure.clone(),
            choices,
            cancellation,
        )
        .map(PreparedAttemptCheckpoint)
    }

    /// Publishes one prepared production checkpoint through root-last ordering.
    ///
    /// # Errors
    ///
    /// Returns a production publication error.
    pub fn publish_attempt_checkpoint(
        &self,
        prepared: &PreparedAttemptCheckpoint,
    ) -> Result<ProductionExactCheckpointPublication, ExactCheckpointStoreError> {
        self.publish_production_closure(&prepared.0)
    }

    /// Loads one production attempt checkpoint.
    ///
    /// Dispatch is bound to the typed root's canonical schema version. The
    /// production loader reauthenticates the envelope kind, version,
    /// content identity, semantic basis, and complete bounded index before this
    /// method returns. Noncurrent roots fail closed as unsupported.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncurrent root version or any absence, corruption,
    /// identity, semantic-basis, index, or size failure.
    pub fn load_attempt_checkpoint(
        &self,
        root: ExactCheckpointId,
    ) -> Result<LoadedProductionExactCheckpoint, ExactCheckpointStoreError> {
        self.load_production_closure(root)
    }

    pub(crate) fn read_authenticated_finding_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, ExactCheckpointStoreError> {
        Ok(self.backend.read(object, None)?)
    }
}

pub(crate) struct ExactFindingCheckpointAuthenticator<'a> {
    campaign: &'a CampaignExecutorStore,
    checkpoints: &'a ExactCheckpointStore,
}

impl<'a> ExactFindingCheckpointAuthenticator<'a> {
    pub(crate) const fn new(
        campaign: &'a CampaignExecutorStore,
        checkpoints: &'a ExactCheckpointStore,
    ) -> Self {
        Self {
            campaign,
            checkpoints,
        }
    }
}

impl FindingExactCheckpointAuthenticator for ExactFindingCheckpointAuthenticator<'_> {
    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        let loaded = Arc::new(
            self.checkpoints
                .load_attempt_checkpoint(checkpoint)
                .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)?,
        );
        let metadata_bytes = loaded
            .metadata_bytes()
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
        if metadata_bytes > maximum_metadata_bytes {
            return Err(FindingExactCheckpointAuthenticationError::LimitExceeded);
        }
        let artifact = self
            .campaign
            .load_scenario_artifact(scenario_artifact)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
        let source = crate::decode_crucible_scenario_artifact(&artifact)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
        let decoded = loaded
            .decode_semantic_checkpoint(&source, &ExecutionCancellation::default())
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)?;
        let authenticated_scenario =
            ScenarioDefId::from_hash(CampaignHash::from_bytes(loaded.scenario().bytes));
        let authenticated_configuration = ConfigurationId::from_hash(CampaignHash::from_bytes(
            decoded.configuration().id().bytes,
        ));
        if authenticated_scenario != scenario || authenticated_configuration != configuration {
            return Err(FindingExactCheckpointAuthenticationError::AuthenticationFailed);
        }
        Ok(AuthenticatedFindingExactCheckpoint::new(
            authenticated_scenario,
            authenticated_configuration,
            decoded.scheduler().event_log_offset().events,
            metadata_bytes,
        ))
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        self.checkpoints
            .read_authenticated_finding_object(object)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

/// Failure while preparing, publishing, or loading an exact QEMU checkpoint.
#[derive(Debug, Error)]
pub enum ExactCheckpointStoreError {
    /// The owning execution canceled checkpoint preparation or publication.
    #[error("exact-checkpoint operation was canceled")]
    Canceled,
    /// The configured per-checkpoint byte ceiling was zero.
    #[error("exact-checkpoint byte limit must be nonzero")]
    InvalidLimit,
    /// The immutable backend lacks a required safety capability.
    #[error("exact-checkpoint store lacks required backend capability {capability}")]
    UnsupportedBackend {
        /// Missing capability name.
        capability: &'static str,
    },
    /// One artifact was empty or exceeded a local hard byte limit.
    #[error(
        "exact-checkpoint {artifact} has {length} bytes outside the admitted maximum {maximum}"
    )]
    ArtifactLimit {
        /// Logical artifact role.
        artifact: &'static str,
        /// Declared or encoded bytes.
        length: u64,
        /// Admitted maximum bytes.
        maximum: u64,
    },
    /// Root structure or semantic bindings were inconsistent.
    #[error("exact-checkpoint root is invalid: {reason}")]
    InvalidRoot {
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// A backend claimed success without exact durable placement evidence.
    #[error("exact-checkpoint placement receipt for {id} is not exact and durable")]
    InvalidReceipt {
        /// Logical object whose receipt was invalid.
        id: ContentId,
    },
    /// The underlying immutable store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The generic root envelope was malformed or over limit.
    #[error(transparent)]
    Envelope(#[from] ContentEnvelopeError),
    /// The complete production continuation failed scenario-aware authentication.
    #[error(transparent)]
    Production(#[from] crucible_api::LifecycleApiError),
    /// Attempt-local native checkpoint retirement failed.
    #[error(transparent)]
    NativeRetirement(#[from] crucible_api::ProductionExactCheckpointRetirementError),
}

fn map_checkpoint_store_error(error: StoreError) -> ExactCheckpointStoreError {
    match error {
        StoreError::StreamIo { source, .. } if is_checkpoint_cancellation_io(&source) => {
            ExactCheckpointStoreError::Canceled
        }
        error => ExactCheckpointStoreError::Store(error),
    }
}

fn cancellation_blob_handle(source: BlobHandle, cancellation: ExecutionCancellation) -> BlobHandle {
    BlobHandle::new(Arc::new(CancellationBlobSource {
        source,
        cancellation,
    }))
}

struct CancellationBlobSource {
    source: BlobHandle,
    cancellation: ExecutionCancellation,
}

impl crucible_cas::content_store::BlobSource for CancellationBlobSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        if self.cancellation.is_canceled() {
            return Err(StoreError::StreamIo {
                operation: "open-canceled-exact-checkpoint-source",
                source: checkpoint_cancellation_io(),
            });
        }
        Ok(Box::new(CancellationReader {
            source: self.source.open()?,
            cancellation: self.cancellation.clone(),
        }))
    }
}

struct CancellationReader {
    source: Box<dyn Read + Send>,
    cancellation: ExecutionCancellation,
}

impl Read for CancellationReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_canceled() {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        let limit = buffer.len().min(CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES);
        let read = self.source.read(&mut buffer[..limit])?;
        if self.cancellation.is_canceled() {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        Ok(read)
    }
}

#[derive(Debug)]
struct CheckpointCancellationIo;

impl fmt::Display for CheckpointCancellationIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("checkpoint canceled")
    }
}

impl std::error::Error for CheckpointCancellationIo {}

fn checkpoint_cancellation_io() -> io::Error {
    io::Error::other(CheckpointCancellationIo)
}

fn is_checkpoint_cancellation_io(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<CheckpointCancellationIo>())
}

impl ExactCheckpointStoreError {
    /// Returns whether retrying the same retained phase may repair the failure.
    ///
    /// Only explicit backend availability and I/O failures are retryable. A
    /// malformed capture, corrupt content, quota rejection, poisoned owner, or
    /// incompatible capability is stable and must be canceled or quarantined
    /// rather than retried forever.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Store(
                StoreError::Unavailable | StoreError::Io { .. } | StoreError::StreamIo { .. }
            )
        ) || matches!(self, Self::NativeRetirement(error) if error.is_retryable())
    }
}

fn require_durable_receipt(
    receipt: PutReceipt,
    expected: ContentId,
    expected_length: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let exact_durable = receipt.id == expected
        && receipt.is_durable()
        && receipt
            .placements
            .iter()
            .filter(|placement| placement.durable)
            .all(|placement| placement.logical_length == expected_length);
    if !exact_durable {
        return Err(ExactCheckpointStoreError::InvalidReceipt { id: expected });
    }
    Ok(())
}

const fn invalid_root(reason: &'static str) -> ExactCheckpointStoreError {
    ExactCheckpointStoreError::InvalidRoot { reason }
}
