//! Crash-safe operational assignment records for the local executor.
//!
//! The ledger separates immutable assignment replies from mutable per-attempt
//! runtime state. Directory records are addressed directly by assignment or
//! attempt identity, so restart recovery does not materialize daemon history in
//! memory. Every file is bounded, checksummed, strictly decoded, and published
//! through an fsynced staging file followed by an atomic link or rename.
//! Retention administration is a separate mutable capability whose fence binds
//! one combined operational-root scan to a persistent generation.
//!
//! The directory layout is:
//!
//! ```text
//! <ledger>/
//!   writer.lock
//!   retention-state-v1
//!   assignments/<two-hex>/<assignment-id-hex>
//!   attempts/<two-hex>/<attempt-key-hash>
//! ```

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_campaign::{
    AssignmentId, AttemptId, CampaignCodecError, CampaignHash, CampaignLineageId, DaemonEpoch,
    ExactCheckpointId, ExecutionId, ObservationId, SubmitAttemptRequest, SubmitAttemptResponse,
};
use rustix::fs::{FlockOperation, flock};

const ASSIGNMENT_MAGIC: &[u8] = b"crucible.executor.assignment-record.v1\0";
const ATTEMPT_STATE_MAGIC: &[u8] = b"crucible.executor.attempt-state-record.v4\0";
const ATTEMPT_STATE_MAGIC_V3: &[u8] = b"crucible.executor.attempt-state-record.v3\0";
const ATTEMPT_STATE_MAGIC_V2: &[u8] = b"crucible.executor.attempt-state-record.v2\0";
const ATTEMPT_STATE_MAGIC_V1: &[u8] = b"crucible.executor.attempt-state-record.v1\0";
const ASSIGNMENT_CHECKSUM_DOMAIN: &str = "crucible.executor.assignment-record.v1";
const ATTEMPT_STATE_CHECKSUM_DOMAIN: &str = "crucible.executor.attempt-state-record.v4";
const ATTEMPT_STATE_CHECKSUM_DOMAIN_V3: &str = "crucible.executor.attempt-state-record.v3";
const ATTEMPT_STATE_CHECKSUM_DOMAIN_V2: &str = "crucible.executor.attempt-state-record.v2";
const ATTEMPT_STATE_CHECKSUM_DOMAIN_V1: &str = "crucible.executor.attempt-state-record.v1";
const RETENTION_STATE_MAGIC: &[u8] = b"crucible.executor.assignment-retention-state.v1\0";
const RETENTION_STATE_CHECKSUM_DOMAIN: &str = "crucible.executor.assignment-retention-state.v1";
const RETENTION_GENERATION_DOMAIN: &str = "crucible.executor.assignment-retention-generation.v1";
const RETENTION_STATE_FILE: &str = "retention-state-v1";
const MAX_LEDGER_RECORD_BYTES: u64 = 16 * 1024;
const MAX_RETENTION_STATE_BYTES: u64 = 256;
const MAX_TYPED_ID_BYTES: usize = 256;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);
static MEMORY_LEDGER_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One immutable exact request and its first durable protocol response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssignmentRecord {
    request: SubmitAttemptRequest,
    response: SubmitAttemptResponse,
}

impl AssignmentRecord {
    /// Builds an assignment record whose response authenticates the request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the response belongs to any other
    /// canonical request basis.
    pub fn new(
        request: SubmitAttemptRequest,
        response: SubmitAttemptResponse,
    ) -> Result<Self, CampaignCodecError> {
        response.validate_for(&request)?;
        Ok(Self { request, response })
    }

    /// Returns the exact request retained for idempotency.
    #[must_use]
    pub const fn request(&self) -> &SubmitAttemptRequest {
        &self.request
    }

    /// Returns the first durable response retained for exact replay.
    #[must_use]
    pub const fn response(&self) -> &SubmitAttemptResponse {
        &self.response
    }
}

/// Exact lineage-qualified semantic key for operational attempt runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttemptExecutionKey {
    lineage: CampaignLineageId,
    attempt: AttemptId,
}

/// Durable operational origin of one local execution incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptExecutionOrigin {
    /// Execution begins from the immutable attempt's starting configuration.
    Initial,
    /// Execution resumes from one exact durable paused root.
    ExactCheckpoint {
        /// Idempotent assignment identity for the resume operation.
        assignment: AssignmentId,
        /// Digest of every canonical resume-request field.
        request_digest: CampaignHash,
        /// Execution incarnation that produced the paused root.
        prior_execution: ExecutionId,
        /// Exact checkpoint from which execution must resume.
        checkpoint: ExactCheckpointId,
    },
}

impl AttemptExecutionOrigin {
    /// Returns the exact resume checkpoint, when this is a resumed execution.
    #[must_use]
    pub const fn checkpoint(self) -> Option<ExactCheckpointId> {
        match self {
            Self::Initial => None,
            Self::ExactCheckpoint { checkpoint, .. } => Some(checkpoint),
        }
    }
}

impl AttemptExecutionKey {
    /// Builds the runtime key for one exact lineage and semantic attempt.
    #[must_use]
    pub const fn new(lineage: CampaignLineageId, attempt: AttemptId) -> Self {
        Self { lineage, attempt }
    }

    /// Returns the exact compatibility lineage.
    #[must_use]
    pub const fn lineage(self) -> CampaignLineageId {
        self.lineage
    }

    /// Returns the immutable semantic attempt.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }
}

/// Durable operational state for one semantic attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptRuntimeState {
    /// One execution is currently owned by a daemon incarnation.
    Running {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
    },
    /// One execution has durably latched an exact-checkpoint request.
    CheckpointRequested {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
    },
    /// One execution has durably reserved an exact-checkpoint publication root.
    CheckpointPublishing {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
        /// Expected exact root, whether or not all immutable bytes are present.
        checkpoint: ExactCheckpointId,
    },
    /// One execution stopped at a complete durable exact checkpoint.
    Paused {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the paused execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
        /// Complete durable exact-checkpoint root.
        checkpoint: ExactCheckpointId,
    },
    /// One execution has durably reserved an observation publication root.
    Publishing {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
        /// Expected immutable observation, whether or not all bytes are present yet.
        observation: ObservationId,
    },
    /// One execution published an immutable observation.
    Completed {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the completed execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
        /// Immutable completed observation.
        observation: ObservationId,
    },
    /// The daemon accepted cancellation before canonical completion.
    Canceled {
        /// Digest of lineage, attempt, resources, and retention.
        execution_basis: CampaignHash,
        /// Initial-start or exact-checkpoint execution origin.
        origin: AttemptExecutionOrigin,
        /// Daemon incarnation that admitted the canceled execution.
        daemon_epoch: DaemonEpoch,
        /// Process-local execution identity.
        execution: ExecutionId,
    },
}

impl AttemptRuntimeState {
    /// Returns the exact operational execution-contract digest.
    #[must_use]
    pub const fn execution_basis(self) -> CampaignHash {
        match self {
            Self::Running {
                execution_basis, ..
            }
            | Self::CheckpointRequested {
                execution_basis, ..
            }
            | Self::CheckpointPublishing {
                execution_basis, ..
            }
            | Self::Paused {
                execution_basis, ..
            }
            | Self::Publishing {
                execution_basis, ..
            }
            | Self::Completed {
                execution_basis, ..
            }
            | Self::Canceled {
                execution_basis, ..
            } => execution_basis,
        }
    }

    /// Returns the durable origin of this execution incarnation.
    #[must_use]
    pub const fn origin(self) -> AttemptExecutionOrigin {
        match self {
            Self::Running { origin, .. }
            | Self::CheckpointRequested { origin, .. }
            | Self::CheckpointPublishing { origin, .. }
            | Self::Paused { origin, .. }
            | Self::Publishing { origin, .. }
            | Self::Completed { origin, .. }
            | Self::Canceled { origin, .. } => origin,
        }
    }

    /// Returns the daemon incarnation that admitted this runtime state.
    #[must_use]
    pub const fn daemon_epoch(self) -> DaemonEpoch {
        match self {
            Self::Running { daemon_epoch, .. }
            | Self::CheckpointRequested { daemon_epoch, .. }
            | Self::CheckpointPublishing { daemon_epoch, .. }
            | Self::Paused { daemon_epoch, .. }
            | Self::Publishing { daemon_epoch, .. }
            | Self::Completed { daemon_epoch, .. }
            | Self::Canceled { daemon_epoch, .. } => daemon_epoch,
        }
    }

    /// Returns the local execution named by this runtime state.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        match self {
            Self::Running { execution, .. }
            | Self::CheckpointRequested { execution, .. }
            | Self::CheckpointPublishing { execution, .. }
            | Self::Paused { execution, .. }
            | Self::Publishing { execution, .. }
            | Self::Completed { execution, .. }
            | Self::Canceled { execution, .. } => execution,
        }
    }

    /// Returns the completed observation, when one was durably published.
    #[must_use]
    pub const fn observation(self) -> Option<ObservationId> {
        match self {
            Self::Publishing { observation, .. } | Self::Completed { observation, .. } => {
                Some(observation)
            }
            Self::Running { .. }
            | Self::CheckpointRequested { .. }
            | Self::CheckpointPublishing { .. }
            | Self::Paused { .. }
            | Self::Canceled { .. } => None,
        }
    }

    /// Returns an exact-checkpoint retention root, when one is durable.
    #[must_use]
    pub const fn checkpoint(self) -> Option<ExactCheckpointId> {
        match self {
            Self::CheckpointPublishing { checkpoint, .. } | Self::Paused { checkpoint, .. } => {
                Some(checkpoint)
            }
            Self::Running { .. }
            | Self::CheckpointRequested { .. }
            | Self::Publishing { .. }
            | Self::Completed { .. }
            | Self::Canceled { .. } => None,
        }
    }

    /// Returns the retained input root of a resumed execution, when present.
    #[must_use]
    pub const fn origin_checkpoint(self) -> Option<ExactCheckpointId> {
        self.origin().checkpoint()
    }
}

/// Result of conditionally publishing one immutable assignment record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentPublish {
    /// The record became durable in this call.
    Stored,
    /// The exact record was already durable.
    Existing,
    /// The assignment identity already named different canonical bytes.
    Conflict,
}

/// Result of conditionally replacing one attempt runtime state.
// The conflict value deliberately remains inline and `Copy`: this bounded
// operational result crosses every ledger backend, and allocating merely to
// shrink the successful discriminant would add a new failure mode to CAS
// reconciliation. AttemptRuntimeState has a fixed 16 KiB encoded ceiling.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptStateCas {
    /// The requested state became durable.
    Advanced,
    /// The expected state did not match the current durable state.
    Conflict {
        /// Current state observed during the failed comparison.
        current: Option<AttemptRuntimeState>,
    },
}

/// Exact digest of one stable operational retention-root inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssignmentRetentionGeneration([u8; 32]);

impl AssignmentRetentionGeneration {
    /// Builds a backend-defined generation from exactly 32 canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw generation digest.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Renders the generation as canonical lowercase hexadecimal text.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

/// One durable operational root observed under an assignment-ledger fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentRetentionRoot {
    /// One in-progress or completed observation publication.
    Observation(ObservationId),
    /// One in-progress or paused exact-checkpoint publication.
    ExactCheckpoint(ExactCheckpointId),
}

/// Terminal evidence that one fenced assignment-ledger inventory completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentRetentionSummary {
    generation: AssignmentRetentionGeneration,
    attempt_records: u64,
    observation_roots: u64,
    checkpoint_roots: u64,
}

impl AssignmentRetentionSummary {
    /// Builds terminal counters for one completed backend inventory.
    #[must_use]
    pub const fn new(
        generation: AssignmentRetentionGeneration,
        attempt_records: u64,
        observation_roots: u64,
        checkpoint_roots: u64,
    ) -> Self {
        Self {
            generation,
            attempt_records,
            observation_roots,
            checkpoint_roots,
        }
    }

    /// Returns the exact operational-ledger generation.
    #[must_use]
    pub const fn generation(self) -> AssignmentRetentionGeneration {
        self.generation
    }

    /// Returns the number of authenticated attempt records visited.
    #[must_use]
    pub const fn attempt_records(self) -> u64 {
        self.attempt_records
    }

    /// Returns the number of observation roots emitted.
    #[must_use]
    pub const fn observation_roots(self) -> u64 {
        self.observation_roots
    }

    /// Returns the number of exact-checkpoint roots emitted.
    #[must_use]
    pub const fn checkpoint_roots(self) -> u64 {
        self.checkpoint_roots
    }

    fn visit(
        &mut self,
        state: AttemptRuntimeState,
        visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<(), AssignmentRetentionVisitorError> {
        self.attempt_records = self
            .attempt_records
            .checked_add(1)
            .ok_or(AssignmentRetentionVisitorError::LimitExceeded)?;
        if let Some(observation) = state.observation() {
            self.observation_roots = self
                .observation_roots
                .checked_add(1)
                .ok_or(AssignmentRetentionVisitorError::LimitExceeded)?;
            visitor(AssignmentRetentionRoot::Observation(observation))?;
        }
        if let Some(checkpoint) = state.checkpoint() {
            self.checkpoint_roots = self
                .checkpoint_roots
                .checked_add(1)
                .ok_or(AssignmentRetentionVisitorError::LimitExceeded)?;
            visitor(AssignmentRetentionRoot::ExactCheckpoint(checkpoint))?;
        }
        if let Some(checkpoint) = state.origin_checkpoint()
            && state.checkpoint() != Some(checkpoint)
        {
            self.checkpoint_roots = self
                .checkpoint_roots
                .checked_add(1)
                .ok_or(AssignmentRetentionVisitorError::LimitExceeded)?;
            visitor(AssignmentRetentionRoot::ExactCheckpoint(checkpoint))?;
        }
        Ok(())
    }
}

/// Stable reason a retention-inventory consumer stopped a fenced scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentRetentionVisitorError {
    /// The consumer's checked work or output bound was exhausted.
    #[error("assignment retention inventory limit exceeded")]
    LimitExceeded,
}

/// Failure to complete one fenced assignment-ledger inventory.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentRetentionInventoryError<E> {
    /// The ledger could not authenticate or enumerate its complete state.
    #[error("assignment retention inventory backend failed")]
    Backend(#[source] E),
    /// The inventory consumer rejected a tentative record prefix.
    #[error(transparent)]
    Visitor(#[from] AssignmentRetentionVisitorError),
}

/// Exclusive authority over one operational assignment-ledger root inventory.
///
/// Visitor output is tentative until terminal success. The visitor must not
/// reenter the fenced ledger.
pub trait AssignmentRetentionFence {
    /// Backend-specific persistence or authentication failure.
    type BackendError;

    /// Streams every durable observation and exact-checkpoint root once.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentRetentionInventoryError::Backend`] when the ledger
    /// cannot authenticate or completely enumerate its state, or
    /// [`AssignmentRetentionInventoryError::Visitor`] when the consumer stops
    /// the scan.
    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>;
}

/// Separate maintenance capability for operational assignment-ledger roots.
pub trait AssignmentRetentionAdmin {
    /// Backend-specific fence-acquisition and inventory failure.
    type Error;

    /// Acquires exclusive root-inventory authority for this ledger.
    ///
    /// # Errors
    ///
    /// Returns the backend error when the ledger cannot establish a complete,
    /// stable root inventory or load its persistent generation.
    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>;
}

/// Pluggable operational ledger used by the single-host executor supervisor.
pub trait AssignmentLedger {
    /// Backend-specific persistence failure.
    type Error;

    /// Loads an immutable assignment response by exact assignment identity.
    ///
    /// A successful existing-record result also reestablishes durable parent
    /// directory metadata after a prior commit-indeterminate publication.
    ///
    /// # Errors
    ///
    /// Returns the backend error when absence cannot be distinguished safely or
    /// when an existing record is malformed, corrupt, or inconsistent.
    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error>;

    /// Conditionally publishes one immutable assignment response.
    ///
    /// # Errors
    ///
    /// Returns the backend error when durable publication or validation fails.
    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error>;

    /// Loads durable runtime state for one lineage-qualified semantic attempt.
    ///
    /// A successful result, including absence, also reestablishes durable
    /// parent-directory metadata when the directory exists. A caller may
    /// therefore use the result to reconcile a prior compare-exchange error.
    ///
    /// # Errors
    ///
    /// Returns the backend error when absence cannot be distinguished safely or
    /// when an existing record is malformed, corrupt, or inconsistent.
    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error>;

    /// Conditionally replaces one attempt runtime state.
    ///
    /// # Errors
    ///
    /// Returns the backend error when durable publication or validation fails.
    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error>;

    /// Streams durable in-progress and completed observation retention roots.
    ///
    /// This unfenced operation supports executor recovery and diagnostics. It
    /// is not a generation-bound input to destructive GC; maintenance code
    /// must use [`AssignmentRetentionAdmin`]. The visitor is invoked once per
    /// runtime record that names an observation, and implementations must not
    /// materialize the complete ledger in memory.
    ///
    /// # Errors
    ///
    /// Returns the backend error when the root set cannot be enumerated
    /// completely or any durable runtime record is corrupt.
    fn visit_observation_roots(
        &self,
        visitor: &mut dyn FnMut(ObservationId),
    ) -> Result<(), Self::Error>;

    /// Streams durable in-progress and paused exact-checkpoint roots.
    ///
    /// This unfenced operation supports executor recovery and diagnostics. It
    /// is not a generation-bound input to destructive GC; maintenance code
    /// must use [`AssignmentRetentionAdmin`]. Implementations invoke the
    /// visitor once per runtime record naming a checkpoint and stream without
    /// materializing the complete ledger.
    ///
    /// # Errors
    ///
    /// Returns the backend error when enumeration is incomplete or corrupt.
    fn visit_checkpoint_roots(
        &self,
        visitor: &mut dyn FnMut(ExactCheckpointId),
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy)]
struct AssignmentRetentionState {
    instance: [u8; 32],
    generation: u64,
}

impl AssignmentRetentionState {
    fn advance(&mut self) -> Result<(), AssignmentLedgerError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AssignmentLedgerError::GenerationExhausted)?;
        Ok(())
    }

    fn digest(self) -> AssignmentRetentionGeneration {
        let mut material = [0_u8; 40];
        material[..32].copy_from_slice(&self.instance);
        material[32..].copy_from_slice(&self.generation.to_le_bytes());
        AssignmentRetentionGeneration(
            CampaignHash::derive(RETENTION_GENERATION_DOMAIN, &material).as_bytes(),
        )
    }
}

/// In-memory assignment ledger for component tests and fake executors.
pub struct MemoryAssignmentLedger {
    assignments: BTreeMap<AssignmentId, AssignmentRecord>,
    attempts: BTreeMap<AttemptExecutionKey, AttemptRuntimeState>,
    retention_generation: AssignmentRetentionGeneration,
}

impl Default for MemoryAssignmentLedger {
    fn default() -> Self {
        let ordinal = MEMORY_LEDGER_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let generation = CampaignHash::derive(
            "crucible.executor.memory-assignment-ledger-instance.v1",
            &ordinal.to_le_bytes(),
        )
        .as_bytes();
        Self {
            assignments: BTreeMap::new(),
            attempts: BTreeMap::new(),
            retention_generation: AssignmentRetentionGeneration::from_bytes(generation),
        }
    }
}

impl AssignmentLedger for MemoryAssignmentLedger {
    type Error = std::convert::Infallible;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        Ok(self.assignments.get(&assignment).cloned())
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        let assignment = record.request.assignment();
        let outcome = match self.assignments.get(&assignment) {
            Some(existing) if existing == record => AssignmentPublish::Existing,
            Some(_) => AssignmentPublish::Conflict,
            None => {
                self.assignments.insert(assignment, record.clone());
                AssignmentPublish::Stored
            }
        };
        Ok(outcome)
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        Ok(self.attempts.get(&key).copied())
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        let current = self.attempts.get(&key).copied();
        if current != expected {
            return Ok(AttemptStateCas::Conflict { current });
        }
        self.retention_generation = AssignmentRetentionGeneration::from_bytes(
            CampaignHash::derive(
                "crucible.executor.memory-assignment-retention-next.v1",
                &self.retention_generation.as_bytes(),
            )
            .as_bytes(),
        );
        match next {
            Some(next) => {
                self.attempts.insert(key, next);
            }
            None => {
                self.attempts.remove(&key);
            }
        }
        Ok(AttemptStateCas::Advanced)
    }

    fn visit_observation_roots(
        &self,
        visitor: &mut dyn FnMut(ObservationId),
    ) -> Result<(), Self::Error> {
        for state in self.attempts.values().copied() {
            if let Some(observation) = state.observation() {
                visitor(observation);
            }
        }
        Ok(())
    }

    fn visit_checkpoint_roots(
        &self,
        visitor: &mut dyn FnMut(ExactCheckpointId),
    ) -> Result<(), Self::Error> {
        for state in self.attempts.values().copied() {
            if let Some(checkpoint) = state.checkpoint() {
                visitor(checkpoint);
            }
            if let Some(checkpoint) = state.origin_checkpoint()
                && state.checkpoint() != Some(checkpoint)
            {
                visitor(checkpoint);
            }
        }
        Ok(())
    }
}

impl AssignmentRetentionAdmin for MemoryAssignmentLedger {
    type Error = std::convert::Infallible;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        Ok(Box::new(MemoryAssignmentRetentionFence { ledger: self }))
    }
}

struct MemoryAssignmentRetentionFence<'a> {
    ledger: &'a mut MemoryAssignmentLedger,
}

impl AssignmentRetentionFence for MemoryAssignmentRetentionFence<'_> {
    type BackendError = std::convert::Infallible;

    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        let mut summary =
            AssignmentRetentionSummary::new(self.ledger.retention_generation, 0, 0, 0);
        for state in self.ledger.attempts.values().copied() {
            summary.visit(state, visitor)?;
        }
        Ok(summary)
    }
}

/// Failure from an assignment ledger.
#[derive(Debug, thiserror::Error)]
pub enum AssignmentLedgerError {
    /// A filesystem operation failed.
    #[error("assignment ledger {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact path being operated on.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// A canonical component message failed strict decoding.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// A ledger record was truncated, corrupt, or internally inconsistent.
    #[error("assignment ledger record is corrupt: {reason}")]
    Corrupt {
        /// Stable corruption category.
        reason: &'static str,
    },
    /// A monotonic operational-retention generation was exhausted.
    #[error("assignment ledger retention generation exhausted")]
    GenerationExhausted,
}

/// Crash-safe directory ledger with one nonblocking process writer lock.
pub struct DirectoryAssignmentLedger {
    root: PathBuf,
    _writer_lock: File,
    retention_state: AssignmentRetentionState,
}

impl DirectoryAssignmentLedger {
    /// Opens a durable ledger and acquires exclusive single-writer ownership.
    ///
    /// Direct record lookup keeps restart memory proportional to active work,
    /// not historical assignments.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentLedgerError`] when the directory cannot be created,
    /// another writer owns it, or the lock cannot be acquired safely.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, AssignmentLedgerError> {
        let root = root.into();
        create_directory_durable(&root)?;
        let lock_path = root.join("writer.lock");
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|source| io_error("open-writer-lock", &lock_path, source))?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            io_error(
                "lock-writer",
                &lock_path,
                std::io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        sync_directory(&root)?;
        let retention_state = load_or_create_retention_state(&root)?;
        Ok(Self {
            root,
            _writer_lock: writer_lock,
            retention_state,
        })
    }

    /// Returns the physical ledger root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn assignment_path(&self, assignment: AssignmentId) -> PathBuf {
        let encoded = encode_hex(&assignment.as_bytes());
        self.root
            .join("assignments")
            .join(&encoded[..2])
            .join(encoded)
    }

    fn attempt_path(&self, key: AttemptExecutionKey) -> PathBuf {
        let mut material = Vec::with_capacity(256);
        push_bytes(&mut material, key.lineage.to_text().as_bytes());
        push_bytes(&mut material, key.attempt.to_text().as_bytes());
        let encoded =
            CampaignHash::derive("crucible.executor.attempt-execution-key.v1", &material).to_hex();
        self.root.join("attempts").join(&encoded[..2]).join(encoded)
    }

    fn advance_retention_state(&mut self) -> Result<(), AssignmentLedgerError> {
        let mut next = self.retention_state;
        next.advance()?;
        persist_retention_state(&self.root, next)?;
        self.retention_state = next;
        Ok(())
    }

    fn visit_attempt_states(
        &self,
        visitor: &mut dyn FnMut(AttemptRuntimeState),
    ) -> Result<(), AssignmentLedgerError> {
        let attempts = self.root.join("attempts");
        let shards = match fs::read_dir(&attempts) {
            Ok(shards) => shards,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(io_error("read-attempt-root-shards", &attempts, source)),
        };
        for shard in shards {
            let shard =
                shard.map_err(|source| io_error("read-attempt-root-shard", &attempts, source))?;
            let shard_path = shard.path();
            let shard_name = shard.file_name();
            let shard_name = shard_name
                .to_str()
                .ok_or_else(|| corrupt("attempt-root-shard-name"))?;
            if shard_name.len() != 2
                || !shard_name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(corrupt("attempt-root-shard-name"));
            }
            if !shard
                .file_type()
                .map_err(|source| io_error("stat-attempt-root-shard", &shard_path, source))?
                .is_dir()
            {
                return Err(corrupt("attempt-root-shard-is-not-directory"));
            }
            let records = fs::read_dir(&shard_path)
                .map_err(|source| io_error("read-attempt-root-records", &shard_path, source))?;
            for record in records {
                let record = record
                    .map_err(|source| io_error("read-attempt-root-record", &shard_path, source))?;
                let path = record.path();
                let name = record.file_name();
                let name = name
                    .to_str()
                    .ok_or_else(|| corrupt("attempt-root-record-name"))?;
                if name.starts_with('.') {
                    if is_staging_name(name)
                        && record
                            .file_type()
                            .map_err(|source| io_error("stat-attempt-root-staging", &path, source))?
                            .is_file()
                    {
                        continue;
                    }
                    return Err(corrupt("attempt-root-unknown-hidden-entry"));
                }
                if name.len() != 64
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(corrupt("attempt-root-record-name"));
                }
                if !record
                    .file_type()
                    .map_err(|source| io_error("stat-attempt-root-record", &path, source))?
                    .is_file()
                {
                    return Err(corrupt("attempt-root-record-is-not-file"));
                }
                let bytes = read_optional_bounded(&path)?
                    .ok_or_else(|| corrupt("attempt-root-record-disappeared"))?;
                let (key, state) = decode_attempt_state(&bytes)?;
                if self.attempt_path(key) != path {
                    return Err(corrupt("attempt-root-record-path-identity-mismatch"));
                }
                visitor(state);
            }
        }
        Ok(())
    }
}

fn is_staging_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".staging-") else {
        return false;
    };
    let Some((process, ordinal)) = suffix.split_once('-') else {
        return false;
    };
    !process.is_empty()
        && process.bytes().all(|byte| byte.is_ascii_digit())
        && !ordinal.is_empty()
        && ordinal.bytes().all(|byte| byte.is_ascii_digit())
}

impl AssignmentLedger for DirectoryAssignmentLedger {
    type Error = AssignmentLedgerError;

    fn load_assignment(
        &self,
        assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        let path = self.assignment_path(assignment);
        let Some(bytes) = read_optional_bounded(&path)? else {
            return Ok(None);
        };
        sync_record_parent(&path)?;
        let record = decode_assignment_record(&bytes)?;
        if record.request.assignment() != assignment {
            return Err(corrupt("assignment-path-identity-mismatch"));
        }
        Ok(Some(record))
    }

    fn publish_assignment(
        &mut self,
        record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        let assignment = record.request.assignment();
        if let Some(existing) = self.load_assignment(assignment)? {
            return Ok(if existing == *record {
                AssignmentPublish::Existing
            } else {
                AssignmentPublish::Conflict
            });
        }

        let path = self.assignment_path(assignment);
        let published = publish_immutable(&path, &encode_assignment_record(record))?;
        if published {
            return Ok(AssignmentPublish::Stored);
        }
        let existing = self
            .load_assignment(assignment)?
            .ok_or_else(|| corrupt("assignment-publish-lost-race"))?;
        Ok(if existing == *record {
            AssignmentPublish::Existing
        } else {
            AssignmentPublish::Conflict
        })
    }

    fn load_attempt(
        &self,
        key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        let path = self.attempt_path(key);
        let Some(bytes) = read_optional_bounded(&path)? else {
            sync_record_parent_if_present(&path)?;
            return Ok(None);
        };
        sync_record_parent(&path)?;
        let (recorded_key, state) = decode_attempt_state(&bytes)?;
        if recorded_key != key {
            return Err(corrupt("attempt-path-identity-mismatch"));
        }
        Ok(Some(state))
    }

    fn compare_exchange_attempt(
        &mut self,
        key: AttemptExecutionKey,
        expected: Option<AttemptRuntimeState>,
        next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        let current = self.load_attempt(key)?;
        if current != expected {
            return Ok(AttemptStateCas::Conflict { current });
        }
        self.advance_retention_state()?;
        let path = self.attempt_path(key);
        match next {
            Some(next) => replace_mutable(&path, &encode_attempt_state(key, next))?,
            None => remove_mutable(&path)?,
        }
        Ok(AttemptStateCas::Advanced)
    }

    fn visit_observation_roots(
        &self,
        visitor: &mut dyn FnMut(ObservationId),
    ) -> Result<(), Self::Error> {
        self.visit_attempt_states(&mut |state| {
            if let Some(observation) = state.observation() {
                visitor(observation);
            }
        })
    }

    fn visit_checkpoint_roots(
        &self,
        visitor: &mut dyn FnMut(ExactCheckpointId),
    ) -> Result<(), Self::Error> {
        self.visit_attempt_states(&mut |state| {
            if let Some(checkpoint) = state.checkpoint() {
                visitor(checkpoint);
            }
            if let Some(checkpoint) = state.origin_checkpoint()
                && state.checkpoint() != Some(checkpoint)
            {
                visitor(checkpoint);
            }
        })
    }
}

impl AssignmentRetentionAdmin for DirectoryAssignmentLedger {
    type Error = AssignmentLedgerError;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        Ok(Box::new(DirectoryAssignmentRetentionFence { ledger: self }))
    }
}

struct DirectoryAssignmentRetentionFence<'a> {
    ledger: &'a mut DirectoryAssignmentLedger,
}

impl AssignmentRetentionFence for DirectoryAssignmentRetentionFence<'_> {
    type BackendError = AssignmentLedgerError;

    fn visit_roots(
        &mut self,
        visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        let mut summary =
            AssignmentRetentionSummary::new(self.ledger.retention_state.digest(), 0, 0, 0);
        let mut visitor_error = None;
        self.ledger
            .visit_attempt_states(&mut |state| {
                if visitor_error.is_none()
                    && let Err(source) = summary.visit(state, visitor)
                {
                    visitor_error = Some(source);
                }
            })
            .map_err(AssignmentRetentionInventoryError::Backend)?;
        if let Some(source) = visitor_error {
            return Err(AssignmentRetentionInventoryError::Visitor(source));
        }
        Ok(summary)
    }
}

fn encode_assignment_record(record: &AssignmentRecord) -> Vec<u8> {
    let request = record.request.canonical_bytes();
    let response = record.response.canonical_bytes();
    let mut payload = Vec::with_capacity(
        ASSIGNMENT_MAGIC.len() + request.len() + response.len() + 2 * size_of::<u32>(),
    );
    payload.extend_from_slice(ASSIGNMENT_MAGIC);
    push_bytes(&mut payload, &request);
    push_bytes(&mut payload, &response);
    seal(payload, ASSIGNMENT_CHECKSUM_DOMAIN)
}

fn decode_assignment_record(bytes: &[u8]) -> Result<AssignmentRecord, AssignmentLedgerError> {
    let payload = open_sealed(bytes, ASSIGNMENT_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(ASSIGNMENT_MAGIC)?;
    let request = SubmitAttemptRequest::from_canonical_bytes(cursor.bytes()?)?;
    let response = SubmitAttemptResponse::from_canonical_bytes(cursor.bytes()?)?;
    cursor.finish()?;
    AssignmentRecord::new(request, response).map_err(Into::into)
}

fn encode_attempt_state(key: AttemptExecutionKey, state: AttemptRuntimeState) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(ATTEMPT_STATE_MAGIC);
    push_bytes(&mut payload, key.lineage.to_text().as_bytes());
    push_bytes(&mut payload, key.attempt.to_text().as_bytes());
    payload.extend_from_slice(&state.execution_basis().as_bytes());
    encode_attempt_origin(&mut payload, state.origin());
    match state {
        AttemptRuntimeState::Running {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(0);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::CheckpointRequested {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(4);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
        AttemptRuntimeState::CheckpointPublishing {
            daemon_epoch,
            execution,
            checkpoint,
            ..
        } => {
            payload.push(5);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, checkpoint.to_text().as_bytes());
        }
        AttemptRuntimeState::Paused {
            daemon_epoch,
            execution,
            checkpoint,
            ..
        } => {
            payload.push(6);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, checkpoint.to_text().as_bytes());
        }
        AttemptRuntimeState::Completed {
            daemon_epoch,
            execution,
            observation,
            ..
        } => {
            payload.push(1);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
        }
        AttemptRuntimeState::Publishing {
            daemon_epoch,
            execution,
            observation,
            ..
        } => {
            payload.push(3);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
            push_bytes(&mut payload, observation.to_text().as_bytes());
        }
        AttemptRuntimeState::Canceled {
            daemon_epoch,
            execution,
            ..
        } => {
            payload.push(2);
            payload.extend_from_slice(&daemon_epoch.as_bytes());
            payload.extend_from_slice(&execution.as_bytes());
        }
    }
    seal(payload, ATTEMPT_STATE_CHECKSUM_DOMAIN)
}

fn decode_attempt_state(
    bytes: &[u8],
) -> Result<(AttemptExecutionKey, AttemptRuntimeState), AssignmentLedgerError> {
    let (payload, magic) = if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN) {
        (payload, ATTEMPT_STATE_MAGIC)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V3) {
        (payload, ATTEMPT_STATE_MAGIC_V3)
    } else if let Ok(payload) = open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V2) {
        (payload, ATTEMPT_STATE_MAGIC_V2)
    } else {
        (
            open_sealed(bytes, ATTEMPT_STATE_CHECKSUM_DOMAIN_V1)?,
            ATTEMPT_STATE_MAGIC_V1,
        )
    };
    let mut cursor = RecordCursor::new(payload);
    cursor.require(magic)?;
    let lineage = parse_typed(cursor.bytes()?, CampaignLineageId::parse)?;
    let attempt = parse_typed(cursor.bytes()?, AttemptId::parse)?;
    let execution_basis = CampaignHash::from_bytes(cursor.fixed()?);
    let origin = if magic == ATTEMPT_STATE_MAGIC {
        decode_attempt_origin(&mut cursor)?
    } else {
        AttemptExecutionOrigin::Initial
    };
    let tag = cursor.byte()?;
    let daemon_epoch = DaemonEpoch::from_bytes(cursor.fixed()?)?;
    let execution = ExecutionId::from_bytes(cursor.fixed()?)?;
    let state = match tag {
        0 => AttemptRuntimeState::Running {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        1 => AttemptRuntimeState::Completed {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
            observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
        },
        2 => AttemptRuntimeState::Canceled {
            execution_basis,
            origin,
            daemon_epoch,
            execution,
        },
        3 if magic == ATTEMPT_STATE_MAGIC
            || magic == ATTEMPT_STATE_MAGIC_V3
            || magic == ATTEMPT_STATE_MAGIC_V2 =>
        {
            AttemptRuntimeState::Publishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                observation: parse_typed(cursor.bytes()?, ObservationId::parse)?,
            }
        }
        4 if magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V3 => {
            AttemptRuntimeState::CheckpointRequested {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
            }
        }
        5 if magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V3 => {
            AttemptRuntimeState::CheckpointPublishing {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            }
        }
        6 if magic == ATTEMPT_STATE_MAGIC || magic == ATTEMPT_STATE_MAGIC_V3 => {
            AttemptRuntimeState::Paused {
                execution_basis,
                origin,
                daemon_epoch,
                execution,
                checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
            }
        }
        _ => return Err(corrupt("attempt-state-unknown-tag")),
    };
    cursor.finish()?;
    Ok((AttemptExecutionKey::new(lineage, attempt), state))
}

fn encode_attempt_origin(payload: &mut Vec<u8>, origin: AttemptExecutionOrigin) {
    match origin {
        AttemptExecutionOrigin::Initial => payload.push(0),
        AttemptExecutionOrigin::ExactCheckpoint {
            assignment,
            request_digest,
            prior_execution,
            checkpoint,
        } => {
            payload.push(1);
            payload.extend_from_slice(&assignment.as_bytes());
            payload.extend_from_slice(&request_digest.as_bytes());
            payload.extend_from_slice(&prior_execution.as_bytes());
            push_bytes(payload, checkpoint.to_text().as_bytes());
        }
    }
}

fn decode_attempt_origin(
    cursor: &mut RecordCursor<'_>,
) -> Result<AttemptExecutionOrigin, AssignmentLedgerError> {
    match cursor.byte()? {
        0 => Ok(AttemptExecutionOrigin::Initial),
        1 => Ok(AttemptExecutionOrigin::ExactCheckpoint {
            assignment: AssignmentId::from_bytes(cursor.fixed()?)?,
            request_digest: CampaignHash::from_bytes(cursor.fixed()?),
            prior_execution: ExecutionId::from_bytes(cursor.fixed()?)?,
            checkpoint: parse_typed(cursor.bytes()?, ExactCheckpointId::parse)?,
        }),
        _ => Err(corrupt("attempt-state-origin-unknown-tag")),
    }
}

fn parse_typed<T>(
    bytes: &[u8],
    parse: impl FnOnce(&str) -> Result<T, CampaignCodecError>,
) -> Result<T, AssignmentLedgerError> {
    if bytes.len() > MAX_TYPED_ID_BYTES {
        return Err(corrupt("typed-id-too-large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| corrupt("typed-id-not-utf8"))?;
    parse(text).map_err(Into::into)
}

fn load_or_create_retention_state(
    root: &Path,
) -> Result<AssignmentRetentionState, AssignmentLedgerError> {
    let path = root.join(RETENTION_STATE_FILE);
    if let Some(bytes) =
        read_optional_with_limit(&path, MAX_RETENTION_STATE_BYTES, "retention-state-size")?
    {
        return decode_retention_state(&bytes);
    }

    let mut instance = [0_u8; 32];
    let random_path = Path::new("/dev/urandom");
    File::open(random_path)
        .and_then(|mut source| source.read_exact(&mut instance))
        .map_err(|source| io_error("read-retention-instance", random_path, source))?;
    let state = AssignmentRetentionState {
        instance,
        generation: 1,
    };
    persist_retention_state(root, state)?;
    Ok(state)
}

fn persist_retention_state(
    root: &Path,
    state: AssignmentRetentionState,
) -> Result<(), AssignmentLedgerError> {
    replace_mutable(
        &root.join(RETENTION_STATE_FILE),
        &encode_retention_state(state),
    )
}

fn encode_retention_state(state: AssignmentRetentionState) -> Vec<u8> {
    let mut payload = Vec::with_capacity(RETENTION_STATE_MAGIC.len() + 32 + size_of::<u64>() + 32);
    payload.extend_from_slice(RETENTION_STATE_MAGIC);
    payload.extend_from_slice(&state.instance);
    payload.extend_from_slice(&state.generation.to_le_bytes());
    seal(payload, RETENTION_STATE_CHECKSUM_DOMAIN)
}

fn decode_retention_state(bytes: &[u8]) -> Result<AssignmentRetentionState, AssignmentLedgerError> {
    if bytes.len() as u64 > MAX_RETENTION_STATE_BYTES {
        return Err(corrupt("retention-state-size"));
    }
    let payload = open_sealed(bytes, RETENTION_STATE_CHECKSUM_DOMAIN)?;
    let mut cursor = RecordCursor::new(payload);
    cursor.require(RETENTION_STATE_MAGIC)?;
    let instance = cursor.fixed()?;
    let generation = u64::from_le_bytes(cursor.fixed()?);
    cursor.finish()?;
    if generation == 0 {
        return Err(corrupt("retention-state-zero-generation"));
    }
    Ok(AssignmentRetentionState {
        instance,
        generation,
    })
}

fn seal(mut payload: Vec<u8>, domain: &str) -> Vec<u8> {
    let checksum = CampaignHash::derive(domain, &payload);
    payload.extend_from_slice(&checksum.as_bytes());
    payload
}

fn open_sealed<'a>(bytes: &'a [u8], domain: &str) -> Result<&'a [u8], AssignmentLedgerError> {
    if bytes.len() < 32 || bytes.len() as u64 > MAX_LEDGER_RECORD_BYTES {
        return Err(corrupt("record-size"));
    }
    let payload_length = bytes.len() - 32;
    let (payload, checksum) = bytes.split_at(payload_length);
    if checksum != CampaignHash::derive(domain, payload).as_bytes() {
        return Err(corrupt("record-checksum"));
    }
    Ok(payload)
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

struct RecordCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AssignmentLedgerError> {
        if self.remaining.len() < length {
            return Err(corrupt("record-truncated"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], AssignmentLedgerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| corrupt("record-fixed-width"))
    }

    fn byte(&mut self) -> Result<u8, AssignmentLedgerError> {
        Ok(self.fixed::<1>()?[0])
    }

    fn bytes(&mut self) -> Result<&'a [u8], AssignmentLedgerError> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        self.take(length)
    }

    fn require(&mut self, expected: &[u8]) -> Result<(), AssignmentLedgerError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(corrupt("record-magic"))
        }
    }

    fn finish(self) -> Result<(), AssignmentLedgerError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(corrupt("record-trailing-bytes"))
        }
    }
}

fn read_optional_bounded(path: &Path) -> Result<Option<Vec<u8>>, AssignmentLedgerError> {
    read_optional_with_limit(path, MAX_LEDGER_RECORD_BYTES, "record-size")
}

fn read_optional_with_limit(
    path: &Path,
    limit: u64,
    size_reason: &'static str,
) -> Result<Option<Vec<u8>>, AssignmentLedgerError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open-record", path, source)),
    };
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-record", path, source))?;
    if bytes.len() as u64 > limit {
        return Err(corrupt(size_reason));
    }
    Ok(Some(bytes))
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> Result<bool, AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-assignment-staging", &staging_path, source))?;
    let published = match fs::hard_link(&staging_path, path) {
        Ok(()) => true,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(source) => return Err(io_error("publish-assignment", path, source)),
    };
    fs::remove_file(&staging_path)
        .map_err(|source| io_error("remove-assignment-staging", &staging_path, source))?;
    sync_directory(directory)?;
    Ok(published)
}

fn replace_mutable(path: &Path, bytes: &[u8]) -> Result<(), AssignmentLedgerError> {
    let directory = record_directory(path)?;
    let (staging_path, mut staging) = create_staging(directory)?;
    staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| io_error("write-attempt-staging", &staging_path, source))?;
    fs::rename(&staging_path, path)
        .map_err(|source| io_error("publish-attempt-state", path, source))?;
    sync_directory(directory)
}

fn remove_mutable(path: &Path) -> Result<(), AssignmentLedgerError> {
    match fs::remove_file(path) {
        Ok(()) => {
            let directory = path
                .parent()
                .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
            sync_directory(directory)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove-attempt-state", path, source)),
    }
}

fn record_directory(path: &Path) -> Result<&Path, AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    create_directory_durable(directory)?;
    Ok(directory)
}

fn sync_record_parent(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    sync_directory(directory)
}

fn sync_record_parent_if_present(path: &Path) -> Result<(), AssignmentLedgerError> {
    let directory = path
        .parent()
        .ok_or_else(|| corrupt("record-path-has-no-parent"))?;
    if directory.is_dir() {
        sync_directory(directory)
    } else {
        Ok(())
    }
}

fn create_staging(directory: &Path) -> Result<(PathBuf, File), AssignmentLedgerError> {
    loop {
        let ordinal = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".staging-{}-{ordinal}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(io_error("create-staging", &path, source)),
        }
    }
}

fn create_directory_durable(path: &Path) -> Result<(), AssignmentLedgerError> {
    if path.as_os_str().is_empty() || path == Path::new(".") {
        return Ok(());
    }
    if path.is_dir() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| corrupt("directory-has-no-parent"))?;
    if parent != path {
        create_directory_durable(parent)?;
    }
    match fs::create_dir(path) {
        Ok(()) => sync_directory(parent),
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
            Ok(())
        }
        Err(source) => Err(io_error("create-directory", path, source)),
    }
}

fn sync_directory(path: &Path) -> Result<(), AssignmentLedgerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync-directory", path, source))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn corrupt(reason: &'static str) -> AssignmentLedgerError {
    AssignmentLedgerError::Corrupt { reason }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> AssignmentLedgerError {
    AssignmentLedgerError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests;
