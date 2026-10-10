//! Durable desired-state and operation journal.
//!
//! The journal is a sequence of checksummed frames grouped into transactions:
//!
//! ```text
//! begin(sequence, transaction, record_count)
//! record(sequence + 1, transaction, namespace, key, value)
//! ...
//! commit(sequence + n, transaction, record_count, transaction_digest)
//! ```
//!
//! A transaction becomes visible only after its commit frame and `sync_data`
//! complete. Replay discards a structurally valid but uncommitted tail and a
//! partial final frame. A checksum mismatch, sequence discontinuity, malformed
//! committed transaction, or unsupported version fails closed. Compaction
//! writes and syncs a replacement file, atomically renames it, then syncs the
//! parent directory. A separate advisory lock remains held across replacement.
//!
//! Protocol's `domain_ledger` owns transaction DATA, canonical native/preparation
//! adapters, and bounded typed-record validation. Protected
//! admission and replay publication stay here and with the journal's domain
//! owners. The private `protected_storage` group owns protected opening, name
//! witnesses, and retained descriptor/failure custody without widening access
//! to the journal's native owner or issuing domain authority.
//! The private `original_currentness` group keeps original native history,
//! fixed writer loans, signing bookends, and postcommit readbacks together.

use crate::journal::semantic_append::{AppendScope, PreflightScope};

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_sandbox_core::{ObjectDigest, OperationId};
use rustix::fs::fstat;
use sha2::{Digest, Sha256};

#[cfg(test)]
use aos_sandbox_journal::framing::{CHECKSUM_OFFSET, append_and_sync};
use aos_sandbox_journal::framing::{
    COMMIT_PAYLOAD_BYTES, EncodedFrameLayout, Frame, FrameError, FrameKind, HEADER_BYTES,
    ReadOnlyFrameScratchV1, read_frame_retained,
};
use aos_sandbox_journal::geometry::EncodedRecordLayout;
#[cfg(test)]
use aos_sandbox_journal::geometry::NativeGeometryBounds;
use aos_sandbox_journal::materialized::{self, RecordMutationRef};
use aos_sandbox_journal::record::RecordError;
use aos_sandbox_journal::recovery::RecoveryTailError;
use aos_sandbox_journal::replay::{
    NativeReplayBookkeeping, NativeReplayCoordinates, NativeReplayError,
};
use aos_sandbox_journal::owner::{NativeJournal, NativeJournalState};
use aos_sandbox_journal::transaction::{self, NativePendingTransaction};

mod delete_batch;
mod semantic_append;
#[cfg(target_os = "linux")]
mod original_currentness;
#[cfg(target_os = "linux")]
use original_currentness::Q04NativeRecipeAuditV1;
#[cfg(target_os = "linux")]
pub(crate) use original_currentness::{
    Q04CachePrepareNativeLoanV1, Q04CacheTerminalNativeLoanV1, Q04CacheTerminalPhaseV1,
};

#[cfg(target_os = "linux")]
mod git_coverage_history;
#[cfg(target_os = "linux")]
pub use git_coverage_history::{
    GitCoverageNativeHistoryErrorV1, GitCoverageNativePrefixLoanV1,
};
#[cfg(target_os = "linux")]
mod git_evidence_namespace;
pub(crate) mod mount_manager_startup;
pub(crate) mod controller_source_successor_issuance;
pub(crate) mod source_tree_successor;
pub use aos_sandbox_protocol::domain_ledger::transaction::{
    IdempotencyKey, JournalLimits, JournalRecord, JournalTransaction,
    encoded_transaction_append_bytes,
};
pub(super) use aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_record_bytes;
use aos_sandbox_protocol::domain_ledger::transaction::{
    decode_record, encode_record, encode_record_fields, encode_transaction, validate_transaction,
};
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;
mod root_local_recovery;
mod root_original_inventory;
pub(crate) use root_original_inventory::materialize as materialize_root_inventory_transaction;
mod root_original_native;
#[cfg(target_os = "linux")]
mod runtime_deployment_history;
#[cfg(target_os = "linux")]
mod runtime_deployment_sidecar_history;
#[cfg(target_os = "linux")]
mod storage_native_issuance_history;
#[cfg(target_os = "linux")]
mod storage_canary_export_history;
#[cfg(target_os = "linux")]
pub use storage_canary_export_history::{
    StorageCanaryBootstrapPrimaryHistoryDataV1,
    StorageCanaryExportEdgeDataV1, StorageCanaryExportHistoryCursorV1,
    StorageCanaryExportHistoryDataV1, StorageCanaryExportHistoryErrorV1,
};
#[cfg(target_os = "linux")]
pub use storage_native_issuance_history::{
    StorageNativeIssuanceEdgeDataV1, StorageNativeIssuanceHistoryCursorV1,
    StorageNativeIssuanceHistoryDataV1, StorageNativeIssuanceHistoryErrorV1,
};
#[cfg(target_os = "linux")]
pub use runtime_deployment_sidecar_history::RuntimeDeploymentNativeTransactionDataV1;
#[cfg(target_os = "linux")]
pub(crate) use runtime_deployment_sidecar_history::RetainedDeploymentNativeHistoryV1;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use runtime_deployment_sidecar_history::{
    observed_native_fixture_v1, require_sidecar_capture_limits_for_test,
};
#[cfg(all(test, target_os = "linux"))]
pub(crate) use runtime_deployment_history::deployment_original_compaction_selected_for_test;
pub use root_original_inventory::{
    MountOriginalInventoryJournalAuthorityV6, OriginalInventoryProtectedReadbackV6,
    PreparedOriginalInventoryAppendV6,
};
pub use root_original_native::{
    MountOriginalNativeJournalAuthorityV5, OriginalRootProtectedReadbackV5,
    PreparedOriginalRootAppendV5,
};
mod source_provider_readonly;
mod source_original_native;
pub use source_original_native::{
    SOURCE_NATIVE_DISPATCH_TERMINAL_BYTES_V1, SOURCE_NATIVE_DISPATCH_TERMINAL_RECORDS_V1,
    SourceCapacityStateV5, SourceOriginalAdmissionInputV5, SourceOriginalAdmissionDataV5,
    SourceCapacityUnionComparisonDataV5, compare_source_original_admission_data_v5,
    compare_source_capacity_union_data_v5,
    SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1,
    source_native_ordinary_capacity_request_v1,
    source_native_release_status_capacity_request_v1,
    OriginalSourceProtectedReadbackV5, PreparedOriginalSourceAppendV5,
    SourceOriginalAppendSubjectV5,
    SourceOriginalChallengeCheckpointV5, SourceOriginalChallengeHistoryViewV5,
    SourceOriginalNativeJournalAuthorityV5, SourceOriginalPhysicalCutV5,
    SourceOriginalReplayViewV5,
};
pub use mount_manager_startup::MountManagerStartupPolicyReceiptV1;
pub(crate) use mount_manager_startup::{
    MountManagerStartupCapturePreflightV1, MountManagerStartupCaptureReceiptV1,
    MountManagerStartupCaptureRecoveryV1,
};
pub use root_local_recovery::{
    Kind2ProtectedReadbackV4, Kind5ProtectedReadbackV4,
    MountBarrierIdleReplacementJournalAuthorityV4, MountDeadReplacementJournalAuthorityV4,
    PreparedBarrierIdleReplacementV4, PreparedDeadReplacementV4,
};
pub use source_provider_readonly::SourceProviderHeldReadOnlyJournalAuthorityV1;
mod cache_policy_hold;
pub(crate) use cache_policy_hold::{
    BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1,
};
#[cfg(target_os = "linux")]
pub(crate) use cache_policy_hold::CacheGitCoverageObservationV1;
mod capacity_reservation;
pub use capacity_reservation::native_held;
mod controller_policy_hold;
pub(crate) mod controller_source_genesis;
pub(crate) mod host_currentness_fence;
pub(crate) mod host_execution_fence;
mod host_settlement_admission_gate;
mod source_domain_challenge;
mod source_domain_policy_hold;
#[cfg(target_os = "linux")]
pub(crate) use source_domain_policy_hold::SourceQ04TransactionRecipesV1;
#[cfg(target_os = "linux")]
pub(crate) use cache_policy_hold::CacheQ04TransactionRecipesV1;
#[cfg(target_os = "linux")]
pub(crate) use cache_policy_hold::q04_clear_recipe_digest_data as q04_cache_clear_recipe_digest_data_v1;
#[cfg(target_os = "linux")]
pub(crate) use source_domain_policy_hold::q04_clear_recipe_digest_data as q04_source_clear_recipe_digest_data_v1;
mod source_project_admission_challenge;
pub(crate) mod source_tree_genesis;
pub use cache_policy_hold::CachePolicyHoldV1;
pub(crate) use cache_policy_hold::NAME as CACHE_POLICY_HOLD_JOURNAL;
pub(crate) use capacity_reservation::capacity_record_has_legacy_purpose;
pub(crate) use capacity_reservation::capacity_reservation_identity_is_exact_v1;
pub(crate) use capacity_reservation::{
    first_source_successor_capacity_delete_v2, first_source_successor_capacity_identity_v2,
    first_source_successor_capacity_record_v2,
};
pub(crate) use source_tree_successor::FirstSourceSuccessorNativePhaseV2;
pub use capacity_reservation::decode_capacity_reservation_request_v1;
pub use capacity_reservation::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1, GlobalCapacityReservationV1,
    PreparedGlobalCapacityReservationV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootSourceGenesisTransitionV1 {
    None,
    Initialize,
}
pub use controller_policy_hold::{
    ControllerPolicyEffectAckV1, ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1,
    ControllerPolicyV8EffectAckV1,
};
pub(crate) use controller_policy_hold::{
    ControllerPolicyV8PreReleaseFloorV1, ControllerPolicyV8ReleaseEvidenceV1,
    ControllerPolicyV8SettlementV1, controller_v8_root_receipt_record_digest_v1,
    v8_root_receipt_matches_ack,
};
#[cfg(target_os = "linux")]
pub(crate) use controller_policy_hold::ControllerQ04TransitionV1;
pub(crate) use host_currentness_fence::HostCurrentnessFenceV1;
pub(crate) use host_execution_fence::HostExecutionFenceV1;
pub use source_domain_challenge::SourceDomainChallengeV1;
pub(crate) use source_domain_challenge::replay_source_domain_challenge_v1;
pub use source_domain_policy_hold::{
    SourceDomainPolicyHoldV1, SourceDomainPolicyV8PendingSettlementV1,
};
use source_project_admission_challenge::SourceProjectAdmissionTransition;
pub use source_project_admission_challenge::{
    SOURCE_PROJECT_ADMISSION_CHALLENGE_BYTES_V1, SOURCE_PROJECT_ADMISSION_RESERVATION_BYTES_V1,
    SOURCE_PROJECT_ADMISSION_TERMINAL_BYTES_V1, SourceProjectAdmissionChallengeKindV1,
    SourceProjectAdmissionChallengeV1, SourceProjectAdmissionReservationV1,
    SourceProjectAdmissionTerminalV1,
};
pub(crate) use source_project_admission_challenge::{
    replay_source_project_admission_challenge_v1, source_project_challenge_matches_current,
};
mod mount_source_consumption;
pub use mount_source_consumption::{
    MountSourceConsumptionCommitReceipt, MountSourceConsumptionCompanionProjectionV2,
    MountSourceConsumptionJournalAuthorityV1, MountSourceConsumptionPreflight,
};

const AUTHORITY_PREFLIGHT_DOMAIN: &[u8] = b"aos.sandbox.journal.authority-preflight.v1\0";

/// Carries configured initial-replay representation DATA before a protected open.
///
/// These separate terms describe logical bytes and inline representations, not
/// allocator RAM, a service budget, a paid loan, or permission to open. They may
/// overcount shared storage. Every consumer must also cover [`Self::unpriced`]
/// before treating an aggregate as a prepaid service extent.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedJournalPreopenReplayExtentV1 {
    /// Preserves the exact limits supplied to the native opener.
    pub(crate) limits: JournalLimits,
    /// Bounds the configured native prefix; this is disk input, not heap storage.
    pub(crate) native_bytes: u64,
    /// Reuses the original Release replay's logical map, frame and owner charge.
    pub(crate) native_replay_representation_bytes: usize,
    /// Covers an advertised frame payload allocated before a partial-tail EOF.
    pub(crate) partial_tail_payload_bytes: usize,
    /// Covers the full BEGIN reservation, irrespective of physical frame count.
    pub(crate) declared_pending_record_bytes: usize,
    /// Covers insertion of one extra transaction ID before count refusal.
    pub(crate) reached_transaction_id_bytes: usize,
    /// Covers intermediate map cells before all transaction deletions apply.
    pub(crate) reached_materialized_cell_bytes: usize,
    /// Bounds committed transactions reached before the count check can refuse.
    pub(crate) source_transactions: usize,
    /// Covers conservative inline cache copies, including the pending marker.
    pub(crate) source_cache_copies: usize,
    /// Bounds original checkpoint rows from this configured native file.
    pub(crate) source_checkpoint_rows: usize,
    /// Covers this file's original checkpoint rows and one independent copy.
    pub(crate) source_checkpoint_representation_bytes: usize,
    /// Covers initial cache owners whose physical-history collections stay empty.
    pub(crate) source_cache_metadata_bytes: usize,
    /// Covers inline native opener, replay, metadata, result and error owners.
    pub(crate) native_owner_result_bytes: usize,
    /// Requires independent bounds for all representations not priced here.
    pub(crate) unpriced: ProtectedJournalPreopenUnpricedPrerequisitesV1,
}

/// Identifies obligations that configured journal limits alone cannot price.
///
/// Collection spare capacity, BTree nodes, Arc control blocks and allocator
/// overhead need separate conservative service provision and physical backstops.
/// Decoder/validator temporaries and owning error payloads need their own bounds,
/// as do native descriptors, kernel state, path/name allocations and service work.
/// The parser checks initial file metadata, so growing input needs independently
/// enforced containment or a stable-prefix prerequisite. Initial replay has no
/// external challenge witness; the legacy marker name does not add the separate
/// later replay's external-history demand to this phase.
///
/// The ordinary read-only opener drops its local files and partial replay on
/// failure. This marker neither retains those locals nor changes their lifetime.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedJournalPreopenUnpricedPrerequisitesV1 {
    /// Requires conservative allocator, decoder/error and native/containment bounds.
    AllocatorDecoderErrorsNativePathsAndExternalChallenges,
}

/// Computes partial initial-replay DATA from the exact configured open limits.
///
/// The writable and retained read-only initial openers pass no Source challenge
/// history. The common parser still accepts and validates its existing families;
/// Source dependencies become pending before physical-cache retention. Independent
/// checkpoint collection, compaction materialization and first-successor clones
/// remain covered. Later challenge-bearing replay has its separate existing
/// demand. No Journal, path, descriptor, authority or payer is constructed.
///
/// # Errors
///
/// Rejects invalid native limits or an unrepresentable checked extent. It does
/// not establish that the represented storage fits physical or paid memory.
#[cfg(target_os = "linux")]
pub(crate) fn protected_journal_preopen_replay_extent_v1(
    limits: JournalLimits,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    validate_limits(limits)?;
    let limit = || JournalError::LimitExceeded("protected journal pre-open replay extent");
    let physical = usize::try_from(limits.maximum_journal_bytes).map_err(|_| limit())?;
    let frames = physical / HEADER_BYTES;
    let source_transactions = limits.maximum_transactions.checked_add(1)
        .ok_or_else(limit)?.min(frames);
    let source_checkpoint_rows = frames;
    let source_cache_copies = 3_usize;
    let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();

    // BEGIN trusts the bounded declared count before reading its records;
    // read_frame allocates the advertised payload before discovering EOF.
    // Neither allocation is bounded by the number of complete physical frames.
    let native_work = native_release_replay_work_v1(physical, limits)?;
    let native_replay_representation_bytes = native_work.replay_indexes
        .checked_add(native_work.pending_records)
        .and_then(|bytes| bytes.checked_add(native_work.frame_payload))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReplayState>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingTransaction>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>()))
        .ok_or_else(limit)?;
    let partial_tail_payload_bytes = limits.maximum_record_bytes.checked_add(7).ok_or_else(limit)?;
    let declared_pending_record_bytes = limits.maximum_records_per_transaction
        .checked_mul(std::mem::size_of::<JournalRecord>()).ok_or_else(limit)?;
    let reached_transaction_id_bytes = std::mem::size_of::<[u8; 16]>();
    let reached_materialized_cell_bytes = limits.maximum_records_per_transaction
        .checked_mul(map_entry).and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;

    // This runs independently of the optional external challenge witness.
    // Retain its committed-frame rows even when Source replay remains pending.
    let source_checkpoint_representation_bytes = source_checkpoint_rows
        .checked_mul(std::mem::size_of::<source_original_native::SourceOriginalChallengeCheckpointV5>())
        .and_then(|bytes| bytes.checked_add(physical))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;
    // replay_transaction(None) returns before origins, cuts, retirements or
    // their maps are retained. observe_compaction likewise only sets pending;
    // its temporary prospective map remains in the native replay allowance.
    let source_cache_metadata_bytes = std::mem::size_of::<source_original_native::replay::SourceOriginalReplayCacheV5>()
        .checked_mul(source_cache_copies)
        .ok_or_else(limit)?;

    // Price simultaneous inline representations conservatively. Ordinary
    // recovery still transfers its maps and drops its failure locals unchanged.
    let native_owner_result_bytes = std::mem::size_of::<ControllerJournalOpenOriginalsV1>()
        .checked_add(std::mem::size_of::<Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<ReplayState, JournalError>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProtectedJournalLocation>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReadOnlyJournalNameWitness>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Frame>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Option<OriginalReleaseSourceCutCaptureV1>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::cell::Cell<bool>>()))
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<fs::Metadata, io::Error>>()))
        .ok_or_else(limit)?;

    Ok(ProtectedJournalPreopenReplayExtentV1 {
        limits,
        native_bytes: limits.maximum_journal_bytes,
        native_replay_representation_bytes,
        partial_tail_payload_bytes,
        declared_pending_record_bytes,
        reached_transaction_id_bytes,
        reached_materialized_cell_bytes,
        source_transactions,
        source_cache_copies,
        source_checkpoint_rows,
        source_checkpoint_representation_bytes,
        source_cache_metadata_bytes,
        native_owner_result_bytes,
        unpriced: ProtectedJournalPreopenUnpricedPrerequisitesV1::AllocatorDecoderErrorsNativePathsAndExternalChallenges,
    })
}

// Closed live crossings; neither the canonical transaction nor project DATA
// can construct the genuine original Root borrower in the issuer arm.
enum ProjectNativeTransitionV3<'cut, 'owner> {
    Genesis(source_tree_successor::ProjectGenesisNativePhaseV3, source_tree_successor::ProjectGenesisNativeCutV3<'cut>),
    #[cfg(target_os = "linux")]
    GlobalGenesis(GlobalGenesisNativeCutV2<'cut>),
    #[cfg(target_os = "linux")]
    GlobalRootGenesis(&'cut crate::policy_compiler::GlobalRootGenesisNativeCutV2<'cut>),
    #[cfg(target_os = "linux")]
    Issuance {
        transition: controller_source_successor_issuance::Transition,
        completed: &'cut crate::policy_compiler::CompletedRootSourceProjectGenesisFloorV3<'cut, 'cut>,
    },
    #[cfg(target_os = "linux")]
    FirstSuccessor(source_tree_successor::FirstSuccessorNativeCutV3<'cut, 'owner>),
    // Selected producers are Linux-only; this uninhabited arm retains the
    // owner's lifetime in the portable ordinary engine without issuing a cut.
    #[cfg(not(target_os = "linux"))]
    Unsupported(std::convert::Infallible, std::marker::PhantomData<&'owner ()>),
}

// Global and mixed Project semantics remain separate. This arm contributes
// only a genuine original cut to the already validated strict native append.
#[cfg(target_os = "linux")]
enum GlobalGenesisNativeCutV2<'cut> {
    SourcePrepared(&'cut crate::policy_compiler::HeldRootSourceGenesisIntentV1<'cut>),
    SourceAnchored(&'cut crate::policy_compiler::RootSourceGenesisFloorProofV1<'cut>),
    ControllerAnchored(&'cut crate::policy_compiler::RootSourceGenesisFloorProofV1<'cut>),
}

pub use aos_sandbox_core::RecordNamespace;

impl From<aos_sandbox_core::journal_namespace::UnknownRecordNamespace> for JournalError {
    fn from(_: aos_sandbox_core::journal_namespace::UnknownRecordNamespace) -> Self {
        Self::MalformedRecord("unknown record namespace")
    }
}

/// Reports whether a request key is new, an exact replay, or a conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyOutcome {
    /// No durable decision exists for this key.
    Vacant,
    /// The exact semantic request was previously accepted as this operation.
    Replay(OperationId),
    /// The key is already bound to different semantic request bytes.
    Conflict,
}

/// Summarizes recovery performed while opening a journal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Number of committed transactions replayed.
    pub committed_transactions: usize,
    /// Number of committed records replayed.
    pub committed_records: usize,
    /// Structurally valid uncommitted or partial-tail bytes removed.
    pub truncated_bytes: u64,
}

/// Identifies the durable position reached by a successful commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitResult {
    /// Sequence number of the synced commit frame.
    pub commit_sequence: u64,
    /// Durable file length after the commit.
    pub durable_bytes: u64,
}

/// Reports journal validation, durability, and ownership failures.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The selected genesis or successor original cut failed before append.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ProjectGenesisOriginal(Box<crate::hierarchy::genesis_profile::SourceGenesisErrorV1>),
    /// The same retained Global genesis original refused the final crossing.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    GlobalGenesisOriginal(Box<crate::hierarchy::genesis_profile::SourceGenesisErrorV1>),
    /// The same original Root flight failed its final physical/clock check.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Q04RootOriginal(Box<crate::policy_compiler::create_q04::CreateQ04ErrorV1>),
    /// The closed Q04 transition failed its unchanged canonical Create ledger.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Q04ControllerLedger(Box<crate::reconciler::ReconcilerError>),
    /// A filesystem operation failed.
    #[error("journal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Another process owns the journal lock.
    #[error("journal is already owned by another process")]
    AlreadyLocked,
    /// The journal exceeds its configured replay byte bound.
    #[error("journal exceeds the configured replay byte bound")]
    JournalTooLarge,
    /// A frame uses an unsupported format version.
    #[error("unsupported journal format version {0}")]
    UnsupportedVersion(u16),
    /// A complete frame failed checksum validation.
    #[error("journal frame checksum mismatch at byte offset {0}")]
    ChecksumMismatch(u64),
    /// Frame sequence numbers are not exact and monotonic.
    #[error("journal sequence discontinuity at byte offset {0}")]
    SequenceDiscontinuity(u64),
    /// A frame violates transaction ordering or commit invariants.
    #[error("malformed journal transaction: {0}")]
    MalformedTransaction(&'static str),
    /// A record payload violates the closed binary schema.
    #[error("malformed journal record: {0}")]
    MalformedRecord(&'static str),
    /// A caller supplied an invalid transaction.
    #[error("transaction identity must be nonzero and records must be nonempty")]
    InvalidTransaction,
    /// A caller supplied an empty or oversized idempotency key.
    #[error("idempotency key must contain between 1 and 128 bytes")]
    InvalidIdempotencyKey,
    /// A configured size or count limit was exceeded.
    #[error("journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A transaction changes the same logical key more than once.
    #[error("transaction contains duplicate logical record keys")]
    DuplicateRecordKey,
    /// A committed transaction identity was reused.
    #[error("transaction identity was already committed")]
    DuplicateTransaction,
    /// A committed idempotency key was rebound to another decision.
    #[error("idempotency key is already bound to another decision")]
    IdempotencyConflict,
    /// An earlier durability failure requires the journal to be reopened.
    #[error("journal handle is poisoned and must be reopened")]
    Poisoned,
    /// A protected path, owner, file type, or mode violates its boundary.
    #[error("protected journal storage boundary is invalid")]
    ProtectedBoundary,
    /// A dedicated authority journal contains a record in another namespace.
    #[error("protected authority journal contains a foreign namespace")]
    ForeignAuthorityNamespace,
    /// An authority token does not describe this journal's current snapshot.
    #[error("protected authority snapshot is stale or belongs to another journal")]
    StaleAuthoritySnapshot,
    /// A preflight token was presented for a different transaction sequence.
    #[error("protected authority preflight does not match the supplied transactions")]
    AuthorityPreflightMismatch,
    /// The kernel cannot enforce the protected opener's resolution policy.
    #[error("protected journal opening requires supported, permitted openat2 resolution")]
    UnsupportedProtectedOpen,
    /// Sequence space is exhausted and cannot safely wrap.
    #[error("journal sequence space is exhausted")]
    SequenceExhausted,
    /// A coverage audit retains its first native cause and final bookend debt.
    #[cfg(target_os = "linux")]
    #[error("journal coverage native history failed: {0}")]
    GitCoverageNativeHistory(#[source] Box<GitCoverageNativeHistoryErrorV1>),
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1> for JournalError {
    fn from(error: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        match error {
            aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1::Malformed => {
                Self::ProtectedBoundary
            }
        }
    }
}

impl From<JournalTransactionDataError> for JournalError {
    fn from(error: JournalTransactionDataError) -> Self {
        match error {
            JournalTransactionDataError::InvalidTransaction => Self::InvalidTransaction,
            JournalTransactionDataError::InvalidIdempotencyKey => Self::InvalidIdempotencyKey,
            JournalTransactionDataError::MalformedTransaction(reason) => {
                Self::MalformedTransaction(reason)
            }
            JournalTransactionDataError::MalformedRecord(reason) => Self::MalformedRecord(reason),
            JournalTransactionDataError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            JournalTransactionDataError::DuplicateRecordKey => Self::DuplicateRecordKey,
            JournalTransactionDataError::JournalTooLarge => Self::JournalTooLarge,
            JournalTransactionDataError::Frame(error) => Self::from(error),
            JournalTransactionDataError::Record(error) => Self::from(error),
        }
    }
}

impl From<FrameError> for JournalError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Io(error) => Self::Io(error),
            FrameError::JournalTooLarge => Self::JournalTooLarge,
            FrameError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            FrameError::ChecksumMismatch(offset) => Self::ChecksumMismatch(offset),
            FrameError::MalformedTransaction(reason) => Self::MalformedTransaction(reason),
            FrameError::LimitExceeded(bound) => Self::LimitExceeded(bound),
            FrameError::MissingRetainedPayload => Self::ProtectedBoundary,
            FrameError::SequenceExhausted => Self::SequenceExhausted,
        }
    }
}

impl From<RecordError> for JournalError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::MalformedRecord(reason) => Self::MalformedRecord(reason),
            RecordError::LimitExceeded(bound) => Self::LimitExceeded(bound),
        }
    }
}

impl From<NativeReplayError> for JournalError {
    fn from(error: NativeReplayError) -> Self {
        match error {
            NativeReplayError::SequenceDiscontinuity(offset) => Self::SequenceDiscontinuity(offset),
            NativeReplayError::SequenceExhausted => Self::SequenceExhausted,
            NativeReplayError::JournalTooLarge => Self::JournalTooLarge,
            NativeReplayError::DuplicateTransaction => Self::DuplicateTransaction,
            NativeReplayError::LimitExceeded(bound) => Self::LimitExceeded(bound),
        }
    }
}

impl From<RecoveryTailError> for JournalError {
    fn from(error: RecoveryTailError) -> Self {
        match error {
            RecoveryTailError::Io(error) => Self::Io(error),
            RecoveryTailError::UncommittedTail => Self::MalformedTransaction(
                "read-only journal has an uncommitted tail",
            ),
            RecoveryTailError::RetainedNativeFailure => Self::ProtectedBoundary,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdempotencyDecision {
    request_digest: [u8; 32],
    operation_id: OperationId,
}

struct PendingTransaction {
    records: Vec<JournalRecord>,
    native: NativePendingTransaction,
}

/// Owns one exclusively locked, append-only journal and its replayed indexes.
pub struct Journal {
    // The contiguous native prefix keeps its original file/set/map drop order.
    // All role admission, semantic indexes, and authority remain in this wrapper.
    native: NativeJournal<RecordNamespace, JournalLimits>,
    idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
    protected: Option<ProtectedJournalLocation>,
    cache_policy_gate: Option<(PathBuf, u32)>,
    mount_git_coverage_denied: bool,
    authority_instance: Arc<JournalAuthorityInstance>,
    source_challenge_history: Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
    source_original_replay: source_original_native::replay::SourceOriginalReplayCacheV5,
    source_history_compacted: bool,
    // Deny-only native provenance survives deletion of a Q04 lower marker.
    // It is never a floor, currentness certificate or permission to mutate.
    #[cfg(target_os = "linux")]
    q04_lower_history_present: bool,
}

// One materializer adopts a completely replayed original. The selected opener
// supplies its already-resident authority allocation; ordinary recovery keeps
// allocating that marker at its original field position.
macro_rules! journal_from_original_replay {
    ($path:expr, $file:expr, $lock:expr, $limits:expr, $protected:expr,
     $replay:ident, $authority:expr) => {
        Journal {
            native: aos_sandbox_journal::owner::NativeJournal::from_owned_parts(
                $path, $file, $lock, $limits,
                aos_sandbox_journal::owner::NativeJournalState::from_owned_parts(
                    $replay.next_sequence, $replay.committed_transactions,
                    $replay.transaction_ids, $replay.committed_namespaces,
                    $replay.state, $replay.materialized_bytes,
                ),
            ),
            idempotency: $replay.idempotency,
            protected: $protected,
            cache_policy_gate: None,
            mount_git_coverage_denied: false,
            authority_instance: $authority,
            source_challenge_history: $replay.source_challenge_history,
            source_original_replay: $replay.source_original_replay,
            source_history_compacted: $replay.source_history_compacted,
            #[cfg(target_os = "linux")]
            q04_lower_history_present: $replay.q04_lower_history_present,
        }
    };
}

#[cfg(target_os = "linux")]
mod nix_offline_provisioning;
#[cfg(target_os = "linux")]
pub use nix_offline_provisioning::{
    NixOfflineContactDataV5, NixOfflineHelperLaunchV5,
    NixOfflineNativeJobErrorV5, NixOfflineNativeJobV5,
};

mod protected_storage;
pub use protected_storage::{ProtectedJournalLockCustodyV1, ProtectedJournalNamesV1};
pub(crate) use protected_storage::{
    ControllerJournalOpenOriginalsV1, ProtectedWriterNameWitness, ProtectedWriterOpenOriginalsV1,
    ReadOnlyJournalNameWitness, ReadOnlyJournalOpenOriginalsV1, ReadOnlyProtectedJournal,
};
use protected_storage::{
    FileIdentity, ProtectedJournalLocation, compact_protected, open_protected_file_into,
    resolve_protected_directory_from_root, rustix_io, validate_protected_fd,
};
#[cfg(test)]
use protected_storage::{
    MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES, ProtectedAncestry, ProtectedJournalOpenMode,
    ProtectedOwnerPolicy, open_protected_file, protected_open_error,
    reject_operator_provisioning_history, require_empty_operator_provisioning_state,
    require_opened_directory_identity, traverse_protected_directory,
};

/// Grants scoped access to one closed authority namespace in a protected journal.
///
/// The guard is constructed by a protected Journal claim method. Ordinary
/// transactions stay within the claimed owner namespace; purpose-specific
/// methods may admit a closed cross-namespace transaction. Every operation
/// checks journal health and retained protected-open provenance. Values and
/// iterators borrowed through the guard cannot remain live across a commit or
/// another mutable operation.
#[must_use = "a protected authority claim must be used while its journal borrow is active"]
pub struct ProtectedJournalAuthority<'journal> {
    journal: &'journal mut Journal,
    namespace: RecordNamespace,
    scope: ProtectedAuthorityScope,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectedAuthorityScope {
    SingleNamespace,
    FixedMountSourceAcquisition,
    RootLocalRecoveryKind2,
    RootLocalRecoveryKind5,
    RootOriginalNativeV5,
    RootOriginalInventoryV6,
    SourceProviderHeldReadOnly,
    SourceOriginalNativeV5,
    MountSourceConsumption,
    MountManagerStartup,
    CapacityReservation(GlobalCapacityReservationPurposeV1),
}

#[derive(Clone, Copy)]
enum RootOwnerEdge {
    #[cfg(target_os = "linux")]
    NixOffline,
    #[cfg(target_os = "linux")]
    NixOfflineClosureData,
    SourceOriginal,
    Local(root_local_recovery::Edge),
    OriginalNative([u8; 32]),
    OriginalInventory {
        root: [u8; 32],
        query: [u8; 32],
        kind: aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::OriginalInventoryTransitionKindV6,
    },
}

// A borrowed DATA view avoids copying the complete eligible Q04 suffix just
// to enter the one existing bounds/materializer/frame-preflight engine.
enum PreflightTransactionViewV1<'recipes> {
    Ordinary(&'recipes [JournalTransaction]),
    #[cfg(target_os = "linux")]
    CacheQ04ReadOnlyBase {
        hold: &'recipes Journal,
        transactions: &'recipes [JournalTransaction; 0],
    },
    #[cfg(target_os = "linux")]
    RootQ04Capacity(&'recipes [JournalTransaction]),
    #[cfg(target_os = "linux")]
    RootQ04 {
        history: &'recipes crate::policy_compiler::create_q04::Q04RootAuthorityHistoryV1,
        first: usize,
        end: usize,
    },
    #[cfg(target_os = "linux")]
    ControllerQ04(&'recipes [ControllerQ04TransitionV1<'recipes>]),
    #[cfg(target_os = "linux")]
    SourceQ04 {
        recipes: &'recipes SourceQ04TransactionRecipesV1<'recipes>,
        first: usize,
        end: usize,
    },
    #[cfg(target_os = "linux")]
    CacheQ04 {
        recipes: &'recipes CacheQ04TransactionRecipesV1<'recipes>,
        first: usize,
        end: usize,
    },
}

// Named, closed DATA cases enter the same ordinary validation boundary.
// This value carries no owner, callback, general hold waiver or commit right.
// Nested loan lifetimes stay independent of this short borrow, especially the
// invariant mutable Cache owner retained by the clearance loan.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Q04JournalTransitionV1<
    'borrow,
    'recipe_cut,
    'root_invocation,
    'root_profile,
    'root_cut,
    'cache_loan,
    'cache_owner,
    'cache_invocation,
    'cache_profile,
    'cache_cut,
    'root_input,
    'root_startup,
> {
    Controller(
        &'borrow ControllerQ04TransitionV1<'recipe_cut>,
        Option<
            &'borrow crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
                'root_invocation,
                'root_profile,
                'root_cut,
            >,
        >,
    ),
    Source(
        &'borrow SourceQ04TransactionRecipesV1<'recipe_cut>,
        usize,
        Option<
            &'borrow crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
                'root_invocation,
                'root_profile,
                'root_cut,
            >,
        >,
        Option<
            &'borrow crate::cache_residency::OriginalQ04CacheClearanceLoanV1<
                'cache_loan,
                'cache_owner,
                'cache_invocation,
                'cache_profile,
                'cache_cut,
            >,
        >,
    ),
    Cache(
        &'borrow CacheQ04TransactionRecipesV1<'recipe_cut>,
        usize,
        Option<
            &'borrow crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
                'root_invocation,
                'root_profile,
                'root_cut,
            >,
        >,
    ),
    Root(
        &'borrow crate::policy_compiler::create_q04::Q04RootAuthorityHistoryV1,
        usize,
        Option<
            &'borrow crate::policy_compiler::create_q04::RootOriginalInputLoanV1<
                'root_input,
                'root_startup,
            >,
        >,
    ),
    // Capacity permits only the nonissuing preflight engine. Actual commit
    // rejects this position even if its predicted bytes are canonical.
    RootCapacity(&'borrow JournalTransaction),
}

impl PreflightTransactionViewV1<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Ordinary(transactions) => transactions.len(),
            #[cfg(target_os = "linux")]
            Self::CacheQ04ReadOnlyBase { transactions, .. } => transactions.len(),
            #[cfg(target_os = "linux")]
            Self::RootQ04Capacity(transactions) => transactions.len(),
            #[cfg(target_os = "linux")]
            Self::RootQ04 { first, end, .. } => end - first,
            #[cfg(target_os = "linux")]
            Self::ControllerQ04(transitions) => transitions.len(),
            #[cfg(target_os = "linux")]
            Self::SourceQ04 { first, end, .. } => end - first,
            #[cfg(target_os = "linux")]
            Self::CacheQ04 { first, end, .. } => end - first,
        }
    }

    // Only the private 0..len loop calls this accessor. Both slices remain
    // immutable for the entire preflight; no callback can change their length.
    fn transaction(&self, index: usize) -> &JournalTransaction {
        match self {
            Self::Ordinary(transactions) => &transactions[index],
            #[cfg(target_os = "linux")]
            Self::CacheQ04ReadOnlyBase { transactions, .. } => &transactions[index],
            #[cfg(target_os = "linux")]
            Self::RootQ04Capacity(transactions) => &transactions[index],
            #[cfg(target_os = "linux")]
            Self::RootQ04 { history, first, .. } => &history.transactions()[first + index],
            #[cfg(target_os = "linux")]
            Self::ControllerQ04(transitions) => transitions[index].transaction(),
            #[cfg(target_os = "linux")]
            Self::SourceQ04 { recipes, first, .. } => &recipes.transactions()[first + index],
            #[cfg(target_os = "linux")]
            Self::CacheQ04 { recipes, first, .. } => &recipes.transactions()[first + index],
        }
    }

    #[cfg(target_os = "linux")]
    fn q04_transition(
        &self,
        index: usize,
    ) -> Option<Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>> {
        match self {
            Self::Ordinary(_) => None,
            Self::CacheQ04ReadOnlyBase { .. } => None,
            Self::RootQ04Capacity(transactions) => Some(Q04JournalTransitionV1::RootCapacity(&transactions[index])),
            Self::RootQ04 { history, first, .. } => Some(Q04JournalTransitionV1::Root(history, first + index, None)),
            Self::ControllerQ04(transitions) => {
                Some(Q04JournalTransitionV1::Controller(&transitions[index], None))
            }
            Self::SourceQ04 { recipes, first, .. } => {
                Some(Q04JournalTransitionV1::Source(recipes, first + index, None, None))
            }
            Self::CacheQ04 { recipes, first, .. } => {
                Some(Q04JournalTransitionV1::Cache(recipes, first + index, None))
            }
        }
    }
}

/// Proves the protected authority snapshot observed at one journal sequence.
///
/// This token is opaque and bound to the exact in-memory journal instance and
/// namespace that minted it. Use
/// [`ProtectedJournalAuthority::validate_snapshot_for_effect`] immediately
/// before relying on copied snapshot state at an effect boundary.
#[must_use = "an authority snapshot token must be validated at its use boundary"]
pub struct ProtectedJournalSnapshot {
    instance: Arc<JournalAuthorityInstance>,
    namespace: RecordNamespace,
    sequence: u64,
    scope: ProtectedAuthorityScope,
}

impl ProtectedJournalSnapshot {
    // Journal descendants may retain the same observation, never refresh it.
    // Every duplicate still needs validation at its own effect boundary.
    fn duplicate_provenance(&self) -> Self {
        Self {
            instance: Arc::clone(&self.instance),
            namespace: self.namespace,
            sequence: self.sequence,
            scope: self.scope,
        }
    }

    /// Returns the exact protected journal sequence captured by this token.
    ///
    /// The number is diagnostic without the opaque token. Callers must still
    /// validate the complete snapshot immediately before relying on it.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Proves successful preflight at one protected authority snapshot.
///
/// This opaque token is bound to the exact in-memory journal instance,
/// namespace, sequence, and ordered transaction contents for which preflight
/// completed. It becomes stale after any intervening commit.
#[must_use = "a preflight token must be validated at its effect boundary"]
pub struct ProtectedJournalPreflight {
    snapshot: ProtectedJournalSnapshot,
    transaction_digest: [u8; 32],
}

/// Seals one current claim over the fixed provider journal for session handoff.
///
/// The move-only value has no public constructor or projection. It carries no
/// record, mutation, signing, or transport authority and is accepted only by
/// the fixed provider security owner.
#[must_use = "a fixed provider journal handoff must be consumed by its session owner"]
pub struct FixedSourceProviderJournalHandoffV1<'authority, 'journal> {
    authority: &'authority ProtectedJournalAuthority<'journal>,
    sequence: u64,
}

impl core::fmt::Debug for FixedSourceProviderJournalHandoffV1<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FixedSourceProviderJournalHandoffV1([protected handoff])")
    }
}

impl FixedSourceProviderJournalHandoffV1<'_, '_> {
    /// Consumes and revalidates the exact fixed journal borrow.
    ///
    /// The retained immutable borrow prevents an intervening commit through
    /// the same owner while this handoff exists.
    ///
    /// # Errors
    ///
    /// Returns an error after owner replacement, reopen, compaction, or any
    /// mismatch with the fixed namespace-41 storage boundary.
    #[doc(hidden)]
    pub fn validate_current(self) -> Result<(), JournalError> {
        self.authority
            .validate_fixed_source_provider_session_handoff(&self)
    }
}

/// Lends the exact fixed Mount namespace-40 owner without allowing it to escape.
#[must_use = "the fixed Mount source authority must remain owner-scoped"]
pub struct MountSourceAcquisitionJournalAuthorityV2<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
}

impl core::fmt::Debug for MountSourceAcquisitionJournalAuthorityV2<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MountSourceAcquisitionJournalAuthorityV2([protected authority])")
    }
}

impl<'journal> MountSourceAcquisitionJournalAuthorityV2<'journal> {
    pub(crate) fn claim(journal: &'journal mut Journal) -> Result<Self, JournalError> {
        Ok(Self {
            authority: journal.claim_fixed_mount_source_acquisition_authority()?,
        })
    }

    /// Runs one operation with a nonescaping exact fixed namespace-40 claim.
    ///
    /// The higher-ranked borrow prevents the raw claim, any borrowed record,
    /// or a security session facade tied to it from surviving this call.
    #[doc(hidden)]
    pub fn with_authority<R>(
        &mut self,
        operation: impl for<'borrow> FnOnce(&'borrow mut ProtectedJournalAuthority<'journal>) -> R,
    ) -> R {
        operation(&mut self.authority)
    }
}

struct JournalAuthorityInstance;

impl Journal {
    /// Reports whether this journal handle remains healthy.
    ///
    /// Materialized values deliberately remain available for diagnostics after
    /// an I/O failure, but they may precede a transaction that reached disk.
    /// This health check alone does not establish protected, current authority.
    /// External authority owners should use [`Self::claim_protected_authority`].
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation.
    pub fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.native.is_poisoned() {
            Err(JournalError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Compares Stage A Source DATA against this actual handle's opened ceilings.
    ///
    /// This advisory does not mint preflight, grant, writer or physical origin
    /// evidence. A future protected adapter must revalidate currentness/custody.
    ///
    /// # Errors
    ///
    /// Rejects a poisoned handle, repeated transaction, incomplete Source union,
    /// insufficient full-transaction/current debt headroom or sequence exhaustion.
    pub(crate) fn compare_source_capacity_advisory_v5(
        &self,
        transaction: Option<&JournalTransaction>,
        origins: &[SourceOriginalAdmissionDataV5],
        challenges: &[aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5<'_>],
    ) -> Result<SourceCapacityUnionComparisonDataV5, JournalError> {
        self.ensure_healthy()?;
        if transaction.is_some_and(|transaction| self.native.transaction_ids().contains(transaction.id())) {
            return Err(JournalError::DuplicateTransaction);
        }
        let comparison = compare_source_capacity_union_data_v5(
            self.native.state(),
            transaction,
            origins,
            challenges,
            self.native.limits(),
        )?;
        let (append_bytes, added_transactions, added_frames) = match transaction {
            Some(transaction) => (
                encoded_transaction_append_bytes(transaction)?,
                1_usize,
                (transaction.records().len() as u64)
                    .checked_add(2)
                    .ok_or(JournalError::SequenceExhausted)?,
            ),
            None => (0, 0, 0),
        };
        let journal_bytes = self.native
            .file()
            .metadata()?
            .len()
            .checked_add(append_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        let transactions = self.native.committed_transactions()
            .checked_add(added_transactions)
            .ok_or(JournalError::LimitExceeded("transaction count"))?;
        let next_sequence = self.native.next_sequence()
            .checked_add(added_frames)
            .ok_or(JournalError::SequenceExhausted)?;
        // The complete union already checked every exact changed floor. Reuse
        // the shared all-family fold on the after cut, with no pretend generic
        // settlement identifier or weaker legacy decoder.
        source_original_native::replay::require_advisory_bounds(
            &comparison, self.native.limits(), journal_bytes, transactions, next_sequence,
        )?;
        Ok(comparison)
    }

    /// Claims this protected journal for one closed authority namespace.
    ///
    /// The claim is unavailable for journals opened through [`Self::open`] and
    /// fails when any materialized record or committed history since the last
    /// compaction belongs to another namespace. The returned guard retains an
    /// exclusive borrow and removes namespace choice from reads. It also
    /// rejects transactions containing foreign records.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] when this journal was not
    /// opened through a protected opener, or [`JournalError::Poisoned`] after
    /// an ambiguous durable mutation. Returns
    /// [`JournalError::ForeignAuthorityNamespace`] when the journal contains
    /// committed history or materialized state outside `namespace`.
    pub fn claim_protected_authority(
        &mut self,
        namespace: RecordNamespace,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        if namespace == RecordNamespace::MountSourceAcquisition
            || namespace == RecordNamespace::NixOfflineProvisioning
            || namespace == RecordNamespace::ControllerResourceReservation
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        capacity_reservation::require_legacy_reservations(self.native.state())?;
        let has_foreign_history = self.native.committed_namespaces().iter().any(|committed_namespace| {
            *committed_namespace != namespace
                && *committed_namespace != RecordNamespace::GlobalCapacityReservation
        });
        let has_foreign_state = self.native.state().keys().any(|(record_namespace, _)| {
            *record_namespace != namespace
                && *record_namespace != RecordNamespace::GlobalCapacityReservation
        });
        if has_foreign_history
            || has_foreign_state
            || !capacity_reservation::all_reservations_owned_by(self.native.state(), namespace)?
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace,
            scope: ProtectedAuthorityScope::SingleNamespace,
        })
    }

    fn claim_fixed_mount_source_acquisition_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        native_held::require_legacy_owner(self.native.state(), RecordNamespace::MountSourceAcquisition)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope: ProtectedAuthorityScope::FixedMountSourceAcquisition,
        })
    }

    /// Claims the closed journal group used by atomic Mount source consumption.
    ///
    /// Owner reads and ordinary commits remain restricted to namespace 40.
    /// The guard additionally permits its single purpose-built four-PUT edge
    /// over namespaces 40, 39, 3, and 2. Other namespaces already retained by
    /// the broker remain inaccessible through this purpose-limited guard.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for an unprotected journal,
    /// [`JournalError::Poisoned`] after ambiguous durability.
    #[doc(hidden)]
    pub(crate) fn claim_mount_source_consumption_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        native_held::require_legacy_owner(self.native.state(), RecordNamespace::MountSourceAcquisition)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountSourceAcquisition,
            scope: ProtectedAuthorityScope::MountSourceConsumption,
        })
    }

    /// Claims the closed journal group used by Mount-manager startup capture.
    ///
    /// The guard exposes no generic record or transaction operations. Its
    /// purpose-specific implementation reads only namespaces 45, 40, 39, and
    /// 2, and may append only one fully derived namespace-45 capture record.
    /// Other broker namespaces remain inaccessible through the guard.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::ProtectedBoundary`] for an unprotected journal,
    /// or [`JournalError::Poisoned`] after ambiguous durability.
    #[doc(hidden)]
    pub(crate) fn claim_mount_manager_startup_authority(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        native_held::require_legacy_owner(self.native.state(), RecordNamespace::MountSourceAcquisition)?;
        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: RecordNamespace::MountManagerStartupAuthority,
            scope: ProtectedAuthorityScope::MountManagerStartup,
        })
    }

    /// Claims one closed cross-namespace capacity-reserved transaction protocol.
    ///
    /// The returned guard exposes capacity-specific admission, recovery, and
    /// settlement. `RuntimeExecution` and `SourceProviderNativeTerminal`
    /// additionally permit ordinary owner-only reads and transactions;
    /// `PublisherCompletion` remains fully composite. No purpose admits
    /// namespace 46 through generic transaction methods.
    ///
    /// # Errors
    ///
    /// Returns an error for an unprotected or poisoned journal or malformed
    /// retained global reservation provenance.
    pub(crate) fn claim_global_capacity_reservation_authority(
        &mut self,
        purpose: GlobalCapacityReservationPurposeV1,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        if purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        capacity_reservation::require_legacy_reservations(self.native.state())?;

        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: purpose.owner_namespace(),
            scope: ProtectedAuthorityScope::CapacityReservation(purpose),
        })
    }

    /// Claims the fixed source-provider native terminal capacity protocol.
    ///
    /// Ordinary operations remain restricted to namespace 41. Capacity
    /// admission and settlement alone may also name namespace 46.
    ///
    /// # Errors
    ///
    /// Returns an error for an unprotected or poisoned journal, malformed
    /// reservation provenance, or foreign committed history or state.
    pub fn claim_source_provider_native_terminal_authority_v1(
        &mut self,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        capacity_reservation::require_legacy_reservations(self.native.state())?;
        let namespace = RecordNamespace::SourceProviderAuthority;
        let has_foreign_history = self.native.committed_namespaces().iter().any(|committed_namespace| {
            *committed_namespace != namespace
                && *committed_namespace != RecordNamespace::GlobalCapacityReservation
        });
        let has_foreign_state = self.native.state().keys().any(|(record_namespace, _)| {
            *record_namespace != namespace
                && *record_namespace != RecordNamespace::GlobalCapacityReservation
        });
        // Deleted foreign rows still taint this generation until compaction.
        if has_foreign_history
            || has_foreign_state
            || !capacity_reservation::all_reservations_owned_by(self.native.state(), namespace)?
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        self.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        )
    }

    /// Requires retained protected storage provenance before resolving authority.
    pub(crate) fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if self.protected.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Returns the currently materialized value for a logical key.
    ///
    /// This diagnostic view remains readable after an ambiguous I/O failure.
    /// It does not establish that the value is current durable authority.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.native.state()
            .get(&(namespace, key.to_vec()))
            .map(Vec::as_slice)
    }

    /// Iterates the materialized records in one namespace by bytewise key.
    ///
    /// The iterator is a stable snapshot only while this journal remains
    /// immutably borrowed. Callers must copy values needed across a commit.
    /// Like [`Self::get`], this diagnostic view does not establish current
    /// authority after an ambiguous I/O failure. The ordered namespace range
    /// avoids scanning unrelated desired-state and operation records.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.native.state()
            .range((namespace, Vec::new())..)
            .take_while(move |((record_namespace, _), _)| *record_namespace == namespace)
            .map(|((_, key), value)| (key.as_slice(), value.as_slice()))
    }

    /// Iterates every materialized record by namespace and bytewise key.
    ///
    /// The iterator is a stable snapshot only while this journal remains
    /// immutably borrowed. Callers must copy values needed across a commit.
    /// Like [`Self::get`], this diagnostic view does not establish current
    /// authority after an ambiguous I/O failure. Consumers that own a closed
    /// journal schema can use this complete ordering to reject foreign
    /// namespaces instead of silently omitting them.
    pub fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> {
        self.native.state()
            .iter()
            .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))
    }

    // This closed borrowed extent prices already-owned storage and the actual
    // native file, rather than materializing a second logical replay. It is
    // DATA until the entered prefix joins the same original bank and writer.
    pub(crate) fn first_global_allocation_shape_v1(
        &self,
    ) -> Result<crate::controller_resource_reservation::service_interval::JournalShape, JournalError> {
        self.ensure_healthy()?;
        let mut retained_bytes = 0_usize;
        for ((_, key), value) in self.native.state() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(JournalError::JournalTooLarge)?;
        }
        for key in self.idempotency.keys() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .ok_or(JournalError::JournalTooLarge)?;
        }
        let cells = self.native.state().len().checked_add(self.idempotency.len())
            .and_then(|count| count.checked_add(self.native.transaction_ids().len()))
            .and_then(|count| count.checked_add(self.native.committed_namespaces().len()))
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(crate::controller_resource_reservation::service_interval::JournalShape {
            retained_bytes,
            cells,
            native_bytes: self.native.file().metadata()?.len(),
            maximum_transaction_bytes: self.native.limits().maximum_transaction_bytes,
            maximum_record_bytes: self.native.limits().maximum_record_bytes,
        })
    }

    // Uses the same framing layouts before the prefix's two record Vecs exist.
    pub(crate) fn first_global_prefix_append_bytes_v1() -> Result<u64, JournalError> {
        let begin = EncodedFrameLayout::new(std::mem::size_of::<u32>())?;
        let head = EncodedFrameLayout::new(EncodedRecordLayout::new(17, Some(945))?.payload_bytes)?;
        let claim = EncodedFrameLayout::new(EncodedRecordLayout::new(17, Some(531))?.payload_bytes)?;
        let commit = EncodedFrameLayout::new(COMMIT_PAYLOAD_BYTES)?;
        [begin.frame_bytes, head.frame_bytes, claim.frame_bytes, commit.frame_bytes]
            .into_iter().try_fold(0_u64, |bytes, frame| {
                bytes.checked_add(frame as u64).ok_or(JournalError::JournalTooLarge)
            })
    }

    // Closed Global recipes: acceptance, Tree/lineage/receipt/pending, floor
    // ACK, Source ACK, Complete, inclusive Project grant, and prefix first use.
    // Fixed genesis values fit the largest existing strict phase payload;
    // native bank heads are separately included in that upper bound. This
    // prices framing through the same engine, not the 1-GiB Source TX ceiling.
    pub(crate) fn first_global_native_append_bound_v1(
        largest_phase_payload: usize,
    ) -> Result<u64, JournalError> {
        let key = controller_source_genesis::ACCEPTANCE_PREFIX.len()
            .checked_add(std::mem::size_of::<aos_sandbox_core::ProjectId>())
            .ok_or(JournalError::JournalTooLarge)?;
        let value = largest_phase_payload.max(945);
        let record = EncodedFrameLayout::new(EncodedRecordLayout::new(key, Some(value))?.payload_bytes)?;
        let begin = EncodedFrameLayout::new(std::mem::size_of::<u32>())?;
        let commit = EncodedFrameLayout::new(COMMIT_PAYLOAD_BYTES)?;
        [1_usize, 4, 1, 2, 1, 3, 2].into_iter().try_fold(0_u64, |bytes, members| {
            let transaction = record.frame_bytes.checked_mul(members)
                .and_then(|bytes| bytes.checked_add(begin.frame_bytes))
                .and_then(|bytes| bytes.checked_add(commit.frame_bytes))
                .ok_or(JournalError::JournalTooLarge)?;
            bytes.checked_add(u64::try_from(transaction).map_err(|_| JournalError::JournalTooLarge)?)
                .ok_or(JournalError::JournalTooLarge)
        })
    }

    /// Reports whether replay produced no materialized record in any namespace.
    ///
    /// This diagnostic view remains available after an ambiguous I/O failure
    /// and does not establish protected, current authority. Authority owners
    /// should use [`ProtectedJournalAuthority::is_materialized_empty`].
    #[must_use]
    pub fn is_materialized_empty(&self) -> bool {
        self.native.state().is_empty()
    }

    /// Returns the next monotonic frame sequence defining the current snapshot boundary.
    ///
    /// The value starts at one for an empty journal and advances only after a
    /// transaction is durably committed. Inventory producers may therefore use
    /// it as a nonzero watermark without implying that an empty journal has a
    /// committed frame. This diagnostic value remains available after poison;
    /// it is not an authority token. Authority owners should use
    /// [`ProtectedJournalAuthority::snapshot`].
    #[must_use]
    pub const fn snapshot_sequence(&self) -> u64 {
        self.native.next_sequence()
    }

    /// Supplies actual opened ceilings to a narrowly owned local protocol.
    pub(crate) const fn configured_limits(&self) -> JournalLimits {
        self.native.limits()
    }

    /// Compares the remaining existing-output Nix main-journal geometry.
    ///
    /// The pending Realize request is already durable. The three widths cover
    /// its Terminal, the following Query RequestPrepared, and Query Terminal.
    /// This borrowed sizing comparison creates no transaction, reservation,
    /// currentness certificate, or permission to perform an effect.
    ///
    /// # Errors
    ///
    /// Rejects unhealthy or changed protected custody, foreign provenance,
    /// missing selected rows, exhausted sequence space, and any opened native
    /// limit exceeded by a record, transaction, or materialization prefix.
    #[doc(hidden)]
    pub fn compare_online_nix_main_suffix_capacity_v1(
        &self,
        traffic_key: &[u8],
        fence_key: &[u8],
        current_effect_key: &[u8],
        fence_value_ceiling: usize,
        pending_effect_value_ceiling: usize,
        complete_effect_value_ceiling: usize,
    ) -> Result<[usize; 3], JournalError> {
        if traffic_key.len() != 9 || fence_key.len() != 24
            || current_effect_key.len() != 24
            || traffic_key == fence_key || fence_key == current_effect_key
            || traffic_key == current_effect_key
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let keys = [Some(traffic_key), Some(fence_key), Some(current_effect_key), None];
        for key in keys.into_iter().flatten() {
            if !self.native.state().iter().any(|((namespace, actual), _)|
                *namespace == RecordNamespace::BrokerSessionTraffic && actual.as_slice() == key)
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }

        let traffic_overhead = EncodedRecordLayout::new(traffic_key.len(), Some(0))?.payload_bytes;
        let traffic_bytes = self.native.limits().maximum_record_bytes.checked_sub(traffic_overhead)
            .ok_or(JournalError::LimitExceeded("record bytes"))?;
        let terminal = [
            OnlineNixExtentV1::put(0, traffic_key.len(), traffic_bytes),
            OnlineNixExtentV1::put(2, current_effect_key.len(), complete_effect_value_ceiling),
        ];
        let request = [
            OnlineNixExtentV1::put(0, traffic_key.len(), traffic_bytes),
            OnlineNixExtentV1::put(1, fence_key.len(), fence_value_ceiling),
            // The real Query UUID/key does not exist yet. One anonymous fixed
            // extent accounts for it without fabricating a prospective key.
            OnlineNixExtentV1::put(3, 24, pending_effect_value_ceiling),
        ];
        let query = [
            OnlineNixExtentV1::put(0, traffic_key.len(), traffic_bytes),
            OnlineNixExtentV1::put(3, 24, complete_effect_value_ceiling),
        ];
        let widths = self.compare_online_nix_extents_v1(
            keys, &[&terminal, &request, &query],
        )?;
        Ok([widths[0], widths[1], widths[2]])
    }

    /// Compares three prepare/finalize pairs on the same opened Nix sidecar.
    ///
    /// The existing checkpoint remains resident during each prepare and is
    /// replaced before the intent and prepared-transaction rows are deleted.
    /// Sizing includes every such transient prefix, not only each final map.
    /// No intent, checkpoint, signature, transaction ID, or token is invented.
    ///
    /// # Errors
    ///
    /// Rejects changed or unhealthy protected custody, foreign or occupied
    /// sidecar rows, exhausted sequence space, and any opened native ceiling.
    #[doc(hidden)]
    pub fn compare_online_nix_floor_suffix_capacity_v1(
        &self,
        checkpoint_key: &[u8],
        intent_key: &[u8],
        transaction_key: &[u8],
        checkpoint_value_bytes: usize,
        intent_value_bytes: usize,
        prepared_main_value_bytes: [usize; 3],
    ) -> Result<(), JournalError> {
        if checkpoint_key != b"checkpoint" || intent_key != b"intent"
            || transaction_key != b"transaction" || self.native.state().len() != 1
            || !self.native.state().iter().any(|((namespace, key), value)|
                *namespace == RecordNamespace::BrokerSessionTraffic
                    && key.as_slice() == checkpoint_key
                    && value.len() == checkpoint_value_bytes)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let keys = [Some(checkpoint_key), Some(intent_key), Some(transaction_key), None];
        let preparations = prepared_main_value_bytes.map(|bytes| [
            OnlineNixExtentV1::put(1, intent_key.len(), intent_value_bytes),
            OnlineNixExtentV1::put(2, transaction_key.len(), bytes),
        ]);
        let finalize = [
            OnlineNixExtentV1::put(0, checkpoint_key.len(), checkpoint_value_bytes),
            OnlineNixExtentV1::delete(1, intent_key.len()),
            OnlineNixExtentV1::delete(2, transaction_key.len()),
        ];
        self.compare_online_nix_extents_v1(keys, &[
            &preparations[0], &finalize,
            &preparations[1], &finalize,
            &preparations[2], &finalize,
        ])?;
        Ok(())
    }

    // Four fixed slots describe only selected extents. All other actual rows
    // stay in the borrowed map and remain charged; no inventory clone is made.
    fn compare_online_nix_extents_v1(
        &self,
        keys: [Option<&[u8]>; 4],
        phases: &[&[OnlineNixExtentV1]],
    ) -> Result<[usize; 6], JournalError> {
        self.ensure_healthy()?;
        self.require_protected_names_current()?;
        validate_limits(self.native.limits())?;
        if phases.is_empty() || phases.len() > 6
            || self.native.committed_namespaces().iter().any(|namespace|
                *namespace != RecordNamespace::BrokerSessionTraffic)
            || self.native.state().keys().any(|(namespace, _)|
                *namespace != RecordNamespace::BrokerSessionTraffic)
            || !self.idempotency.is_empty()
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        let mut values = [None; 4];
        let mut materialized = 0_usize;
        for ((_, key), value) in self.native.state() {
            materialized = materialized.checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(JournalError::LimitExceeded("materialized state bytes"))?;
            for (index, selected) in keys.iter().enumerate() {
                if *selected == Some(key.as_slice()) {
                    values[index] = Some(value.len());
                }
            }
        }
        if materialized != self.native.materialized_bytes() {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut entries = self.native.state().len();
        let original_length = self.native.file().metadata()?.len();
        let mut length = original_length;
        let mut next = self.native.next_sequence();
        let mut committed = self.native.committed_transactions();
        let mut widths = [0_usize; 6];
        if next == 0 || next == u64::MAX || length > self.native.limits().maximum_journal_bytes
            || materialized > self.native.limits().maximum_materialized_bytes
            || entries > self.native.limits().maximum_materialized_records
        {
            return Err(JournalError::ProtectedBoundary);
        }

        for (phase, records) in phases.iter().enumerate() {
            if records.is_empty() || records.len() > self.native.limits().maximum_records_per_transaction {
                return Err(JournalError::LimitExceeded("transaction record count"));
            }
            let _ = u32::try_from(records.len())
                .map_err(|_| JournalError::LimitExceeded("transaction record count"))?;
            let mut changed = [false; 4];
            let mut payload = 0_usize;
            let mut append = EncodedFrameLayout::new(4)?.frame_bytes
                .checked_add(EncodedFrameLayout::new(COMMIT_PAYLOAD_BYTES)?.frame_bytes)
                .ok_or(JournalError::JournalTooLarge)?;
            for record in *records {
                if record.slot >= values.len() || changed[record.slot]
                    || keys[record.slot].is_some_and(|key| key.len() != record.key_bytes)
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                changed[record.slot] = true;
                let layout = EncodedRecordLayout::new(record.key_bytes, record.value_bytes)?;
                if record.key_bytes > self.native.limits().maximum_key_bytes
                    || layout.payload_bytes > self.native.limits().maximum_record_bytes
                {
                    return Err(JournalError::LimitExceeded("record bytes"));
                }
                payload = payload.checked_add(layout.payload_bytes)
                    .filter(|bytes| *bytes <= self.native.limits().maximum_transaction_bytes)
                    .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
                append = append.checked_add(EncodedFrameLayout::new(layout.payload_bytes)?.frame_bytes)
                    .ok_or(JournalError::JournalTooLarge)?;

                if let Some(old) = values[record.slot] {
                    materialized = materialized.checked_sub(record.key_bytes)
                        .and_then(|bytes| bytes.checked_sub(old))
                        .ok_or(JournalError::ProtectedBoundary)?;
                }
                match record.value_bytes {
                    Some(bytes) => {
                        if values[record.slot].is_none() {
                            entries = entries.checked_add(1)
                                .ok_or(JournalError::LimitExceeded("materialized record count"))?;
                        }
                        materialized = materialized.checked_add(record.key_bytes)
                            .and_then(|total| total.checked_add(bytes))
                            .filter(|total| *total <= self.native.limits().maximum_materialized_bytes)
                            .ok_or(JournalError::LimitExceeded("materialized state bytes"))?;
                    }
                    None if values[record.slot].is_some() => entries -= 1,
                    None => {}
                }
                values[record.slot] = record.value_bytes;
                if entries > self.native.limits().maximum_materialized_records {
                    return Err(JournalError::LimitExceeded("materialized record count"));
                }
            }

            committed = committed.checked_add(1)
                .filter(|count| *count <= self.native.limits().maximum_transactions)
                .ok_or(JournalError::LimitExceeded("committed transaction count"))?;
            let frames = u64::try_from(records.len()).ok().and_then(|count| count.checked_add(2))
                .ok_or(JournalError::SequenceExhausted)?;
            next = next.checked_add(frames).filter(|next| *next != u64::MAX)
                .ok_or(JournalError::SequenceExhausted)?;
            length = length.checked_add(u64::try_from(append).map_err(|_| JournalError::JournalTooLarge)?)
                .filter(|bytes| *bytes <= self.native.limits().maximum_journal_bytes)
                .ok_or(JournalError::JournalTooLarge)?;
            widths[phase] = JournalTransaction::maximum_prepared_bytes_v1(JournalLimits {
                maximum_records_per_transaction: records.len(),
                maximum_transaction_bytes: payload,
                ..self.native.limits()
            })?;
        }

        self.require_protected_names_current()?;
        if self.native.file().metadata()?.len() != original_length {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(widths)
    }

    /// Diagnostically resolves a caller key against materialized request identity.
    ///
    /// This view remains available after poison and does not establish current
    /// authority.
    #[must_use]
    pub fn check_idempotency(
        &self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome {
        match self.idempotency.get(key.as_bytes()) {
            None => IdempotencyOutcome::Vacant,
            Some(decision) if decision.request_digest == request_digest => {
                IdempotencyOutcome::Replay(decision.operation_id)
            }
            Some(_) => IdempotencyOutcome::Conflict,
        }
    }

    /// Returns the already-decoded selected genesis and successor family DATA.
    ///
    /// # Errors
    /// Rejects a poisoned writer or any incomplete selected whole-family join.
    /// This comparison does not lend mutation, signing or Root currentness.
    pub(crate) fn source_project_genesis_data_v3(
        &self,
        selected: aos_sandbox_core::ProjectId,
    ) -> Result<source_tree_successor::SourceProjectFamilyDataV3, JournalError> {
        self.ensure_healthy()?;
        source_tree_successor::current_project_genesis_data_v3(self.native.state(), selected)
    }

    /// Borrows the complete bank replay cut from the healthy original writer.
    #[cfg(target_os = "linux")]
    pub(crate) fn controller_resource_state_v1(
        &self,
    ) -> Result<&BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, JournalError> {
        self.validate_held_protected_names()?;
        Ok(self.native.state())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn controller_resource_contains_transaction_v1(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<bool, JournalError> {
        self.validate_held_protected_names()?;
        Ok(self.native.transaction_ids().contains(transaction_id))
    }

    /// Rewrites the materialized state into an atomically installed journal.
    ///
    /// A successful compaction establishes a new canonical materialization
    /// boundary. Namespace history removed by compaction no longer participates
    /// in later protected-authority claims. Compaction also rotates the
    /// in-memory authority identity, making every earlier snapshot and
    /// preflight token stale even when the replacement reuses a sequence value.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the compacted state exceeds transaction
    /// bounds or any temporary-file, sync, rename, directory-sync, reopen, or
    /// validation operation fails, or while a closed policy owner hold or Host
    /// Effect fence is held, or for the fixed deployment preparation main,
    /// whose original native history must remain intact.
    pub fn compact(&mut self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if self.mount_git_coverage_denies_new_v1() {
            return Err(JournalError::ProtectedBoundary);
        }
        if delete_batch::has_dependencies(self.native.state()) {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(target_os = "linux")]
        if self.q04_lower_history_present {
            // The initial Q04 slice retains exact completed lower native
            // acquire/release/clear membership. Materializing only the final
            // released row would erase that relation; no retirement is implied.
            return Err(JournalError::ProtectedBoundary);
        }
        if self.native.state().keys().any(|(namespace, _)| {
            *namespace == RecordNamespace::NixOfflineProvisioning
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        if self.source_original_replay.has_dependencies()
            || source_original_native::replay::has_original_rows(self.native.state())
            || self.native.state().keys().any(|(namespace, key)| {
                *namespace == RecordNamespace::SourceProviderAuthority
                    && source_original_native::challenge::is_challenge_key(key)
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(target_os = "linux")]
        runtime_deployment_history::require_no_compaction(self)?;
        root_local_recovery::pending(self.native.state())?;
        root_original_native::pending(self.native.state(), self.native.limits())?;
        root_original_inventory::validate_rejoined_capacity(
            self.native.state(),
            self.native.materialized_bytes(),
            self.native.file().metadata()?.len(),
            self.native.committed_transactions(),
            self.native.limits(),
            self.native.next_sequence(),
        )?;
        source_tree_genesis::require_no_compaction(self.native.state())?;
        source_tree_successor::require_no_compaction(self.native.state())?;
        source_project_admission_challenge::require_no_compaction(self.native.state())?;
        controller_source_genesis::require_no_compaction(self.native.state())?;
        controller_source_successor_issuance::require_no_compaction(self.native.state())?;
        // The bank retains exact native transaction membership and uncertain
        // claims. Generic state-only compaction is not its recovery barrier.
        if self.native.state().keys().any(|(namespace, _)| {
            *namespace == RecordNamespace::ControllerResourceReservation
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        cache_policy_hold::require_valid_compaction(self)?;
        host_settlement_admission_gate::require_no_compaction(self.native.state())?;
        host_currentness_fence::require_no_compaction(self.native.state())?;
        host_execution_fence::require_no_compaction(self.native.state())?;
        controller_policy_hold::require_no_compaction(self.native.state())?;
        source_domain_policy_hold::require_no_compaction(self.native.state())?;
        let _cache_policy_guard = cache_policy_hold::mutation_guard(self)?;
        if let Err(error) = self.compact_inner() {
            self.native.poison();
            return Err(error);
        }
        root_local_recovery::pending(self.native.state()).inspect_err(|_| self.native.poison())?;
        root_original_native::pending(self.native.state(), self.native.limits())
            .inspect_err(|_| self.native.poison())?;
        root_original_inventory::validate_rejoined_capacity(
            self.native.state(),
            self.native.materialized_bytes(),
            self.native.file().metadata()?.len(),
            self.native.committed_transactions(),
            self.native.limits(),
            self.native.next_sequence(),
        ).inspect_err(|_| self.native.poison())?;
        Ok(())
    }

    fn compact_inner(&mut self) -> Result<(), JournalError> {
        if let Some(location) = &self.protected {
            let (file, replay) = compact_protected(location, self.native.state(), self.native.limits())?;
            self.native.replace_replayed_file(
                file,
                NativeJournalState::from_owned_parts(
                    replay.next_sequence, replay.committed_transactions,
                    replay.transaction_ids, replay.committed_namespaces,
                    replay.state, replay.materialized_bytes,
                ),
            );
            self.idempotency = replay.idempotency;
            self.source_challenge_history = replay.source_challenge_history;
            self.source_original_replay = replay.source_original_replay;
            self.source_history_compacted = replay.source_history_compacted;
            #[cfg(target_os = "linux")]
            {
                self.q04_lower_history_present = replay.q04_lower_history_present;
            }
            self.authority_instance = Arc::new(JournalAuthorityInstance);
            return Ok(());
        }
        let temporary = sibling_with_suffix(self.native.path(), ".compact.tmp");
        let mut replacement = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;

        write_compacted(&mut replacement, self.native.state(), self.native.limits())?;
        replacement.sync_all()?;
        if replacement.metadata()?.len() > self.native.limits().maximum_journal_bytes {
            return Err(JournalError::JournalTooLarge);
        }
        drop(replacement);

        fs::rename(&temporary, self.native.path())?;
        sync_parent(self.native.path())?;

        let (file, replay) = reopen_replacement(self.native.path(), self.native.limits())?;
        self.native.replace_replayed_file(
            file,
            NativeJournalState::from_owned_parts(
                replay.next_sequence, replay.committed_transactions,
                replay.transaction_ids, replay.committed_namespaces,
                replay.state, replay.materialized_bytes,
            ),
        );
        self.idempotency = replay.idempotency;
        self.source_challenge_history = replay.source_challenge_history;
        self.source_original_replay = replay.source_original_replay;
        self.source_history_compacted = replay.source_history_compacted;
        #[cfg(target_os = "linux")]
        {
            self.q04_lower_history_present = replay.q04_lower_history_present;
        }
        self.authority_instance = Arc::new(JournalAuthorityInstance);
        Ok(())
    }
}

impl ProtectedJournalAuthority<'_> {
    /// Checks this held root-owned writer against its fixed physical names.
    ///
    /// The existing exclusive claim stays borrowed while the journal opener
    /// re-resolves its directory and compares the journal and lock inodes.
    /// This observation grants no authority and changes neither namespace nor
    /// claim scope. It does not fence a privileged rename after the check.
    ///
    /// # Errors
    ///
    /// Rejects a claim that cannot perform generic authority reads, changed
    /// root/directory/journal/lock names, or an unhealthy protected writer.
    pub fn validate_held_root_owned_at(
        &self,
        directory: impl AsRef<Path>,
        name: &str,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.validate_held_root_owned_at(directory, name)
    }

    /// Validates the fixed provider namespace-41 storage boundary.
    ///
    /// This purpose check compares the retained protected directory descriptor
    /// with a fresh no-symlink resolution of the compiled-in provider state
    /// root and requires the exact journal basename. It grants no record or
    /// mutation authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the current dedicated namespace-41
    /// claim over `/var/lib/aos/source-provider/provider.journal`.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_storage(&self) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_fixed_storage("/var/lib/aos/source-provider", "provider.journal")
    }

    /// Validates the fixed Provider native-hold challenge journal location.
    ///
    /// The dedicated journal shares namespace 41 but has its own exclusive
    /// lock and format. Its retained directory must still be the protected
    /// Provider state root at each authority-bound read or mutation.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the current dedicated namespace-41
    /// claim over the fixed native-hold challenge journal.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_hold_challenge_storage(
        &self,
    ) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_fixed_storage(
            "/var/lib/aos/source-provider",
            "native-hold-challenges.journal",
        )
    }

    fn validate_fixed_storage(&self, directory: &str, name: &str) -> Result<(), JournalError> {
        let retained = self
            .journal
            .protected
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if retained.expected_uid() != 0 || retained.name() != name {
            return Err(JournalError::ProtectedBoundary);
        }
        let fixed = resolve_protected_directory_from_root::<crate::journal::JournalError>(
            Path::new(directory),
            0,
        )?;
        retained.require_opened_directory::<JournalError>(&fixed)?;
        Ok(())
    }

    /// Mints one move-only handoff from the exact current fixed provider claim.
    ///
    /// # Errors
    ///
    /// Returns an error unless the fixed path, basename, namespace, journal
    /// instance, and current sequence are all protected and current.
    #[doc(hidden)]
    pub fn fixed_source_provider_session_handoff(
        &self,
    ) -> Result<FixedSourceProviderJournalHandoffV1<'_, '_>, JournalError> {
        self.validate_fixed_source_provider_storage()?;
        Ok(FixedSourceProviderJournalHandoffV1 {
            authority: self,
            sequence: self.journal.native.next_sequence(),
        })
    }

    /// Revalidates a fixed provider session handoff before it is consumed.
    ///
    /// # Errors
    ///
    /// Returns an error after another append, compaction, reopen, or owner
    /// replacement, or for a handoff minted by another journal.
    #[doc(hidden)]
    pub fn validate_fixed_source_provider_session_handoff(
        &self,
        handoff: &FixedSourceProviderJournalHandoffV1<'_, '_>,
    ) -> Result<(), JournalError> {
        if self.scope == ProtectedAuthorityScope::SourceOriginalNativeV5 {
            source_original_native::writer::require_fixed(self.journal)?;
        } else if self.scope == ProtectedAuthorityScope::SourceProviderHeldReadOnly {
            source_provider_readonly::validate_current_authority(self)?;
        } else {
            self.validate_fixed_source_provider_storage()?;
        }
        if !core::ptr::eq(handoff.authority, self) || handoff.sequence != self.journal.native.next_sequence()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Validates this guard as the exact namespace-40 Mount source authority.
    ///
    /// This purpose check is public only so security custody in another crate
    /// can reject a generic protected guard before interpreting `AOSMSA02`
    /// bytes. It grants no record, mutation, or snapshot authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy and names namespace 40.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if !matches!(
            (self.namespace, self.scope),
            (
                RecordNamespace::MountSourceAcquisition,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::FixedMountSourceAcquisition
                    | ProtectedAuthorityScope::RootLocalRecoveryKind2
                    | ProtectedAuthorityScope::RootLocalRecoveryKind5
                    | ProtectedAuthorityScope::RootOriginalNativeV5
                    | ProtectedAuthorityScope::RootOriginalInventoryV6
                    | ProtectedAuthorityScope::MountSourceConsumption
            ) | (
                RecordNamespace::MountManagerStartupAuthority,
                ProtectedAuthorityScope::MountManagerStartup
            )
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.validate_fixed_storage("/var/lib/aos/sandbox-mount", "mount.journal")
    }

    /// Rejoins the same fixed Source owner before observing its NEW-effect denial.
    ///
    /// This is a negative-only observation. An unselected result does not
    /// replace any original Session, graph, request, clock or mutation check.
    ///
    /// # Errors
    /// Rejects another purpose, changed names or an unhealthy original writer.
    #[doc(hidden)]
    pub fn mount_source_git_coverage_denies_new_v1(&self) -> Result<bool, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self.journal.mount_git_coverage_denies_new_v1())
    }

    /// Iterates exact current namespace-40 records through an approved owner or startup scope.
    ///
    /// This method does not expose other namespaces admitted by a purpose guard.
    /// Callers must run the canonical AOSMSA02 graph validator before relying
    /// on any returned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is the sealed namespace-40 owner,
    /// Mount-consumption, or Mount-manager-startup scope.
    #[doc(hidden)]
    pub fn mount_source_acquisition_records(
        &self,
    ) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self
            .journal
            .records(RecordNamespace::MountSourceAcquisition))
    }

    /// Returns one exact current namespace-40 value through an approved scope.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is an approved namespace-40 owner or
    /// purpose guard.
    #[doc(hidden)]
    pub fn mount_source_acquisition_get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self
            .journal
            .get(RecordNamespace::MountSourceAcquisition, key))
    }

    /// Validates the mutation-owning single-namespace AOSMSA02 authority.
    ///
    /// Purpose-scoped composite guards may read namespace 40 for correlation,
    /// but cannot be substituted for the owner that commits row-only or
    /// request/head lifecycle transitions.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the exact namespace-40 owner scope.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_owner_authority(&self) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        if self.namespace != RecordNamespace::MountSourceAcquisition
            || !matches!(
                self.scope,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::FixedMountSourceAcquisition
            )
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Reports whether this protected journal generation retained one transaction identity.
    ///
    /// The identity is diagnostic unless the caller also validates the exact
    /// deterministic AOSMSA02 transaction shape and every current record.
    /// Compaction changes the authority instance and removes old provenance.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the sealed namespace-40 authority.
    #[doc(hidden)]
    pub fn contains_mount_source_acquisition_transaction(
        &self,
        transaction_id: &[u8; 16],
    ) -> Result<bool, JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        Ok(self.journal.native.transaction_ids().contains(transaction_id))
    }

    /// Validates an exact current namespace-40 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard names namespace 40 and the snapshot
    /// has the same journal instance, purpose scope, namespace, and sequence.
    #[doc(hidden)]
    pub fn validate_mount_source_acquisition_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates this guard as the exact namespace-41 provider authority.
    ///
    /// This purpose check is public only so the provider owner and independent
    /// security custody can reject a generic protected guard before decoding
    /// `AOSSPL01`. It grants no record, mutation, or snapshot authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy, purpose scoped,
    /// and names [`RecordNamespace::SourceProviderAuthority`].
    #[doc(hidden)]
    pub fn validate_source_provider_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.namespace != RecordNamespace::SourceProviderAuthority
            || !matches!(
                self.scope,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::CapacityReservation(
                        GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
                    )
            )
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Validates an exact current namespace-41 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the dedicated namespace-41 scope
    /// and the snapshot has the same journal instance, scope, and sequence.
    #[doc(hidden)]
    pub fn validate_source_provider_authority_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_source_provider_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates this guard as the exact namespace-45 startup authority.
    ///
    /// This sealed purpose check prevents caller-shaped activation metadata in
    /// any other protected namespace from authorizing manager custody or
    /// absence. It grants no descriptor or mutation authority by itself.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is healthy, purpose scoped, and names
    /// [`RecordNamespace::MountManagerStartupAuthority`].
    #[doc(hidden)]
    pub fn validate_mount_manager_startup_authority(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.namespace != RecordNamespace::MountManagerStartupAuthority
            || self.scope != ProtectedAuthorityScope::MountManagerStartup
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    /// Validates an exact current namespace-45 snapshot and guard.
    ///
    /// # Errors
    ///
    /// Returns an error unless the guard is the dedicated namespace-45 scope
    /// and the snapshot has the same journal instance, scope, and sequence.
    #[doc(hidden)]
    pub fn validate_mount_manager_startup_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_manager_startup_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates the exact namespace-40 authority used by startup absence proof.
    ///
    /// This sealed crate-local check prevents a generic protected authority for
    /// another namespace from authenticating shaped `AOSMSA02` bytes. Both the
    /// dedicated namespace scope and the purpose-scoped composite Mount source
    /// authority are accepted; the snapshot must still name this exact journal
    /// instance, scope, namespace, and sequence.
    pub(crate) fn validate_mount_source_inventory_snapshot(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_snapshot(snapshot)
    }

    /// Validates a namespace-40 snapshot's immutable journal provenance.
    ///
    /// Unlike an effect snapshot, this accepts a later sequence in the same
    /// uncompacted journal. The inventory capability separately compares its
    /// exact acquisition row, allowing a canonical proof batch to be consumed
    /// across unrelated row commits without surviving compaction or target-row
    /// replacement.
    pub(crate) fn validate_mount_source_inventory_origin(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        self.validate_mount_source_acquisition_authority()?;
        if !Arc::ptr_eq(&self.journal.authority_instance, &snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.scope != self.scope
            || snapshot.sequence > self.journal.snapshot_sequence()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Returns the current authority value for a logical key.
    ///
    /// The returned value borrows this guard, so it cannot remain live across a
    /// commit or another mutable authority operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn get(&self, key: &[u8]) -> Result<Option<&[u8]>, JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.get(self.namespace, key))
    }

    /// Iterates current authority records by bytewise key.
    ///
    /// The iterator borrows this guard, so it cannot remain live across a
    /// commit or another mutable authority operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn records(&self) -> Result<impl Iterator<Item = (&[u8], &[u8])>, JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.records(self.namespace))
    }

    /// Reports whether current authority contains no materialized records.
    ///
    /// This supports fail-closed initialization of a dedicated authority
    /// journal without treating diagnostic state from a poisoned handle as
    /// authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn is_materialized_empty(&self) -> Result<bool, JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        Ok(self.journal.is_materialized_empty())
    }

    /// Captures an opaque token for the current authority snapshot.
    ///
    /// The token carries no authority by itself. Consumers must validate it
    /// immediately before an effect that depends on state copied from this
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// or [`JournalError::ProtectedBoundary`] if retained protected-open
    /// provenance is absent.
    pub fn snapshot(&self) -> Result<ProtectedJournalSnapshot, JournalError> {
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        Ok(self.current_snapshot())
    }

    /// Validates a snapshot token immediately before an authority-bound effect.
    ///
    /// Validation checks journal health, the exact in-memory journal instance,
    /// the claimed namespace, and the current sequence. A successful check is
    /// therefore invalidated by every intervening commit.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// [`JournalError::ProtectedBoundary`] when this journal lacks retained
    /// protected-open provenance, or [`JournalError::StaleAuthoritySnapshot`]
    /// when `snapshot` belongs to another journal or namespace or its sequence
    /// is no longer current. Read-only Source guards return
    /// [`JournalError::ForeignAuthorityNamespace`] without granting an effect.
    pub fn validate_snapshot_for_effect(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
        if self.scope == ProtectedAuthorityScope::SourceProviderHeldReadOnly {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.validate_generic_authority_read()?;
        self.journal.ensure_protected_authority()?;
        self.validate_snapshot(snapshot)
    }

    /// Validates ordered authority transactions against the current journal.
    ///
    /// Every record must belong to the namespace claimed by this guard. The
    /// returned token records the exact journal instance and sequence at which
    /// validation completed. Preflight remains advisory until the token is
    /// validated at the corresponding effect boundary.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if protected current authority is unavailable
    /// or any transaction would fail the journal's commit validation.
    pub fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.preflight_with_cache_gate(transactions, CacheMutationGateV1::Ordinary)
    }

    /// Preflights the same protected scope against the original Cache gate.
    ///
    /// # Errors
    /// Refuses stale protected authority, changed gate or failed ordinary bounds.
    pub(crate) fn preflight_with_retained_cache_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.preflight_with_cache_gate(transactions, CacheMutationGateV1::Retained(gate))
    }

    pub(crate) fn preflight_with_cache_gate(
        &self,
        transactions: &[JournalTransaction],
        mut gate: CacheMutationGateV1<'_>,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        gate.preflight(self.journal, transactions)?;

        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(transactions),
        })
    }

    /// Validates a preflight token immediately before its dependent effect.
    ///
    /// Validation checks journal health, the exact in-memory journal instance,
    /// the claimed namespace, the current sequence, and the exact ordered
    /// transaction contents supplied to preflight. It fails after any
    /// intervening commit, including one made through this guard.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Poisoned`] after an ambiguous durable mutation,
    /// [`JournalError::ProtectedBoundary`] when this journal lacks retained
    /// protected-open provenance,
    /// [`JournalError::ForeignAuthorityNamespace`] when any supplied
    /// transaction record belongs to another namespace, or
    /// [`JournalError::StaleAuthoritySnapshot`] when `preflight` belongs to
    /// another journal or namespace or its sequence is no longer current.
    /// Returns
    /// [`JournalError::AuthorityPreflightMismatch`] when `transactions` differ
    /// from the preflighted sequence.
    pub fn validate_preflight_for_effect(
        &self,
        preflight: &ProtectedJournalPreflight,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespaces(transactions)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if preflight.transaction_digest != authority_preflight_digest(transactions) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }

        Ok(())
    }

    /// Appends and synchronously commits one authority transaction.
    ///
    /// Every record must belong to the namespace claimed by this guard. A
    /// durability failure poisons the underlying journal; every subsequent
    /// operation through this guard will then fail its health check.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if protected current authority is unavailable,
    /// transaction validation fails, or the durable append cannot complete.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespace(transaction)?;
        self.journal.commit(transaction)
    }

    /// Commits one exact preflight under the same original Cache gate borrow.
    ///
    /// # Errors
    /// Returns stale preflight, protected-gate or ambiguous append failure.
    pub(crate) fn commit_with_retained_cache_gate_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        transaction: &JournalTransaction,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<CommitResult, JournalError> {
        self.validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))?;
        self.journal
            .commit_with_retained_cache_gate_v1(transaction, gate)
    }

    /// Commits an exact protected preflight with the resident original gate.
    ///
    /// # Errors
    /// Refuses stale preflight, changed originals or ambiguous durability.
    pub(crate) fn commit_with_original_cache_gate_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        transaction: &JournalTransaction,
        mut gate: CacheMutationGateV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.validate_preflight_for_effect(preflight, std::slice::from_ref(transaction))?;
        gate.commit(self.journal, transaction)
    }

    /// Rechecks a closed original disposition without admitting an append.
    ///
    /// # Errors
    /// Refuses wrong scope or changed original protected target and interlock.
    pub(crate) fn require_original_cache_gate_v1(
        &self,
        gate: &mut CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_mutation()?;
        gate.check(self.journal)
    }

    /// Rechecks the original target even for a retained same-record replay.
    ///
    /// # Errors
    /// Refuses wrong authority scope or changed original protected target/gate.
    pub(crate) fn require_retained_cache_gate_v1(
        &self,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_mutation()?;
        gate.require_for_target(self.journal)
    }

    /// Checks only the sealed exact own append, never an arbitrary successor head.
    ///
    /// # Errors
    /// Refuses wrong scope, original identity, transaction or successor evidence.
    pub(crate) fn require_retained_cache_own_append_v1(
        &self,
        before: &ProtectedJournalSnapshot,
        transaction: &JournalTransaction,
        result: &CommitResult,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        self.require_original_cache_own_append_v1(
            before,
            transaction,
            result,
            &mut CacheMutationGateV1::Retained(gate),
        )
    }

    /// Checks the actual append seal for either original Cache disposition.
    ///
    /// # Errors
    /// Refuses wrong scope, original identity, transaction or successor seal.
    pub(crate) fn require_original_cache_own_append_v1(
        &self,
        before: &ProtectedJournalSnapshot,
        transaction: &JournalTransaction,
        result: &CommitResult,
        gate: &mut CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespace(transaction)?;
        if !Arc::ptr_eq(&before.instance, &self.journal.authority_instance)
            || before.scope != self.scope
            || before.namespace != self.namespace
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        gate.require_own_append(self.journal, before.sequence, transaction, result)
    }

    /// Acquires the nonauthorizing Host Effect fence from an exact owner cut.
    ///
    /// The caller must rejoin its preliminary stage and pre-fence digest under
    /// this writer claim. This narrow exception admits only the one fence row;
    /// no ordinary or policy-hold transaction can mutate a held Effect journal.
    pub(crate) fn acquire_host_execution_fence_v1(
        &mut self,
        fence: HostExecutionFenceV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        use crate::runtime_execution::no_apply_settlement::{
            HostSettlementRecordV1, HostSettlementStageV1, lease_key,
        };

        let purpose = self.validate_capacity_authority()?;
        let snapshot_sequence = self.journal.snapshot_sequence();
        let fence_bytes = fence.encode()?;
        let exact_transaction = matches!(transaction.records(), [record]
            if record.namespace() == RecordNamespace::Effect
                && record.key() == host_execution_fence::KEY
                && record.value() == Some(fence_bytes.as_slice()));
        if purpose != GlobalCapacityReservationPurposeV1::RuntimeExecution
            || !exact_transaction
            || fence.pre_fence_epoch != snapshot_sequence
            || fence.commit_sequence
                != snapshot_sequence
                    .checked_add(2)
                    .ok_or(JournalError::SequenceExhausted)?
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let preliminary_key = lease_key(fence.execution, HostSettlementStageV1::Preliminary);
        let preliminary = self
            .journal
            .get(RecordNamespace::Effect, &preliminary_key)
            .ok_or(JournalError::ProtectedBoundary)
            .and_then(|bytes| {
                HostSettlementRecordV1::decode_canonical(bytes)
                    .map_err(|_| JournalError::ProtectedBoundary)
            })?;
        let measured_cut = host_execution_fence::effect_cut_v1(
            self.journal.records(RecordNamespace::Effect),
            fence.store_binding,
            fence.pre_fence_epoch,
            false,
        )?;
        let owner_matches = self.journal.get(
            RecordNamespace::Effect,
            host_execution_fence::RUNTIME_OWNER_MARKER_KEY,
        ) == Some(fence.store_binding.as_bytes());
        let later_stages_absent = [
            HostSettlementStageV1::FloorSealed,
            HostSettlementStageV1::AckRetained,
        ]
        .into_iter()
        .all(|stage| {
            self.journal
                .get(RecordNamespace::Effect, &lease_key(fence.execution, stage))
                .is_none()
        });
        if !owner_matches
            || preliminary.stage != HostSettlementStageV1::Preliminary
            || preliminary.execution != fence.execution
            || preliminary.digest() != fence.preliminary_digest
            || preliminary.commit_sequence > fence.pre_fence_epoch
            || !later_stages_absent
            || measured_cut != fence.pre_fence_cut
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_fence_acquisition: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    #[cfg(test)]
    pub(crate) fn inject_host_execution_fence_for_test(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        if self.validate_capacity_authority()?
            != GlobalCapacityReservationPurposeV1::RuntimeExecution
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_fence_acquisition: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    /// Acquires the nonauthorizing HostState half of a retained Effect fence.
    ///
    /// The fixed five-record currentness view and its original snapshot are
    /// rechecked here. The caller holds the Effect writer and must verify that
    /// `effect_fence_digest` names its exact durable AOSCHF01 row.
    pub(crate) fn acquire_host_currentness_fence_v1(
        &mut self,
        fence: HostCurrentnessFenceV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        let fence_bytes = fence.encode()?;
        let exact_transaction = matches!(transaction.records(), [record]
            if record.namespace() == RecordNamespace::HostExecution
                && record.key() == host_currentness_fence::KEY
                && record.value() == Some(fence_bytes.as_slice()));
        if self.namespace != RecordNamespace::HostExecution
            || self.scope != ProtectedAuthorityScope::SingleNamespace
            || !exact_transaction
            || self.journal.snapshot_sequence() != fence.pre_hold_epoch
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal.ensure_protected_authority()?;

        let keys = self
            .journal
            .records(RecordNamespace::HostExecution)
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        let exact_owner = keys.len() == host_currentness_fence::OWNER_KEYS.len()
            && keys
                .iter()
                .all(|key| host_currentness_fence::OWNER_KEYS.contains(key));
        let measured_cut = host_currentness_fence::cut_v1(
            self.journal.records(RecordNamespace::HostExecution),
            fence.store_binding,
            fence.pre_hold_epoch,
            false,
        )?;
        if !exact_owner || measured_cut != fence.pre_hold_cut {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_currentness_fence_acquisition: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    #[cfg(test)]
    pub(crate) fn inject_host_currentness_fence_for_test(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        if self.namespace != RecordNamespace::HostExecution
            || self.scope != ProtectedAuthorityScope::SingleNamespace
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_currentness_fence_acquisition: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    /// Appends one structurally exact, nonauthorizing admission-time witness.
    ///
    /// The protected HostState cut and trusted clock provenance are supplied
    /// by the retaining Host owner; this low-level boundary independently
    /// rechecks the Effect marker, preliminary stage, sequence, and key.
    pub(crate) fn append_host_settlement_admission_witness_v1(
        &mut self,
        witness: crate::runtime_execution::HostSettlementAdmissionWitnessV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV1;

        use crate::runtime_execution::no_apply_settlement::{
            HostSettlementRecordV1, HostSettlementStageV1, lease_key,
        };

        if self.validate_capacity_authority()?
            != GlobalCapacityReservationPurposeV1::RuntimeExecution
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let bytes = witness
            .encode()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let exact_transaction = matches!(transaction.records(), [record]
            if record.namespace() == RecordNamespace::Effect
                && record.key() == witness.key()
                && record.value() == Some(bytes.as_slice()));
        let expected_sequence = self
            .journal
            .snapshot_sequence()
            .checked_add(2)
            .ok_or(JournalError::ProtectedBoundary)?;
        if !exact_transaction
            || witness.commit_sequence != expected_sequence
            || self
                .journal
                .get(RecordNamespace::Effect, host_execution_fence::KEY)
                .is_some()
            || self.journal.get(
                RecordNamespace::Effect,
                host_execution_fence::RUNTIME_OWNER_MARKER_KEY,
            ) != Some(witness.store_binding.as_bytes())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut marker_key = Vec::with_capacity(17);
        marker_key.push(b'n');
        marker_key.extend_from_slice(witness.execution.as_bytes());
        let marker = self
            .journal
            .get(RecordNamespace::Effect, &marker_key)
            .ok_or(JournalError::ProtectedBoundary)
            .and_then(|bytes| {
                HostExecutionNoApplyRecordV1::decode_canonical(bytes)
                    .map_err(|_| JournalError::ProtectedBoundary)
            })?;
        let preliminary = self
            .journal
            .get(
                RecordNamespace::Effect,
                &lease_key(witness.execution, HostSettlementStageV1::Preliminary),
            )
            .ok_or(JournalError::ProtectedBoundary)
            .and_then(|bytes| {
                HostSettlementRecordV1::decode_canonical(bytes)
                    .map_err(|_| JournalError::ProtectedBoundary)
            })?;
        if !witness.matches_stage(marker, preliminary, witness.store_binding) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_settlement_admission_append: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    #[cfg(test)]
    pub(crate) fn inject_host_settlement_admission_witness_for_test(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        if self.validate_capacity_authority()?
            != GlobalCapacityReservationPurposeV1::RuntimeExecution
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.journal
            .commit_in_scope(
                transaction,
                AppendScope {
                    allow_host_settlement_admission_append: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )
    }

    /// Prepares capacity reservation bound to this protected owner namespace.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request names this exact single-namespace
    /// authority and all durable reservation fields and bounds are valid.
    pub fn prepare_global_capacity_reservation_v1(
        &self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<PreparedGlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if request.purpose != purpose || request.owner_namespace != self.namespace {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        self.journal
            .prepare_global_capacity_reservation_v1(request, admission_transaction_id)
    }

    /// Preflights one owner admission transaction and its exact capacity record.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign record, a different reservation record or
    /// transaction ID, or any ordinary or outstanding-capacity bound failure.
    pub fn preflight_global_capacity_reservation_v1(
        &self,
        prepared: &PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        if prepared.request.purpose != purpose
            || prepared.request.owner_namespace != self.namespace
            || transaction.id() != &prepared.admission_transaction_id
            || transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
                .ne([prepared.record()])
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)),
            PreflightScope {
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(std::slice::from_ref(transaction)),
        })
    }

    /// Atomically commits owner admission and its exact capacity reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the preflight is stale, admission differs, or the
    /// durable append cannot preserve every outstanding reservation.
    pub fn commit_global_capacity_reservation_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if preflight.transaction_digest
            != authority_preflight_digest(std::slice::from_ref(transaction))
            || prepared.request.purpose != purpose
            || prepared.request.owner_namespace != self.namespace
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal
            .commit_global_capacity_reservation_v1(prepared, transaction)
    }

    /// Recovers one exact owner-bound capacity settlement authority after replay.
    ///
    /// # Errors
    ///
    /// Returns an error unless the retained reservation is canonical and owned
    /// by this exact protected namespace.
    pub fn recover_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let reservation = self
            .journal
            .recover_global_capacity_reservation_v1(reservation_id)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(reservation)
    }

    /// Looks up one exact owner-bound capacity reservation after replay.
    ///
    /// `Ok(None)` is an authenticated absence. Malformed records, replay
    /// provenance failures, and authority failures remain errors and must not
    /// be interpreted as absence.
    ///
    /// # Errors
    ///
    /// Returns an error unless the purpose authority and every retained
    /// namespace-46 record involved in the lookup remain valid.
    pub fn lookup_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<Option<GlobalCapacityReservationV1>, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let reservation = self
            .journal
            .lookup_global_capacity_reservation_v1(reservation_id)?;
        let Some(reservation) = reservation else {
            return Ok(None);
        };
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(Some(reservation))
    }

    /// Validates the complete retained reservation set for this purpose owner.
    ///
    /// This closes cold replay over namespace 46 without exposing reservation
    /// values as caller-mintable authority. Every retained record is decoded
    /// and provenance-checked before its identity is compared with `expected`.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, foreign, duplicated, missing, or orphan
    /// reservations, or when protected journal currentness is unavailable.
    pub fn validate_global_capacity_reservation_set_v1(
        &self,
        expected: &BTreeSet<[u8; 32]>,
    ) -> Result<(), JournalError> {
        let purpose = self.validate_capacity_authority()?;
        capacity_reservation::require_legacy_reservations(self.journal.native.state())?;
        let mut retained = BTreeSet::new();
        for (key, value) in self
            .journal
            .records(RecordNamespace::GlobalCapacityReservation)
        {
            let (request, _admission_transaction, reservation_id) =
                capacity_reservation::decode_reservation(value)?;
            if key
                != capacity_reservation::reservation_key(reservation_id).as_slice()
                || request.purpose != purpose
                || request.owner_namespace != self.namespace
                || !retained.insert(reservation_id)
            {
                return Err(JournalError::MalformedRecord(
                    "capacity reservation set is not canonical",
                ));
            }
        }
        if &retained != expected {
            return Err(JournalError::MalformedRecord(
                "capacity reservation set differs from protected owners",
            ));
        }
        Ok(())
    }

    /// Recovers one reservation from its stable binding and protected record.
    ///
    /// The caller does not supply the original owner digest or admission
    /// transaction ID. Both are decoded from the canonical namespace-46 record
    /// and authenticated by replay provenance before the complete stable
    /// binding is compared.
    ///
    /// # Errors
    ///
    /// Returns an error unless the reservation is current, canonical, owned by
    /// this purpose guard, and exactly matches every supplied stable field.
    pub fn recover_global_capacity_reservation_by_binding_v1(
        &self,
        reservation_id: [u8; 32],
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if binding.purpose != purpose {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let reservation = self
            .journal
            .recover_global_capacity_reservation_v1(reservation_id)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
            || !reservation.matches_recovery_binding(binding)
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(reservation)
    }

    /// Recovers the unique reservation matching a complete stable binding.
    ///
    /// Namespace-46 enumeration remains inside this sealed purpose guard. Every
    /// record is canonically decoded and replay-provenanced; zero or multiple
    /// stable matches fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for a foreign purpose, malformed retained record, or
    /// when the binding has anything other than one exact current match.
    pub fn recover_unique_global_capacity_reservation_v1(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        if binding.purpose != purpose {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let reservation = self
            .journal
            .recover_unique_global_capacity_reservation_v1(binding)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(reservation)
    }

    /// Preflights an exact terminal or poison transaction against held capacity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the reservation is current, its sole deletion is
    /// present, all other records belong to the owner, and one retained branch fits.
    pub fn preflight_reserved_terminal_v1(
        &self,
        reservation: &GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        capacity_reservation::validate_settlement_shape(self.journal, reservation, transaction)?;
        self.journal.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)),
            PreflightScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        Ok(ProtectedJournalPreflight {
            snapshot: self.current_snapshot(),
            transaction_digest: authority_preflight_digest(std::slice::from_ref(transaction)),
        })
    }

    /// Commits one preflighted terminal branch and consumes its reservation.
    ///
    /// # Errors
    ///
    /// Returns an error for stale preflight, altered records, foreign ownership,
    /// exceeded retained branch bounds, or an ambiguous durable append.
    pub fn commit_reserved_terminal_v1(
        &mut self,
        preflight: &ProtectedJournalPreflight,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        let purpose = self.validate_capacity_transaction_namespaces(transaction)?;
        self.validate_snapshot(&preflight.snapshot)?;
        if reservation.request.purpose != purpose
            || reservation.request.owner_namespace != self.namespace
            || preflight.transaction_digest
                != authority_preflight_digest(std::slice::from_ref(transaction))
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        self.journal
            .settle_global_capacity_reservation_v1(reservation, transaction)
    }

    fn validate_capacity_transaction_namespaces(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<GlobalCapacityReservationPurposeV1, JournalError> {
        let purpose = self.validate_capacity_authority()?;
        let mut publisher_authority = false;
        let mut authority_publication = false;
        let mut effect = false;
        let mut desired_state = false;
        let mut source_provider_authority = false;
        let mut consumer_resource = false;
        let mut capacity_record = false;
        for record in transaction.records() {
            if !purpose.permits(record.namespace()) {
                return Err(JournalError::ForeignAuthorityNamespace);
            }
            match record.namespace() {
                RecordNamespace::PublisherAuthority => publisher_authority = true,
                RecordNamespace::AuthorityPublication => authority_publication = true,
                RecordNamespace::Effect => effect = true,
                RecordNamespace::DesiredState => desired_state = true,
                RecordNamespace::SourceProviderAuthority => source_provider_authority = true,
                RecordNamespace::ControllerConsumerReadAttempt => consumer_resource = true,
                RecordNamespace::GlobalCapacityReservation => capacity_record = true,
                _ => return Err(JournalError::ForeignAuthorityNamespace),
            }
        }
        let closed_shape = match purpose {
            GlobalCapacityReservationPurposeV1::PublisherCompletion => {
                publisher_authority && authority_publication
            }
            GlobalCapacityReservationPurposeV1::RuntimeExecution => effect,
            GlobalCapacityReservationPurposeV1::RootProjectAdmission => desired_state,
            GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal => {
                source_provider_authority
            }
            GlobalCapacityReservationPurposeV1::ControllerProjectAdmission => effect,
            GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor => desired_state,
            GlobalCapacityReservationPurposeV1::ControllerConsumerResource => consumer_resource,
            GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor
            | GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck
            | GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => {
                return Err(JournalError::ProtectedBoundary);
            }
        };
        if !closed_shape || !capacity_record {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(purpose)
    }

    fn validate_capacity_authority(
        &self,
    ) -> Result<GlobalCapacityReservationPurposeV1, JournalError> {
        self.journal.ensure_protected_authority()?;
        let ProtectedAuthorityScope::CapacityReservation(purpose) = self.scope else {
            return Err(JournalError::ForeignAuthorityNamespace);
        };
        if purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        if self.namespace != purpose.owner_namespace() {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(purpose)
    }

    fn current_snapshot(&self) -> ProtectedJournalSnapshot {
        ProtectedJournalSnapshot {
            instance: Arc::clone(&self.journal.authority_instance),
            namespace: self.namespace,
            sequence: self.journal.snapshot_sequence(),
            scope: self.scope,
        }
    }

    fn validate_snapshot(&self, snapshot: &ProtectedJournalSnapshot) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.journal.authority_instance, &snapshot.instance)
            || snapshot.namespace != self.namespace
            || snapshot.sequence != self.journal.snapshot_sequence()
            || snapshot.scope != self.scope
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }

        Ok(())
    }

    fn validate_transaction_namespaces(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        for transaction in transactions {
            self.validate_transaction_namespace(transaction)?;
        }

        Ok(())
    }

    fn validate_transaction_namespace(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() != self.namespace)
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        Ok(())
    }

    fn validate_generic_authority_read(&self) -> Result<(), JournalError> {
        if matches!(self.scope, ProtectedAuthorityScope::CapacityReservation(purpose)
            if purpose.is_first_source_successor())
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        if self.namespace == RecordNamespace::MountManagerStartupAuthority
            || self.scope == ProtectedAuthorityScope::MountManagerStartup
            || self.scope
                == ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::PublisherCompletion,
                )
            || self.scope
                == ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::RootProjectAdmission,
                )
            || self.scope
                == ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
                )
            || self.scope
                == ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
                )
            || self.scope
                == ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
                )
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }

    fn validate_generic_authority_mutation(&self) -> Result<(), JournalError> {
        self.validate_generic_authority_read()?;
        if !matches!(
            self.scope,
            ProtectedAuthorityScope::SingleNamespace
                | ProtectedAuthorityScope::FixedMountSourceAcquisition
                | ProtectedAuthorityScope::CapacityReservation(
                    GlobalCapacityReservationPurposeV1::RuntimeExecution
                        | GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
                )
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }
}

fn authority_preflight_digest(transactions: &[JournalTransaction]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_PREFLIGHT_DOMAIN);
    digest.update(transactions.len().to_be_bytes());

    for transaction in transactions {
        digest.update(transaction.id());
        digest.update(transaction.records().len().to_be_bytes());

        for record in transaction.records() {
            digest.update([record.namespace() as u8]);
            digest.update(record.key().len().to_be_bytes());
            digest.update(record.key());

            match record.value() {
                Some(value) => {
                    digest.update([1]);
                    digest.update(value.len().to_be_bytes());
                    digest.update(value);
                }
                None => digest.update([0]),
            }
        }
    }

    digest.finalize().into()
}

struct ReplayState {
    durable_end: u64,
    next_sequence: u64,
    committed_transactions: usize,
    committed_records: usize,
    transaction_ids: BTreeSet<[u8; 16]>,
    committed_namespaces: BTreeSet<RecordNamespace>,
    state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    materialized_bytes: usize,
    idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
    source_challenge_history: Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
    source_original_replay: source_original_native::replay::SourceOriginalReplayCacheV5,
    source_history_compacted: bool,
    #[cfg(target_os = "linux")]
    q04_lower_history_present: bool,
}

// Only Journal-owned partial originals live here. Transitive validators keep
// their existing private temporaries; this is not a complete allocator bound.
struct ReadOnlyReplayScratchV1 {
    offset: u64,
    durable_end: u64,
    expected_sequence: u64,
    durable_next_sequence: u64,
    committed_transactions: usize,
    committed_records: usize,
    materialized_bytes: usize,
    source_challenge_history_bytes: u64,
    transaction_ids: BTreeSet<[u8; 16]>,
    committed_namespaces: BTreeSet<RecordNamespace>,
    state: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    idempotency: BTreeMap<Vec<u8>, IdempotencyDecision>,
    pending: Option<PendingTransaction>,
    reached_pending: Option<PendingTransaction>,
    reached_transaction: Option<JournalTransaction>,
    reached_frame: Option<Frame>,
    partial_frame: Option<ReadOnlyFrameScratchV1>,
    prospective: Option<BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>>,
    compaction_last_key: Option<(RecordNamespace, Vec<u8>)>,
    source_challenge_history: Vec<source_original_native::SourceOriginalChallengeCheckpointV5>,
    source_original_replay: source_original_native::replay::SourceOriginalReplayCacheV5,
}

fn replay_read_only_retained(
    file: &mut File,
    limits: JournalLimits,
    scratch: &mut Option<ReadOnlyReplayScratchV1>,
) -> Result<ReplayState, JournalError> {
    replay_original_retained(
        file, limits, None,
        #[cfg(target_os = "linux")]
        None,
        Some(scratch),
    )
}

// Shared logical representation arithmetic only. The original Release caller
// still prices its already-owned indexes before this independent replay work.
#[cfg(target_os = "linux")]
struct NativeReleaseReplayWorkV1 {
    replay_indexes: usize,
    pending_records: usize,
    frame_payload: usize,
}

#[cfg(target_os = "linux")]
fn native_release_replay_work_v1(
    physical: usize,
    limits: JournalLimits,
) -> Result<NativeReleaseReplayWorkV1, JournalError> {
    let limit = || JournalError::LimitExceeded("original Release replay copy");
    let historical_frames = physical / HEADER_BYTES;
    let historical_rows = historical_frames.min(limits.maximum_materialized_records);
    let historical_transactions = historical_frames.min(limits.maximum_transactions);
    let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
    let idempotency_entry = std::mem::size_of::<(Vec<u8>, IdempotencyDecision)>();

    // Two native maps cover the replay and its prospective materialization;
    // the third payload allowance covers idempotency and pending records.
    let replay_indexes = physical.checked_mul(3)
        .and_then(|bytes| bytes.checked_add(historical_rows.checked_mul(map_entry)?.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(historical_rows.checked_mul(idempotency_entry)?))
        .and_then(|bytes| bytes.checked_add(historical_transactions.checked_mul(16)?))
        .and_then(|bytes| bytes.checked_add(
            historical_frames.checked_mul(std::mem::size_of::<RecordNamespace>())?,
        ))
        .ok_or_else(limit)?;
    let pending_records = historical_frames.min(limits.maximum_records_per_transaction)
        .checked_mul(std::mem::size_of::<JournalRecord>()).ok_or_else(limit)?;
    let frame_payload = limits.maximum_record_bytes.checked_add(7)
        .ok_or_else(limit)?.min(physical);

    Ok(NativeReleaseReplayWorkV1 { replay_indexes, pending_records, frame_payload })
}

// The private union descriptor has these fields. Preserve the existing four
// alignment allowances instead of exposing or duplicating that private type.
#[cfg(target_os = "linux")]
fn source_release_historical_descriptor_bytes_v1() -> Result<usize, JournalError> {
    use source_original_native::SourceOriginalAdmissionDataV5;
    use aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceRetirementComparisonV5;

    std::mem::size_of::<[u8; 16]>()
        .checked_add(std::mem::size_of::<bool>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<aos_sandbox_core::ObjectDigest>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::sync::Arc<OriginalSourceRetirementComparisonV5>>()))
        .and_then(|bytes| bytes.checked_add(
            4 * std::mem::align_of::<SourceOriginalAdmissionDataV5>(),
        ))
        .ok_or(JournalError::LimitExceeded("Source original Release replay copy"))
}

#[cfg(target_os = "linux")]
fn is_q04_lower_history_record_v1(record: &JournalRecord) -> bool {
    use crate::policy_compiler::create_q04::{CACHE_PENDING_KEY, CONTROLLER_IDENTITY_KEY, SOURCE_PENDING_KEY};

    (record.namespace() == RecordNamespace::SourceDomainPolicyHold && record.key() == SOURCE_PENDING_KEY)
        || (record.namespace() == RecordNamespace::DesiredState && record.key() == CACHE_PENDING_KEY)
        || (record.namespace() == RecordNamespace::ControllerPolicyHold && record.key() == CONTROLLER_IDENTITY_KEY)
        || (record.namespace() == RecordNamespace::DesiredState && record.key().starts_with(b"\0aos-q04-root-"))
}

fn replay(file: &mut File, limits: JournalLimits) -> Result<ReplayState, JournalError> {
    replay_with_source_original(file, limits, None)
}

fn replay_with_source_original(
    file: &mut File,
    limits: JournalLimits,
    challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
) -> Result<ReplayState, JournalError> {
    #[cfg(target_os = "linux")]
    {
        replay_original_observed(file, limits, challenges, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        replay_original_observed(file, limits, challenges)
    }
}

#[cfg(target_os = "linux")]
fn replay_observed<R: Read + Seek + Borrow<File>>(
    file: &mut R,
    limits: JournalLimits,
    deployment_history: Option<&mut runtime_deployment_history::HistoryAuditV1<'_>>,
) -> Result<ReplayState, JournalError> {
    replay_original_observed(
        file, limits, None, deployment_history.map(DeploymentHistoryObserverV1::Main),
    )
}

#[cfg(target_os = "linux")]
fn replay_sidecar_observed<R: Read + Seek + Borrow<File>>(
    file: &mut R,
    limits: JournalLimits,
    history: &mut runtime_deployment_sidecar_history::SidecarHistoryAuditV1,
) -> Result<ReplayState, JournalError> {
    replay_original_observed(file, limits, None, Some(DeploymentHistoryObserverV1::Sidecar(history)))
}

/// Selects closed original-history observers, never caller callbacks.
#[cfg(target_os = "linux")]
enum DeploymentHistoryObserverV1<'observer, 'data> {
    GitCoverage(&'observer mut git_coverage_history::NativePrefixObserverV1<'data>),
    Main(&'observer mut runtime_deployment_history::HistoryAuditV1<'data>),
    Sidecar(&'observer mut runtime_deployment_sidecar_history::SidecarHistoryAuditV1),
    Storage(&'observer mut storage_native_issuance_history::StorageHistoryObserverV1),
    NixOffline(&'observer mut nix_offline_provisioning::NativeHistoryV5),
    Q04(&'observer mut Q04NativeRecipeAuditV1<'data>),
    Delete(&'observer mut delete_batch::NativeObserverV1),
    OriginalRelease(&'observer mut OriginalReleaseControllerNativeHistoryV1),
    OriginalReleaseSource {
        history: &'observer mut OriginalReleaseControllerNativeHistoryV1,
        remaining: usize,
    },
}

#[cfg(target_os = "linux")]
impl DeploymentHistoryObserverV1<'_, '_> {
    fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
        native_digest: &[u8],
    ) -> Result<(), JournalError> {
        match self {
            Self::GitCoverage(history) => history.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
            Self::Main(history) => history.observe(transaction, begin_sequence, commit_sequence),
            Self::Sidecar(history) => history.observe(transaction, begin_sequence, commit_sequence),
            Self::Storage(history) => history.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
            Self::Q04(history) => history.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
            Self::NixOffline(history) => history.observe(
                transaction, begin_sequence, begin_offset, end_offset,
            ),
            Self::Delete(history) => history.observe(
                transaction, commit_sequence, end_offset, native_digest,
            ),
            Self::OriginalRelease(history) => history.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
                native_digest,
            ),
            Self::OriginalReleaseSource { history, remaining } => {
                // The real held Journal supplies this count. The check precedes
                // Source cache retention in the same validated COMMIT parser.
                if *remaining == 0 {
                    return Err(JournalError::LimitExceeded("Source original Release native transactions"));
                }
                if history.next_sequence.is_none() {
                    // The same parser also validates any initial compacted
                    // prefix before returning. Root's sequence1 rule is literal.
                    history.next_sequence = Some(begin_sequence);
                    history.durable_end = begin_offset;
                }
                history.observe(
                    transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
                    native_digest,
                )?;
                *remaining -= 1;
                Ok(())
            }
        }
    }
}

/// Observes only validated native COMMITs of the actual selected writer.
///
/// The last native hash is not a materialized-history digest. No caller supplies
/// it, and this observer does not admit cleanup or grant a write.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct OriginalReleaseControllerNativeHistoryV1 {
    next_sequence: Option<u64>,
    durable_end: u64,
    head: Option<[u8; 32]>,
}

#[cfg(target_os = "linux")]
impl OriginalReleaseControllerNativeHistoryV1 {
    fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
        native_digest: &[u8],
    ) -> Result<(), JournalError> {
        let next = commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?;
        let frames = u64::try_from(transaction.records().len())
            .map_err(|_| JournalError::LimitExceeded("original Release native frames"))?
            .checked_add(2).ok_or(JournalError::SequenceExhausted)?;
        if begin_sequence != self.next_sequence.unwrap_or(1)
            || next.checked_sub(begin_sequence) != Some(frames)
            || begin_offset != self.durable_end
            || end_offset.checked_sub(begin_offset)
                != Some(encoded_transaction_append_bytes(transaction)?)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let head = native_digest.try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.next_sequence = Some(next);
        self.durable_end = end_offset;
        self.head = Some(head);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum OriginalReleaseControllerCutFailureV1 {
    Protection,
    CopyBound,
    Native,
    Comparison,
    NamedPost,
}

/// Selects fixed original owners inside the same native replay engine.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum OriginalReleaseNativeCutPurposeV1 {
    Controller,
    Root,
    Source,
}

/// Retains whole native readback DATA and each independent named bookend.
///
/// This has no public constructor, field, writer or cut getter. Its closed
/// consumers are the captured Controller Release request and the same Root
/// phase-7 readback; neither consumer obtains current cleanup authority.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalReleaseControllerCutCaptureV1 {
    purpose: OriginalReleaseNativeCutPurposeV1,
    protection: Option<Result<ProtectedWriterNameWitness, JournalError>>,
    copy_bound: Option<Result<(), JournalError>>,
    native: Option<Result<ReplayState, JournalError>>,
    comparison: Option<Result<(), JournalError>>,
    named_post: Option<Result<(), JournalError>>,
    history: OriginalReleaseControllerNativeHistoryV1,
    first: Option<OriginalReleaseControllerCutFailureV1>,
    error_transferred: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum OriginalReleaseSourceCutFailureV1 {
    Readback,
    Native,
    ChallengePost,
}

/// Retains Source's same-readback validation, native replay and challenge post.
///
/// No field or constructor escapes Journal. This is physical observation DATA,
/// not current cleanup admission, census membership or paid capacity.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalReleaseSourceCutCaptureV1 {
    readback: Option<Result<(), JournalError>>,
    native: OriginalReleaseControllerCutCaptureV1,
    challenge_post: Option<Result<(), JournalError>>,
    first: Option<OriginalReleaseSourceCutFailureV1>,
    error_transferred: bool,
}

#[cfg(target_os = "linux")]
impl OriginalReleaseSourceCutCaptureV1 {
    fn postcheck_debt(&self) -> Option<&JournalError> {
        self.native.named_post.as_ref().and_then(|returned| returned.as_ref().err())
            .or_else(|| self.challenge_post.as_ref().and_then(|returned| returned.as_ref().err()))
    }

    fn transfer_first_error(&mut self) -> Option<JournalError> {
        if self.error_transferred {
            return None;
        }
        let error = match self.first? {
            OriginalReleaseSourceCutFailureV1::Readback
                if matches!(self.readback, Some(Err(_))) =>
            {
                self.readback.take().and_then(Result::err)
            }
            OriginalReleaseSourceCutFailureV1::Native => self.native.transfer_first_error(),
            OriginalReleaseSourceCutFailureV1::ChallengePost
                if matches!(self.challenge_post, Some(Err(_))) =>
            {
                self.challenge_post.take().and_then(Result::err)
            }
            _ => None,
        };
        self.error_transferred = error.is_some();
        error
    }
}

#[cfg(target_os = "linux")]
impl OriginalReleaseControllerCutCaptureV1 {
    // Move only a proven parked first Err into the containing selected action
    // Result. The attempted cut, site, native Ok and all other debt stay here;
    // a vacated Err slot neither makes this reusable nor enables a write.
    pub(crate) fn transfer_first_error(&mut self) -> Option<JournalError> {
        if self.error_transferred {
            return None;
        }
        let site = self.first?;
        let error = match site {
            OriginalReleaseControllerCutFailureV1::Protection
                if matches!(self.protection, Some(Err(_))) =>
            {
                self.protection.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::CopyBound
                if matches!(self.copy_bound, Some(Err(_))) =>
            {
                self.copy_bound.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::Native
                if matches!(self.native, Some(Err(_))) =>
            {
                self.native.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::Comparison
                if matches!(self.comparison, Some(Err(_))) =>
            {
                self.comparison.take().and_then(Result::err)
            }
            OriginalReleaseControllerCutFailureV1::NamedPost
                if matches!(self.named_post, Some(Err(_))) =>
            {
                self.named_post.take().and_then(Result::err)
            }
            _ => None,
        };
        self.error_transferred = error.is_some();
        error
    }

    pub(crate) fn recheck(&self, journal: &Journal) -> Result<(), JournalError> {
        if self.first.is_some() || self.error_transferred {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let witness = self.protection.as_ref().and_then(|returned| returned.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let replayed = self.native.as_ref().and_then(|returned| returned.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        journal.require_original_release_cut_location_v1(self.purpose)?;
        journal.require_original_release_controller_replay_v1(
            replayed,
            &self.history,
            witness.file().byte_len(),
        )?;
        journal.validate_protected_writer_name_witness(witness)
    }

    // Only the opaque Root readback invokes this unit-copy method after its
    // own full graph/snapshot comparison. No scalar head is accepted as input.
    fn copy_root_native_cut_into_v1(
        &self,
        journal: &Journal,
        destination: &mut [u8; 40],
    ) -> Result<(), JournalError> {
        if !matches!(self.purpose, OriginalReleaseNativeCutPurposeV1::Root) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.recheck(journal)?;
        let head = self.history.head.ok_or(JournalError::ProtectedBoundary)?;
        let next = self.history.next_sequence.ok_or(JournalError::ProtectedBoundary)?;
        destination[..32].copy_from_slice(&head);
        destination[32..].copy_from_slice(&next.to_be_bytes());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn capture_original_release_controller_cut_v1(
        &self,
    ) -> OriginalReleaseControllerCutCaptureV1 {
        self.capture_original_release_native_cut_v1(OriginalReleaseNativeCutPurposeV1::Controller)
    }

    fn capture_original_release_root_cut_v1(&self) -> OriginalReleaseControllerCutCaptureV1 {
        self.capture_original_release_native_cut_v1(OriginalReleaseNativeCutPurposeV1::Root)
    }

    fn require_original_release_cut_location_v1(
        &self,
        purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        match purpose {
            OriginalReleaseNativeCutPurposeV1::Controller => self.require_protected_named_location(
                Path::new("/var/lib/aos/sandboxd"), "controller.journal",
                self.protected_owner_uid()?,
                crate::controller_service::journal::production_journal_limits(),
            ),
            OriginalReleaseNativeCutPurposeV1::Root => self.require_protected_named_location(
                Path::new("/var/lib/aos/sandbox-mount"), "mount.journal", 0, self.native.limits(),
            ),
            OriginalReleaseNativeCutPurposeV1::Source => source_original_native::writer::require_fixed(self),
        }
    }

    fn capture_original_release_native_cut_v1(
        &self,
        purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> OriginalReleaseControllerCutCaptureV1 {
        let mut captured = OriginalReleaseControllerCutCaptureV1 {
            purpose,
            protection: None,
            copy_bound: None,
            native: None,
            comparison: None,
            named_post: None,
            history: OriginalReleaseControllerNativeHistoryV1::default(),
            first: None,
            error_transferred: false,
        };
        captured.protection = Some((|| {
            self.require_original_release_cut_location_v1(purpose)?;
            self.protected_writer_name_witness()
        })());
        if matches!(captured.protection, Some(Err(_))) {
            captured.first = Some(OriginalReleaseControllerCutFailureV1::Protection);
        }

        // The original and returned indexes, decoded record containers and
        // bounded parser payload coexist. Price their logical storage before
        // replay; allocator nodes and nested validator work remain separate
        // funding obligations, not implied by this native headroom check.
        captured.copy_bound = Some((|| {
            let witness = captured
                .protection
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes =
                self.original_release_controller_replay_copy_bytes_v1(witness.file().byte_len())?;
            if bytes > self.native.limits().maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded("original Release replay copy"));
            }
            Ok(())
        })());
        if matches!(captured.copy_bound, Some(Err(_))) {
            captured.first.get_or_insert(OriginalReleaseControllerCutFailureV1::CopyBound);
        }

        self.observe_original_release_native_cut_v1(&mut captured, None, None);
        captured
    }

    // Both routes use this exact ReadAt/parser/result-parking sequence. The
    // Source route supplies its real held challenge view, never another witness.
    fn observe_original_release_native_cut_v1(
        &self,
        captured: &mut OriginalReleaseControllerCutCaptureV1,
        challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
        readback: Option<&Result<(), JournalError>>,
    ) {
        if captured.first.is_none() && readback.is_none_or(Result::is_ok) {
            if let Some(Ok(witness)) = captured.protection.as_ref() {
                let mut reader = runtime_deployment_history::ReadAtCursorV1::new(
                    self.native.file(),
                    witness.file().byte_len(),
                );
                // The original native Result is parked before projecting its
                // full-map comparison, including partial-replay failure.
                let observer = match challenges {
                    Some(_) => DeploymentHistoryObserverV1::OriginalReleaseSource {
                        history: &mut captured.history,
                        remaining: self.native.committed_transactions(),
                    },
                    None => DeploymentHistoryObserverV1::OriginalRelease(&mut captured.history),
                };
                captured.native = Some(replay_original_observed(
                    &mut reader, self.native.limits(), challenges,
                    Some(observer),
                ));
                if matches!(captured.native, Some(Err(_))) {
                    captured.first = Some(OriginalReleaseControllerCutFailureV1::Native);
                }
                if let Some(Ok(replayed)) = captured.native.as_ref() {
                    captured.comparison = Some(match challenges {
                        Some(challenges) => self.require_original_release_source_replay_v1(
                            replayed,
                            &captured.history,
                            witness.file().byte_len(),
                            challenges,
                        ),
                        None => self.require_original_release_controller_replay_v1(
                            replayed,
                            &captured.history,
                            witness.file().byte_len(),
                        ),
                    });
                    if matches!(captured.comparison, Some(Err(_))) {
                        captured.first.get_or_insert(OriginalReleaseControllerCutFailureV1::Comparison);
                    }
                }
            }
        }

        // The same original names are observed even after native/copy failure.
        // No append descriptor seek, reopen, duplicate, recovery or new parser.
        if let Some(Ok(witness)) = captured.protection.as_ref() {
            captured.named_post = Some(self.validate_protected_writer_name_witness(witness));
            if matches!(captured.named_post, Some(Err(_))) {
                captured.first.get_or_insert(OriginalReleaseControllerCutFailureV1::NamedPost);
            }
        }
    }

    fn observe_original_release_source_cut_into_v1(
        &self,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
        readback: Result<(), JournalError>,
        destination: &mut Option<OriginalReleaseSourceCutCaptureV1>,
    ) -> Result<(), JournalError> {
        if destination.is_some() {
            std::process::abort();
        }
        let captured = OriginalReleaseControllerCutCaptureV1 {
            purpose: OriginalReleaseNativeCutPurposeV1::Source,
            protection: None,
            copy_bound: None,
            native: None,
            comparison: None,
            named_post: None,
            history: OriginalReleaseControllerNativeHistoryV1::default(),
            first: None,
            error_transferred: false,
        };
        *destination = Some(OriginalReleaseSourceCutCaptureV1 {
            readback: Some(readback),
            native: captured,
            challenge_post: None,
            first: None,
            error_transferred: false,
        });
        let Some(source) = destination.as_mut() else {
            std::process::abort();
        };
        if matches!(source.readback, Some(Err(_))) {
            source.first = Some(OriginalReleaseSourceCutFailureV1::Readback);
        }
        let captured = &mut source.native;
        captured.protection = Some((|| {
            self.require_original_release_cut_location_v1(captured.purpose)?;
            self.source_original_replay.validate_challenges(challenges)?;
            self.protected_writer_name_witness()
        })());
        if matches!(captured.protection, Some(Err(_))) {
            captured.first.get_or_insert(OriginalReleaseControllerCutFailureV1::Protection);
        }

        captured.copy_bound = Some((|| {
            let witness = captured.protection.as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let bytes = self.original_release_source_replay_copy_bytes_v1(
                witness.file().byte_len(),
                challenges,
            )?;
            if bytes > self.native.limits().maximum_materialized_bytes {
                return Err(JournalError::LimitExceeded(
                    "Source original Release replay copy",
                ));
            }
            Ok(())
        })());
        if matches!(captured.copy_bound, Some(Err(_))) {
            captured.first.get_or_insert(OriginalReleaseControllerCutFailureV1::CopyBound);
        }

        self.observe_original_release_native_cut_v1(
            &mut source.native, Some(challenges), source.readback.as_ref(),
        );
        if source.native.named_post.is_none() {
            source.native.named_post = Some(self.require_original_release_cut_location_v1(
                OriginalReleaseNativeCutPurposeV1::Source,
            ));
            if matches!(source.native.named_post, Some(Err(_))) {
                source.native.first.get_or_insert(OriginalReleaseControllerCutFailureV1::NamedPost);
            }
        }
        if source.native.first.is_some() {
            source.first.get_or_insert(OriginalReleaseSourceCutFailureV1::Native);
        }
        source.challenge_post = Some(challenges.validate_current());
        if matches!(source.challenge_post, Some(Err(_))) {
            source.first.get_or_insert(OriginalReleaseSourceCutFailureV1::ChallengePost);
        }
        if source.first.is_some() {
            return match source.transfer_first_error() {
                Some(cause) => Err(cause),
                None => std::process::abort(),
            };
        }
        Ok(())
    }

    // The captured physical prefix bounds all historical payloads, including
    // rows larger than today's materialized map. It is not a second quota or
    // a claim that per-record ceilings fund the whole caller's owner graph.
    fn original_release_controller_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
    ) -> Result<usize, JournalError> {
        if !self.source_challenge_history.is_empty()
            || self.source_original_replay.has_dependencies()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.original_release_native_replay_copy_bytes_v1(physical_end)
    }

    fn original_release_native_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
    ) -> Result<usize, JournalError> {
        let limit = || JournalError::LimitExceeded("original Release replay copy");
        let physical = usize::try_from(physical_end).map_err(|_| limit())?;
        let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();
        let idempotency_entry = std::mem::size_of::<(Vec<u8>, IdempotencyDecision)>();

        let original_indexes = self.native.state().len().checked_mul(map_entry)
            .and_then(|bytes| bytes.checked_add(self.native.materialized_bytes()))
            .and_then(|bytes| bytes.checked_add(self.native.transaction_ids().len().checked_mul(16)?))
            .and_then(|bytes| bytes.checked_add(
                self.native.committed_namespaces().len().checked_mul(std::mem::size_of::<RecordNamespace>())?,
            ))
            .and_then(|bytes| bytes.checked_add(self.idempotency.len().checked_mul(idempotency_entry)?))
            .ok_or_else(limit)?;
        let original_indexes = self.idempotency.keys().try_fold(original_indexes, |bytes, key| {
            bytes.checked_add(key.len()).ok_or_else(limit)
        })?;

        let NativeReleaseReplayWorkV1 { replay_indexes, pending_records, frame_payload } =
            native_release_replay_work_v1(physical, self.native.limits())?;

        original_indexes.checked_add(replay_indexes)
            .and_then(|bytes| bytes.checked_add(pending_records))
            .and_then(|bytes| bytes.checked_add(frame_payload))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReplayState>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingTransaction>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>()))
            .ok_or_else(limit)
    }

    fn original_release_source_replay_copy_bytes_v1(
        &self,
        physical_end: u64,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<usize, JournalError> {
        use source_original_native::{SourceOriginalAdmissionDataV5, SourceOriginalPhysicalCutV5};

        let limit = || JournalError::LimitExceeded("Source original Release replay copy");
        let physical = usize::try_from(physical_end).map_err(|_| limit())?;
        // The fixed Source observer rejects an extra COMMIT before any Source
        // retention. Price actual original metadata, not a guessed count from
        // the serialized width of today's large carriers.
        let transactions = self.native.committed_transactions();
        if transactions == 0 || transactions > self.native.limits().maximum_transactions {
            return Err(JournalError::ProtectedBoundary);
        }
        let pairs = transactions.checked_mul(transactions).ok_or_else(limit)?;
        // A historical reference contains these four fields. Four maximum
        // alignment allowances conservatively cover its padding without
        // exposing that private representation outside its owning module.
        let historical_descriptor = source_release_historical_descriptor_bytes_v1()?;

        // Each physical transaction can retain two cut maps, one four-payload
        // Applying seed and one three-payload current retirement. Historical
        // retirements contribute at most one three-payload copy per origin pair.
        // This bounds the existing retained_bytes charge, not allocator RAM.
        let source_payload = transactions.checked_mul(9)
            .and_then(|linear| pairs.checked_mul(3).and_then(|square| linear.checked_add(square)))
            .and_then(|factor| physical.checked_mul(factor))
            .and_then(|bytes| bytes.checked_add(transactions.checked_mul(
                std::mem::size_of::<SourceOriginalAdmissionDataV5>()
                    .checked_add(std::mem::size_of::<SourceOriginalPhysicalCutV5>())?,
            )?))
            .and_then(|bytes| bytes.checked_add(pairs.checked_mul(2)?
                .checked_mul(historical_descriptor)?))
            .ok_or_else(limit)?.min(self.native.limits().maximum_materialized_bytes);
        let resident = self.source_original_replay.original_release_resident_copy_bytes_v1()?;
        let representation = std::mem::size_of::<Option<OriginalReleaseSourceCutCaptureV1>>()
            .checked_sub(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::cell::Cell<bool>>()))
            .ok_or_else(limit)?;
        // The live challenge Journal's original Vec and the cached Arc witness
        // coexist. Charge both payloads independently; borrowing does not
        // eliminate the original Vec's residence or its separate native owner.
        let challenge_resident = challenges.checkpoints()?.try_fold(0_usize, |bytes, row| {
            bytes.checked_add(std::mem::size_of::<source_original_native::SourceOriginalChallengeCheckpointV5>())
                .and_then(|bytes| bytes.checked_add(row.key().len()))
                .and_then(|bytes| bytes.checked_add(row.value().len()))
                .ok_or_else(limit)
        })?;

        // Retain the fresh independent cache AND guard an additional logical
        // comparison allowance. The shared parser's original limits stay
        // unchanged; nested allocator/validator peaks remain funding debt.
        self.original_release_native_replay_copy_bytes_v1(physical_end)?
            .checked_add(resident)
            .and_then(|bytes| bytes.checked_add(challenge_resident))
            .and_then(|bytes| bytes.checked_add(source_payload.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(physical.checked_mul(6)?))
            .and_then(|bytes| bytes.checked_add(representation))
            .ok_or_else(limit)
    }

    fn require_original_release_controller_replay_v1(
        &self,
        replayed: &ReplayState,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
    ) -> Result<(), JournalError> {
        self.require_original_release_native_replay_v1(
            replayed, history, physical_end, OriginalReleaseNativeCutPurposeV1::Controller,
        )
    }

    fn require_original_release_source_replay_v1(
        &self,
        replayed: &ReplayState,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
        challenges: &source_original_native::SourceOriginalChallengeHistoryViewV5<'_>,
    ) -> Result<(), JournalError> {
        self.require_original_release_native_replay_v1(
            replayed, history, physical_end, OriginalReleaseNativeCutPurposeV1::Source,
        )?;
        source_original_native::writer::require_original_release_source_replay_v1(
            self, replayed, challenges,
        )
    }

    fn require_original_release_native_replay_v1(
        &self,
        replayed: &ReplayState,
        history: &OriginalReleaseControllerNativeHistoryV1,
        physical_end: u64,
        purpose: OriginalReleaseNativeCutPurposeV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        if history.head.is_none_or(|head| head == [0; 32])
            || self.native.next_sequence() == 0 || self.native.next_sequence() == u64::MAX
            || history.durable_end != physical_end
            || history.next_sequence != Some(self.native.next_sequence())
            || replayed.durable_end != physical_end
            || replayed.next_sequence != self.native.next_sequence()
            || replayed.committed_transactions != self.native.committed_transactions()
            || replayed.transaction_ids != *self.native.transaction_ids()
            || replayed.committed_namespaces != *self.native.committed_namespaces()
            || replayed.state != *self.native.state()
            || replayed.materialized_bytes != self.native.materialized_bytes()
            || replayed.idempotency != self.idempotency
            || (!matches!(purpose, OriginalReleaseNativeCutPurposeV1::Source)
                && (!replayed.source_challenge_history.is_empty()
                    || !self.source_challenge_history.is_empty()
                    || replayed.source_original_replay.has_dependencies()
                    || self.source_original_replay.has_dependencies()))
            || replayed.source_history_compacted != self.source_history_compacted
            || replayed.q04_lower_history_present != self.q04_lower_history_present
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

// The closed history observers use the original parser and actual File.
// A private read-at cursor changes no append-description offset or identity.
fn replay_original_observed<R: Read + Seek + Borrow<File>>(
    file: &mut R,
    limits: JournalLimits,
    challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
    #[cfg(target_os = "linux")]
    deployment_history: Option<DeploymentHistoryObserverV1<'_, '_>>,
) -> Result<ReplayState, JournalError> {
    replay_original_retained(
        file, limits, challenges,
        #[cfg(target_os = "linux")]
        deployment_history,
        None,
    )
}

// The selected destination changes ownership on failure, never replay rules.
// Ordinary calls inline to the original loop and local disposal order.
fn replay_original_retained<R: Read + Seek + Borrow<File>>(
    file: &mut R,
    limits: JournalLimits,
    challenges: Option<&source_original_native::SourceOriginalChallengeHistoryViewV5<'_>>,
    #[cfg(target_os = "linux")]
    mut deployment_history: Option<DeploymentHistoryObserverV1<'_, '_>>,
    scratch: Option<&mut Option<ReadOnlyReplayScratchV1>>,
) -> Result<ReplayState, JournalError> {
    file.seek(SeekFrom::Start(0))?;
    let mut native = NativeReplayBookkeeping::new();
    let mut committed_namespaces = BTreeSet::new();
    #[cfg(target_os = "linux")]
    let mut q04_lower_history_present = false;
    let mut state = BTreeMap::new();
    let mut materialized_bytes = 0_usize;
    let mut idempotency = BTreeMap::new();
    let mut pending: Option<PendingTransaction> = None;
    let mut compaction_prefix = true;
    let mut compaction_index = 1_u64;
    let mut compaction_last_key = None;
    let mut materialized_compaction = false;
    let mut source_challenge_history = Vec::new();
    let mut source_challenge_history_bytes = 0;
    let mut source_original_replay =
        source_original_native::replay::SourceOriginalReplayCacheV5::default();
    let mut source_history_compacted = false;
    let mut reached_pending = None;
    let mut reached_transaction = None;
    let mut reached_frame = None;
    let mut partial_frame = None;
    let mut reached_prospective = None;
    let retained = scratch.is_some();
    let outcome: Result<(), JournalError> = (|| {
        let source_journal_identity =
            FileIdentity::of::<crate::journal::JournalError>(<R as Borrow<File>>::borrow(file))?;

        loop {
            let Some((frame, bytes_read)) = read_frame_retained(
                file, native.coordinates().offset, limits.maximum_record_bytes,
                retained.then_some(&mut partial_frame),
            )? else {
                break;
            };
            let frame_outcome: Result<(), JournalError> = (|| {
                native.observe_frame(&frame, bytes_read)?;
                let NativeReplayCoordinates {
                    offset, durable_end, expected_sequence, durable_next_sequence,
                    committed_transactions, ..
                } = native.coordinates();

                match frame.kind {
                    FrameKind::Begin => {
                        if pending.is_some() {
                            return Err(JournalError::MalformedTransaction("nested begin frame"));
                        }
                        let count = transaction::decode_begin_count(
                            &frame.payload, limits.maximum_records_per_transaction,
                        )?;
                        pending = Some(PendingTransaction {
                            records: Vec::with_capacity(count),
                            native: NativePendingTransaction::begin(&frame, count, offset, bytes_read)?,
                        });
                    }
                    FrameKind::Record => {
                        let transaction = pending.as_mut().ok_or(JournalError::MalformedTransaction(
                            "record outside transaction",
                        ))?;
                        transaction.native.observe_record(&frame, transaction.records.len())?;
                        transaction
                            .records
                            .push(decode_record(&frame.payload, limits)?);
                    }
                    FrameKind::Commit => {
                        reached_pending = pending.take();
                        let transaction = reached_pending.as_ref().ok_or(JournalError::MalformedTransaction(
                            "commit outside transaction",
                        ))?;
                        transaction.native.validate_commit(&frame, transaction.records.len())?;
                        let (begin_sequence, begin_offset) = transaction.native.begin_position();
                        reached_transaction = Some(JournalTransaction::from_unvalidated_data(
                            transaction.native.transaction_id(),
                            std::mem::take(&mut reached_pending.as_mut()
                                .ok_or(JournalError::ProtectedBoundary)?.records),
                        ));
                        let replay_transaction = reached_transaction.as_ref()
                            .ok_or(JournalError::ProtectedBoundary)?;
                        validate_transaction(&replay_transaction, limits)?;
                        delete_batch::validate(&state, &replay_transaction, begin_sequence, limits)?;

                        #[cfg(target_os = "linux")]
                        if let Some(history) = deployment_history.as_mut() {
                            history.observe(
                                &replay_transaction, begin_sequence, frame.sequence, begin_offset, offset,
                                &frame.payload[4..],
                            )?;
                        }

                        let mut query_edge = None;
                        let mut logical_replay = false;
                        let mut first_successor_replay = false;
                        let mut compaction_id = [0_u8; 16];
                        compaction_id[..8].copy_from_slice(&compaction_index.to_le_bytes());
                        compaction_id[8..].copy_from_slice(b"compact1");
                        if compaction_prefix && *replay_transaction.id() == compaction_id {
                            if delete_batch::has_dependencies(&state)
                                || delete_batch::selected(&replay_transaction)
                            {
                                return Err(JournalError::ProtectedBoundary);
                            }
                            // Private compaction emits a sorted, PUT-only initial copy.
                            // Its IDs alone never exempt an ordinary logical mutation.
                            for record in replay_transaction.records() {
                                let key = (record.namespace(), record.key().to_vec());
                                if record.value().is_none()
                                    || compaction_last_key
                                        .as_ref()
                                        .is_some_and(|last| *last >= key)
                                    || state.contains_key(&key)
                                {
                                    return Err(JournalError::MalformedTransaction(
                                        "invalid compaction snapshot",
                                    ));
                                }
                                compaction_last_key = Some(key);
                            }
                            compaction_index = compaction_index
                                .checked_add(1)
                                .ok_or(JournalError::SequenceExhausted)?;
                            materialized_compaction = true;
                            source_history_compacted = true;
                            source_original_replay.observe_compaction(
                                &root_original_inventory::materialize(&state, &replay_transaction),
                            );
                        } else {
                            if materialized_compaction {
                                source_tree_successor::validate_replayed_state(&state, true)?;
                                root_local_recovery::pending(&state)?;
                                root_original_native::pending(&state, limits)?;
                                root_original_inventory::validate_rejoined_capacity(
                                    &state, materialized_bytes, durable_end, committed_transactions,
                                    limits, durable_next_sequence,
                                )?;
                                materialized_compaction = false;
                            }
                            compaction_prefix = false;
                            logical_replay = true;
                            first_successor_replay = source_tree_successor::validate_replayed_transaction(
                                &state, &replay_transaction, limits,
                            )?;
                            let source_edge = source_original_replay.replay_transaction(
                                &state,
                                &replay_transaction,
                                challenges,
                                limits,
                                begin_sequence,
                                frame.sequence,
                                begin_offset,
                                offset,
                                committed_transactions.checked_add(1).ok_or(
                                    JournalError::LimitExceeded("committed transaction count"),
                                )?,
                                source_journal_identity.physical_pair(),
                            )?;
                            if !source_edge {
                                query_edge = root_original_inventory::replay_edge(
                                    &state, &replay_transaction, limits,
                                )?;
                                if query_edge.is_none()
                                    && !root_original_native::validate_replayed_transaction(
                                        &state, &replay_transaction, limits, expected_sequence,
                                    )?
                                {
                                    root_local_recovery::validate_replayed_transaction(
                                        &state,
                                        &replay_transaction,
                                    )?;
                                }
                                if query_edge.is_none() {
                                    root_original_inventory::preserve_other_owner(
                                        &state, &replay_transaction, limits,
                                    )?;
                                }
                            }
                            source_original_native::challenge::capture_checkpoint(
                                &mut source_challenge_history,
                                &mut source_challenge_history_bytes,
                                &replay_transaction,
                                begin_sequence,
                                frame.sequence,
                                begin_offset,
                                offset,
                                limits,
                            )?;
                        }
                        native.register_transaction(*replay_transaction.id())?;
                        validate_idempotency_changes(&idempotency, replay_transaction.records())?;
                        materialized_bytes = validate_materialized_change(
                            &state,
                            materialized_bytes,
                            replay_transaction.records(),
                            limits,
                        )?;
                        // Keep floor decoding at its original short-circuit
                        // position; acquire a full prospective copy only for
                        // the checks that actually consume it. Earlier errors
                        // no longer acquire or retain that unnecessary clone.
                        if logical_replay
                            && (query_edge.is_some()
                                || first_successor_replay
                                || root_original_inventory::has_query_floor(&state)?
                                || root_original_inventory::has_query_floor_after(&state, &replay_transaction)?)
                        {
                            reached_prospective = Some(root_original_inventory::materialize(&state, &replay_transaction));
                            let prospective = reached_prospective.as_ref()
                                .ok_or(JournalError::ProtectedBoundary)?;
                            // Exact owner/settlement validation already ran above.
                            // Empty-change accounting charges that exact post-state;
                            // no new settlement interpretation or authority follows.
                            validate_reserved_capacity(
                                &prospective,
                                materialized_bytes,
                                &[],
                                None,
                                offset,
                                committed_transactions.checked_add(1)
                                    .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                                limits,
                                None,
                            )?;
                            root_original_inventory::require_sequence_headroom(
                                &prospective, expected_sequence,
                            )?;
                            if first_successor_replay {
                                source_tree_successor::require_sequence_headroom(&prospective, expected_sequence)?;
                            }
                            reached_prospective = None;
                        }
                        for record in replay_transaction.records() {
                            committed_namespaces.insert(record.namespace());
                            #[cfg(target_os = "linux")]
                            {
                                q04_lower_history_present |= is_q04_lower_history_record_v1(record);
                            }
                            apply_record(&mut state, &mut idempotency, record)?;
                        }
                        native.finish_commit(
                            replay_transaction.records().len(), limits.maximum_transactions,
                        )?;
                        reached_transaction = None;
                        reached_pending = None;
                    }
                }
                Ok(())
            })();
            if let Err(error) = frame_outcome {
                if retained {
                    reached_frame = Some(frame);
                } else {
                    // Match the ordinary commit locals' disposal before its frame.
                    drop(reached_prospective.take());
                    drop(reached_transaction.take());
                    drop(reached_pending.take());
                }
                return Err(error);
            }
        }

        source_tree_successor::validate_replayed_state(&state, materialized_compaction)?;
        root_local_recovery::pending(&state)?;
        root_original_native::pending(&state, limits)?;
        let NativeReplayCoordinates {
            durable_end, durable_next_sequence, committed_transactions, ..
        } = native.coordinates();
        root_original_inventory::validate_rejoined_capacity(
            &state, materialized_bytes, durable_end, committed_transactions, limits,
            durable_next_sequence,
        )?;
        Ok(())
    })();
    let NativeReplayCoordinates {
        offset, durable_end, expected_sequence, durable_next_sequence,
        committed_transactions, committed_records,
    } = native.coordinates();
    if let Some(destination) = scratch {
        if outcome.is_err() || pending.is_some() || partial_frame.is_some() {
            let failed = outcome.is_err();
            *destination = Some(ReadOnlyReplayScratchV1 {
                offset, durable_end, expected_sequence, durable_next_sequence,
                committed_transactions, committed_records, materialized_bytes,
                source_challenge_history_bytes,
                transaction_ids: if failed { native.take_transaction_ids() } else { BTreeSet::new() },
                committed_namespaces: if failed { std::mem::take(&mut committed_namespaces) } else { BTreeSet::new() },
                state: if failed { std::mem::take(&mut state) } else { BTreeMap::new() },
                idempotency: if failed { std::mem::take(&mut idempotency) } else { BTreeMap::new() },
                pending,
                reached_pending,
                reached_transaction,
                reached_frame,
                partial_frame,
                prospective: reached_prospective,
                compaction_last_key,
                source_challenge_history: if failed {
                    std::mem::take(&mut source_challenge_history)
                } else {
                    Vec::new()
                },
                source_original_replay: if failed {
                    std::mem::take(&mut source_original_replay)
                } else {
                    Default::default()
                },
            });
        }
    }
    outcome?;
    Ok(ReplayState {
        durable_end,
        next_sequence: durable_next_sequence,
        committed_transactions,
        committed_records,
        transaction_ids: native.take_transaction_ids(),
        committed_namespaces,
        state,
        materialized_bytes,
        idempotency,
        source_challenge_history,
        source_original_replay,
        source_history_compacted,
        #[cfg(target_os = "linux")]
        q04_lower_history_present,
    })
}

// Closed lower clear-recipe DATA, not an append certificate. The actual
// owner later verifies full native membership at these original coordinates.
// SHA256(domain || owner:u8 || (BEu32 length || Cut680) ||
//   (BEu32 length || names48) || (BEu32 length || NEXT:BEu64) ||
//   (BEu32 length || concatenated SAME canonical BEGIN/DELETE/COMMIT frames)).
#[cfg(target_os = "linux")]
fn q04_lower_clear_native_digest_v1(
    identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    owner: crate::policy_compiler::create_q04::Q04TransactionOwnerV1,
    names: ProtectedJournalNamesV1,
    first_sequence: u64,
    transaction: &JournalTransaction,
) -> Result<ObjectDigest, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
    use crate::policy_compiler::create_q04::{
        CACHE_PENDING_KEY, CreateQ04ErrorV1, Q04TransactionOwnerV1, SOURCE_PENDING_KEY,
    };

    let (tag, namespace, key) = match owner {
        Q04TransactionOwnerV1::Source => (1, RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY),
        Q04TransactionOwnerV1::Cache => (2, RecordNamespace::DesiredState, CACHE_PENDING_KEY),
        _ => return Err(CreateQ04ErrorV1::ChangedCut),
    };
    if first_sequence == 0 || transaction.records().len() != 1
        || transaction.records()[0].namespace() != namespace
        || transaction.records()[0].key() != key
        || transaction.records()[0].value().is_some()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let frames = encode_transaction(transaction, first_sequence)?;
    let native_bytes = frames.iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.len()).ok_or(CreateQ04ErrorV1::Bounds)
    })?;
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.lower-clear-native-recipe.v1\0");
    digest.update([tag]);
    for value in [identity.bytes().as_slice(), names.to_bytes().as_slice(), first_sequence.to_be_bytes().as_slice()] {
        digest.update(u32::try_from(value.len()).map_err(|_| CreateQ04ErrorV1::Bounds)?.to_be_bytes());
        digest.update(value);
    }
    digest.update(u32::try_from(native_bytes).map_err(|_| CreateQ04ErrorV1::Bounds)?.to_be_bytes());
    for frame in frames {
        digest.update(frame);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

#[allow(clippy::too_many_arguments)]
fn validate_reserved_capacity(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    prospective_materialized_bytes: usize,
    records: &[JournalRecord],
    settling_reservation: Option<[u8; 32]>,
    prospective_journal_bytes: u64,
    prospective_transactions: usize,
    limits: JournalLimits,
    root_local_edge: Option<RootOwnerEdge>,
) -> Result<(), JournalError> {
    let mut reservations = capacity_reservation::accounting_reservations(state)?;
    for record in records {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        match record.value() {
            Some(value) => {
                let decoded = if root_local_edge.is_some() {
                    // Only a closed private local edge has passed whole-owner
                    // validation above. Generic and legacy callers stay strict.
                    capacity_reservation::accounting_reservation(record.key(), value)?
                } else {
                    capacity_reservation::decode_capacity_record(record.key(), value)?
                };
                if reservations
                    .insert(decoded.reservation_id, decoded)
                    .is_some()
                {
                    return Err(JournalError::DuplicateRecordKey);
                }
            }
            None => {
                let identifier = if matches!(root_local_edge, Some(RootOwnerEdge::SourceOriginal)) {
                    let value = state.get(&(record.namespace(), record.key().to_vec()))
                        .ok_or(JournalError::ProtectedBoundary)?;
                    capacity_reservation::accounting_reservation(record.key(), value)?
                        .reservation_id
                } else {
                    settling_reservation.ok_or(JournalError::ProtectedBoundary)?
                };
                if record.key()
                    != capacity_reservation::reservation_key(identifier).as_slice()
                    || reservations.remove(&identifier).is_none()
                {
                    return Err(JournalError::MalformedRecord(
                        "capacity settlement does not remove its exact reservation",
                    ));
                }
            }
        }
    }
    let (reserved_records, reserved_bytes, reserved_transactions) =
        reservations.values().try_fold(
            (0_usize, 0_u64, 0_usize),
            |(records, bytes, transactions), reservation| {
                Ok::<_, JournalError>((
                    records
                        .checked_add(reservation.maximum_records)
                        .ok_or(JournalError::LimitExceeded("reserved record count"))?,
                    bytes
                        .checked_add(reservation.maximum_bytes)
                        .ok_or(JournalError::JournalTooLarge)?,
                    transactions
                        .checked_add(reservation.maximum_transactions)
                        .ok_or(JournalError::LimitExceeded("reserved transaction count"))?,
                ))
            },
        )?;
    let projected_entries = projected_materialized_record_count(state, records)?;
    if prospective_materialized_bytes
        .checked_add(
            usize::try_from(reserved_bytes)
                .map_err(|_| JournalError::LimitExceeded("reserved materialized bytes"))?,
        )
        .is_none_or(|bytes| bytes > limits.maximum_materialized_bytes)
        || projected_entries
            .checked_add(reserved_records)
            .is_none_or(|count| count > limits.maximum_materialized_records)
        || prospective_journal_bytes
            .checked_add(reserved_bytes)
            .is_none_or(|bytes| bytes > limits.maximum_journal_bytes)
        || prospective_transactions
            .checked_add(reserved_transactions)
            .is_none_or(|count| count > limits.maximum_transactions)
    {
        return Err(JournalError::LimitExceeded(
            "outstanding global capacity reservations",
        ));
    }
    Ok(())
}

fn projected_materialized_record_count(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    records: &[JournalRecord],
) -> Result<usize, JournalError> {
    materialized::projected_record_count(state, records.iter().map(RecordMutationRef::from))
        .map_err(JournalError::from)
}

fn validate_limits(limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_journal::geometry::validate_native_bounds(limits.into())
        .map_err(JournalError::from)
}

fn validate_materialized_change(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    current_bytes: usize,
    records: &[JournalRecord],
    limits: JournalLimits,
) -> Result<usize, JournalError> {
    materialized::validate_change(
        state,
        current_bytes,
        records.iter().map(RecordMutationRef::from),
        limits.maximum_materialized_bytes,
        limits.maximum_materialized_records,
    )
    .map_err(JournalError::from)
}

fn validate_idempotency_changes(
    idempotency: &BTreeMap<Vec<u8>, IdempotencyDecision>,
    records: &[JournalRecord],
) -> Result<(), JournalError> {
    for record in records {
        if record.namespace() != RecordNamespace::Idempotency {
            continue;
        }
        let value = record.value().ok_or(JournalError::MalformedRecord(
            "idempotency records cannot be deleted",
        ))?;
        let request_digest = value[..32]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid idempotency digest"))?;
        let operation_bytes = value[32..]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid operation identity"))?;
        let proposed = IdempotencyDecision {
            request_digest,
            operation_id: OperationId::from_bytes(operation_bytes),
        };
        if idempotency
            .get(record.key())
            .is_some_and(|existing| existing != &proposed)
        {
            return Err(JournalError::IdempotencyConflict);
        }
    }
    Ok(())
}

/// Carries only one fixed selected sizing extent, never record bytes or a key.
struct OnlineNixExtentV1 {
    slot: usize,
    key_bytes: usize,
    value_bytes: Option<usize>,
}

impl OnlineNixExtentV1 {
    const fn put(slot: usize, key_bytes: usize, value_bytes: usize) -> Self {
        Self { slot, key_bytes, value_bytes: Some(value_bytes) }
    }

    const fn delete(slot: usize, key_bytes: usize) -> Self {
        Self { slot, key_bytes, value_bytes: None }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn q04_controller_before_rows_digest_v1(
    operation_id: OperationId,
    sandbox: [u8; 16],
    operation: &[u8],
    desired: &[u8],
    effect: &[u8],
) -> Result<ObjectDigest, JournalError> {
    use crate::controller_service::public_projection::{PublicProjectionKindV1, projection_key};

    let desired_key = projection_key(PublicProjectionKindV1::Sandbox, sandbox);
    let effect_key = aos_sandbox_protocol::domain_ledger::operation::effect_key(operation_id, 0);
    let rows: [(RecordNamespace, &[u8], &[u8]); 3] = [
        (RecordNamespace::Operation, operation_id.as_bytes(), operation),
        (RecordNamespace::DesiredState, &desired_key, desired),
        (RecordNamespace::Effect, &effect_key, effect),
    ];
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.create-q04.controller-before-rows.v1\0");
    for (namespace, key, value) in rows {
        if value.is_empty() || value.len() > 64 * 1024 {
            return Err(JournalError::ProtectedBoundary);
        }
        digest.update(encode_record_fields(namespace, key, Some(value))?);
    }
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

fn apply_record(
    state: &mut BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    idempotency: &mut BTreeMap<Vec<u8>, IdempotencyDecision>,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    materialized::apply_mutation(state, RecordMutationRef::from(record));

    apply_idempotency_record(idempotency, record)
}

fn apply_idempotency_record(
    idempotency: &mut BTreeMap<Vec<u8>, IdempotencyDecision>,
    record: &JournalRecord,
) -> Result<(), JournalError> {
    if record.namespace() == RecordNamespace::Idempotency {
        let value = record.value().ok_or(JournalError::MalformedRecord(
            "idempotency records cannot be deleted",
        ))?;
        let request_digest = value[..32]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid idempotency digest"))?;
        let operation_bytes = value[32..]
            .try_into()
            .map_err(|_| JournalError::MalformedRecord("invalid operation identity"))?;
        idempotency.insert(
            record.key().to_vec(),
            IdempotencyDecision {
                request_digest,
                operation_id: OperationId::from_bytes(operation_bytes),
            },
        );
    }
    Ok(())
}

fn write_compacted(
    file: &mut File,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    let mut first_sequence = 1_u64;
    let mut transaction_index = 0_u64;
    let mut chunk = Vec::new();
    let mut chunk_bytes = 0_usize;
    for ((namespace, key), value) in state {
        let record = RecordMutationRef {
            namespace: *namespace,
            key,
            value: Some(value.as_slice()),
        };
        // Preserve lookahead representation refusal before flushing the prior chunk.
        let record_bytes =
            EncodedRecordLayout::new(key.len(), Some(value.len()))?.payload_bytes;
        if !chunk.is_empty()
            && (chunk.len() == limits.maximum_records_per_transaction
                || chunk_bytes.saturating_add(record_bytes) > limits.maximum_transaction_bytes)
        {
            if transaction_index >= limits.maximum_transactions as u64 {
                return Err(JournalError::LimitExceeded("committed transaction count"));
            }
            first_sequence = write_compaction_transaction(
                file,
                &chunk,
                transaction_index,
                first_sequence,
                limits,
            )?;
            transaction_index = transaction_index
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?;
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk_bytes = chunk_bytes
            .checked_add(record_bytes)
            .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
        chunk.push(record);
    }
    if !chunk.is_empty() {
        if transaction_index >= limits.maximum_transactions as u64 {
            return Err(JournalError::LimitExceeded("committed transaction count"));
        }
        write_compaction_transaction(file, &chunk, transaction_index, first_sequence, limits)?;
    }
    file.flush()?;
    Ok(())
}

fn write_compaction_transaction(
    file: &mut File,
    records: &[RecordMutationRef<'_, RecordNamespace>],
    transaction_index: u64,
    first_sequence: u64,
    limits: JournalLimits,
) -> Result<u64, JournalError> {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&(transaction_index + 1).to_le_bytes());
    id[8..].copy_from_slice(b"compact1");
    let records = records
        .iter()
        .map(|record| {
            let namespace = record.namespace;
            let key = record.key.to_vec();
            match record.value {
                Some(value) => JournalRecord::put(namespace, key, value.to_vec()),
                None => JournalRecord::delete(namespace, key),
            }
        })
        .collect();
    let transaction = JournalTransaction::new(id, records)?;
    validate_transaction(&transaction, limits)?;
    let frames = encode_transaction(&transaction, first_sequence)?;
    for frame in &frames {
        file.write_all(frame)?;
    }
    first_sequence
        .checked_add(frames.len() as u64)
        .ok_or(JournalError::SequenceExhausted)
}

fn reopen_replacement(
    path: &Path,
    limits: JournalLimits,
) -> Result<(File, ReplayState), JournalError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let replay = replay(&mut file, limits)?;
    if replay.durable_end != file.metadata()?.len() {
        return Err(JournalError::MalformedTransaction(
            "compacted journal has an uncommitted tail",
        ));
    }
    file.seek(SeekFrom::End(0))?;
    Ok((file, replay))
}

fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let parent = path.parent().ok_or_else(|| {
        JournalError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal path has no parent directory",
        ))
    })?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::{self, File, OpenOptions};
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use aos_sandbox_core::OperationId;

    use super::{
        FileIdentity, GlobalCapacityReservationPurposeV1,
        GlobalCapacityReservationRecoveryBindingV1, GlobalCapacityReservationRequestV1,
        HEADER_BYTES, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
        JournalRecord, JournalTransaction, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
        ProtectedAncestry, ProtectedAuthorityScope, ProtectedJournalAuthority,
        ProtectedJournalLockCustodyV1, ProtectedOwnerPolicy,
        ReadOnlyJournalNameWitness, RecordNamespace, RecoveryReport, encode_transaction,
        open_protected_file, protected_open_error,
        require_opened_directory_identity, traverse_protected_directory,
    };

    #[test]
    fn transaction_data_errors_project_original_journal_classes_and_native_cause() {
        use super::{FrameError, RecordError};
        use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError as DataError;

        let cases = [
            (
                DataError::InvalidTransaction,
                JournalError::InvalidTransaction,
            ),
            (
                DataError::InvalidIdempotencyKey,
                JournalError::InvalidIdempotencyKey,
            ),
            (
                DataError::MalformedTransaction("shape"),
                JournalError::MalformedTransaction("shape"),
            ),
            (
                DataError::MalformedRecord("record"),
                JournalError::MalformedRecord("record"),
            ),
            (
                DataError::LimitExceeded("bound"),
                JournalError::LimitExceeded("bound"),
            ),
            (
                DataError::DuplicateRecordKey,
                JournalError::DuplicateRecordKey,
            ),
            (DataError::JournalTooLarge, JournalError::JournalTooLarge),
            (
                DataError::Frame(FrameError::JournalTooLarge),
                JournalError::JournalTooLarge,
            ),
            (
                DataError::Frame(FrameError::UnsupportedVersion(3)),
                JournalError::UnsupportedVersion(3),
            ),
            (
                DataError::Frame(FrameError::ChecksumMismatch(19)),
                JournalError::ChecksumMismatch(19),
            ),
            (
                DataError::Frame(FrameError::MalformedTransaction("frame")),
                JournalError::MalformedTransaction("frame"),
            ),
            (
                DataError::Frame(FrameError::LimitExceeded("frame")),
                JournalError::LimitExceeded("frame"),
            ),
            (
                DataError::Frame(FrameError::MissingRetainedPayload),
                JournalError::ProtectedBoundary,
            ),
            (
                DataError::Frame(FrameError::SequenceExhausted),
                JournalError::SequenceExhausted,
            ),
            (
                DataError::Record(RecordError::MalformedRecord("payload")),
                JournalError::MalformedRecord("payload"),
            ),
            (
                DataError::Record(RecordError::LimitExceeded("payload")),
                JournalError::LimitExceeded("payload"),
            ),
        ];
        for (data, expected) in cases {
            let actual = JournalError::from(data);

            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
            assert_eq!(actual.to_string(), expected.to_string());
        }

        let original = std::io::Error::other(std::io::Error::from_raw_os_error(5));
        let cause = original.get_ref().unwrap() as *const _;
        let JournalError::Io(actual) =
            JournalError::from(DataError::Frame(FrameError::Io(original)))
        else {
            panic!("transaction DATA projection lost native I/O custody");
        };

        assert!(std::ptr::eq(cause, actual.get_ref().unwrap() as *const _));
        assert_eq!(
            actual
                .get_ref()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(5)
        );
    }

    #[test]
    fn native_record_decode_preserves_closed_namespace_error_precedence() {
        let limits = JournalLimits {
            maximum_key_bytes: 0,
            maximum_record_bytes: 0,
            ..JournalLimits::default()
        };

        for namespace in [0, 77, 78, 79, 255] {
            let payload = [namespace, 0, 0, 255, 255, 255, 255];

            assert!(matches!(
                super::decode_record(&payload[..6], limits).map_err(JournalError::from),
                Err(JournalError::MalformedRecord("record header is truncated")),
            ));
            assert!(matches!(
                super::decode_record(&payload, limits).map_err(JournalError::from),
                Err(JournalError::MalformedRecord("unknown record namespace")),
            ));
        }

        let limits = JournalLimits {
            maximum_key_bytes: 1,
            maximum_record_bytes: 0,
            ..JournalLimits::default()
        };

        assert!(matches!(
            super::decode_record(&[1, 2, 0, 0, 0, 0, 0], limits).map_err(JournalError::from),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
        assert!(matches!(
            super::decode_record(&[1, 1, 0, 0, 0, 0, 0], limits).map_err(JournalError::from),
            Err(JournalError::MalformedRecord("record length mismatch")),
        ));
    }

    #[test]
    fn replay_rejects_unknown_namespace_before_attempting_later_frame_io() {
        use std::borrow::Borrow;
        use std::io::{self, Read, Seek};

        struct FailAfterPrefix {
            file: File,
            prefix_bytes: usize,
            read_bytes: usize,
            attempted_later_read: bool,
        }

        impl Read for FailAfterPrefix {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.read_bytes >= self.prefix_bytes {
                    self.attempted_later_read = true;
                    return Err(io::Error::other("later frame read must not occur"));
                }
                let read = self.file.read(bytes)?;
                self.read_bytes += read;
                Ok(read)
            }
        }

        impl Seek for FailAfterPrefix {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                let position = self.file.seek(position)?;
                self.read_bytes = usize::try_from(position).map_err(io::Error::other)?;
                Ok(position)
            }
        }

        impl Borrow<File> for FailAfterPrefix {
            fn borrow(&self) -> &File {
                &self.file
            }
        }

        let frames = aos_sandbox_journal::transaction::encode_transaction(
            [7; 16],
            1,
            [aos_sandbox_journal::transaction::NativeRecordRef {
                namespace_byte: 255,
                key: b"key",
                value: None,
            }]
            .into_iter(),
        )
        .unwrap();
        let prefix = [&frames[0][..], &frames[1][..]].concat();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&prefix).unwrap();
        let mut reader = FailAfterPrefix {
            file,
            prefix_bytes: prefix.len(),
            read_bytes: 0,
            attempted_later_read: false,
        };

        let outcome = super::replay_original_retained(
            &mut reader,
            JournalLimits::default(),
            None,
            #[cfg(target_os = "linux")]
            None,
            None,
        );

        assert!(matches!(
            outcome,
            Err(JournalError::MalformedRecord("unknown record namespace")),
        ));
        assert_eq!(reader.read_bytes, prefix.len());
        assert!(!reader.attempted_later_read);
    }

    #[test]
    fn native_record_error_adapter_preserves_each_classification_and_message() {
        use super::RecordError;

        let cases = [
            (
                RecordError::MalformedRecord("record header is truncated"),
                JournalError::MalformedRecord("record header is truncated"),
            ),
            (
                RecordError::MalformedRecord("invalid value length"),
                JournalError::MalformedRecord("invalid value length"),
            ),
            (
                RecordError::MalformedRecord("record length mismatch"),
                JournalError::MalformedRecord("record length mismatch"),
            ),
            (
                RecordError::LimitExceeded("record key bytes"),
                JournalError::LimitExceeded("record key bytes"),
            ),
            (
                RecordError::LimitExceeded("record payload bytes"),
                JournalError::LimitExceeded("record payload bytes"),
            ),
        ];

        for (codec, expected) in cases {
            assert_eq!(codec.to_string(), expected.to_string());

            let actual = JournalError::from(codec);

            assert_eq!(std::mem::discriminant(&actual), std::mem::discriminant(&expected));
            assert_eq!(actual.to_string(), expected.to_string());
        }
    }

    #[test]
    fn native_tail_error_adapter_preserves_selected_classification_and_ordinary_cause() {
        use super::RecoveryTailError;

        let cases = [
            (
                RecoveryTailError::UncommittedTail,
                JournalError::MalformedTransaction("read-only journal has an uncommitted tail"),
            ),
            (RecoveryTailError::RetainedNativeFailure, JournalError::ProtectedBoundary),
        ];
        for (native, expected) in cases {
            assert_eq!(native.to_string(), expected.to_string());

            let actual = JournalError::from(native);

            assert_eq!(std::mem::discriminant(&actual), std::mem::discriminant(&expected));
            assert_eq!(actual.to_string(), expected.to_string());
        }

        let native = std::io::Error::from_raw_os_error(9);
        let expected_kind = native.kind();
        let expected_errno = native.raw_os_error();

        let actual = JournalError::from(RecoveryTailError::Io(native));

        let JournalError::Io(actual) = actual else {
            panic!("ordinary tail failure must retain its native I/O cause");
        };
        assert_eq!(actual.kind(), expected_kind);
        assert_eq!(actual.raw_os_error(), expected_errno);
    }

    #[test]
    fn typed_native_record_wrappers_preserve_canonical_bytes() {
        let cases: [(Option<&[u8]>, &[u8]); 3] = [
            (Some(b"v"), &[1, 1, 0, 1, 0, 0, 0, b'k', b'v']),
            (Some(b""), &[1, 1, 0, 0, 0, 0, 0, b'k']),
            (None, &[1, 1, 0, 255, 255, 255, 255, b'k']),
        ];

        for (value, expected) in cases {
            let record = match value {
                Some(value) => JournalRecord::put(RecordNamespace::DesiredState, b"k".to_vec(), value.to_vec()),
                None => JournalRecord::delete(RecordNamespace::DesiredState, b"k".to_vec()),
            };

            let payload = super::encode_record(&record).unwrap();
            let decoded = super::decode_record(&payload, JournalLimits::default()).unwrap();

            assert_eq!(payload, expected);
            assert_eq!(decoded, record);
        }
    }

    #[test]
    fn materialized_mutation_view_borrows_the_original_record_bytes() {
        let record = JournalRecord::put(
            RecordNamespace::DesiredState,
            b"key".to_vec(),
            b"value".to_vec(),
        );

        let view = super::RecordMutationRef::from(&record);

        assert_eq!(view.namespace, record.namespace());
        assert!(std::ptr::eq(view.key, record.key()));
        assert!(std::ptr::eq(view.value.unwrap(), record.value().unwrap()));
    }

    #[test]
    fn idempotency_refusal_still_follows_materialized_map_mutation() {
        let key = b"decision".to_vec();
        let mut state = std::collections::BTreeMap::from([
            ((RecordNamespace::Idempotency, key.clone()), vec![0; 48]),
        ]);
        let mut idempotency = std::collections::BTreeMap::new();
        let record = JournalRecord::delete(RecordNamespace::Idempotency, key.clone());

        let result = super::apply_record(&mut state, &mut idempotency, &record);

        assert!(matches!(
            result,
            Err(JournalError::MalformedRecord("idempotency records cannot be deleted")),
        ));
        assert!(!state.contains_key(&(RecordNamespace::Idempotency, key)));
        assert!(idempotency.is_empty());
    }

    #[test]
    fn native_geometry_view_preserves_all_eight_typed_limit_fields() {
        let limits = JournalLimits {
            maximum_journal_bytes: 101,
            maximum_record_bytes: 102,
            maximum_key_bytes: 103,
            maximum_records_per_transaction: 104,
            maximum_transaction_bytes: 105,
            maximum_transactions: 106,
            maximum_materialized_bytes: 107,
            maximum_materialized_records: 108,
        };

        let actual = super::NativeGeometryBounds::from(limits);

        assert_eq!(actual, super::NativeGeometryBounds {
            maximum_journal_bytes: 101,
            maximum_record_bytes: 102,
            maximum_key_bytes: 103,
            maximum_records_per_transaction: 104,
            maximum_transaction_bytes: 105,
            maximum_transactions: 106,
            maximum_materialized_bytes: 107,
            maximum_materialized_records: 108,
        });
    }

    #[test]
    fn framing_error_adapter_preserves_original_classification_and_io() {
        use super::FrameError;

        let cases = [
            (FrameError::JournalTooLarge, JournalError::JournalTooLarge),
            (FrameError::UnsupportedVersion(2), JournalError::UnsupportedVersion(2)),
            (FrameError::ChecksumMismatch(17), JournalError::ChecksumMismatch(17)),
            (
                FrameError::MalformedTransaction("unknown frame kind"),
                JournalError::MalformedTransaction("unknown frame kind"),
            ),
            (
                FrameError::LimitExceeded("frame payload bytes"),
                JournalError::LimitExceeded("frame payload bytes"),
            ),
            (FrameError::MissingRetainedPayload, JournalError::ProtectedBoundary),
            (FrameError::SequenceExhausted, JournalError::SequenceExhausted),
        ];

        for (framing, expected) in cases {
            assert_eq!(framing.to_string(), expected.to_string());

            let actual = JournalError::from(framing);

            assert_eq!(std::mem::discriminant(&actual), std::mem::discriminant(&expected));
            assert_eq!(actual.to_string(), expected.to_string());
        }

        let original_io = std::io::Error::from_raw_os_error(5);
        let expected_kind = original_io.kind();
        let expected_message = original_io.to_string();
        let JournalError::Io(actual_io) = JournalError::from(FrameError::Io(original_io)) else {
            panic!("framing I/O error lost its journal classification");
        };

        assert_eq!(actual_io.raw_os_error(), Some(5));
        assert_eq!(actual_io.kind(), expected_kind);
        assert_eq!(actual_io.to_string(), expected_message);
    }

    #[test]
    fn measured_widths_match_encoded_put_delete_and_empty_transactions() {
        let cases = [
            vec![],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![],
                vec![],
            )],
            vec![JournalRecord::delete(
                RecordNamespace::Operation,
                b"deleted".to_vec(),
            )],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"first".to_vec(),
                    vec![1, 2],
                ),
                JournalRecord::delete(RecordNamespace::Effect, b"second".to_vec()),
                JournalRecord::put(
                    RecordNamespace::Operation,
                    b"third".to_vec(),
                    vec![],
                ),
            ],
        ];

        for (index, records) in cases.into_iter().enumerate() {
            // Measurement, like encoding, does not perform owner admission or
            // the separate transaction validator's nonempty/UUID checks.
            let transaction = JournalTransaction::from_unvalidated_data([index as u8; 16], records);
            let frames = encode_transaction(&transaction, 0).unwrap();
            let append_bytes = frames.iter().map(|frame| frame.len() as u64).sum::<u64>();
            let record_bytes = transaction
                .records()
                .iter()
                .map(|record| super::encode_record(record).unwrap().len() as u64)
                .sum::<u64>();

            assert_eq!(
                super::encoded_transaction_append_bytes(&transaction).unwrap(),
                append_bytes,
            );
            assert_eq!(
                super::encoded_transaction_record_bytes(&transaction).unwrap(),
                record_bytes,
            );
        }
    }

    #[test]
    fn online_nix_suffix_extents_use_the_native_and_prepared_width_engines() {
        use super::{EncodedFrameLayout, EncodedRecordLayout};

        let maximum_record = 67_242_238;
        let traffic = EncodedRecordLayout::new(9, Some(maximum_record - 16)).unwrap();
        let fence = EncodedRecordLayout::new(24, Some(741)).unwrap();
        let pending = EncodedRecordLayout::new(24, Some(617)).unwrap();
        let complete = EncodedRecordLayout::new(24, Some(649)).unwrap();
        let cases = [
            (2, traffic.payload_bytes + complete.payload_bytes, 67_242_958),
            (3, traffic.payload_bytes + fence.payload_bytes + pending.payload_bytes, 67_243_702),
            (2, traffic.payload_bytes + complete.payload_bytes, 67_242_958),
        ];

        let mut main_append = 0;
        for (records, payload, expected_prepared) in cases {
            let limits = JournalLimits {
                maximum_record_bytes: maximum_record,
                maximum_records_per_transaction: records,
                maximum_transaction_bytes: payload,
                ..JournalLimits::default()
            };
            let prepared = JournalTransaction::maximum_prepared_bytes_v1(limits).unwrap();
            let append = payload + EncodedFrameLayout::new(4).unwrap().frame_bytes
                + EncodedFrameLayout::new(36).unwrap().frame_bytes + records * HEADER_BYTES;

            assert_eq!(prepared, expected_prepared);
            main_append += append;
        }
        assert_eq!(main_append, 201_730_550);

        let largest_prepared = 67_243_702;
        let sidecar_prepare = EncodedRecordLayout::new(6, Some(324)).unwrap().payload_bytes
            + EncodedRecordLayout::new(11, Some(largest_prepared)).unwrap().payload_bytes;
        let sidecar_finalize = EncodedRecordLayout::new(10, Some(156)).unwrap().payload_bytes
            + EncodedRecordLayout::new(6, None).unwrap().payload_bytes
            + EncodedRecordLayout::new(11, None).unwrap().payload_bytes;

        assert_eq!(sidecar_prepare, largest_prepared + 355);
        assert_eq!(sidecar_finalize, 204);
        assert_eq!(10 + 156 + 6 + 324 + 11 + largest_prepared, 67_244_209);
    }

    #[test]
    fn both_measurements_preserve_record_key_error() {
        let transaction = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![1; u16::MAX as usize + 1],
                vec![],
            )],
        );

        assert!(matches!(
            super::encoded_transaction_record_bytes(&transaction).map_err(JournalError::from),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
        assert!(matches!(
            super::encoded_transaction_append_bytes(&transaction).map_err(JournalError::from),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
        assert!(matches!(
            encode_transaction(&transaction, 0).map_err(JournalError::from),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
    }

    #[test]
    fn encoder_retains_sequence_checks_without_post_commit_increment() {
        let valid = transaction(
            1,
            vec![JournalRecord::delete(
                RecordNamespace::DesiredState,
                b"key".to_vec(),
            )],
        );
        let invalid = transaction(
            2,
            vec![JournalRecord::delete(
                RecordNamespace::DesiredState,
                vec![1; u16::MAX as usize + 1],
            )],
        );

        assert!(encode_transaction(&valid, u64::MAX - 2).is_ok());
        assert!(matches!(
            encode_transaction(&valid, u64::MAX - 1).map_err(JournalError::from),
            Err(JournalError::SequenceExhausted),
        ));
        assert!(matches!(
            encode_transaction(&invalid, u64::MAX).map_err(JournalError::from),
            Err(JournalError::SequenceExhausted),
        ));
        assert!(matches!(
            encode_transaction(&invalid, u64::MAX - 1).map_err(JournalError::from),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn q04_lower_history_includes_put_and_clear_only_in_the_exact_owner_namespace() {
        use crate::policy_compiler::create_q04::{CACHE_PENDING_KEY, SOURCE_PENDING_KEY};

        for (namespace, key) in [
            (RecordNamespace::SourceDomainPolicyHold, SOURCE_PENDING_KEY),
            (RecordNamespace::DesiredState, CACHE_PENDING_KEY),
        ] {
            let put = JournalRecord::put(namespace, key.to_vec(), vec![1]);
            let clear = JournalRecord::delete(namespace, key.to_vec());

            assert!(super::is_q04_lower_history_record_v1(&put));
            assert!(super::is_q04_lower_history_record_v1(&clear));
        }

        for (namespace, key) in [
            (RecordNamespace::DesiredState, SOURCE_PENDING_KEY),
            (RecordNamespace::SourceDomainPolicyHold, CACHE_PENDING_KEY),
            (RecordNamespace::Effect, SOURCE_PENDING_KEY),
            (RecordNamespace::DesiredState, b"ordinary".as_slice()),
        ] {
            let record = JournalRecord::put(namespace, key.to_vec(), vec![1]);

            assert!(!super::is_q04_lower_history_record_v1(&record));
        }
    }

    #[test]
    fn operator_empty_provisioning_mode_never_enables_repair() {
        use super::ProtectedJournalOpenMode;

        let ordinary_create = ProtectedJournalOpenMode::Ordinary { allow_create: true };
        assert!(ordinary_create.allows_creation());
        assert!(ordinary_create.allows_repair());

        let ordinary_existing = ProtectedJournalOpenMode::Ordinary { allow_create: false };
        assert!(!ordinary_existing.allows_creation());
        assert!(!ordinary_existing.allows_repair());

        let provision = ProtectedJournalOpenMode::StorageOperatorEmptyProvisionV4;
        assert!(provision.allows_creation());
        assert!(!provision.allows_repair());
    }

    #[test]
    fn operator_provisioning_refuses_all_physical_history() {
        assert!(
            super::reject_operator_provisioning_history::<crate::journal::JournalError>(0).is_ok()
        );
        for length in [1, 32, 4096, u64::MAX] {
            assert!(matches!(
                super::reject_operator_provisioning_history::<crate::journal::JournalError>(length),
                Err(JournalError::ProtectedBoundary),
            ));
        }
    }

    #[test]
    fn operator_provisioning_requires_native_genesis_not_just_empty_state() {
        use super::require_empty_operator_provisioning_state;

        assert!(require_empty_operator_provisioning_state(1, 0, false).is_ok());
        for (sequence, transactions, history) in [
            (0, 0, false),
            (2, 0, false),
            (u64::MAX, 0, false),
            (1, 1, false),
            (1, 0, true),
            (4, 1, true),
        ] {
            assert!(matches!(
                require_empty_operator_provisioning_state(sequence, transactions, history),
                Err(JournalError::ProtectedBoundary),
            ));
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-sandbox-journal-{label}-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("state.journal")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_only_directory_must_match_mount_witness_before_replay() {
        let directory = TestDirectory::new("read-only-mount-identity");
        let opened = File::open(&directory.0).unwrap();
        let identity = FileIdentity::of::<crate::journal::JournalError>(&opened).unwrap();

        assert!(
            require_opened_directory_identity::<crate::journal::JournalError>(
                &opened,
                identity.physical_pair()
            )
            .is_ok()
        );
        assert!(matches!(
            require_opened_directory_identity::<crate::journal::JournalError>(
                &opened,
                (
                    identity.physical_pair().0,
                    identity.physical_pair().1.wrapping_add(1)
                ),
            ),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    fn transaction(id: u8, records: Vec<JournalRecord>) -> JournalTransaction {
        JournalTransaction::new([id; 16], records).unwrap()
    }

    fn source_provider_capacity_request() -> GlobalCapacityReservationRequestV1 {
        GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
            owner_namespace: RecordNamespace::SourceProviderAuthority,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 3,
            terminal_bytes: 4096,
            poison_records: 3,
            poison_bytes: 4096,
        }
    }

    #[test]
    fn source_held_readonly_scope_refuses_legacy_factories_and_effects() {
        // This local protected-open fixture tests scope refusal only. It is
        // not the fixed production location or a qualified Security Session.
        let directory = TestDirectory::new("source-held-readonly-scope");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let before = (
            journal.native.state().clone(),
            journal.native.next_sequence(),
            journal.native.committed_transactions(),
            journal.native.file().metadata().unwrap().len(),
        );
        let request = source_provider_capacity_request();
        let binding = GlobalCapacityReservationRecoveryBindingV1 {
            purpose: request.purpose,
            operation_id: request.operation_id,
            artifact_digest: request.artifact_digest,
            checkpoint_digest: request.checkpoint_digest,
            chain_head_digest: request.chain_head_digest,
            future_transactions: request.future_transactions,
            terminal_records: request.terminal_records,
            terminal_bytes: request.terminal_bytes,
            poison_records: request.poison_records,
            poison_bytes: request.poison_bytes,
        };
        let change = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"forbidden".to_vec(),
                vec![1],
            )],
        );
        {
            let mut view = ProtectedJournalAuthority {
                journal: &mut journal,
                namespace: RecordNamespace::SourceProviderAuthority,
                scope: ProtectedAuthorityScope::SourceProviderHeldReadOnly,
            };
            let snapshot = view.snapshot().unwrap();

            // Immutable Security artifact factories use these unchanged
            // purpose checks, not a generic readable snapshot as authority.
            assert!(matches!(
                view.validate_source_provider_authority(),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(matches!(
                view.validate_source_provider_authority_snapshot(&snapshot),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(view.validate_fixed_source_provider_storage().is_err());
            assert!(view.fixed_source_provider_session_handoff().is_err());
            assert!(matches!(
                view.validate_snapshot_for_effect(&snapshot),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(matches!(
                view.prepare_global_capacity_reservation_v1(request, [2; 16]),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(matches!(
                view.recover_unique_global_capacity_reservation_v1(&binding),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(matches!(
                view.preflight_transactions(std::slice::from_ref(&change)),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            let preflight = super::ProtectedJournalPreflight {
                snapshot: view.snapshot().unwrap(),
                transaction_digest: super::authority_preflight_digest(std::slice::from_ref(
                    &change,
                )),
            };
            assert!(matches!(
                view.validate_preflight_for_effect(&preflight, std::slice::from_ref(&change)),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            assert!(matches!(
                view.commit(&change),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
        }
        assert_eq!(
            before,
            (
                journal.native.state().clone(),
                journal.native.next_sequence(),
                journal.native.committed_transactions(),
                journal.native.file().metadata().unwrap().len(),
            )
        );
        journal.ensure_healthy().unwrap();
    }

    #[test]
    fn source_held_readonly_claim_requires_actual_fixed_physical_custody() {
        let directory = TestDirectory::new("source-held-readonly-location");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(journal.claim_source_provider_held_readonly_v1().is_err());
        journal.ensure_healthy().unwrap();
        assert!(journal.native.state().is_empty());
    }

    #[test]
    fn source_provider_native_capacity_replays_and_settles_under_fixed_purpose() {
        let directory = TestDirectory::new("source-provider-native-capacity");
        let request = source_provider_capacity_request();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let reservation_id = {
            let mut authority = journal
                .claim_source_provider_native_terminal_authority_v1()
                .unwrap();
            authority.validate_source_provider_authority().unwrap();

            let prepared = authority
                .prepare_global_capacity_reservation_v1(request, [7; 16])
                .unwrap();
            assert_eq!(prepared.record().value().unwrap()[11], 3);
            let reservation_id = prepared.reservation_id();
            let admission = transaction(
                7,
                vec![
                    JournalRecord::put(
                        RecordNamespace::SourceProviderAuthority,
                        b"owner".to_vec(),
                        b"admitted".to_vec(),
                    ),
                    prepared.record().clone(),
                ],
            );
            let preflight = authority
                .preflight_global_capacity_reservation_v1(&prepared, &admission)
                .unwrap();
            let (_, committed_reservation) = authority
                .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
                .unwrap();
            assert_eq!(committed_reservation.reservation_id(), reservation_id);
            assert_eq!(
                authority.get(b"owner").unwrap(),
                Some(b"admitted".as_slice())
            );
            assert_eq!(authority.records().unwrap().count(), 1);
            authority
                .commit(&transaction(
                    9,
                    vec![JournalRecord::put(
                        RecordNamespace::SourceProviderAuthority,
                        b"ordinary".to_vec(),
                        b"retained".to_vec(),
                    )],
                ))
                .unwrap();
            reservation_id
        };
        drop(journal);

        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        let mut authority = reopened
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        authority
            .validate_global_capacity_reservation_set_v1(&[reservation_id].into())
            .unwrap();
        let reservation = authority
            .recover_global_capacity_reservation_by_binding_v1(
                reservation_id,
                &GlobalCapacityReservationRecoveryBindingV1 {
                    purpose: request.purpose,
                    operation_id: request.operation_id,
                    artifact_digest: request.artifact_digest,
                    checkpoint_digest: request.checkpoint_digest,
                    chain_head_digest: request.chain_head_digest,
                    future_transactions: request.future_transactions,
                    terminal_records: request.terminal_records,
                    terminal_bytes: request.terminal_bytes,
                    poison_records: request.poison_records,
                    poison_bytes: request.poison_bytes,
                },
            )
            .unwrap();
        let terminal = transaction(
            8,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"owner".to_vec(),
                    b"settled".to_vec(),
                ),
                reservation.settlement_record(),
            ],
        );
        let preflight = authority
            .preflight_reserved_terminal_v1(&reservation, &terminal)
            .unwrap();
        authority
            .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
            .unwrap();
        authority
            .validate_global_capacity_reservation_set_v1(&Default::default())
            .unwrap();
        assert_eq!(
            authority.get(b"owner").unwrap(),
            Some(b"settled".as_slice())
        );
    }

    #[test]
    fn source_provider_native_capacity_rejects_foreign_purpose_and_namespace() {
        let directory = TestDirectory::new("source-provider-native-isolation");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let mut authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let mut wrong_purpose = source_provider_capacity_request();
        wrong_purpose.purpose = GlobalCapacityReservationPurposeV1::RuntimeExecution;
        assert!(matches!(
            authority.prepare_global_capacity_reservation_v1(wrong_purpose, [1; 16]),
            Err(JournalError::ForeignAuthorityNamespace)
        ));

        let prepared = authority
            .prepare_global_capacity_reservation_v1(source_provider_capacity_request(), [2; 16])
            .unwrap();
        let foreign_admission = transaction(
            2,
            vec![
                JournalRecord::put(RecordNamespace::Effect, b"foreign".to_vec(), vec![1]),
                prepared.record().clone(),
            ],
        );
        assert!(matches!(
            authority.preflight_global_capacity_reservation_v1(&prepared, &foreign_admission),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        let generic_capacity = transaction(3, vec![prepared.record().clone()]);
        assert!(matches!(
            authority.commit(&generic_capacity),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        let foreign_generic = transaction(
            4,
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                b"foreign".to_vec(),
                vec![1],
            )],
        );
        assert!(matches!(
            authority.commit(&foreign_generic),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
        drop(authority);

        let generic = journal
            .claim_protected_authority(RecordNamespace::SourceProviderAuthority)
            .unwrap();
        assert!(matches!(
            generic.prepare_global_capacity_reservation_v1(
                source_provider_capacity_request(),
                [5; 16]
            ),
            Err(JournalError::ForeignAuthorityNamespace)
        ));
    }

    #[test]
    fn source_provider_native_claim_rejects_foreign_state_and_deleted_history() {
        for (label, delete_foreign) in [("retained", false), ("deleted", true)] {
            let directory = TestDirectory::new(label);
            let (mut journal, _) = protected_open(&directory.0).unwrap();
            journal
                .commit(&transaction(
                    21,
                    vec![JournalRecord::put(
                        RecordNamespace::Effect,
                        b"foreign".to_vec(),
                        vec![1],
                    )],
                ))
                .unwrap();
            if delete_foreign {
                journal
                    .commit(&transaction(
                        22,
                        vec![JournalRecord::delete(
                            RecordNamespace::Effect,
                            b"foreign".to_vec(),
                        )],
                    ))
                    .unwrap();
                assert!(journal.records(RecordNamespace::Effect).next().is_none());
            }

            assert!(matches!(
                journal.claim_source_provider_native_terminal_authority_v1(),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
            drop(journal);

            let (mut reopened, _) = protected_open(&directory.0).unwrap();
            assert!(matches!(
                reopened.claim_source_provider_native_terminal_authority_v1(),
                Err(JournalError::ForeignAuthorityNamespace)
            ));
        }
    }

    #[test]
    fn source_provider_native_capacity_checks_postimage_materialized_bytes_on_commit() {
        let directory = TestDirectory::new("source-provider-capacity-postimage-bytes");
        let request = source_provider_capacity_request();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        {
            let mut authority = journal
                .claim_source_provider_native_terminal_authority_v1()
                .unwrap();
            let prepared = authority
                .prepare_global_capacity_reservation_v1(request, [11; 16])
                .unwrap();
            let admission = transaction(
                11,
                vec![
                    JournalRecord::put(
                        RecordNamespace::SourceProviderAuthority,
                        b"owner".to_vec(),
                        b"admitted".to_vec(),
                    ),
                    prepared.record().clone(),
                ],
            );
            let preflight = authority
                .preflight_global_capacity_reservation_v1(&prepared, &admission)
                .unwrap();
            authority
                .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
                .unwrap();
        }

        // Leave one byte beyond the held promise, then grow the owner by two.
        // The owner alone fits, but its postimage plus the promise must not.
        journal.native.replace_limits_for_fixture(JournalLimits {
            maximum_materialized_bytes: journal.native.materialized_bytes()
                + usize::try_from(request.terminal_bytes).unwrap() + 1,
            ..journal.native.limits()
        });
        let before_sequence = journal.snapshot_sequence();
        let before_length = journal.native.file().metadata().unwrap().len();
        let competing = transaction(
            12,
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"owner".to_vec(),
                b"admitted++".to_vec(),
            )],
        );
        let mut authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();

        assert!(matches!(
            authority.preflight_transactions(std::slice::from_ref(&competing)),
            Err(JournalError::LimitExceeded(
                "outstanding global capacity reservations"
            ))
        ));
        assert!(matches!(
            authority.commit(&competing),
            Err(JournalError::LimitExceeded(
                "outstanding global capacity reservations"
            ))
        ));
        assert_eq!(
            authority.get(b"owner").unwrap(),
            Some(b"admitted".as_slice())
        );
        drop(authority);

        assert_eq!(journal.snapshot_sequence(), before_sequence);
        assert_eq!(journal.native.file().metadata().unwrap().len(), before_length);
        assert!(journal.ensure_healthy().is_ok());
    }

    #[test]
    fn source_provider_native_capacity_preserves_near_limit_terminal_space() {
        let mut request = source_provider_capacity_request();
        request.terminal_records = 2;
        request.poison_records = 2;
        let limits_with_terminal_slots = |slots: usize| JournalLimits {
            // Admission retains one owner and one reservation row. The held
            // terminal branch needs two further slots until settlement.
            maximum_materialized_records: 2 + slots,
            ..JournalLimits::default()
        };
        let admission = |prepared: &super::PreparedGlobalCapacityReservationV1| {
            transaction(
                11,
                vec![
                    JournalRecord::put(
                        RecordNamespace::SourceProviderAuthority,
                        b"owner".to_vec(),
                        b"admitted".to_vec(),
                    ),
                    prepared.record().clone(),
                ],
            )
        };

        let too_small = TestDirectory::new("source-provider-capacity-one-terminal-slot");
        fs::set_permissions(&too_small.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&too_small.0).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            &too_small.0,
            "protected.journal",
            limits_with_terminal_slots(1),
            uid,
        )
        .unwrap();
        let authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let prepared = authority
            .prepare_global_capacity_reservation_v1(request, [11; 16])
            .unwrap();
        assert!(matches!(
            authority.preflight_global_capacity_reservation_v1(&prepared, &admission(&prepared)),
            Err(JournalError::LimitExceeded(
                "outstanding global capacity reservations"
            ))
        ));
        assert_eq!(authority.records().unwrap().count(), 0);
        drop(authority);
        assert_eq!(journal.snapshot_sequence(), 1);
        drop(journal);

        let enough = TestDirectory::new("source-provider-capacity-two-terminal-slots");
        fs::set_permissions(&enough.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&enough.0).unwrap().uid();
        let limits = limits_with_terminal_slots(2);
        let (mut journal, _) =
            Journal::open_protected_at_uid(&enough.0, "protected.journal", limits, uid).unwrap();
        let mut authority = journal
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        let prepared = authority
            .prepare_global_capacity_reservation_v1(request, [11; 16])
            .unwrap();
        let admission = admission(&prepared);
        let preflight = authority
            .preflight_global_capacity_reservation_v1(&prepared, &admission)
            .unwrap();
        let (_, reservation) = authority
            .commit_global_capacity_reservation_v1(&preflight, prepared, &admission)
            .unwrap();
        let competing = transaction(
            12,
            vec![JournalRecord::put(
                RecordNamespace::SourceProviderAuthority,
                b"competing".to_vec(),
                vec![1],
            )],
        );
        assert!(matches!(
            authority.commit(&competing),
            Err(JournalError::LimitExceeded(
                "outstanding global capacity reservations"
            ))
        ));
        assert_eq!(authority.get(b"competing").unwrap(), None);

        let terminal = transaction(
            13,
            vec![
                JournalRecord::put(
                    RecordNamespace::SourceProviderAuthority,
                    b"owner".to_vec(),
                    b"settled".to_vec(),
                ),
                reservation.settlement_record(),
            ],
        );
        let preflight = authority
            .preflight_reserved_terminal_v1(&reservation, &terminal)
            .unwrap();
        authority
            .commit_reserved_terminal_v1(&preflight, reservation, &terminal)
            .unwrap();
        drop(authority);
        drop(journal);

        let (mut reopened, _) =
            Journal::open_protected_at_uid(&enough.0, "protected.journal", limits, uid).unwrap();
        let authority = reopened
            .claim_source_provider_native_terminal_authority_v1()
            .unwrap();
        authority
            .validate_global_capacity_reservation_set_v1(&Default::default())
            .unwrap();
        assert_eq!(
            authority.get(b"owner").unwrap(),
            Some(b"settled".as_slice())
        );
        assert_eq!(authority.get(b"competing").unwrap(), None);
    }

    #[test]
    fn namespace_codes_are_append_only_and_unknown_codes_fail_closed() {
        let namespaces = [
            RecordNamespace::DesiredState,
            RecordNamespace::Operation,
            RecordNamespace::Effect,
            RecordNamespace::Idempotency,
            RecordNamespace::OwnershipGate,
            RecordNamespace::AuthorityPublication,
            RecordNamespace::PublisherAuthority,
            RecordNamespace::PublisherPolicy,
            RecordNamespace::PublisherIngress,
            RecordNamespace::RuntimeAuthority,
            RecordNamespace::RuntimeGeneration,
            RecordNamespace::NamespaceTarget,
            RecordNamespace::MountAttempt,
            RecordNamespace::MountCompletion,
            RecordNamespace::MountInventory,
            RecordNamespace::AttachmentDesired,
            RecordNamespace::AttachmentVerification,
            RecordNamespace::FilesystemViewRevision,
            RecordNamespace::AttachmentSlot,
            RecordNamespace::SandboxSpec,
            RecordNamespace::MountDestinationSlot,
            RecordNamespace::DestinationSlotInventory,
            RecordNamespace::DestinationSlotAttempt,
            RecordNamespace::DestinationSlotCompletion,
            RecordNamespace::StorageResourceInventory,
            RecordNamespace::NetworkResourceInventory,
            RecordNamespace::HostCatalogReconciliation,
            RecordNamespace::StorageCatalogReservation,
            RecordNamespace::StorageCatalogTransition,
            RecordNamespace::StorageCatalogHead,
            RecordNamespace::StorageRuntimeConfiguration,
            RecordNamespace::StorageWorkspacePublicationIntent,
            RecordNamespace::StorageWorkspacePinAttempt,
            RecordNamespace::StorageCatalogPreparation,
            RecordNamespace::StorageWorkspacePinRepairIntent,
            RecordNamespace::HostExecution,
            RecordNamespace::StorageResolverPolicyFloor,
            RecordNamespace::ControllerIdentity,
            RecordNamespace::MountSourcePin,
            RecordNamespace::MountSourceAcquisition,
            RecordNamespace::SourceProviderAuthority,
            RecordNamespace::MountSourceAcquisitionInventory,
            RecordNamespace::AttachmentSourceAttempt,
            RecordNamespace::AttachmentSourceCompletion,
            RecordNamespace::MountManagerStartupAuthority,
            RecordNamespace::GlobalCapacityReservation,
            RecordNamespace::BrokerSessionTraffic,
            RecordNamespace::CliAuthorizationTime,
            RecordNamespace::OperatorRecovery,
            RecordNamespace::FilesystemWorkerRegistration,
            RecordNamespace::PublicOperationAuthorization,
            RecordNamespace::LifecycleAtomicSnapshotSource,
            RecordNamespace::PublicAttachRoute,
            RecordNamespace::PublicAttachPending,
            RecordNamespace::BrokerSessionStorageGroupArchive,
            RecordNamespace::GuestRootPublication,
            RecordNamespace::AttachmentSourceDispatch,
            RecordNamespace::StorageGuestRootPublicationAttempt,
            RecordNamespace::BrokerSessionStorageInventoryArchive,
            RecordNamespace::BrokerSessionStorageInventoryAbandonment,
            RecordNamespace::PublicCapabilityBootstrap,
            RecordNamespace::StorageExecutionOutput,
            RecordNamespace::ControllerExecutionPreissue,
            RecordNamespace::ControllerExecutionOutputAttempt,
            RecordNamespace::ControllerExecutionOutputSettlement,
            RecordNamespace::ControllerExecutionArgumentAttempt,
            RecordNamespace::ControllerExecutionArgumentReceipt,
            RecordNamespace::ControllerExecutionSpecAttempt,
            RecordNamespace::ControllerPolicyHold,
            RecordNamespace::SourceDomainPolicyHold,
            RecordNamespace::ControllerExecutionObserveReservation,
            RecordNamespace::ControllerCreateFailurePrepare,
            RecordNamespace::ControllerNoApplySettlementCursor,
            RecordNamespace::ControllerStorageOutputReserveAttempt,
            RecordNamespace::ControllerConsumerReadAttempt,
            RecordNamespace::NixOfflineProvisioning,
        ];
        for (index, namespace) in namespaces.into_iter().enumerate() {
            let code = namespace as u8;
            assert_eq!(code, u8::try_from(index + 1).unwrap());
            assert_eq!(RecordNamespace::from_byte(code).unwrap(), namespace);
        }
        assert_eq!(RecordNamespace::ControllerResourceReservation as u8, 80);
        assert_eq!(
            RecordNamespace::from_byte(80).unwrap(),
            RecordNamespace::ControllerResourceReservation,
        );

        for code in [0, 77, 78, 79, 255] {
            let error = RecordNamespace::from_byte(code).unwrap_err();
            assert!(matches!(
                JournalError::from(error),
                JournalError::MalformedRecord("unknown record namespace"),
            ));
        }
    }

    #[test]
    fn public_attach_reservation_survives_reopen_without_admitting_an_operation() {
        use crate::public_attach_pending::{
            load_public_attach_pending_v1, reserve_public_attach_pending_v1,
        };

        let directory = TestDirectory::new("public-attach-pending");
        let key = IdempotencyKey::new(b"attach-request".to_vec()).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let pending = reserve_public_attach_pending_v1(
            &mut journal,
            &key,
            [1; 32],
            [2; 16],
            [3; 16],
            4,
            [5; 16],
            [6; 16],
            100,
            1_000,
        )
        .unwrap();
        assert_eq!(
            journal.check_idempotency(&key, [1; 32]),
            IdempotencyOutcome::Vacant
        );
        assert!(journal.records(RecordNamespace::Operation).next().is_none());
        assert!(
            journal
                .records(RecordNamespace::DesiredState)
                .next()
                .is_none()
        );
        assert!(
            journal
                .records(RecordNamespace::PublicAttachRoute)
                .next()
                .is_none()
        );
        assert_eq!(
            reserve_public_attach_pending_v1(
                &mut journal,
                &key,
                [1; 32],
                [2; 16],
                [3; 16],
                4,
                [5; 16],
                [6; 16],
                101,
                1_000,
            )
            .unwrap(),
            pending
        );
        drop(journal);

        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            load_public_attach_pending_v1(&reopened, &key).unwrap(),
            Some(pending.clone())
        );
        assert!(
            reserve_public_attach_pending_v1(
                &mut reopened,
                &key,
                [9; 32],
                [2; 16],
                [3; 16],
                4,
                [5; 16],
                [6; 16],
                101,
                1_000,
            )
            .is_err()
        );
    }

    #[test]
    fn expired_public_attach_pending_renews_the_same_operation_id() {
        use crate::public_attach_pending::{
            load_public_attach_pending_v1, reserve_public_attach_pending_v1,
        };

        let directory = TestDirectory::new("public-attach-renewal");
        let key = IdempotencyKey::new(b"attach-renewal".to_vec()).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let reserve = |journal: &mut Journal, now| {
            reserve_public_attach_pending_v1(
                journal, &key, [1; 32], [2; 16], [3; 16], 4, [5; 16], [6; 16], now, 1_000,
            )
            .unwrap()
        };

        let original = reserve(&mut journal, 100);
        let renewed = reserve(&mut journal, original.expires_at());
        assert_eq!(renewed.operation_id(), original.operation_id());
        assert_eq!(renewed.expires_at(), 700);
        assert_ne!(renewed.record_digest(), original.record_digest());
        assert_eq!(
            journal.check_idempotency(&key, [1; 32]),
            IdempotencyOutcome::Vacant
        );
        assert!(journal.records(RecordNamespace::Operation).next().is_none());
        journal
            .commit(&transaction(
                7,
                vec![JournalRecord::idempotency(
                    &key,
                    [1; 32],
                    renewed.operation_id(),
                )],
            ))
            .unwrap();
        assert!(
            reserve_public_attach_pending_v1(
                &mut journal,
                &key,
                [1; 32],
                [2; 16],
                [3; 16],
                4,
                [5; 16],
                [6; 16],
                700,
                1_000,
            )
            .is_err()
        );
        drop(journal);

        let (reopened, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            load_public_attach_pending_v1(&reopened, &key).unwrap(),
            Some(renewed)
        );
    }

    #[test]
    fn publisher_authority_namespace_survives_replay_and_compaction() {
        let directory = TestDirectory::new("publisher-namespace");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let key = b"same-key".to_vec();
        journal
            .commit(&transaction(
                1,
                vec![
                    JournalRecord::put(
                        RecordNamespace::PublisherAuthority,
                        key.clone(),
                        b"publisher-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::AuthorityPublication,
                        key.clone(),
                        b"assignment-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        key.clone(),
                        b"policy-record".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::PublisherIngress,
                        key.clone(),
                        b"ingress-record".to_vec(),
                    ),
                ],
            ))
            .unwrap();
        journal.compact().unwrap();
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::PublisherAuthority, &key),
            Some(b"publisher-record".as_slice()),
        );
        assert_eq!(
            journal.get(RecordNamespace::AuthorityPublication, &key),
            Some(b"assignment-record".as_slice()),
        );
        assert_eq!(
            journal
                .records(RecordNamespace::AuthorityPublication)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"assignment-record".as_slice())],
        );
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherAuthority)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"publisher-record".as_slice())],
        );
        assert_eq!(journal.records(RecordNamespace::DesiredState).count(), 0);
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherPolicy)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"policy-record".as_slice())],
        );
        assert_eq!(
            journal
                .records(RecordNamespace::PublisherIngress)
                .collect::<Vec<_>>(),
            vec![(key.as_slice(), b"ingress-record".as_slice())],
        );
    }

    #[test]
    fn all_records_orders_namespaces_then_bytewise_keys() {
        let directory = TestDirectory::new("all-records-order");
        let (mut journal, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![
                    JournalRecord::put(
                        RecordNamespace::Effect,
                        b"zeta".to_vec(),
                        b"effect".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"zeta".to_vec(),
                        b"desired-zeta".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"alpha".to_vec(),
                        b"desired-alpha".to_vec(),
                    ),
                    JournalRecord::put(
                        RecordNamespace::Operation,
                        b"middle".to_vec(),
                        b"operation".to_vec(),
                    ),
                ],
            ))
            .unwrap();

        assert_eq!(
            journal.all_records().collect::<Vec<_>>(),
            vec![
                (
                    RecordNamespace::DesiredState,
                    b"alpha".as_slice(),
                    b"desired-alpha".as_slice(),
                ),
                (
                    RecordNamespace::DesiredState,
                    b"zeta".as_slice(),
                    b"desired-zeta".as_slice(),
                ),
                (
                    RecordNamespace::Operation,
                    b"middle".as_slice(),
                    b"operation".as_slice(),
                ),
                (
                    RecordNamespace::Effect,
                    b"zeta".as_slice(),
                    b"effect".as_slice(),
                ),
            ],
        );
    }

    fn protected_open(directory: &Path) -> Result<(Journal, RecoveryReport), JournalError> {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory).unwrap().uid();
        Journal::open_protected_at_uid(
            directory,
            "protected.journal",
            JournalLimits::default(),
            uid,
        )
    }

    #[test]
    fn duplicated_snapshot_preserves_exact_provenance() {
        let directory = TestDirectory::new("snapshot-duplicate-identity");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let original = authority.snapshot().unwrap();

        let duplicate = original.duplicate_provenance();

        assert!(std::sync::Arc::ptr_eq(&original.instance, &duplicate.instance));
        assert_eq!(original.namespace, duplicate.namespace);
        assert_eq!(original.sequence, duplicate.sequence);
        assert_eq!(original.scope, duplicate.scope);
        authority.validate_snapshot_for_effect(&duplicate).unwrap();

        let mut foreign_namespace = original.duplicate_provenance();
        foreign_namespace.namespace = RecordNamespace::Effect;
        assert!(matches!(
            authority.validate_snapshot_for_effect(&foreign_namespace),
            Err(JournalError::StaleAuthoritySnapshot),
        ));

        let mut foreign_scope = original.duplicate_provenance();
        foreign_scope.scope = ProtectedAuthorityScope::FixedMountSourceAcquisition;
        assert!(matches!(
            authority.validate_snapshot_for_effect(&foreign_scope),
            Err(JournalError::StaleAuthoritySnapshot),
        ));
    }

    #[test]
    fn duplicated_snapshot_remains_foreign_and_stale() {
        let directory = TestDirectory::new("snapshot-duplicate-current");
        let foreign_directory = TestDirectory::new("snapshot-duplicate-foreign");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let (mut foreign_journal, _) = protected_open(&foreign_directory.0).unwrap();
        let mut authority = journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let foreign_authority = foreign_journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .unwrap();
        let original = authority.snapshot().unwrap();
        let duplicate = original.duplicate_provenance();
        let foreign = foreign_authority.snapshot().unwrap().duplicate_provenance();

        assert_eq!(original.namespace, foreign.namespace);
        assert_eq!(original.sequence, foreign.sequence);
        assert_eq!(original.scope, foreign.scope);
        assert!(matches!(
            authority.validate_snapshot_for_effect(&foreign),
            Err(JournalError::StaleAuthoritySnapshot),
        ));

        authority
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"advance".to_vec(),
                    vec![1],
                )],
            ))
            .unwrap();

        assert!(matches!(
            authority.validate_snapshot_for_effect(&duplicate),
            Err(JournalError::StaleAuthoritySnapshot),
        ));
        assert!(matches!(
            authority.validate_snapshot_for_effect(&original.duplicate_provenance()),
            Err(JournalError::StaleAuthoritySnapshot),
        ));
    }

    fn read_only_test_open(
        path: &Path,
    ) -> Result<(Journal, ReadOnlyJournalNameWitness), JournalError> {
        let directory = File::open(path)?;
        let uid = directory.metadata()?.uid();

        let (readback, _) = Journal::open_read_only_protected_directory(
            path,
            directory,
            "protected.journal",
            JournalLimits::default(),
            uid,
        )?;
        Ok(readback.into_parts())
    }

    #[test]
    fn read_only_replay_coexists_with_writer_lock_and_rejects_stale_head() {
        let directory = TestDirectory::new("read-only-stale-head");
        let (mut writer, _) = protected_open(&directory.0).unwrap();
        writer
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"head".to_vec(),
                    b"first".to_vec(),
                )],
            ))
            .unwrap();

        let (read_only, witness) = read_only_test_open(&directory.0).unwrap();
        assert_eq!(
            read_only.get(RecordNamespace::DesiredState, b"head"),
            Some(b"first".as_slice()),
        );
        witness
            .check_in_directory(&File::open(&directory.0).unwrap())
            .unwrap();

        writer
            .commit(&transaction(
                2,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"head".to_vec(),
                    b"second".to_vec(),
                )],
            ))
            .unwrap();
        assert!(matches!(
            witness.check_in_directory(&File::open(&directory.0).unwrap()),
            Err(JournalError::StaleAuthoritySnapshot),
        ));
    }

    #[test]
    fn read_only_replay_rejects_replaced_names_and_symlinks() {
        let directory = TestDirectory::new("read-only-names");
        let (writer, _) = protected_open(&directory.0).unwrap();
        let (_read_only, witness) = read_only_test_open(&directory.0).unwrap();
        drop(writer);

        let replacement = directory.0.join("replacement");
        fs::write(&replacement, b"").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, directory.0.join("protected.journal")).unwrap();
        assert!(
            witness
                .check_in_directory(&File::open(&directory.0).unwrap())
                .is_err()
        );

        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        symlink(
            "protected.journal.lock",
            directory.0.join("protected.journal"),
        )
        .unwrap();
        assert!(
            witness
                .check_in_directory(&File::open(&directory.0).unwrap())
                .is_err()
        );

        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        symlink(
            "protected.journal",
            directory.0.join("protected.journal.lock"),
        )
        .unwrap();
        assert!(
            witness
                .check_in_directory(&File::open(&directory.0).unwrap())
                .is_err()
        );
    }

    #[test]
    fn read_only_replay_rejects_lock_and_directory_replacement() {
        let directory = TestDirectory::new("read-only-lock");
        let (writer, _) = protected_open(&directory.0).unwrap();
        let (_read_only, witness) = read_only_test_open(&directory.0).unwrap();
        drop(writer);

        let replacement = directory.0.join("replacement.lock");
        fs::write(&replacement, b"").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, directory.0.join("protected.journal.lock")).unwrap();
        assert!(
            witness
                .check_in_directory(&File::open(&directory.0).unwrap())
                .is_err()
        );

        let other = TestDirectory::new("read-only-other-directory");
        fs::set_permissions(&other.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            witness.check_in_directory(&File::open(&other.0).unwrap()),
            Err(JournalError::ProtectedBoundary),
        ));
    }

    #[test]
    fn read_only_replay_rejects_tail_without_repairing_it() {
        let directory = TestDirectory::new("read-only-tail");
        let (writer, _) = protected_open(&directory.0).unwrap();
        drop(writer);
        let path = directory.0.join("protected.journal");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let length = fs::metadata(&path).unwrap().len();

        assert!(matches!(
            read_only_test_open(&directory.0),
            Err(JournalError::MalformedTransaction(_)),
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
    }

    #[test]
    fn service_ancestry_only_transitions_from_root_to_exact_owner() {
        let directory_mode = rustix::fs::FileType::Directory.as_raw_mode() | 0o755;
        for owners in [vec![0, 0, 1000, 1000], vec![1000, 1000]] {
            let mut policy = ProtectedAncestry::new(1000);
            for uid in owners {
                policy
                    .admit_metadata::<crate::journal::JournalError>(uid, directory_mode)
                    .unwrap();
            }
        }
        for owners in [vec![0, 1001], vec![0, 1000, 1001], vec![0, 1000, 0]] {
            let mut policy = ProtectedAncestry::new(1000);
            let mut rejected = false;
            for uid in owners {
                if policy
                    .admit_metadata::<crate::journal::JournalError>(uid, directory_mode)
                    .is_err()
                {
                    rejected = true;
                    break;
                }
            }
            assert!(rejected);
        }
        let mut root_only = ProtectedAncestry::new(0);
        root_only
            .admit_metadata::<crate::journal::JournalError>(0, directory_mode)
            .unwrap();
        root_only
            .admit_metadata::<crate::journal::JournalError>(0, directory_mode)
            .unwrap();
        assert!(
            root_only
                .admit_metadata::<crate::journal::JournalError>(1000, directory_mode)
                .is_err()
        );
    }

    #[test]
    fn service_ancestry_rejects_writable_directories_and_non_directories() {
        for owner in [0, 1000] {
            for mode in [0o722, 0o770, 0o777, 0o1777] {
                let mut policy = ProtectedAncestry::new(1000);
                assert!(
                    policy
                        .admit_metadata::<crate::journal::JournalError>(
                            owner,
                            rustix::fs::FileType::Directory.as_raw_mode() | mode
                        )
                        .is_err()
                );
            }
            let mut policy = ProtectedAncestry::new(1000);
            assert!(
                policy
                    .admit_metadata::<crate::journal::JournalError>(
                        owner,
                        rustix::fs::FileType::RegularFile.as_raw_mode() | 0o700
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn service_opener_never_skips_unsafe_absolute_ancestry() {
        let directory = TestDirectory::new("service-ancestry");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();
        let leaf = directory.0.join("private");
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        // The private test opener accepts this leaf, but production must reject
        // its writable ancestor regardless of the leaf's owner and mode. The
        // fixture owns that ancestor; no property of the host TMPDIR is assumed.
        assert!(matches!(
            Journal::open_protected_at_for_uid(
                &leaf,
                "state.journal",
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
        for path in [
            "relative",
            "",
            "/",
            "/tmp//leaf",
            "/tmp/./leaf",
            "/tmp/../leaf",
        ] {
            assert!(matches!(
                Journal::open_protected_at_for_uid(
                    path,
                    "state.journal",
                    JournalLimits::default(),
                    uid,
                ),
                Err(JournalError::ProtectedBoundary)
            ));
        }
    }

    #[test]
    fn protected_writer_rejects_replaced_journal_and_lock_names() {
        let directory = TestDirectory::new("named-writer-currentness");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            "controller.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        assert!(journal.require_protected_names_current().is_ok());

        for name in ["controller.journal", "controller.journal.lock"] {
            let current = directory.0.join(name);
            let retained = directory.0.join(format!("{name}.retained"));
            fs::rename(&current, &retained).unwrap();
            fs::write(&current, []).unwrap();
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                journal.require_protected_names_current(),
                Err(JournalError::StaleAuthoritySnapshot)
            ));
            fs::remove_file(&current).unwrap();
            fs::rename(&retained, &current).unwrap();
            assert!(journal.require_protected_names_current().is_ok());
        }
    }

    #[test]
    fn fixture_named_writer_cut_rejects_replacements_wrong_owner_and_poison() {
        let directory = TestDirectory::new("fixture-named-writer-cut");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            "state.journal",
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        journal
            .validate_held_protected_at_uid_for_test(&directory.0, "state.journal", uid)
            .unwrap();
        assert!(
            journal
                .validate_held_protected_at_uid_for_test(&directory.0, "state.journal", uid + 1)
                .is_err()
        );

        for name in ["state.journal", "state.journal.lock"] {
            let current = directory.0.join(name);
            let retained = directory.0.join(format!("{name}.retained"));
            fs::rename(&current, &retained).unwrap();
            fs::write(&current, []).unwrap();
            fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                journal
                    .validate_held_protected_at_uid_for_test(&directory.0, "state.journal", uid)
                    .is_err()
            );
            fs::remove_file(&current).unwrap();
            fs::rename(&retained, &current).unwrap();
        }

        let retained = directory.0.with_extension("retained");
        fs::rename(&directory.0, &retained).unwrap();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            journal
                .validate_held_protected_at_uid_for_test(&directory.0, "state.journal", uid)
                .is_err()
        );
        fs::remove_dir(&directory.0).unwrap();
        fs::rename(&retained, &directory.0).unwrap();

        journal.native.poison();
        assert!(matches!(
            journal.validate_held_protected_at_uid_for_test(&directory.0, "state.journal", uid),
            Err(JournalError::Poisoned)
        ));
    }

    #[test]
    fn existing_protected_opener_neither_creates_names_nor_repairs_tail() {
        let directory = TestDirectory::new("existing-only");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits::default();

        assert!(
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid,)
                .is_err()
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);

        let (mut provisioned, _) =
            Journal::open_protected_at_uid(&directory.0, "state.journal", limits, uid).unwrap();
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![2],
                vec![3],
            )],
        )
        .unwrap();
        provisioned.commit(&transaction).unwrap();
        let sequence = provisioned.snapshot_sequence();
        drop(provisioned);

        let path = directory.0.join("state.journal");
        let temporary = directory.0.join("state.journal.compact.tmp");
        let journal_bytes = fs::read(&path).unwrap();
        fs::write(&temporary, b"uncommitted replacement").unwrap();
        assert!(
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid,)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), journal_bytes);
        assert_eq!(fs::read(&temporary).unwrap(), b"uncommitted replacement");
        fs::remove_file(&temporary).unwrap();
        symlink("state.journal", &temporary).unwrap();
        assert!(
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid,)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), journal_bytes);
        assert!(
            fs::symlink_metadata(&temporary)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&temporary).unwrap();

        let (reopened, report) =
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid)
                .unwrap();
        assert_eq!(reopened.snapshot_sequence(), sequence);
        assert_eq!(report.truncated_bytes, 0);
        reopened.validate_held_protected_names().unwrap();

        let moved = directory.0.join("moved.journal");
        fs::rename(&path, &moved).unwrap();
        assert!(reopened.validate_held_protected_names().is_err());
        fs::rename(&moved, &path).unwrap();
        drop(reopened);

        let lock_path = directory.0.join("state.journal.lock");
        fs::remove_file(&lock_path).unwrap();
        assert!(
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid,)
                .is_err()
        );
        assert!(!lock_path.exists());
        let (restored, _) =
            Journal::open_protected_at_uid(&directory.0, "state.journal", limits, uid).unwrap();
        drop(restored);

        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            Journal::open_existing_protected_at_uid(&directory.0, "state.journal", limits, uid),
            Err(JournalError::MalformedTransaction(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn protected_open_rejects_public_modes_and_symlinks() {
        let directory = TestDirectory::new("protected-rejections");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                "protected.journal",
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.0.join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, directory.0.join("protected.journal")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::write(directory.0.join("protected.journal"), b"").unwrap();
        fs::set_permissions(
            directory.0.join("protected.journal"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        symlink(&target, directory.0.join("protected.journal.lock")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        fs::create_dir(directory.0.join("protected.journal")).unwrap();
        assert!(protected_open(&directory.0).is_err());
        fs::remove_dir(directory.0.join("protected.journal")).unwrap();

        fs::hard_link(&target, directory.0.join("protected.journal")).unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal")).unwrap();
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();
        fs::hard_link(&target, directory.0.join("protected.journal.lock")).unwrap();
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::ProtectedBoundary)
        ));
        fs::remove_file(directory.0.join("protected.journal.lock")).unwrap();

        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                "protected.journal",
                JournalLimits::default(),
                uid.wrapping_add(1),
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        let alias = directory.0.with_extension("symlink");
        symlink(&directory.0, &alias).unwrap();
        assert!(
            Journal::open_protected_at_uid(
                &alias,
                "another.journal",
                JournalLimits::default(),
                uid,
            )
            .is_err()
        );
        fs::remove_file(alias).unwrap();

        let maximum_name = "j".repeat(MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES);
        let (mut journal, _) = Journal::open_protected_at_uid(
            &directory.0,
            &maximum_name,
            JournalLimits::default(),
            uid,
        )
        .unwrap();
        journal.compact().unwrap();
        drop(journal);
        assert!(matches!(
            Journal::open_protected_at_uid(
                &directory.0,
                &"j".repeat(MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES + 1),
                JournalLimits::default(),
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn protected_traversal_rejects_untrusted_ancestors_and_relative_paths() {
        assert!(matches!(
            Journal::open_protected_at(
                "relative/protected",
                "state.journal",
                JournalLimits::default(),
            ),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            Journal::open_protected_at(
                "/tmp//ambiguous",
                "state.journal",
                JournalLimits::default(),
            ),
            Err(JournalError::ProtectedBoundary)
        ));

        let root = TestDirectory::new("protected-ancestry");
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&root.0).unwrap().uid();
        fs::create_dir(root.0.join("trusted")).unwrap();
        fs::set_permissions(root.0.join("trusted"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.0.join("trusted/final")).unwrap();
        fs::set_permissions(
            root.0.join("trusted/final"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let directory = traverse_protected_directory::<crate::journal::JournalError>(
            File::open(&root.0).unwrap(),
            [b"trusted".as_slice(), b"final".as_slice()],
            uid,
        )
        .unwrap();
        let (journal, _) = Journal::open_protected_directory(
            &root.0.join("trusted/final"),
            directory,
            "state.journal",
            JournalLimits::default(),
            ProtectedOwnerPolicy::Exact(uid),
            true,
        )
        .unwrap();
        drop(journal);

        fs::create_dir(root.0.join("writable")).unwrap();
        fs::set_permissions(root.0.join("writable"), fs::Permissions::from_mode(0o777)).unwrap();
        fs::create_dir(root.0.join("writable/final")).unwrap();
        fs::set_permissions(
            root.0.join("writable/final"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(matches!(
            traverse_protected_directory::<crate::journal::JournalError>(
                File::open(&root.0).unwrap(),
                [b"writable".as_slice(), b"final".as_slice()],
                uid,
            ),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn protected_open_errors_distinguish_policy_and_kernel_support() {
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::LOOP),
            JournalError::ProtectedBoundary
        ));
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::XDEV),
            JournalError::ProtectedBoundary
        ));
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::NOSYS),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::PERM),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::INVAL),
            JournalError::UnsupportedProtectedOpen
        ));
        assert!(matches!(
            protected_open_error::<crate::journal::JournalError>(rustix::io::Errno::NOENT),
            JournalError::Io(_)
        ));
    }

    #[test]
    fn protected_lock_custody_loan_outlives_writer_without_becoming_a_writer() {
        let directory = TestDirectory::new("protected-lock-loan");
        let (journal, _) = protected_open(&directory.0).unwrap();
        let loan = journal.loan_protected_lock_custody().unwrap();
        let metadata = fs::metadata(directory.0.join("protected.journal.lock")).unwrap();
        assert_eq!(
            loan.identity().unwrap(),
            (metadata.dev(), metadata.ino(), metadata.uid())
        );
        drop(journal);

        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::AlreadyLocked)
        ));
        drop(loan);
        let (journal, report) = protected_open(&directory.0).unwrap();
        assert_eq!(report.committed_transactions, 0);
        assert_eq!(journal.get(RecordNamespace::DesiredState, b"key"), None);
    }

    #[test]
    fn protected_lock_custody_loan_rejects_replaced_names_and_unprotected_writer() {
        let directory = TestDirectory::new("protected-lock-loan-replaced");
        let (journal, _) = protected_open(&directory.0).unwrap();
        fs::rename(
            directory.0.join("protected.journal.lock"),
            directory.0.join("old.lock"),
        )
        .unwrap();
        assert!(journal.loan_protected_lock_custody().is_err());

        let (unprotected, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        assert!(unprotected.loan_protected_lock_custody().is_err());
    }

    #[test]
    fn protected_lock_custody_rejects_data_and_read_only_descriptions() {
        let directory = TestDirectory::new("protected-lock-loan-shape");
        let (journal, _) = protected_open(&directory.0).unwrap();
        let loan = journal.loan_protected_lock_custody().unwrap();
        loan.lock.set_len(1).unwrap();
        assert!(loan.identity().is_err());
        assert!(journal.loan_protected_lock_custody().is_err());
        loan.lock.set_len(0).unwrap();

        let read_only = ProtectedJournalLockCustodyV1 {
            lock: File::open(directory.0.join("protected.journal.lock")).unwrap(),
        };
        assert!(read_only.identity().is_err());
        assert!(loan.identity().is_ok());
    }

    #[test]
    fn protected_files_are_private_locked_and_compact_fd_relatively() {
        let directory = TestDirectory::new("protected-compact");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            fs::metadata(directory.0.join("protected.journal"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.0.join("protected.journal.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            protected_open(&directory.0),
            Err(JournalError::AlreadyLocked)
        ));
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();

        let moved = directory.0.with_extension("retained");
        fs::rename(&directory.0, &moved).unwrap();
        fs::create_dir(&directory.0).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        journal.compact().unwrap();
        assert!(moved.join("protected.journal").exists());
        assert!(!directory.0.join("protected.journal").exists());
        drop(journal);
        fs::remove_dir(&directory.0).unwrap();
        fs::rename(&moved, &directory.0).unwrap();
        let (journal, _) = protected_open(&directory.0).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"key"),
            Some(b"value".as_slice())
        );
    }

    #[test]
    fn protected_open_removes_bounded_stale_temp_without_reusing_it() {
        let directory = TestDirectory::new("protected-stale-temp");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let temporary = directory.0.join("protected.journal.compact.tmp");
        fs::write(&temporary, b"partial prior compaction").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(!temporary.exists());
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();
        journal.compact().unwrap();
        assert!(!temporary.exists());
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"key"),
            Some(b"value".as_slice())
        );
        drop(journal);

        let victim = directory.0.join("victim");
        fs::write(&victim, b"must remain unchanged").unwrap();
        symlink(&victim, &temporary).unwrap();
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(!temporary.exists());
        journal.compact().unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");
        assert!(!temporary.exists());
    }

    #[test]
    fn protected_exclusive_temp_rejects_regular_and_symlink_collisions() {
        let directory = TestDirectory::new("protected-temp-collisions");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let directory_fd = File::open(&directory.0).unwrap();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let collision = directory.0.join("collision.tmp");
        fs::write(&collision, b"stale").unwrap();
        fs::set_permissions(&collision, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            open_protected_file::<crate::journal::JournalError>(
                &directory_fd,
                "collision.tmp",
                uid,
                true,
                true,
                true
            )
            .is_err()
        );
        assert_eq!(fs::read(&collision).unwrap(), b"stale");

        fs::remove_file(&collision).unwrap();
        let victim = directory.0.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, &collision).unwrap();
        assert!(
            open_protected_file::<crate::journal::JournalError>(
                &directory_fd,
                "collision.tmp",
                uid,
                true,
                true,
                true
            )
            .is_err()
        );
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn protected_compaction_cleans_bounded_temp_after_failure() {
        let directory = TestDirectory::new("protected-temp-cleanup");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap();
        journal.native.replace_limits_for_fixture(JournalLimits {
            maximum_journal_bytes: 1,
            ..journal.native.limits()
        });
        assert!(journal.compact().is_err());
        let names: Vec<_> = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.to_string_lossy().contains(".compact."))
        );
    }

    #[test]
    fn protected_reopen_truncates_a_partial_crash_tail() {
        let directory = TestDirectory::new("protected-crash-tail");
        let path = directory.0.join("protected.journal");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let committed_length = journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"key".to_vec(),
                    b"value".to_vec(),
                )],
            ))
            .unwrap()
            .durable_bytes;
        drop(journal);

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"partial-frame").unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (journal, report) = protected_open(&directory.0).unwrap();
        assert_eq!(report.committed_transactions, 1);
        assert_eq!(report.committed_records, 1);
        assert_eq!(report.truncated_bytes, 13);
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"key"),
            Some(b"value".as_slice())
        );
        assert_eq!(fs::metadata(path).unwrap().len(), committed_length);
    }

    fn commit_fixture(path: &Path) -> u64 {
        let (mut journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"sandbox-1".to_vec(),
                    b"running".to_vec(),
                )],
            ))
            .unwrap()
            .durable_bytes
    }

    #[test]
    fn committed_transactions_replay_atomically() {
        let directory = TestDirectory::new("replay");
        let path = directory.journal();
        let length = commit_fixture(&path);

        let (journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(report.committed_transactions, 1);
        assert_eq!(report.committed_records, 1);
        assert_eq!(report.truncated_bytes, 0);
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"sandbox-1"),
            Some(b"running".as_slice())
        );
        assert_eq!(fs::metadata(path).unwrap().len(), length);
    }

    #[test]
    fn partial_final_frame_is_removed_to_last_commit() {
        let directory = TestDirectory::new("partial");
        let path = directory.journal();
        let committed_length = commit_fixture(&path);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0xa5; HEADER_BYTES / 2]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (_, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(report.truncated_bytes, (HEADER_BYTES / 2) as u64);
        assert_eq!(fs::metadata(path).unwrap().len(), committed_length);
    }

    #[test]
    fn complete_corrupt_frame_fails_closed() {
        let directory = TestDirectory::new("checksum");
        let path = directory.journal();
        commit_fixture(&path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(HEADER_BYTES as u64)).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        assert!(matches!(
            Journal::open(path, JournalLimits::default()),
            Err(JournalError::ChecksumMismatch(_))
        ));
    }

    #[test]
    fn exact_idempotency_replay_and_conflict_survive_reopen() {
        let directory = TestDirectory::new("idempotency");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request-42".to_vec()).unwrap();
        let operation = OperationId::from_bytes([0x44; 16]);
        let digest = [0x11; 32];
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::idempotency(&key, digest, operation)],
            ))
            .unwrap();
        drop(journal);

        let (journal, _) = Journal::open(path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.check_idempotency(&key, digest),
            IdempotencyOutcome::Replay(operation)
        );
        assert_eq!(
            journal.check_idempotency(&key, [0x22; 32]),
            IdempotencyOutcome::Conflict
        );
    }

    #[test]
    fn compaction_batches_preserve_exact_native_bytes_and_literal_row_payloads() {
        let state = std::collections::BTreeMap::from([
            ((RecordNamespace::DesiredState, b"c".to_vec()), b"3".to_vec()),
            ((RecordNamespace::DesiredState, b"a".to_vec()), b"1".to_vec()),
            ((RecordNamespace::DesiredState, b"b".to_vec()), b"2".to_vec()),
        ]);
        let limits = JournalLimits {
            maximum_records_per_transaction: 2,
            maximum_transaction_bytes: 18,
            ..JournalLimits::default()
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();

        super::write_compacted(file.as_file_mut(), &state, limits).unwrap();

        let first = JournalTransaction::new(
            *b"\x01\0\0\0\0\0\0\0compact1",
            vec![
                JournalRecord::put(RecordNamespace::DesiredState, b"a".to_vec(), b"1".to_vec()),
                JournalRecord::put(RecordNamespace::DesiredState, b"b".to_vec(), b"2".to_vec()),
            ],
        )
        .unwrap();
        let last = JournalTransaction::new(
            *b"\x02\0\0\0\0\0\0\0compact1",
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"c".to_vec(),
                b"3".to_vec(),
            )],
        )
        .unwrap();
        let expected = [
            encode_transaction(&first, 1).unwrap(),
            encode_transaction(&last, 5).unwrap(),
        ]
        .concat()
        .concat();
        let actual = std::fs::read(file.path()).unwrap();
        assert_eq!(actual, expected);

        // Literal native record payloads independently specify field widths,
        // namespace byte, sorted row order, and the exact two chunk boundaries.
        let mut reader = std::io::Cursor::new(actual);
        let mut offset = 0;
        let mut frames = Vec::new();
        while let Some((frame, bytes)) =
            super::read_frame_retained(&mut reader, offset, 1024, None).unwrap()
        {
            frames.push(frame);
            offset += bytes;
        }
        assert_eq!(frames.len(), 7);
        assert_eq!(frames[0].payload, [2, 0, 0, 0]);
        assert_eq!(frames[1].payload, [1, 1, 0, 1, 0, 0, 0, b'a', b'1']);
        assert_eq!(frames[2].payload, [1, 1, 0, 1, 0, 0, 0, b'b', b'2']);
        assert_eq!(&frames[3].payload[..4], &[2, 0, 0, 0]);
        assert_eq!(frames[4].payload, [1, 0, 0, 0]);
        assert_eq!(frames[5].payload, [1, 1, 0, 1, 0, 0, 0, b'c', b'3']);
        assert_eq!(&frames[6].payload[..4], &[1, 0, 0, 0]);
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.sequence, index as u64 + 1);
            assert_eq!(
                frame.transaction_id,
                if index < 4 { *first.id() } else { *last.id() },
            );
        }
    }

    #[test]
    fn compaction_lookahead_representation_fails_before_previous_count_or_schema_and_write() {
        let state = std::collections::BTreeMap::from([
            ((RecordNamespace::Idempotency, b"a".to_vec()), vec![1; 47]),
            (
                (
                    RecordNamespace::Idempotency,
                    vec![b'z'; usize::from(u16::MAX) + 1],
                ),
                vec![1; 48],
            ),
        ]);
        let limits = JournalLimits {
            maximum_records_per_transaction: 1,
            maximum_transactions: 0,
            ..JournalLimits::default()
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();

        assert!(matches!(
            super::write_compacted(file.as_file_mut(), &state, limits),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn compaction_previous_batch_keeps_typed_idempotency_refusal_before_any_write() {
        let state = std::collections::BTreeMap::from([
            ((RecordNamespace::Idempotency, b"a".to_vec()), vec![1; 47]),
            ((RecordNamespace::Idempotency, b"b".to_vec()), vec![1; 48]),
        ]);
        let limits = JournalLimits {
            maximum_records_per_transaction: 1,
            ..JournalLimits::default()
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();

        assert!(matches!(
            super::write_compacted(file.as_file_mut(), &state, limits),
            Err(JournalError::MalformedRecord("invalid idempotency decision")),
        ));
        assert_eq!(file.as_file().metadata().unwrap().len(), 0);
    }

    #[test]
    fn compaction_later_configured_key_refusal_retains_the_original_prior_native_chunk() {
        let state = std::collections::BTreeMap::from([
            ((RecordNamespace::DesiredState, b"a".to_vec()), b"1".to_vec()),
            ((RecordNamespace::DesiredState, b"bb".to_vec()), b"2".to_vec()),
        ]);
        let limits = JournalLimits {
            maximum_records_per_transaction: 1,
            maximum_key_bytes: 1,
            ..JournalLimits::default()
        };
        let mut file = tempfile::NamedTempFile::new().unwrap();

        assert!(matches!(
            super::write_compacted(file.as_file_mut(), &state, limits),
            Err(JournalError::LimitExceeded("record key bytes")),
        ));

        let first = JournalTransaction::new(
            *b"\x01\0\0\0\0\0\0\0compact1",
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"a".to_vec(),
                b"1".to_vec(),
            )],
        )
        .unwrap();
        assert_eq!(
            std::fs::read(file.path()).unwrap(),
            encode_transaction(&first, 1).unwrap().concat(),
        );
    }

    #[test]
    fn compaction_preserves_only_materialized_values_and_indexes() {
        let directory = TestDirectory::new("compact");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request".to_vec()).unwrap();
        let operation = OperationId::from_bytes([0x33; 16]);
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        b"resource".to_vec(),
                        b"old".to_vec(),
                    ),
                    JournalRecord::idempotency(&key, [0x55; 32], operation),
                ],
            ))
            .unwrap();
        journal
            .commit(&transaction(
                2,
                vec![JournalRecord::put(
                    RecordNamespace::DesiredState,
                    b"resource".to_vec(),
                    b"new".to_vec(),
                )],
            ))
            .unwrap();
        journal.compact().unwrap();
        drop(journal);

        let (journal, report) = Journal::open(path, JournalLimits::default()).unwrap();
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"resource"),
            Some(b"new".as_slice())
        );
        assert_eq!(
            journal.check_idempotency(&key, [0x55; 32]),
            IdempotencyOutcome::Replay(operation)
        );
        assert_eq!(report.committed_records, 2);
    }

    #[test]
    fn a_second_owner_is_rejected() {
        let directory = TestDirectory::new("lock");
        let path = directory.journal();
        let (_journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(matches!(
            Journal::open(path, JournalLimits::default()),
            Err(JournalError::AlreadyLocked)
        ));
    }

    #[test]
    fn transaction_duplicate_keys_are_rejected_before_append() {
        let directory = TestDirectory::new("duplicate");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let record = JournalRecord::put(
            RecordNamespace::Operation,
            b"operation".to_vec(),
            b"accepted".to_vec(),
        );
        let error = journal
            .commit(&transaction(1, vec![record.clone(), record]))
            .unwrap_err();
        assert!(matches!(error, JournalError::DuplicateRecordKey));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn valid_uncommitted_tail_is_removed_and_sequence_is_reused() {
        let directory = TestDirectory::new("uncommitted");
        let path = directory.journal();
        let committed_length = commit_fixture(&path);
        let trailing = transaction(
            2,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"not-committed".to_vec(),
                b"invisible".to_vec(),
            )],
        );
        let frames = encode_transaction(&trailing, 4).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&frames[0]).unwrap();
        file.write_all(&frames[1]).unwrap();
        file.sync_data().unwrap();
        drop(file);

        let (mut journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert!(report.truncated_bytes > 0);
        assert_eq!(fs::metadata(&path).unwrap().len(), committed_length);
        assert_eq!(
            journal.get(RecordNamespace::DesiredState, b"not-committed"),
            None
        );
        let result = journal.commit(&trailing).unwrap();
        assert_eq!(result.commit_sequence, 6);
    }

    #[test]
    fn duplicate_transaction_identity_is_rejected() {
        let directory = TestDirectory::new("duplicate-transaction");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let first = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"one".to_vec(),
                b"accepted".to_vec(),
            )],
        );
        journal.commit(&first).unwrap();
        let duplicate = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"two".to_vec(),
                b"accepted".to_vec(),
            )],
        );
        assert!(matches!(
            journal.commit(&duplicate),
            Err(JournalError::DuplicateTransaction)
        ));
    }

    #[test]
    fn idempotency_decisions_cannot_be_rebound() {
        let directory = TestDirectory::new("idempotency-rebind");
        let path = directory.journal();
        let key = IdempotencyKey::new(b"request".to_vec()).unwrap();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal
            .commit(&transaction(
                1,
                vec![JournalRecord::idempotency(
                    &key,
                    [0x11; 32],
                    OperationId::from_bytes([0x22; 16]),
                )],
            ))
            .unwrap();
        let rebind = transaction(
            2,
            vec![JournalRecord::idempotency(
                &key,
                [0x33; 32],
                OperationId::from_bytes([0x44; 16]),
            )],
        );
        assert!(matches!(
            journal.commit(&rebind),
            Err(JournalError::IdempotencyConflict)
        ));
    }

    #[test]
    fn append_failure_poisons_handle_until_reopen() {
        let directory = TestDirectory::new("poison");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal.ensure_healthy().unwrap();
        journal.native.replace_file(
            OpenOptions::new().read(true).open(&path).unwrap(),
        );
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"resource".to_vec(),
                b"desired".to_vec(),
            )],
        );
        assert!(matches!(journal.commit(&entry), Err(JournalError::Io(_))));
        assert!(matches!(
            journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(
            journal.commit(&entry),
            Err(JournalError::Poisoned)
        ));
    }

    #[test]
    fn publisher_registry_rejects_unprotected_or_poisoned_journal() {
        use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
        use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

        let directory = TestDirectory::new("publisher-poison");
        let (mut unprotected, _) =
            Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        assert!(matches!(
            unprotected.ensure_protected_authority(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            PublisherPolicyStore::load(&mut unprotected, PublisherPolicyLimits::default()).is_err()
        );
        assert!(
            PublisherCapabilityRegistry::load(
                &mut unprotected,
                PublisherAuthorityLimits::default(),
            )
            .is_err()
        );

        let (mut journal, _) = protected_open(&directory.0).unwrap();
        assert!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),)
                .is_ok()
        );
        journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(directory.0.join("protected.journal"))
                .unwrap(),
        );
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"resource".to_vec(),
                b"desired".to_vec(),
            )],
        );
        assert!(matches!(journal.commit(&entry), Err(JournalError::Io(_))));
        assert!(matches!(
            journal.ensure_protected_authority(),
            Err(JournalError::Poisoned)
        ));
        assert!(
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).is_err()
        );
        assert!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default(),)
                .is_err()
        );

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        assert!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).is_ok()
        );
        assert!(
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default(),)
                .is_ok()
        );
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn poisoned_journal_blocks_holder_join_despite_cached_live_state() {
        use crate::publisher_authority::PublisherCapabilityRegistry;
        use crate::publisher_control::tests::join::{join_fixture, join_now, send_holder};
        use crate::publisher_control::{PublisherControlError, PublisherJoinError};
        use crate::publisher_ingress::PublisherIngressStore;

        let mut fixture = join_fixture();
        let capability = fixture.request.capability();
        let instance = fixture.registered.registration.fields().instance;
        {
            let capabilities = PublisherCapabilityRegistry::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.authority_limits,
            )
            .unwrap();
            assert_eq!(
                capabilities.resolve_current(capability).unwrap().id(),
                capability
            );
        }
        {
            let ingress = PublisherIngressStore::load(
                &mut fixture.registered.local.journal,
                fixture.join_policy.control.ingress_limits,
            )
            .unwrap();
            let pending = ingress
                .challenge(instance, fixture.request.challenge())
                .unwrap()
                .unwrap();
            assert_eq!(&pending.fields().request, &fixture.request);
        }
        let authority_before: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherAuthority)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let ingress_before: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherIngress)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        send_holder(&mut fixture.holder, &fixture.request);

        // An append/sync error is always durability-ambiguous to the service.
        // Keep the materialized capability and challenge maps in memory while
        // forcing the protected handle into its permanently poisoned state.
        fixture.registered.local.journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(
                    fixture
                        .registered
                        .local
                        .directory
                        .path()
                        .join("issuance.journal"),
                )
                .unwrap(),
        );
        let failed = transaction(
            0xee,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"holder-join-poison".to_vec(),
                b"must-not-authorize".to_vec(),
            )],
        );
        assert!(matches!(
            fixture.registered.local.journal.commit(&failed),
            Err(JournalError::Io(_))
        ));
        assert!(matches!(
            fixture
                .registered
                .local
                .journal
                .ensure_protected_authority(),
            Err(JournalError::Poisoned)
        ));

        assert!(matches!(
            join_now(&mut fixture),
            Err(PublisherJoinError::Control(PublisherControlError::Journal(
                JournalError::Poisoned
            )))
        ));
        assert_eq!(
            fixture.holders.capability_id(fixture.holder_id).unwrap(),
            capability,
            "the poisoned precheck must not consume and reinterpret the queued holder record"
        );
        let authority_after: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherAuthority)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        let ingress_after: Vec<_> = fixture
            .registered
            .local
            .journal
            .records(RecordNamespace::PublisherIngress)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(authority_after, authority_before);
        assert_eq!(ingress_after, ingress_before);
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn failed_local_issuance_commit_never_activates_a_session() {
        use crate::local_provisioning::LocalProvisioningError;
        use crate::local_provisioning::tests::{
            anchor, fixture, open_journal, provision_samples, sample, sessions,
        };
        use crate::publisher_authority::{
            PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
        };

        let mut fixture = fixture(true, true);
        let mut sessions = sessions();
        assert_eq!(
            fixture
                .journal
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0,
        );
        // Preserve the healthy protected journal and policy state while making
        // the first issuance append fail before any bytes can be written.
        fixture.journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(fixture.directory.path().join("issuance.journal"))
                .unwrap(),
        );
        assert!(matches!(
            provision_samples(&mut fixture, &mut sessions, vec![Ok(sample(150, 1000))]),
            Err(LocalProvisioningError::Authority(
                PublisherAuthorityError::Journal(JournalError::Io(_))
            ))
        ));
        assert!(matches!(
            fixture.journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        assert!(matches!(
            PublisherCapabilityRegistry::load(
                &mut fixture.journal,
                PublisherAuthorityLimits::default(),
            ),
            Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
        ));
        // Capacity is exactly one. A new preparation can succeed only if the
        // failed operation neither activated a session nor retained its slot.
        let pending = sessions.prepare(fixture.scope, anchor()).unwrap();
        drop(pending);

        let directory = fixture.directory.path().to_path_buf();
        drop(fixture.journal);
        let reopened = open_journal(&directory);
        assert_eq!(
            reopened
                .records(RecordNamespace::PublisherAuthority)
                .count(),
            0
        );
        // Replay, not the poisoned in-memory view, establishes that this
        // injected pre-write failure committed neither capability nor audit.
        reopened.ensure_protected_authority().unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "kernel-tests"))]
    #[test]
    fn failed_publisher_registration_commit_retires_execution_pin() {
        use crate::local_provisioning::tests::{anchor, fixture, open_journal, sample};
        use crate::publisher_control::{PublisherControlError, PublisherControlPolicy};
        use crate::publisher_ingress::{PublisherIngressError, PublisherIngressLimits};
        use crate::publisher_sessions::{
            PublisherSessionError, PublisherSessionLimits, PublisherSessionRegistry,
            PublisherSessionScope,
        };
        use aos_sandbox_linux::seqpacket::RecordSubjectListener;
        use rustix::net::{
            AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
        };

        let mut fixture = fixture(true, true);
        let socket_directory = tempfile::tempdir().unwrap();
        let path = socket_directory.path().join("publisher.sock");
        let mut listener = RecordSubjectListener::bind(&path, 2).unwrap();
        let sender = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        connect(&sender, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        let scope = PublisherSessionScope {
            principal: fixture.scope.holder,
            node: aos_sandbox_core::NodeId::from_bytes([0x73; 16]),
            project: fixture.scope.project,
            cache_resource: fixture.scope.cache_resource,
        };
        let config = PublisherControlPolicy {
            clock_provenance: fixture.config.clock_provenance,
            maximum_challenge_seconds: 60,
            policy_limits: fixture.config.policy_limits,
            ingress_limits: PublisherIngressLimits::default(),
        };
        let mut sessions = PublisherSessionRegistry::new(PublisherSessionLimits {
            maximum_sessions: 1,
        })
        .unwrap();
        // Keep protected policy real, but fail the append before any write.
        // The caller cannot assume that every possible I/O failure is pre-write.
        fixture.journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(fixture.directory.path().join("issuance.journal"))
                .unwrap(),
        );
        assert!(matches!(
            crate::publisher_control::register(
                &mut fixture.journal,
                &mut sessions,
                &mut listener,
                scope,
                anchor(),
                None,
                config,
                &mut || Ok(sample(150, 1000)),
            ),
            Err(PublisherControlError::Ingress(
                PublisherIngressError::Journal(JournalError::Io(_))
            ))
        ));
        assert!(matches!(
            fixture.journal.ensure_healthy(),
            Err(JournalError::Poisoned)
        ));
        // No instance greeting escaped, but the exact process pin still reserves
        // this service: an ambiguous commit cannot make it available for reuse.
        assert!(matches!(
            sessions.prepare(&mut listener, scope, anchor()),
            Err(PublisherSessionError::ServiceReserved)
        ));

        let directory = fixture.directory.path().to_path_buf();
        drop(fixture.journal);
        let reopened = open_journal(&directory);
        assert_eq!(
            reopened.records(RecordNamespace::PublisherIngress).count(),
            0
        );
        reopened.ensure_protected_authority().unwrap();
    }

    #[test]
    fn failed_capability_revocation_denies_reads_until_protected_replay() {
        use crate::publisher_authority::{
            PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
        };

        let directory = TestDirectory::new("publisher-revocation-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let id = aos_sandbox_core::CapabilityId::new();
        let capability = crate::publisher_authority::tests::capability(id, 200);
        PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default())
            .unwrap()
            .install_from_trusted_controller([1; 16], capability.clone())
            .unwrap();

        journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(directory.0.join("protected.journal"))
                .unwrap(),
        );
        {
            let mut registry = PublisherCapabilityRegistry::load(
                &mut journal,
                PublisherAuthorityLimits::default(),
            )
            .unwrap();
            assert_eq!(registry.resolve_current(id).unwrap(), capability);
            assert!(matches!(
                registry.revoke_from_trusted_controller([2; 16], id),
                Err(PublisherAuthorityError::Journal(JournalError::Io(_))),
            ));
            assert!(matches!(
                registry.resolve_current(id),
                Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
            ));
        }
        assert!(matches!(
            PublisherCapabilityRegistry::load(&mut journal, PublisherAuthorityLimits::default()),
            Err(PublisherAuthorityError::Journal(JournalError::Poisoned)),
        ));

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        let registry =
            PublisherCapabilityRegistry::load(&mut reopened, PublisherAuthorityLimits::default())
                .unwrap();
        // The injected descriptor rejected the write before any bytes reached
        // disk. Only protected replay, not the stale in-memory snapshot, may
        // therefore restore this still-active record.
        assert_eq!(registry.resolve_current(id).unwrap(), capability);
    }

    #[test]
    fn failed_controller_generation_update_denies_policy_reads_until_replay() {
        use crate::publisher_policy::{
            PublisherControllerHeadV1, PublisherPolicyError, PublisherPolicyLimits,
            PublisherPolicyStore,
        };

        let directory = TestDirectory::new("publisher-policy-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let first = PublisherControllerHeadV1 {
            principal: aos_sandbox_core::PrincipalId::new(),
            generation: 1,
        };
        PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())
            .unwrap()
            .advance_controller_from_trusted_controller([1; 16], None, first)
            .unwrap();

        journal.native.replace_file(
            OpenOptions::new()
                .read(true)
                .open(directory.0.join("protected.journal"))
                .unwrap(),
        );
        {
            let mut policies =
                PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()).unwrap();
            assert_eq!(policies.controller_head().unwrap(), Some(first));
            assert!(matches!(
                policies.advance_controller_from_trusted_controller(
                    [2; 16],
                    Some(1),
                    PublisherControllerHeadV1 {
                        generation: 2,
                        ..first
                    },
                ),
                Err(PublisherPolicyError::Journal(JournalError::Io(_))),
            ));
            assert!(matches!(
                policies.controller_head(),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.current_policy(aos_sandbox_core::ProjectId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.revocation_head(aos_sandbox_core::RevocationScopeId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.resource_binding(aos_sandbox_core::ResourceId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
        }
        assert!(matches!(
            PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default()),
            Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
        ));

        drop(journal);
        let (mut reopened, _) = protected_open(&directory.0).unwrap();
        let policies =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert_eq!(policies.controller_head().unwrap(), Some(first));
    }

    #[test]
    fn materialized_limit_rejects_before_writing() {
        let directory = TestDirectory::new("materialized-limit");
        let path = directory.journal();
        let limits = JournalLimits {
            maximum_materialized_bytes: 4,
            ..JournalLimits::default()
        };
        let (mut journal, _) = Journal::open(&path, limits).unwrap();
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"key".to_vec(),
                b"value".to_vec(),
            )],
        );
        assert!(matches!(
            journal.commit(&entry),
            Err(JournalError::LimitExceeded("materialized state bytes"))
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn preflight_checks_an_ordered_append_without_mutating_the_journal() {
        let directory = TestDirectory::new("preflight-sequence");
        let path = directory.journal();
        let first = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"first".to_vec(),
                vec![1; 32],
            )],
        );
        let future = transaction(
            2,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"future".to_vec(),
                vec![2; 64],
            )],
        );
        let first_bytes = encode_transaction(&first, 1)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum::<usize>();
        let future_bytes = encode_transaction(&future, 4)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum::<usize>();
        let limits = JournalLimits {
            maximum_journal_bytes: u64::try_from(first_bytes + future_bytes - 1).unwrap(),
            ..JournalLimits::default()
        };
        let (mut journal, _) = Journal::open(&path, limits).unwrap();
        journal.commit(&first).unwrap();
        let length = fs::metadata(&path).unwrap().len();
        let sequence = journal.snapshot_sequence();

        assert!(matches!(
            journal.preflight_transactions(std::slice::from_ref(&future)),
            Err(JournalError::JournalTooLarge)
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), length);
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert!(journal.get(RecordNamespace::Operation, b"future").is_none());
    }

    #[test]
    fn sequence_exhaustion_is_rejected_before_any_frame_is_written() {
        let directory = TestDirectory::new("sequence-exhaustion-prewrite");
        let path = directory.journal();
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        journal.native.replace_next_sequence_for_fixture(u64::MAX - 2);
        let entry = transaction(
            1,
            vec![JournalRecord::put(
                RecordNamespace::Operation,
                b"operation".to_vec(),
                b"prepared".to_vec(),
            )],
        );

        assert!(matches!(
            journal.commit(&entry),
            Err(JournalError::SequenceExhausted)
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
        assert!(
            journal
                .get(RecordNamespace::Operation, b"operation")
                .is_none()
        );
    }

    #[test]
    fn every_transaction_frame_boundary_recovers_atomically() {
        let records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                b"sandbox".to_vec(),
                b"running".to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Operation,
                b"operation".to_vec(),
                b"applying".to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                b"effect".to_vec(),
                b"planned".to_vec(),
            ),
        ];
        let transaction = transaction(1, records);
        let frames = encode_transaction(&transaction, 1).unwrap();

        for persisted_frames in 0..=frames.len() {
            let directory = TestDirectory::new(&format!("frame-boundary-{persisted_frames}"));
            let path = directory.journal();
            let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
            drop(journal);

            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            for frame in frames.iter().take(persisted_frames) {
                file.write_all(frame).unwrap();
            }
            file.sync_data().unwrap();
            drop(file);

            let (journal, report) = Journal::open(&path, JournalLimits::default()).unwrap();
            if persisted_frames == frames.len() {
                assert_eq!(report.committed_transactions, 1);
                assert_eq!(
                    journal.get(RecordNamespace::DesiredState, b"sandbox"),
                    Some(b"running".as_slice())
                );
                assert_eq!(
                    journal.get(RecordNamespace::Operation, b"operation"),
                    Some(b"applying".as_slice())
                );
                assert_eq!(
                    journal.get(RecordNamespace::Effect, b"effect"),
                    Some(b"planned".as_slice())
                );
            } else {
                assert_eq!(report.committed_transactions, 0);
                assert!(report.truncated_bytes > 0 || persisted_frames == 0);
                assert_eq!(journal.get(RecordNamespace::DesiredState, b"sandbox"), None);
                assert_eq!(fs::metadata(path).unwrap().len(), 0);
            }
        }
    }
}
