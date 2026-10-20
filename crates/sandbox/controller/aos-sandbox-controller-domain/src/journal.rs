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
//! The private `original_release_capture` group owns Release observation,
//! comparison, retained first causes and copy budgets; capture fields stay here.
//! The Linux-only `controller` owner retains Controller journal admission,
//! node identity binding, fixed limits, and the original paid writer construction.

use crate::journal::semantic_append::{AppendScope, PreflightScope};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_ledger_replay::replay::source_original::cache::SourceOriginalReplayDataV5;

#[cfg(test)]
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aos_sandbox_model::{ObjectDigest, OperationId};
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
use aos_sandbox_journal::storage::JournalReadIdentityDataV1;
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, IdempotencyDecisionV1 as IdempotencyDecision,
};
use aos_sandbox_journal::transaction::{self, NativePendingTransaction};

#[cfg(target_os = "linux")]
pub mod controller;

#[cfg(target_os = "linux")]
pub(crate) struct JournalShape {
    pub(crate) retained_bytes: usize,
    pub(crate) cells: usize,
    pub(crate) native_bytes: u64,
    pub(crate) maximum_transaction_bytes: usize,
    pub(crate) maximum_record_bytes: usize,
}

mod delete_batch;
mod new_use;
#[cfg(target_os = "linux")]
pub(crate) mod inventory_native;
#[cfg(target_os = "linux")]
pub(crate) mod delete_storage_preparation;
mod runtime_history_read;
#[cfg(target_os = "linux")]
mod start_assignment_receiving;
mod delete_resource_signing;
mod semantic_append;
pub use semantic_append::ProtectedJournalPreflightOriginalV2;

#[cfg(target_os = "linux")]
pub(crate) use semantic_append::delete::{
    SourceDeleteSemanticScopeV1, DeletePlanningBaseCutsDataV2,
    SourceDeleteMetadataRequestDataV2, SourceDeleteMetadataRequestErrorV2,
    DeleteDependencyGraphDataV2, SourceDeleteGraphErrorV2,
};
#[cfg(target_os = "linux")]
pub use semantic_append::delete::{DeleteInventorySessionAppendOriginalV1, DeleteInventorySessionAppendDisposalV1, DeleteInventoryIoDisposalV1, DeleteInventorySecurityShapeDataV1};
pub(crate) use semantic_append::delete::{SourceDeletePendingFenceV1, DeleteSourceFrontierClockV3};
pub(crate) use semantic_append::delete::SourceDeleteCompletionDisposalOriginalV4;
#[cfg(target_os = "linux")]
pub(crate) use semantic_append::delete::{SourceExecutionSemanticScopeV1, CompletedEnvironmentSourceAppendV1, QualifiedEnvironmentSourceViewV1};
mod native_backing;
pub use native_backing::JournalProtectedNativeResidencyV1;
#[cfg(target_os = "linux")]
mod source_construction;
#[cfg(target_os = "linux")]
pub(crate) use source_construction::SourceJournalConstructionOriginalsV1;
mod native_append;
#[cfg(target_os = "linux")]
mod native_interval;
#[cfg(target_os = "linux")]
mod native_compaction;
#[cfg(target_os = "linux")]
pub(crate) mod root_construction;
#[cfg(target_os = "linux")]
pub(crate) use native_backing::ControllerCoordinatorSelectionV1;
pub(crate) mod semantic_replay;
mod semantic_remainder;
mod ordinary_materialization;
mod ordinary_semantics;
mod ordinary_opening;
mod ordinary_reread;
use ordinary_reread::{ObservedReplayStateV1, replay_coordinator_observed_v1, replay_published_bytes_observed_v1};

#[cfg(target_os = "linux")]
mod network_session_replay;
#[cfg(target_os = "linux")]
pub use network_session_replay::NetworkSessionSemanticReplayOriginalV1;
#[doc(hidden)]
pub mod broker_session_receiving;
pub(crate) mod create_storage_history;
#[cfg(target_os = "linux")]
mod readonly_receiving;
#[cfg(target_os = "linux")]
mod root_controller_readonly;
#[cfg(target_os = "linux")]
pub(crate) use root_controller_readonly::{
    RootControllerReadonlyReceivingContextV1, root_controller_replay_fixed_controls_v1, ROOT_CONTROLLER_DIRECTORY_V1,
    ROOT_CONTROLLER_JOURNAL_V1,
};
#[cfg(target_os = "linux")]
mod root_controller_readonly_audit;
#[cfg(target_os = "linux")]
pub(crate) use root_controller_readonly_audit::{RootControllerReadonlyGeometryAuditV1, RootDeleteAuxiliaryRowDataV3, DeleteAdmissionAuditInputsDataV3};
#[cfg(target_os = "linux")]
use readonly_receiving::{CapturedReadonlyReceivingContextV1, ReadonlyReceivingContextV1};
#[cfg(target_os = "linux")]
mod create_storage_append;
mod execution_no_apply_settlement;
#[cfg(target_os = "linux")]
mod delete_admission;
#[cfg(target_os = "linux")]
pub(crate) use delete_admission::ControllerDeleteAdmissionOriginalV3;
pub(crate) use delete_admission::ControllerDeleteTerminalOriginalV4;
#[cfg(target_os = "linux")]
mod create_stopped_pre_ack;
#[cfg(target_os = "linux")]
mod create_stopped_terminal;
#[cfg(target_os = "linux")]
mod create_stopped_observer;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use create_stopped_observer::{CreateStoppedColdObserverOriginalV1, CreateStoppedColdObserverClosedV1};
#[cfg(target_os = "linux")]
pub(crate) use create_stopped_terminal::{
    LifecycleTerminalMetadataOriginalV4, start_terminal_receiving_demand_v2, stop_terminal_receiving_demand_v5,
    stop_cleanup_terminal_model_receiving_demand_v1,
    CreateStoppedControllerTerminalAppendOriginalV1, create_stopped_terminal_receiving_demand_v1,
    CreateStoppedMetadataTransitionOriginalV1, create_stopped_metadata_model_receiving_demand_v1,
};
#[cfg(target_os = "linux")]
pub(crate) use create_stopped_pre_ack::CreateStoppedControllerPreAckAppendOriginalV1;
pub(crate) mod source_provisioning;
#[cfg(target_os = "linux")]
mod operator_recover;
mod public_authorization_floor;
#[cfg(target_os = "linux")]
mod operator_recover_floor;
mod root_q04_inert_successor;
#[cfg(target_os = "linux")]
mod create_storage_position;
mod start_resource_completion;
pub(crate) use start_resource_completion::StartResourceNativePositionsOriginalV2;
#[cfg(target_os = "linux")]
pub(crate) use create_storage_position::{CreateStorageWriterPositionOriginalV1, create_storage_name_peak_demand_v1};
#[cfg(target_os = "linux")]
mod source_readonly_receiving;
#[cfg(target_os = "linux")]
pub(crate) use source_readonly_receiving::semantic_demand as source_readonly_semantic_demand_v1;
#[cfg(target_os = "linux")]
mod storage_prepare_clock;
#[cfg(target_os = "linux")]
pub(crate) mod storage_native_commit;
#[cfg(target_os = "linux")]
pub use storage_native_commit::{StorageStateNativeCommitAttemptV1, StorageStateNativeCommitClosedV1};
#[cfg(target_os = "linux")]
pub use storage_prepare_clock::StoragePrepareNativeClockCaptureV1;
#[cfg(target_os = "linux")]
mod original_release_capture;
#[cfg(target_os = "linux")]
mod receiving_demand;
#[cfg(target_os = "linux")]
mod append_receiving_demand;
#[cfg(target_os = "linux")]
pub use append_receiving_demand::JournalAppendReceivingDemandErrorV1;
#[cfg(target_os = "linux")]
mod semantic_receiving;
#[cfg(target_os = "linux")]
mod create_stopped_history;
#[cfg(target_os = "linux")]
mod original_currentness;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
mod cache_held_observation;
#[cfg(target_os = "linux")]
pub(crate) use cache_held_observation::CacheHeldWriterShapeV1;

#[cfg(target_os = "linux")]
use original_release_capture::native_release_replay_work_v1;
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
mod source_history;
mod cache_policy_hold;
pub(crate) use cache_policy_hold::{
    BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1,
};
#[cfg(target_os = "linux")]
pub(crate) use cache_policy_hold::CacheGitCoverageObservationV1;
mod capacity_reservation;
pub use capacity_reservation::native_held;
mod controller_policy_hold;
#[cfg(target_os = "linux")]
pub(crate) use controller_policy_hold::{
    RootControllerCreateAcceptanceOriginalsV1, RootControllerAcceptedNativeProgressV1,
};
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
pub(crate) use source_domain_policy_hold::q04_clear_recipe_digest_data as q04_source_clear_recipe_digest_data_v1;
mod source_project_admission_challenge;
pub(crate) mod source_tree_genesis;

pub(crate) use cache_policy_hold::NAME as CACHE_POLICY_HOLD_JOURNAL;

pub(crate) use capacity_reservation::capacity_reservation_identity_is_exact_v1;
pub(crate) use capacity_reservation::{
    first_source_successor_capacity_delete_v2, first_source_successor_capacity_identity_v2,
    first_source_successor_capacity_record_v2,
};
pub(crate) use source_tree_successor::FirstSourceSuccessorNativePhaseV2;

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
    ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1, ControllerPolicyV8EffectAckV1,
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

/// Carries configured initial-replay representation DATA before a protected open.
///
/// These separate terms describe logical bytes and inline representations, not
/// allocator RAM, a service budget, a paid loan, or permission to open. They may
/// overcount shared storage. Every consumer must also cover [`Self::unpriced`]
/// before treating an aggregate as a prepaid service extent.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedJournalPreopenReplayExtentV1 {
    /// Preserves the exact limits supplied to the native opener.
    pub limits: JournalLimits,
    /// Bounds the configured native prefix; this is disk input, not heap storage.
    pub native_bytes: u64,
    /// Reuses the original Release replay's logical map, frame and owner charge.
    pub native_replay_representation_bytes: usize,
    /// Identifies the physical-clipped pending term already included above.
    ///
    /// A complete initial receiving demand replaces this term with
    /// `declared_pending_record_bytes`; it does not omit the full BEGIN reserve.
    pub clipped_native_pending_record_bytes: usize,
    /// Covers reached frame Vec capacity plus the shared fixed read scratch.
    ///
    /// The incremental frame reader grows only after bytes are read; the full
    /// advertised payload is a wire limit, not an absent-byte allocation.
    pub native_frame_read_memory_bytes: usize,
    /// Preserves the unchanged advertised frame payload wire ceiling.
    pub maximum_advertised_payload_bytes: usize,
    /// Covers the full BEGIN reservation, irrespective of physical frame count.
    pub declared_pending_record_bytes: usize,
    /// Covers insertion of one extra transaction ID before count refusal.
    pub reached_transaction_id_bytes: usize,
    /// Covers intermediate map cells before all transaction deletions apply.
    pub reached_materialized_cell_bytes: usize,
    /// Bounds committed transactions reached before the count check can refuse.
    pub source_transactions: usize,
    /// Covers conservative inline cache copies, including the pending marker.
    pub source_cache_copies: usize,
    /// Bounds original checkpoint rows from this configured native file.
    pub source_checkpoint_rows: usize,
    /// Covers this file's original checkpoint rows and one independent copy.
    pub source_checkpoint_representation_bytes: usize,
    /// Covers initial cache owners whose physical-history collections stay empty.
    pub source_cache_metadata_bytes: usize,
    /// Covers inline native opener, replay, metadata, result and error owners.
    pub native_owner_result_bytes: usize,
    /// Requires independent bounds for all representations not priced here.
    pub unpriced: ProtectedJournalPreopenUnpricedPrerequisitesV1,
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
pub enum ProtectedJournalPreopenUnpricedPrerequisitesV1 {
    /// Requires conservative allocator, decoder/error and native/containment bounds.
    AllocatorDecoderErrorsNativePathsAndExternalChallenges,
}

/// Computes replay representation DATA for an already captured physical prefix.
///
/// The caller retains the genuine original metadata and bounds its reader to
/// this same length. A scalar alone authenticates neither that prefix nor a
/// payer. BEGIN count storage retains its full configured maximum independently
/// of the prefix; frame Vec capacity follows reached bytes plus fixed scratch.
///
/// # Errors
/// Rejects invalid limits, an excessive captured prefix, or checked overflow.
#[cfg(target_os = "linux")]
pub fn protected_journal_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits,
    native_prefix_bytes: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    validate_limits(limits)?;
    let limit = || JournalError::LimitExceeded("protected journal pre-open replay extent");
    if native_prefix_bytes > limits.maximum_journal_bytes {
        return Err(JournalError::JournalTooLarge);
    }
    let physical = usize::try_from(native_prefix_bytes).map_err(|_| limit())?;
    let frames = physical / HEADER_BYTES;
    let source_transactions = limits.maximum_transactions.checked_add(1)
        .ok_or_else(limit)?.min(frames);
    let source_checkpoint_rows = frames;
    let source_cache_copies = 3_usize;
    let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();

    // BEGIN reserves its bounded declared count before reading its records.
    // The shared frame reader instead grows only after actual bytes arrive;
    // its reached Vec capacity and fixed read scratch are already in Native work.
    let native_work = native_release_replay_work_v1(physical, limits)?;
    let native_replay_representation_bytes = native_work.replay_indexes
        .checked_add(native_work.pending_records)
        .and_then(|bytes| bytes.checked_add(native_work.frame_payload))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ObservedReplayStateV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(Vec<JournalRecord>, NativePendingTransaction)>()))
        .and_then(|bytes| bytes.checked_add(ordinary_reread::receiving_control_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalReleaseControllerCutCaptureV1>()))
        .ok_or_else(limit)?;
    let maximum_advertised_payload_bytes = limits.maximum_record_bytes.checked_add(7).ok_or_else(limit)?;
    let declared_pending_record_bytes = limits.maximum_records_per_transaction
        .checked_mul(std::mem::size_of::<JournalRecord>()).ok_or_else(limit)?;
    let reached_transaction_id_bytes = std::mem::size_of::<[u8; 16]>();
    let reached_materialized_cell_bytes = limits.maximum_records_per_transaction
        .checked_mul(map_entry).and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;

    // This runs independently of the optional external challenge witness.
    // Retain its committed-frame rows even when Source replay remains pending.
    let source_checkpoint_representation_bytes = source_checkpoint_rows
        .checked_mul(std::mem::size_of::<source_history::SourceOriginalChallengeCheckpointV5>())
        .and_then(|bytes| bytes.checked_add(physical))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;
    // replay_transaction(None) returns before origins, cuts, retirements or
    // their maps are retained. observe_compaction likewise only sets pending;
    // its temporary prospective map remains in the native replay allowance.
    let source_cache_metadata_bytes = std::mem::size_of::<source_history::replay::SourceOriginalReplayCacheV5>()
        .checked_mul(source_cache_copies)
        .ok_or_else(limit)?;

    // Price simultaneous inline representations conservatively. Ordinary
    // recovery still transfers its maps and drops its failure locals unchanged.
    let native_owner_result_bytes = std::mem::size_of::<ProtectedWriterOpenOriginalsV1>()
        .checked_add(std::mem::size_of::<Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<ObservedReplayStateV1, JournalError>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ProtectedJournalLocation>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ReadOnlyJournalNameWitness>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Frame>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::cell::Cell<bool>>()))
        .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<fs::Metadata, io::Error>>()))
        .ok_or_else(limit)?;

    Ok(ProtectedJournalPreopenReplayExtentV1 {
        limits,
        native_bytes: native_prefix_bytes,
        native_replay_representation_bytes,
        clipped_native_pending_record_bytes: native_work.pending_records,
        native_frame_read_memory_bytes: native_work.frame_payload,
        maximum_advertised_payload_bytes,
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

pub use aos_sandbox_model::RecordNamespace;

impl From<aos_sandbox_model::journal_namespace::UnknownRecordNamespace> for JournalError {
    fn from(error: aos_sandbox_model::journal_namespace::UnknownRecordNamespace) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

pub use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyOutcome;

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
    /// Keeps the actual normal Boot journal receiving and independent posts.
    #[error(transparent)]
    BootReceivingOriginal(runtime_deployment_receiving::BootJournalReceivingFailureOriginalV1),
    /// Keeps the actual independently owed fixed deployment root/name original.
    #[error(transparent)]
    BootJournalPostOriginal(runtime_deployment_post::RuntimeDeploymentJournalPostFailureV1),
    /// Preserves the canonical typed new-use refusal from actual Controller rows.
    #[error(transparent)]
    NewUseTombstone(aos_sandbox_protocol::domain_ledger::delete_batch::new_use::PublicMutationNewUseErrorV2),

    /// Preserves the sole metadata-only Recover admission or terminal codec refusal.
    #[error(transparent)]
    MetadataComplete(#[from] aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::MetadataCompleteDataErrorV1),
    /// Preserves the sole bank replay and durable baseline-precharge refusal.
    #[error(transparent)]
    ResourceBank(#[from] aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError),
    /// Preserves the canonical Environment projection refusal on its Source cut.
    #[error(transparent)]
    EnvironmentProjection(aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),

    /// Preserves the shared canonical Delete Source-predecessor refusal.
    #[error(transparent)]
    DeleteSourceCut(#[from] aos_sandbox_ledger_replay::replay::tree_lineage::delete_cut::DeleteSourceCutDataErrorV2),

    /// Preserves the sole provisioning companion or publication-link refusal.
    #[error(transparent)]
    ProvisioningResources(#[from] aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1),
    /// Preserves checked receiving-representation arithmetic at its original boundary.
    #[error(transparent)]
    ReceivingAccounting(#[from] aos_sandbox_model::AccountingError),

    /// Keeps the actual replacement, upper semantic prefix and owed posts.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ReplacementOriginal(native_compaction::JournalReplacementFailureOriginalV1),

    /// Keeps the same captured journal's failed owned append DATA.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    CapturedAppendOriginal(aos_sandbox_broker::canonical_journal::coordinator::retained_data::RetainedAppendDataFailureV1),

    /// Keeps the original selected body error and independently owed native post.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    NativePostOriginal(native_interval::JournalNativePostFailureOriginalV1),

    /// Preserves the actual closed Controller native entry failure.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ControllerNative(aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1),
    /// Borrows the exact permanently retained Controller append cause.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    ControllerAppendOriginal(aos_sandbox_broker::controller_receiving::bank_launch::ControllerAppendFailureOriginalV1),
    /// Preserves the actual Root native/invocation entry failure.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    RootNative(aos_sandbox_broker::receiving::RootWriterErrorV1),
    /// Retains the original Root financial refusal independently of Domain U.
    #[error(transparent)]
    RootFinancial(aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1),
    /// Borrows the exact permanently retained Root append cause.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    RootAppendOriginal(aos_sandbox_broker::receiving::RootAppendFailureOriginalV1),
    /// Preserves the actual fixed Source entry failure.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    SourceNative(aos_sandbox_broker::source_receiving::SourceNativeErrorV1),
    /// Borrows the exact permanently retained fixed Source append cause.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    SourceAppendOriginal(aos_sandbox_broker::source_receiving::SourceAppendFailureOriginalV1),
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
    /// The distinct recovered Create joint terminal comparison refused.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    RecoveredCreateTerminal(#[from] aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedRecoveredTerminalDataErrorV1),
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
    /// A selected readonly name stage refused; its whole native cause stays owned.
    #[error("selected readonly name observation {0} refused")]
    ReadOnlyNameReceivingFailure(u8),
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

impl From<CanonicalJournalMechanicalErrorV1> for JournalError {
    fn from(error: CanonicalJournalMechanicalErrorV1) -> Self {
        match error {
            CanonicalJournalMechanicalErrorV1::ResourceBank(value) => Self::ResourceBank(value),
            CanonicalJournalMechanicalErrorV1::ProvisioningResources(value) => Self::ProvisioningResources(value),
            CanonicalJournalMechanicalErrorV1::Io(value) => Self::Io(value),
            CanonicalJournalMechanicalErrorV1::AlreadyLocked => Self::AlreadyLocked,
            CanonicalJournalMechanicalErrorV1::JournalTooLarge => Self::JournalTooLarge,
            CanonicalJournalMechanicalErrorV1::UnsupportedVersion(value) => Self::UnsupportedVersion(value),
            CanonicalJournalMechanicalErrorV1::ChecksumMismatch(value) => Self::ChecksumMismatch(value),
            CanonicalJournalMechanicalErrorV1::SequenceDiscontinuity(value) => Self::SequenceDiscontinuity(value),
            CanonicalJournalMechanicalErrorV1::MalformedTransaction(value) => Self::MalformedTransaction(value),
            CanonicalJournalMechanicalErrorV1::MalformedRecord(value) => Self::MalformedRecord(value),
            CanonicalJournalMechanicalErrorV1::InvalidTransaction => Self::InvalidTransaction,
            CanonicalJournalMechanicalErrorV1::InvalidIdempotencyKey => Self::InvalidIdempotencyKey,
            CanonicalJournalMechanicalErrorV1::LimitExceeded(value) => Self::LimitExceeded(value),
            CanonicalJournalMechanicalErrorV1::DuplicateRecordKey => Self::DuplicateRecordKey,
            CanonicalJournalMechanicalErrorV1::DuplicateTransaction => Self::DuplicateTransaction,
            CanonicalJournalMechanicalErrorV1::IdempotencyConflict => Self::IdempotencyConflict,
            CanonicalJournalMechanicalErrorV1::Poisoned => Self::Poisoned,
            CanonicalJournalMechanicalErrorV1::ProtectedBoundary => Self::ProtectedBoundary,
            CanonicalJournalMechanicalErrorV1::ForeignAuthorityNamespace => Self::ForeignAuthorityNamespace,
            CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot => Self::StaleAuthoritySnapshot,
            CanonicalJournalMechanicalErrorV1::AuthorityPreflightMismatch => Self::AuthorityPreflightMismatch,
            CanonicalJournalMechanicalErrorV1::UnsupportedProtectedOpen => Self::UnsupportedProtectedOpen,
            CanonicalJournalMechanicalErrorV1::SequenceExhausted => Self::SequenceExhausted,
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1> for JournalError {
    fn from(error: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError>
    for JournalError
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError,
    ) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<JournalTransactionDataError> for JournalError {
    fn from(error: JournalTransactionDataError) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<FrameError> for JournalError {
    fn from(error: FrameError) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<RecordError> for JournalError {
    fn from(error: RecordError) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<NativeReplayError> for JournalError {
    fn from(error: NativeReplayError) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

impl From<RecoveryTailError> for JournalError {
    fn from(error: RecoveryTailError) -> Self {
        Self::from(CanonicalJournalMechanicalErrorV1::from(error))
    }
}

#[cfg(target_os = "linux")]
mod provisioning;
mod start_admission;
#[cfg(target_os = "linux")]
mod execution_admission;
pub(crate) use start_admission::StartAdmissionJournalIdentityV1;

/// Owns one exclusively locked, append-only journal and its replayed indexes.
pub struct Journal {
    #[cfg(target_os = "linux")]
    operator_recovery: Option<crate::controller_resource_reservation::operator_create_recovery::OperatorRecoverCustodyV2>,
    #[cfg(target_os = "linux")]
    provisioning: Option<Box<crate::reconciler::provisioning::ProvisioningScopeV1>>,
    start_admission: Option<Box<crate::reconciler::start_admission::StartAdmissionScopeV1>>,
    execution_admission: Option<Box<crate::controller_execution_operation::public_admission::ExecutionPublicAdmissionScopeV2>>,
    // The contiguous native prefix keeps its original file/set/map drop order.
    // All role admission, semantic indexes, and authority remain in this wrapper.
    native: native_backing::JournalNativeBackingV1,
    #[cfg(target_os = "linux")]
    root_journal_financial: Option<aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1>,
    #[cfg(target_os = "linux")]
    native_interval: Option<Arc<native_interval::JournalNativeIntervalOriginalV1>>,
    #[cfg(target_os = "linux")]
    replacement_original: Option<Arc<native_compaction::JournalReplacementOriginalV1>>,
    cache_policy_gate: Option<(PathBuf, u32)>,
    authority_instance: Arc<JournalAuthorityInstance>,
    source_challenge_history: Vec<source_history::SourceOriginalChallengeCheckpointV5>,
    source_original_replay: source_history::replay::SourceOriginalReplayCacheV5,
    source_history_compacted: bool,
    // Deny-only native provenance survives deletion of a Q04 lower marker.
    // It is never a floor, currentness certificate or permission to mutate.
    #[cfg(target_os = "linux")]
    q04_lower_history_present: bool,
}

#[cfg(target_os = "linux")]
mod root_readonly_model;
#[cfg(target_os = "linux")]
pub(crate) use root_readonly_model::{RootReadonlyJournalModelOriginalsV1,
    RootReadonlyJournalModelInputsV1};

#[cfg(target_os = "linux")]
mod nix_offline_provisioning;
#[cfg(target_os = "linux")]
pub use nix_offline_provisioning::{
    NixOfflineContactDataV5, NixOfflineHelperLaunchV5,
    NixOfflineNativeJobErrorV5, NixOfflineNativeJobV5,
};

#[cfg(target_os = "linux")]
mod execution_observation;
pub(crate) use execution_observation::ExecutionObservationJournalIdentityV4;

mod storage_captured_open;
pub(crate) use storage_captured_open::controller_session_directory_data_v1;
pub(crate) use storage_captured_open::EnvironmentEvidenceCapturedJournalOpenV1;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
pub(crate) use storage_captured_open::StorageNativeOpeningOwnerLinkV1;
#[cfg(target_os = "linux")]
pub use storage_captured_open::{
    HostPeerCapturedJournalOpenV2, HostExecutionCapturedJournalOpenV2,
    HostAgentCapturedJournalOpenV2, HostLifecycleCapturedJournalOpenV2,
    HostArgumentCapturedJournalOpenV2,
    RuntimeDeploymentMainCapturedJournalOpenV1, RuntimeDeploymentFloorCapturedJournalOpenV1,
    ControllerBrokerSessionCapturedJournalOpenV1, ControllerStartResourceSessionCapturedJournalOpenV4, ControllerStorageFloorCapturedJournalOpenV1, StorageBrokerFloorCapturedJournalOpenV2,
    StorageHostSessionCapturedJournalOpenV1,
    CapturedJournalOpenModeV1, StorageBrokerCapturedJournalOpenV1, StorageStateCapturedJournalOpenV1,
    MountBrokerSessionCapturedJournalOpenV4, HostBrokerSessionCapturedJournalOpenV1,
    StorageWorkspaceCapturedJournalOpenV1, StorageNativeIssuanceCapturedJournalOpenV1, StorageOutputCapturedJournalOpenV1,
    StorageRequestTrustCapturedJournalOpenV1,
};

mod protected_storage;
mod runtime_deployment_post;
pub(crate) mod runtime_deployment_receiving;
pub use runtime_deployment_post::{
    RuntimeDeploymentJournalPostFailureV1, RuntimeDeploymentJournalPostOriginalV1,
};
pub use protected_storage::ProtectedJournalCurrentnessOriginalsV1;
pub use protected_storage::{ProtectedJournalLockCustodyV1, ProtectedJournalNamesV1};
pub(crate) use protected_storage::{
    ProtectedWriterNameWitness, ProtectedWriterOpenOriginalsV1,
    ReadOnlyJournalNameWitness, ReadOnlyJournalOpenOriginalsV1, ReadOnlyProtectedJournal,
};
use protected_storage::{
    FileIdentity, ProtectedJournalLocation, open_protected_file_into,
    resolve_protected_directory_from_root, rustix_io, validate_protected_fd,
};
#[cfg(test)]
use protected_storage::{
    MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES, ProtectedAncestry, open_protected_file, protected_open_error,
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
    CapacityReservation(GlobalCapacityReservationPurposeV1),
}

#[derive(Clone, Copy)]
enum RootOwnerEdge {
    #[cfg(target_os = "linux")]
    NixOffline,
    #[cfg(target_os = "linux")]
    NixOfflineClosureData,
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







struct JournalAuthorityInstance;

/// Holds a comparison-only weak stamp of an already-owned Journal instance.
///
/// This stamp survives moves but neither keeps the writer alive nor grants
/// read, mutation, currentness or effect authority. Compaction replaces the
/// original identity and therefore invalidates the comparison.
#[doc(hidden)]
pub struct JournalAuthorityComparisonStampV1(std::sync::Weak<JournalAuthorityInstance>);

impl Journal {
    /// Borrows the identity allocation of this exact existing writer as DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn authority_comparison_stamp_v1(&self) -> JournalAuthorityComparisonStampV1 {
        JournalAuthorityComparisonStampV1(Arc::downgrade(&self.authority_instance))
    }

    /// Compares a stamp to this same retained writer without native IO.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_authority_comparison_stamp_v1(&self, stamp: &JournalAuthorityComparisonStampV1) -> bool {
        std::sync::Weak::ptr_eq(&Arc::downgrade(&self.authority_instance), &stamp.0)
    }
}

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
        self.claim_protected_authority_engine_v1(namespace, None)
    }

    /// Claims the same namespace while retaining both reached capacity scans.
    ///
    /// The supplied captures are passive DATA destinations. All ordinary
    /// health, namespace, canonical-family and ownership guards run in their
    /// existing order; this method neither grants payment nor skips refusal.
    /// The caller keeps the complete returned error beside both captures.
    ///
    /// # Errors
    /// Returns the same native or canonical refusal as the ordinary claim.
    /// Reused captures refuse entry without replacing their first partials.
    pub fn claim_protected_authority_retaining_v1(
        &mut self,
        namespace: RecordNamespace,
        captures: &mut [aos_sandbox_protocol::domain_ledger::capacity_family::family::
            CanonicalCapacityReadCaptureV1; 2],
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.claim_protected_authority_engine_v1(namespace, Some(captures))
    }

    fn claim_protected_authority_engine_v1(
        &mut self,
        namespace: RecordNamespace,
        mut captures: Option<&mut [aos_sandbox_protocol::domain_ledger::capacity_family::family::
            CanonicalCapacityReadCaptureV1; 2]>,
    ) -> Result<ProtectedJournalAuthority<'_>, JournalError> {
        self.ensure_protected_authority()?;
        if namespace == RecordNamespace::MountSourceAcquisition
            || namespace == RecordNamespace::NixOfflineProvisioning
            || namespace == RecordNamespace::ControllerResourceReservation
            || namespace == RecordNamespace::CreateStorageHistory
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        match captures.as_deref_mut() {
            Some(originals) => originals[0].require_legacy_once_v1(self.native.state()),
            None => aos_sandbox_protocol::domain_ledger::capacity_family::family::
                require_legacy_reservations(self.native.state()),
        }.map_err(JournalError::from)?;
        let has_foreign_history =
            self.native
                .committed_namespaces()
                .iter()
                .any(|committed_namespace| {
                    *committed_namespace != namespace
                        && *committed_namespace != RecordNamespace::GlobalCapacityReservation
                });
        let has_foreign_state = self.native.state().keys().any(|(record_namespace, _)| {
            *record_namespace != namespace
                && *record_namespace != RecordNamespace::GlobalCapacityReservation
        });
        if has_foreign_history
            || has_foreign_state
            || !(match captures {
                Some(originals) => originals[1].all_owned_by_once_v1(self.native.state(), namespace),
                None => aos_sandbox_protocol::domain_ledger::capacity_family::
                    all_reservations_owned_by(self.native.state(), namespace),
            }.map_err(JournalError::from)?)
        {
            return Err(JournalError::ForeignAuthorityNamespace);
        }

        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace,
            scope: ProtectedAuthorityScope::SingleNamespace,
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
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_reservations(
            self.native.state(),
        )
        .map_err(JournalError::from)?;

        Ok(ProtectedJournalAuthority {
            journal: self,
            namespace: purpose.owner_namespace(),
            scope: ProtectedAuthorityScope::CapacityReservation(purpose),
        })
    }


    /// Requires retained protected storage provenance before resolving authority.
    pub(crate) fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if !self.native.is_protected() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    // This lends the SAME actual native map/index as comparison DATA only.
    // Protected provenance and all currentness/financial guards stay here.
    pub(crate) fn historical_read_view_v1(&self) -> HistoricalLedgerReadViewV1<'_> {
        self.native.read_view().historical_view()
    }

    /// Returns the currently materialized value for a logical key.
    ///
    /// This diagnostic view remains readable after an ambiguous I/O failure.
    /// It does not establish that the value is current durable authority.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.historical_read_view_v1().get(namespace, key)
    }

    /// Iterates the materialized records in one namespace by bytewise key.
    ///
    /// The iterator is a stable snapshot only while this journal remains
    /// immutably borrowed. Callers must copy values needed across a commit.
    /// Like [`Self::get`], this diagnostic view does not establish current
    /// authority after an ambiguous I/O failure. The ordered namespace range
    /// avoids scanning unrelated desired-state and operation records.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.historical_read_view_v1().records(namespace)
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
        self.historical_read_view_v1().all_records()
    }

    // This lends the SAME original file's whole metadata Result and unchanged
    // limits as DATA. Its genuine role guard supplies currentness/payment;
    // neither the tuple nor this private adapter constructs writer authority.
    pub(crate) fn held_native_receiving_metadata_v1(
        &self,
    ) -> (std::io::Result<std::fs::Metadata>, JournalLimits) {
        (self.native.metadata(), self.native.limits())
    }

    /// Measures the same held Session writer for passive receiving geometry.
    ///
    /// The caller prepays its fixed original before this native metadata read.
    /// Its whole result remains in `metadata`; neither this extent nor the
    /// original creates a payer, a new file, or current Session authority.
    /// Materialized bytes backstop an externally shortened physical prefix.
    ///
    /// # Errors
    /// Rejects repeated sampling, unhealthy/unprotected custody, native metadata
    /// failure or invalid/overflowing exact native and materialized extents.
    #[doc(hidden)]
    pub fn held_session_receiving_extent_v1(
        &self,
        metadata: &mut Option<std::io::Result<std::fs::Metadata>>,
    ) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
        if metadata.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.ensure_protected_authority()?;
        *metadata = Some(self.native.metadata());
        let physical = match metadata.as_ref() {
            Some(Ok(value)) => value.len(),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let prefix = physical.max(self.held_materialized_encoding_bytes_v1()?);
        protected_journal_preopen_replay_extent_for_prefix_v1(self.native.limits(), prefix)
    }

    // Measures only the SAME already-held materialized key/value bytes through
    // the actual encoder's geometry. The passive width prevents a smaller
    // externally damaged File length from underpricing its resident read view.
    pub(crate) fn held_materialized_encoding_bytes_v1(&self) -> Result<u64, JournalError> {
        let records = self.native.state().iter().map(|((_, key), value)| {
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: key.len(),
                value_bytes: Some(value.len()),
            }
        });
        aos_sandbox_journal::geometry::encoded_transaction_append_bytes(records)
            .map_err(JournalError::from)
    }

    // This closed borrowed extent prices already-owned storage and the actual
    // native file, rather than materializing a second logical replay. It is
    // DATA until the entered prefix joins the same original bank and writer.
    pub(crate) fn first_global_allocation_shape_v1(
        &self,
    ) -> Result<crate::journal::JournalShape, JournalError> {
        self.first_global_allocation_shape_engine_v6(None)
    }

    pub(crate) fn first_global_allocation_shape_engine_v6(
        &self,
        metadata: Option<&mut Option<std::io::Result<std::fs::Metadata>>>,
    ) -> Result<crate::journal::JournalShape, JournalError> {
        self.ensure_healthy()?;
        let mut retained_bytes = 0_usize;
        for ((_, key), value) in self.native.state() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .and_then(|bytes| bytes.checked_add(value.capacity()))
                .ok_or(JournalError::JournalTooLarge)?;
        }
        for key in self.native.idempotency().keys() {
            retained_bytes = retained_bytes.checked_add(key.capacity())
                .ok_or(JournalError::JournalTooLarge)?;
        }
        let cells = self.native.state().len().checked_add(self.native.idempotency().len())
            .and_then(|count| count.checked_add(self.native.transaction_ids().len()))
            .and_then(|count| count.checked_add(self.native.committed_namespaces().len()))
            .ok_or(JournalError::JournalTooLarge)?;
        let native_bytes = match metadata {
            Some(destination) => {
                if destination.is_some() { return Err(JournalError::ProtectedBoundary); }
                *destination = Some(self.held_native_receiving_metadata_v1().0);
                match destination.as_ref() {
                    Some(Ok(metadata)) => metadata.len(),
                    _ => return Err(JournalError::ProtectedBoundary),
                }
            }
            None => self.held_native_receiving_metadata_v1().0?.len(),
        };
        Ok(crate::journal::JournalShape {
            retained_bytes,
            cells,
            native_bytes,
            maximum_transaction_bytes: self.native.limits().maximum_transaction_bytes,
            maximum_record_bytes: self.native.limits().maximum_record_bytes,
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
        let key = aos_sandbox_ledger_replay::replay::controller_source_genesis::ACCEPTANCE_PREFIX.len()
            .checked_add(std::mem::size_of::<aos_sandbox_model::ProjectId>())
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

    /// Borrows this journal's actual opened ceilings as comparison DATA.
    ///
    /// The returned limits do not establish currentness, ownership, admission
    /// or permission to read, replay or mutate a journal. A genuine caller
    /// independently binds its same held journal before deriving a sidecar.
    #[doc(hidden)]
    #[must_use]
    pub const fn configured_limits_data_v1(&self) -> JournalLimits {
        self.configured_limits()
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
            || !self.native.idempotency().is_empty()
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
        let original_length = self.native.metadata()?.len();
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
        if self.native.metadata()?.len() != original_length {
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
        self.historical_read_view_v1().check_idempotency(key, request_digest)
    }

    /// Returns the already-decoded selected genesis and successor family DATA.
    ///
    /// # Errors
    /// Rejects a poisoned writer or any incomplete selected whole-family join.
    /// This comparison does not lend mutation, signing or Root currentness.
    pub(crate) fn source_project_genesis_data_v3(
        &self,
        selected: aos_sandbox_model::ProjectId,
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
        if self.native.state().keys().any(|(namespace, _)| {
            *namespace == RecordNamespace::CreateStorageHistory
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        if aos_sandbox_ledger_replay::git_coverage_prefix::has_durable_owner_fence_v1(
            self.native.state(),
        ) {
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
            || aos_sandbox_ledger_replay::replay::source_original::cache::has_original_rows(self.native.state())
            || self.native.state().keys().any(|(namespace, key)| {
                *namespace == RecordNamespace::SourceProviderAuthority
                    && aos_sandbox_ledger_replay::replay::challenge::is_challenge_key(key)
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
            self.native.metadata()?.len(),
            self.native.committed_transactions(),
            self.native.limits(),
            self.native.next_sequence(),
        )?;
        source_tree_genesis::require_no_compaction(self.native.state())?;
        source_tree_successor::require_no_compaction(self.native.state())?;
        source_project_admission_challenge::require_no_compaction(self.native.state())?;
        aos_sandbox_ledger_replay::replay::controller_source_genesis::require_no_compaction(self.native.state()).map_err(crate::journal::JournalError::from)?;
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
        let result = (|| {
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
            self.native.metadata()?.len(),
            self.native.committed_transactions(),
            self.native.limits(),
            self.native.next_sequence(),
        ).inspect_err(|_| self.native.poison())?;
        Ok(())
        })();
        #[cfg(target_os = "linux")]
        { self.finish_selected_compaction_v1(result) }
        #[cfg(not(target_os = "linux"))]
        { result }
    }

    fn compact_inner(&mut self) -> Result<(), JournalError> {
        let ordinary = match &mut self.native {
            native_backing::JournalNativeBackingV1::Ordinary(ordinary) => ordinary,
            #[cfg(target_os = "linux")]
            _ => return self.compact_selected_v1(),
        };
        let limits = ordinary.held.read_view_v1().limits();
        let mut replacement = ordinary
            .held
            .prepare_replacement_once_v1()
            .map_err(project_ordinary_replacement_error)?;
        let mut semantic = ordinary_semantics::OrdinarySemanticReplayOriginalV1::new();
        let replayed = (|| {
            let identity = replacement
                .prepare_parser_identity_once_v1()
                .map_err(project_ordinary_replacement_error)?;
            let mut cursor = replacement
                .begin_indexed_replay_once_v1()
                .map_err(project_ordinary_replacement_error)?;
            semantic
                .observe_once(
                    &mut cursor,
                    identity,
                    limits,
                    None,
                    #[cfg(target_os = "linux")]
                    None,
                )
                .map_err(|()| JournalError::ProtectedBoundary)
        })();
        if let Err(body) = replayed {
            let native_selected = replacement.native_failure_v1().is_some()
                || replacement.index_failure_v1().is_some();
            semantic.dispose_ordinary_prospective_v1();
            let current_disposal = replacement.dispose_ordinary_current_once_v1();
            let (upper_native, upper_semantic) = semantic.into_ordinary_errors();
            let pending_disposal = replacement.dispose_ordinary_pending_once_v1();
            let errors = replacement.into_ordinary_errors_v1();
            let (index, native) = match errors {
                Ok(errors) => errors,
                // An impossible private phase mismatch keeps the whole real
                // replacement alive through its ordinary negative Drop.
                Err(original) => {
                    drop(original);
                    return Err(body);
                }
            };
            if native_selected {
                if let Some(cause) = index {
                    return Err(project_idempotency_record_error(cause));
                }
                if let Some(cause) = native {
                    return Err(
                        CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(cause).into(),
                    );
                }
            }
            if let Some(cause) = upper_native.or(upper_semantic) {
                return Err(cause);
            }
            // Independent disposition results cannot replace the earlier body
            // refusal; all reached originals have already retired in order.
            drop(current_disposal);
            drop(pending_disposal);
            return Err(body);
        }

        let remainder = match semantic.take_remainder_once() {
            Some(remainder) => remainder,
            None => {
                semantic.dispose_ordinary_prospective_v1();
                let _ = replacement.dispose_ordinary_current_once_v1();
                drop(semantic.into_ordinary_errors());
                let _ = replacement.dispose_ordinary_pending_once_v1();
                drop(replacement.into_ordinary_errors_v1());
                return Err(JournalError::ProtectedBoundary);
            }
        };
        // Upper temporary semantics end before the physical final metadata/
        // seek. The full successful remainder stays resident on that failure.
        semantic.dispose_ordinary_prospective_v1();
        drop(semantic);
        let ready = replacement
            .finish_replayed_once_v1()
            .map_err(project_ordinary_replacement_error)?;
        let installed = ready
            .install_once_v1(&mut ordinary.held)
            .map_err(project_ordinary_replacement_error)?;
        self.source_challenge_history = remainder.source_challenge_history;
        self.source_original_replay = remainder.source_original_replay;
        self.source_history_compacted = remainder.source_history_compacted;
        #[cfg(target_os = "linux")]
        {
            self.q04_lower_history_present = remainder.q04_lower_history_present;
        }
        let instance = installed
            .finish_after_semantic_once_v1(&mut ordinary.held, JournalAuthorityInstance)
            .map_err(project_ordinary_replacement_error)?;
        self.authority_instance = Arc::clone(instance.comparison_arc_v1());
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



    fn validate_fixed_storage(&self, directory: &str, name: &str) -> Result<(), JournalError> {
        let retained = self.journal.native.protected_view()
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
    /// is no longer current.
    pub fn validate_snapshot_for_effect(
        &self,
        snapshot: &ProtectedJournalSnapshot,
    ) -> Result<(), JournalError> {
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
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_reservations(
            self.journal.native.state(),
        )
        .map_err(JournalError::from)?;
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
    aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(transactions)
}

pub(crate) fn source_native_family_dynamic_demand_v1(
    state: &source_tree_successor::State,
    transaction: Option<&JournalTransaction>,
) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
    source_tree_successor::source_member_dynamic_demand_v1(state, transaction)
}

pub(crate) fn source_native_family_fixed_footprint_v1() -> Option<(usize, usize)> {
    let (state_bytes, state_cells) = source_tree_successor::SourceReplayFamilyOriginalsV1::boxed_footprint_v1()?;
    let (transition_bytes, transition_cells) = source_tree_successor::SourceReplayTransactionOriginalsV1::boxed_footprint_v1()?;
    Some((state_bytes.checked_add(transition_bytes)?, state_cells.checked_add(transition_cells)?))
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
fn is_q04_lower_history_record_v1(record: &JournalRecord) -> bool {
    aos_sandbox_ledger_replay::semantic_recipe::is_q04_lower_history_record_data_v1(record)
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
    DeletePending(&'observer mut semantic_append::delete::PendingNativeObserverV1<'data>),
    OriginalRelease(&'observer mut OriginalReleaseControllerNativeHistoryV1),
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
            Self::DeletePending(history) => history.observe(
                transaction, commit_sequence, end_offset, native_digest,
            ),
            Self::OriginalRelease(history) => history.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
                native_digest,
            ),
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
}

/// Retains whole native readback DATA and each independent named bookend.
///
/// This has no public constructor, field, writer or cut getter. Its actual
/// Controller/Root owner retains it through native comparison and named posts;
/// no captured readback grants current cleanup authority.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalReleaseControllerCutCaptureV1 {
    purpose: OriginalReleaseNativeCutPurposeV1,
    protection: Option<Result<ProtectedWriterNameWitness, JournalError>>,
    copy_bound: Option<Result<(), JournalError>>,
    native: Option<Result<ObservedReplayStateV1, JournalError>>,
    comparison: Option<Result<(), JournalError>>,
    named_post: Option<Result<(), JournalError>>,
    history: OriginalReleaseControllerNativeHistoryV1,
    first: Option<OriginalReleaseControllerCutFailureV1>,
    error_transferred: bool,
}



#[cfg(test)]
fn validate_replayed_source_transaction(
    state: &source_tree_successor::State,
    transaction: &JournalTransaction,
    limits: JournalLimits,
    retaining: bool,
    original: &mut Option<Box<source_tree_successor::SourceReplayTransactionOriginalsV1>>,
) -> Result<bool, JournalError> {
    semantic_replay::validate_replayed_source_transaction(state, transaction, limits, retaining, original)
}

// Each actual validation has a fresh pure destination. Only complete positive
// validation disposes it; a negative remains in the same Native scratch through
// the enclosing Source transport and currentness posts. This is no loan rearm.
#[cfg(test)]
fn validate_replayed_source_state(
    state: &source_tree_successor::State,
    compacted: bool,
    retaining: bool,
    original: &mut Option<Box<source_tree_successor::SourceReplayFamilyOriginalsV1>>,
) -> Result<(), JournalError> {
    semantic_replay::validate_replayed_source_state(state, compacted, retaining, original)
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
    _root_local_edge: Option<RootOwnerEdge>,
) -> Result<(), JournalError> {
    use aos_sandbox_broker::domain_transaction_custody::pressure::{
        CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
    };
    let deletion = CapacityDeletionSelectorDataV1::Reservation(settling_reservation);
    validate_reserved_capacity_data_v1(
        state, prospective_materialized_bytes, records, deletion,
        prospective_journal_bytes, prospective_transactions, limits,
    ).map_err(JournalError::from)
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

fn project_idempotency_record_error(
    error: aos_sandbox_protocol::domain_ledger::readonly::IdempotencyRecordDataErrorV1,
) -> JournalError {
    JournalError::from(CanonicalJournalMechanicalErrorV1::from(error))
}

fn validate_idempotency_changes(
    idempotency: &BTreeMap<Vec<u8>, IdempotencyDecision>,
    records: &[JournalRecord],
) -> Result<(), JournalError> {
    aos_sandbox_protocol::domain_ledger::readonly::validate_idempotency_changes(idempotency, records)
        .map_err(project_idempotency_record_error)
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
    use aos_sandbox_protocol::public_api::projection::{PublicProjectionKindV1, projection_key};

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
    aos_sandbox_protocol::domain_ledger::readonly::apply_idempotency_record(idempotency, record)
        .map_err(project_idempotency_record_error)
}

fn write_compacted(
    file: &mut File,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(), JournalError> {
    aos_sandbox_broker::canonical_journal::write_compacted_data(file, state, limits)
        .map_err(|error| JournalError::from(CanonicalJournalMechanicalErrorV1::from(error)))
}

// Only the ordinary adapter consumes its completed native causes. Selected
// replacement errors stay in their actual permanent stage and original sink.
fn project_ordinary_replacement_error(
    error: aos_sandbox_broker::canonical_journal::coordinator::replacement::CanonicalReplacementErrorV1,
) -> JournalError {
    use aos_sandbox_broker::canonical_journal::coordinator::replacement::CanonicalReplacementErrorV1 as Error;
    match error {
        Error::Native(error) => JournalError::from(
            CanonicalJournalMechanicalErrorV1::from_ordinary_native_v1(error),
        ),
        Error::Encode(error) => JournalError::from(CanonicalJournalMechanicalErrorV1::from(error)),
        Error::Closed => JournalError::ProtectedBoundary,
    }
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

    use aos_sandbox_model::OperationId;

    use super::{
        FileIdentity, GlobalCapacityReservationPurposeV1,
        GlobalCapacityReservationRecoveryBindingV1, GlobalCapacityReservationRequestV1,
        HEADER_BYTES, IdempotencyKey, IdempotencyOutcome, Journal, JournalError, JournalLimits,
        JournalRecord, JournalTransaction, MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES,
        ProtectedAncestry, ProtectedAuthorityScope, ProtectedJournalAuthority,
        ProtectedJournalLockCustodyV1,
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

        for namespace in [0, 79, 82, 83, 255] {
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
    fn readonly_cursor_replays_the_same_real_committed_prefix_without_ofd_seek() {
        use aos_sandbox_journal::storage::ReadOnlyCapturedFileCursorV1;

        let transaction = transaction(23, vec![JournalRecord::put(
            RecordNamespace::DesiredState, b"scope".to_vec(), b"active".to_vec(),
        )]);
        let frames = encode_transaction(&transaction, 1).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        for frame in &frames {
            file.write_all(frame).unwrap();
        }
        let length = file.metadata().unwrap().len();
        file.seek(SeekFrom::Start(2)).unwrap();
        let mut reader = ReadOnlyCapturedFileCursorV1::new(&file, length);

        let actual = super::ordinary_reread::replay_fixture_observed_v1(
            &mut reader, JournalLimits::default(), None,
            #[cfg(target_os = "linux")]
            None,
        ).unwrap();

        assert_eq!(actual.committed_transactions, 1);
        assert_eq!(actual.committed_records, 1);
        assert_eq!(actual.durable_end, length);
        assert_eq!(actual.native.state_data_v1().get(&(RecordNamespace::DesiredState, b"scope".to_vec())),
            Some(&b"active".to_vec()));
        assert_eq!((&file).stream_position().unwrap(), 2);
    }

    #[test]
    fn readonly_cursor_preserves_the_actual_unknown_namespace_replay_refusal() {
        use aos_sandbox_journal::storage::{CapturedFileCursor, ReadOnlyCapturedFileCursorV1};

        let frames = aos_sandbox_journal::transaction::encode_transaction(
            [24; 16], 1,
            [aos_sandbox_journal::transaction::NativeRecordRef {
                namespace_byte: 255, key: b"key", value: None,
            }].into_iter(),
        ).unwrap();
        let prefix = [&frames[0][..], &frames[1][..]].concat();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&prefix).unwrap();
        let mut ordinary = CapturedFileCursor::new(&file, prefix.len() as u64);
        let mut readonly = ReadOnlyCapturedFileCursorV1::new(&file, prefix.len() as u64);

        let ordinary = super::ordinary_reread::replay_fixture_observed_v1(
            &mut ordinary, JournalLimits::default(), None,
            #[cfg(target_os = "linux")]
            None,
        );
        let readonly = super::ordinary_reread::replay_fixture_observed_v1(
            &mut readonly, JournalLimits::default(), None,
            #[cfg(target_os = "linux")]
            None,
        );

        assert!(matches!(ordinary,
            Err(JournalError::MalformedRecord("unknown record namespace"))));
        assert!(matches!(readonly,
            Err(JournalError::MalformedRecord("unknown record namespace"))));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn public_projection_queries_refuse_intrinsic_poison_even_for_absent_rows() {
        use crate::controller_service::public_projection::PublicProjectionStoreV1;
        use aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1;
        let directory = TestDirectory::new("poisoned-public-observer");
        let (mut journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        let resource = [1; 16];
        let operation = OperationId::from_bytes([2; 16]);
        assert!(PublicProjectionStoreV1::new(&journal).get(PublicProjectionKindV1::Sandbox, resource).unwrap().is_none());

        journal.native.poison();

        let observer = PublicProjectionStoreV1::new(&journal);
        assert!(observer.get(PublicProjectionKindV1::Sandbox, resource).is_err());
        assert!(observer.list(PublicProjectionKindV1::Sandbox, aos_sandbox_model::ProjectId::from_bytes([3; 16])).is_err());
        assert!(observer.list_operation(operation).is_err());
        assert!(matches!(journal.ensure_healthy(), Err(JournalError::Poisoned)));
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
            RecordNamespace::ControllerStorageCaptureAdmission,
            RecordNamespace::RootExecutionNoApplyFloorV2,
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

        assert_eq!(RecordNamespace::CreateStorageHistory as u8, 81);
        assert_eq!(
            RecordNamespace::from_byte(81).unwrap(),
            RecordNamespace::CreateStorageHistory,
        );

        for code in [0, 79, 82, 83, 255] {
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
        foreign_scope.scope = ProtectedAuthorityScope::CapacityReservation(
            GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
        );
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
        let uid = std::fs::metadata(path)?.uid();
        let (readback, _) = Journal::open_actual_ordinary_readonly_v1(
            path, "protected.journal", JournalLimits::default(), uid, None, true,
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
        drop(directory);
        let (journal, _) = Journal::open_protected_at_uid(
            &root.0.join("trusted/final"),
            "state.journal",
            JournalLimits::default(),
            uid,
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

    #[test]
    fn resident_encoding_width_survives_an_externally_truncated_file() {
        let directory = TestDirectory::new("resident-receiving-width");
        let (mut journal, _) = Journal::open(directory.journal(), JournalLimits::default()).unwrap();
        journal.commit(&transaction(1, vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            b"resident".to_vec(),
            vec![0x52; 4096],
        )])).unwrap();
        let before = journal.held_materialized_encoding_bytes_v1().unwrap();
        assert!(before >= 4096);

        // This explicit native fault changes the same File after its map was
        // replayed. It grants no protected read, selected J or currentness.
        journal.native.set_length_for_fixture(0).unwrap();
        let (metadata, limits) = journal.held_native_receiving_metadata_v1();
        let physical = metadata.unwrap().len();
        let resident = journal.held_materialized_encoding_bytes_v1().unwrap();
        let extent = super::protected_journal_preopen_replay_extent_for_prefix_v1(
            limits, physical.max(resident),
        ).unwrap();

        assert_eq!(physical, 0);
        assert_eq!(resident, before);
        assert_eq!(extent.native_bytes, resident);
        assert_eq!(journal.get(RecordNamespace::DesiredState, b"resident").unwrap().len(), 4096);
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
        use crate::publisher_admin::capabilities::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
        use crate::publisher_admin::policy::{PublisherPolicyLimits, PublisherPolicyStore};

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
    fn failed_publisher_registration_commit_retires_execution_pin() {
        use crate::publisher_admin::registration::tests::fixture::{anchor, fixture, open_journal, sample};
        use crate::publisher_admin::registration::{PublisherControlError, PublisherControlPolicy};
        use crate::publisher_admin::audit::{PublisherIngressError, PublisherIngressLimits};
        use aos_sandbox_publisher::publisher_sessions::{
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
            node: aos_sandbox_model::NodeId::from_bytes([0x73; 16]),
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
            crate::publisher_admin::registration::register(
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
        use crate::publisher_admin::capabilities::{
            PublisherAuthorityError, PublisherAuthorityLimits, PublisherCapabilityRegistry,
        };

        let directory = TestDirectory::new("publisher-revocation-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let id = aos_sandbox_model::CapabilityId::new();
        let capability = crate::publisher_admin::capabilities::tests::capability(id, 200);
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
        use crate::publisher_admin::policy::{
            PublisherControllerHeadV1, PublisherPolicyError, PublisherPolicyLimits,
            PublisherPolicyStore,
        };

        let directory = TestDirectory::new("publisher-policy-poison");
        let (mut journal, _) = protected_open(&directory.0).unwrap();
        let first = PublisherControllerHeadV1 {
            principal: aos_sandbox_model::PrincipalId::new(),
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
                policies.current_policy(aos_sandbox_model::ProjectId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.revocation_head(aos_sandbox_model::RevocationScopeId::new()),
                Err(PublisherPolicyError::Journal(JournalError::Poisoned)),
            ));
            assert!(matches!(
                policies.resource_binding(aos_sandbox_model::ResourceId::new()),
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

mod catalog_maintenance;
