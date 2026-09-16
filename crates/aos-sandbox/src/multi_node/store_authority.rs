//! Private protected-store authority boundary.
//!
//! This module is the sole home of the durable-store adapter and its session
//! constructor. Journal code receives only a consumed opaque commit grant;
//! ordinary siblings cannot implement the backend or manufacture durability
//! acknowledgements from scalar digests. Every write uses an exact monotonic
//! compare-and-swap transaction and byte-for-byte current readback. A lost
//! response retains a singular recovery token instead of inferring success.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, RestoreScopeId};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

use super::assignment::{
    AssignmentEffectPlanV1, AssignmentIntentV1, AssignmentObservationReducerV1,
    AtomicSnapshotPublicationV1, AuthenticatedSnapshotChunkV1,
    AuthenticatedSnapshotDependencyRangeV1, DurableSnapshotDependencySetV1,
    DurableSnapshotTransferCheckpointV1, InvalidAssignmentModel, InvalidSnapshotTransfer,
    NodeAssignmentObservationV1, SnapshotDependencyRangeV1, SnapshotRestoreAdmissionDecisionV1,
    SnapshotRestoreAdmissionV1, SnapshotTransferChunkRequestV1, SnapshotTransferCompletionV1,
    SnapshotTransferManifestV1, SnapshotTransferResumeV1, VerifiedAssignmentAuthorityV1,
    VerifiedRestoreAuthorizationV1, VerifiedSnapshotDependencySetV1, VerifiedStagedSnapshotV1,
    staged_prefix_commitment,
};
use super::capability::{NodeBootId, NodeBootLineageV1, NodeCapabilitySnapshotV1};
use super::carrier_authority::{
    AuthenticatedAssignmentCarrierContractV1, DormantAuthenticatedCoordinatorNodeTransportV1,
    DormantOutboundExchangeV1, DormantOutboundResponseV1, DormantTransportHandshakeV1,
    issue_context_from_protected_bootstrap, issue_response_from_protected_channel,
    issue_session_from_protected_channel, verify_assignment_contract_from_protected_channel,
};
use super::draining::{
    DrainAssignmentPlanV1, DrainAssignmentStrategyV1, DrainDirectiveV1, DrainObservationV1,
    InvalidDrainModel, NodeDrainModeV1, drain_directive_digest,
};
use super::evidence::AuthenticatedEvidenceContextV1;
use super::evidence_authority::ProtectedEvidenceIntegrationV1;
use super::journal::{
    AssignmentEffectSemanticGrantV1, InvalidMultiNodeJournal, JournalEffectStateV1,
    MultiNodeJournalCheckpointV1, MultiNodeJournalDomainV1, MultiNodeJournalRecordV1,
    MultiNodeJournalReducerV1, ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};
use super::placement::PlacementCandidateV1;
use super::protected_artifact_store::{
    ProtectedArtifactKindV1, ProtectedArtifactRecoveryV1, ProtectedArtifactStoreOutcomeV1,
    ProtectedArtifactStoreV1, snapshot_chunk_effect, snapshot_dependency_effect,
};
use super::protocol::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1,
    InvalidMultiNodeProtocol, MAX_WATCH_EVENTS, NodeRequestBodyV1, NodeRequestEnvelopeV1,
    NodeResponseBodyV1, NodeResponseEnvelopeV1, NodeWatchBindingV1, NodeWatchBootstrapV1,
    NodeWatchCursorV1, NodeWatchEventBodyV1, NodeWatchEventV1, ResyncInventoryV1,
    RollingVersionWindowV1,
};
use super::reducer_state::{
    CapabilityJournalStateV1, DrainJournalStateV1, DurableAssignmentObservationV1,
    DurableDependencyProjectionV1, DurableDrainObservationV1, DurableEvidenceBindingV1,
    DurablePublicationProjectionV1, DurableStagedChunkV1, DurableWatchEventV1,
    MultiNodeReducerStateV1, SnapshotTransferJournalStateV1, WatchJournalStateV1,
    decode_snapshot_manifest_seed,
};

const PROTECTED_STORE_HEAD_KEY: &[u8] = b"\0aos-multi-node-protected-store-v1\0head";
const PROTECTED_STORE_HISTORY_MAGIC: &[u8; 8] = b"AOSMPS01";
const PROTECTED_MULTI_NODE_JOURNAL_NAME: &str = "multi-node-authority-v1.journal";
const PROTECTED_MULTI_NODE_BOOTSTRAP_JOURNAL_NAME: &str =
    "multi-node-authority-bootstrap-v1.journal";
const PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_JOURNAL_NAME: &str =
    "multi-node-snapshot-inbox-v1.journal";
const PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_KEY: &[u8] =
    b"\0aos-multi-node-snapshot-inbox-v1\0manifest";
const PROTECTED_MULTI_NODE_BOOTSTRAP_KEY: &[u8] =
    b"\0aos-multi-node-protected-bootstrap-v1\0config";
const PROTECTED_MULTI_NODE_CLOCK_KEY: &[u8] =
    b"\0aos-multi-node-protected-bootstrap-v1\0clock-floor";
const PROTECTED_MULTI_NODE_CLOCK_MAGIC: &[u8; 8] = b"AOSMCL01";
const PROTECTED_MULTI_NODE_BASE_GENERATION: u64 = 1;
const PROTECTED_MULTI_NODE_ROOT: &str = "/var/lib/aos/sandbox/multi-node";
const PROTECTED_MULTI_NODE_DESTINATION_ROOT: &str = "/var/lib/aos/sandbox/multi-node-destination";
const MAXIMUM_PROTECTED_STORE_HISTORY_BYTES: usize = 512 * 1024 * 1024;

/// Reports a protected-root open or authenticated multi-node replay failure.
#[derive(Debug, thiserror::Error)]
pub enum ProtectedMultiNodeAuthorityOpenErrorV1 {
    /// Protected path, ownership, replay, locking, or journal limits failed.
    #[error("protected multi-node journal could not be opened: {0}")]
    Journal(#[from] JournalError),
    /// The retained multi-node authority history failed typed authentication.
    #[error("protected multi-node authority history is invalid: {0}")]
    Authority(#[from] InvalidMultiNodeJournal),
    /// The live channel or canonical bootstrap frame mismatched protected config.
    #[error("protected multi-node bootstrap carrier is invalid: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
}

/// Reports authenticated multi-node observation persistence failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedMultiNodeUpdateErrorV1 {
    /// The authenticated carrier or semantic response was invalid or stale.
    #[error("multi-node carrier update is invalid: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
    /// Drain desired-state or authenticated observation semantics were invalid.
    #[error("multi-node drain update is invalid: {0}")]
    Drain(#[from] InvalidDrainModel),
    /// Snapshot manifest, integrity, resume, or evidence semantics were invalid.
    #[error("multi-node snapshot update is invalid: {0}")]
    Snapshot(#[from] InvalidSnapshotTransfer),
    /// Protected replay, transition validation, or persistence failed.
    #[error("multi-node protected update failed: {0}")]
    Journal(#[from] InvalidMultiNodeJournal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProtectedStoreObjectKindV1 {
    Record,
    Checkpoint,
}

mod sealed {
    pub trait Sealed {}
}

/// Describes one exact protected write without exposing an authority handle.
struct ProtectedWriteRequestV1<'a> {
    domain: super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes: &'a [u8],
    canonical_bytes_digest: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    expected_generation: u64,
    expected_root_digest: ObjectDigest,
    next_generation: u64,
    transaction_digest: ObjectDigest,
}

/// Carries the protected backend's authenticated, nondeterministic receipt.
///
/// Construction is private to this authority module and its protected-store
/// integration. It is singular and cannot be cloned or copied.
struct ProtectedWriteResultV1 {
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    replay_fence: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    predecessor_root_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
}

/// Preserves a possibly committed protected write instead of treating it as failure.
enum ProtectedWriteOutcomeV1 {
    Committed(ProtectedWriteResultV1),
    OutcomeUnknown,
}

/// Returns exact bytes and receipt facts from authenticated current readback.
struct ProtectedWriteReadbackV1 {
    domain: super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes: Vec<u8>,
    result: ProtectedWriteResultV1,
}

/// Couples an assignment journal record to its authenticated carrier contract.
///
/// The wrapper is singular. It is the only value in this module that allows a
/// future publisher to retain peer, node, epoch, assignment, lease, detached
/// signature, and replay binding alongside the durable record.
#[must_use]
pub struct ProtectedAssignmentStoreCommitV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains exact assignment authority across an outcome-unknown store write.
#[must_use]
pub struct ProtectedAssignmentRecoveryRequiredV1 {
    recovery: ProtectedStoreRecoveryRequiredV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Reports a protected assignment write without discarding ambiguity state.
#[must_use]
pub enum ProtectedAssignmentWriteOutcomeV1 {
    /// The exact protected assignment row was read back after commit.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// The exact transaction and carrier authority must be recovered.
    RecoveryRequired(ProtectedAssignmentRecoveryRequiredV1),
}

/// Reports recovery of one protected assignment write.
#[must_use]
pub enum ProtectedAssignmentWriteResolutionV1 {
    /// The exact protected assignment row was authenticated as committed.
    Committed(ProtectedAssignmentStoreCommitV1),
    /// Recovery remains indeterminate or found a conflicting current value.
    RecoveryRequired {
        /// Retains the exact transaction and carrier authority for another observation.
        recovery: ProtectedAssignmentRecoveryRequiredV1,
        /// Describes the fail-closed recovery classification.
        reason: InvalidMultiNodeJournal,
    },
}

/// Reports protected assignment verification or persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtectedAssignmentWriteErrorV1 {
    /// Carrier, signature, trust-policy, or protected identity verification failed.
    #[error("protected assignment carrier verification failed: {0}")]
    Protocol(#[from] InvalidMultiNodeProtocol),
    /// Assignment intent or reducer plan construction failed.
    #[error("protected assignment reducer planning failed: {0}")]
    Assignment(#[from] InvalidAssignmentModel),
    /// Protected storage or canonical replay validation failed.
    #[error("protected assignment journal write failed: {0}")]
    Journal(#[from] InvalidMultiNodeJournal),
}

/// Allows publication only after the exact assignment store commit completed.
#[must_use]
struct ProtectedAssignmentPublicationV1 {
    record: ProtectedJournalRecordV1,
    carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Carries an exact prepared multi-node effect after durable publication.
#[must_use]
struct ProtectedAssignmentEffectHandoffV1 {
    publication: ProtectedAssignmentPublicationV1,
    semantic_grant: AssignmentEffectSemanticGrantV1,
    effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
}

/// Retains a current, reducer-authorized assignment effect without dispatching it.
#[must_use]
pub struct ProtectedAssignmentEffectReadyV1 {
    handoff: ProtectedAssignmentEffectHandoffV1,
}

enum ProtectedAssignmentCommitOutcomeV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
    },
}

enum ProtectedAssignmentResolutionV1 {
    Committed(ProtectedAssignmentStoreCommitV1),
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
        reason: InvalidMultiNodeJournal,
    },
}

/// Defines the sole protected-store backend accepted by the authority.
trait ProtectedStoreBackendV1: sealed::Sealed {
    /// Persists one exact transaction with explicit ambiguous-outcome reporting.
    ///
    /// An error certifies that no write took effect. Any result lost after the
    /// commit point must be reported as [`ProtectedWriteOutcomeV1::OutcomeUnknown`].
    fn persist_once(
        &mut self,
        request: ProtectedWriteRequestV1<'_>,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedWriteOutcomeV1, InvalidMultiNodeJournal>;

    fn read_current(
        &mut self,
        domain: super::journal::MultiNodeJournalDomainV1,
        kind: ProtectedStoreObjectKindV1,
        operation: Option<OperationId>,
    ) -> Result<ProtectedWriteReadbackV1, InvalidMultiNodeJournal>;
}

/// Retains one canonical protected-store append in the bounded authenticated head.
#[derive(Clone)]
struct ProtectedStoreHistoryEntryV1 {
    domain: super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes: Vec<u8>,
    canonical_bytes_digest: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    durability_generation: u64,
    predecessor_root_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
    transaction_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    context_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
}

/// Implements the sealed backend over one dedicated protected journal namespace.
///
/// The single materialized head carries the complete bounded canonical history.
/// Reopen validates every link before any session can be claimed, and writes
/// replace the head only after exact current-value comparison and protected
/// preflight/readback.
struct ProtectedJournalStoreBackendV1 {
    journal: Journal,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    base_generation: u64,
    base_root_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    authenticated_context: AuthenticatedEvidenceContextV1,
    history: Vec<ProtectedStoreHistoryEntryV1>,
    encoded_head: Option<Vec<u8>>,
}

impl sealed::Sealed for ProtectedJournalStoreBackendV1 {}

impl ProtectedJournalStoreBackendV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_protected_journal(
        mut journal: Journal,
        storage_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        base_generation: u64,
        base_root_digest: ObjectDigest,
        authenticated_context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if storage_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || base_generation == 0
            || base_root_digest.as_bytes() == &[0; 32]
            || authenticated_context.replay_fence() != replay_fence
            || !authenticated_context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let encoded_head = {
            let authority = journal
                .claim_protected_authority(RecordNamespace::RuntimeAuthority)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            let records = authority
                .records()
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
                .take(2)
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .collect::<Vec<_>>();
            match records.as_slice() {
                [] => None,
                [(key, value)] if key.as_slice() == PROTECTED_STORE_HEAD_KEY => Some(value.clone()),
                _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
            }
        };
        let history = match encoded_head.as_deref() {
            Some(bytes) => decode_protected_store_history(
                bytes,
                storage_domain_digest,
                replay_fence,
                base_generation,
                base_root_digest,
            )?,
            None => Vec::new(),
        };
        let durability_generation = history
            .last()
            .map_or(base_generation, |entry| entry.durability_generation);
        let protected_root_digest = history
            .last()
            .map_or(base_root_digest, |entry| entry.protected_root_digest);
        if history.last().is_some_and(|entry| {
            entry.context_digest != protected_context_digest(authenticated_context)
                || !authenticated_context.is_current_at(verified_at_unix_seconds)
        }) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        validate_protected_store_semantics(
            &history,
            storage_domain_digest,
            replay_fence,
            authenticated_context,
        )?;
        Ok(Self {
            journal,
            storage_domain_digest,
            replay_fence,
            base_generation,
            base_root_digest,
            durability_generation,
            protected_root_digest,
            authenticated_context,
            history,
            encoded_head,
        })
    }

    fn authority_session(
        &mut self,
    ) -> Result<ProtectedStoreAuthoritySessionV1<'_>, InvalidMultiNodeJournal> {
        let storage_domain_digest = self.storage_domain_digest;
        let durability_generation = self.durability_generation;
        let protected_root_digest = self.protected_root_digest;
        let replay_fence = self.replay_fence;
        ProtectedStoreAuthoritySessionV1::from_verified_backend(
            self,
            storage_domain_digest,
            durability_generation,
            protected_root_digest,
            replay_fence,
        )
    }

    fn domain_genesis_digest(&self, domain: MultiNodeJournalDomainV1) -> ObjectDigest {
        protected_domain_genesis_digest(self.storage_domain_digest, self.replay_fence, domain)
    }

    fn next_domain_boundary(
        &self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<(u64, ObjectDigest), InvalidMultiNodeJournal> {
        let Some(entry) = self
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == domain)
        else {
            return Ok((1, self.domain_genesis_digest(domain)));
        };
        match entry.kind {
            ProtectedStoreObjectKindV1::Record => {
                let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
                Ok((
                    record
                        .sequence()
                        .checked_add(1)
                        .ok_or(InvalidMultiNodeJournal::HistoryGap)?,
                    record.digest(),
                ))
            }
            ProtectedStoreObjectKindV1::Checkpoint => {
                let checkpoint =
                    MultiNodeJournalCheckpointV1::decode_canonical(&entry.canonical_bytes)?;
                Ok((
                    checkpoint
                        .floor_sequence()
                        .checked_add(1)
                        .ok_or(InvalidMultiNodeJournal::HistoryGap)?,
                    checkpoint.digest(),
                ))
            }
        }
    }

    fn protects_record(&self, record: &ProtectedJournalRecordV1) -> bool {
        record.storage_domain_digest() == self.storage_domain_digest
            && record.replay_fence() == self.replay_fence
            && record.context() == self.authenticated_context
    }
}

impl ProtectedStoreBackendV1 for ProtectedJournalStoreBackendV1 {
    fn persist_once(
        &mut self,
        request: ProtectedWriteRequestV1<'_>,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedWriteOutcomeV1, InvalidMultiNodeJournal> {
        if request.storage_domain_digest != self.storage_domain_digest
            || request.replay_fence != self.replay_fence
            || request.expected_generation != self.durability_generation
            || request.expected_root_digest != self.protected_root_digest
            || request.next_generation
                != self
                    .durability_generation
                    .checked_add(1)
                    .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            || request.canonical_bytes.is_empty()
            || request.canonical_bytes.len() > super::journal::MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES
            || ObjectDigest::from_bytes(Sha256::digest(request.canonical_bytes).into())
                != request.canonical_bytes_digest
            || protected_transaction_digest(
                request.domain,
                request.kind,
                request.operation,
                request.canonical_bytes_digest,
                request.authority_binding_digest,
                request.storage_domain_digest,
                request.expected_generation,
                request.expected_root_digest,
                request.next_generation,
                request.replay_fence,
            ) != request.transaction_digest
            || !self
                .authenticated_context
                .is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let opaque_receipt_commitment = protected_receipt_commitment(
            request.transaction_digest,
            self.authenticated_context,
            verified_at_unix_seconds,
        );
        let protected_root_digest = protected_store_successor_root(
            self.protected_root_digest,
            request.transaction_digest,
            opaque_receipt_commitment,
        );
        let entry = ProtectedStoreHistoryEntryV1 {
            domain: request.domain,
            kind: request.kind,
            operation: request.operation,
            canonical_bytes: request.canonical_bytes.to_vec(),
            canonical_bytes_digest: request.canonical_bytes_digest,
            authority_binding_digest: request.authority_binding_digest,
            durability_generation: request.next_generation,
            predecessor_root_digest: request.expected_root_digest,
            protected_root_digest,
            transaction_digest: request.transaction_digest,
            opaque_receipt_commitment,
            context_digest: protected_context_digest(self.authenticated_context),
            verified_at_unix_seconds,
        };
        let mut next_history = self.history.clone();
        next_history.push(entry.clone());
        let encoded = encode_protected_store_history(
            self.storage_domain_digest,
            self.replay_fence,
            self.base_generation,
            self.base_root_digest,
            &next_history,
        )?;
        decode_protected_store_history(
            &encoded,
            self.storage_domain_digest,
            self.replay_fence,
            self.base_generation,
            self.base_root_digest,
        )?;
        validate_protected_store_semantics(
            &next_history,
            self.storage_domain_digest,
            self.replay_fence,
            self.authenticated_context,
        )?;
        let transaction_id: [u8; 16] = request.transaction_digest.as_bytes()[..16]
            .try_into()
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::RuntimeAuthority,
                PROTECTED_STORE_HEAD_KEY.to_vec(),
                encoded.clone(),
            )],
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let committed = {
            let mut authority = self
                .journal
                .claim_protected_authority(RecordNamespace::RuntimeAuthority)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            let records = authority
                .records()
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            let mut records = records.take(2);
            let current = records.next();
            let current_matches = match (self.encoded_head.as_deref(), current) {
                (None, None) => true,
                (Some(expected), Some((key, value))) => {
                    key == PROTECTED_STORE_HEAD_KEY && value == expected
                }
                _ => false,
            };
            if !current_matches || records.next().is_some() {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            drop(current);
            drop(records);
            let preflight = authority
                .preflight_transactions(std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            authority
                .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            if authority.commit(&transaction).is_err() {
                false
            } else {
                authority
                    .get(PROTECTED_STORE_HEAD_KEY)
                    .is_ok_and(|current| current == Some(encoded.as_slice()))
            }
        };
        if !committed {
            return Ok(ProtectedWriteOutcomeV1::OutcomeUnknown);
        }
        self.history = next_history;
        self.encoded_head = Some(encoded);
        self.durability_generation = request.next_generation;
        self.protected_root_digest = protected_root_digest;
        Ok(ProtectedWriteOutcomeV1::Committed(ProtectedWriteResultV1 {
            storage_domain_digest: self.storage_domain_digest,
            durability_generation: request.next_generation,
            protected_root_digest,
            opaque_receipt_commitment,
            replay_fence: self.replay_fence,
            authority_binding_digest: request.authority_binding_digest,
            predecessor_root_digest: request.expected_root_digest,
            transaction_digest: request.transaction_digest,
            context: self.authenticated_context,
        }))
    }

    fn read_current(
        &mut self,
        domain: super::journal::MultiNodeJournalDomainV1,
        kind: ProtectedStoreObjectKindV1,
        operation: Option<OperationId>,
    ) -> Result<ProtectedWriteReadbackV1, InvalidMultiNodeJournal> {
        let encoded = {
            let authority = self
                .journal
                .claim_protected_authority(RecordNamespace::RuntimeAuthority)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            let records = authority
                .records()
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
                .take(2)
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .collect::<Vec<_>>();
            match records.as_slice() {
                [(key, value)] if key.as_slice() == PROTECTED_STORE_HEAD_KEY => value.clone(),
                _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
            }
        };
        if self.encoded_head.as_ref() != Some(&encoded) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let history = decode_protected_store_history(
            &encoded,
            self.storage_domain_digest,
            self.replay_fence,
            self.base_generation,
            self.base_root_digest,
        )?;
        validate_protected_store_semantics(
            &history,
            self.storage_domain_digest,
            self.replay_fence,
            self.authenticated_context,
        )?;
        let entry = history
            .iter()
            .rev()
            .find(|entry| {
                entry.domain == domain && entry.kind == kind && entry.operation == operation
            })
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        if entry.context_digest != protected_context_digest(self.authenticated_context) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(ProtectedWriteReadbackV1 {
            domain,
            kind,
            operation,
            canonical_bytes: entry.canonical_bytes.clone(),
            result: ProtectedWriteResultV1 {
                storage_domain_digest: self.storage_domain_digest,
                durability_generation: entry.durability_generation,
                protected_root_digest: entry.protected_root_digest,
                opaque_receipt_commitment: entry.opaque_receipt_commitment,
                replay_fence: self.replay_fence,
                authority_binding_digest: entry.authority_binding_digest,
                predecessor_root_digest: entry.predecessor_root_digest,
                transaction_digest: entry.transaction_digest,
                context: self.authenticated_context,
            },
        })
    }
}

/// Owns the fixed authenticated source-side multi-node boundary.
///
/// The zero-argument opener uses a fixed protected root and authenticates its
/// signed source bootstrap record. Journal identity, clock floor, storage
/// commitments, and reducer genesis values are fixed or derived internally;
/// destination storage and restore authority live behind the separate
/// [`ProtectedSnapshotDestinationAuthorityOwnerV1`].
pub struct ProtectedMultiNodeAuthorityOwnerV1 {
    directory: PathBuf,
    role: ProtectedMultiNodeOwnerRoleV1,
    store: ProtectedStoreJournalIntegrationV1,
    artifacts: ProtectedArtifactStoreV1,
    clock: ProtectedMultiNodeClockV1,
    bootstrap: ProtectedMultiNodeBootstrapV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtectedMultiNodeOwnerRoleV1 {
    Source,
    Destination,
}

/// Owns destination-only protected storage and restore admission.
///
/// The destination bootstrap, journal, artifact root, clock floor, and node
/// identity are independent of the source owner. The inner owner is not
/// exposed, so source-authenticated context cannot be retyped as destination
/// durability or restore authority.
pub struct ProtectedSnapshotDestinationAuthorityOwnerV1 {
    inner: ProtectedMultiNodeAuthorityOwnerV1,
}

/// Proves the source owner currently admits one immutable transfer identity.
///
/// This value is issued only from authenticated source replay. It contains no
/// destination mutation authority.
#[must_use]
pub struct ProtectedSnapshotSourceAdmissionV1 {
    manifest: SnapshotTransferManifestV1,
    source_record: ProtectedJournalRecordV1,
    source_store_root: ObjectDigest,
    source_epoch: u64,
}

/// Joins destination-only restore admission to its current assignment intent.
///
/// The token remains inert: it proves that a destination assignment may
/// consume the published snapshot, but dispatches no restore effect.
#[must_use]
pub struct ProtectedDestinationAssignmentRestoreV1 {
    admission: SnapshotRestoreAdmissionV1,
    assignment: AssignmentIntentV1,
    destination_record: ProtectedJournalRecordV1,
}

/// Retains a protected row and its monotonic evidence verifier session.
///
/// Public callers can retain the authenticated context, but the generic grant
/// mint remains crate-controlled for typed verifier adapters.
pub struct ProtectedMultiNodeEvidenceSessionV1 {
    integration: ProtectedEvidenceIntegrationV1,
}

/// Retains one exact current protected row under its owning store.
pub struct ProtectedMultiNodeCurrentRecordV1 {
    record: ProtectedJournalRecordV1,
}

/// Retains an authenticated outbound request and its exact canonical frame.
#[must_use]
pub struct ProtectedOutboundNodeRequestV1 {
    envelope: NodeRequestEnvelopeV1,
    canonical_frame: Vec<u8>,
}

/// Retains a carrier-authenticated cursor-gap binding for exact resynchronization.
#[must_use]
pub struct ProtectedWatchResyncRequiredV1 {
    binding: NodeWatchBindingV1,
}

/// Reports durable watch progress or an authenticated resynchronization edge.
#[must_use]
pub enum ProtectedWatchCommitOutcomeV1 {
    /// The exact ordered batch was durably committed or retained for recovery.
    Store(ProtectedRecordCommitOutcomeV1),
    /// The authenticated peer proved that the current cursor fell below its floor.
    ResyncRequired(ProtectedWatchResyncRequiredV1),
    /// One exact semantic event artifact still needs protected readback.
    ArtifactRecoveryRequired(ProtectedWatchArtifactRecoveryV1),
    /// A semantic domain reducer write must be recovered before cursor commit.
    ReducerRecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Retains one exact watch semantic artifact across an unknown write outcome.
#[must_use]
pub struct ProtectedWatchArtifactRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
}

/// Reports complete-inventory persistence before its cursor marker is committed.
#[must_use]
pub enum ProtectedWatchBootstrapCommitOutcomeV1 {
    /// The inventory artifact and exact cursor marker were durably committed.
    Store(ProtectedRecordCommitOutcomeV1),
    /// The complete inventory artifact still needs protected readback.
    ArtifactRecoveryRequired(ProtectedWatchArtifactRecoveryV1),
    /// A capability reducer write must be resolved before the cursor can advance.
    ReducerRecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Reports protected readback of a watch semantic artifact.
#[must_use]
pub enum ProtectedWatchArtifactRecoveryOutcomeV1 {
    /// The exact semantic artifact is durably present; the caller may retry the reducer commit.
    Stored,
    /// Protected readback remains indeterminate.
    RecoveryRequired(ProtectedWatchArtifactRecoveryV1),
}

struct ProtectedWatchSemanticProjectionV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    capability: NodeCapabilitySnapshotV1,
    assignments: BTreeMap<aos_sandbox_core::SandboxId, NodeAssignmentObservationV1>,
    drain: Option<DrainObservationV1>,
}

impl ProtectedWatchSemanticProjectionV1 {
    fn from_inventory(inventory: ResyncInventoryV1) -> Result<Self, InvalidMultiNodeProtocol> {
        let cursor = inventory.cursor();
        let assignments = inventory
            .assignments()
            .iter()
            .cloned()
            .map(|observation| (observation.sandbox(), observation))
            .collect::<BTreeMap<_, _>>();
        if assignments.len() != inventory.assignments().len() {
            return Err(InvalidMultiNodeProtocol::InventoryNotCanonical);
        }
        Ok(Self {
            node: cursor.node(),
            lineage: cursor.lineage(),
            capability: inventory.capabilities().clone(),
            assignments,
            drain: None,
        })
    }

    fn apply(&mut self, body: NodeWatchEventBodyV1) -> Result<(), InvalidMultiNodeProtocol> {
        match body {
            NodeWatchEventBodyV1::Capability(next) => {
                if next.node() != self.node
                    || next.lineage() != self.lineage
                    || next.sequence() <= self.capability.sequence()
                {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                self.capability = *next;
            }
            NodeWatchEventBodyV1::Assignment(next) => {
                if next.node() != self.node || next.lineage() != self.lineage {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                if let Some(prior) = self.assignments.get(&next.sandbox()) {
                    if next.sequence() <= prior.sequence()
                        || next.epoch() < prior.epoch()
                        || (next.epoch() == prior.epoch()
                            && next.desired_generation() < prior.desired_generation())
                        || (next.epoch() == prior.epoch()
                            && next.desired_generation() == prior.desired_generation()
                            && (next.assignment_digest() != prior.assignment_digest()
                                || !prior.phase().can_transition_to(next.phase())))
                    {
                        return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                    }
                }
                self.assignments.insert(next.sandbox(), *next);
            }
            NodeWatchEventBodyV1::Drain(next) => {
                if next.node() != self.node || next.lineage() != self.lineage {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                if self.drain.as_ref().is_some_and(|prior| {
                    next.generation() < prior.generation()
                        || (next.generation() == prior.generation()
                            && (next.operation() != prior.operation()
                                || next.sequence() <= prior.sequence()
                                || !prior.phase().can_transition_to(next.phase())))
                }) {
                    return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical);
                }
                self.drain = Some(*next);
            }
        }
        Ok(())
    }
}

/// Retains one exact authenticated snapshot-byte write across ambiguous storage.
#[must_use]
pub struct ProtectedSnapshotArtifactRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
    response_frame_digest: ObjectDigest,
}

/// Reports protected snapshot staging followed by durable reducer publication.
#[must_use]
pub enum ProtectedSnapshotChunkCommitOutcomeV1 {
    /// The exact verified boundary entered the protected multi-node journal.
    Store(ProtectedRecordCommitOutcomeV1),
    /// Fixed artifact storage still needs exact readback classification.
    ArtifactRecoveryRequired(ProtectedSnapshotArtifactRecoveryV1),
}

/// Retains an exact dependency-range write across ambiguous fixed storage.
#[must_use]
pub struct ProtectedSnapshotDependencyRecoveryV1 {
    recovery: ProtectedArtifactRecoveryV1,
    response_frame_digest: ObjectDigest,
}

/// Reports one durable dependency-range transition.
#[must_use]
pub enum ProtectedSnapshotDependencyCommitOutcomeV1 {
    /// The protected dependency prefix and reducer state advanced together.
    Store(ProtectedRecordCommitOutcomeV1),
    /// Fixed artifact storage still needs exact readback classification.
    ArtifactRecoveryRequired(ProtectedSnapshotDependencyRecoveryV1),
}

/// Confirms that the authenticated source accepted the exact durable resume boundary.
#[must_use]
pub struct ProtectedSnapshotResumeReadyV1 {
    identity: super::assignment::SnapshotTransferIdentityV1,
    resume: SnapshotTransferResumeV1,
}

/// Identifies the distinct protected endpoints of one fixed-root transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedSnapshotTransferRolesV1 {
    source_node: NodeId,
    destination_node: NodeId,
    source_current_until_unix_seconds: u64,
    destination_validated_at_unix_seconds: u64,
    destination_storage_binding: ObjectDigest,
}

impl ProtectedSnapshotTransferRolesV1 {
    /// Returns the authenticated carrier endpoint that serves immutable bytes.
    #[must_use]
    pub const fn source_node(self) -> NodeId {
        self.source_node
    }

    /// Returns the distinct fixed protected-storage endpoint receiving bytes.
    #[must_use]
    pub const fn destination_node(self) -> NodeId {
        self.destination_node
    }

    /// Returns the protected source currentness deadline.
    #[must_use]
    pub const fn source_current_until_unix_seconds(self) -> u64 {
        self.source_current_until_unix_seconds
    }

    /// Returns the monotonic protected time at which destination storage was checked.
    #[must_use]
    pub const fn destination_validated_at_unix_seconds(self) -> u64 {
        self.destination_validated_at_unix_seconds
    }

    /// Returns the destination role's fixed storage binding.
    #[must_use]
    pub const fn destination_storage_binding(self) -> ObjectDigest {
        self.destination_storage_binding
    }
}

impl ProtectedSnapshotResumeReadyV1 {
    /// Returns the immutable transfer identity.
    #[must_use]
    pub const fn identity(&self) -> super::assignment::SnapshotTransferIdentityV1 {
        self.identity
    }

    /// Returns the exact durable boundary accepted by the source.
    #[must_use]
    pub const fn resume(&self) -> SnapshotTransferResumeV1 {
        self.resume
    }
}

impl ProtectedOutboundNodeRequestV1 {
    /// Returns the authenticated semantic request envelope.
    #[must_use]
    pub const fn envelope(&self) -> &NodeRequestEnvelopeV1 {
        &self.envelope
    }

    /// Returns the exact canonical bytes ready for an external transport.
    #[must_use]
    pub fn canonical_frame(&self) -> &[u8] {
        &self.canonical_frame
    }
}

impl ProtectedMultiNodeCurrentRecordV1 {
    /// Returns the exact protected current record.
    #[must_use]
    pub const fn record(&self) -> &ProtectedJournalRecordV1 {
        &self.record
    }
}

impl ProtectedSnapshotSourceAdmissionV1 {
    /// Returns the exact immutable transfer admitted by the source owner.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotTransferManifestV1 {
        &self.manifest
    }

    /// Returns the source owner's authenticated coordinator epoch.
    #[must_use]
    pub const fn source_epoch(&self) -> u64 {
        self.source_epoch
    }

    /// Returns the source protected-store root that admitted the manifest.
    #[must_use]
    pub const fn source_store_root(&self) -> ObjectDigest {
        self.source_store_root
    }
}

impl ProtectedDestinationAssignmentRestoreV1 {
    /// Returns destination-only restore admission evidence.
    #[must_use]
    pub const fn admission(&self) -> &SnapshotRestoreAdmissionV1 {
        &self.admission
    }

    /// Returns the exact destination assignment joined to the admission.
    #[must_use]
    pub const fn assignment(&self) -> &AssignmentIntentV1 {
        &self.assignment
    }

    /// Returns the destination protected row that fixed the assignment join.
    #[must_use]
    pub const fn destination_record(&self) -> &ProtectedJournalRecordV1 {
        &self.destination_record
    }
}

impl ProtectedMultiNodeEvidenceSessionV1 {
    /// Returns the exact protected verifier context retained by this session.
    #[must_use]
    pub fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.integration.context()
    }
}

impl ProtectedMultiNodeAuthorityOwnerV1 {
    /// Opens the fixed protected-root multi-node authority journal.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeAuthorityOpenErrorV1`] when protected path
    /// enforcement, journal replay, or typed authority replay fails closed.
    pub fn open_fixed_protected() -> Result<
        (Self, RecoveryReport, Option<ProtectedRecordCommitOutcomeV1>),
        ProtectedMultiNodeAuthorityOpenErrorV1,
    > {
        let directory = Path::new(PROTECTED_MULTI_NODE_ROOT);
        Self::open_fixed_at(directory, ProtectedMultiNodeOwnerRoleV1::Source)
    }

    fn open_fixed_at(
        directory: &Path,
        role: ProtectedMultiNodeOwnerRoleV1,
    ) -> Result<
        (Self, RecoveryReport, Option<ProtectedRecordCommitOutcomeV1>),
        ProtectedMultiNodeAuthorityOpenErrorV1,
    > {
        let (bootstrap, mut clock) = read_protected_multi_node_bootstrap(directory)?;
        let current_unix_seconds = clock.sample_current_time()?;
        if current_unix_seconds < bootstrap.authenticated_at_unix_seconds
            || current_unix_seconds > bootstrap.valid_until_unix_seconds
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let bootstrap_frame = CanonicalNodeFrameV1::decode(
            &bootstrap.canonical_frame,
            bootstrap.maximum_response_bytes,
        )?;
        let authenticated_context = issue_context_from_protected_bootstrap(
            bootstrap.node,
            bootstrap.lineage,
            bootstrap.authenticated_channel_binding,
            &bootstrap_frame,
            bootstrap.coordinator_epoch,
            bootstrap.authenticated_at_unix_seconds,
            current_unix_seconds,
            bootstrap.valid_until_unix_seconds,
            bootstrap.maximum_request_bytes,
            bootstrap.maximum_response_bytes,
            bootstrap.replay_fence,
            &bootstrap.signed_payload,
            &bootstrap.canonical_signature,
            &bootstrap.canonical_trust_policy,
            &bootstrap.public_key,
        )?;
        clock.advance_to(current_unix_seconds)?;
        let replay_fence = bootstrap.replay_fence;
        let storage_domain_digest =
            protected_multi_node_storage_domain_digest(authenticated_context);
        let base_root_digest =
            protected_multi_node_base_root_digest(storage_domain_digest, replay_fence);
        let (journal, report) = Journal::open_protected_at(
            directory,
            PROTECTED_MULTI_NODE_JOURNAL_NAME,
            protected_multi_node_journal_limits(),
        )?;
        let artifacts = ProtectedArtifactStoreV1::open_fixed(
            directory,
            storage_domain_digest,
            replay_fence,
            authenticated_context,
        )?;
        let mut owner = Self::from_authenticated_journal(
            directory.to_path_buf(),
            role,
            journal,
            storage_domain_digest,
            replay_fence,
            PROTECTED_MULTI_NODE_BASE_GENERATION,
            base_root_digest,
            authenticated_context,
            current_unix_seconds,
            artifacts,
            clock,
            bootstrap,
        )?;
        owner.validate_protected_watch_history()?;
        if let Some(MultiNodeReducerStateV1::SnapshotTransfer(state)) =
            owner.current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)?
        {
            owner
                .validate_snapshot_manifest_owner(state.manifest())
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        }
        let initial_admission = if owner.store.backend.history.is_empty() {
            Some(owner.admit_bootstrap_capability_once()?)
        } else {
            owner.validate_bootstrap_capability_history()?;
            None
        };
        Ok((owner, report, initial_admission))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_authenticated_journal(
        directory: PathBuf,
        role: ProtectedMultiNodeOwnerRoleV1,
        journal: Journal,
        storage_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        base_generation: u64,
        base_root_digest: ObjectDigest,
        authenticated_context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
        artifacts: ProtectedArtifactStoreV1,
        clock: ProtectedMultiNodeClockV1,
        bootstrap: ProtectedMultiNodeBootstrapV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        Ok(Self {
            directory,
            role,
            store: ProtectedStoreJournalIntegrationV1::from_authenticated_journal(
                journal,
                storage_domain_digest,
                replay_fence,
                base_generation,
                base_root_digest,
                authenticated_context,
                verified_at_unix_seconds,
            )?,
            artifacts,
            clock,
            bootstrap,
        })
    }

    fn observe_current_time(&mut self) -> Result<u64, InvalidMultiNodeJournal> {
        self.clock.recover_pending()?;
        let current_unix_seconds = self.clock.sample_current_time()?;
        let bootstrap_frame = CanonicalNodeFrameV1::decode(
            &self.bootstrap.canonical_frame,
            self.bootstrap.maximum_response_bytes,
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let revalidated_context = issue_context_from_protected_bootstrap(
            self.bootstrap.node,
            self.bootstrap.lineage,
            self.bootstrap.authenticated_channel_binding,
            &bootstrap_frame,
            self.bootstrap.coordinator_epoch,
            self.bootstrap.authenticated_at_unix_seconds,
            current_unix_seconds,
            self.bootstrap.valid_until_unix_seconds,
            self.bootstrap.maximum_request_bytes,
            self.bootstrap.maximum_response_bytes,
            self.bootstrap.replay_fence,
            &self.bootstrap.signed_payload,
            &self.bootstrap.canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        if revalidated_context != self.store.backend.authenticated_context {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        self.clock.advance_to(current_unix_seconds)?;
        Ok(current_unix_seconds)
    }

    /// Authenticates a dormant transport against fixed protected trust state.
    ///
    /// The caller supplies only the peer's detached signature. The trust policy,
    /// pinned key, and current time are loaded and observed by this owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when protected time, trust
    /// state, the signature, or the exact handshake binding fails closed.
    pub fn authenticate_dormant_transport(
        &mut self,
        handshake: DormantTransportHandshakeV1,
        canonical_signature: &[u8],
    ) -> Result<DormantAuthenticatedCoordinatorNodeTransportV1, ProtectedMultiNodeUpdateErrorV1>
    {
        let current_unix_seconds = self.observe_current_time()?;
        handshake
            .authenticate_with_protected_owner(
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
    }

    /// Prepares a current generated request under protected time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when protected time or the
    /// authenticated session/request semantics are invalid.
    pub fn prepare_dormant_exchange(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request: OperationId,
        body: &NodeRequestBodyV1,
    ) -> Result<DormantOutboundExchangeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .prepare_exchange_at_protected_time(request, body, current_unix_seconds)
            .map_err(Into::into)
    }

    /// Authenticates one inbound request with protected trust and time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the exact request is
    /// signed by the fixed pin and current under the protected clock.
    pub fn accept_dormant_request(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeRequestEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .accept_request_with_protected_owner(
                request_bytes,
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
    }

    /// Prepares a typed response under protected currentness.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when the request is stale or
    /// the response is not its exact typed answer.
    pub fn prepare_dormant_response(
        &mut self,
        transport: &DormantAuthenticatedCoordinatorNodeTransportV1,
        request: &NodeRequestEnvelopeV1,
        body: &NodeResponseBodyV1,
    ) -> Result<DormantOutboundResponseV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .prepare_response_at_protected_time(request, body, current_unix_seconds)
            .map_err(Into::into)
    }

    /// Authenticates one exact response using only protected trust and time.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the fixed pin signed
    /// the canonical response and it exactly answers the retained request.
    pub fn accept_dormant_response(
        &mut self,
        transport: DormantAuthenticatedCoordinatorNodeTransportV1,
        request: &DormantOutboundExchangeV1,
        response_bytes: &[u8],
        canonical_signature: &[u8],
    ) -> Result<NodeResponseEnvelopeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        transport.validate_protected_owner(
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
        )?;
        transport
            .accept_response_with_protected_owner(
                request,
                response_bytes,
                canonical_signature,
                &self.bootstrap.canonical_trust_policy,
                &self.bootstrap.public_key,
                current_unix_seconds,
            )
            .map_err(Into::into)
    }

    /// Returns the authenticated genesis commitment for one reducer domain.
    #[must_use]
    pub fn domain_genesis_digest(&self, domain: MultiNodeJournalDomainV1) -> ObjectDigest {
        self.store.domain_genesis_digest(domain)
    }

    /// Admits the signed bootstrap's exact capability projection for an empty store.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless the journal is empty, the
    /// protected canonical frame decodes to one exact capability response, and
    /// its snapshot and internally derived operation match this owner.
    pub fn admit_bootstrap_capability_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let verified_at = self.observe_current_time()?;
        if !self.store.backend.history.is_empty() {
            return Err(InvalidMultiNodeJournal::HistoryGap);
        }
        let record = self.expected_bootstrap_capability_record(verified_at)?;
        self.store.commit_record_once(record, verified_at)
    }

    fn validate_bootstrap_capability_history(&mut self) -> Result<(), InvalidMultiNodeJournal> {
        let verified_at = self.observe_current_time()?;
        let expected = self.expected_bootstrap_capability_record(verified_at)?;
        let first = self
            .store
            .backend
            .history
            .first()
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        let expected_bytes = expected.encode_canonical();
        if first.domain != MultiNodeJournalDomainV1::Capability
            || first.kind != ProtectedStoreObjectKindV1::Record
            || first.operation != Some(expected.operation())
            || first.authority_binding_digest.is_some()
            || first.canonical_bytes != expected_bytes
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(())
    }

    fn expected_bootstrap_capability_record(
        &self,
        verified_at: u64,
    ) -> Result<MultiNodeJournalRecordV1, InvalidMultiNodeJournal> {
        let context = self.store.backend.authenticated_context;
        let frame = CanonicalNodeFrameV1::decode(
            &self.bootstrap.canonical_frame,
            self.bootstrap.maximum_response_bytes,
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let snapshot = CanonicalNodeSemanticCodecV1::new()
            .decode_protected_bootstrap_capabilities(context, &frame, verified_at)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let expected_evidence = DurableEvidenceBindingV1::new(
            context.node(),
            context.lineage(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.carrier_binding_digest(),
            context.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            context.replay_fence(),
        )?;
        let state = CapabilityJournalStateV1::new(snapshot, expected_evidence)?;
        let operation = protected_bootstrap_capability_operation(
            self.clock.config_digest,
            frame.request(),
            frame.frame_digest(),
            frame.body_digest(),
            context,
        )?;
        let payload = super::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::Capability(state),
        )?;
        let payload_digest = payload.digest();
        let effect_digest = protected_initial_capability_effect_digest(operation, payload_digest);
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Capability,
            operation,
            1,
            self.domain_genesis_digest(MultiNodeJournalDomainV1::Capability),
            payload_digest,
            payload,
            JournalEffectStateV1::IntentCommitted,
            effect_digest,
        )?;
        Ok(record)
    }

    /// Reconstructs one exact cold-replayed current record handle.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] if protected readback or typed replay
    /// no longer matches the owner opened from the fixed protected root.
    pub fn current_record(
        &mut self,
        domain: MultiNodeJournalDomainV1,
        operation: OperationId,
    ) -> Result<Option<ProtectedMultiNodeCurrentRecordV1>, InvalidMultiNodeJournal> {
        self.observe_current_time()?;
        let Some(entry) = self
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == domain)
        else {
            return Ok(None);
        };
        if entry.kind != ProtectedStoreObjectKindV1::Record || entry.operation != Some(operation) {
            return Ok(None);
        }
        let entry_verified_at_unix_seconds = entry.verified_at_unix_seconds;
        let readback = self.store.backend.read_current(
            domain,
            ProtectedStoreObjectKindV1::Record,
            Some(operation),
        )?;
        let result = readback.result;
        let grant = ProtectedStoreCommitGrantV1 {
            kind: ProtectedStoreObjectKindV1::Record,
            canonical_bytes_digest: ObjectDigest::from_bytes(
                Sha256::digest(&readback.canonical_bytes).into(),
            ),
            storage_domain_digest: result.storage_domain_digest,
            durability_generation: result.durability_generation,
            protected_root_digest: result.protected_root_digest,
            opaque_receipt_commitment: result.opaque_receipt_commitment,
            replay_fence: result.replay_fence,
            authority_binding_digest: result.authority_binding_digest,
            context: result.context,
        };
        let record = ProtectedJournalRecordV1::from_authority_commit(
            &readback.canonical_bytes,
            grant,
            entry_verified_at_unix_seconds,
        )?;
        Ok(Some(ProtectedMultiNodeCurrentRecordV1 { record }))
    }

    /// Replays the complete set of incomplete snapshot transfers.
    ///
    /// The protected owner discovers operation identities from its own full
    /// history, so callers cannot omit a transfer or forge an empty set. Each
    /// retained row is independently read back through the fixed store before
    /// the lifecycle inventory commitment is issued.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] for stale protected context,
    /// malformed transfer state, duplicate current rows, or failed readback.
    pub fn lifecycle_transfer_inventory(
        &mut self,
    ) -> Result<crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1, InvalidMultiNodeJournal>
    {
        self.observe_current_time()?;
        let operations = self
            .store
            .backend
            .history
            .iter()
            .filter(|entry| {
                entry.domain == MultiNodeJournalDomainV1::SnapshotTransfer
                    && entry.kind == ProtectedStoreObjectKindV1::Record
            })
            .filter_map(|entry| entry.operation)
            .collect::<BTreeSet<_>>();
        let mut records = Vec::new();
        records
            .try_reserve_exact(operations.len())
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        for operation in operations {
            let protected = self.current_record_for_operation(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                operation,
            )?;
            let transfer = protected
                .record()
                .record()
                .state_payload()
                .snapshot_transfer_state()
                .ok_or(InvalidMultiNodeJournal::NonCanonicalPayload)?;
            if transfer.publication().is_none() {
                records.push(protected);
            }
        }
        let generation = self
            .store
            .backend
            .history
            .last()
            .map_or(self.store.backend.base_generation, |entry| {
                entry.durability_generation
            });
        crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1::from_protected_records(
            generation,
            self.store.backend.protected_root_digest,
            &records,
        )
        .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)
    }

    /// Rechecks an earlier complete transfer inventory against protected replay.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] if any row, absence, generation, or
    /// whole-inventory commitment changed.
    pub fn recheck_lifecycle_transfer_inventory(
        &mut self,
        retained: &crate::lifecycle::LifecycleAuthenticatedTransferInventoryV1,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let current = self.lifecycle_transfer_inventory()?;
        if &current != retained {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(())
    }

    /// Rechecks one exact current transfer transition under the protected owner.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] if the operation's current record,
    /// transition state, predecessor, payload, effect, or durable record digest
    /// differs from the retained post-effect row.
    pub fn recheck_lifecycle_transfer_record(
        &mut self,
        retained: &ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<(), InvalidMultiNodeJournal> {
        self.observe_current_time()?;
        let record = retained.record().record();
        if record.domain() != MultiNodeJournalDomainV1::SnapshotTransfer {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let current = self.current_record_for_operation(record.domain(), record.operation())?;
        if current.record().record() != record {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(())
    }

    fn current_record_for_operation(
        &mut self,
        domain: MultiNodeJournalDomainV1,
        operation: OperationId,
    ) -> Result<ProtectedMultiNodeCurrentRecordV1, InvalidMultiNodeJournal> {
        let entry = self
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| {
                entry.domain == domain
                    && entry.kind == ProtectedStoreObjectKindV1::Record
                    && entry.operation == Some(operation)
            })
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let entry_verified_at_unix_seconds = entry.verified_at_unix_seconds;
        let readback = self.store.backend.read_current(
            domain,
            ProtectedStoreObjectKindV1::Record,
            Some(operation),
        )?;
        let result = readback.result;
        let grant = ProtectedStoreCommitGrantV1 {
            kind: ProtectedStoreObjectKindV1::Record,
            canonical_bytes_digest: ObjectDigest::from_bytes(
                Sha256::digest(&readback.canonical_bytes).into(),
            ),
            storage_domain_digest: result.storage_domain_digest,
            durability_generation: result.durability_generation,
            protected_root_digest: result.protected_root_digest,
            opaque_receipt_commitment: result.opaque_receipt_commitment,
            replay_fence: result.replay_fence,
            authority_binding_digest: result.authority_binding_digest,
            context: result.context,
        };
        let record = ProtectedJournalRecordV1::from_authority_commit(
            &readback.canonical_bytes,
            grant,
            entry_verified_at_unix_seconds,
        )?;
        Ok(ProtectedMultiNodeCurrentRecordV1 { record })
    }

    /// Commits one exact reducer checkpoint under this protected owner.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless typed replay proves that the
    /// checkpoint is the exact next floor for its retained domain history.
    pub fn commit_checkpoint_once(
        &mut self,
        checkpoint: MultiNodeJournalCheckpointV1,
    ) -> Result<ProtectedCheckpointCommitOutcomeV1, InvalidMultiNodeJournal> {
        let verified_at = self.observe_current_time()?;
        self.store.commit_checkpoint_once(checkpoint, verified_at)
    }

    /// Resolves a non-assignment write only through exact protected readback.
    #[must_use]
    pub fn resolve_store_write(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if let Err(reason) = self.observe_current_time() {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired { recovery, reason };
        }
        match self.store.resolve_ambiguous(recovery) {
            ProtectedStoreResolutionV1::Committed { grant, recovery } => {
                let decoded = match grant.kind() {
                    ProtectedStoreObjectKindV1::Record => {
                        ProtectedJournalRecordV1::from_authority_commit(
                            &recovery.canonical_bytes,
                            grant,
                            recovery.verified_at_unix_seconds,
                        )
                        .map(ProtectedStoreRecoveryOutcomeV1::RecordCommitted)
                    }
                    ProtectedStoreObjectKindV1::Checkpoint => {
                        ProtectedJournalCheckpointV1::from_authority_commit(
                            &recovery.canonical_bytes,
                            grant,
                            recovery.verified_at_unix_seconds,
                        )
                        .map(ProtectedStoreRecoveryOutcomeV1::CheckpointCommitted)
                    }
                };
                match decoded {
                    Ok(committed) => committed,
                    Err(reason) => {
                        ProtectedStoreRecoveryOutcomeV1::RecoveryRequired { recovery, reason }
                    }
                }
            }
            ProtectedStoreResolutionV1::RecoveryRequired { recovery, reason } => {
                ProtectedStoreRecoveryOutcomeV1::RecoveryRequired { recovery, reason }
            }
        }
    }

    /// Issues one transport session from an exact protected expected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the row belongs to this
    /// owner and the exact canonical frame matches its protected context.
    pub fn issue_carrier_session(
        &mut self,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_channel_binding: [u8; 32],
    ) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
        let verified_at_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        issue_session_from_protected_channel(
            &protected_expected.record,
            frame,
            authenticated_channel_binding,
            self.bootstrap.maximum_request_bytes,
            self.bootstrap.maximum_response_bytes,
            verified_at_unix_seconds,
        )
    }

    /// Builds an authenticated capability request without dispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the session belongs to this
    /// fixed protected owner and remains current at the durable clock floor.
    pub fn prepare_capability_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::GetCapabilities,
            b"get-capabilities",
        )
    }

    fn prepare_outbound_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
        body: NodeRequestBodyV1,
        purpose: &[u8],
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        let current_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        let context = self.store.backend.authenticated_context;
        if session.node() != context.node()
            || session.lineage() != context.lineage()
            || session.binding_digest() != context.carrier_binding_digest()
            || session.audience_digest() != context.audience_digest()
            || session.disclosure_domain_digest() != context.disclosure_domain_digest()
            || session.coordinator_epoch() != context.coordinator_epoch()
            || session.replay_fence() != context.replay_fence()
            || !session.is_current_at(current_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            context,
            current_unix_seconds,
            purpose,
        )?;
        let codec = CanonicalNodeSemanticCodecV1::new();
        let canonical_frame = CanonicalNodeFrameV1::encode_request(
            &body,
            session.version(),
            context.carrier_binding_digest(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            operation,
            self.bootstrap.maximum_request_bytes,
            &codec,
        )?;
        let frame =
            CanonicalNodeFrameV1::decode(&canonical_frame, self.bootstrap.maximum_request_bytes)?;
        let envelope = NodeRequestEnvelopeV1::from_canonical_frame(
            session,
            &frame,
            current_unix_seconds,
            &codec,
        )?;
        Ok(ProtectedOutboundNodeRequestV1 {
            envelope,
            canonical_frame,
        })
    }

    /// Decodes one response under the same protected expected identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for a protected-store mismatch,
    /// stale session, frame mismatch, request mismatch, or invalid body.
    pub fn authenticate_carrier_response(
        &mut self,
        session: AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        request: &NodeRequestEnvelopeV1,
        frame: &CanonicalNodeFrameV1<'_>,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        let verified_at_unix_seconds = self
            .observe_current_time()
            .map_err(|_| InvalidMultiNodeProtocol::SessionMismatch)?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let grant = issue_response_from_protected_channel(
            session,
            &protected_expected.record,
            frame,
            verified_at_unix_seconds,
        )?;
        NodeResponseEnvelopeV1::from_authenticated_carrier(
            grant,
            request,
            frame,
            verified_at_unix_seconds,
            codec,
        )
    }

    /// Commits one advancing authenticated capability response.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is
    /// current for this protected owner and advances the exact durable
    /// capability projection without boot, sequence, or carrier equivocation.
    pub fn commit_capability_update(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        let observation = response.validated_capabilities()?;
        let context = self.store.backend.authenticated_context;
        if !observation.is_current_at(verified_at_unix_seconds)
            || observation.audience_node() != context.node()
            || observation.audience_digest() != context.audience_digest()
            || observation.disclosure_domain_digest() != context.disclosure_domain_digest()
            || observation.carrier_binding_digest() != context.carrier_binding_digest()
            || observation.coordinator_epoch() != context.coordinator_epoch()
            || observation.replay_fence() != context.replay_fence()
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let state = CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            context,
        )?;
        let current = reducers
            .get(&MultiNodeJournalDomainV1::Capability)
            .and_then(MultiNodeJournalReducerV1::restored_projection)
            .and_then(|state| match state {
                MultiNodeReducerStateV1::Capability(state) => Some(state),
                _ => None,
            })
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if !current.admits_successor(&state) {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::Capability)?;
        let payload = super::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::Capability(state),
        )?;
        let payload_digest = payload.digest();
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Capability,
            response.request(),
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            observation.evidence_binding_digest(),
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Resolves only an exact ambiguous capability update by protected readback.
    #[must_use]
    pub fn resolve_capability_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Capability {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Issues placement evidence from the exact current authenticated update.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay and
    /// a fresh clock sample prove that `response` is the current capability
    /// projection. The returned value remains scheduling evidence only.
    pub fn issue_current_placement_candidate(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<PlacementCandidateV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let observation = response.validated_capabilities()?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.snapshot() != observation.snapshot()
            || current.evidence().canonical_frame_digest()
                != observation.canonical_observation_digest()
            || !observation.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(PlacementCandidateV1::from_authenticated_observation(
            observation,
        ))
    }

    /// Durably admits the fixed owner's first cordon-only drain generation.
    ///
    /// The dormant fixed owner derives every field from its protected identity,
    /// current clock floor, and current root. It accepts no caller directive.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when a drain projection
    /// already exists or protected replay and persistence cannot prove the edge.
    pub fn admit_fixed_cordon_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let accepted_at_unix_seconds = self.observe_current_time()?;
        if self
            .current_domain_projection(MultiNodeJournalDomainV1::Drain)?
            .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            self.store.backend.authenticated_context,
            accepted_at_unix_seconds,
            b"fixed-cordon",
        )?;
        let directive = DrainDirectiveV1::new(
            operation,
            self.store.backend.authenticated_context.node(),
            1,
            NodeDrainModeV1::CordonOnly,
            accepted_at_unix_seconds,
            None,
            Vec::new(),
        )?;
        let state = DrainJournalStateV1::new(directive.clone(), None)?;
        let payload =
            super::journal::CanonicalJournalPayloadV1::new(MultiNodeReducerStateV1::Drain(state))?;
        let directive_digest = drain_directive_digest(&directive);
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Drain,
            operation,
            1,
            self.store
                .backend
                .domain_genesis_digest(MultiNodeJournalDomainV1::Drain),
            directive_digest,
            payload,
            JournalEffectStateV1::IntentCommitted,
            directive_digest,
        )?;
        self.store
            .commit_record_once(record, accepted_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Durably admits a fixed-root evacuation of the current assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one nonempty current assignment and the next drain generation can require
    /// snapshot, stop, containment, and replacement readiness.
    pub fn admit_fixed_evacuation_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.admit_fixed_assignment_drain(NodeDrainModeV1::Evacuate, b"fixed-evacuate")
    }

    /// Durably admits fixed-root decommissioning of the current assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one nonempty current assignment and every selected row uses the required
    /// snapshot-stop-and-replace workflow.
    pub fn admit_fixed_decommission_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.admit_fixed_assignment_drain(NodeDrainModeV1::Decommission, b"fixed-decommission")
    }

    fn admit_fixed_assignment_drain(
        &mut self,
        mode: NodeDrainModeV1,
        purpose: &[u8],
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let accepted_at_unix_seconds = self.observe_current_time()?;
        let assignment =
            match self.current_domain_projection(MultiNodeJournalDomainV1::Assignment)? {
                Some(MultiNodeReducerStateV1::Assignment(state)) => state,
                _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
            };
        let current_drain = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => Some(state),
            None => None,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current_drain.as_ref().is_some_and(|state| {
            let phase = state.observation().map(DurableDrainObservationV1::phase);
            match (state.directive().mode(), mode) {
                (NodeDrainModeV1::CordonOnly, _) => !matches!(
                    phase,
                    Some(super::draining::DrainPhaseV1::Cordoned)
                        | Some(super::draining::DrainPhaseV1::Complete)
                ),
                (NodeDrainModeV1::Evacuate, NodeDrainModeV1::Decommission) => {
                    phase != Some(super::draining::DrainPhaseV1::Complete)
                }
                _ => true,
            }
        }) {
            return Err(InvalidDrainModel::InvalidPhaseTransition.into());
        }
        let generation = match current_drain.as_ref() {
            Some(state) => state
                .directive()
                .generation()
                .checked_add(1)
                .ok_or(InvalidDrainModel::InvalidPhaseTransition)?,
            None => 1,
        };
        let deadline_unix_seconds = accepted_at_unix_seconds
            .checked_add(3_600)
            .ok_or(InvalidDrainModel::InvalidDeadline)?;
        let operation = protected_outbound_operation(
            self.clock.config_digest,
            self.store.backend.protected_root_digest,
            self.store.backend.authenticated_context,
            accepted_at_unix_seconds,
            purpose,
        )?;
        let assignments = vec![DrainAssignmentPlanV1::from_intent(
            assignment.intent(),
            DrainAssignmentStrategyV1::SnapshotStopAndReplace,
        )];
        let directive = DrainDirectiveV1::new(
            operation,
            self.store.backend.authenticated_context.node(),
            generation,
            mode,
            accepted_at_unix_seconds,
            Some(deadline_unix_seconds),
            assignments,
        )?;
        let state = DrainJournalStateV1::new(directive.clone(), None)?;
        let payload =
            super::journal::CanonicalJournalPayloadV1::new(MultiNodeReducerStateV1::Drain(state))?;
        let directive_digest = drain_directive_digest(&directive);
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::Drain)?;
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::Drain,
            operation,
            sequence,
            predecessor_digest,
            directive_digest,
            payload,
            JournalEffectStateV1::IntentCommitted,
            directive_digest,
        )?;
        self.store
            .commit_record_once(record, accepted_at_unix_seconds)
            .map_err(Into::into)
    }

    /// Builds a drain reconciliation request from the protected current directive.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless a current durable
    /// drain exists and the authenticated session belongs to the same owner.
    pub fn prepare_current_drain_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::ReconcileDrain(Box::new(state.directive().clone())),
            b"reconcile-drain",
        )
        .map_err(Into::into)
    }

    /// Durably commits a current carrier-authenticated cordon observation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response matches
    /// the exact current fixed cordon and advances its sequence and phase.
    pub fn commit_current_drain_observation(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let NodeResponseBodyV1::Drain(observation) = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if !observation.matches(current.directive())
            || !observation
                .context()
                .is_current_at(verified_at_unix_seconds)
            || observation.context() != self.store.backend.authenticated_context
            || !observation.assignments().is_empty()
            || !current.directive().assignments().is_empty()
            || current.observation().is_some_and(|retained| {
                observation.sequence() <= retained.sequence()
                    || !retained.phase().can_transition_to(observation.phase())
                    || observation.observed_at_unix_seconds() < retained.observed_at_unix_seconds()
            })
        {
            return Err(InvalidDrainModel::InvalidPhaseTransition.into());
        }
        let context = observation.context();
        let evidence = DurableEvidenceBindingV1::new(
            context.node(),
            context.lineage(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.carrier_binding_digest(),
            context.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            context.replay_fence(),
        )?;
        let durable = DurableDrainObservationV1::new(
            observation.sequence(),
            observation.phase(),
            Vec::new(),
            observation.observed_at_unix_seconds(),
            evidence,
        )?;
        let state = DrainJournalStateV1::new(current.directive().clone(), Some(durable))?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Drain(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Resolves only an exact ambiguous drain transition by protected readback.
    #[must_use]
    pub fn resolve_drain_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Drain {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Admits the immutable manifest provisioned in the fixed protected inbox.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the inbox contains
    /// exactly one canonical manifest bound to this owner and no transfer has
    /// already been admitted.
    pub fn admit_protected_snapshot_manifest_once(
        &mut self,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        if self
            .current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)?
            .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let manifest = read_protected_snapshot_manifest(&self.directory)?;
        self.validate_snapshot_manifest_owner(&manifest)?;
        let resume = SnapshotTransferResumeV1::new(&manifest, manifest.identity(), 0)?;
        let inbox_receipt = protected_snapshot_inbox_receipt(&manifest);
        let dependencies = manifest
            .dependencies()
            .iter()
            .map(|descriptor| DurableDependencyProjectionV1 {
                descriptor: descriptor.clone(),
                next_offset: 0,
                verified_prefix_digest: protected_empty_dependency_digest(
                    manifest.identity().manifest_digest(),
                    descriptor.digest(),
                ),
                protected_object_receipt: inbox_receipt,
                liveness_digest: None,
                live_until_unix_seconds: None,
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            manifest.clone(),
            resume,
            Vec::new(),
            dependencies,
            None,
        )?;
        let empty_prefix = Vec::new();
        self.commit_snapshot_projection(
            state,
            manifest.identity().operation(),
            staged_prefix_commitment(manifest.identity(), resume, &empty_prefix),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues the exact current source-side manifest admission.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the fixed source
    /// owner has durably admitted the manifest and its authenticated context
    /// remains current.
    pub fn issue_current_snapshot_source_admission(
        &mut self,
    ) -> Result<ProtectedSnapshotSourceAdmissionV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let state = self.current_snapshot_projection()?;
        let identity = state.manifest().identity();
        let current = self
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                identity.operation(),
            )?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        let context = current.record.context();
        if context.node() != identity.source_node()
            || context.coordinator_epoch()
                != self.store.backend.authenticated_context.coordinator_epoch()
            || !context.is_current_at(current_unix_seconds)
            || current
                .record
                .record()
                .state_payload()
                .snapshot_transfer_state()
                .is_none_or(|durable| durable.manifest() != state.manifest())
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(ProtectedSnapshotSourceAdmissionV1 {
            manifest: state.manifest().clone(),
            source_store_root: current.record.protected_root_digest(),
            source_epoch: context.coordinator_epoch(),
            source_record: current.record,
        })
    }

    /// Stages one authenticated dependency range and advances its durable prefix.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] for a range not equal to the
    /// exact next protected offset, corrupted complete bytes, or store failure.
    fn commit_snapshot_dependency_range(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let state = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_dependency_range(request.envelope())?;
        let range = authenticated.request();
        let (dependency_index, current_dependency) = state
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.descriptor == *range.dependency())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if range.identity() != state.manifest().identity()
            || range.offset() != current_dependency.next_offset
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
        }
        let subject = protected_snapshot_dependency_subject(
            state.manifest().identity().manifest_digest(),
            range.dependency().digest(),
        );
        let effect = snapshot_dependency_effect(subject, range.offset(), authenticated.bytes())?;
        match self
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?
        {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .commit_staged_dependency_boundary(
                    state,
                    dependency_index,
                    authenticated.bytes().len(),
                    receipt,
                    response.canonical_frame_digest(),
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotDependencyCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotDependencyCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotDependencyRecoveryV1 {
                        recovery,
                        response_frame_digest: response.canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Authenticates one source-served dependency range without storing it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless this fixed source
    /// owns the current manifest and the response exactly answers the protected
    /// request under its current carrier context.
    pub fn authenticate_snapshot_dependency_response(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotDependencyRangeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        self.validate_response_context(response, current_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_dependency_range(request.envelope())?;
        if authenticated.request().identity() != current.manifest().identity()
            || !authenticated.context().is_current_at(current_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(authenticated)
    }

    /// Resolves one ambiguous dependency artifact and continues the same prefix edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the token still names
    /// the exact next protected dependency offset and immutable descriptor.
    fn resolve_snapshot_dependency_range(
        &mut self,
        recovery: ProtectedSnapshotDependencyRecoveryV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let state = self.current_snapshot_projection()?;
        let recovery_subject = recovery.recovery.subject()?;
        let recovery_ordinal = recovery.recovery.ordinal()?;
        let (dependency_index, dependency) = state
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| {
                protected_snapshot_dependency_subject(
                    state.manifest().identity().manifest_digest(),
                    dependency.descriptor.digest(),
                ) == recovery_subject
                    && dependency.next_offset == recovery_ordinal
            })
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let prior_offset = dependency.next_offset;
        let staged_length = recovery.recovery.byte_length();
        match self.artifacts.resolve(recovery.recovery)? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => {
                if staged_length == 0 || dependency.next_offset != prior_offset {
                    return Err(InvalidMultiNodeJournal::HistoryGap.into());
                }
                self.commit_staged_dependency_boundary(
                    state,
                    dependency_index,
                    staged_length,
                    receipt,
                    recovery.response_frame_digest,
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotDependencyCommitOutcomeV1::Store)
            }
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery_again) => Ok(
                ProtectedSnapshotDependencyCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotDependencyRecoveryV1 {
                        recovery: recovery_again,
                        response_frame_digest: recovery.response_frame_digest,
                    },
                ),
            ),
        }
    }

    /// Stages an authenticated chunk and durably advances its exact boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] for request substitution,
    /// stale carrier evidence, chunk corruption, or protected store failure.
    fn commit_snapshot_chunk(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let state = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_chunk(request.envelope())?;
        let chunk_request = authenticated.request();
        if chunk_request.identity() != state.manifest().identity()
            || chunk_request.chunk().index() != state.resume().next_chunk()
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint.into());
        }
        let effect = snapshot_chunk_effect(
            state.manifest().identity().manifest_digest(),
            chunk_request.chunk().index(),
            authenticated.bytes(),
        )?;
        let outcome = self
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?;
        match outcome {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .commit_staged_snapshot_boundary(
                    state,
                    receipt,
                    response.canonical_frame_digest(),
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotChunkCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotChunkCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotArtifactRecoveryV1 {
                        recovery,
                        response_frame_digest: response.canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Authenticates one source-served chunk without granting storage authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless this is the fixed
    /// source owner and the response exactly answers the protected request for
    /// its current admitted transfer.
    pub fn authenticate_snapshot_chunk_response(
        &mut self,
        request: &ProtectedOutboundNodeRequestV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<AuthenticatedSnapshotChunkV1, ProtectedMultiNodeUpdateErrorV1> {
        let current_unix_seconds = self.observe_current_time()?;
        if self.role != ProtectedMultiNodeOwnerRoleV1::Source {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        self.validate_response_context(response, current_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        let authenticated = response.validated_snapshot_chunk(request.envelope())?;
        if authenticated.request().identity() != current.manifest().identity()
            || !authenticated.context().is_current_at(current_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(authenticated)
    }

    /// Resolves one ambiguous fixed-artifact write and continues the same edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact protected
    /// readback proves the same manifest, chunk index, bytes, and current state.
    fn resolve_snapshot_chunk(
        &mut self,
        recovery: ProtectedSnapshotArtifactRecoveryV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let state = self.current_snapshot_projection()?;
        if recovery.recovery.subject()? != state.manifest().identity().manifest_digest()
            || recovery.recovery.ordinal()? != u64::from(state.resume().next_chunk())
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        match self.artifacts.resolve(recovery.recovery)? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .commit_staged_snapshot_boundary(
                    state,
                    receipt,
                    recovery.response_frame_digest,
                    verified_at_unix_seconds,
                )
                .map(ProtectedSnapshotChunkCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery_again) => Ok(
                ProtectedSnapshotChunkCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotArtifactRecoveryV1 {
                        recovery: recovery_again,
                        response_frame_digest: recovery.response_frame_digest,
                    },
                ),
            ),
        }
    }

    /// Issues a durable resume checkpoint from fixed bytes and current journal state.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed record is
    /// the exact protected current boundary and every retained chunk byte is present.
    fn issue_snapshot_checkpoint(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<DurableSnapshotTransferCheckpointV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let state = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            .clone();
        let latest = self
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                state.manifest().identity().operation(),
            )?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if latest.record != protected_current.record {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let staged_prefix = self.artifacts.snapshot_prefix(
            state.manifest().identity().manifest_digest(),
            state.resume().next_chunk(),
        )?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (
                state.manifest().clone(),
                state.resume(),
                staged_prefix,
                journal_record,
                verified_at_unix_seconds,
            ),
            context,
            verified_at_unix_seconds,
        )?;
        DurableSnapshotTransferCheckpointV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Commits a complete dependency set produced only by authenticated reducers.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless every verified
    /// descriptor exactly covers the protected manifest and the final carrier
    /// evidence remains current for this owner.
    fn commit_verified_snapshot_dependencies(
        &mut self,
        verified: &VerifiedSnapshotDependencySetV1,
        final_response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(final_response, verified_at_unix_seconds)?;
        let current = self.current_snapshot_projection()?;
        if verified.identity() != current.manifest().identity()
            || verified.dependencies().len() != current.manifest().dependencies().len()
            || verified
                .dependencies()
                .iter()
                .zip(current.manifest().dependencies())
                .any(|(actual, expected)| actual.descriptor() != expected)
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical.into());
        }
        let context = self.store.backend.authenticated_context;
        let dependencies = verified
            .dependencies()
            .iter()
            .map(|dependency| DurableDependencyProjectionV1 {
                descriptor: dependency.descriptor().clone(),
                next_offset: dependency.descriptor().encoded_size(),
                verified_prefix_digest: dependency.descriptor().digest(),
                protected_object_receipt: protected_snapshot_dependency_receipt(
                    verified.digest(),
                    dependency.descriptor().digest(),
                    self.store.backend.protected_root_digest,
                ),
                liveness_digest: Some(protected_snapshot_dependency_liveness(
                    verified.digest(),
                    dependency.descriptor().digest(),
                    context,
                )),
                live_until_unix_seconds: Some(context.valid_until_unix_seconds()),
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.commit_snapshot_record(
            state,
            verified.identity().operation(),
            verified.digest(),
            verified.digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues durable dependency evidence from the exact current protected row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed row is
    /// current and commits the supplied move-safe verified dependency set.
    fn issue_snapshot_dependencies(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
        verified: VerifiedSnapshotDependencySetV1,
    ) -> Result<DurableSnapshotDependencySetV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let identity = verified.identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (verified, journal_record, verified_at_unix_seconds),
            context,
            verified_at_unix_seconds,
        )?;
        DurableSnapshotDependencySetV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Durably publishes a fully verified staged snapshot inside fixed storage.
    ///
    /// This is a dormant protected-store transition only; it dispatches no
    /// restore, workload, listener, or network effect.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless staged bytes and
    /// dependency evidence name the exact complete current transfer.
    fn commit_snapshot_publication(
        &mut self,
        staged: &VerifiedStagedSnapshotV1,
        dependencies: &DurableSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let current = self.current_snapshot_projection()?;
        if staged.identity() != current.manifest().identity()
            || dependencies.identity() != staged.identity()
            || !dependencies.is_current_at(verified_at_unix_seconds)
            || current.publication().is_some()
            || current.resume().next_chunk() as usize != current.manifest().chunks().len()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let publication_generation = 1;
        let publication_digest = protected_snapshot_publication_digest(
            staged,
            dependencies.digest(),
            publication_generation,
            self.store.backend.protected_root_digest,
        );
        let publication = DurablePublicationProjectionV1 {
            publication_digest,
            publication_generation,
            protected_receipt_commitment: protected_snapshot_publication_receipt(
                publication_digest,
                self.store.backend.protected_root_digest,
            ),
        };
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            current.dependencies().to_vec(),
            Some(publication),
        )?;
        self.commit_snapshot_record(
            state,
            staged.identity().operation(),
            staged.final_prefix_digest(),
            publication_digest,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues atomic-publication evidence from the exact current protected row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless publication metadata,
    /// staged bytes, fixed storage, and current owner evidence all agree.
    fn issue_snapshot_publication(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
        staged: VerifiedStagedSnapshotV1,
    ) -> Result<AtomicSnapshotPublicationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let identity = staged.identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let publication = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .and_then(SnapshotTransferJournalStateV1::publication)
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        let journal_record = protected_current.record.clone();
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = evidence.integration.context();
        let grant = evidence.integration.issue_once(
            (
                staged,
                publication.publication_generation,
                publication.publication_digest,
                journal_record,
                verified_at_unix_seconds,
            ),
            context,
            verified_at_unix_seconds,
        )?;
        AtomicSnapshotPublicationV1::from_storage_verifier(grant).map_err(Into::into)
    }

    /// Joins exact staged, dependency, and publication evidence into completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless all three opaque
    /// values remain current for the same immutable transfer.
    fn issue_snapshot_completion(
        &mut self,
        staged: VerifiedStagedSnapshotV1,
        dependencies: DurableSnapshotDependencySetV1,
        publication: AtomicSnapshotPublicationV1,
    ) -> Result<SnapshotTransferCompletionV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !dependencies.is_current_at(verified_at_unix_seconds)
            || !publication
                .evidence_context()
                .is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        SnapshotTransferCompletionV1::from_atomic_publication(staged, dependencies, publication)
            .map_err(Into::into)
    }

    /// Commits a snapshot-complete, contained, reassignment-ready drain edge.
    ///
    /// The carrier supplies only the node's raw progress. This fixed owner
    /// joins it to opaque snapshot and assignment-authority values that can be
    /// issued only by protected paths, then derives the complete evidence row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless an evacuation or
    /// decommission directive has one exact snapshot-stop target and the joined
    /// observation proves containment and replacement readiness.
    pub fn commit_current_reassignment_ready_drain(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let NodeResponseBodyV1::Drain(reported) = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        self.commit_reassignment_ready_drain_observation(
            response,
            reported,
            snapshot_completion,
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )
    }

    /// Commits a reassignment-ready drain observation carried by a watch event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the indexed event is
    /// an authenticated drain report and the same opaque snapshot and authority
    /// joins required by [`Self::commit_current_reassignment_ready_drain`] hold.
    pub fn commit_current_watch_reassignment_ready_drain(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        event_index: usize,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let NodeResponseBodyV1::WatchBatch {
            events,
            cursor_gap: None,
        } = response.body()
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        let Some(NodeWatchEventBodyV1::Drain(reported)) =
            events.get(event_index).map(NodeWatchEventV1::body)
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        self.commit_reassignment_ready_drain_observation(
            response,
            reported,
            snapshot_completion,
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_reassignment_ready_drain_observation(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        reported: &DrainObservationV1,
        snapshot_completion: SnapshotTransferCompletionV1,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
            Some(MultiNodeReducerStateV1::Drain(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.directive().mode() == NodeDrainModeV1::CordonOnly
            || current.directive().assignments().len() != 1
            || current.directive().assignments()[0].strategy()
                != DrainAssignmentStrategyV1::SnapshotStopAndReplace
        {
            return Err(InvalidDrainModel::IncompatibleStrategy.into());
        }
        let transfer_identity = snapshot_completion.identity();
        let context = self.store.backend.authenticated_context;
        if transfer_identity.source_node() != context.node()
            || transfer_identity.destination_node() == context.node()
            || transfer_identity.storage_domain_digest() != self.store.backend.storage_domain_digest
            || transfer_identity.audience_digest() != context.audience_digest()
            || transfer_identity.disclosure_domain_digest() != context.disclosure_domain_digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let observation = DrainObservationV1::from_protected_owner(
            current.directive(),
            reported,
            Some(snapshot_completion),
            snapshot_authority,
            containment_authority,
            verified_at_unix_seconds,
        )?;
        if observation.reassignment_ready().len() != 1
            || !matches!(
                observation.phase(),
                super::draining::DrainPhaseV1::ReadyForReassignment
                    | super::draining::DrainPhaseV1::Complete
            )
        {
            return Err(InvalidDrainModel::ProgressMismatch.into());
        }
        let durable = durable_drain_observation(&observation)?;
        let state = DrainJournalStateV1::new(current.directive().clone(), Some(durable))?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Drain(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    /// Issues current restore-policy evidence from the fixed protected owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the consumed snapshot
    /// row is the exact current published transfer for this owner.
    fn issue_snapshot_restore_authorization(
        &mut self,
        protected_current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<VerifiedRestoreAuthorizationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let state = protected_current
            .record
            .record()
            .state_payload()
            .snapshot_transfer_state()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?
            .clone();
        let publication = state
            .publication()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        let identity = state.manifest().identity();
        self.require_exact_snapshot_current(&protected_current, identity.operation())?;
        let context = protected_current.record.context();
        let restore_scope =
            protected_snapshot_restore_scope(identity, publication.publication_digest)?;
        let authorization_digest = protected_snapshot_restore_authorization_digest(
            identity,
            restore_scope,
            publication,
            context,
        );
        let mut evidence = self.open_evidence_session(protected_current)?;
        let verified_at_unix_seconds = self.observe_current_time()?;
        let grant = evidence.integration.issue_once(
            (
                context,
                identity.project(),
                identity.sandbox(),
                identity.destination_node(),
                identity.storage_domain_digest(),
                identity.audience_digest(),
                identity.disclosure_domain_digest(),
                restore_scope,
                publication.publication_generation,
                authorization_digest,
                verified_at_unix_seconds,
                context.valid_until_unix_seconds(),
            ),
            context,
            verified_at_unix_seconds,
        )?;
        VerifiedRestoreAuthorizationV1::from_owner_verifier(grant).map_err(Into::into)
    }

    fn require_exact_snapshot_current(
        &mut self,
        protected_current: &ProtectedMultiNodeCurrentRecordV1,
        operation: OperationId,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let latest = self
            .current_record(MultiNodeJournalDomainV1::SnapshotTransfer, operation)?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if latest.record != protected_current.record {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(())
    }

    fn current_snapshot_projection(
        &self,
    ) -> Result<SnapshotTransferJournalStateV1, InvalidMultiNodeJournal> {
        match self.current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)? {
            Some(MultiNodeReducerStateV1::SnapshotTransfer(state)) => {
                self.validate_snapshot_manifest_owner(state.manifest())
                    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
                Ok(state)
            }
            _ => Err(InvalidMultiNodeJournal::HistoryGap),
        }
    }

    fn require_destination_snapshot_role(&self) -> Result<(), InvalidSnapshotTransfer> {
        if self.role != ProtectedMultiNodeOwnerRoleV1::Destination {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(())
    }

    /// Resolves only an exact ambiguous snapshot-state commit by protected readback.
    #[must_use]
    pub fn resolve_snapshot_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::SnapshotTransfer {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    fn validate_snapshot_manifest_owner(
        &self,
        manifest: &SnapshotTransferManifestV1,
    ) -> Result<(), InvalidSnapshotTransfer> {
        let identity = manifest.identity();
        let context = self.store.backend.authenticated_context;
        let role_matches = match self.role {
            ProtectedMultiNodeOwnerRoleV1::Source => {
                identity.source_node() == context.node()
                    && identity.destination_node() != context.node()
            }
            ProtectedMultiNodeOwnerRoleV1::Destination => {
                identity.destination_node() == context.node()
                    && identity.source_node() != context.node()
                    && identity.storage_domain_digest() == self.store.backend.storage_domain_digest
            }
        };
        if !role_matches
            || identity.audience_digest() != context.audience_digest()
            || identity.disclosure_domain_digest() != context.disclosure_domain_digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
        }
        Ok(())
    }

    fn commit_staged_snapshot_boundary(
        &mut self,
        current: SnapshotTransferJournalStateV1,
        protected_object_receipt: ObjectDigest,
        response_frame_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let index = current.resume().next_chunk();
        let chunk = current
            .manifest()
            .chunks()
            .get(
                usize::try_from(index)
                    .map_err(|_| InvalidSnapshotTransfer::InvalidResumeCheckpoint)?,
            )
            .copied()
            .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?;
        let resume = SnapshotTransferResumeV1::new(
            current.manifest(),
            current.manifest().identity(),
            index
                .checked_add(1)
                .ok_or(InvalidSnapshotTransfer::InvalidResumeCheckpoint)?,
        )?;
        let mut staged_chunks = current.staged_chunks().to_vec();
        staged_chunks.push(DurableStagedChunkV1 {
            bytes_digest: chunk.digest(),
            index,
            length: chunk.length(),
            protected_object_receipt,
        });
        let transfer_operation = current.manifest().identity().operation();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            resume,
            staged_chunks,
            current.dependencies().to_vec(),
            current.publication(),
        )?;
        let staged_prefix = self.artifacts.snapshot_prefix(
            state.manifest().identity().manifest_digest(),
            state.resume().next_chunk(),
        )?;
        let effect_digest =
            staged_prefix_commitment(state.manifest().identity(), resume, &staged_prefix);
        if response_frame_digest.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeProtocol::Unspecified.into());
        }
        self.commit_snapshot_projection(
            state,
            transfer_operation,
            effect_digest,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    fn commit_staged_dependency_boundary(
        &mut self,
        current: SnapshotTransferJournalStateV1,
        dependency_index: usize,
        staged_length: usize,
        protected_object_receipt: ObjectDigest,
        response_frame_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.require_destination_snapshot_role()?;
        let dependency = current
            .dependencies()
            .get(dependency_index)
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let staged_length = u64::try_from(staged_length)
            .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let next_offset = dependency
            .next_offset
            .checked_add(staged_length)
            .filter(|end| *end <= dependency.descriptor.encoded_size())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let subject = protected_snapshot_dependency_subject(
            current.manifest().identity().manifest_digest(),
            dependency.descriptor.digest(),
        );
        let prefix = self.artifacts.dependency_prefix(subject, next_offset)?;
        let verified_prefix_digest = ObjectDigest::from_bytes(Sha256::digest(&prefix).into());
        let complete = next_offset == dependency.descriptor.encoded_size();
        if complete && verified_prefix_digest != dependency.descriptor.digest() {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
        }
        if response_frame_digest.as_bytes() == &[0; 32] {
            return Err(InvalidMultiNodeProtocol::Unspecified.into());
        }
        let context = self.store.backend.authenticated_context;
        let mut dependencies = current.dependencies().to_vec();
        dependencies[dependency_index] = DurableDependencyProjectionV1 {
            descriptor: dependency.descriptor.clone(),
            next_offset,
            verified_prefix_digest,
            protected_object_receipt,
            liveness_digest: complete.then(|| {
                protected_snapshot_dependency_liveness(
                    current.manifest().identity().manifest_digest(),
                    dependency.descriptor.digest(),
                    context,
                )
            }),
            live_until_unix_seconds: complete.then_some(context.valid_until_unix_seconds()),
        };
        let operation = current.manifest().identity().operation();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.commit_snapshot_record(
            state,
            operation,
            verified_prefix_digest,
            protected_object_receipt,
            verified_at_unix_seconds,
        )
        .map_err(Into::into)
    }

    fn commit_snapshot_projection(
        &mut self,
        state: SnapshotTransferJournalStateV1,
        operation: OperationId,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let payload_digest = state.resume().verified_prefix_digest();
        self.commit_snapshot_record(
            state,
            operation,
            payload_digest,
            effect_digest,
            verified_at_unix_seconds,
        )
    }

    fn commit_snapshot_record(
        &mut self,
        state: SnapshotTransferJournalStateV1,
        operation: OperationId,
        payload_digest: ObjectDigest,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let (sequence, predecessor_digest) = self
            .store
            .backend
            .next_domain_boundary(MultiNodeJournalDomainV1::SnapshotTransfer)?;
        let payload = super::journal::CanonicalJournalPayloadV1::new(
            MultiNodeReducerStateV1::SnapshotTransfer(state.clone()),
        )?;
        let record = MultiNodeJournalRecordV1::new(
            MultiNodeJournalDomainV1::SnapshotTransfer,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            effect_digest,
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
    }

    /// Builds the complete-inventory request that establishes a watch cursor.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the authenticated session
    /// belongs to this owner and admits its fixed rolling-version window.
    pub fn prepare_watch_bootstrap_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        let binding = self.protected_watch_binding(session)?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments { binding },
            b"watch-bootstrap",
        )
    }

    /// Durably installs an authenticated complete-inventory watch bootstrap.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the inventory is
    /// current, exactly bound to this owner, and is either the initial binding
    /// or a monotonic cursor-gap resynchronization of the retained watch.
    pub fn commit_watch_bootstrap(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedWatchBootstrapCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let inventory = response.validated_inventory()?;
        let bootstrap =
            NodeWatchBootstrapV1::from_validated_inventory(&inventory, verified_at_unix_seconds)?;
        let binding = bootstrap.cursor().binding();
        if let Some(MultiNodeReducerStateV1::Watch(current)) =
            self.current_domain_projection(MultiNodeJournalDomainV1::Watch)?
        {
            let current_binding = current.binding();
            if binding.query_digest() != current_binding.query_digest()
                || binding.authorization_digest() != current_binding.authorization_digest()
                || binding.audience_digest() != current_binding.audience_digest()
                || binding.disclosure_domain_digest() != current_binding.disclosure_domain_digest()
                || binding.schema() != current_binding.schema()
                || binding.coordinator_epoch() < current_binding.coordinator_epoch()
                || binding.history_floor_sequence() < current_binding.history_floor_sequence()
                || binding.bootstrap_watermark() < current.cursor().event_sequence()
            {
                return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
            }
        } else if binding.coordinator_epoch()
            != self.store.backend.authenticated_context.coordinator_epoch()
            || binding.history_floor_sequence() != 0
            || binding.history_floor_event_uid()
                != protected_watch_binding_digest(self.clock.config_digest, b"history-floor")
            || binding.bootstrap_watermark() != 0
            || binding.query_digest()
                != protected_watch_binding_digest(self.clock.config_digest, b"query")
            || binding.authorization_digest()
                != protected_watch_binding_digest(self.clock.config_digest, b"authorization")
            || binding.audience_digest()
                != self.store.backend.authenticated_context.audience_digest()
            || binding.disclosure_domain_digest()
                != self
                    .store
                    .backend
                    .authenticated_context
                    .disclosure_domain_digest()
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let codec = CanonicalNodeSemanticCodecV1::new();
        let canonical_inventory = codec.encode_watch_inventory(inventory.inventory())?;
        let inventory_receipt = match self.artifacts.store_exact(
            ProtectedArtifactKindV1::WatchInventory,
            bootstrap.inventory_digest(),
            binding.bootstrap_watermark(),
            &canonical_inventory,
        )? {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => receipt,
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => {
                return Ok(
                    ProtectedWatchBootstrapCommitOutcomeV1::ArtifactRecoveryRequired(
                        ProtectedWatchArtifactRecoveryV1 { recovery },
                    ),
                );
            }
        };
        if let Some(recovery) = self.install_watch_bootstrap_capability(
            response,
            inventory.inventory(),
            verified_at_unix_seconds,
        )? {
            return Ok(ProtectedWatchBootstrapCommitOutcomeV1::ReducerRecoveryRequired(recovery));
        }
        let state = WatchJournalStateV1::new(
            binding,
            bootstrap.cursor(),
            bootstrap.inventory_digest(),
            inventory_receipt,
            Vec::new(),
        )?;
        self.validate_watch_artifacts_and_semantics(&state, self.store.backend.history.len())?;
        self.commit_domain_projection(
            MultiNodeReducerStateV1::Watch(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )
        .map(ProtectedWatchBootstrapCommitOutcomeV1::Store)
        .map_err(Into::into)
    }

    fn install_watch_bootstrap_capability(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        inventory: &ResyncInventoryV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Option<ProtectedStoreRecoveryRequiredV1>, ProtectedMultiNodeUpdateErrorV1> {
        let context = response.authenticated_context();
        let evidence = DurableEvidenceBindingV1::new(
            inventory.capabilities().node(),
            inventory.capabilities().lineage(),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            context.carrier_binding_digest(),
            response.canonical_frame_digest(),
            context.canonical_frame_bytes(),
            context.coordinator_epoch(),
            context.verified_at_unix_seconds(),
            context.valid_until_unix_seconds(),
            context.replay_fence(),
        )?;
        let next = CapabilityJournalStateV1::new(inventory.capabilities().clone(), evidence)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current.snapshot() == next.snapshot() {
            return Ok(None);
        }
        if !current.admits_successor(&next) {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        match self.commit_domain_projection(
            MultiNodeReducerStateV1::Capability(next),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )? {
            ProtectedRecordCommitOutcomeV1::Committed(_) => Ok(None),
            ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery) => Ok(Some(recovery)),
        }
    }

    /// Resolves the exact capability reducer edge preceding a watch bootstrap.
    #[must_use]
    pub fn resolve_watch_bootstrap_reducer(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Capability {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Builds a watch request from the exact cold-replayed protected cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] when no durable bootstrap
    /// exists or the session, coordinator epoch, schema, or cursor is stale.
    pub fn prepare_watch_resume_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if state.binding().coordinator_epoch() != session.coordinator_epoch()
            || state.binding().audience_digest() != session.audience_digest()
            || state.binding().disclosure_domain_digest() != session.disclosure_domain_digest()
            || !state.binding().schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let maximum_events = u16::try_from(MAX_WATCH_EVENTS)
            .map_err(|_| InvalidMultiNodeProtocol::InvalidFrameLimits)?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::Watch {
                after: state.cursor(),
                maximum_events,
            },
            b"watch-resume",
        )
        .map_err(Into::into)
    }

    /// Builds a bounded relist that advances the retained watch history floor.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless current replay and
    /// session fencing prove one exact same-policy compaction bootstrap.
    pub fn prepare_watch_compaction_resync_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let binding = current.binding();
        if binding.coordinator_epoch() != session.coordinator_epoch()
            || binding.audience_digest() != session.audience_digest()
            || binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
        }
        let next = NodeWatchBindingV1::new(
            binding.coordinator_epoch(),
            current.cursor().event_sequence(),
            current.cursor().last_event_uid(),
            current.cursor().event_sequence(),
            binding.query_digest(),
            binding.authorization_digest(),
            binding.audience_digest(),
            binding.disclosure_domain_digest(),
            binding.schema(),
        )?;
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments { binding: next },
            b"watch-compaction-resync",
        )
        .map_err(Into::into)
    }

    /// Commits one exact ordered watch batch or returns a sealed resync edge.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] for stale carrier evidence,
    /// a cursor/version/epoch mismatch, an orphan event, or an oversized
    /// retained stream.
    pub fn commit_watch_batch(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedWatchCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Watch)? {
            Some(MultiNodeReducerStateV1::Watch(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let NodeResponseBodyV1::WatchBatch { events, cursor_gap } = response.body() else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if let Some(binding) = cursor_gap {
            if !events.is_empty()
                || !watch_binding_advances(current.binding(), *binding, current.cursor())
            {
                return Err(InvalidMultiNodeProtocol::WatchBindingMismatch.into());
            }
            return Ok(ProtectedWatchCommitOutcomeV1::ResyncRequired(
                ProtectedWatchResyncRequiredV1 { binding: *binding },
            ));
        }
        if events.is_empty() {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical.into());
        }
        let first = events
            .first()
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        if first.cursor().binding() != current.binding()
            || first.cursor().lineage() != current.cursor().lineage()
            || first.cursor().event_sequence()
                != current.cursor().event_sequence().saturating_add(1)
            || first.predecessor_event_uid() != current.cursor().last_event_uid()
            || events.len().saturating_add(current.events().len()) > MAX_WATCH_EVENTS
        {
            return Err(InvalidMultiNodeProtocol::WatchBatchNotCanonical.into());
        }
        let mut durable_events = current.events().to_vec();
        let codec = CanonicalNodeSemanticCodecV1::new();
        for event in events {
            let canonical_event = codec.encode_watch_event_body(event.body())?;
            let protected_event_receipt = match self.artifacts.store_exact(
                ProtectedArtifactKindV1::WatchEvent,
                event.cursor().last_event_uid(),
                event.cursor().event_sequence(),
                &canonical_event,
            )? {
                ProtectedArtifactStoreOutcomeV1::Stored(receipt) => receipt,
                ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => {
                    return Ok(ProtectedWatchCommitOutcomeV1::ArtifactRecoveryRequired(
                        ProtectedWatchArtifactRecoveryV1 { recovery },
                    ));
                }
            };
            durable_events.push(DurableWatchEventV1 {
                canonical_event_bytes: event.canonical_event_bytes(),
                canonical_event_digest: event.canonical_event_digest(),
                event_uid: event.cursor().last_event_uid(),
                predecessor_event_uid: event.predecessor_event_uid(),
                sequence: event.cursor().event_sequence(),
                protected_event_receipt,
                carrier_frame_digest: response.canonical_frame_digest(),
            });
        }
        if let Some(recovery) =
            self.apply_watch_domain_events(response, events, verified_at_unix_seconds)?
        {
            return Ok(ProtectedWatchCommitOutcomeV1::ReducerRecoveryRequired(
                recovery,
            ));
        }
        let cursor = events
            .last()
            .map(NodeWatchEventV1::cursor)
            .ok_or(InvalidMultiNodeProtocol::WatchBatchNotCanonical)?;
        let state = WatchJournalStateV1::new(
            current.binding(),
            cursor,
            current.bootstrap_inventory_digest(),
            current.bootstrap_inventory_receipt(),
            durable_events,
        )?;
        self.validate_watch_artifacts_and_semantics(&state, self.store.backend.history.len())?;
        let outcome = self.commit_domain_projection(
            MultiNodeReducerStateV1::Watch(state),
            response.request(),
            response.canonical_frame_digest(),
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedWatchCommitOutcomeV1::Store(outcome))
    }

    fn apply_watch_domain_events(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        events: &[NodeWatchEventV1],
        verified_at_unix_seconds: u64,
    ) -> Result<Option<ProtectedStoreRecoveryRequiredV1>, ProtectedMultiNodeUpdateErrorV1> {
        for (event_index, event) in events.iter().enumerate() {
            let next = match event.body() {
                NodeWatchEventBodyV1::Capability(_) => {
                    let observation = response.validated_watch_capability(event_index)?;
                    let next =
                        CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
                    let current = match self
                        .current_domain_projection(MultiNodeJournalDomainV1::Capability)?
                    {
                        Some(MultiNodeReducerStateV1::Capability(state)) => state,
                        _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
                    };
                    if current == next
                        || (current.evidence().canonical_frame_digest()
                            == response.canonical_frame_digest()
                            && current.snapshot().lineage() == next.snapshot().lineage()
                            && current.snapshot().sequence() >= next.snapshot().sequence())
                    {
                        continue;
                    }
                    if !current.admits_successor(&next) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Capability(next)
                }
                NodeWatchEventBodyV1::Assignment(observation) => {
                    let current = match self
                        .current_domain_projection(MultiNodeJournalDomainV1::Assignment)?
                    {
                        Some(MultiNodeReducerStateV1::Assignment(state)) => state,
                        _ => continue,
                    };
                    if !observation.matches(current.intent()) {
                        continue;
                    }
                    let durable = DurableAssignmentObservationV1::new(
                        observation.sandbox(),
                        observation.incarnation(),
                        observation.epoch(),
                        observation.desired_generation(),
                        observation.assignment_digest(),
                        observation.sequence(),
                        observation.phase(),
                        observation.realized_lifecycle(),
                        observation.reason(),
                        observation.observed_at_unix_seconds(),
                        observation
                            .authority()
                            .map(|authority| authority.guardian_digest()),
                    )?;
                    if current.observation() == Some(&durable) {
                        continue;
                    }
                    if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Assignment)?
                        == Some(response.canonical_frame_digest())
                        && current
                            .observation()
                            .is_some_and(|prior| prior.sequence >= observation.sequence())
                    {
                        continue;
                    }
                    if current.observation().is_some_and(|prior| {
                        observation.sequence() <= prior.sequence
                            || !prior.phase.can_transition_to(observation.phase())
                    }) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Assignment(
                        super::reducer_state::AssignmentJournalStateV1::new(
                            current.intent().clone(),
                            Some(durable),
                            current.capability_evidence_digest(),
                            current.affinities().to_vec(),
                        )?,
                    )
                }
                NodeWatchEventBodyV1::Drain(observation) => {
                    let current =
                        match self.current_domain_projection(MultiNodeJournalDomainV1::Drain)? {
                            Some(MultiNodeReducerStateV1::Drain(state)) => state,
                            _ => continue,
                        };
                    if !observation.matches(current.directive()) {
                        continue;
                    }
                    let requires_protected_evidence =
                        observation.assignments().iter().any(|assignment| {
                            matches!(
                                assignment.progress(),
                                super::draining::DrainAssignmentProgressV1::Contained
                                    | super::draining::DrainAssignmentProgressV1::Released
                            )
                        });
                    if requires_protected_evidence {
                        if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Drain)?
                            != Some(response.canonical_frame_digest())
                            || current.observation().is_none_or(|durable| {
                                !durable_drain_matches_report(durable, observation)
                            })
                        {
                            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
                        }
                        continue;
                    }
                    let durable = durable_drain_observation(observation)?;
                    if current.observation() == Some(&durable) {
                        continue;
                    }
                    if self.current_domain_effect_digest(MultiNodeJournalDomainV1::Drain)?
                        == Some(response.canonical_frame_digest())
                        && current
                            .observation()
                            .is_some_and(|prior| prior.sequence() >= durable.sequence())
                    {
                        continue;
                    }
                    if current.observation().is_some_and(|prior| {
                        durable.sequence() <= prior.sequence()
                            || !prior.phase().can_transition_to(durable.phase())
                    }) {
                        return Err(InvalidMultiNodeJournal::Equivocation.into());
                    }
                    MultiNodeReducerStateV1::Drain(DrainJournalStateV1::new(
                        current.directive().clone(),
                        Some(durable),
                    )?)
                }
            };
            match self.commit_domain_projection(
                next,
                response.request(),
                response.canonical_frame_digest(),
                verified_at_unix_seconds,
            )? {
                ProtectedRecordCommitOutcomeV1::Committed(_) => {}
                ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery) => {
                    return Ok(Some(recovery));
                }
            }
        }
        Ok(None)
    }

    /// Issues placement evidence from a durably applied capability watch event.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the selected event is
    /// carrier-authenticated, current, and exactly equals the protected current
    /// capability projection installed before the watch cursor.
    pub fn issue_current_watch_placement_candidate(
        &mut self,
        response: &NodeResponseEnvelopeV1,
        event_index: usize,
    ) -> Result<PlacementCandidateV1, ProtectedMultiNodeUpdateErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        self.validate_response_context(response, verified_at_unix_seconds)?;
        let observation = response.validated_watch_capability(event_index)?;
        let current = match self.current_domain_projection(MultiNodeJournalDomainV1::Capability)? {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let expected = CapabilityJournalStateV1::from_authenticated_observation(&observation)?;
        if current != expected || !observation.is_current_at(verified_at_unix_seconds) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(PlacementCandidateV1::from_authenticated_observation(
            observation,
        ))
    }

    /// Builds the exact relist request required by a carrier-authenticated gap.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the consumed binding remains
    /// current for this fixed owner's authenticated session.
    pub fn prepare_watch_resync_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
        resync: ProtectedWatchResyncRequiredV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        if resync.binding.coordinator_epoch() != session.coordinator_epoch()
            || resync.binding.audience_digest() != session.audience_digest()
            || resync.binding.disclosure_domain_digest() != session.disclosure_domain_digest()
            || !resync.binding.schema().admits(session.version())
        {
            return Err(InvalidMultiNodeProtocol::WatchBindingMismatch);
        }
        self.prepare_outbound_request(
            session,
            NodeRequestBodyV1::RelistAssignments {
                binding: resync.binding,
            },
            b"watch-resync",
        )
    }

    /// Resolves only an exact ambiguous watch commit by protected readback.
    #[must_use]
    pub fn resolve_watch_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        if recovery.domain != MultiNodeJournalDomainV1::Watch {
            return ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                recovery,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        self.resolve_store_write(recovery)
    }

    /// Resolves one exact watch semantic artifact through protected readback.
    #[must_use]
    pub fn resolve_watch_artifact(
        &mut self,
        pending: ProtectedWatchArtifactRecoveryV1,
    ) -> ProtectedWatchArtifactRecoveryOutcomeV1 {
        if self.observe_current_time().is_err() {
            return ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(pending);
        }
        match self.artifacts.resolve(pending.recovery.clone()) {
            Ok(ProtectedArtifactStoreOutcomeV1::Stored(_)) => {
                ProtectedWatchArtifactRecoveryOutcomeV1::Stored
            }
            Ok(ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery)) => {
                ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(
                    ProtectedWatchArtifactRecoveryV1 { recovery },
                )
            }
            Err(_) => ProtectedWatchArtifactRecoveryOutcomeV1::RecoveryRequired(pending),
        }
    }

    fn validate_watch_artifacts_and_semantics(
        &self,
        state: &WatchJournalStateV1,
        history_prefix_len: usize,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let inventory_bytes = self.artifacts.exact_payload(
            ProtectedArtifactKindV1::WatchInventory,
            state.bootstrap_inventory_digest(),
            state.binding().bootstrap_watermark(),
        )?;
        let inventory_receipt = self.artifacts.exact_receipt(
            ProtectedArtifactKindV1::WatchInventory,
            state.bootstrap_inventory_digest(),
            state.binding().bootstrap_watermark(),
        )?;
        if inventory_receipt != state.bootstrap_inventory_receipt() {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let codec = CanonicalNodeSemanticCodecV1::new();
        let inventory = codec
            .decode_watch_inventory(inventory_bytes, self.store.backend.authenticated_context)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        if inventory.cursor().binding() != state.binding()
            || inventory.cursor().event_sequence() != state.binding().bootstrap_watermark()
            || !self
                .history_prefix_contains_capability(history_prefix_len, inventory.capabilities())?
        {
            return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
        }
        let mut projection = ProtectedWatchSemanticProjectionV1::from_inventory(inventory)
            .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        for event in state.events() {
            let bytes = self.artifacts.exact_payload(
                ProtectedArtifactKindV1::WatchEvent,
                event.event_uid,
                event.sequence,
            )?;
            let receipt = self.artifacts.exact_receipt(
                ProtectedArtifactKindV1::WatchEvent,
                event.event_uid,
                event.sequence,
            )?;
            if receipt != event.protected_event_receipt
                || usize::try_from(event.canonical_event_bytes).ok() != Some(bytes.len())
                || ObjectDigest::from_bytes(Sha256::digest(bytes).into())
                    != event.canonical_event_digest
            {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            let body = codec
                .decode_watch_event_body(bytes, self.store.backend.authenticated_context)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
            if !self.history_contains_watch_domain_event(
                history_prefix_len,
                event.carrier_frame_digest,
                &body,
            )? {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            if let NodeWatchEventBodyV1::Drain(report) = &body
                && report.assignments().iter().any(|assignment| {
                    matches!(
                        assignment.progress(),
                        super::draining::DrainAssignmentProgressV1::Contained
                            | super::draining::DrainAssignmentProgressV1::Released
                    )
                })
                && !self.history_contains_verified_drain_event(
                    history_prefix_len,
                    event.carrier_frame_digest,
                    report,
                )?
            {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
            }
            projection
                .apply(body)
                .map_err(|_| InvalidMultiNodeJournal::NonCanonicalPayload)?;
        }
        Ok(())
    }

    fn history_prefix_contains_capability(
        &self,
        history_prefix_len: usize,
        snapshot: &NodeCapabilitySnapshotV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.domain != MultiNodeJournalDomainV1::Capability
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            let MultiNodeReducerStateV1::Capability(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            if state.snapshot() == snapshot {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn history_contains_watch_domain_event(
        &self,
        history_prefix_len: usize,
        carrier_frame_digest: ObjectDigest,
        body: &NodeWatchEventBodyV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        let mut matching_intent_exists = false;
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.kind != ProtectedStoreObjectKindV1::Record {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            match (body, record.state_payload().state()) {
                (
                    NodeWatchEventBodyV1::Capability(snapshot),
                    MultiNodeReducerStateV1::Capability(state),
                ) if record.effect_digest() == carrier_frame_digest
                    && state.snapshot() == snapshot.as_ref()
                    && state.evidence().canonical_frame_digest() == carrier_frame_digest =>
                {
                    return Ok(true);
                }
                (
                    NodeWatchEventBodyV1::Assignment(observation),
                    MultiNodeReducerStateV1::Assignment(state),
                ) => {
                    if observation.matches(state.intent()) {
                        matching_intent_exists = true;
                        if record.effect_digest() == carrier_frame_digest
                            && state.observation().is_some_and(|durable| {
                                durable_assignment_matches_report(durable, observation)
                            })
                        {
                            return Ok(true);
                        }
                    }
                }
                (NodeWatchEventBodyV1::Drain(report), MultiNodeReducerStateV1::Drain(state))
                    if report.matches(state.directive()) =>
                {
                    matching_intent_exists = true;
                    if record.effect_digest() == carrier_frame_digest
                        && state
                            .observation()
                            .is_some_and(|durable| durable_drain_matches_report(durable, report))
                    {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }
        Ok(match body {
            NodeWatchEventBodyV1::Capability(_) => false,
            NodeWatchEventBodyV1::Assignment(_) | NodeWatchEventBodyV1::Drain(_) => {
                !matching_intent_exists
            }
        })
    }

    fn history_contains_verified_drain_event(
        &self,
        history_prefix_len: usize,
        carrier_frame_digest: ObjectDigest,
        report: &DrainObservationV1,
    ) -> Result<bool, InvalidMultiNodeJournal> {
        for entry in self.store.backend.history.iter().take(history_prefix_len) {
            if entry.domain != MultiNodeJournalDomainV1::Drain
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            if record.effect_digest() != carrier_frame_digest {
                continue;
            }
            let MultiNodeReducerStateV1::Drain(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            if state.directive().operation() == report.operation()
                && state
                    .observation()
                    .is_some_and(|durable| durable_drain_matches_report(durable, report))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_protected_watch_history(&self) -> Result<(), InvalidMultiNodeJournal> {
        let mut prior: Option<WatchJournalStateV1> = None;
        for (history_index, entry) in self.store.backend.history.iter().enumerate() {
            if entry.domain != MultiNodeJournalDomainV1::Watch
                || entry.kind != ProtectedStoreObjectKindV1::Record
            {
                continue;
            }
            let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
            let MultiNodeReducerStateV1::Watch(state) = record.state_payload().state() else {
                return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
            };
            let state = state.clone();
            self.validate_watch_artifacts_and_semantics(&state, history_index)?;
            match &prior {
                None => {
                    if !state.events().is_empty()
                        || state.bootstrap_inventory_digest() != record.effect_digest()
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
                Some(previous) if state.events().is_empty() => {
                    if state.binding().bootstrap_watermark() < previous.cursor().event_sequence()
                        || state.bootstrap_inventory_digest() != record.effect_digest()
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
                Some(previous) => {
                    if !state.events().starts_with(previous.events())
                        || state.events().len() <= previous.events().len()
                        || state.events()[previous.events().len()..]
                            .iter()
                            .any(|event| event.carrier_frame_digest != record.effect_digest())
                    {
                        return Err(InvalidMultiNodeJournal::NonCanonicalPayload);
                    }
                }
            }
            prior = Some(state);
        }
        Ok(())
    }

    fn current_domain_projection(
        &self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<Option<MultiNodeReducerStateV1>, InvalidMultiNodeJournal> {
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            self.store.backend.authenticated_context,
        )?;
        Ok(reducers
            .get(&domain)
            .and_then(MultiNodeJournalReducerV1::restored_projection)
            .cloned())
    }

    fn current_domain_effect_digest(
        &self,
        domain: MultiNodeJournalDomainV1,
    ) -> Result<Option<ObjectDigest>, InvalidMultiNodeJournal> {
        self.store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| {
                entry.domain == domain && entry.kind == ProtectedStoreObjectKindV1::Record
            })
            .map(|entry| {
                MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)
                    .map(|record| record.effect_digest())
            })
            .transpose()
    }

    fn commit_domain_projection(
        &mut self,
        state: MultiNodeReducerStateV1,
        operation: OperationId,
        effect_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        let domain = state.domain();
        let (sequence, predecessor_digest) = self.store.backend.next_domain_boundary(domain)?;
        let payload = super::journal::CanonicalJournalPayloadV1::new(state)?;
        let payload_digest = payload.digest();
        let record = MultiNodeJournalRecordV1::new(
            domain,
            operation,
            sequence,
            predecessor_digest,
            payload_digest,
            payload,
            JournalEffectStateV1::Committed,
            effect_digest,
        )?;
        self.store
            .commit_record_once(record, verified_at_unix_seconds)
    }

    fn validate_response_context(
        &self,
        response: &NodeResponseEnvelopeV1,
        verified_at_unix_seconds: u64,
    ) -> Result<(), ProtectedMultiNodeUpdateErrorV1> {
        let context = self.store.backend.authenticated_context;
        if response.authenticated_context() != context
            || response.node() != context.node()
            || !response.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch.into());
        }
        Ok(())
    }

    fn protected_watch_binding(
        &self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<NodeWatchBindingV1, InvalidMultiNodeProtocol> {
        let context = self.store.backend.authenticated_context;
        if session.node() != context.node()
            || session.lineage() != context.lineage()
            || session.coordinator_epoch() != context.coordinator_epoch()
        {
            return Err(InvalidMultiNodeProtocol::SessionMismatch);
        }
        let schema = RollingVersionWindowV1::new(session.version(), session.version())?;
        NodeWatchBindingV1::new(
            context.coordinator_epoch(),
            0,
            protected_watch_binding_digest(self.clock.config_digest, b"history-floor"),
            0,
            protected_watch_binding_digest(self.clock.config_digest, b"query"),
            protected_watch_binding_digest(self.clock.config_digest, b"authorization"),
            context.audience_digest(),
            context.disclosure_domain_digest(),
            schema,
        )
    }

    /// Opens a monotonic evidence-verifier child by consuming its protected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless the row belongs to this exact
    /// protected owner and retains a current authenticated verifier context.
    pub fn open_evidence_session(
        &mut self,
        protected_record: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<ProtectedMultiNodeEvidenceSessionV1, InvalidMultiNodeJournal> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self.store.backend.protects_record(&protected_record.record) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let integration = ProtectedEvidenceIntegrationV1::from_protected_record(
            protected_record.record,
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedMultiNodeEvidenceSessionV1 { integration })
    }

    /// Issues a crate-internal evidence grant under a freshly advanced clock floor.
    pub(super) fn issue_verified_evidence_once<T>(
        &mut self,
        session: &mut ProtectedMultiNodeEvidenceSessionV1,
        value: T,
    ) -> Result<super::evidence_authority::VerifierEvidenceGrantV1<T>, InvalidMultiNodeJournal>
    {
        let verified_at_unix_seconds = self.observe_current_time()?;
        let context = session.integration.context();
        if context != self.store.backend.authenticated_context {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        session
            .integration
            .issue_once(value, context, verified_at_unix_seconds)
    }

    /// Verifies and commits one exact prepared assignment transition.
    ///
    /// The detached signature is canonical-decoded under fixed bounds against
    /// the trust policy and signer key retained by the protected bootstrap. The
    /// signer must also be the live carrier binding committed by
    /// `protected_expected`; no scalar key digest can substitute for it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] for a protected-row,
    /// reducer, session, signature, policy, or persistence mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_verified_assignment_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self
            .store
            .backend
            .protects_record(&protected_expected.record)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            .intent()
            .clone();
        let plan = AssignmentObservationReducerV1::new(intent.clone())
            .issue_effect_plan(record.operation())?;
        let carrier = verify_assignment_contract_from_protected_channel(
            &session,
            &protected_expected.record,
            &intent,
            authority,
            canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
            verified_at_unix_seconds,
        )?;
        let outcome = self
            .store
            .backend
            .authority_session()?
            .commit_assignment_record_once(record, &plan, carrier, verified_at_unix_seconds)?;
        Ok(match outcome {
            ProtectedAssignmentCommitOutcomeV1::Committed(committed) => {
                ProtectedAssignmentWriteOutcomeV1::Committed(committed)
            }
            ProtectedAssignmentCommitOutcomeV1::RecoveryRequired { recovery, carrier } => {
                ProtectedAssignmentWriteOutcomeV1::RecoveryRequired(
                    ProtectedAssignmentRecoveryRequiredV1 { recovery, carrier },
                )
            }
        })
    }

    /// Converts one current committed assignment into a dormant effect handoff.
    ///
    /// The method replays the complete protected history, obtains the reducer's
    /// exact semantic grant, reauthenticates the assignment signature and live
    /// carrier at the freshly advanced clock floor, and stops before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] when the committed row is no
    /// longer current or any reducer, carrier, signature, or authority binding
    /// differs from the protected history.
    pub fn prepare_verified_assignment_effect_handoff(
        &mut self,
        committed: ProtectedAssignmentStoreCommitV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentEffectReadyV1, ProtectedAssignmentWriteErrorV1> {
        let verified_at_unix_seconds = self.observe_current_time()?;
        if !self.store.backend.protects_record(committed.record()) {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        let record = committed.record().record();
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?
            .intent()
            .clone();
        let plan = AssignmentObservationReducerV1::new(intent.clone())
            .issue_effect_plan(record.operation())?;
        let reducers = replay_protected_store_semantics(
            &self.store.backend.history,
            self.store.backend.storage_domain_digest,
            self.store.backend.replay_fence,
            self.store.backend.authenticated_context,
        )?;
        let assignment_reducer = reducers
            .get(&MultiNodeJournalDomainV1::Assignment)
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?;
        let semantic_grant = assignment_reducer.issue_assignment_effect_grant(plan)?;
        let effect_time_carrier = verify_assignment_contract_from_protected_channel(
            &session,
            committed.record(),
            &intent,
            authority,
            canonical_signature,
            &self.bootstrap.canonical_trust_policy,
            &self.bootstrap.public_key,
            verified_at_unix_seconds,
        )?;
        let handoff = committed.into_publication().into_effect_handoff(
            semantic_grant,
            effect_time_carrier,
            verified_at_unix_seconds,
        )?;
        Ok(ProtectedAssignmentEffectReadyV1 { handoff })
    }

    /// Resolves one assignment write only through exact protected readback.
    #[must_use]
    pub fn resolve_assignment_write(
        &mut self,
        pending: ProtectedAssignmentRecoveryRequiredV1,
    ) -> ProtectedAssignmentWriteResolutionV1 {
        if let Err(reason) = self.observe_current_time() {
            return ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                recovery: pending,
                reason,
            };
        }
        let resolution = match self.store.backend.authority_session() {
            Ok(mut session) => {
                session.resolve_ambiguous_assignment(pending.recovery, pending.carrier)
            }
            Err(reason) => {
                return ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                    recovery: pending,
                    reason,
                };
            }
        };
        match resolution {
            ProtectedAssignmentResolutionV1::Committed(committed) => {
                ProtectedAssignmentWriteResolutionV1::Committed(committed)
            }
            ProtectedAssignmentResolutionV1::RecoveryRequired {
                recovery,
                carrier,
                reason,
            } => ProtectedAssignmentWriteResolutionV1::RecoveryRequired {
                recovery: ProtectedAssignmentRecoveryRequiredV1 { recovery, carrier },
                reason,
            },
        }
    }
}

impl ProtectedSnapshotDestinationAuthorityOwnerV1 {
    /// Opens the independent fixed destination authority root.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeAuthorityOpenErrorV1`] unless the destination
    /// bootstrap, clock floor, journal, artifacts, and typed replay authenticate.
    pub fn open_fixed_protected() -> Result<
        (Self, RecoveryReport, Option<ProtectedRecordCommitOutcomeV1>),
        ProtectedMultiNodeAuthorityOpenErrorV1,
    > {
        let (inner, report, initial) = ProtectedMultiNodeAuthorityOwnerV1::open_fixed_at(
            Path::new(PROTECTED_MULTI_NODE_DESTINATION_ROOT),
            ProtectedMultiNodeOwnerRoleV1::Destination,
        )?;
        Ok((Self { inner }, report, initial))
    }

    /// Returns the exact cold-replayed destination capability row.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless protected replay has
    /// one current capability record for the destination bootstrap identity.
    pub fn current_capability_record(
        &mut self,
    ) -> Result<ProtectedMultiNodeCurrentRecordV1, ProtectedMultiNodeUpdateErrorV1> {
        let operation = self
            .inner
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == MultiNodeJournalDomainV1::Capability)
            .and_then(|entry| entry.operation)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        self.inner
            .current_record(MultiNodeJournalDomainV1::Capability, operation)?
            .ok_or_else(|| InvalidMultiNodeJournal::HistoryGap.into())
    }

    /// Issues a destination transport session from its exact protected row.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the signed channel frame and
    /// binding belong to this destination owner and remain current.
    pub fn issue_carrier_session(
        &mut self,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        frame: &CanonicalNodeFrameV1<'_>,
        authenticated_channel_binding: [u8; 32],
    ) -> Result<AuthenticatedNodeSessionV1, InvalidMultiNodeProtocol> {
        self.inner
            .issue_carrier_session(protected_expected, frame, authenticated_channel_binding)
    }

    /// Builds a destination capability request without dispatching it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] unless the session is current for
    /// the destination's independent protected channel.
    pub fn prepare_capability_request(
        &mut self,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, InvalidMultiNodeProtocol> {
        self.inner.prepare_capability_request(session)
    }

    /// Authenticates one destination capability response under its own owner.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeProtocol`] for any protected row, session,
    /// request, signature, channel, or canonical-frame mismatch.
    pub fn authenticate_carrier_response(
        &mut self,
        session: AuthenticatedNodeSessionV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        request: &NodeRequestEnvelopeV1,
        frame: &CanonicalNodeFrameV1<'_>,
        codec: &CanonicalNodeSemanticCodecV1,
    ) -> Result<NodeResponseEnvelopeV1, InvalidMultiNodeProtocol> {
        self.inner
            .authenticate_carrier_response(session, protected_expected, request, frame, codec)
    }

    /// Commits one advancing destination capability observation.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is the
    /// exact current successor for the destination's capability reducer.
    pub fn commit_capability_update(
        &mut self,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.commit_capability_update(response)
    }

    /// Resolves an exact destination capability write by protected readback.
    #[must_use]
    pub fn resolve_capability_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        self.inner.resolve_capability_update(recovery)
    }

    /// Verifies and commits an exact destination assignment transition.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedAssignmentWriteErrorV1`] unless the destination
    /// protected row, carrier, signature, assignment authority, and reducer
    /// transition all match exactly.
    pub fn commit_verified_assignment_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        protected_expected: &ProtectedMultiNodeCurrentRecordV1,
        session: AuthenticatedNodeSessionV1,
        authority: VerifiedAssignmentAuthorityV1,
        canonical_signature: &[u8],
    ) -> Result<ProtectedAssignmentWriteOutcomeV1, ProtectedAssignmentWriteErrorV1> {
        self.inner.commit_verified_assignment_once(
            record,
            protected_expected,
            session,
            authority,
            canonical_signature,
        )
    }

    /// Resolves an exact destination assignment write by protected readback.
    #[must_use]
    pub fn resolve_assignment_write(
        &mut self,
        pending: ProtectedAssignmentRecoveryRequiredV1,
    ) -> ProtectedAssignmentWriteResolutionV1 {
        self.inner.resolve_assignment_write(pending)
    }

    /// Admits the exact source-approved manifest into destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless independent source
    /// and destination protected contexts are current, distinct, and bind the
    /// same transfer identity, epochs, operation, artifact root, and policy.
    pub fn admit_source_transfer_once(
        &mut self,
        source: &ProtectedSnapshotSourceAdmissionV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        if self.inner.role != ProtectedMultiNodeOwnerRoleV1::Destination
            || self
                .inner
                .current_domain_projection(MultiNodeJournalDomainV1::SnapshotTransfer)?
                .is_some()
        {
            return Err(InvalidMultiNodeJournal::Equivocation.into());
        }
        let manifest = read_protected_snapshot_manifest(&self.inner.directory)?;
        self.inner.validate_snapshot_manifest_owner(&manifest)?;
        let identity = manifest.identity();
        let source_context = source.source_record.context();
        let destination_context = self.inner.store.backend.authenticated_context;
        if source.manifest != manifest
            || source_context.node() != identity.source_node()
            || destination_context.node() != identity.destination_node()
            || source_context.node() == destination_context.node()
            || source_context.coordinator_epoch() != source.source_epoch
            || source.source_store_root != source.source_record.protected_root_digest()
            || source.source_record.record().operation() != identity.operation()
            || source.source_record.record().domain() != MultiNodeJournalDomainV1::SnapshotTransfer
            || source
                .source_record
                .record()
                .state_payload()
                .snapshot_transfer_state()
                .is_none_or(|state| state.manifest() != &manifest)
            || !source_context.is_current_at(destination_time)
            || !destination_context.is_current_at(destination_time)
            || source_context.audience_digest() != destination_context.audience_digest()
            || source_context.disclosure_domain_digest()
                != destination_context.disclosure_domain_digest()
            || identity.storage_domain_digest() != self.inner.store.backend.storage_domain_digest
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let resume = SnapshotTransferResumeV1::new(&manifest, identity, 0)?;
        let inbox_receipt = protected_snapshot_inbox_receipt(&manifest);
        let dependencies = manifest
            .dependencies()
            .iter()
            .map(|descriptor| DurableDependencyProjectionV1 {
                descriptor: descriptor.clone(),
                next_offset: 0,
                verified_prefix_digest: protected_empty_dependency_digest(
                    identity.manifest_digest(),
                    descriptor.digest(),
                ),
                protected_object_receipt: inbox_receipt,
                liveness_digest: None,
                live_until_unix_seconds: None,
            })
            .collect();
        let state =
            SnapshotTransferJournalStateV1::new(manifest, resume, Vec::new(), dependencies, None)?;
        self.inner
            .commit_snapshot_projection(
                state,
                identity.operation(),
                protected_cross_owner_admission_digest(
                    source,
                    destination_context,
                    self.inner.store.backend.protected_root_digest,
                ),
                destination_time,
            )
            .map_err(Into::into)
    }

    /// Returns independently authenticated source and destination roles.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source admission and
    /// destination replay remain current for one exact transfer identity.
    pub fn current_snapshot_transfer_roles(
        &mut self,
        source: &ProtectedSnapshotSourceAdmissionV1,
    ) -> Result<ProtectedSnapshotTransferRolesV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let identity = state.manifest().identity();
        let source_context = source.source_record.context();
        let destination_context = self.inner.store.backend.authenticated_context;
        if source.manifest != *state.manifest()
            || source_context.node() != identity.source_node()
            || destination_context.node() != identity.destination_node()
            || source_context.coordinator_epoch() != source.source_epoch
            || !source_context.is_current_at(destination_time)
            || !destination_context.is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        Ok(ProtectedSnapshotTransferRolesV1 {
            source_node: identity.source_node(),
            destination_node: identity.destination_node(),
            source_current_until_unix_seconds: source_context.valid_until_unix_seconds(),
            destination_validated_at_unix_seconds: destination_time,
            destination_storage_binding: protected_snapshot_destination_storage_binding(
                self.inner.store.backend.storage_domain_digest,
                self.inner.store.backend.protected_root_digest,
                identity.destination_node(),
            ),
        })
    }

    /// Builds the exact begin-or-resume request from destination durability.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source and destination
    /// owners retain one manifest and the source session is current.
    pub fn prepare_snapshot_resume_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::BeginSnapshotTransfer {
                    manifest: Box::new(destination.manifest().clone()),
                    resume: Some(destination.resume()),
                },
                b"snapshot-destination-resume",
            )
            .map_err(Into::into)
    }

    /// Verifies source acknowledgement of the destination's durable boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the response is
    /// source-authenticated and names the exact destination resume checkpoint.
    pub fn confirm_snapshot_resume(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        response: &NodeResponseEnvelopeV1,
    ) -> Result<ProtectedSnapshotResumeReadyV1, ProtectedMultiNodeUpdateErrorV1> {
        let source_time = source.observe_current_time()?;
        source.validate_response_context(response, source_time)?;
        let destination = self.inner.current_snapshot_projection()?;
        let NodeResponseBodyV1::SnapshotTransferReady {
            identity,
            next_chunk,
        } = response.body()
        else {
            return Err(InvalidMultiNodeProtocol::MethodMismatch.into());
        };
        if identity != &destination.manifest().identity()
            || *next_chunk != destination.resume().next_chunk()
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint.into());
        }
        Ok(ProtectedSnapshotResumeReadyV1 {
            identity: *identity,
            resume: destination.resume(),
        })
    }

    /// Builds the next exact source request from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless both owners retain the
    /// same manifest and the source session is current for its protected role.
    pub fn prepare_next_snapshot_chunk_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let request = SnapshotTransferChunkRequestV1::new(
            destination.manifest(),
            destination.resume().next_chunk(),
        )?;
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::FetchSnapshotChunk { request },
                b"snapshot-destination-chunk",
            )
            .map_err(Into::into)
    }

    /// Commits source-authenticated bytes into destination-only storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless source evidence is
    /// current and exactly equals the destination's next immutable chunk.
    pub fn commit_authenticated_snapshot_chunk(
        &mut self,
        authenticated: AuthenticatedSnapshotChunkV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let request = authenticated.request();
        if request.identity() != state.manifest().identity()
            || request.chunk().index() != state.resume().next_chunk()
            || authenticated.context().node() != request.identity().source_node()
            || !authenticated.context().is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::InvalidResumeCheckpoint.into());
        }
        let effect = snapshot_chunk_effect(
            request.identity().manifest_digest(),
            request.chunk().index(),
            authenticated.bytes(),
        )?;
        match self
            .inner
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?
        {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .inner
                .commit_staged_snapshot_boundary(
                    state,
                    receipt,
                    authenticated.context().canonical_frame_digest(),
                    destination_time,
                )
                .map(ProtectedSnapshotChunkCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotChunkCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotArtifactRecoveryV1 {
                        recovery,
                        response_frame_digest: authenticated.context().canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Builds the next exact dependency request from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless chunks are complete,
    /// one dependency range remains, and both fixed owners retain one identity.
    pub fn prepare_next_snapshot_dependency_request(
        &mut self,
        source: &mut ProtectedMultiNodeAuthorityOwnerV1,
        session: &AuthenticatedNodeSessionV1,
    ) -> Result<ProtectedOutboundNodeRequestV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination = self.inner.current_snapshot_projection()?;
        let admitted = source.issue_current_snapshot_source_admission()?;
        if admitted.manifest != *destination.manifest()
            || destination.resume().next_chunk() as usize != destination.manifest().chunks().len()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let (dependency_index, projection) = destination
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.next_offset < dependency.descriptor.encoded_size())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let remaining = projection
            .descriptor
            .encoded_size()
            .checked_sub(projection.next_offset)
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let length = u32::try_from(remaining.min(u64::from(
            super::assignment::MAX_SNAPSHOT_TRANSFER_CHUNK_BYTES,
        )))
        .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        let request = SnapshotDependencyRangeV1::new(
            destination.manifest(),
            u32::try_from(dependency_index)
                .map_err(|_| InvalidSnapshotTransfer::DependenciesNotCanonical)?,
            projection.next_offset,
            length,
        )?;
        source
            .prepare_outbound_request(
                session,
                NodeRequestBodyV1::FetchSnapshotDependency { request },
                b"snapshot-destination-dependency",
            )
            .map_err(Into::into)
    }

    /// Commits a source-authenticated dependency range into destination storage.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the opaque range is
    /// current and equals the destination's exact next dependency prefix.
    pub fn commit_authenticated_snapshot_dependency(
        &mut self,
        authenticated: AuthenticatedSnapshotDependencyRangeV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let state = self.inner.current_snapshot_projection()?;
        let range = authenticated.request();
        let (dependency_index, current_dependency) = state
            .dependencies()
            .iter()
            .enumerate()
            .find(|(_, dependency)| dependency.descriptor == *range.dependency())
            .ok_or(InvalidSnapshotTransfer::DependenciesNotCanonical)?;
        if range.identity() != state.manifest().identity()
            || range.offset() != current_dependency.next_offset
            || authenticated.context().node() != range.identity().source_node()
            || !authenticated.context().is_current_at(destination_time)
        {
            return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
        }
        let subject = protected_snapshot_dependency_subject(
            range.identity().manifest_digest(),
            range.dependency().digest(),
        );
        let effect = snapshot_dependency_effect(subject, range.offset(), authenticated.bytes())?;
        match self
            .inner
            .artifacts
            .store_snapshot_effect(effect, authenticated.bytes())?
        {
            ProtectedArtifactStoreOutcomeV1::Stored(receipt) => self
                .inner
                .commit_staged_dependency_boundary(
                    state,
                    dependency_index,
                    authenticated.bytes().len(),
                    receipt,
                    authenticated.context().canonical_frame_digest(),
                    destination_time,
                )
                .map(ProtectedSnapshotDependencyCommitOutcomeV1::Store),
            ProtectedArtifactStoreOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedSnapshotDependencyCommitOutcomeV1::ArtifactRecoveryRequired(
                    ProtectedSnapshotDependencyRecoveryV1 {
                        recovery,
                        response_frame_digest: authenticated.context().canonical_frame_digest(),
                    },
                ),
            ),
        }
    }

    /// Resolves an exact destination chunk-artifact ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact artifact
    /// readback and destination replay still name the same chunk boundary.
    pub fn resolve_snapshot_chunk(
        &mut self,
        recovery: ProtectedSnapshotArtifactRecoveryV1,
    ) -> Result<ProtectedSnapshotChunkCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.resolve_snapshot_chunk(recovery)
    }

    /// Resolves an exact destination dependency-artifact ambiguity.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact artifact
    /// readback and destination replay still name the same dependency boundary.
    pub fn resolve_snapshot_dependency(
        &mut self,
        recovery: ProtectedSnapshotDependencyRecoveryV1,
    ) -> Result<ProtectedSnapshotDependencyCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.resolve_snapshot_dependency_range(recovery)
    }

    /// Returns an opaque current destination snapshot record.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless destination replay
    /// yields the exact current transfer operation.
    pub fn current_snapshot_record(
        &mut self,
    ) -> Result<ProtectedMultiNodeCurrentRecordV1, ProtectedMultiNodeUpdateErrorV1> {
        let state = self.inner.current_snapshot_projection()?;
        self.inner
            .current_record(
                MultiNodeJournalDomainV1::SnapshotTransfer,
                state.manifest().identity().operation(),
            )?
            .ok_or_else(|| InvalidMultiNodeJournal::HistoryGap.into())
    }

    /// Issues a destination-protected staged-byte checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the record is the
    /// exact current destination boundary and every staged byte is present.
    pub fn issue_snapshot_checkpoint(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
    ) -> Result<DurableSnapshotTransferCheckpointV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_checkpoint(current)
    }

    /// Commits a complete verified dependency set under destination authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless exact protected
    /// dependency bytes already cover every manifest descriptor.
    pub fn commit_verified_snapshot_dependencies(
        &mut self,
        verified: &VerifiedSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let current = self.inner.current_snapshot_projection()?;
        if verified.identity() != current.manifest().identity()
            || verified.dependencies().len() != current.manifest().dependencies().len()
            || verified
                .dependencies()
                .iter()
                .zip(current.manifest().dependencies())
                .any(|(actual, expected)| actual.descriptor() != expected)
        {
            return Err(InvalidSnapshotTransfer::DependenciesNotCanonical.into());
        }
        for dependency in current.dependencies() {
            let subject = protected_snapshot_dependency_subject(
                current.manifest().identity().manifest_digest(),
                dependency.descriptor.digest(),
            );
            let bytes = self
                .inner
                .artifacts
                .dependency_prefix(subject, dependency.descriptor.encoded_size())?;
            if ObjectDigest::from_bytes(Sha256::digest(&bytes).into())
                != dependency.descriptor.digest()
            {
                return Err(InvalidSnapshotTransfer::ChunkIntegrityMismatch.into());
            }
        }
        let context = self.inner.store.backend.authenticated_context;
        let dependencies = current
            .dependencies()
            .iter()
            .map(|dependency| DurableDependencyProjectionV1 {
                descriptor: dependency.descriptor.clone(),
                next_offset: dependency.descriptor.encoded_size(),
                verified_prefix_digest: dependency.descriptor.digest(),
                protected_object_receipt: dependency.protected_object_receipt,
                liveness_digest: Some(protected_snapshot_dependency_liveness(
                    verified.digest(),
                    dependency.descriptor.digest(),
                    context,
                )),
                live_until_unix_seconds: Some(context.valid_until_unix_seconds()),
            })
            .collect();
        let state = SnapshotTransferJournalStateV1::new(
            current.manifest().clone(),
            current.resume(),
            current.staged_chunks().to_vec(),
            dependencies,
            current.publication(),
        )?;
        self.inner
            .commit_snapshot_record(
                state,
                verified.identity().operation(),
                verified.digest(),
                verified.digest(),
                destination_time,
            )
            .map_err(Into::into)
    }

    /// Issues durable destination dependency evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the opaque record is
    /// current and commits the exact complete dependency set.
    pub fn issue_snapshot_dependencies(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
        verified: VerifiedSnapshotDependencySetV1,
    ) -> Result<DurableSnapshotDependencySetV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_dependencies(current, verified)
    }

    /// Commits atomic destination publication for verified immutable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless staged bytes and
    /// dependency evidence equal the destination's current transfer.
    pub fn commit_snapshot_publication(
        &mut self,
        staged: &VerifiedStagedSnapshotV1,
        dependencies: &DurableSnapshotDependencySetV1,
    ) -> Result<ProtectedRecordCommitOutcomeV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.commit_snapshot_publication(staged, dependencies)
    }

    /// Issues atomic publication evidence solely from destination replay.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the supplied record
    /// is the exact current published destination state.
    pub fn issue_snapshot_publication(
        &mut self,
        current: ProtectedMultiNodeCurrentRecordV1,
        staged: VerifiedStagedSnapshotV1,
    ) -> Result<AtomicSnapshotPublicationV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner.issue_snapshot_publication(current, staged)
    }

    /// Joins destination staging, dependencies, and publication into completion.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless all opaque values are
    /// current and bind one exact immutable transfer.
    pub fn issue_snapshot_completion(
        &mut self,
        staged: VerifiedStagedSnapshotV1,
        dependencies: DurableSnapshotDependencySetV1,
        publication: AtomicSnapshotPublicationV1,
    ) -> Result<SnapshotTransferCompletionV1, ProtectedMultiNodeUpdateErrorV1> {
        self.inner
            .issue_snapshot_completion(staged, dependencies, publication)
    }

    /// Constructs destination-only restore admission from a verified publication.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless destination capability,
    /// authorization, publication, dependency, epoch, and currentness evidence
    /// all remain exact under this protected owner.
    pub fn admit_current_snapshot_restore(
        &mut self,
        destination_capability_response: &NodeResponseEnvelopeV1,
        completion: SnapshotTransferCompletionV1,
    ) -> Result<SnapshotRestoreAdmissionDecisionV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        self.inner
            .validate_response_context(destination_capability_response, destination_time)?;
        let capability = destination_capability_response.validated_capabilities()?;
        let current_capability = match self
            .inner
            .current_domain_projection(MultiNodeJournalDomainV1::Capability)?
        {
            Some(MultiNodeReducerStateV1::Capability(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        if current_capability.snapshot() != capability.snapshot()
            || current_capability.evidence().canonical_frame_digest()
                != capability.canonical_observation_digest()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let state = self.inner.current_snapshot_projection()?;
        let publication = state
            .publication()
            .ok_or(InvalidSnapshotTransfer::RestoreAdmissionMismatch)?;
        if completion.identity() != state.manifest().identity()
            || completion.publication_generation() != publication.publication_generation
            || completion.publication_digest() != publication.publication_digest
            || completion.protected_journal_record().context().node()
                != state.manifest().identity().destination_node()
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let current = self.current_snapshot_record()?;
        if current.record() != completion.protected_journal_record() {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let authorization = self.inner.issue_snapshot_restore_authorization(current)?;
        SnapshotRestoreAdmissionV1::from_verified_publication(
            state.manifest(),
            completion,
            &capability,
            authorization,
            destination_time,
        )
        .map_err(Into::into)
    }

    /// Joins eligible restore admission to the exact destination assignment.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedMultiNodeUpdateErrorV1`] unless the admission remains
    /// current and its project, sandbox, destination, incarnation, epoch, and
    /// generation equal the protected current destination assignment.
    pub fn join_current_destination_assignment_restore(
        &mut self,
        admission: SnapshotRestoreAdmissionV1,
    ) -> Result<ProtectedDestinationAssignmentRestoreV1, ProtectedMultiNodeUpdateErrorV1> {
        let destination_time = self.inner.observe_current_time()?;
        let assignment = match self
            .inner
            .current_domain_projection(MultiNodeJournalDomainV1::Assignment)?
        {
            Some(MultiNodeReducerStateV1::Assignment(state)) => state,
            _ => return Err(InvalidMultiNodeJournal::HistoryGap.into()),
        };
        let identity = admission.identity();
        if !admission.is_current_at(destination_time)
            || assignment.intent().assignment().manifest().project() != identity.project()
            || assignment.intent().sandbox() != identity.sandbox()
            || assignment.intent().incarnation() != identity.incarnation()
            || assignment.intent().epoch() != identity.assignment_epoch()
            || assignment.intent().desired_generation() != identity.desired_generation()
            || assignment.intent().assignment_digest() != identity.assignment_digest()
            || assignment.intent().node() != identity.destination_node()
            || !assignment
                .intent()
                .selected_capability_binding()
                .matches_current(admission.destination_capability(), destination_time)
        {
            return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch.into());
        }
        let operation = self
            .inner
            .store
            .backend
            .history
            .iter()
            .rev()
            .find(|entry| entry.domain == MultiNodeJournalDomainV1::Assignment)
            .and_then(|entry| entry.operation)
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        let destination_record = self
            .inner
            .current_record(MultiNodeJournalDomainV1::Assignment, operation)?
            .ok_or(InvalidMultiNodeJournal::HistoryGap)?;
        if destination_record
            .record()
            .record()
            .state_payload()
            .assignment_state()
            .is_none_or(|state| state.intent() != assignment.intent())
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
        }
        Ok(ProtectedDestinationAssignmentRestoreV1 {
            admission,
            assignment: assignment.intent().clone(),
            destination_record: destination_record.record,
        })
    }

    /// Resolves an exact destination snapshot reducer write.
    #[must_use]
    pub fn resolve_snapshot_update(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreRecoveryOutcomeV1 {
        self.inner.resolve_snapshot_update(recovery)
    }
}

/// Owns the dormant, crate-controlled protected-store integration.
pub(super) struct ProtectedStoreJournalIntegrationV1 {
    backend: ProtectedJournalStoreBackendV1,
}

impl ProtectedStoreJournalIntegrationV1 {
    /// Reopens and authenticates the complete bounded store history.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_journal(
        journal: Journal,
        storage_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        base_generation: u64,
        base_root_digest: ObjectDigest,
        authenticated_context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        let backend = ProtectedJournalStoreBackendV1::from_protected_journal(
            journal,
            storage_domain_digest,
            replay_fence,
            base_generation,
            base_root_digest,
            authenticated_context,
            verified_at_unix_seconds,
        )?;
        let mut integration = Self { backend };
        {
            let _session = integration.backend.authority_session()?;
        }
        Ok(integration)
    }

    /// Returns the protected genesis commitment for a new domain chain.
    pub(super) fn domain_genesis_digest(&self, domain: MultiNodeJournalDomainV1) -> ObjectDigest {
        self.backend.domain_genesis_digest(domain)
    }

    /// Commits one non-assignment record through the sealed backend.
    pub(super) fn commit_record_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        self.backend
            .authority_session()?
            .commit_record_once(record, verified_at_unix_seconds)
    }

    /// Commits one checkpoint through the same global CAS chain.
    pub(super) fn commit_checkpoint_once(
        &mut self,
        checkpoint: MultiNodeJournalCheckpointV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedCheckpointCommitOutcomeV1, InvalidMultiNodeJournal> {
        self.backend
            .authority_session()?
            .commit_checkpoint_once(checkpoint, verified_at_unix_seconds)
    }

    /// Reclassifies one ambiguous write only by authenticated exact readback.
    pub(super) fn resolve_ambiguous(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreResolutionV1 {
        if self.backend.durability_generation == recovery.next_generation {
            return match self.resolve_replayed_successor(&recovery) {
                Ok(grant) => ProtectedStoreResolutionV1::Committed { grant, recovery },
                Err(reason) => ProtectedStoreResolutionV1::RecoveryRequired { recovery, reason },
            };
        }
        match self.backend.authority_session() {
            Ok(mut session) => session.resolve_ambiguous(recovery),
            Err(reason) => ProtectedStoreResolutionV1::RecoveryRequired { recovery, reason },
        }
    }

    fn resolve_replayed_successor(
        &mut self,
        recovery: &ProtectedStoreRecoveryRequiredV1,
    ) -> Result<ProtectedStoreCommitGrantV1, InvalidMultiNodeJournal> {
        let readback =
            self.backend
                .read_current(recovery.domain, recovery.kind, recovery.operation)?;
        let result = readback.result;
        if readback.canonical_bytes != recovery.canonical_bytes
            || ObjectDigest::from_bytes(Sha256::digest(&readback.canonical_bytes).into())
                != recovery.canonical_bytes_digest
            || result.storage_domain_digest != self.backend.storage_domain_digest
            || result.durability_generation != recovery.next_generation
            || result.predecessor_root_digest != recovery.expected_root_digest
            || result.protected_root_digest != self.backend.protected_root_digest
            || result.transaction_digest != recovery.transaction_digest
            || result.replay_fence != self.backend.replay_fence
            || result.authority_binding_digest != recovery.authority_binding_digest
            || result.context != self.backend.authenticated_context
            || !result
                .context
                .is_current_at(recovery.verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(ProtectedStoreCommitGrantV1 {
            kind: recovery.kind,
            canonical_bytes_digest: recovery.canonical_bytes_digest,
            storage_domain_digest: result.storage_domain_digest,
            durability_generation: result.durability_generation,
            protected_root_digest: result.protected_root_digest,
            opaque_receipt_commitment: result.opaque_receipt_commitment,
            replay_fence: result.replay_fence,
            authority_binding_digest: result.authority_binding_digest,
            context: result.context,
        })
    }

    /// Restores one bounded canonical checkpoint and successor sequence.
    pub(super) fn restore_once(
        &mut self,
        checkpoint: ProtectedJournalCheckpointV1,
        records: Vec<ProtectedJournalRecordV1>,
        verified_at_unix_seconds: u64,
    ) -> Result<MultiNodeJournalReducerV1, InvalidMultiNodeJournal> {
        self.backend.authority_session()?.restore_once(
            checkpoint,
            records,
            verified_at_unix_seconds,
        )
    }
}

/// Owns exclusive access to one authenticated protected-store backend.
///
/// Its constructor is private and intended only for a protected-store integration
/// that performs actual storage authentication and replay-fence persistence.
struct ProtectedStoreAuthoritySessionV1<'a> {
    backend: &'a mut dyn ProtectedStoreBackendV1,
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    replay_fence: ObjectDigest,
}

/// Retains exact canonical bytes needed to resolve an outcome-unknown write.
#[must_use]
pub struct ProtectedStoreRecoveryRequiredV1 {
    domain: super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes: Vec<u8>,
    canonical_bytes_digest: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    expected_generation: u64,
    expected_root_digest: ObjectDigest,
    next_generation: u64,
    transaction_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
}

enum ProtectedStorePersistOutcomeV1 {
    Committed {
        grant: ProtectedStoreCommitGrantV1,
        recovery: ProtectedStoreRecoveryRequiredV1,
    },
    RecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

pub(super) enum ProtectedStoreResolutionV1 {
    Committed {
        grant: ProtectedStoreCommitGrantV1,
        recovery: ProtectedStoreRecoveryRequiredV1,
    },
    RecoveryRequired {
        recovery: ProtectedStoreRecoveryRequiredV1,
        reason: InvalidMultiNodeJournal,
    },
}

/// Reports a protected record write without discarding ambiguity state.
#[must_use]
pub enum ProtectedRecordCommitOutcomeV1 {
    /// The exact canonical row was committed and read back.
    Committed(ProtectedJournalRecordV1),
    /// The exact transaction must be resolved through protected readback.
    RecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Reports a protected checkpoint write without discarding ambiguity state.
#[must_use]
pub enum ProtectedCheckpointCommitOutcomeV1 {
    /// The exact canonical checkpoint was committed and read back.
    Committed(ProtectedJournalCheckpointV1),
    /// The exact transaction must be resolved through protected readback.
    RecoveryRequired(ProtectedStoreRecoveryRequiredV1),
}

/// Reports recovery of any non-assignment protected-store object.
#[must_use]
pub enum ProtectedStoreRecoveryOutcomeV1 {
    /// The exact canonical record was authenticated as committed.
    RecordCommitted(ProtectedJournalRecordV1),
    /// The exact canonical checkpoint was authenticated as committed.
    CheckpointCommitted(ProtectedJournalCheckpointV1),
    /// Recovery remains indeterminate or observed conflicting state.
    RecoveryRequired {
        /// Retains the exact transaction for another observation.
        recovery: ProtectedStoreRecoveryRequiredV1,
        /// Describes the fail-closed recovery classification.
        reason: InvalidMultiNodeJournal,
    },
}

impl sealed::Sealed for ProtectedStoreAuthoritySessionV1<'_> {}

impl<'a> ProtectedStoreAuthoritySessionV1<'a> {
    fn from_verified_backend(
        backend: &'a mut dyn ProtectedStoreBackendV1,
        storage_domain_digest: ObjectDigest,
        durability_generation: u64,
        protected_root_digest: ObjectDigest,
        replay_fence: ObjectDigest,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        if storage_domain_digest.as_bytes() == &[0; 32]
            || durability_generation == 0
            || protected_root_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(Self {
            backend,
            storage_domain_digest,
            durability_generation,
            protected_root_digest,
            replay_fence,
        })
    }

    /// Persists and issues one exact protected journal record.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when persistence, authentication,
    /// currentness, monotonic durability, byte binding, or replay fencing fails.
    fn commit_record_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedRecordCommitOutcomeV1, InvalidMultiNodeJournal> {
        if record.domain() == super::journal::MultiNodeJournalDomainV1::Assignment {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let canonical_bytes = record.encode_canonical();
        let domain = record.domain();
        let grant = self.persist_once(
            domain,
            ProtectedStoreObjectKindV1::Record,
            Some(record.operation()),
            &canonical_bytes,
            verified_at_unix_seconds,
            None,
            None,
        )?;
        match grant {
            ProtectedStorePersistOutcomeV1::Committed { grant, recovery } => {
                match ProtectedJournalRecordV1::from_authority_commit(
                    &canonical_bytes,
                    grant,
                    verified_at_unix_seconds,
                ) {
                    Ok(record) => Ok(ProtectedRecordCommitOutcomeV1::Committed(record)),
                    Err(_) => {
                        self.reopen_ambiguous(&recovery);
                        Ok(ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery))
                    }
                }
            }
            ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery) => {
                Ok(ProtectedRecordCommitOutcomeV1::RecoveryRequired(recovery))
            }
        }
    }

    /// Persists one assignment record under its exact authenticated carrier.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] unless the record contains the exact
    /// node/epoch/assignment selected by the carrier contract, its lease and
    /// signature binding is current, and the protected receipt echoes that
    /// singular contract.
    fn commit_assignment_record_once(
        &mut self,
        record: MultiNodeJournalRecordV1,
        plan: &AssignmentEffectPlanV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedAssignmentCommitOutcomeV1, InvalidMultiNodeJournal> {
        let assignment = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let intent = assignment.intent();
        if record.domain() != super::journal::MultiNodeJournalDomainV1::Assignment
            || record.payload_digest() != intent.assignment_digest()
            || record.state_payload().assignment_digest() != Some(carrier.assignment_digest())
            || !plan.matches(record.operation(), intent, record.effect_digest())
            || intent.node() != carrier.node()
            || intent.epoch() != carrier.assignment_epoch()
            || carrier.peer_identity_digest().as_bytes() == &[0; 32]
            || carrier.lease_generation() == 0
            || carrier.lease_digest().as_bytes() == &[0; 32]
            || carrier.signature_digest().as_bytes() == &[0; 32]
            || carrier.replay_fence() != self.replay_fence
            || !carrier.is_current_for(intent, verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }

        let canonical_bytes = record.encode_canonical();
        let domain = record.domain();
        let carrier_digest = carrier.digest();
        let grant = self.persist_once(
            domain,
            ProtectedStoreObjectKindV1::Record,
            Some(record.operation()),
            &canonical_bytes,
            verified_at_unix_seconds,
            Some(carrier_digest),
            Some(&carrier),
        )?;
        let (grant, recovery) = match grant {
            ProtectedStorePersistOutcomeV1::Committed { grant, recovery } => (grant, recovery),
            ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery) => {
                return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired {
                    recovery,
                    carrier,
                });
            }
        };
        if grant.context() != carrier.context() {
            self.reopen_ambiguous(&recovery);
            return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired { recovery, carrier });
        }
        let record = match ProtectedJournalRecordV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        ) {
            Ok(record) => record,
            Err(_) => {
                self.reopen_ambiguous(&recovery);
                return Ok(ProtectedAssignmentCommitOutcomeV1::RecoveryRequired {
                    recovery,
                    carrier,
                });
            }
        };
        Ok(ProtectedAssignmentCommitOutcomeV1::Committed(
            ProtectedAssignmentStoreCommitV1 { record, carrier },
        ))
    }

    /// Resolves an interrupted assignment write without losing carrier authority.
    fn resolve_ambiguous_assignment(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
        carrier: AuthenticatedAssignmentCarrierContractV1,
    ) -> ProtectedAssignmentResolutionV1 {
        if recovery.authority_binding_digest != Some(carrier.digest()) {
            return ProtectedAssignmentResolutionV1::RecoveryRequired {
                recovery,
                carrier,
                reason: InvalidMultiNodeJournal::ProtectedStoreMismatch,
            };
        }
        let verified_at_unix_seconds = recovery.verified_at_unix_seconds;
        let canonical_bytes = recovery.canonical_bytes.clone();
        let grant = match self.try_resolve_ambiguous(&recovery, Some(&carrier)) {
            Ok(grant) => grant,
            Err(reason) => {
                return ProtectedAssignmentResolutionV1::RecoveryRequired {
                    recovery,
                    carrier,
                    reason,
                };
            }
        };
        let record = match ProtectedJournalRecordV1::from_authority_commit(
            &canonical_bytes,
            grant,
            verified_at_unix_seconds,
        ) {
            Ok(record) => record,
            Err(reason) => {
                self.reopen_ambiguous(&recovery);
                return ProtectedAssignmentResolutionV1::RecoveryRequired {
                    recovery,
                    carrier,
                    reason,
                };
            }
        };
        ProtectedAssignmentResolutionV1::Committed(ProtectedAssignmentStoreCommitV1 {
            record,
            carrier,
        })
    }

    /// Persists and issues one exact protected journal checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when persistence, authentication,
    /// currentness, monotonic durability, byte binding, or replay fencing fails.
    fn commit_checkpoint_once(
        &mut self,
        checkpoint: MultiNodeJournalCheckpointV1,
        verified_at_unix_seconds: u64,
    ) -> Result<ProtectedCheckpointCommitOutcomeV1, InvalidMultiNodeJournal> {
        let canonical_bytes = checkpoint.encode_canonical();
        let domain = checkpoint.domain();
        let grant = self.persist_once(
            domain,
            ProtectedStoreObjectKindV1::Checkpoint,
            None,
            &canonical_bytes,
            verified_at_unix_seconds,
            None,
            None,
        )?;
        match grant {
            ProtectedStorePersistOutcomeV1::Committed { grant, recovery } => {
                match ProtectedJournalCheckpointV1::from_authority_commit(
                    &canonical_bytes,
                    grant,
                    verified_at_unix_seconds,
                ) {
                    Ok(checkpoint) => Ok(ProtectedCheckpointCommitOutcomeV1::Committed(checkpoint)),
                    Err(_) => {
                        self.reopen_ambiguous(&recovery);
                        Ok(ProtectedCheckpointCommitOutcomeV1::RecoveryRequired(
                            recovery,
                        ))
                    }
                }
            }
            ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery) => Ok(
                ProtectedCheckpointCommitOutcomeV1::RecoveryRequired(recovery),
            ),
        }
    }

    /// Restores exact reducer and partial-effect state through this store session.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal`] when the checkpoint or any successor
    /// belongs to another protected domain/replay fence, is stale, or breaks
    /// the canonical journal chain.
    fn restore_once(
        &mut self,
        checkpoint: ProtectedJournalCheckpointV1,
        records: Vec<ProtectedJournalRecordV1>,
        verified_at_unix_seconds: u64,
    ) -> Result<MultiNodeJournalReducerV1, InvalidMultiNodeJournal> {
        if checkpoint.storage_domain_digest() != self.storage_domain_digest
            || checkpoint.replay_fence() != self.replay_fence
            || checkpoint.durability_generation() < self.durability_generation
            || records.iter().any(|record| {
                record.storage_domain_digest() != self.storage_domain_digest
                    || record.replay_fence() != self.replay_fence
                    || record.durability_generation() < checkpoint.durability_generation()
            })
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let restored_generation = records
            .last()
            .map_or(checkpoint.durability_generation(), |record| {
                record.durability_generation()
            });
        let restored_root = records.last().map_or_else(
            || checkpoint.protected_root_digest(),
            ProtectedJournalRecordV1::protected_root_digest,
        );
        let grant = ProtectedStoreRestoreGrantV1 {
            checkpoint,
            records,
            verified_at_unix_seconds,
            storage_domain_digest: self.storage_domain_digest,
            replay_fence: self.replay_fence,
        };
        let reducer = MultiNodeJournalReducerV1::restore_from_authority(grant)?;
        self.durability_generation = restored_generation;
        self.protected_root_digest = restored_root;
        Ok(reducer)
    }

    fn persist_once(
        &mut self,
        domain: super::journal::MultiNodeJournalDomainV1,
        kind: ProtectedStoreObjectKindV1,
        operation: Option<OperationId>,
        canonical_bytes: &[u8],
        verified_at_unix_seconds: u64,
        authority_binding_digest: Option<ObjectDigest>,
        expected_carrier: Option<&AuthenticatedAssignmentCarrierContractV1>,
    ) -> Result<ProtectedStorePersistOutcomeV1, InvalidMultiNodeJournal> {
        let canonical_bytes_digest =
            ObjectDigest::from_bytes(Sha256::digest(canonical_bytes).into());
        let next_generation = self
            .durability_generation
            .checked_add(1)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let transaction_digest = protected_transaction_digest(
            domain,
            kind,
            operation,
            canonical_bytes_digest,
            authority_binding_digest,
            self.storage_domain_digest,
            self.durability_generation,
            self.protected_root_digest,
            next_generation,
            self.replay_fence,
        );
        let outcome = self.backend.persist_once(
            ProtectedWriteRequestV1 {
                domain,
                kind,
                operation,
                canonical_bytes,
                canonical_bytes_digest,
                authority_binding_digest,
                storage_domain_digest: self.storage_domain_digest,
                replay_fence: self.replay_fence,
                expected_generation: self.durability_generation,
                expected_root_digest: self.protected_root_digest,
                next_generation,
                transaction_digest,
            },
            verified_at_unix_seconds,
        )?;
        let recovery = ProtectedStoreRecoveryRequiredV1 {
            domain,
            kind,
            operation,
            canonical_bytes: canonical_bytes.to_vec(),
            canonical_bytes_digest,
            authority_binding_digest,
            expected_generation: self.durability_generation,
            expected_root_digest: self.protected_root_digest,
            next_generation,
            transaction_digest,
            verified_at_unix_seconds,
        };
        let ProtectedWriteOutcomeV1::Committed(result) = outcome else {
            return Ok(ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery));
        };
        let readback = match self.backend.read_current(domain, kind, operation) {
            Ok(readback) => readback,
            Err(_) => {
                return Ok(ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery));
            }
        };
        if readback.domain != domain
            || readback.kind != kind
            || readback.operation != operation
            || readback.canonical_bytes != canonical_bytes
            || ObjectDigest::from_bytes(Sha256::digest(&readback.canonical_bytes).into())
                != canonical_bytes_digest
            || !same_write_result(&result, &readback.result)
        {
            return Ok(ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery));
        }
        let grant = match self.validate_committed_result(
            kind,
            canonical_bytes_digest,
            authority_binding_digest,
            expected_carrier,
            next_generation,
            transaction_digest,
            verified_at_unix_seconds,
            readback.result,
        ) {
            Ok(grant) => grant,
            Err(_) => return Ok(ProtectedStorePersistOutcomeV1::RecoveryRequired(recovery)),
        };
        Ok(ProtectedStorePersistOutcomeV1::Committed { grant, recovery })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_committed_result(
        &mut self,
        kind: ProtectedStoreObjectKindV1,
        canonical_bytes_digest: ObjectDigest,
        authority_binding_digest: Option<ObjectDigest>,
        expected_carrier: Option<&AuthenticatedAssignmentCarrierContractV1>,
        next_generation: u64,
        transaction_digest: ObjectDigest,
        verified_at_unix_seconds: u64,
        result: ProtectedWriteResultV1,
    ) -> Result<ProtectedStoreCommitGrantV1, InvalidMultiNodeJournal> {
        if result.storage_domain_digest != self.storage_domain_digest
            || result.durability_generation != next_generation
            || result.predecessor_root_digest != self.protected_root_digest
            || result.transaction_digest != transaction_digest
            || result.protected_root_digest.as_bytes() == &[0; 32]
            || result.opaque_receipt_commitment.as_bytes() == &[0; 32]
            || result.replay_fence != self.replay_fence
            || result.context.replay_fence() != result.replay_fence
            || result.authority_binding_digest != authority_binding_digest
            || result
                .authority_binding_digest
                .is_some_and(|digest| digest.as_bytes() == &[0; 32])
            || !result.context.is_current_at(verified_at_unix_seconds)
            || expected_carrier.is_some_and(|carrier| {
                result.authority_binding_digest != Some(carrier.digest())
                    || result.context != carrier.context()
            })
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        self.durability_generation = result.durability_generation;
        self.protected_root_digest = result.protected_root_digest;
        Ok(ProtectedStoreCommitGrantV1 {
            kind,
            canonical_bytes_digest,
            storage_domain_digest: result.storage_domain_digest,
            durability_generation: result.durability_generation,
            protected_root_digest: result.protected_root_digest,
            opaque_receipt_commitment: result.opaque_receipt_commitment,
            replay_fence: result.replay_fence,
            authority_binding_digest: result.authority_binding_digest,
            context: result.context,
        })
    }

    /// Resolves an interrupted write only by exact authenticated readback.
    fn resolve_ambiguous(
        &mut self,
        recovery: ProtectedStoreRecoveryRequiredV1,
    ) -> ProtectedStoreResolutionV1 {
        match self.try_resolve_ambiguous(&recovery, None) {
            Ok(grant) => ProtectedStoreResolutionV1::Committed { grant, recovery },
            Err(reason) => ProtectedStoreResolutionV1::RecoveryRequired { recovery, reason },
        }
    }

    fn try_resolve_ambiguous(
        &mut self,
        recovery: &ProtectedStoreRecoveryRequiredV1,
        expected_carrier: Option<&AuthenticatedAssignmentCarrierContractV1>,
    ) -> Result<ProtectedStoreCommitGrantV1, InvalidMultiNodeJournal> {
        if recovery.expected_generation != self.durability_generation
            || recovery.expected_root_digest != self.protected_root_digest
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let readback =
            self.backend
                .read_current(recovery.domain, recovery.kind, recovery.operation)?;
        if readback.domain != recovery.domain
            || readback.kind != recovery.kind
            || readback.operation != recovery.operation
            || readback.canonical_bytes != recovery.canonical_bytes
            || ObjectDigest::from_bytes(Sha256::digest(&readback.canonical_bytes).into())
                != recovery.canonical_bytes_digest
            || readback.result.transaction_digest != recovery.transaction_digest
            || expected_carrier.is_some_and(|carrier| {
                readback.result.context.node() != carrier.node()
                    || readback.result.context.lineage() != carrier.lineage()
                    || readback.result.context.coordinator_epoch() != carrier.coordinator_epoch()
                    || readback.result.context.replay_fence() != carrier.replay_fence()
                    || readback.result.authority_binding_digest != Some(carrier.digest())
            })
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        self.validate_committed_result(
            recovery.kind,
            recovery.canonical_bytes_digest,
            recovery.authority_binding_digest,
            expected_carrier,
            recovery.next_generation,
            recovery.transaction_digest,
            recovery.verified_at_unix_seconds,
            readback.result,
        )
    }

    fn reopen_ambiguous(&mut self, recovery: &ProtectedStoreRecoveryRequiredV1) {
        self.durability_generation = recovery.expected_generation;
        self.protected_root_digest = recovery.expected_root_digest;
    }
}

#[allow(clippy::too_many_arguments)]
fn protected_transaction_digest(
    domain: super::journal::MultiNodeJournalDomainV1,
    kind: ProtectedStoreObjectKindV1,
    operation: Option<OperationId>,
    canonical_bytes_digest: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    storage_domain_digest: ObjectDigest,
    expected_generation: u64,
    expected_root_digest: ObjectDigest,
    next_generation: u64,
    replay_fence: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.protected-transaction.v1\0");
    digest.update([domain as u8]);
    digest.update([match kind {
        ProtectedStoreObjectKindV1::Record => 1,
        ProtectedStoreObjectKindV1::Checkpoint => 2,
    }]);
    match operation {
        Some(operation) => {
            digest.update([1]);
            digest.update(operation.as_bytes());
        }
        None => digest.update([0; 17]),
    }
    digest.update(canonical_bytes_digest.as_bytes());
    match authority_binding_digest {
        Some(binding) => {
            digest.update([1]);
            digest.update(binding.as_bytes());
        }
        None => digest.update([0; 33]),
    }
    digest.update(storage_domain_digest.as_bytes());
    digest.update(expected_generation.to_be_bytes());
    digest.update(expected_root_digest.as_bytes());
    digest.update(next_generation.to_be_bytes());
    digest.update(replay_fence.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn same_write_result(left: &ProtectedWriteResultV1, right: &ProtectedWriteResultV1) -> bool {
    left.storage_domain_digest == right.storage_domain_digest
        && left.durability_generation == right.durability_generation
        && left.protected_root_digest == right.protected_root_digest
        && left.opaque_receipt_commitment == right.opaque_receipt_commitment
        && left.replay_fence == right.replay_fence
        && left.authority_binding_digest == right.authority_binding_digest
        && left.predecessor_root_digest == right.predecessor_root_digest
        && left.transaction_digest == right.transaction_digest
        && left.context == right.context
}

fn encode_protected_store_history(
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    base_generation: u64,
    base_root_digest: ObjectDigest,
    history: &[ProtectedStoreHistoryEntryV1],
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    if history.len() > super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let count = u32::try_from(history.len())
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROTECTED_STORE_HISTORY_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(storage_domain_digest.as_bytes());
    bytes.extend_from_slice(replay_fence.as_bytes());
    bytes.extend_from_slice(&base_generation.to_be_bytes());
    bytes.extend_from_slice(base_root_digest.as_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for entry in history {
        let canonical_length = u32::try_from(entry.canonical_bytes.len())
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        bytes.push(entry.domain as u8);
        bytes.push(match entry.kind {
            ProtectedStoreObjectKindV1::Record => 1,
            ProtectedStoreObjectKindV1::Checkpoint => 2,
        });
        match entry.operation {
            Some(operation) => {
                bytes.push(1);
                bytes.extend_from_slice(operation.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 16]);
            }
        }
        bytes.push(0);
        bytes.extend_from_slice(&canonical_length.to_be_bytes());
        bytes.extend_from_slice(&entry.canonical_bytes);
        bytes.extend_from_slice(entry.canonical_bytes_digest.as_bytes());
        match entry.authority_binding_digest {
            Some(binding) => {
                bytes.push(1);
                bytes.extend_from_slice(binding.as_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 32]);
            }
        }
        bytes.extend_from_slice(&entry.durability_generation.to_be_bytes());
        bytes.extend_from_slice(entry.predecessor_root_digest.as_bytes());
        bytes.extend_from_slice(entry.protected_root_digest.as_bytes());
        bytes.extend_from_slice(entry.transaction_digest.as_bytes());
        bytes.extend_from_slice(entry.opaque_receipt_commitment.as_bytes());
        bytes.extend_from_slice(entry.context_digest.as_bytes());
        bytes.extend_from_slice(&entry.verified_at_unix_seconds.to_be_bytes());
        if bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-store-history.v1\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(bytes)
}

fn decode_protected_store_history(
    bytes: &[u8],
    expected_storage_domain_digest: ObjectDigest,
    expected_replay_fence: ObjectDigest,
    expected_base_generation: u64,
    expected_base_root_digest: ObjectDigest,
) -> Result<Vec<ProtectedStoreHistoryEntryV1>, InvalidMultiNodeJournal> {
    if bytes.len() < 156 || bytes.len() > MAXIMUM_PROTECTED_STORE_HISTORY_BYTES {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let (payload, retained_digest) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    );
    let expected_digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-store-history.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_digest != expected_digest {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let mut decoder = ProtectedStoreHistoryDecoderV1::new(payload);
    if decoder.read_exact(8)? != PROTECTED_STORE_HISTORY_MAGIC
        || decoder.read_u16()? != 1
        || decoder.read_exact(6)? != [0; 6]
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_storage_domain_digest
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_replay_fence
        || decoder.read_u64()? != expected_base_generation
        || ObjectDigest::from_bytes(decoder.read_array()?) != expected_base_root_digest
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let count = usize::try_from(decoder.read_u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if count > super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let mut history = Vec::with_capacity(count);
    let mut predecessor_generation = expected_base_generation;
    let mut predecessor_root = expected_base_root_digest;
    for _ in 0..count {
        let domain = match decoder.read_u8()? {
            0 => super::journal::MultiNodeJournalDomainV1::Capability,
            1 => super::journal::MultiNodeJournalDomainV1::Assignment,
            2 => super::journal::MultiNodeJournalDomainV1::Drain,
            3 => super::journal::MultiNodeJournalDomainV1::SnapshotTransfer,
            4 => super::journal::MultiNodeJournalDomainV1::Watch,
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let kind = match decoder.read_u8()? {
            1 => ProtectedStoreObjectKindV1::Record,
            2 => ProtectedStoreObjectKindV1::Checkpoint,
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let operation_present = decoder.read_u8()?;
        let operation_bytes = decoder.read_array()?;
        let operation = match operation_present {
            0 if operation_bytes == [0; 16] => None,
            1 if operation_bytes != [0; 16] => Some(OperationId::from_bytes(operation_bytes)),
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        if decoder.read_u8()? != 0 {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let canonical_length = usize::try_from(decoder.read_u32()?)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        if canonical_length == 0
            || canonical_length > super::journal::MAX_MULTI_NODE_JOURNAL_PAYLOAD_BYTES
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        let canonical_bytes = decoder.read_exact(canonical_length)?.to_vec();
        let canonical_bytes_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let binding_present = decoder.read_u8()?;
        let binding_bytes = decoder.read_array()?;
        let authority_binding_digest = match binding_present {
            0 if binding_bytes == [0; 32] => None,
            1 if binding_bytes != [0; 32] => Some(ObjectDigest::from_bytes(binding_bytes)),
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        };
        let durability_generation = decoder.read_u64()?;
        let predecessor_root_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let protected_root_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let transaction_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let opaque_receipt_commitment = ObjectDigest::from_bytes(decoder.read_array()?);
        let context_digest = ObjectDigest::from_bytes(decoder.read_array()?);
        let verified_at_unix_seconds = decoder.read_u64()?;
        if ObjectDigest::from_bytes(Sha256::digest(&canonical_bytes).into())
            != canonical_bytes_digest
            || predecessor_generation.checked_add(1) != Some(durability_generation)
            || predecessor_root_digest != predecessor_root
            || protected_store_successor_root(
                predecessor_root_digest,
                transaction_digest,
                opaque_receipt_commitment,
            ) != protected_root_digest
            || protected_transaction_digest(
                domain,
                kind,
                operation,
                canonical_bytes_digest,
                authority_binding_digest,
                expected_storage_domain_digest,
                predecessor_generation,
                predecessor_root_digest,
                durability_generation,
                expected_replay_fence,
            ) != transaction_digest
            || context_digest.as_bytes() == &[0; 32]
            || verified_at_unix_seconds == 0
            || protected_receipt_commitment_from_context_digest(
                transaction_digest,
                context_digest,
                verified_at_unix_seconds,
            ) != opaque_receipt_commitment
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        match kind {
            ProtectedStoreObjectKindV1::Record => {
                let record = MultiNodeJournalRecordV1::decode_canonical(&canonical_bytes)?;
                if operation != Some(record.operation()) || domain != record.domain() {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
            }
            ProtectedStoreObjectKindV1::Checkpoint => {
                let checkpoint = MultiNodeJournalCheckpointV1::decode_canonical(&canonical_bytes)?;
                if operation.is_some() || domain != checkpoint.domain() {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
            }
        }
        history.push(ProtectedStoreHistoryEntryV1 {
            domain,
            kind,
            operation,
            canonical_bytes,
            canonical_bytes_digest,
            authority_binding_digest,
            durability_generation,
            predecessor_root_digest,
            protected_root_digest,
            transaction_digest,
            opaque_receipt_commitment,
            context_digest,
            verified_at_unix_seconds,
        });
        predecessor_generation = durability_generation;
        predecessor_root = protected_root_digest;
    }
    if !decoder.is_finished() {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    if encode_protected_store_history(
        expected_storage_domain_digest,
        expected_replay_fence,
        expected_base_generation,
        expected_base_root_digest,
        &history,
    )?
    .as_slice()
        != bytes
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(history)
}

/// Replays every retained object through the typed reducer before it is trusted.
///
/// Receipt reconstruction is confined to this protected-store module and uses
/// only the authenticated context supplied when the journal was claimed. This
/// makes cold open and prospective writes enforce the same transition and
/// checkpoint-floor rules as live reducer use.
fn validate_protected_store_semantics(
    history: &[ProtectedStoreHistoryEntryV1],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    authenticated_context: AuthenticatedEvidenceContextV1,
) -> Result<(), InvalidMultiNodeJournal> {
    replay_protected_store_semantics(
        history,
        storage_domain_digest,
        replay_fence,
        authenticated_context,
    )?;
    Ok(())
}

fn replay_protected_store_semantics(
    history: &[ProtectedStoreHistoryEntryV1],
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    authenticated_context: AuthenticatedEvidenceContextV1,
) -> Result<BTreeMap<MultiNodeJournalDomainV1, MultiNodeJournalReducerV1>, InvalidMultiNodeJournal>
{
    if history.len() > super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }

    let context_digest = protected_context_digest(authenticated_context);
    let mut reducers = BTreeMap::<_, MultiNodeJournalReducerV1>::new();
    for entry in history {
        if entry.context_digest != context_digest
            || !authenticated_context.is_current_at(entry.verified_at_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }

        let grant = ProtectedStoreCommitGrantV1 {
            kind: entry.kind,
            canonical_bytes_digest: entry.canonical_bytes_digest,
            storage_domain_digest,
            durability_generation: entry.durability_generation,
            protected_root_digest: entry.protected_root_digest,
            opaque_receipt_commitment: entry.opaque_receipt_commitment,
            replay_fence,
            authority_binding_digest: entry.authority_binding_digest,
            context: authenticated_context,
        };
        match entry.kind {
            ProtectedStoreObjectKindV1::Record => {
                let record = MultiNodeJournalRecordV1::decode_canonical(&entry.canonical_bytes)?;
                let domain = record.domain();
                let reducer = match reducers.entry(domain) {
                    std::collections::btree_map::Entry::Occupied(occupied) => occupied.into_mut(),
                    std::collections::btree_map::Entry::Vacant(vacant) => {
                        vacant.insert(MultiNodeJournalReducerV1::new(
                            domain,
                            protected_domain_genesis_digest(
                                storage_domain_digest,
                                replay_fence,
                                domain,
                            ),
                        )?)
                    }
                };
                let protected = ProtectedJournalRecordV1::from_authority_commit(
                    &entry.canonical_bytes,
                    grant,
                    entry.verified_at_unix_seconds,
                )?;
                reducer.apply(protected, entry.verified_at_unix_seconds)?;
            }
            ProtectedStoreObjectKindV1::Checkpoint => {
                let checkpoint =
                    MultiNodeJournalCheckpointV1::decode_canonical(&entry.canonical_bytes)?;
                let reducer = reducers
                    .get_mut(&checkpoint.domain())
                    .ok_or(InvalidMultiNodeJournal::UnsafeCompaction)?;
                let protected = ProtectedJournalCheckpointV1::from_authority_commit(
                    &entry.canonical_bytes,
                    grant,
                    entry.verified_at_unix_seconds,
                )?;
                reducer.compact(protected, entry.verified_at_unix_seconds)?;
            }
        }
    }
    Ok(reducers)
}

struct ProtectedStoreHistoryDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProtectedStoreHistoryDecoderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], InvalidMultiNodeJournal> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], InvalidMultiNodeJournal> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)
    }

    fn read_u8(&mut self) -> Result<u8, InvalidMultiNodeJournal> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, InvalidMultiNodeJournal> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, InvalidMultiNodeJournal> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, InvalidMultiNodeJournal> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn protected_context_digest(context: AuthenticatedEvidenceContextV1) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.multi-node.protected-store-context.v1\0");
    digest.update(context.node().as_bytes());
    digest.update(context.lineage().boot().as_bytes());
    digest.update(context.lineage().generation().to_be_bytes());
    digest.update(context.audience_digest().as_bytes());
    digest.update(context.disclosure_domain_digest().as_bytes());
    digest.update(context.carrier_binding_digest().as_bytes());
    digest.update(context.canonical_frame_digest().as_bytes());
    digest.update(context.canonical_frame_bytes().to_be_bytes());
    digest.update(context.coordinator_epoch().to_be_bytes());
    digest.update(context.verified_at_unix_seconds().to_be_bytes());
    digest.update(context.valid_until_unix_seconds().to_be_bytes());
    digest.update(context.replay_fence().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn protected_multi_node_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 16 * 1024 * 1024 * 1024,
        maximum_record_bytes: MAXIMUM_PROTECTED_STORE_HISTORY_BYTES + 4 * 1024,
        maximum_key_bytes: 256,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: MAXIMUM_PROTECTED_STORE_HISTORY_BYTES + 8 * 1024,
        maximum_transactions: super::journal::MAX_MULTI_NODE_JOURNAL_REPLAY_RECORDS,
        maximum_materialized_bytes: MAXIMUM_PROTECTED_STORE_HISTORY_BYTES + 4 * 1024,
        maximum_materialized_records: 1,
    }
}

fn protected_multi_node_bootstrap_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 4 * 1024 * 1024 * 1024,
        maximum_record_bytes: 256 * 1024,
        maximum_key_bytes: 256,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: 512 * 1024,
        maximum_transactions: 1_000_000,
        maximum_materialized_bytes: 512 * 1024,
        maximum_materialized_records: 2,
    }
}

fn protected_snapshot_inbox_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: 64 * 1024 * 1024,
        maximum_record_bytes: super::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES
            + 4 * 1024,
        maximum_key_bytes: 256,
        maximum_records_per_transaction: 1,
        maximum_transaction_bytes: super::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES
            + 8 * 1024,
        maximum_transactions: 1,
        maximum_materialized_bytes: super::assignment::MAX_SNAPSHOT_TRANSFER_MANIFEST_WIRE_BYTES
            + 4 * 1024,
        maximum_materialized_records: 1,
    }
}

fn read_protected_snapshot_manifest(
    directory: &Path,
) -> Result<SnapshotTransferManifestV1, InvalidMultiNodeJournal> {
    let (mut journal, _) = Journal::open_protected_at(
        directory,
        PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_JOURNAL_NAME,
        protected_snapshot_inbox_journal_limits(),
    )
    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let authority = journal
        .claim_protected_authority(RecordNamespace::RuntimeAuthority)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let records = authority
        .records()
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
        .take(2)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    let [(key, value)] = records.as_slice() else {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    };
    if key.as_slice() != PROTECTED_MULTI_NODE_SNAPSHOT_INBOX_KEY {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    decode_snapshot_manifest_seed(value)
}

#[derive(Clone)]
struct ProtectedMultiNodeBootstrapV1 {
    node: NodeId,
    lineage: NodeBootLineageV1,
    authenticated_channel_binding: [u8; 32],
    canonical_frame: Vec<u8>,
    coordinator_epoch: u64,
    authenticated_at_unix_seconds: u64,
    valid_until_unix_seconds: u64,
    maximum_request_bytes: u32,
    maximum_response_bytes: u32,
    replay_fence: ObjectDigest,
    signed_payload: Vec<u8>,
    canonical_trust_policy: Vec<u8>,
    public_key: [u8; 32],
    canonical_signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProtectedMultiNodeClockFloorV1 {
    config_digest: ObjectDigest,
    coordinator_epoch: u64,
    replay_fence: ObjectDigest,
    observed_unix_seconds: u64,
    predecessor_unix_seconds: u64,
}

/// Owns the fixed-root clock floor and its exclusive protected journal.
struct ProtectedMultiNodeClockV1 {
    directory: PathBuf,
    journal: Option<Journal>,
    config_digest: ObjectDigest,
    coordinator_epoch: u64,
    replay_fence: ObjectDigest,
    floor_unix_seconds: u64,
    encoded_floor: Option<Vec<u8>>,
    pending_floor: Option<Vec<u8>>,
}

impl ProtectedMultiNodeClockV1 {
    fn sample_current_time(&self) -> Result<u64, InvalidMultiNodeJournal> {
        let current_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
            .as_secs();
        if current_unix_seconds < self.floor_unix_seconds {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        Ok(current_unix_seconds)
    }

    fn advance_to(&mut self, current_unix_seconds: u64) -> Result<(), InvalidMultiNodeJournal> {
        if current_unix_seconds < self.floor_unix_seconds {
            return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
        }
        if current_unix_seconds == self.floor_unix_seconds {
            return Ok(());
        }

        self.persist_successor(current_unix_seconds)
    }

    fn recover_pending(&mut self) -> Result<(), InvalidMultiNodeJournal> {
        let Some(pending_floor) = self.pending_floor.clone() else {
            return Ok(());
        };
        if self.journal.is_none() {
            self.journal = Some(
                Journal::open_protected_at(
                    &self.directory,
                    PROTECTED_MULTI_NODE_BOOTSTRAP_JOURNAL_NAME,
                    protected_multi_node_bootstrap_journal_limits(),
                )
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
                .0,
            );
        }
        if self.validate_exact_floor(&pending_floor).is_ok() {
            let decoded = decode_protected_multi_node_clock_floor(&pending_floor)?;
            self.floor_unix_seconds = decoded.observed_unix_seconds;
            self.encoded_floor = Some(pending_floor);
            self.pending_floor = None;
            return Ok(());
        }
        let retained_floor = self.encoded_floor.clone();
        if self.validate_exact_floor_option(retained_floor).is_ok() {
            self.pending_floor = None;
            return Ok(());
        }
        Err(InvalidMultiNodeJournal::ProtectedStoreMismatch)
    }

    fn persist_successor(
        &mut self,
        current_unix_seconds: u64,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let floor = ProtectedMultiNodeClockFloorV1 {
            config_digest: self.config_digest,
            coordinator_epoch: self.coordinator_epoch,
            replay_fence: self.replay_fence,
            observed_unix_seconds: current_unix_seconds,
            predecessor_unix_seconds: self.floor_unix_seconds,
        };
        let encoded_floor = encode_protected_multi_node_clock_floor(floor);
        let transaction_id = protected_multi_node_clock_transaction_id(&encoded_floor)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::RuntimeAuthority,
                PROTECTED_MULTI_NODE_CLOCK_KEY.to_vec(),
                encoded_floor.clone(),
            )],
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        self.pending_floor = Some(encoded_floor.clone());
        let mut journal = self
            .journal
            .take()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let _attempted = (|| {
            let mut authority = journal
                .claim_protected_authority(RecordNamespace::RuntimeAuthority)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            validate_protected_multi_node_clock_records(
                &authority,
                self.config_digest,
                self.encoded_floor.as_deref(),
            )?;
            let preflight = authority
                .preflight_transactions(std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            authority
                .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            authority
                .commit(&transaction)
                .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
            Ok::<(), InvalidMultiNodeJournal>(())
        })();
        drop(journal);

        let reopened = Journal::open_protected_at(
            &self.directory,
            PROTECTED_MULTI_NODE_BOOTSTRAP_JOURNAL_NAME,
            protected_multi_node_bootstrap_journal_limits(),
        )
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
        .0;
        self.journal = Some(reopened);
        if self.validate_exact_floor(&encoded_floor).is_ok() {
            // Exact protected readback is the only success classification after
            // an append, including when the append response was ambiguous.
            self.floor_unix_seconds = current_unix_seconds;
            self.encoded_floor = Some(encoded_floor);
            self.pending_floor = None;
            return Ok(());
        }
        let retained_floor = self.encoded_floor.clone();
        if self.validate_exact_floor_option(retained_floor).is_ok() {
            self.pending_floor = None;
        }
        Err(InvalidMultiNodeJournal::ProtectedStoreMismatch)
    }

    fn validate_exact_floor(
        &mut self,
        encoded_floor: &[u8],
    ) -> Result<(), InvalidMultiNodeJournal> {
        let journal = self
            .journal
            .as_mut()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::RuntimeAuthority)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        validate_protected_multi_node_clock_records(
            &authority,
            self.config_digest,
            Some(encoded_floor),
        )
    }

    fn validate_exact_floor_option(
        &mut self,
        encoded_floor: Option<Vec<u8>>,
    ) -> Result<(), InvalidMultiNodeJournal> {
        let journal = self
            .journal
            .as_mut()
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        let authority = journal
            .claim_protected_authority(RecordNamespace::RuntimeAuthority)
            .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
        validate_protected_multi_node_clock_records(
            &authority,
            self.config_digest,
            encoded_floor.as_deref(),
        )
    }
}

fn read_protected_multi_node_bootstrap(
    directory: &Path,
) -> Result<
    (ProtectedMultiNodeBootstrapV1, ProtectedMultiNodeClockV1),
    ProtectedMultiNodeAuthorityOpenErrorV1,
> {
    let (mut journal, _) = Journal::open_protected_at(
        directory,
        PROTECTED_MULTI_NODE_BOOTSTRAP_JOURNAL_NAME,
        protected_multi_node_bootstrap_journal_limits(),
    )?;
    let records = {
        let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
        authority
            .records()?
            .take(3)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<Vec<_>>()
    };
    if records.is_empty() || records.len() > 2 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
    }
    let mut config = None;
    let mut encoded_floor = None;
    for (key, value) in records {
        match key.as_slice() {
            PROTECTED_MULTI_NODE_BOOTSTRAP_KEY if config.is_none() => config = Some(value),
            PROTECTED_MULTI_NODE_CLOCK_KEY if encoded_floor.is_none() => {
                encoded_floor = Some(value)
            }
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into()),
        }
    }
    let config = config.ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let bootstrap = decode_protected_multi_node_bootstrap(&config)?;
    let config_digest = protected_multi_node_bootstrap_config_digest(&config);
    let floor_unix_seconds = match encoded_floor.as_deref() {
        Some(bytes) => {
            let floor = decode_protected_multi_node_clock_floor(bytes)?;
            if floor.config_digest != config_digest
                || floor.coordinator_epoch != bootstrap.coordinator_epoch
                || floor.replay_fence != bootstrap.replay_fence
                || floor.observed_unix_seconds < floor.predecessor_unix_seconds
            {
                return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
            }
            floor.observed_unix_seconds
        }
        None => 0,
    };
    let clock = ProtectedMultiNodeClockV1 {
        directory: directory.to_path_buf(),
        journal: Some(journal),
        config_digest,
        coordinator_epoch: bootstrap.coordinator_epoch,
        replay_fence: bootstrap.replay_fence,
        floor_unix_seconds,
        encoded_floor,
        pending_floor: None,
    };
    Ok((bootstrap, clock))
}

fn validate_protected_multi_node_clock_records(
    authority: &crate::journal::ProtectedJournalAuthority<'_>,
    expected_config_digest: ObjectDigest,
    expected_floor: Option<&[u8]>,
) -> Result<(), InvalidMultiNodeJournal> {
    let records = authority
        .records()
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?
        .take(3)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    if records.is_empty() || records.len() > 2 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch.into());
    }
    let mut found_config = false;
    let mut found_floor = false;
    for (key, value) in records {
        match key.as_slice() {
            PROTECTED_MULTI_NODE_BOOTSTRAP_KEY if !found_config => {
                if protected_multi_node_bootstrap_config_digest(&value) != expected_config_digest {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
                found_config = true;
            }
            PROTECTED_MULTI_NODE_CLOCK_KEY if !found_floor => {
                if expected_floor != Some(value.as_slice()) {
                    return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
                }
                found_floor = true;
            }
            _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
        }
    }
    if !found_config || found_floor != expected_floor.is_some() {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(())
}

fn protected_multi_node_bootstrap_config_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-bootstrap-config-digest.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn encode_protected_multi_node_clock_floor(floor: ProtectedMultiNodeClockFloorV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(PROTECTED_MULTI_NODE_CLOCK_MAGIC);
    bytes.extend_from_slice(floor.config_digest.as_bytes());
    bytes.extend_from_slice(&floor.coordinator_epoch.to_be_bytes());
    bytes.extend_from_slice(floor.replay_fence.as_bytes());
    bytes.extend_from_slice(&floor.observed_unix_seconds.to_be_bytes());
    bytes.extend_from_slice(&floor.predecessor_unix_seconds.to_be_bytes());
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-clock-floor.v1\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&checksum);
    bytes
}

fn decode_protected_multi_node_clock_floor(
    bytes: &[u8],
) -> Result<ProtectedMultiNodeClockFloorV1, InvalidMultiNodeJournal> {
    if bytes.len() != 128 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let (payload, checksum) = bytes.split_at(96);
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-clock-floor.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if checksum != expected_checksum {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let mut decoder = ProtectedStoreHistoryDecoderV1::new(payload);
    if decoder.read_exact(8)? != PROTECTED_MULTI_NODE_CLOCK_MAGIC {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let floor = ProtectedMultiNodeClockFloorV1 {
        config_digest: ObjectDigest::from_bytes(decoder.read_array()?),
        coordinator_epoch: decoder.read_u64()?,
        replay_fence: ObjectDigest::from_bytes(decoder.read_array()?),
        observed_unix_seconds: decoder.read_u64()?,
        predecessor_unix_seconds: decoder.read_u64()?,
    };
    if !decoder.is_finished()
        || floor.config_digest.as_bytes() == &[0; 32]
        || floor.coordinator_epoch == 0
        || floor.replay_fence.as_bytes() == &[0; 32]
        || floor.observed_unix_seconds == 0
        || floor.predecessor_unix_seconds > floor.observed_unix_seconds
        || encode_protected_multi_node_clock_floor(floor).as_slice() != bytes
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(floor)
}

fn protected_multi_node_clock_transaction_id(
    encoded_floor: &[u8],
) -> Result<[u8; 16], InvalidMultiNodeJournal> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-clock-transaction.v1\0")
        .chain_update(encoded_floor)
        .finalize()
        .into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(id)
}

fn decode_protected_multi_node_bootstrap(
    bytes: &[u8],
) -> Result<ProtectedMultiNodeBootstrapV1, InvalidMultiNodeJournal> {
    if bytes.len() < 360 || bytes.len() > 256 * 1024 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let (payload, retained_checksum) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
    );
    let expected_checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-bootstrap-config.v1\0")
        .chain_update(payload)
        .finalize()
        .into();
    if retained_checksum != expected_checksum {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }

    let mut decoder = ProtectedStoreHistoryDecoderV1::new(payload);
    if decoder.read_exact(8)? != b"AOSMBC01" {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let node = NodeId::from_bytes(decoder.read_array()?);
    let boot = NodeBootId::new(decoder.read_array()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let generation = decoder.read_u64()?;
    let predecessor_present = decoder.read_u8()?;
    let predecessor_boot_bytes = decoder.read_array()?;
    let predecessor_digest_bytes = decoder.read_array()?;
    let (predecessor_boot, predecessor_digest) = match predecessor_present {
        0 if predecessor_boot_bytes == [0; 16] && predecessor_digest_bytes == [0; 32] => {
            (None, None)
        }
        1 if predecessor_boot_bytes != [0; 16] && predecessor_digest_bytes != [0; 32] => (
            Some(
                NodeBootId::new(predecessor_boot_bytes)
                    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?,
            ),
            Some(ObjectDigest::from_bytes(predecessor_digest_bytes)),
        ),
        _ => return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch),
    };
    let lineage = NodeBootLineageV1::new(
        boot,
        generation,
        predecessor_boot,
        predecessor_digest,
        ObjectDigest::from_bytes(decoder.read_array()?),
    )
    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let authenticated_channel_binding = decoder.read_array()?;
    let canonical_frame_length = usize::try_from(decoder.read_u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if canonical_frame_length == 0
        || canonical_frame_length > super::protocol::MAX_NODE_RESPONSE_BYTES as usize
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_frame = decoder.read_exact(canonical_frame_length)?.to_vec();
    let coordinator_epoch = decoder.read_u64()?;
    let authenticated_at_unix_seconds = decoder.read_u64()?;
    let valid_until_unix_seconds = decoder.read_u64()?;
    let maximum_request_bytes = decoder.read_u32()?;
    let maximum_response_bytes = decoder.read_u32()?;
    let replay_fence = ObjectDigest::from_bytes(decoder.read_array()?);
    let signed_payload = payload[..decoder.offset].to_vec();
    let trust_policy_length = usize::try_from(decoder.read_u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if trust_policy_length == 0 || trust_policy_length > 64 * 1024 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_trust_policy = decoder.read_exact(trust_policy_length)?.to_vec();
    let public_key = decoder.read_array()?;
    let signature_length = usize::try_from(decoder.read_u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if signature_length == 0 || signature_length > 64 * 1024 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_signature = decoder.read_exact(signature_length)?.to_vec();
    if !decoder.is_finished()
        || node.as_bytes() == &[0; 16]
        || coordinator_epoch == 0
        || valid_until_unix_seconds <= authenticated_at_unix_seconds
        || maximum_request_bytes == 0
        || maximum_response_bytes == 0
        || replay_fence.as_bytes() == &[0; 32]
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let bootstrap = ProtectedMultiNodeBootstrapV1 {
        node,
        lineage,
        authenticated_channel_binding,
        canonical_frame,
        coordinator_epoch,
        authenticated_at_unix_seconds,
        valid_until_unix_seconds,
        maximum_request_bytes,
        maximum_response_bytes,
        replay_fence,
        signed_payload,
        canonical_trust_policy,
        public_key,
        canonical_signature,
    };
    if encode_decoded_protected_multi_node_bootstrap(&bootstrap)?.as_slice() != bytes {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(bootstrap)
}

fn encode_decoded_protected_multi_node_bootstrap(
    bootstrap: &ProtectedMultiNodeBootstrapV1,
) -> Result<Vec<u8>, InvalidMultiNodeJournal> {
    let policy_length = u32::try_from(bootstrap.canonical_trust_policy.len())
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let signature_length = u32::try_from(bootstrap.canonical_signature.len())
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let mut bytes = bootstrap.signed_payload.clone();
    bytes.extend_from_slice(&policy_length.to_be_bytes());
    bytes.extend_from_slice(&bootstrap.canonical_trust_policy);
    bytes.extend_from_slice(&bootstrap.public_key);
    bytes.extend_from_slice(&signature_length.to_be_bytes());
    bytes.extend_from_slice(&bootstrap.canonical_signature);
    let checksum: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-bootstrap-config.v1\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

fn protected_multi_node_storage_domain_digest(
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-storage-domain.v1\0")
            .chain_update(protected_context_digest(context).as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_multi_node_base_root_digest(
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-base-root.v1\0")
            .chain_update(storage_domain_digest.as_bytes())
            .chain_update(replay_fence.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_initial_capability_effect_digest(
    operation: OperationId,
    payload_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.initial-capability-effect.v1\0")
            .chain_update(operation.as_bytes())
            .chain_update(payload_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_bootstrap_capability_operation(
    config_digest: ObjectDigest,
    signed_frame_operation: OperationId,
    frame_digest: ObjectDigest,
    body_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
) -> Result<OperationId, InvalidMultiNodeJournal> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.bootstrap-capability-operation.v1\0")
        .chain_update(config_digest.as_bytes())
        .chain_update(signed_frame_operation.as_bytes())
        .chain_update(frame_digest.as_bytes())
        .chain_update(body_digest.as_bytes())
        .chain_update(protected_context_digest(context).as_bytes())
        .finalize()
        .into();
    let mut operation = [0; 16];
    operation.copy_from_slice(&digest[..16]);
    if operation == [0; 16] {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    Ok(OperationId::from_bytes(operation))
}

fn protected_outbound_operation(
    config_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    current_unix_seconds: u64,
    purpose: &[u8],
) -> Result<OperationId, InvalidMultiNodeProtocol> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.protected-outbound-operation.v1\0")
        .chain_update(config_digest.as_bytes())
        .chain_update(protected_root_digest.as_bytes())
        .chain_update(protected_context_digest(context).as_bytes())
        .chain_update(current_unix_seconds.to_be_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut operation = [0; 16];
    operation.copy_from_slice(&digest[..16]);
    if operation == [0; 16] {
        return Err(InvalidMultiNodeProtocol::Unspecified);
    }
    Ok(OperationId::from_bytes(operation))
}

fn protected_watch_binding_digest(config_digest: ObjectDigest, purpose: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-watch-binding.v1\0")
            .chain_update(config_digest.as_bytes())
            .chain_update((purpose.len() as u64).to_be_bytes())
            .chain_update(purpose)
            .finalize()
            .into(),
    )
}

fn protected_snapshot_inbox_receipt(manifest: &SnapshotTransferManifestV1) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-snapshot-inbox.v1\0")
            .chain_update(manifest.identity().manifest_digest().as_bytes())
            .chain_update(manifest.root().digest().as_bytes())
            .chain_update(manifest.root().encoded_size().to_be_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_destination_storage_binding(
    storage_domain_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
    destination_node: NodeId,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-destination-role.v1\0")
            .chain_update(storage_domain_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .chain_update(destination_node.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_cross_owner_admission_digest(
    source: &ProtectedSnapshotSourceAdmissionV1,
    destination_context: AuthenticatedEvidenceContextV1,
    destination_store_root: ObjectDigest,
) -> ObjectDigest {
    let identity = source.manifest.identity();
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.cross-owner-snapshot-admission.v1\0")
            .chain_update(identity.operation().as_bytes())
            .chain_update(identity.manifest_digest().as_bytes())
            .chain_update(identity.source_node().as_bytes())
            .chain_update(identity.destination_node().as_bytes())
            .chain_update(source.source_epoch.to_be_bytes())
            .chain_update(destination_context.coordinator_epoch().to_be_bytes())
            .chain_update(source.source_store_root.as_bytes())
            .chain_update(destination_store_root.as_bytes())
            .chain_update(identity.storage_domain_digest().as_bytes())
            .chain_update(source.manifest.root().digest().as_bytes())
            .chain_update(source.source_record.record().digest().as_bytes())
            .chain_update(
                source
                    .source_record
                    .context()
                    .valid_until_unix_seconds()
                    .to_be_bytes(),
            )
            .chain_update(destination_context.valid_until_unix_seconds().to_be_bytes())
            .finalize()
            .into(),
    )
}

fn durable_drain_observation(
    observation: &DrainObservationV1,
) -> Result<DurableDrainObservationV1, InvalidMultiNodeJournal> {
    let context = observation.context();
    let evidence = DurableEvidenceBindingV1::new(
        context.node(),
        context.lineage(),
        context.audience_digest(),
        context.disclosure_domain_digest(),
        context.carrier_binding_digest(),
        context.canonical_frame_digest(),
        context.canonical_frame_bytes(),
        context.coordinator_epoch(),
        context.verified_at_unix_seconds(),
        context.valid_until_unix_seconds(),
        context.replay_fence(),
    )?;
    let assignments = observation
        .assignments()
        .iter()
        .map(|assignment| {
            super::reducer_state::DurableDrainAssignmentV1::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.desired_generation(),
                assignment.assignment_digest(),
                assignment.progress(),
                assignment
                    .snapshot_evidence()
                    .map(|snapshot| snapshot.transfer_manifest_digest()),
                assignment
                    .containment_evidence()
                    .map(|containment| containment.evidence_digest()),
                assignment
                    .release_evidence()
                    .map(|release| release.released_inventory_digest()),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    DurableDrainObservationV1::new(
        observation.sequence(),
        observation.phase(),
        assignments,
        observation.observed_at_unix_seconds(),
        evidence,
    )
}

fn durable_assignment_matches_report(
    durable: &DurableAssignmentObservationV1,
    report: &NodeAssignmentObservationV1,
) -> bool {
    durable.sandbox == report.sandbox()
        && durable.incarnation == report.incarnation()
        && durable.epoch == report.epoch()
        && durable.desired_generation == report.desired_generation()
        && durable.assignment_digest == report.assignment_digest()
        && durable.sequence == report.sequence()
        && durable.phase == report.phase()
        && durable.realized_lifecycle == report.realized_lifecycle()
        && durable.reason == report.reason()
        && durable.observed_at_unix_seconds == report.observed_at_unix_seconds()
}

fn durable_drain_matches_report(
    durable: &DurableDrainObservationV1,
    report: &DrainObservationV1,
) -> bool {
    durable.sequence() == report.sequence()
        && durable.phase() == report.phase()
        && durable.observed_at_unix_seconds() == report.observed_at_unix_seconds()
        && durable.assignments().len() == report.assignments().len()
        && durable
            .assignments()
            .iter()
            .zip(report.assignments())
            .all(|(left, right)| {
                left.sandbox == right.sandbox()
                    && left.incarnation == right.incarnation()
                    && left.epoch == right.epoch()
                    && left.desired_generation == right.desired_generation()
                    && left.assignment_digest == right.assignment_digest()
                    && left.progress == right.progress()
            })
}

fn protected_empty_dependency_digest(
    manifest_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.empty-dependency-prefix.v1\0")
            .chain_update(manifest_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_dependency_receipt(
    dependency_set_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-receipt.v1\0")
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_dependency_subject(
    manifest_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-subject.v1\0")
            .chain_update(manifest_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_dependency_liveness(
    dependency_set_digest: ObjectDigest,
    dependency_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-dependency-live.v1\0")
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(dependency_digest.as_bytes())
            .chain_update(protected_context_digest(context).as_bytes())
            .chain_update(context.valid_until_unix_seconds().to_be_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_publication_digest(
    staged: &VerifiedStagedSnapshotV1,
    dependency_set_digest: ObjectDigest,
    publication_generation: u64,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-publication.v1\0")
            .chain_update(staged.identity().manifest_digest().as_bytes())
            .chain_update(staged.root().digest().as_bytes())
            .chain_update(staged.final_prefix_digest().as_bytes())
            .chain_update(dependency_set_digest.as_bytes())
            .chain_update(publication_generation.to_be_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_publication_receipt(
    publication_digest: ObjectDigest,
    protected_root_digest: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-publication-receipt.v1\0")
            .chain_update(publication_digest.as_bytes())
            .chain_update(protected_root_digest.as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_snapshot_restore_scope(
    identity: super::assignment::SnapshotTransferIdentityV1,
    publication_digest: ObjectDigest,
) -> Result<RestoreScopeId, InvalidSnapshotTransfer> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.multi-node.snapshot-restore-scope.v1\0")
        .chain_update(identity.manifest_digest().as_bytes())
        .chain_update(publication_digest.as_bytes())
        .finalize()
        .into();
    let mut scope = [0; 16];
    scope.copy_from_slice(&digest[..16]);
    if scope == [0; 16] {
        return Err(InvalidSnapshotTransfer::RestoreAdmissionMismatch);
    }
    Ok(RestoreScopeId::from_bytes(scope))
}

fn protected_snapshot_restore_authorization_digest(
    identity: super::assignment::SnapshotTransferIdentityV1,
    restore_scope: RestoreScopeId,
    publication: DurablePublicationProjectionV1,
    context: AuthenticatedEvidenceContextV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.snapshot-restore-authorization.v1\0")
            .chain_update(identity.manifest_digest().as_bytes())
            .chain_update(restore_scope.as_bytes())
            .chain_update(publication.publication_digest.as_bytes())
            .chain_update(publication.publication_generation.to_be_bytes())
            .chain_update(protected_context_digest(context).as_bytes())
            .finalize()
            .into(),
    )
}

fn watch_binding_advances(
    current: NodeWatchBindingV1,
    next: NodeWatchBindingV1,
    cursor: NodeWatchCursorV1,
) -> bool {
    next != current
        && next.query_digest() == current.query_digest()
        && next.authorization_digest() == current.authorization_digest()
        && next.audience_digest() == current.audience_digest()
        && next.disclosure_domain_digest() == current.disclosure_domain_digest()
        && next.schema() == current.schema()
        && next.coordinator_epoch() >= current.coordinator_epoch()
        && next.history_floor_sequence() >= current.history_floor_sequence()
        && (next.history_floor_sequence() != current.history_floor_sequence()
            || next.history_floor_event_uid() == current.history_floor_event_uid())
        && next.bootstrap_watermark() >= cursor.event_sequence()
}

fn protected_domain_genesis_digest(
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
    domain: MultiNodeJournalDomainV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-domain-genesis.v1\0")
            .chain_update(storage_domain_digest.as_bytes())
            .chain_update(replay_fence.as_bytes())
            .chain_update([domain as u8])
            .finalize()
            .into(),
    )
}

fn protected_receipt_commitment(
    transaction_digest: ObjectDigest,
    context: AuthenticatedEvidenceContextV1,
    verified_at_unix_seconds: u64,
) -> ObjectDigest {
    protected_receipt_commitment_from_context_digest(
        transaction_digest,
        protected_context_digest(context),
        verified_at_unix_seconds,
    )
}

fn protected_receipt_commitment_from_context_digest(
    transaction_digest: ObjectDigest,
    context_digest: ObjectDigest,
    verified_at_unix_seconds: u64,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-receipt.v1\0")
            .chain_update(transaction_digest.as_bytes())
            .chain_update(context_digest.as_bytes())
            .chain_update(verified_at_unix_seconds.to_be_bytes())
            .finalize()
            .into(),
    )
}

fn protected_store_successor_root(
    predecessor_root: ObjectDigest,
    transaction_digest: ObjectDigest,
    receipt_commitment: ObjectDigest,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.multi-node.protected-store-root.v1\0")
            .chain_update(predecessor_root.as_bytes())
            .chain_update(transaction_digest.as_bytes())
            .chain_update(receipt_commitment.as_bytes())
            .finalize()
            .into(),
    )
}

impl ProtectedAssignmentStoreCommitV1 {
    /// Returns the exact protected assignment journal record.
    #[must_use]
    pub fn record(&self) -> &ProtectedJournalRecordV1 {
        &self.record
    }

    /// Consumes the readback-confirmed commit into a publication typestate.
    fn into_publication(self) -> ProtectedAssignmentPublicationV1 {
        ProtectedAssignmentPublicationV1 {
            record: self.record,
            carrier: self.carrier,
        }
    }
}

impl ProtectedAssignmentPublicationV1 {
    /// Releases only the reducer-authorized effect under current assignment authority.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMultiNodeJournal::InvalidRecoveryTransition`] unless the
    /// semantic grant names this exact protected row and a current effect-time
    /// carrier preserves its peer, assignment, and lease authority.
    fn into_effect_handoff(
        self,
        semantic_grant: AssignmentEffectSemanticGrantV1,
        effect_time_carrier: AuthenticatedAssignmentCarrierContractV1,
        effect_time_unix_seconds: u64,
    ) -> Result<ProtectedAssignmentEffectHandoffV1, InvalidMultiNodeJournal> {
        let record = self.record.record();
        let intent = record
            .state_payload()
            .assignment_state()
            .ok_or(InvalidMultiNodeJournal::InvalidRecoveryTransition)?
            .intent();
        if record.domain() != super::journal::MultiNodeJournalDomainV1::Assignment
            || record.effect_state() != super::journal::JournalEffectStateV1::EffectPrepared
            || record.payload_digest() != semantic_grant.payload_digest()
            || semantic_grant.intent() != intent
            || !semantic_grant.matches(record.operation(), intent, record.effect_digest())
            || record.digest() != semantic_grant.record_digest()
            || self.record.receipt_commitment() != semantic_grant.receipt_commitment()
            || self.record.authority_binding_digest()
                != Some(semantic_grant.authority_binding_digest())
            || self.record.authority_binding_digest() != Some(self.carrier.digest())
            || !effect_time_carrier.matches_assignment_and_lease_of(&self.carrier)
            || effect_time_carrier.replay_fence() != self.carrier.replay_fence()
            || effect_time_carrier.verified_at_unix_seconds() != effect_time_unix_seconds
            || !effect_time_carrier.is_current_for(intent, effect_time_unix_seconds)
        {
            return Err(InvalidMultiNodeJournal::InvalidRecoveryTransition);
        }
        Ok(ProtectedAssignmentEffectHandoffV1 {
            publication: self,
            semantic_grant,
            effect_time_carrier,
        })
    }
}

impl ProtectedAssignmentEffectHandoffV1 {
    /// Returns the exact typed assignment intent selected by the reducer plan.
    fn intent(&self) -> &super::assignment::AssignmentIntentV1 {
        self.semantic_grant.intent()
    }

    /// Returns the exact durable operation identity.
    fn operation(&self) -> OperationId {
        self.semantic_grant.operation()
    }

    /// Returns the exact durable effect commitment.
    fn effect_digest(&self) -> ObjectDigest {
        self.semantic_grant.effect_digest()
    }

    /// Returns the carrier contract that authenticated the durable row.
    fn carrier_contract_digest(&self) -> ObjectDigest {
        self.publication.carrier.digest()
    }

    /// Returns the current carrier contract checked at effect handoff time.
    fn effect_time_carrier_contract_digest(&self) -> ObjectDigest {
        self.effect_time_carrier.digest()
    }

    /// Returns the reducer-issued semantic authority retained by the handoff.
    fn semantic_authority_binding_digest(&self) -> ObjectDigest {
        self.semantic_grant.authority_binding_digest()
    }
}

impl ProtectedAssignmentEffectReadyV1 {
    /// Returns the exact reducer-selected assignment intent.
    #[must_use]
    pub fn intent(&self) -> &super::assignment::AssignmentIntentV1 {
        self.handoff.intent()
    }

    /// Returns the exact durable operation identity.
    #[must_use]
    pub fn operation(&self) -> OperationId {
        self.handoff.operation()
    }

    /// Returns the exact durable effect commitment.
    #[must_use]
    pub fn effect_digest(&self) -> ObjectDigest {
        self.handoff.effect_digest()
    }

    /// Returns the carrier commitment persisted with the assignment row.
    #[must_use]
    pub fn carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.carrier_contract_digest()
    }

    /// Returns the freshly reauthenticated effect-time carrier commitment.
    #[must_use]
    pub fn effect_time_carrier_contract_digest(&self) -> ObjectDigest {
        self.handoff.effect_time_carrier_contract_digest()
    }

    /// Returns the reducer-issued semantic authority commitment.
    #[must_use]
    pub fn semantic_authority_binding_digest(&self) -> ObjectDigest {
        self.handoff.semantic_authority_binding_digest()
    }
}

/// Carries one consumed protected restore decision into the journal reducer.
pub(super) struct ProtectedStoreRestoreGrantV1 {
    checkpoint: ProtectedJournalCheckpointV1,
    records: Vec<ProtectedJournalRecordV1>,
    verified_at_unix_seconds: u64,
    storage_domain_digest: ObjectDigest,
    replay_fence: ObjectDigest,
}

impl ProtectedStoreRestoreGrantV1 {
    pub(super) fn into_parts(
        self,
    ) -> (
        ProtectedJournalCheckpointV1,
        Vec<ProtectedJournalRecordV1>,
        u64,
        ObjectDigest,
        ObjectDigest,
    ) {
        (
            self.checkpoint,
            self.records,
            self.verified_at_unix_seconds,
            self.storage_domain_digest,
            self.replay_fence,
        )
    }
}

/// Carries one consumed protected-store commit decision into journal code.
pub(super) struct ProtectedStoreCommitGrantV1 {
    kind: ProtectedStoreObjectKindV1,
    canonical_bytes_digest: ObjectDigest,
    storage_domain_digest: ObjectDigest,
    durability_generation: u64,
    protected_root_digest: ObjectDigest,
    opaque_receipt_commitment: ObjectDigest,
    replay_fence: ObjectDigest,
    authority_binding_digest: Option<ObjectDigest>,
    context: AuthenticatedEvidenceContextV1,
}

impl ProtectedStoreCommitGrantV1 {
    pub(super) const fn kind(&self) -> ProtectedStoreObjectKindV1 {
        self.kind
    }
    pub(super) const fn canonical_bytes_digest(&self) -> ObjectDigest {
        self.canonical_bytes_digest
    }
    pub(super) const fn storage_domain_digest(&self) -> ObjectDigest {
        self.storage_domain_digest
    }
    pub(super) const fn durability_generation(&self) -> u64 {
        self.durability_generation
    }
    pub(super) const fn protected_root_digest(&self) -> ObjectDigest {
        self.protected_root_digest
    }
    pub(super) const fn opaque_receipt_commitment(&self) -> ObjectDigest {
        self.opaque_receipt_commitment
    }
    pub(super) const fn replay_fence(&self) -> ObjectDigest {
        self.replay_fence
    }
    pub(super) const fn authority_binding_digest(&self) -> Option<ObjectDigest> {
        self.authority_binding_digest
    }
    pub(super) const fn context(&self) -> AuthenticatedEvidenceContextV1 {
        self.context
    }
}
