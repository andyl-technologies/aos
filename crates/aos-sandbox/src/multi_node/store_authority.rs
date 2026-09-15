//! Private protected-store authority boundary.
//!
//! This module is the sole home of the durable-store adapter and its session
//! constructor. Journal code receives only a consumed opaque commit grant;
//! ordinary siblings cannot implement the backend or manufacture durability
//! acknowledgements from scalar digests. Every write uses an exact monotonic
//! compare-and-swap transaction and byte-for-byte current readback. A lost
//! response retains a singular recovery token instead of inferring success.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

use super::assignment::{
    AssignmentEffectPlanV1, AssignmentObservationReducerV1, InvalidAssignmentModel,
    VerifiedAssignmentAuthorityV1,
};
use super::capability::{NodeBootId, NodeBootLineageV1};
use super::carrier_authority::{
    AuthenticatedAssignmentCarrierContractV1, issue_context_from_protected_bootstrap,
    issue_response_from_protected_channel, issue_session_from_protected_channel,
    verify_assignment_contract_from_protected_channel,
};
use super::evidence::AuthenticatedEvidenceContextV1;
use super::evidence_authority::ProtectedEvidenceIntegrationV1;
use super::journal::{
    AssignmentEffectSemanticGrantV1, InvalidMultiNodeJournal, JournalEffectStateV1,
    MultiNodeJournalCheckpointV1, MultiNodeJournalDomainV1, MultiNodeJournalRecordV1,
    MultiNodeJournalReducerV1, ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};
use super::protocol::{
    AuthenticatedNodeSessionV1, CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1,
    InvalidMultiNodeProtocol, NodeRequestEnvelopeV1, NodeResponseEnvelopeV1,
};
use super::reducer_state::{
    CapabilityJournalStateV1, DurableEvidenceBindingV1, MultiNodeReducerStateV1,
};

const PROTECTED_STORE_HEAD_KEY: &[u8] = b"\0aos-multi-node-protected-store-v1\0head";
const PROTECTED_STORE_HISTORY_MAGIC: &[u8; 8] = b"AOSMPS01";
const PROTECTED_MULTI_NODE_JOURNAL_NAME: &str = "multi-node-authority-v1.journal";
const PROTECTED_MULTI_NODE_BOOTSTRAP_JOURNAL_NAME: &str =
    "multi-node-authority-bootstrap-v1.journal";
const PROTECTED_MULTI_NODE_BOOTSTRAP_KEY: &[u8] =
    b"\0aos-multi-node-protected-bootstrap-v1\0config";
const PROTECTED_MULTI_NODE_CLOCK_KEY: &[u8] =
    b"\0aos-multi-node-protected-bootstrap-v1\0clock-floor";
const PROTECTED_MULTI_NODE_CLOCK_MAGIC: &[u8; 8] = b"AOSMCL01";
const PROTECTED_MULTI_NODE_BASE_GENERATION: u64 = 1;
const PROTECTED_MULTI_NODE_ROOT: &str = "/var/lib/aos/sandbox/multi-node";
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

/// Owns the complete dormant protected multi-node integration boundary.
///
/// The zero-argument opener uses a fixed protected root and authenticates its
/// signed bootstrap record. Journal identity, clock floor, storage commitments,
/// and reducer genesis values are fixed or derived internally; raw journals and
/// scalar authority inputs remain inaccessible.
pub struct ProtectedMultiNodeAuthorityOwnerV1 {
    store: ProtectedStoreJournalIntegrationV1,
    clock: ProtectedMultiNodeClockV1,
    bootstrap: ProtectedMultiNodeBootstrapV1,
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

impl ProtectedMultiNodeCurrentRecordV1 {
    /// Returns the exact protected current record.
    #[must_use]
    pub const fn record(&self) -> &ProtectedJournalRecordV1 {
        &self.record
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
        let mut owner = Self::from_authenticated_journal(
            journal,
            storage_domain_digest,
            replay_fence,
            PROTECTED_MULTI_NODE_BASE_GENERATION,
            base_root_digest,
            authenticated_context,
            current_unix_seconds,
            clock,
            bootstrap,
        )?;
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
        journal: Journal,
        storage_domain_digest: ObjectDigest,
        replay_fence: ObjectDigest,
        base_generation: u64,
        base_root_digest: ObjectDigest,
        authenticated_context: AuthenticatedEvidenceContextV1,
        verified_at_unix_seconds: u64,
        clock: ProtectedMultiNodeClockV1,
        bootstrap: ProtectedMultiNodeBootstrapV1,
    ) -> Result<Self, InvalidMultiNodeJournal> {
        Ok(Self {
            store: ProtectedStoreJournalIntegrationV1::from_authenticated_journal(
                journal,
                storage_domain_digest,
                replay_fence,
                base_generation,
                base_root_digest,
                authenticated_context,
                verified_at_unix_seconds,
            )?,
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
                    Path::new(PROTECTED_MULTI_NODE_ROOT),
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
            Path::new(PROTECTED_MULTI_NODE_ROOT),
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
