//! Private protected-store authority boundary.
//!
//! This module is the sole home of the durable-store adapter and its session
//! constructor. Journal code receives only a consumed opaque commit grant;
//! ordinary siblings cannot implement the backend or manufacture durability
//! acknowledgements from scalar digests. Every write uses an exact monotonic
//! compare-and-swap transaction and byte-for-byte current readback. A lost
//! response retains a singular recovery token instead of inferring success.
//!
//! Default ownership opens and validates the complete retained history, including
//! historical assignment, drain, watch, and snapshot DATA. Remote orchestration
//! is an explicitly selected private child; it shares, not replaces, this owner.
//! Retained-history encoding and historical projections live in a private child;
//! this parent retains live CAS/recovery custody and fixed bootstrap/clock state.

#[cfg(feature = "multi-node")]
pub(super) mod remote;

mod retained_history;

use retained_history::{
    decode_protected_store_history, encode_protected_store_history, protected_context_digest,
    protected_domain_genesis_digest, protected_receipt_commitment, protected_store_successor_root,
    protected_transaction_digest,
    validate_protected_store_semantics,
};
#[cfg(feature = "multi-node")]
use retained_history::{durable_drain_matches_report, replay_protected_store_semantics};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{NodeId, ObjectDigest, OperationId, bounded_codec::BoundedReader};

use crate::journal::{
    Journal, JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    RecoveryReport,
};

use super::assignment::{InvalidSnapshotTransfer, SnapshotTransferManifestV1};
use super::capability::{NodeBootId, NodeBootLineageV1};
use super::carrier_authority::{
    AuthenticatedAssignmentCarrierContractV1, issue_context_from_protected_bootstrap,
};
use super::evidence::AuthenticatedEvidenceContextV1;
use super::journal::{
    InvalidMultiNodeJournal, JournalEffectStateV1, MultiNodeJournalCheckpointV1,
    MultiNodeJournalDomainV1, MultiNodeJournalRecordV1, MultiNodeJournalReducerV1,
    ProtectedJournalCheckpointV1, ProtectedJournalRecordV1,
};
use super::protected_artifact_store::ProtectedArtifactStoreV1;
use super::protocol::{
    CanonicalNodeFrameV1, CanonicalNodeSemanticCodecV1, InvalidMultiNodeProtocol,
};
use super::reducer_state::{
    CapabilityJournalStateV1, DurableEvidenceBindingV1, MultiNodeReducerStateV1,
};

const PROTECTED_STORE_HEAD_KEY: &[u8] = b"\0aos-multi-node-protected-store-v1\0head";
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
#[derive(Eq, PartialEq)]
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
            let _ = current;
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
/// separately selected destination owner under `local_inventory::remote`.
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
            || result != readback.result
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

#[cfg(test)]
mod protected_store_history_decoder_tests {
    use super::{BoundedReader, InvalidMultiNodeJournal};

    #[test]
    fn truncated_and_overflowing_fields_preserve_cursor_and_store_error() {
        let bytes = [7, 8];
        let mut decoder = BoundedReader::new(&bytes, |_| {
            InvalidMultiNodeJournal::ProtectedStoreMismatch
        });

        assert_eq!(
            decoder.array::<4>(),
            Err(InvalidMultiNodeJournal::ProtectedStoreMismatch)
        );
        assert_eq!(decoder.u8(), Ok(7));
        assert_eq!(
            decoder.bytes(usize::MAX),
            Err(InvalidMultiNodeJournal::ProtectedStoreMismatch)
        );
        assert_eq!(decoder.u8(), Ok(8));
        assert!(decoder.is_empty());
        assert_eq!(bytes.len() - decoder.remaining(), bytes.len());
    }
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
    let mut decoder = BoundedReader::new(payload, |_| {
        InvalidMultiNodeJournal::ProtectedStoreMismatch
    });
    if decoder.bytes(8)? != PROTECTED_MULTI_NODE_CLOCK_MAGIC {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let floor = ProtectedMultiNodeClockFloorV1 {
        config_digest: ObjectDigest::from_bytes(decoder.array()?),
        coordinator_epoch: decoder.u64()?,
        replay_fence: ObjectDigest::from_bytes(decoder.array()?),
        observed_unix_seconds: decoder.u64()?,
        predecessor_unix_seconds: decoder.u64()?,
    };
    if !decoder.is_empty()
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

    let mut decoder = BoundedReader::new(payload, |_| {
        InvalidMultiNodeJournal::ProtectedStoreMismatch
    });
    if decoder.bytes(8)? != b"AOSMBC01" {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let node = NodeId::from_bytes(decoder.array()?);
    let boot = NodeBootId::new(decoder.array()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let generation = decoder.u64()?;
    let predecessor_present = decoder.u8()?;
    let predecessor_boot_bytes = decoder.array()?;
    let predecessor_digest_bytes = decoder.array()?;
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
        ObjectDigest::from_bytes(decoder.array()?),
    )
    .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    let authenticated_channel_binding = decoder.array()?;
    let canonical_frame_length = usize::try_from(decoder.u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if canonical_frame_length == 0
        || canonical_frame_length > super::protocol::MAX_NODE_RESPONSE_BYTES as usize
    {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_frame = decoder.bytes(canonical_frame_length)?.to_vec();
    let coordinator_epoch = decoder.u64()?;
    let authenticated_at_unix_seconds = decoder.u64()?;
    let valid_until_unix_seconds = decoder.u64()?;
    let maximum_request_bytes = decoder.u32()?;
    let maximum_response_bytes = decoder.u32()?;
    let replay_fence = ObjectDigest::from_bytes(decoder.array()?);
    let signed_payload = payload[..payload.len() - decoder.remaining()].to_vec();
    let trust_policy_length = usize::try_from(decoder.u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if trust_policy_length == 0 || trust_policy_length > 64 * 1024 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_trust_policy = decoder.bytes(trust_policy_length)?.to_vec();
    let public_key = decoder.array()?;
    let signature_length = usize::try_from(decoder.u32()?)
        .map_err(|_| InvalidMultiNodeJournal::ProtectedStoreMismatch)?;
    if signature_length == 0 || signature_length > 64 * 1024 {
        return Err(InvalidMultiNodeJournal::ProtectedStoreMismatch);
    }
    let canonical_signature = decoder.bytes(signature_length)?.to_vec();
    if !decoder.is_empty()
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
